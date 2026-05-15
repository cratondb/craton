//! # ehr-mini — End-to-end FHIR R4 walkthrough.
//!
//! Demonstrates the FHIR pipeline shipped in v0.9.x: parse a clinical
//! transaction Bundle, fan it into typed events, derive projection
//! rows for search, run FHIRPath against the canonical JSON, and
//! verify the byte-stability that the Kimberlite audit log will
//! commit to when this lands in the server-side ingest path.
//!
//! Runs offline — no server required. The pipeline this exercises
//! is exactly what `kimberlite-server` will execute when it receives
//! a `POST /fhir/Bundle` with a `transaction` payload.
//!
//! # Running
//!
//! ```bash
//! cd examples/rust
//! cargo run --example ehr_mini
//! ```

use anyhow::Result;
use kimberlite_fhir::fhirpath;
use kimberlite_fhir::resource::FhirResource;
use kimberlite_fhir::resources::{Bundle, Observation, Patient};
use kimberlite_fhir_store::{
    BundleIngester, FhirAction, FhirEvent, ObservationProjection, PatientProjection, Projection,
    fhir_stream_name, fhir_stream_policy,
};
use kimberlite_types::TenantId;

/// A realistic ambulatory-visit transaction Bundle: register a
/// patient, log the encounter, record a vital sign — all atomic.
const CLINICAL_VISIT_BUNDLE: &str = r#"{
    "resourceType": "Bundle",
    "id": "visit-2026-03-15",
    "type": "transaction",
    "entry": [
        {
            "fullUrl": "urn:uuid:alice-001",
            "resource": {
                "resourceType": "Patient",
                "id": "alice-001",
                "active": true,
                "name": [
                    {"use": "official", "family": "Smith", "given": ["Alice", "M."]},
                    {"use": "nickname", "family": "Smith", "given": ["Ali"]}
                ],
                "gender": "female",
                "birthDate": "1980-05-12",
                "identifier": [{
                    "system": "http://hospital.example.org/mrn",
                    "value": "MRN-12345"
                }],
                "telecom": [
                    {"system": "phone", "value": "555-1234", "use": "home"},
                    {"system": "email", "value": "alice@example.com"}
                ]
            },
            "request": {"method": "POST", "url": "Patient"}
        },
        {
            "fullUrl": "urn:uuid:enc-2026-03-15",
            "resource": {
                "resourceType": "Encounter",
                "id": "enc-2026-03-15",
                "status": "finished",
                "class": {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
                    "code": "AMB",
                    "display": "ambulatory"
                },
                "subject": {"reference": "Patient/alice-001"},
                "period": {
                    "start": "2026-03-15T09:00:00Z",
                    "end": "2026-03-15T09:30:00Z"
                }
            },
            "request": {"method": "POST", "url": "Encounter"}
        },
        {
            "fullUrl": "urn:uuid:obs-weight-001",
            "resource": {
                "resourceType": "Observation",
                "id": "obs-weight-001",
                "status": "final",
                "category": [{
                    "coding": [{
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "vital-signs"
                    }]
                }],
                "code": {
                    "coding": [{
                        "system": "http://loinc.org",
                        "code": "29463-7",
                        "display": "Body Weight"
                    }]
                },
                "subject": {"reference": "Patient/alice-001"},
                "encounter": {"reference": "Encounter/enc-2026-03-15"},
                "effectiveDateTime": "2026-03-15T09:15:00Z",
                "valueQuantity": {
                    "value": 72.5,
                    "unit": "kg",
                    "system": "http://unitsofmeasure.org",
                    "code": "kg"
                }
            },
            "request": {"method": "POST", "url": "Observation"}
        }
    ]
}"#;

fn main() -> Result<()> {
    let tenant = TenantId::new(42);

    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  ehr-mini — Kimberlite FHIR R4 pipeline walkthrough          │");
    println!("│  Tenant: {}                                                  │", u64::from(tenant));
    println!("└──────────────────────────────────────────────────────────────┘");

    // ──────────────────────────────────────────────────────────────
    // Step 1 — Parse the transaction bundle.
    // ──────────────────────────────────────────────────────────────
    println!("\n[1] Parse the transaction Bundle");
    let bundle = Bundle::from_json(CLINICAL_VISIT_BUNDLE.as_bytes())?;
    println!(
        "    ✓ Bundle `{}` parsed: type={:?}, {} entries",
        bundle.id.as_deref().unwrap_or("(no id)"),
        bundle.r#type,
        bundle.entry.len()
    );

    // ──────────────────────────────────────────────────────────────
    // Step 2 — Fan the bundle into per-resource events.
    // ──────────────────────────────────────────────────────────────
    println!("\n[2] BundleIngester → per-stream events");
    let ingester = BundleIngester::new();
    let entries = ingester.events_for(&bundle)?;
    for entry in &entries {
        let stream = fhir_stream_name(u64::from(tenant), entry.kind);
        let policy = fhir_stream_policy(entry.kind);
        println!(
            "    · {} → stream `{}`  (action: {:?}, retention: {} days, class: {:?})",
            entry.event.resource_type,
            stream,
            entry.event.action,
            policy.min_retention_days.unwrap_or(0),
            entry.kind.default_data_class()
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Step 3 — Postcard-encode + decode to prove byte-stability.
    // ──────────────────────────────────────────────────────────────
    println!("\n[3] Audit-grade byte-stability");
    for entry in &entries {
        let encoded = entry.event.encode()?;
        let decoded = FhirEvent::decode(&encoded)?;
        assert_eq!(decoded, entry.event, "round-trip mismatch");
        println!(
            "    ✓ {} event {} encoded → {} bytes, decoded → identical",
            entry.event.resource_type,
            entry.event.resource_id,
            encoded.len()
        );
    }

    // Two independent encodes of the same Patient produce the same
    // canonical bytes — this is the audit-log hash-chain invariant.
    let patient_event = entries
        .iter()
        .find(|e| e.event.resource_type == "Patient")
        .expect("patient in bundle");
    let canonical_a = patient_event.event.canonical_json.clone();
    let p_again = FhirEvent::from_resource(
        FhirAction::Create,
        &patient_event.event.to_resource::<Patient>()?,
    )?;
    assert_eq!(
        canonical_a, p_again.canonical_json,
        "canonical JSON must be deterministic"
    );
    println!(
        "    ✓ canonical JSON deterministic across two encodes ({} bytes)",
        canonical_a.len()
    );

    // ──────────────────────────────────────────────────────────────
    // Step 4 — Derive projection rows (the search-indexed surface).
    // ──────────────────────────────────────────────────────────────
    println!("\n[4] Projection rows for SQL search");

    let patient: Patient = patient_event.event.to_resource()?;
    let p_proj = PatientProjection::from_resource(&patient).expect("patient has id");
    println!(
        "    {} row:",
        PatientProjection::table_name(),
    );
    println!("      id                       = {}", p_proj.id);
    println!(
        "      family_name              = {}",
        p_proj.family_name.as_deref().unwrap_or("∅")
    );
    println!(
        "      given_names              = {}",
        p_proj.given_names.as_deref().unwrap_or("∅")
    );
    println!(
        "      birth_date               = {}",
        p_proj.birth_date.as_deref().unwrap_or("∅")
    );
    println!(
        "      gender                   = {}",
        p_proj.gender.as_deref().unwrap_or("∅")
    );
    println!(
        "      primary_identifier       = {} (system: {})",
        p_proj.primary_identifier.as_deref().unwrap_or("∅"),
        p_proj.primary_identifier_system.as_deref().unwrap_or("∅")
    );

    let obs_event = entries
        .iter()
        .find(|e| e.event.resource_type == "Observation")
        .expect("observation in bundle");
    let observation: Observation = obs_event.event.to_resource()?;
    let o_proj = ObservationProjection::from_resource(&observation).expect("obs has id");
    println!(
        "    {} row:",
        ObservationProjection::table_name()
    );
    println!("      id                       = {}", o_proj.id);
    println!("      status                   = {}", o_proj.status);
    println!(
        "      code                     = {} (system: {})",
        o_proj.code.as_deref().unwrap_or("∅"),
        o_proj.code_system.as_deref().unwrap_or("∅")
    );
    println!(
        "      subject_ref              = {}",
        o_proj.subject_ref.as_deref().unwrap_or("∅")
    );
    println!(
        "      value_numeric / unit     = {} {}",
        o_proj
            .value_numeric
            .map(|v| v.to_string())
            .unwrap_or_else(|| "∅".into()),
        o_proj.value_unit.as_deref().unwrap_or("")
    );

    // ──────────────────────────────────────────────────────────────
    // Step 5 — FHIRPath queries against the canonical JSON.
    // ──────────────────────────────────────────────────────────────
    println!("\n[5] FHIRPath queries against canonical JSON");
    let patient_json: serde_json::Value = serde_json::from_slice(&patient_event.event.canonical_json)?;
    let obs_json: serde_json::Value = serde_json::from_slice(&obs_event.event.canonical_json)?;

    let demos = [
        ("Patient.name[0].family", &patient_json),
        ("Patient.name.given", &patient_json),
        (
            "Patient.identifier.where(system = 'http://hospital.example.org/mrn').value",
            &patient_json,
        ),
        ("Patient.telecom.where(system = 'phone').value", &patient_json),
        ("Observation.code.coding[0].code", &obs_json),
        ("Observation.valueQuantity.value", &obs_json),
        ("Observation.valueQuantity.value > 70", &obs_json),
    ];

    for (expr, ctx) in demos {
        let result = fhirpath::evaluate(expr, ctx)?;
        let rendered: Vec<String> = result
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => format!("\"{s}\""),
                other => other.to_string(),
            })
            .collect();
        println!("    FHIRPATH `{expr}` →");
        println!("      [{}]", rendered.join(", "));
    }

    // ──────────────────────────────────────────────────────────────
    // Wrap-up.
    // ──────────────────────────────────────────────────────────────
    println!("\n──────────────────────────────────────────────────────────────");
    println!("Pipeline OK: Bundle → events → projections → FHIRPath.");
    println!("Every event in steps [2]–[3] is ready to be hash-chained");
    println!("into the Kimberlite audit log byte-for-byte.");
    println!();

    Ok(())
}
