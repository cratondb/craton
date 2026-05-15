//! End-to-end tests across the adapter — Bundle → events → projections.

use kimberlite_fhir::resources::{
    Bundle, BundleEntry, BundleEntryRequest, BundleType, ObservationStatus, Patient,
};

use crate::bundle::BundleIngester;
use crate::event::FhirAction;
use crate::projection::{ObservationProjection, PatientProjection, Projection};
use crate::streams::{fhir_stream_name, fhir_stream_policy, FhirResourceKind};

#[test]
fn end_to_end_clinical_visit_bundle() {
    // A real-world shape: register a patient, log the visit, record
    // a vital sign — all in one transaction bundle. The ingester
    // produces three events, projector builds two rows (Patient +
    // Observation; Encounter projector exercised in its own test).
    let raw = br#"{
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "fullUrl": "urn:uuid:p1",
                "resource": {
                    "resourceType": "Patient",
                    "id": "p1",
                    "name": [{"family": "Doe", "given": ["Jane"]}],
                    "gender": "female",
                    "birthDate": "1990-01-15",
                    "identifier": [{
                        "system": "http://hospital.example.org/mrn",
                        "value": "MRN-99"
                    }]
                },
                "request": { "method": "POST", "url": "Patient" }
            },
            {
                "fullUrl": "urn:uuid:e1",
                "resource": {
                    "resourceType": "Encounter",
                    "id": "e1",
                    "status": "finished",
                    "class": {"code": "AMB"},
                    "subject": {"reference": "Patient/p1"}
                },
                "request": { "method": "POST", "url": "Encounter" }
            },
            {
                "fullUrl": "urn:uuid:o1",
                "resource": {
                    "resourceType": "Observation",
                    "id": "o1",
                    "status": "final",
                    "code": {
                        "coding": [{
                            "system": "http://loinc.org",
                            "code": "8867-4",
                            "display": "Heart rate"
                        }]
                    },
                    "subject": {"reference": "Patient/p1"},
                    "encounter": {"reference": "Encounter/e1"},
                    "valueQuantity": {"value": 72, "unit": "/min"}
                },
                "request": { "method": "POST", "url": "Observation" }
            }
        ]
    }"#;

    let bundle: Bundle = kimberlite_fhir::resource::FhirResource::from_json(raw).unwrap();

    // 1. Ingester fans out into per-stream events.
    let events = BundleIngester::new().events_for(&bundle).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, FhirResourceKind::Patient);
    assert_eq!(events[1].kind, FhirResourceKind::Encounter);
    assert_eq!(events[2].kind, FhirResourceKind::Observation);
    for entry in &events {
        assert_eq!(entry.event.action, FhirAction::Create);
    }

    // 2. Each event round-trips through postcard.
    for entry in &events {
        let bytes = entry.event.encode().unwrap();
        let decoded = crate::event::FhirEvent::decode(&bytes).unwrap();
        assert_eq!(decoded, entry.event);
    }

    // 3. Projection rows derive from the typed resources cleanly.
    let p: Patient = events[0].event.to_resource().unwrap();
    let p_proj = PatientProjection::from_resource(&p).unwrap();
    assert_eq!(p_proj.id, "p1");
    assert_eq!(p_proj.family_name.as_deref(), Some("Doe"));
    assert_eq!(p_proj.primary_identifier.as_deref(), Some("MRN-99"));

    let o: kimberlite_fhir::resources::Observation = events[2].event.to_resource().unwrap();
    let o_proj = ObservationProjection::from_resource(&o).unwrap();
    assert_eq!(o_proj.code.as_deref(), Some("8867-4"));
    assert_eq!(o_proj.value_numeric, Some(72.0));
    assert_eq!(o_proj.value_unit.as_deref(), Some("/min"));
    assert_eq!(o_proj.status, "final");
    assert_eq!(o.status, ObservationStatus::Final);
}

#[test]
fn streams_use_fhir_naming_convention_per_tenant() {
    let tenant = 2026;
    assert_eq!(
        fhir_stream_name(tenant, FhirResourceKind::Patient),
        "fhir.Patient.2026"
    );
    assert_eq!(
        fhir_stream_name(tenant, FhirResourceKind::Observation),
        "fhir.Observation.2026"
    );

    // And the retention policy on those streams is HIPAA's 6-year
    // minimum — the healthcare-first default from Sprint 2.
    let policy = fhir_stream_policy(FhirResourceKind::Patient);
    assert_eq!(policy.min_retention_days, Some(2_190));
}

#[test]
fn projection_table_names_are_snake_case_per_resource() {
    assert_eq!(PatientProjection::table_name(), "fhir_patient");
    assert_eq!(ObservationProjection::table_name(), "fhir_observation");
}

#[test]
fn empty_transaction_bundle_yields_empty_event_list() {
    let b = Bundle {
        r#type: BundleType::Transaction,
        entry: vec![],
        ..Default::default()
    };
    let out = BundleIngester::new().events_for(&b).unwrap();
    assert!(out.is_empty());
}

#[test]
fn mixed_method_bundle_preserves_order_and_action_mapping() {
    let p = Patient {
        id: Some("p1".into()),
        ..Default::default()
    };
    let p_value = serde_json::to_value(&p).unwrap();

    let mk = |method: &str, id: &str| -> BundleEntry {
        let mut r = p_value.clone();
        if let serde_json::Value::Object(ref mut m) = r {
            m.insert("id".into(), serde_json::Value::String(id.into()));
        }
        BundleEntry {
            resource: Some(r),
            request: Some(BundleEntryRequest {
                method: method.into(),
                url: format!("Patient/{id}"),
                ..Default::default()
            }),
            ..Default::default()
        }
    };

    let b = Bundle {
        r#type: BundleType::Transaction,
        entry: vec![mk("POST", "a"), mk("PUT", "b"), mk("DELETE", "c")],
        ..Default::default()
    };
    let out = BundleIngester::new().events_for(&b).unwrap();
    assert_eq!(
        (out[0].event.action, &*out[0].event.resource_id),
        (FhirAction::Create, "a")
    );
    assert_eq!(
        (out[1].event.action, &*out[1].event.resource_id),
        (FhirAction::Update, "b")
    );
    assert_eq!(
        (out[2].event.action, &*out[2].event.resource_id),
        (FhirAction::Delete, "c")
    );
}
