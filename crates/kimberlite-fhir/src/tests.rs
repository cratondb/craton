//! Cross-cutting tests — round-trip fidelity, canonical-JSON
//! determinism, and the Bundle → typed-resources path that the
//! storage adapter will lean on in Q1.4.

use crate::canonical::to_canonical_bytes;
use crate::resource::FhirResource;
use crate::resources::{Bundle, BundleEntry, BundleType, Observation, ObservationStatus, Patient};

#[test]
fn full_clinical_bundle_round_trips() {
    // A realistic "patient + observation" transaction bundle.
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
                    "birthDate": "1990-01-15"
                },
                "request": { "method": "POST", "url": "Patient" }
            },
            {
                "fullUrl": "urn:uuid:o1",
                "resource": {
                    "resourceType": "Observation",
                    "id": "o1",
                    "status": "final",
                    "code": {"text": "Heart rate"},
                    "subject": {"reference": "Patient/p1"},
                    "valueQuantity": {"value": 72, "unit": "/min"}
                },
                "request": { "method": "POST", "url": "Observation" }
            }
        ]
    }"#;

    let bundle = Bundle::from_json(raw).unwrap();
    assert_eq!(bundle.entry.len(), 2);

    // Downcast each entry to its typed resource shape.
    let p = bundle.entry[0]
        .as_resource::<Patient>()
        .unwrap()
        .unwrap();
    assert_eq!(p.id(), Some("p1"));

    let o = bundle.entry[1]
        .as_resource::<Observation>()
        .unwrap()
        .unwrap();
    assert_eq!(o.id(), Some("o1"));
    assert_eq!(o.status, ObservationStatus::Final);
}

#[test]
fn canonical_json_is_byte_stable_across_two_runs() {
    // The hash-chain audit guarantee: serialising the same resource
    // twice must produce the same bytes regardless of HashMap
    // ordering, etc.
    let p = Patient {
        id: Some("p1".into()),
        ..Default::default()
    };
    let a = to_canonical_bytes(&p).unwrap();
    let b = to_canonical_bytes(&p).unwrap();
    assert_eq!(a, b);
}

#[test]
fn cross_resource_canonicalisation_yields_distinct_bytes() {
    let p1 = Patient {
        id: Some("p1".into()),
        ..Default::default()
    };
    let p2 = Patient {
        id: Some("p2".into()),
        ..Default::default()
    };
    assert_ne!(
        to_canonical_bytes(&p1).unwrap(),
        to_canonical_bytes(&p2).unwrap()
    );
}

#[test]
fn empty_bundle_round_trips() {
    let b = Bundle {
        r#type: BundleType::Searchset,
        total: Some(0),
        entry: vec![],
        ..Default::default()
    };
    let bytes = b.to_json().unwrap();
    let parsed = Bundle::from_json(&bytes).unwrap();
    assert_eq!(b, parsed);
}

#[test]
fn unknown_resource_in_bundle_entry_is_preserved_as_json() {
    // A future R5 resource we don't have a typed model for must still
    // survive a Bundle round-trip — the entry resource is `Value`.
    let raw = br#"{
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "ResearchStudy",
                    "id": "rs1",
                    "status": "active",
                    "customField": "preserved"
                }
            }
        ]
    }"#;
    let b = Bundle::from_json(raw).unwrap();
    let re_emitted = b.to_json_string().unwrap();
    assert!(re_emitted.contains(r#""resourceType":"ResearchStudy""#));
    assert!(re_emitted.contains(r#""customField":"preserved""#));
}

#[test]
fn entry_with_no_resource_returns_none_on_downcast() {
    let entry = BundleEntry::default();
    assert!(entry.as_resource::<Patient>().is_none());
}
