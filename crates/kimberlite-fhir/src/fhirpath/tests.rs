//! Integration tests for the FHIRPath subset evaluator.

use serde_json::json;

use super::evaluate;

fn patient() -> serde_json::Value {
    json!({
        "resourceType": "Patient",
        "id": "alice-001",
        "active": true,
        "name": [
            { "use": "official", "family": "Smith", "given": ["Alice", "M."] },
            { "use": "nickname", "family": "Smith", "given": ["Ali"] }
        ],
        "gender": "female",
        "birthDate": "1980-05-12",
        "identifier": [
            { "system": "http://hospital.example.org/mrn", "value": "MRN-12345" }
        ],
        "telecom": [
            { "system": "phone", "value": "555-1234", "use": "home" },
            { "system": "email", "value": "alice@example.com" }
        ]
    })
}

fn observation() -> serde_json::Value {
    json!({
        "resourceType": "Observation",
        "id": "o1",
        "status": "final",
        "code": {
            "coding": [{
                "system": "http://loinc.org",
                "code": "29463-7",
                "display": "Body Weight"
            }]
        },
        "subject": { "reference": "Patient/alice-001" },
        "valueQuantity": { "value": 72.5, "unit": "kg" }
    })
}

#[test]
fn resource_type_prefix_is_consumed() {
    let r = evaluate("Patient.id", &patient()).unwrap();
    assert_eq!(r, vec![json!("alice-001")]);
}

#[test]
fn nested_path_auto_flattens_array() {
    // Patient.name.given crosses 2 name entries × multiple givens.
    // Expected: ["Alice", "M.", "Ali"] flattened.
    let r = evaluate("Patient.name.given", &patient()).unwrap();
    assert_eq!(r, vec![json!("Alice"), json!("M."), json!("Ali")]);
}

#[test]
fn index_picks_single_element() {
    let r = evaluate("Patient.name[0].family", &patient()).unwrap();
    assert_eq!(r, vec![json!("Smith")]);
}

#[test]
fn index_out_of_bounds_returns_empty() {
    let r = evaluate("Patient.name[5].family", &patient()).unwrap();
    assert!(r.is_empty());
}

#[test]
fn where_filters_collection_by_predicate() {
    let r = evaluate("Patient.name.where(use = 'official').given", &patient()).unwrap();
    // Only the official name's given names.
    assert_eq!(r, vec![json!("Alice"), json!("M.")]);
}

#[test]
fn where_with_nonexistent_property_returns_empty() {
    let r = evaluate("Patient.name.where(foo = 'bar').family", &patient()).unwrap();
    assert!(r.is_empty());
}

#[test]
fn equality_against_string_literal() {
    let r = evaluate("Patient.gender = 'female'", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);

    let r = evaluate("Patient.gender = 'male'", &patient()).unwrap();
    assert_eq!(r, vec![json!(false)]);
}

#[test]
fn numeric_comparison_on_quantity() {
    let r = evaluate("Observation.valueQuantity.value > 70", &observation()).unwrap();
    assert_eq!(r, vec![json!(true)]);

    let r = evaluate("Observation.valueQuantity.value >= 100", &observation()).unwrap();
    assert_eq!(r, vec![json!(false)]);
}

#[test]
fn exists_function() {
    let r = evaluate("Patient.identifier.exists()", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);

    let r = evaluate("Patient.deceased.exists()", &patient()).unwrap();
    assert_eq!(r, vec![json!(false)]);
}

#[test]
fn empty_function_is_inverse_of_exists() {
    let r = evaluate("Patient.deceased.empty()", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);

    let r = evaluate("Patient.identifier.empty()", &patient()).unwrap();
    assert_eq!(r, vec![json!(false)]);
}

#[test]
fn count_returns_collection_size() {
    let r = evaluate("Patient.name.count()", &patient()).unwrap();
    assert_eq!(r, vec![json!(2)]);

    let r = evaluate("Patient.name.given.count()", &patient()).unwrap();
    assert_eq!(r, vec![json!(3)]);
}

#[test]
fn first_and_last() {
    let r = evaluate("Patient.name.given.first()", &patient()).unwrap();
    assert_eq!(r, vec![json!("Alice")]);

    let r = evaluate("Patient.name.given.last()", &patient()).unwrap();
    assert_eq!(r, vec![json!("Ali")]);
}

#[test]
fn and_or_combination() {
    let r =
        evaluate("Patient.active = true and Patient.gender = 'female'", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);

    let r =
        evaluate("Patient.gender = 'male' or Patient.gender = 'female'", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);
}

#[test]
fn not_inverts_boolean() {
    let r = evaluate("not(Patient.gender = 'male')", &patient()).unwrap();
    assert_eq!(r, vec![json!(true)]);
}

#[test]
fn nested_identifier_search() {
    // The pattern an MRN lookup follows: filter identifiers by system,
    // then read value.
    let r = evaluate(
        "Patient.identifier.where(system = 'http://hospital.example.org/mrn').value",
        &patient(),
    )
    .unwrap();
    assert_eq!(r, vec![json!("MRN-12345")]);
}

#[test]
fn observation_loinc_code_lookup() {
    let r = evaluate("Observation.code.coding[0].code", &observation()).unwrap();
    assert_eq!(r, vec![json!("29463-7")]);
}

#[test]
fn unknown_function_errors() {
    let err = evaluate("Patient.name.unknownFunc()", &patient()).unwrap_err();
    assert!(matches!(
        err,
        super::FhirPathError::UnknownFunction { name } if name == "unknownFunc"
    ));
}

#[test]
fn comparison_against_empty_is_false_not_error() {
    let r = evaluate("Patient.nonexistent = 'foo'", &patient()).unwrap();
    assert_eq!(r, vec![json!(false)]);
}

#[test]
fn telecom_phone_extraction_via_where() {
    let r = evaluate(
        "Patient.telecom.where(system = 'phone').value",
        &patient(),
    )
    .unwrap();
    assert_eq!(r, vec![json!("555-1234")]);
}
