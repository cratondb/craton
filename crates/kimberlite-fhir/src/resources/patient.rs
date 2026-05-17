//! FHIR R4 [Patient](https://www.hl7.org/fhir/R4/patient.html).

use serde::{Deserialize, Serialize};

use crate::datatypes::{Address, ContactPoint, HumanName, Identifier, Meta, Reference};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Patient` — the subject of healthcare and related services.
///
/// US Core constraint (informational, not enforced here): a Patient
/// MUST carry an `identifier`, a `name`, and one of `gender` or
/// `birthDate` to be valid against the US Core profile. Validation is
/// caller responsibility — this struct is a faithful FHIR R4 shape
/// without profile enforcement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Patient {
    /// Always the literal `"Patient"`. Round-tripped explicitly so the
    /// emitted JSON is FHIR-valid without a wrapper.
    #[serde(rename = "resourceType")]
    pub resource_type: PatientResourceTag,

    /// Logical id of the resource (resource-id within its tenant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier: Vec<Identifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<HumanName>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telecom: Vec<ContactPoint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<PatientGender>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "birthDate")]
    pub birth_date: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<Address>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "managingOrganization"
    )]
    pub managing_organization: Option<Reference>,

    /// Catch-all for fields not modelled in this struct — survives
    /// round-trip so Epic/Cerner-specific extensions don't get lost.
    #[serde(flatten)]
    pub extras: FhirExtras,
}

/// Marker tag enforcing the `resourceType` literal on serialisation.
/// Defaults to `Patient`; deserialisation accepts only `"Patient"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum PatientResourceTag {
    #[default]
    Patient,
}

/// FHIR `Patient.gender` value set (`administrative-gender`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatientGender {
    Male,
    Female,
    Other,
    Unknown,
}

impl FhirResource for Patient {
    const RESOURCE_TYPE: &'static str = "Patient";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::to_canonical_bytes;

    fn alice() -> Patient {
        Patient {
            id: Some("alice-001".into()),
            identifier: vec![Identifier {
                system: Some("http://hospital.example.org/mrn".into()),
                value: Some("MRN-12345".into()),
                ..Default::default()
            }],
            active: Some(true),
            name: vec![HumanName {
                family: Some("Smith".into()),
                given: vec!["Alice".into(), "M.".into()],
                ..Default::default()
            }],
            gender: Some(PatientGender::Female),
            birth_date: Some("1980-05-12".into()),
            ..Default::default()
        }
    }

    #[test]
    fn round_trip_to_json_and_back() {
        let p = alice();
        let bytes = p.to_json().unwrap();
        let parsed = Patient::from_json(&bytes).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn resource_type_field_is_emitted() {
        let bytes = alice().to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v.get("resourceType").and_then(|x| x.as_str()),
            Some("Patient")
        );
    }

    #[test]
    fn rejects_wrong_resource_type() {
        let bytes = br#"{"resourceType":"Observation","id":"o1"}"#;
        let err = Patient::from_json(bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::resource::ResourceError::WrongResourceType { actual, .. } if actual == "Observation"
        ));
    }

    #[test]
    fn unknown_fields_round_trip_via_extras() {
        // Epic-style extension that we don't model explicitly.
        let raw = br#"{"resourceType":"Patient","id":"p1","epicExtension":{"foo":"bar"}}"#;
        let parsed = Patient::from_json(raw).unwrap();
        assert!(!parsed.extras.is_empty());
        let re_emitted = parsed.to_json_string().unwrap();
        assert!(re_emitted.contains("epicExtension"));
        assert!(re_emitted.contains(r#""foo":"bar""#));
    }

    #[test]
    fn canonical_json_is_deterministic_across_field_orders() {
        // Two equivalent JSON inputs (different key order) canonicalise
        // to the same bytes — exactly the property the audit log
        // depends on.
        let a = br#"{"id":"p1","resourceType":"Patient","active":true}"#;
        let b = br#"{"active":true,"resourceType":"Patient","id":"p1"}"#;
        let pa = Patient::from_json(a).unwrap();
        let pb = Patient::from_json(b).unwrap();
        let ca = to_canonical_bytes(&pa).unwrap();
        let cb = to_canonical_bytes(&pb).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn id_accessor_returns_logical_id() {
        let p = alice();
        assert_eq!(p.id(), Some("alice-001"));
    }
}
