//! FHIR R4 complex datatypes.
//!
//! These are the building blocks every resource composes. Each maps
//! 1:1 to the FHIR R4 specification of the same name; field
//! cardinalities and required/optional status reflect the spec.

use serde::{Deserialize, Serialize};

/// FHIR `Identifier` — typed external identifier for a resource (MRN,
/// NPI, SSN, etc.). At least `value` is conventionally present;
/// `system` resolves the identifier namespace (a URI like
/// `urn:oid:2.16.840.1.113883.4.1` for US SSN).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub type_: Option<CodeableConcept>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<Period>,
}

/// FHIR `HumanName` — a person's name, with separate `family` and
/// pluggable `given` parts (the FHIR spec correctly assumes a person
/// can have multiple given names).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HumanName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub given: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffix: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<Period>,
}

/// FHIR `Coding` — single coded value from a coding system (ICD-10,
/// SNOMED CT, LOINC, CPT, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Coding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "userSelected")]
    pub user_selected: Option<bool>,
}

/// FHIR `CodeableConcept` — a concept that may be expressed across
/// multiple coding systems with a free-text fallback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CodeableConcept {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coding: Vec<Coding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// FHIR `Reference` — a pointer to another resource by logical id or
/// literal URL (e.g. `"Patient/123"` or
/// `"https://ehr.example.com/fhir/Patient/123"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Reference {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Identifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

impl Reference {
    /// Build a literal reference of the form `"ResourceType/id"`.
    pub fn literal(resource_type: &str, id: &str) -> Self {
        Self {
            reference: Some(format!("{resource_type}/{id}")),
            type_: Some(resource_type.to_string()),
            identifier: None,
            display: None,
        }
    }
}

/// FHIR `Period` — start and end of a time window. Stored as strings
/// to preserve the FHIR `dateTime` partial-date semantics (a Period
/// can be bounded by a year, a month, or a full timestamp).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Period {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}

/// FHIR `Address`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub district: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "postalCode")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<Period>,
}

/// FHIR `ContactPoint` — a means of contacting the resource subject
/// (phone, email, fax, url, sms, other, pager).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ContactPoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<Period>,
}

/// FHIR `Meta` — version, last-updated, profiles, security/tag codings
/// for a resource. Profiles include US Core URLs like
/// `http://hl7.org/fhir/us/core/StructureDefinition/us-core-patient`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    #[serde(skip_serializing_if = "Option::is_none", rename = "versionId")]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "lastUpdated")]
    pub last_updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<Coding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag: Vec<Coding>,
}

/// FHIR `Quantity` — numeric value with optional unit and coded unit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Quantity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}
