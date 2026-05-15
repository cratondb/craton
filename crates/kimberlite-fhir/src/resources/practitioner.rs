//! FHIR R4 [Practitioner](https://www.hl7.org/fhir/R4/practitioner.html).

use serde::{Deserialize, Serialize};

use crate::datatypes::{Address, ContactPoint, HumanName, Identifier, Meta};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Practitioner` — a person directly or indirectly involved in
/// the provisioning of healthcare. The SMART on FHIR `fhirUser` claim
/// usually references a Practitioner when the launching app is run by
/// a clinician.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Practitioner {
    #[serde(rename = "resourceType")]
    pub resource_type: PractitionerResourceTag,

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

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<Address>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "birthDate")]
    pub birth_date: Option<String>,

    #[serde(flatten)]
    pub extras: FhirExtras,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum PractitionerResourceTag {
    #[default]
    Practitioner,
}

impl FhirResource for Practitioner {
    const RESOURCE_TYPE: &'static str = "Practitioner";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = Practitioner {
            id: Some("dr-jones".into()),
            identifier: vec![Identifier {
                system: Some("http://hl7.org/fhir/sid/us-npi".into()),
                value: Some("1234567890".into()),
                ..Default::default()
            }],
            name: vec![HumanName {
                family: Some("Jones".into()),
                given: vec!["Robert".into()],
                prefix: vec!["Dr.".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let bytes = p.to_json().unwrap();
        let parsed = Practitioner::from_json(&bytes).unwrap();
        assert_eq!(p, parsed);
        assert_eq!(parsed.id(), Some("dr-jones"));
    }

    #[test]
    fn rejects_wrong_resource_type() {
        let raw = br#"{"resourceType":"Patient","id":"p1"}"#;
        let err = Practitioner::from_json(raw).unwrap_err();
        assert!(matches!(
            err,
            crate::resource::ResourceError::WrongResourceType { .. }
        ));
    }
}
