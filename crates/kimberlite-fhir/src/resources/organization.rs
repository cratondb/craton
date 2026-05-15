//! FHIR R4 [Organization](https://www.hl7.org/fhir/R4/organization.html).

use serde::{Deserialize, Serialize};

use crate::datatypes::{Address, CodeableConcept, ContactPoint, Identifier, Meta, Reference};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Organization` — a formally or informally recognised grouping
/// of people or organisations formed for a common purpose. Used as
/// `managingOrganization` on Patient and `serviceProvider` on
/// Encounter; the SMART on FHIR `fhirUser` claim can also reference
/// an Organization for organisational service accounts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Organization {
    #[serde(rename = "resourceType")]
    pub resource_type: OrganizationResourceTag,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier: Vec<Identifier>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "type")]
    pub type_: Vec<CodeableConcept>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alias: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telecom: Vec<ContactPoint>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<Address>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "partOf")]
    pub part_of: Option<Reference>,

    #[serde(flatten)]
    pub extras: FhirExtras,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum OrganizationResourceTag {
    #[default]
    Organization,
}

impl FhirResource for Organization {
    const RESOURCE_TYPE: &'static str = "Organization";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal() {
        let o = Organization {
            id: Some("acme-health".into()),
            name: Some("Acme Health Network".into()),
            active: Some(true),
            ..Default::default()
        };
        let bytes = o.to_json().unwrap();
        let parsed = Organization::from_json(&bytes).unwrap();
        assert_eq!(o, parsed);
    }
}
