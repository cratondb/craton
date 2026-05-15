//! FHIR R4 [Bundle](https://www.hl7.org/fhir/R4/bundle.html).
//!
//! Bundles are the FHIR transport primitive: a Patient + Encounter +
//! several Observations arriving together as one wire payload. The
//! `BundleType` of `transaction` instructs the server to apply all
//! entries atomically; `searchset` is the response shape for a search
//! REST call; `batch` is non-atomic batch processing.

use serde::{Deserialize, Serialize};

use crate::datatypes::{Identifier, Meta};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Bundle`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Bundle {
    #[serde(rename = "resourceType")]
    pub resource_type: BundleResourceTag,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Identifier>,

    pub r#type: BundleType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry: Vec<BundleEntry>,

    #[serde(flatten)]
    pub extras: FhirExtras,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum BundleResourceTag {
    #[default]
    Bundle,
}

/// FHIR `Bundle.type` value set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BundleType {
    Document,
    Message,
    #[default]
    Transaction,
    TransactionResponse,
    Batch,
    BatchResponse,
    History,
    Searchset,
    Collection,
}

/// One entry in a Bundle. `resource` is the inner resource as a
/// `serde_json::Value` so a Bundle can carry mixed resource types
/// without forcing this struct to become a giant enum. Callers
/// downcast via [`BundleEntry::as_resource`] when they need a typed
/// view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BundleEntry {
    #[serde(skip_serializing_if = "Option::is_none", rename = "fullUrl")]
    pub full_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<BundleEntryRequest>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<BundleEntryResponse>,
}

impl BundleEntry {
    /// Try to interpret this entry's `resource` as a typed FHIR
    /// resource of type `T`. Returns `None` if no resource present;
    /// returns an error if the resource's `resourceType` doesn't
    /// match `T::RESOURCE_TYPE` or the JSON shape is invalid.
    pub fn as_resource<T: FhirResource>(
        &self,
    ) -> Option<Result<T, crate::resource::ResourceError>> {
        let v = self.resource.as_ref()?;
        let bytes = match serde_json::to_vec(v) {
            Ok(b) => b,
            Err(e) => return Some(Err(crate::resource::ResourceError::Json(e))),
        };
        Some(T::from_json(&bytes))
    }
}

/// FHIR `Bundle.entry.request` — for transaction / batch bundles, the
/// HTTP-shaped intent (POST a new Patient, PUT to replace, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BundleEntryRequest {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ifNoneMatch")]
    pub if_none_match: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ifMatch")]
    pub if_match: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ifNoneExist")]
    pub if_none_exist: Option<String>,
}

/// FHIR `Bundle.entry.response`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BundleEntryResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "lastModified")]
    pub last_modified: Option<String>,
}

impl FhirResource for Bundle {
    const RESOURCE_TYPE: &'static str = "Bundle";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::Patient;

    #[test]
    fn transaction_bundle_with_patient_entry_round_trips() {
        let p = Patient {
            id: Some("p-1".into()),
            ..Default::default()
        };
        let p_value = serde_json::to_value(&p).unwrap();
        let b = Bundle {
            id: Some("bundle-1".into()),
            r#type: BundleType::Transaction,
            entry: vec![BundleEntry {
                full_url: Some("urn:uuid:patient-1".into()),
                resource: Some(p_value),
                request: Some(BundleEntryRequest {
                    method: "POST".into(),
                    url: "Patient".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let bytes = b.to_json().unwrap();
        let parsed = Bundle::from_json(&bytes).unwrap();
        assert_eq!(b, parsed);
    }

    #[test]
    fn bundle_entry_downcasts_to_typed_patient() {
        let p = Patient {
            id: Some("p-2".into()),
            ..Default::default()
        };
        let entry = BundleEntry {
            resource: Some(serde_json::to_value(&p).unwrap()),
            ..Default::default()
        };
        let downcast = entry.as_resource::<Patient>().unwrap().unwrap();
        assert_eq!(downcast.id(), Some("p-2"));
    }

    #[test]
    fn bundle_entry_downcast_to_wrong_type_errors() {
        let p = Patient {
            id: Some("p-3".into()),
            ..Default::default()
        };
        let entry = BundleEntry {
            resource: Some(serde_json::to_value(&p).unwrap()),
            ..Default::default()
        };
        let err = entry
            .as_resource::<crate::resources::Observation>()
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            crate::resource::ResourceError::WrongResourceType { actual, .. } if actual == "Patient"
        ));
    }

    #[test]
    fn bundle_type_serialises_kebab() {
        let b = Bundle {
            r#type: BundleType::TransactionResponse,
            ..Default::default()
        };
        let s = b.to_json_string().unwrap();
        assert!(s.contains(r#""type":"transaction-response""#));
    }
}
