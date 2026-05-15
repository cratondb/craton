//! Transaction-bundle ingester.
//!
//! Takes a [`kimberlite_fhir::Bundle`] of type `transaction` (or
//! `batch`) and produces the typed [`FhirEvent`]s that should be
//! appended to per-resource streams. Each entry's `request.method`
//! drives the [`FhirAction`]: `POST` → Create, `PUT` → Update,
//! `DELETE` → Delete.
//!
//! Atomicity is **caller responsibility**: this module returns a
//! `Vec<IngestedEntry>` deterministically; the SDK / server commits
//! the appends inside a single transaction so the bundle is
//! all-or-nothing.

use kimberlite_fhir::resources::{
    Bundle, BundleEntry, BundleType, Encounter, Observation, Organization, Patient, Practitioner,
};
use thiserror::Error;

use crate::event::{FhirAction, FhirEvent, FhirEventError};
use crate::streams::FhirResourceKind;

/// Errors from ingesting a Bundle.
#[derive(Debug, Error)]
pub enum BundleIngestError {
    #[error("bundle.type must be `transaction` or `batch`, got `{got:?}`")]
    UnsupportedBundleType { got: BundleType },

    #[error("bundle entry {index} has no `resource`")]
    EntryMissingResource { index: usize },

    #[error(
        "bundle entry {index} has no `request.method` — required for transaction/batch bundles"
    )]
    EntryMissingRequestMethod { index: usize },

    #[error("bundle entry {index} request.method `{method}` is not recognised (POST/PUT/DELETE)")]
    EntryUnknownMethod { index: usize, method: String },

    #[error(
        "bundle entry {index} carries `resourceType=\"{resource_type}\"`, which this adapter does not support"
    )]
    EntryUnsupportedResource {
        index: usize,
        resource_type: String,
    },

    #[error("bundle entry {index} has no `resourceType` field in its resource payload")]
    EntryMissingResourceType { index: usize },

    #[error("bundle entry {index} {context}: {source}")]
    Event {
        index: usize,
        context: &'static str,
        #[source]
        source: FhirEventError,
    },
}

/// One ingested entry: the resource kind it targets (so the caller
/// knows which stream to append to) and the typed event.
#[derive(Debug, Clone, PartialEq)]
pub struct IngestedEntry {
    pub kind: FhirResourceKind,
    pub event: FhirEvent,
}

/// Ingester that turns transaction bundles into typed events.
///
/// Stateless on purpose — every call is a pure transformation. Live
/// authentication / scope checking happens at the SDK / server
/// boundary before invoking this.
#[derive(Debug, Default, Clone, Copy)]
pub struct BundleIngester;

impl BundleIngester {
    pub fn new() -> Self {
        Self
    }

    /// Convert a Bundle into the sequence of events to append.
    ///
    /// Order is preserved from the bundle. Fails on the first entry
    /// that can't be turned into an event so the caller can surface a
    /// targeted error message.
    pub fn events_for(&self, bundle: &Bundle) -> Result<Vec<IngestedEntry>, BundleIngestError> {
        if !matches!(bundle.r#type, BundleType::Transaction | BundleType::Batch) {
            return Err(BundleIngestError::UnsupportedBundleType {
                got: bundle.r#type,
            });
        }

        let mut out = Vec::with_capacity(bundle.entry.len());
        for (index, entry) in bundle.entry.iter().enumerate() {
            out.push(self.entry_to_event(index, entry)?);
        }
        Ok(out)
    }

    fn entry_to_event(
        &self,
        index: usize,
        entry: &BundleEntry,
    ) -> Result<IngestedEntry, BundleIngestError> {
        let resource = entry
            .resource
            .as_ref()
            .ok_or(BundleIngestError::EntryMissingResource { index })?;

        let resource_type_str = resource
            .get("resourceType")
            .and_then(|v| v.as_str())
            .ok_or(BundleIngestError::EntryMissingResourceType { index })?;

        let kind = FhirResourceKind::from_resource_type(resource_type_str).ok_or_else(|| {
            BundleIngestError::EntryUnsupportedResource {
                index,
                resource_type: resource_type_str.to_string(),
            }
        })?;

        let action = match entry.request.as_ref() {
            Some(req) => action_for_method(&req.method).ok_or_else(|| {
                BundleIngestError::EntryUnknownMethod {
                    index,
                    method: req.method.clone(),
                }
            })?,
            None => {
                // Permit entries without request.method only when the
                // bundle is a `transaction` *response* (we don't accept
                // those here) — for ingestion, `request.method` is
                // mandatory.
                return Err(BundleIngestError::EntryMissingRequestMethod { index });
            }
        };

        let event = event_for_kind(kind, action, entry).map_err(|e| {
            BundleIngestError::Event {
                index,
                context: "encode resource",
                source: e,
            }
        })?;

        Ok(IngestedEntry { kind, event })
    }
}

/// FHIR REST verb → [`FhirAction`].
fn action_for_method(method: &str) -> Option<FhirAction> {
    match method.to_ascii_uppercase().as_str() {
        "POST" => Some(FhirAction::Create),
        "PUT" => Some(FhirAction::Update),
        "DELETE" => Some(FhirAction::Delete),
        _ => None,
    }
}

/// Decode the entry's `resource` to the typed shape implied by `kind`
/// and build the corresponding [`FhirEvent`].
fn event_for_kind(
    kind: FhirResourceKind,
    action: FhirAction,
    entry: &BundleEntry,
) -> Result<FhirEvent, FhirEventError> {
    match kind {
        FhirResourceKind::Patient => {
            let r = entry
                .as_resource::<Patient>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
        FhirResourceKind::Practitioner => {
            let r = entry
                .as_resource::<Practitioner>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
        FhirResourceKind::Organization => {
            let r = entry
                .as_resource::<Organization>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
        FhirResourceKind::Encounter => {
            let r = entry
                .as_resource::<Encounter>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
        FhirResourceKind::Observation => {
            let r = entry
                .as_resource::<Observation>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
        FhirResourceKind::Bundle => {
            let r = entry
                .as_resource::<Bundle>()
                .ok_or(FhirEventError::MissingId)??;
            FhirEvent::from_resource(action, &r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_fhir::resources::{BundleEntry, BundleEntryRequest, BundleType, Patient};

    fn patient_entry(id: &str, method: &str) -> BundleEntry {
        let p = Patient {
            id: Some(id.into()),
            ..Default::default()
        };
        BundleEntry {
            resource: Some(serde_json::to_value(&p).expect("serialise patient")),
            request: Some(BundleEntryRequest {
                method: method.into(),
                url: "Patient".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn transaction_bundle_with_one_patient_post_creates_one_event() {
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![patient_entry("alice-001", "POST")],
            ..Default::default()
        };
        let out = BundleIngester::new().events_for(&b).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FhirResourceKind::Patient);
        assert_eq!(out[0].event.action, FhirAction::Create);
        assert_eq!(out[0].event.resource_id, "alice-001");
        assert_eq!(out[0].event.resource_type, "Patient");
    }

    #[test]
    fn batch_bundle_is_also_supported() {
        let b = Bundle {
            r#type: BundleType::Batch,
            entry: vec![patient_entry("alice-001", "POST")],
            ..Default::default()
        };
        let out = BundleIngester::new().events_for(&b).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn document_bundle_is_rejected() {
        let b = Bundle {
            r#type: BundleType::Document,
            entry: vec![patient_entry("alice-001", "POST")],
            ..Default::default()
        };
        let err = BundleIngester::new().events_for(&b).unwrap_err();
        assert!(matches!(
            err,
            BundleIngestError::UnsupportedBundleType {
                got: BundleType::Document
            }
        ));
    }

    #[test]
    fn put_maps_to_update_and_delete_maps_to_delete() {
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![
                patient_entry("p1", "PUT"),
                patient_entry("p2", "DELETE"),
            ],
            ..Default::default()
        };
        let out = BundleIngester::new().events_for(&b).unwrap();
        assert_eq!(out[0].event.action, FhirAction::Update);
        assert_eq!(out[1].event.action, FhirAction::Delete);
    }

    #[test]
    fn unknown_method_is_rejected_with_index() {
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![
                patient_entry("alice-001", "POST"),
                patient_entry("bob-002", "PATCH"),
            ],
            ..Default::default()
        };
        let err = BundleIngester::new().events_for(&b).unwrap_err();
        assert!(matches!(
            err,
            BundleIngestError::EntryUnknownMethod { index: 1, ref method }
                if method == "PATCH"
        ));
    }

    #[test]
    fn missing_request_block_is_rejected() {
        let mut entry = patient_entry("alice-001", "POST");
        entry.request = None;
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![entry],
            ..Default::default()
        };
        let err = BundleIngester::new().events_for(&b).unwrap_err();
        assert!(matches!(
            err,
            BundleIngestError::EntryMissingRequestMethod { index: 0 }
        ));
    }

    #[test]
    fn unsupported_resource_type_is_rejected_by_name() {
        let entry = BundleEntry {
            resource: Some(serde_json::json!({
                "resourceType": "DiagnosticReport",
                "id": "dr1"
            })),
            request: Some(BundleEntryRequest {
                method: "POST".into(),
                url: "DiagnosticReport".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![entry],
            ..Default::default()
        };
        let err = BundleIngester::new().events_for(&b).unwrap_err();
        assert!(matches!(
            err,
            BundleIngestError::EntryUnsupportedResource { index: 0, ref resource_type }
                if resource_type == "DiagnosticReport"
        ));
    }

    #[test]
    fn mixed_resource_types_produce_distinct_kinds() {
        let p_entry = patient_entry("alice-001", "POST");
        let obs_entry = BundleEntry {
            resource: Some(serde_json::json!({
                "resourceType": "Observation",
                "id": "o1",
                "status": "final",
                "code": {"text": "HR"},
                "subject": {"reference": "Patient/alice-001"}
            })),
            request: Some(BundleEntryRequest {
                method: "POST".into(),
                url: "Observation".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let b = Bundle {
            r#type: BundleType::Transaction,
            entry: vec![p_entry, obs_entry],
            ..Default::default()
        };
        let out = BundleIngester::new().events_for(&b).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, FhirResourceKind::Patient);
        assert_eq!(out[1].kind, FhirResourceKind::Observation);
    }
}
