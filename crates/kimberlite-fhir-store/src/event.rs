//! The on-disk event shape — a typed action plus the canonical FHIR
//! JSON of the resource.
//!
//! `FhirEvent` is what each entry in a per-resource stream contains.
//! It is the byte sequence the audit log hash-chain commits over and
//! the byte sequence the projector decodes to derive search-indexed
//! rows.
//!
//! ## Wire shape
//!
//! ```text
//! postcard {
//!   version:        u8,            // event-encoding version (= 1)
//!   action:         FhirAction,    // Create | Update | Delete
//!   resource_type:  String,        // "Patient", "Observation", ...
//!   resource_id:    String,        // logical id within the tenant
//!   version_id:     Option<String>,// FHIR Meta.versionId, if known
//!   canonical_json: Vec<u8>,       // canonical FHIR JSON bytes
//! }
//! ```
//!
//! `canonical_json` is the byte sequence produced by
//! [`kimberlite_fhir::canonical::to_canonical_bytes`], so two encodes
//! of the same resource agree byte-for-byte — required for the audit
//! hash-chain.

use kimberlite_fhir::canonical::to_canonical_bytes;
use kimberlite_fhir::resource::FhirResource;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire-format version. Bump only when the postcard shape changes.
pub const FHIR_EVENT_VERSION: u8 = 1;

/// The action a FHIR event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FhirAction {
    /// New resource (POST in REST terms; first occurrence of a logical id).
    Create,
    /// In-place update of an existing resource (PUT).
    Update,
    /// Resource deletion (DELETE). The `canonical_json` payload is
    /// still populated with the *prior* canonical bytes so the audit
    /// log retains what was deleted.
    Delete,
}

/// Errors from encoding or decoding a [`FhirEvent`].
#[derive(Debug, Error)]
pub enum FhirEventError {
    #[error("FHIR resource error: {0}")]
    Resource(#[from] kimberlite_fhir::resource::ResourceError),

    #[error("canonical JSON error: {0}")]
    Canonical(#[from] kimberlite_fhir::canonical::CanonicalError),

    #[error("postcard encode/decode error: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("FHIR resource missing required logical id")]
    MissingId,

    #[error("unsupported FHIR event encoding version: {found} (expected {expected})")]
    VersionMismatch { found: u8, expected: u8 },

    #[error(
        "encoded resource_type `{encoded}` does not match requested type `{requested}` on decode"
    )]
    ResourceTypeMismatch {
        encoded: String,
        requested: &'static str,
    },
}

/// One event in a FHIR resource stream.
///
/// The struct is intentionally flat (no nested `Option<…>` chains) so
/// the on-disk postcard size is small and decoding is allocation-light.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FhirEvent {
    /// Encoding version (see [`FHIR_EVENT_VERSION`]).
    pub version: u8,
    pub action: FhirAction,
    pub resource_type: String,
    pub resource_id: String,
    /// FHIR `Meta.versionId` if the resource carried one, else `None`.
    pub version_id: Option<String>,
    /// Canonical FHIR JSON bytes — the fidelity-preserving payload.
    pub canonical_json: Vec<u8>,
}

impl FhirEvent {
    /// Build a `FhirEvent` from a typed FHIR resource.
    ///
    /// The resource MUST carry a logical id (FHIR `id`). Returns
    /// [`FhirEventError::MissingId`] otherwise — passing an
    /// unidentified resource to storage is a forensic smell.
    pub fn from_resource<T: FhirResource>(
        action: FhirAction,
        resource: &T,
    ) -> Result<Self, FhirEventError> {
        let resource_id = resource.id().ok_or(FhirEventError::MissingId)?.to_string();
        let canonical_json = to_canonical_bytes(resource)?;
        Ok(Self {
            version: FHIR_EVENT_VERSION,
            action,
            resource_type: T::RESOURCE_TYPE.to_string(),
            resource_id,
            version_id: None,
            canonical_json,
        })
    }

    /// Decode the `canonical_json` payload back into a typed resource.
    ///
    /// Asserts that the encoded `resource_type` matches `T::RESOURCE_TYPE`
    /// — a Patient event decoded as Observation is rejected.
    pub fn to_resource<T: FhirResource>(&self) -> Result<T, FhirEventError> {
        if self.resource_type != T::RESOURCE_TYPE {
            return Err(FhirEventError::ResourceTypeMismatch {
                encoded: self.resource_type.clone(),
                requested: T::RESOURCE_TYPE,
            });
        }
        Ok(T::from_json(&self.canonical_json)?)
    }

    /// Serialise to the postcard wire format.
    pub fn encode(&self) -> Result<Vec<u8>, FhirEventError> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Deserialise from the postcard wire format, verifying the
    /// encoding version.
    pub fn decode(bytes: &[u8]) -> Result<Self, FhirEventError> {
        let event: Self = postcard::from_bytes(bytes)?;
        if event.version != FHIR_EVENT_VERSION {
            return Err(FhirEventError::VersionMismatch {
                found: event.version,
                expected: FHIR_EVENT_VERSION,
            });
        }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_fhir::resources::{Patient, PatientGender};

    fn alice() -> Patient {
        Patient {
            id: Some("alice-001".into()),
            gender: Some(PatientGender::Female),
            birth_date: Some("1980-05-12".into()),
            ..Default::default()
        }
    }

    #[test]
    fn from_resource_captures_id_and_type() {
        let evt = FhirEvent::from_resource(FhirAction::Create, &alice()).unwrap();
        assert_eq!(evt.resource_type, "Patient");
        assert_eq!(evt.resource_id, "alice-001");
        assert_eq!(evt.action, FhirAction::Create);
        assert_eq!(evt.version, FHIR_EVENT_VERSION);
    }

    #[test]
    fn from_resource_rejects_missing_id() {
        let p = Patient {
            id: None,
            ..Default::default()
        };
        let err = FhirEvent::from_resource(FhirAction::Create, &p).unwrap_err();
        assert!(matches!(err, FhirEventError::MissingId));
    }

    #[test]
    fn round_trip_resource_through_event() {
        let p = alice();
        let evt = FhirEvent::from_resource(FhirAction::Create, &p).unwrap();
        let decoded: Patient = evt.to_resource().unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_event_through_postcard() {
        let evt = FhirEvent::from_resource(FhirAction::Update, &alice()).unwrap();
        let bytes = evt.encode().unwrap();
        let decoded = FhirEvent::decode(&bytes).unwrap();
        assert_eq!(evt, decoded);
    }

    #[test]
    fn canonical_json_is_byte_stable() {
        // The hash-chain audit property: the SAME resource always
        // produces the SAME canonical_json bytes.
        let a = FhirEvent::from_resource(FhirAction::Create, &alice())
            .unwrap()
            .canonical_json;
        let b = FhirEvent::from_resource(FhirAction::Create, &alice())
            .unwrap()
            .canonical_json;
        assert_eq!(a, b);
    }

    #[test]
    fn to_resource_rejects_wrong_type() {
        let evt = FhirEvent::from_resource(FhirAction::Create, &alice()).unwrap();
        let err: FhirEventError = evt
            .to_resource::<kimberlite_fhir::resources::Observation>()
            .unwrap_err();
        assert!(matches!(
            err,
            FhirEventError::ResourceTypeMismatch { encoded, requested }
                if encoded == "Patient" && requested == "Observation"
        ));
    }

    #[test]
    fn decode_rejects_version_mismatch() {
        let mut evt = FhirEvent::from_resource(FhirAction::Create, &alice()).unwrap();
        evt.version = 99;
        let bytes = evt.encode().unwrap();
        let err = FhirEvent::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            FhirEventError::VersionMismatch {
                found: 99,
                expected: FHIR_EVENT_VERSION
            }
        ));
    }
}
