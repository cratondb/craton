//! Shared resource trait and error type.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that arise constructing or validating FHIR resources.
#[derive(Debug, Error)]
pub enum ResourceError {
    /// JSON serialisation/deserialisation failed.
    #[error("FHIR JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The `resourceType` field did not match the expected resource.
    #[error("expected resourceType `{expected}`, found `{actual}`")]
    WrongResourceType {
        expected: &'static str,
        actual: String,
    },

    /// A required field was missing or empty.
    #[error("required field `{0}` missing or empty")]
    MissingRequired(&'static str),
}

/// Canonical FHIR fields every resource carries — fields that aren't
/// part of our typed schema but appear on real-world payloads.
///
/// Anything from the FHIR R4 spec or downstream profiles that we don't
/// model explicitly lands here on deserialisation and is re-emitted
/// verbatim on serialisation. This is the **fidelity** half of the
/// "typed + canonical JSON" promise: a Patient written by Epic and
/// read by Kimberlite re-emits the original Epic-specific extensions
/// untouched.
///
/// Stored as a flat `serde_json::Value` map; keys collide with typed
/// fields only by accident, in which case the typed field wins on
/// serialisation (typed fields are written first; `#[serde(flatten)]`
/// of extras merges last and overwrite-on-collision is the serde
/// default for flatten over a `Map`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct FhirExtras(pub serde_json::Map<String, serde_json::Value>);

impl FhirExtras {
    /// Returns true if no unknown fields were captured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Trait every FHIR resource in this crate implements.
///
/// The `RESOURCE_TYPE` constant pairs with the JSON `resourceType`
/// field and is enforced on deserialisation by each resource's serde
/// implementation. Implementors can call [`FhirResource::from_json`]
/// to parse and validate the type tag in one step.
pub trait FhirResource: Sized + Serialize + for<'de> Deserialize<'de> {
    /// The literal `resourceType` value FHIR R4 assigns this resource.
    const RESOURCE_TYPE: &'static str;

    /// The logical id of the resource, if assigned.
    fn id(&self) -> Option<&str>;

    /// Parse a FHIR R4 JSON payload into this resource type.
    ///
    /// Verifies that `resourceType` matches `RESOURCE_TYPE`; surfaces a
    /// [`ResourceError::WrongResourceType`] if not (a Patient JSON
    /// deserialised as Observation is a forensic smell, not a benign
    /// type mismatch).
    fn from_json(bytes: &[u8]) -> Result<Self, ResourceError> {
        let v: serde_json::Value = serde_json::from_slice(bytes)?;
        if let Some(rt) = v.get("resourceType").and_then(|x| x.as_str()) {
            if rt != Self::RESOURCE_TYPE {
                return Err(ResourceError::WrongResourceType {
                    expected: Self::RESOURCE_TYPE,
                    actual: rt.to_string(),
                });
            }
        }
        Ok(serde_json::from_value(v)?)
    }

    /// Emit this resource as FHIR R4 JSON.
    fn to_json(&self) -> Result<Vec<u8>, ResourceError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Emit this resource as a FHIR R4 JSON string.
    fn to_json_string(&self) -> Result<String, ResourceError> {
        Ok(serde_json::to_string(self)?)
    }
}
