//! Runtime context for an authorized SMART session.
//!
//! When the authorization server issues an access token, it may
//! include launch-context claims that bind the token to a specific
//! Patient, Encounter, or `fhirUser`. The [`LaunchContext`] carries
//! those bindings at request time so the authorize() decision can
//! enforce `patient/...` scopes correctly.

use serde::{Deserialize, Serialize};

/// What the caller is trying to do.
///
/// SMART v1 collapses CRUD onto two verbs: `read` covers GET
/// (single-read + search); `write` covers POST/PUT/PATCH/DELETE.
/// SMART v2 splits these further (c/r/u/d/s/$); we'll add finer
/// actions when v2 scopes ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
}

/// Runtime context for an authorized SMART session.
///
/// Populated from the SMART claims on the issued access token. All
/// fields are optional: a `system/...` token carries no patient
/// context; a standalone-launch token without `launch/patient`
/// carries no patient binding either.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchContext {
    /// FHIR `Patient` logical id the session is bound to. Required
    /// when `patient/...` scopes are in play.
    pub patient_id: Option<String>,
    /// FHIR `Encounter` logical id (rare; some EHR launches bind
    /// the active visit).
    pub encounter_id: Option<String>,
    /// `fhirUser` — a reference like `Practitioner/dr-jones` or
    /// `Patient/alice-001` identifying the user driving the app.
    pub fhir_user: Option<String>,
}

impl LaunchContext {
    /// Build an empty launch context. Useful for `system/...` tokens
    /// where no patient/encounter/user binding applies.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a patient-bound context — the canonical
    /// standalone-launch shape after `launch/patient` resolves.
    pub fn for_patient(patient_id: impl Into<String>) -> Self {
        Self {
            patient_id: Some(patient_id.into()),
            ..Default::default()
        }
    }
}
