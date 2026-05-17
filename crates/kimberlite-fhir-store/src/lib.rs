//! # `kimberlite-fhir-store`: FHIR ↔ Kimberlite storage adapter.
//!
//! The bridge between [`kimberlite_fhir`] typed resources and the
//! Kimberlite kernel's event-sourced storage model. Three layers:
//!
//! 1. [`event`] — the on-disk event encoding. A [`FhirEvent`] carries
//!    a typed FHIR action together with the canonical FHIR JSON bytes
//!    of the resource, so downstream auditors can re-emit the exact
//!    payload that was committed and hash-chain over byte-stable
//!    bytes.
//! 2. [`streams`] — naming convention and healthcare-first stream
//!    metadata. Every FHIR resource type lives in its own stream per
//!    tenant, defaulted to [`kimberlite_types::DataClass::PHI`].
//! 3. [`projection`] — typed row structs for the SQL-queryable
//!    projection of each resource. The indexed columns each resource
//!    type exposes for search (`family_name`, `mrn`, `loinc_code`,
//!    etc.) without paying for full-resource scans.
//! 4. [`bundle`] — transaction-bundle ingester that fans a
//!    [`kimberlite_fhir::Bundle`] into the typed events that the
//!    server should append.
//!
//! The adapter is intentionally **pure transformation**: no I/O, no
//! clocks, no randomness in the core path (FCIS). The shell that
//! executes the appends lives in the server / SDK; this crate gives
//! it the data shapes to write.

#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod bundle;
pub mod event;
pub mod projection;
pub mod streams;

pub use bundle::{BundleIngestError, BundleIngester, IngestedEntry};
pub use event::{FhirAction, FhirEvent, FhirEventError};
pub use projection::{
    EncounterProjection, ObservationProjection, OrganizationProjection, PatientProjection,
    PractitionerProjection, Projection,
};
pub use streams::{FhirResourceKind, fhir_stream_name, fhir_stream_policy};

#[cfg(test)]
mod tests;
