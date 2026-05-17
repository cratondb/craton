//! # `kimberlite-fhir`: FHIR R4 typed resource model
//!
//! Hand-written FHIR R4 (HL7 4.0.1) types for the resources Kimberlite's
//! healthcare wedge needs to round-trip end-to-end:
//!
//! - **Identity**: [`Patient`], [`Practitioner`], [`Organization`]
//! - **Clinical**: [`Encounter`], [`Observation`]
//! - **Transport**: [`Bundle`]
//!
//! All types serialise to and deserialise from canonical FHIR R4 JSON.
//! Unknown fields are tolerated on read (forward compatibility with R5
//! extensions, profile-specific extras) and round-trip through the
//! [`extras`][resource::FhirExtras] sidecar so exports re-emit the
//! original payload byte-for-byte.
//!
//! ## Design
//!
//! - **Parse, don't validate**: every resource has a strongly-typed Rust
//!   representation. Validation happens once at the JSON boundary.
//! - **Healthcare-first defaults**: a stream of these resources is PHI
//!   by construction (see [`kimberlite_types::DataClass`]).
//! - **No `unsafe`**: workspace lint denies it.
//! - **Canonical JSON**: [`canonical::to_canonical_json`] emits a
//!   deterministic, byte-stable serialisation suitable for hash-chain
//!   inclusion in the Kimberlite audit log.
//!
//! ## Scope
//!
//! This is the **wedge** resource set, not the full R4 catalogue. Each
//! resource is a faithful FHIR R4 representation of the fields most
//! clinical / EHR-adjacent workloads use; anything beyond is preserved
//! via [`FhirExtras`][resource::FhirExtras] on read and re-emitted on
//! write. Add resources to this crate as healthcare workloads demand.

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

pub mod canonical;
pub mod datatypes;
pub mod fhirpath;
pub mod resource;
pub mod resources;

pub use datatypes::{
    Address, CodeableConcept, Coding, ContactPoint, HumanName, Identifier, Meta, Period, Quantity,
    Reference,
};
pub use resource::{FhirExtras, FhirResource, ResourceError};
pub use resources::{Bundle, Encounter, Observation, Organization, Patient, Practitioner};

#[cfg(test)]
mod tests;
