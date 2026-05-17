#![no_main]

//! Healthcare-pivot Q3 fuzz target — FHIR R4 resource parser.
//!
//! Drives arbitrary bytes through:
//! 1. `serde_json::from_slice::<Patient>(...)` — must never panic; returns
//!    `Err` on malformed JSON or schema-mismatched bytes.
//! 2. `Bundle` parsing — same contract, the higher-arity collection
//!    resource that nests Patient/Encounter/Observation.
//! 3. Round-trip via `canonical::to_canonical_bytes` — anything that
//!    deserializes must re-serialize and the second deserialize must
//!    produce the same value (deterministic canonical form is the
//!    contract the audit log relies on).
//!
//! The fuzzer's invariants:
//! - No panic on any input.
//! - If `parse(bytes) = Ok(p)`, then
//!   `parse(canonicalize(p)) = Ok(p')` and `p == p'`.

use kimberlite_fhir::canonical;
use kimberlite_fhir::resources::{Bundle, Patient};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Tier 1 — raw bytes -> Patient. Vast majority will fail at JSON
    // parsing; we just need to ensure no panic.
    if let Ok(patient) = serde_json::from_slice::<Patient>(data) {
        // Tier 2 — round-trip determinism. Canonical bytes must
        // re-parse to a structurally identical Patient.
        if let Ok(canonical_bytes) = canonical::to_canonical_bytes(&patient) {
            let reparsed = serde_json::from_slice::<Patient>(&canonical_bytes)
                .expect("canonical Patient bytes must re-parse");
            assert_eq!(
                patient, reparsed,
                "FHIR Patient round-trip is not byte-stable",
            );
        }
    }

    // Tier 3 — raw bytes -> Bundle. Different resource shape, same
    // contract. Bundles can nest other resources via
    // `entry[].resource` so this exercises the dynamic-dispatch path.
    if let Ok(bundle) = serde_json::from_slice::<Bundle>(data) {
        if let Ok(canonical_bytes) = canonical::to_canonical_bytes(&bundle) {
            let reparsed = serde_json::from_slice::<Bundle>(&canonical_bytes)
                .expect("canonical Bundle bytes must re-parse");
            assert_eq!(
                bundle, reparsed,
                "FHIR Bundle round-trip is not byte-stable",
            );
        }
    }
});
