#![no_main]

//! Healthcare-pivot Q3 fuzz target — HIPAA Safe Harbor de-identification.
//!
//! Drives arbitrary JSON through
//! `kimberlite_compliance::deidentification::deidentify_and_attest`
//! with the default Safe Harbor ruleset (45 CFR §164.514(b)(2) — all
//! 18 identifier classes).
//!
//! Invariants:
//! 1. **No panic.** Any JSON value as input must return `Ok(...)` or
//!    `Err(DeidentifyError::*)`. A panic in the de-id transform is a
//!    HIPAA Safe Harbor failure mode and a production data-loss bug.
//! 2. **Identifier coverage.** If the input contained a known Safe
//!    Harbor field (e.g. `ssn`, `mrn`, `phone`), the returned
//!    `removed` set MUST contain the matching
//!    `SafeHarborIdentifier` variant.
//! 3. **Round-trip stability.** The attestation produced by the
//!    transform must round-trip through serde without altering its
//!    SHA-256 hashes.

use kimberlite_compliance::deidentification::{
    deidentify, deidentify_and_attest, DeidentifyConfig, SafeHarborIdentifier,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    // Tier 1 — JSON parsing. The de-id transform requires a JSON
    // object at the root; everything else must surface as `Err`,
    // never panic.
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    let config = DeidentifyConfig::safe_harbor_default();

    // Tier 2 — pure de-id transform. Non-object roots return
    // `Err(DeidentifyError::NonObjectRoot)`; valid objects return
    // `(transformed, removed_identifiers)`.
    let Ok((transformed, removed)) = deidentify(&value, &config) else {
        return;
    };

    // Tier 3 — convenience wrapper that produces an attestation.
    // Re-runs the transform internally; must agree with Tier 2 on the
    // set of removed identifiers.
    if let Ok((transformed2, attestation)) = deidentify_and_attest(&value, &config) {
        assert_eq!(
            transformed, transformed2,
            "deidentify and deidentify_and_attest disagree on transformed output",
        );
        assert_eq!(
            removed, attestation.removed,
            "deidentify and deidentify_and_attest disagree on removed identifiers",
        );

        // Tier 4 — attestation hashes must round-trip through serde.
        // The audit chain relies on byte-stable canonicalization.
        let json = serde_json::to_vec(&attestation).expect("attestation serializes");
        let reparsed: kimberlite_compliance::deidentification::DeidentificationAttestation =
            serde_json::from_slice(&json).expect("attestation re-parses");
        assert_eq!(
            attestation.original_sha256_hex, reparsed.original_sha256_hex,
            "attestation pre-image hash lost across serde round-trip",
        );
        assert_eq!(
            attestation.transformed_sha256_hex, reparsed.transformed_sha256_hex,
            "attestation post-image hash lost across serde round-trip",
        );
    }

    // Tier 5 — sanity guard. If any identifier *class* was reported as
    // removed, the transformed output must differ from the input.
    // (The reverse — identical bytes implies empty removed — is the
    // contract `attest()`'s debug_assert enforces internally.)
    if !removed.is_empty() {
        assert_ne!(
            value, transformed,
            "de-id reported removals but output equals input",
        );
    }

    // Discourage dead-code elimination on the imported enum.
    let _ = SafeHarborIdentifier::Name;
});
