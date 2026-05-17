#![no_main]

//! Healthcare-pivot Q3 fuzz target — audit-log signature & canonical
//! serialization round-trip.
//!
//! Drives arbitrary bytes through two paths:
//!
//! 1. **RecordSignature construction** — `RecordSignature::try_new`
//!    receives caller-supplied hash + signer + signature bytes. The
//!    fallible constructor enforces non-empty hash, non-empty signer,
//!    and exactly 64-byte Ed25519 signatures (per
//!    `signature_binding.rs`). The fuzzer asserts that any input
//!    either yields a `RecordSignature` or a typed
//!    `SignatureBindingError`, never a panic.
//!
//! 2. **Postcard canonical round-trip** — every successfully-built
//!    `RecordSignature` must round-trip through `postcard` (the same
//!    canonical encoding the audit-event hash chain uses). The bytes
//!    must re-deserialize to a structurally identical signature.
//!
//! Together these cover the surface that an OCR audit relies on: the
//! signed-witness path through which compliance can prove "this PHI
//! event was authored by this user at this time" — corruption of
//! which is a HIPAA §164.530(j)(2) audit-integrity failure.

use chrono::{DateTime, TimeZone, Utc};
use kimberlite_compliance::signature_binding::{
    RecordSignature, SignatureBindingError, SignatureMeaning,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We need at least: 1 byte for meaning, 8 for the timestamp,
    // 1 for the hash-length nibble, 1 for the signer-length nibble.
    // Anything shorter we treat as empty input.
    if data.len() < 11 {
        return;
    }

    // Decode a SignatureMeaning from the first byte.
    let meaning = match data[0] % 3 {
        0 => SignatureMeaning::Authorship,
        1 => SignatureMeaning::Review,
        _ => SignatureMeaning::Approval,
    };

    // Decode a timestamp from the next 8 bytes (treated as seconds
    // since the Unix epoch). Clamp to a representable range so we
    // never feed `chrono::Utc.timestamp_opt` an out-of-range value.
    let raw_ts = i64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let clamped_ts = raw_ts.rem_euclid(4_000_000_000); // ~ year 2096
    let signed_at: DateTime<Utc> = Utc
        .timestamp_opt(clamped_ts, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().expect("epoch is valid"));

    // Split the remaining bytes into hash, signer, signature according
    // to two length nibbles. Modular slicing keeps the splits in range
    // regardless of input size.
    let body = &data[9..];
    let hash_len = (data[9] as usize) % (body.len() + 1);
    let signer_len_byte = data[10] as usize;
    let after_hash = &body[hash_len.min(body.len())..];
    let signer_len = signer_len_byte % (after_hash.len() + 1);
    let signer_bytes = &after_hash[..signer_len.min(after_hash.len())];
    let sig_bytes = &after_hash[signer_len.min(after_hash.len())..];

    let hash_vec = body[..hash_len.min(body.len())].to_vec();
    let signer_id = String::from_utf8_lossy(signer_bytes).to_string();
    let sig_vec = sig_bytes.to_vec();

    // Tier 1 — try_new is fallible. It must return either a valid
    // RecordSignature or a typed error; never panic.
    let result = RecordSignature::try_new(
        "fuzz-sig".to_string(),
        hash_vec.clone(),
        signer_id.clone(),
        meaning,
        signed_at,
        sig_vec.clone(),
    );

    match result {
        Ok(sig) => {
            // Tier 2 — postcard canonical encoding must round-trip.
            // The audit-log hash chain depends on this property:
            // `compute_event_hash` postcard-serializes the event with
            // event_hash zeroed and feeds the bytes into SHA-256. If
            // round-trip is unstable, an honest replay surfaces as a
            // chain break.
            let encoded = postcard::to_allocvec(&sig).expect("RecordSignature serializes");
            let decoded: RecordSignature =
                postcard::from_bytes(&encoded).expect("RecordSignature re-deserializes");
            assert_eq!(
                sig.signature_id, decoded.signature_id,
                "signature_id lost across postcard round-trip",
            );
            assert_eq!(
                sig.record_hash, decoded.record_hash,
                "record_hash lost across postcard round-trip",
            );
            assert_eq!(
                sig.signer_id, decoded.signer_id,
                "signer_id lost across postcard round-trip",
            );
            assert_eq!(
                sig.signature_bytes, decoded.signature_bytes,
                "signature_bytes lost across postcard round-trip",
            );
        }
        Err(SignatureBindingError::EmptyHash) => {
            // Expected: hash_len == 0 (or original `body` was empty).
        }
        Err(SignatureBindingError::EmptySigner) => {
            // Expected: signer_bytes was empty after the split.
        }
        Err(SignatureBindingError::WrongSignatureLength { .. }) => {
            // Expected: sig_vec.len() != 64.
        }
    }
});
