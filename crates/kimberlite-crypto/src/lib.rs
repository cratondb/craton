//! # kmb-crypto: Cryptographic primitives for `Kimberlite`
//!
//! This crate provides the cryptographic foundation for `Kimberlite`'s
//! tamper-evident append-only log.
//!
//! ## Modules
//!
//! | Module | Purpose | Status |
//! |--------|---------|--------|
//! | [`chain`] | Hash chains for tamper evidence (SHA-256) | ✅ Ready |
//! | [`hash`] | Dual-hash abstraction (SHA-256/BLAKE3) | ✅ Ready |
//! | [`signature`] | Ed25519 signatures for non-repudiation | ✅ Ready |
//! | [`encryption`] | AES-256-GCM encryption and key wrapping | ✅ Ready |
//!
//! ## Quick Start
//!
//! ```
//! use kimberlite_crypto::{chain_hash, ChainHash, SigningKey, internal_hash, HashPurpose};
//! use kimberlite_crypto::{EncryptionKey, WrappedKey};
//!
//! // Build a tamper-evident chain of records (SHA-256 for compliance)
//! let hash0 = chain_hash(None, b"genesis record");
//! let hash1 = chain_hash(Some(&hash0), b"second record");
//!
//! // Fast internal hash (BLAKE3) for deduplication
//! let fingerprint = internal_hash(b"content to deduplicate");
//!
//! // Sign records for non-repudiation
//! let signing_key = SigningKey::generate();
//! let signature = signing_key.sign(hash1.as_bytes());
//!
//! // Verify the signature
//! let verifying_key = signing_key.verifying_key();
//! assert!(verifying_key.verify(hash1.as_bytes(), &signature).is_ok());
//!
//! // Wrap a key for secure storage (key hierarchy)
//! let kek = EncryptionKey::generate();
//! let dek = EncryptionKey::generate();
//! let wrapped = WrappedKey::new(&kek, &dek.to_bytes());
//! let unwrapped = wrapped.unwrap_key(&kek).unwrap();
//! assert_eq!(dek.to_bytes(), unwrapped);
//! ```
//!
//! ## PRESSURECRAFT lints
//!
//! This crate opts in to strict lints that encode PRESSURECRAFT rules:
//! no `.unwrap()` (use `.expect("invariant: …")`), no bare `panic!`,
//! no `todo!`/`unimplemented!` stubs, no functions longer than the
//! `too-many-lines-threshold` in `clippy.toml`. Test code is exempt.

#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::too_many_lines
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::too_many_lines
    )
)]

pub mod anonymize;
pub mod chain;
pub mod crc32;
pub mod encryption;
pub mod error;
pub mod field;
pub mod hash;
pub mod kms;
pub mod signature;

// Verified cryptographic implementations with Coq proof certificates
// Enable with: features = ["verified-crypto"]
#[cfg(feature = "verified-crypto")]
pub mod verified;

#[cfg(test)]
mod tests_assertions;

// Kani verification harnesses for bounded model checking
#[cfg(kani)]
mod kani_proofs;

// Re-export primary types at crate root for convenience
pub use anonymize::{
    DatePrecision, GeoLevel, KAnonymityResult, MaskStyle, check_k_anonymity, generalize_age,
    generalize_numeric, generalize_zip, mask, redact, truncate_date,
};
pub use chain::{ChainHash, HASH_LENGTH, chain_hash};
pub use crc32::{Crc32, crc32};
pub use encryption::{
    CachedCipher, DataEncryptionKey, EncryptionKey, InMemoryMasterKey, KeyEncryptionKey,
    MasterKeyProvider, WrappedKey,
};
pub use error::CryptoError;
pub use field::{
    FieldKey, ReversibleToken, TOKEN_LENGTH, Token, decrypt_field, encrypt_field, matches_token,
    tokenize,
};
pub use hash::{HashAlgorithm, HashPurpose, InternalHash, hash_with_purpose, internal_hash};
pub use signature::{Signature, SigningKey, VerifyingKey};
