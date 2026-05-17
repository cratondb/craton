//! External Key-Management-Service (KMS) providers for Bring-Your-Own-Key.
//!
//! Q3.2 of the healthcare pivot. Healthcare buyers — especially payers,
//! RCM vendors, and federal-health (VA, IHS, DoD) — expect KEKs to live
//! in their cloud KMS, not in the application process. This module
//! defines the abstraction that any cloud KMS plugs into, ships an
//! in-memory mock suitable for development and CI, and documents the
//! AWS / GCP / Azure integration patterns so operators can wire in
//! their preferred provider without touching this crate.
//!
//! # The shape of envelope encryption with an external KMS
//!
//! ```text
//! Cloud KMS (root key — never leaves)
//!     │
//!     │  encrypt(plaintext_kek_bytes) ─► ciphertext blob
//!     │  decrypt(ciphertext blob)     ─► plaintext_kek_bytes
//!     ▼
//! Kimberlite KEK (held in memory only while needed)
//!     │
//!     └── wraps ──► DataEncryptionKey (per-tenant)
//! ```
//!
//! The root key (cloud-side) is referenced by an opaque
//! [`KmsKeyRef`] (ARN / resource name / vault URI). The KEK round-trips
//! through the cloud as a [`SealedKey`] ciphertext blob — opaque,
//! provider-specific encoding that Kimberlite stores alongside tenant
//! metadata.
//!
//! # Implementing a new provider
//!
//! Implement [`KmsProvider`]:
//!
//! ```ignore
//! use kimberlite_crypto::kms::{KmsProvider, KmsKeyRef, SealedKey, KmsError};
//!
//! struct MyKms { /* SDK client */ }
//!
//! impl KmsProvider for MyKms {
//!     fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
//!         // call the cloud's Encrypt API; return ciphertext blob
//!         todo!()
//!     }
//!     fn open(&self, key_ref: &KmsKeyRef, sealed: &SealedKey) -> Result<Vec<u8>, KmsError> {
//!         // call the cloud's Decrypt API; return plaintext bytes
//!         todo!()
//!     }
//!     fn provider_name(&self) -> &'static str { "my-kms" }
//! }
//! ```
//!
//! Then wrap it with [`KmsMasterKey`] to plug into Kimberlite's existing
//! [`MasterKeyProvider`] hierarchy.

use crate::CryptoError;
use crate::encryption::{EncryptionKey, KEY_LENGTH, KeyEncryptionKey, WrappedKey};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

/// Opaque reference to a key in the external KMS.
///
/// AWS:   `arn:aws:kms:us-east-1:123456789012:key/abcd1234-...`
/// GCP:   `projects/p/locations/l/keyRings/r/cryptoKeys/k`
/// Azure: `https://vault.vault.azure.net/keys/keyname/version`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsKeyRef(String);

impl KmsKeyRef {
    pub fn new(s: impl Into<String>) -> Self {
        let s: String = s.into();
        assert!(!s.is_empty(), "KmsKeyRef cannot be empty");
        Self(s)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider-opaque ciphertext returned by `seal` and consumed by `open`.
///
/// Kimberlite treats this as a black-box byte blob — the provider's
/// internal format is none of our business. We persist it alongside
/// the tenant's wrapped-KEK record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKey(Vec<u8>);

impl SealedKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "SealedKey cannot be empty");
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("KMS key not found: {0}")]
    KeyNotFound(String),

    #[error("KMS authentication failure: {0}")]
    AuthError(String),

    #[error("KMS network / IO error: {0}")]
    Transport(String),

    #[error("KMS rejected the operation: {0}")]
    OperationDenied(String),

    #[error("KMS returned malformed ciphertext")]
    Malformed,

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Abstraction over an external KMS.
///
/// Implementations call the provider's encrypt / decrypt API. The
/// trait is intentionally minimal — anything fancier (key rotation,
/// auditing, region-specific keys) is a provider implementation detail.
pub trait KmsProvider: Send + Sync {
    /// Seal (encrypt) `plaintext` against the KMS-managed root key
    /// identified by `key_ref`. Returns a provider-opaque ciphertext.
    fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError>;

    /// Open (decrypt) `sealed`, returning the original plaintext.
    /// `key_ref` should match the one used to seal; some providers
    /// (AWS KMS with key-ID hint) tolerate `None` here.
    fn open(&self, key_ref: &KmsKeyRef, sealed: &SealedKey) -> Result<Vec<u8>, KmsError>;

    /// Stable provider identifier for telemetry and audit logs.
    fn provider_name(&self) -> &'static str;
}

/// Pairs a [`KmsProvider`] with a [`KmsKeyRef`] identifying the
/// cloud-side root key for a single tenant or environment. This is
/// the integration point operators use to wire an external KMS into
/// Kimberlite's key hierarchy.
///
/// Unlike the in-process [`crate::encryption::MasterKeyProvider`],
/// the KMS path uses a variable-length [`SealedKey`] blob rather
/// than the fixed-shape `WrappedKey` envelope — real cloud KMS
/// ciphertexts carry provider-specific metadata that doesn't fit
/// the local AES-GCM shape.
pub struct KmsMasterKey<P: KmsProvider> {
    provider: P,
    key_ref: KmsKeyRef,
}

impl<P: KmsProvider> KmsMasterKey<P> {
    pub fn new(provider: P, key_ref: KmsKeyRef) -> Self {
        Self { provider, key_ref }
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.provider_name()
    }

    pub fn key_ref(&self) -> &KmsKeyRef {
        &self.key_ref
    }

    /// Seal raw bytes against the KMS root key. The caller persists
    /// the returned [`SealedKey`] alongside the tenant record.
    pub fn seal_raw(&self, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
        self.provider.seal(&self.key_ref, plaintext)
    }

    /// Open a previously sealed key. Mirror of `seal_raw`.
    pub fn open_raw(&self, sealed: &SealedKey) -> Result<Vec<u8>, KmsError> {
        self.provider.open(&self.key_ref, sealed)
    }

    /// Generate a new tenant KEK and seal it against the KMS root key
    /// in one call. Returns the in-memory KEK (for immediate use) and
    /// the [`SealedKey`] (for persistence).
    ///
    /// Constructs the KEK from raw CSPRNG bytes so we can both seal
    /// the bytes against the cloud KMS *and* hand back the in-memory
    /// KEK without ever exposing a `to_bytes` accessor on the KEK
    /// type itself.
    pub fn generate_sealed_kek(&self) -> Result<(KeyEncryptionKey, SealedKey), KmsError> {
        let mut bytes = [0u8; KEY_LENGTH];
        crate::encryption::fill_random(&mut bytes);
        let sealed = self.provider.seal(&self.key_ref, &bytes)?;
        let kek = KeyEncryptionKey::from_bytes(&bytes);
        // Zero out the local copy now that the KEK owns its own.
        bytes.fill(0);
        Ok((kek, sealed))
    }

    /// Restore a tenant KEK from its sealed form. Performs one round
    /// trip to the KMS.
    pub fn restore_sealed_kek(&self, sealed: &SealedKey) -> Result<KeyEncryptionKey, KmsError> {
        let plaintext = self.provider.open(&self.key_ref, sealed)?;
        let bytes: [u8; KEY_LENGTH] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| KmsError::Malformed)?;
        Ok(KeyEncryptionKey::from_bytes(&bytes))
    }

    /// KEK rotation procedure: re-seal an existing KEK under a new
    /// [`KmsKeyRef`] (the rotation target). The caller orchestrates
    /// the swap of the persisted SealedKey atomically — typically
    /// inside a Kimberlite audit-logged config-change transaction.
    pub fn rotate_kek(
        &self,
        sealed_under_old: &SealedKey,
        new_root: &KmsMasterKey<P>,
    ) -> Result<SealedKey, KmsError> {
        let kek_bytes = self.provider.open(&self.key_ref, sealed_under_old)?;
        new_root.provider.seal(&new_root.key_ref, &kek_bytes)
    }
}

// ============================================================================
// InMemoryKms — production-quality mock backed by local AES-GCM
// ============================================================================

/// Local KMS substitute that performs the same envelope encryption
/// as a cloud KMS would, but using a process-local key. Suitable for:
///
/// - **CI** — no cloud credentials needed
/// - **Development** — full integration of the [`KmsProvider`] flow
/// - **Single-node deployments** where the operator accepts that the
///   root key lives on the same host
///
/// NOT suitable for production multi-tenant deployments — use a real
/// cloud KMS (AWS / GCP / Azure) where the root key is hardware-backed.
pub struct InMemoryKms {
    keys: Mutex<HashMap<KmsKeyRef, EncryptionKey>>,
}

impl Default for InMemoryKms {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKms {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Provision a new root key for the given reference. Mimics the
    /// `aws kms create-key` step an operator runs once at setup.
    pub fn create_key(&self, key_ref: KmsKeyRef) -> Result<(), KmsError> {
        let mut keys = self.keys.lock().expect("InMemoryKms mutex poisoned");
        if keys.contains_key(&key_ref) {
            return Err(KmsError::OperationDenied(format!(
                "key already exists: {}",
                key_ref.as_str()
            )));
        }
        keys.insert(key_ref, EncryptionKey::generate());
        Ok(())
    }
}

impl KmsProvider for InMemoryKms {
    fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
        let keys = self.keys.lock().expect("InMemoryKms mutex poisoned");
        let key = keys
            .get(key_ref)
            .ok_or_else(|| KmsError::KeyNotFound(key_ref.as_str().to_string()))?;
        let bytes: [u8; KEY_LENGTH] = plaintext.try_into().map_err(|_| KmsError::Malformed)?;
        let wrapped = WrappedKey::new(key, &bytes);
        Ok(SealedKey::new(wrapped.to_bytes().to_vec()))
    }

    fn open(&self, key_ref: &KmsKeyRef, sealed: &SealedKey) -> Result<Vec<u8>, KmsError> {
        let keys = self.keys.lock().expect("InMemoryKms mutex poisoned");
        let key = keys
            .get(key_ref)
            .ok_or_else(|| KmsError::KeyNotFound(key_ref.as_str().to_string()))?;
        let bytes: [u8; crate::encryption::WRAPPED_KEY_LENGTH] = sealed
            .as_bytes()
            .try_into()
            .map_err(|_| KmsError::Malformed)?;
        let wrapped = WrappedKey::from_bytes(&bytes);
        let plaintext = wrapped.unwrap_key(key)?;
        Ok(plaintext.to_vec())
    }

    fn provider_name(&self) -> &'static str {
        "in-memory-kms"
    }
}

// ============================================================================
// Documentation modules for cloud providers
// ============================================================================

/// **AWS KMS integration pattern.** Operators implementing this should
/// pull `aws-sdk-kms` into their deployment crate (not this one — we
/// keep the workspace SDK-free) and wire it via [`KmsProvider`]:
///
/// ```ignore
/// use aws_sdk_kms::{Client, primitives::Blob};
/// use kimberlite_crypto::kms::{KmsProvider, KmsKeyRef, SealedKey, KmsError};
///
/// pub struct AwsKms { client: Client }
///
/// impl KmsProvider for AwsKms {
///     fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
///         let out = self.client.encrypt()
///             .key_id(key_ref.as_str())
///             .plaintext(Blob::new(plaintext))
///             .send()
///             .map_err(|e| KmsError::Transport(e.to_string()))?;
///         let blob = out.ciphertext_blob.ok_or(KmsError::Malformed)?;
///         Ok(SealedKey::new(blob.into_inner()))
///     }
///     // open() mirrors via self.client.decrypt()...
///     // provider_name() returns "aws-kms"
/// }
/// ```
///
/// Recommended IAM action surface: `kms:Encrypt`, `kms:Decrypt`,
/// `kms:DescribeKey`. Scope to a single CMK ARN per tenant.
pub mod aws_kms_integration {}

/// **GCP Cloud KMS integration pattern.** Use `google-cloud-kms`:
///
/// ```ignore
/// use google_cloud_kms::client::Client;
/// use kimberlite_crypto::kms::{KmsProvider, KmsKeyRef, SealedKey, KmsError};
///
/// pub struct GcpKms { client: Client }
///
/// impl KmsProvider for GcpKms {
///     fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
///         // client.encrypt(EncryptRequest { name: key_ref.as_str(), plaintext, ... })
///         //   .await → EncryptResponse { ciphertext }
///         //   → SealedKey::new(ciphertext)
///         todo!()
///     }
///     // open() → client.decrypt()
///     // provider_name() returns "gcp-cloud-kms"
/// }
/// ```
///
/// Recommended IAM role: `roles/cloudkms.cryptoKeyEncrypterDecrypter`
/// scoped to the specific `projects/.../cryptoKeys/...` resource.
pub mod gcp_kms_integration {}

/// **Azure Key Vault integration pattern.** Use `azure_security_keyvault_keys`:
///
/// ```ignore
/// use azure_security_keyvault_keys::KeyClient;
/// use kimberlite_crypto::kms::{KmsProvider, KmsKeyRef, SealedKey, KmsError};
///
/// pub struct AzureKeyVault { client: KeyClient, key_name: String }
///
/// impl KmsProvider for AzureKeyVault {
///     fn seal(&self, _key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
///         // client.encrypt(&self.key_name, RsaOaep256, plaintext)
///         //   .await → EncryptResult { ciphertext }
///         //   → SealedKey::new(ciphertext)
///         todo!()
///     }
///     // open() → client.decrypt(...)
///     // provider_name() returns "azure-key-vault"
/// }
/// ```
///
/// Recommended access policy: `wrapKey` + `unwrapKey` (or `encrypt` +
/// `decrypt` for symmetric keys). Use Managed Identity for auth rather
/// than service-principal secrets.
pub mod azure_key_vault_integration {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_kms() -> (InMemoryKms, KmsKeyRef) {
        let kms = InMemoryKms::new();
        let key_ref = KmsKeyRef::new("test-root-key");
        kms.create_key(key_ref.clone()).unwrap();
        (kms, key_ref)
    }

    #[test]
    fn seal_then_open_round_trips() {
        let (kms, key_ref) = fresh_kms();
        let plaintext = [0x42u8; KEY_LENGTH];
        let sealed = kms.seal(&key_ref, &plaintext).unwrap();
        let recovered = kms.open(&key_ref, &sealed).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn open_with_unknown_key_ref_fails() {
        let (kms, _) = fresh_kms();
        let sealed = SealedKey::new(vec![0u8; crate::encryption::WRAPPED_KEY_LENGTH]);
        let other = KmsKeyRef::new("unprovisioned");
        let err = kms.open(&other, &sealed).unwrap_err();
        assert!(matches!(err, KmsError::KeyNotFound(_)));
    }

    #[test]
    fn create_key_twice_rejects_duplicate() {
        let (kms, key_ref) = fresh_kms();
        let err = kms.create_key(key_ref).unwrap_err();
        assert!(matches!(err, KmsError::OperationDenied(_)));
    }

    #[test]
    fn kms_master_key_seals_and_restores_tenant_kek() {
        let kms = InMemoryKms::new();
        let key_ref = KmsKeyRef::new("tenant-root");
        kms.create_key(key_ref.clone()).unwrap();
        let master = KmsMasterKey::new(kms, key_ref);
        let (kek, sealed) = master.generate_sealed_kek().unwrap();
        let kek_bytes = kek.to_bytes();
        drop(kek);
        let restored = master.restore_sealed_kek(&sealed).unwrap();
        assert_eq!(restored.to_bytes(), kek_bytes);
        assert_eq!(master.provider_name(), "in-memory-kms");
    }

    /// Test-only adapter that lets two `KmsMasterKey` instances share a
    /// single in-memory KMS for the rotation round-trip.
    struct ArcKms(std::sync::Arc<InMemoryKms>);
    impl KmsProvider for ArcKms {
        fn seal(&self, key_ref: &KmsKeyRef, plaintext: &[u8]) -> Result<SealedKey, KmsError> {
            self.0.seal(key_ref, plaintext)
        }
        fn open(&self, key_ref: &KmsKeyRef, sealed: &SealedKey) -> Result<Vec<u8>, KmsError> {
            self.0.open(key_ref, sealed)
        }
        fn provider_name(&self) -> &'static str {
            "arc-in-memory-kms"
        }
    }

    #[test]
    fn kek_rotation_to_new_root_re_seals() {
        let kms = std::sync::Arc::new(InMemoryKms::new());
        let old_ref = KmsKeyRef::new("root-old");
        let new_ref = KmsKeyRef::new("root-new");
        kms.create_key(old_ref.clone()).unwrap();
        kms.create_key(new_ref.clone()).unwrap();

        let old_master = KmsMasterKey::new(ArcKms(kms.clone()), old_ref);
        let new_master = KmsMasterKey::new(ArcKms(kms.clone()), new_ref);

        let (kek, sealed_old) = old_master.generate_sealed_kek().unwrap();
        let kek_bytes = kek.to_bytes();
        drop(kek);

        let sealed_new = old_master.rotate_kek(&sealed_old, &new_master).unwrap();
        let restored = new_master.restore_sealed_kek(&sealed_new).unwrap();
        assert_eq!(restored.to_bytes(), kek_bytes);
    }

    #[test]
    #[should_panic(expected = "KmsKeyRef cannot be empty")]
    fn empty_key_ref_panics() {
        let _ = KmsKeyRef::new("");
    }

    #[test]
    #[should_panic(expected = "SealedKey cannot be empty")]
    fn empty_sealed_key_panics() {
        let _ = SealedKey::new(vec![]);
    }
}
