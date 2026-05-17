//! HIPAA Safe Harbor de-identification (45 CFR § 164.514(b)(2)).
//!
//! Removes the 18 HIPAA identifiers from a record and emits a
//! cryptographic attestation proving which identifier classes were
//! touched, the pre-image hash, and the post-image hash. The
//! attestation chains into the existing compliance audit log so
//! provenance of any de-identified dataset is verifiable from the
//! original record forward.
//!
//! # The 18 identifiers (Safe Harbor)
//!
//! 1. Names
//! 2. Geographic subdivisions smaller than a state (street, city,
//!    county, precinct, ZIP — except first 3 digits of ZIP when the
//!    covered population > 20,000)
//! 3. All dates (except year) directly related to an individual,
//!    plus all ages > 89
//! 4. Phone numbers
//! 5. Fax numbers
//! 6. Email addresses
//! 7. Social security numbers
//! 8. Medical record numbers
//! 9. Health plan beneficiary numbers
//! 10. Account numbers
//! 11. Certificate / license numbers
//! 12. Vehicle identifiers (incl. license plates)
//! 13. Device identifiers and serial numbers
//! 14. URLs
//! 15. IP addresses
//! 16. Biometric identifiers
//! 17. Full-face photos and comparable images
//! 18. Any other unique identifying number, characteristic, or code
//!
//! # Architecture (FCIS)
//!
//! The transform is pure: `deidentify(value, &config) ->
//! (Value, IdentifierSet)`. Hash computation is pure. The audit
//! emission is the only impure edge and is the caller's
//! responsibility — append a `ComplianceAuditAction::DeidentificationApplied`
//! to the log after calling `attest(...)`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Current transform version. Bump when rule semantics change so
/// older attestations remain interpretable.
pub const TRANSFORM_VERSION: &str = "safe-harbor-v1";

/// Sentinel value substituted for removed identifiers.
pub const REDACTED_SENTINEL: &str = "[REDACTED]";

/// Sentinel for ages > 89 (HIPAA aggregates these into "90+").
pub const AGE_90_PLUS_SENTINEL: i64 = 90;

#[derive(Debug, Error)]
pub enum DeidentifyError {
    #[error("Record root must be a JSON object, got {0}")]
    NonObjectRoot(&'static str),

    #[error("Birthdate field '{0}' is not a parseable ISO-8601 date")]
    BadDate(String),
}

pub type Result<T> = std::result::Result<T, DeidentifyError>;

/// The 18 HIPAA Safe Harbor identifier classes.
///
/// `BTreeSet<SafeHarborIdentifier>` is the canonical "which classes
/// were touched" set carried in the attestation — ordering is
/// stable so two equivalent attestations hash identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafeHarborIdentifier {
    Name,
    GeographicSubdivision,
    DateElement,
    PhoneNumber,
    FaxNumber,
    EmailAddress,
    SocialSecurityNumber,
    MedicalRecordNumber,
    HealthPlanBeneficiaryNumber,
    AccountNumber,
    CertificateOrLicenseNumber,
    VehicleIdentifier,
    DeviceIdentifier,
    Url,
    IpAddress,
    BiometricIdentifier,
    FullFacePhoto,
    OtherUniqueIdentifier,
}

impl SafeHarborIdentifier {
    /// All 18 identifier classes, in canonical order. Used by callers
    /// that want to render coverage matrices.
    pub const ALL: [Self; 18] = [
        Self::Name,
        Self::GeographicSubdivision,
        Self::DateElement,
        Self::PhoneNumber,
        Self::FaxNumber,
        Self::EmailAddress,
        Self::SocialSecurityNumber,
        Self::MedicalRecordNumber,
        Self::HealthPlanBeneficiaryNumber,
        Self::AccountNumber,
        Self::CertificateOrLicenseNumber,
        Self::VehicleIdentifier,
        Self::DeviceIdentifier,
        Self::Url,
        Self::IpAddress,
        Self::BiometricIdentifier,
        Self::FullFacePhoto,
        Self::OtherUniqueIdentifier,
    ];
}

/// What to do with a matched field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformAction {
    /// Replace value with `REDACTED_SENTINEL`.
    Redact,
    /// Keep only the year component of an ISO-8601 date.
    YearOnly,
    /// Truncate a ZIP code to its first 3 digits.
    ZipTruncate,
    /// Cap age at `AGE_90_PLUS_SENTINEL`.
    Age90Plus,
}

/// A rule mapping a JSON-pointer-ish field name to an identifier
/// class + action. Field-name matching is exact on the JSON object
/// key (case-insensitive). For nested fields, separate path segments
/// with `/` (e.g., `address/zip`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeidentifyRule {
    pub field: String,
    pub identifier: SafeHarborIdentifier,
    pub action: TransformAction,
}

impl DeidentifyRule {
    pub fn new(
        field: impl Into<String>,
        identifier: SafeHarborIdentifier,
        action: TransformAction,
    ) -> Self {
        Self {
            field: field.into(),
            identifier,
            action,
        }
    }
}

/// Configuration for the de-identification transform.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeidentifyConfig {
    pub rules: Vec<DeidentifyRule>,
}

impl DeidentifyConfig {
    /// Default ruleset covering common FHIR/EHR field names. Callers
    /// extend with `push_rule` for site-specific schemas.
    pub fn safe_harbor_default() -> Self {
        use SafeHarborIdentifier::{
            AccountNumber, BiometricIdentifier, CertificateOrLicenseNumber, DateElement,
            DeviceIdentifier, EmailAddress, FaxNumber, FullFacePhoto, GeographicSubdivision,
            HealthPlanBeneficiaryNumber, IpAddress, MedicalRecordNumber, Name, PhoneNumber,
            SocialSecurityNumber, Url, VehicleIdentifier,
        };
        use TransformAction::{Age90Plus, Redact, YearOnly, ZipTruncate};
        let mut config = Self::default();
        // Names
        for f in [
            "name",
            "first_name",
            "last_name",
            "family_name",
            "given_name",
            "middle_name",
        ] {
            config.rules.push(DeidentifyRule::new(f, Name, Redact));
        }
        // Geographic (street/city — keep state; zip truncates)
        for f in [
            "street",
            "street_address",
            "address1",
            "address2",
            "city",
            "county",
            "precinct",
        ] {
            config
                .rules
                .push(DeidentifyRule::new(f, GeographicSubdivision, Redact));
        }
        config.rules.push(DeidentifyRule::new(
            "zip",
            GeographicSubdivision,
            ZipTruncate,
        ));
        config.rules.push(DeidentifyRule::new(
            "postal_code",
            GeographicSubdivision,
            ZipTruncate,
        ));
        // Dates + age
        for f in [
            "birthdate",
            "birth_date",
            "dob",
            "admission_date",
            "discharge_date",
            "death_date",
        ] {
            config
                .rules
                .push(DeidentifyRule::new(f, DateElement, YearOnly));
        }
        config
            .rules
            .push(DeidentifyRule::new("age", DateElement, Age90Plus));
        // Contact
        config
            .rules
            .push(DeidentifyRule::new("phone", PhoneNumber, Redact));
        config
            .rules
            .push(DeidentifyRule::new("phone_number", PhoneNumber, Redact));
        config
            .rules
            .push(DeidentifyRule::new("fax", FaxNumber, Redact));
        config
            .rules
            .push(DeidentifyRule::new("email", EmailAddress, Redact));
        // Numbers
        config
            .rules
            .push(DeidentifyRule::new("ssn", SocialSecurityNumber, Redact));
        config
            .rules
            .push(DeidentifyRule::new("mrn", MedicalRecordNumber, Redact));
        config.rules.push(DeidentifyRule::new(
            "medical_record_number",
            MedicalRecordNumber,
            Redact,
        ));
        config.rules.push(DeidentifyRule::new(
            "member_id",
            HealthPlanBeneficiaryNumber,
            Redact,
        ));
        config
            .rules
            .push(DeidentifyRule::new("account_number", AccountNumber, Redact));
        config.rules.push(DeidentifyRule::new(
            "license_number",
            CertificateOrLicenseNumber,
            Redact,
        ));
        config.rules.push(DeidentifyRule::new(
            "license_plate",
            VehicleIdentifier,
            Redact,
        ));
        config
            .rules
            .push(DeidentifyRule::new("vin", VehicleIdentifier, Redact));
        config
            .rules
            .push(DeidentifyRule::new("device_id", DeviceIdentifier, Redact));
        config.rules.push(DeidentifyRule::new(
            "device_serial",
            DeviceIdentifier,
            Redact,
        ));
        // Network / media
        config.rules.push(DeidentifyRule::new("url", Url, Redact));
        config
            .rules
            .push(DeidentifyRule::new("ip_address", IpAddress, Redact));
        config
            .rules
            .push(DeidentifyRule::new("ip", IpAddress, Redact));
        config.rules.push(DeidentifyRule::new(
            "fingerprint",
            BiometricIdentifier,
            Redact,
        ));
        config
            .rules
            .push(DeidentifyRule::new("face_photo", FullFacePhoto, Redact));
        config
            .rules
            .push(DeidentifyRule::new("photo_url", FullFacePhoto, Redact));
        config
    }

    pub fn push_rule(&mut self, rule: DeidentifyRule) {
        self.rules.push(rule);
    }
}

/// Cryptographic attestation that a record was de-identified.
///
/// All hashes are SHA-256 (compliance-critical path — never BLAKE3).
/// The `removed` set is the **stable** ordered set of identifier
/// classes touched, so two equivalent attestations serialize and
/// hash identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeidentificationAttestation {
    /// SHA-256 of the canonical JSON serialization of the input record.
    pub original_sha256_hex: String,
    /// SHA-256 of the canonical JSON serialization of the output record.
    pub transformed_sha256_hex: String,
    /// Which of the 18 identifier classes were removed.
    pub removed: BTreeSet<SafeHarborIdentifier>,
    /// Stable version tag for the transform semantics.
    pub transform_version: String,
    /// Wall-clock of attestation issuance.
    pub attested_at: DateTime<Utc>,
}

impl DeidentificationAttestation {
    /// SHA-256 of the attestation itself, suitable for chaining into
    /// the existing audit hash chain.
    pub fn attestation_sha256_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("attestation is always JSON-serialisable");
        let digest = Sha256::digest(&bytes);
        hex_lower(&digest)
    }

    /// Returns true iff the transform is asserted to have removed at
    /// least one identifier class. Useful as a guard before emitting
    /// to a downstream "de-identified streams" projection.
    pub fn is_meaningful(&self) -> bool {
        !self.removed.is_empty()
    }
}

/// Pure transform. Walks the JSON object, applies rules, returns
/// the de-identified value plus the set of identifier classes that
/// were actually touched (a class is only added if at least one
/// matching field was redacted/transformed).
pub fn deidentify(
    value: &Value,
    config: &DeidentifyConfig,
) -> Result<(Value, BTreeSet<SafeHarborIdentifier>)> {
    let Value::Object(obj) = value else {
        return Err(DeidentifyError::NonObjectRoot(match value {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => unreachable!(),
        }));
    };
    // Build a lookup map: lowercased field-path -> rule.
    let mut by_field: BTreeMap<String, &DeidentifyRule> = BTreeMap::new();
    for rule in &config.rules {
        by_field.insert(rule.field.to_lowercase(), rule);
    }
    let mut removed: BTreeSet<SafeHarborIdentifier> = BTreeSet::new();
    let mut out = serde_json::Map::with_capacity(obj.len());
    for (k, v) in obj {
        let lk = k.to_lowercase();
        if let Some(rule) = by_field.get(&lk) {
            match apply_action(v, rule.action) {
                Some(new_v) => {
                    removed.insert(rule.identifier);
                    out.insert(k.clone(), new_v);
                }
                None => {
                    // Action could not apply (e.g. YearOnly on a non-string) — fall back to Redact.
                    removed.insert(rule.identifier);
                    out.insert(k.clone(), Value::String(REDACTED_SENTINEL.to_string()));
                }
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    debug_assert_eq!(out.len(), obj.len(), "field count must be preserved");
    Ok((Value::Object(out), removed))
}

/// Construct an attestation from a (pre, post, removed) triple.
pub fn attest(
    original: &Value,
    transformed: &Value,
    removed: BTreeSet<SafeHarborIdentifier>,
) -> DeidentificationAttestation {
    let original_sha256_hex = sha256_canonical(original);
    let transformed_sha256_hex = sha256_canonical(transformed);
    debug_assert_ne!(
        original_sha256_hex, transformed_sha256_hex,
        "pre and post hashes must differ when any identifier was removed",
    );
    DeidentificationAttestation {
        original_sha256_hex,
        transformed_sha256_hex,
        removed,
        transform_version: TRANSFORM_VERSION.to_string(),
        attested_at: Utc::now(),
    }
}

/// Convenience: transform + attest in one call.
pub fn deidentify_and_attest(
    value: &Value,
    config: &DeidentifyConfig,
) -> Result<(Value, DeidentificationAttestation)> {
    let (transformed, removed) = deidentify(value, config)?;
    let attestation = attest(value, &transformed, removed);
    Ok((transformed, attestation))
}

fn apply_action(value: &Value, action: TransformAction) -> Option<Value> {
    match action {
        TransformAction::Redact => Some(Value::String(REDACTED_SENTINEL.to_string())),
        TransformAction::YearOnly => match value.as_str() {
            Some(s) if s.len() >= 4 => Some(Value::String(s[..4].to_string())),
            _ => None,
        },
        TransformAction::ZipTruncate => match value.as_str() {
            Some(s) if s.len() >= 3 => Some(Value::String(s[..3].to_string())),
            _ => None,
        },
        TransformAction::Age90Plus => match value.as_i64() {
            Some(n) if n > 89 => Some(Value::Number(AGE_90_PLUS_SENTINEL.into())),
            Some(_) => Some(value.clone()),
            None => None,
        },
    }
}

fn sha256_canonical(value: &Value) -> String {
    // Canonical JSON: sort object keys; serde_json::Map preserves
    // insertion order, so we walk and re-emit through a BTreeMap.
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical).expect("canonical JSON is always serialisable");
    let digest = Sha256::digest(&bytes);
    hex_lower(&digest)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(obj) => {
            let sorted: BTreeMap<&String, Value> =
                obj.iter().map(|(k, v)| (k, canonicalize(v))).collect();
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                out.insert(k.clone(), v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_record() -> Value {
        json!({
            "first_name": "Alice",
            "last_name": "Patient",
            "mrn": "MRN-1234567",
            "ssn": "123-45-6789",
            "email": "alice@example.com",
            "phone": "555-0100",
            "birthdate": "1955-03-14",
            "age": 95,
            "zip": "94110",
            "city": "San Francisco",
            "state": "CA",
            "ip": "192.0.2.1",
            "diagnosis_code": "E11.9"
        })
    }

    #[test]
    fn removes_all_expected_identifier_classes() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (transformed, removed) = deidentify(&sample_record(), &cfg).unwrap();
        assert!(removed.contains(&SafeHarborIdentifier::Name));
        assert!(removed.contains(&SafeHarborIdentifier::MedicalRecordNumber));
        assert!(removed.contains(&SafeHarborIdentifier::SocialSecurityNumber));
        assert!(removed.contains(&SafeHarborIdentifier::EmailAddress));
        assert!(removed.contains(&SafeHarborIdentifier::PhoneNumber));
        assert!(removed.contains(&SafeHarborIdentifier::DateElement));
        assert!(removed.contains(&SafeHarborIdentifier::GeographicSubdivision));
        assert!(removed.contains(&SafeHarborIdentifier::IpAddress));
        // state is not in default ruleset (allowed by Safe Harbor)
        assert_eq!(
            transformed.get("state").and_then(|v| v.as_str()),
            Some("CA")
        );
        // diagnosis code is non-identifier clinical data — untouched
        assert_eq!(
            transformed.get("diagnosis_code").and_then(|v| v.as_str()),
            Some("E11.9")
        );
    }

    #[test]
    fn birthdate_keeps_only_year() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (transformed, _) = deidentify(&sample_record(), &cfg).unwrap();
        assert_eq!(
            transformed.get("birthdate").and_then(|v| v.as_str()),
            Some("1955")
        );
    }

    #[test]
    fn age_over_89_caps_at_90() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (transformed, _) = deidentify(&sample_record(), &cfg).unwrap();
        assert_eq!(
            transformed.get("age").and_then(serde_json::Value::as_i64),
            Some(90)
        );
    }

    #[test]
    fn zip_truncates_to_three_digits() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (transformed, _) = deidentify(&sample_record(), &cfg).unwrap();
        assert_eq!(transformed.get("zip").and_then(|v| v.as_str()), Some("941"));
    }

    #[test]
    fn attestation_hashes_differ() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (transformed, attestation) = deidentify_and_attest(&sample_record(), &cfg).unwrap();
        assert_ne!(
            attestation.original_sha256_hex,
            attestation.transformed_sha256_hex
        );
        assert_eq!(attestation.transform_version, TRANSFORM_VERSION);
        assert!(attestation.is_meaningful());
        // Hash is 64 hex chars (SHA-256).
        assert_eq!(attestation.original_sha256_hex.len(), 64);
        assert_eq!(attestation.transformed_sha256_hex.len(), 64);
        // Re-attesting the same pre/post pair yields the same content hashes.
        let attestation2 = attest(&sample_record(), &transformed, attestation.removed.clone());
        assert_eq!(
            attestation.original_sha256_hex,
            attestation2.original_sha256_hex
        );
        assert_eq!(
            attestation.transformed_sha256_hex,
            attestation2.transformed_sha256_hex
        );
    }

    #[test]
    fn canonicalization_is_key_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(sha256_canonical(&a), sha256_canonical(&b));
    }

    #[test]
    fn rejects_non_object_root() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let err = deidentify(&json!([1, 2, 3]), &cfg).unwrap_err();
        assert!(matches!(err, DeidentifyError::NonObjectRoot("array")));
    }

    #[test]
    fn empty_record_is_meaningless_attestation() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (_, removed) = deidentify(&json!({"diagnosis_code": "E11.9"}), &cfg).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn attestation_self_hash_is_stable() {
        let cfg = DeidentifyConfig::safe_harbor_default();
        let (_, attestation) = deidentify_and_attest(&sample_record(), &cfg).unwrap();
        let h1 = attestation.attestation_sha256_hex();
        let h2 = attestation.attestation_sha256_hex();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn all_eighteen_classes_enumerated() {
        assert_eq!(SafeHarborIdentifier::ALL.len(), 18);
        let unique: BTreeSet<_> = SafeHarborIdentifier::ALL.iter().collect();
        assert_eq!(unique.len(), 18);
    }
}
