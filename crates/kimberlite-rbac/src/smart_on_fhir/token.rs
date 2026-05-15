//! JWT validation for SMART access tokens.
//!
//! SMART on FHIR access tokens are conventionally signed JWTs
//! (RS256/ES256/PS256). This module wraps `jsonwebtoken` with a
//! SMART-shaped claim struct so callers don't have to roll their own
//! deserialisation.
//!
//! ## What we validate
//!
//! - **Signature** against a caller-supplied PEM key (asymmetric).
//!   The caller is responsible for fetching the issuer's JWKS and
//!   converting it to PEM — that I/O step doesn't belong here.
//! - **Expiry** (`exp`) and not-before (`nbf`).
//! - **Audience** (`aud`) when the caller provides one.
//! - **Issuer** (`iss`) when the caller provides one.
//!
//! ## What we do NOT validate
//!
//! - Token revocation (no I/O to an introspection endpoint).
//! - `jti` replay (no shared state across requests).
//! - Scope semantics — that lives in
//!   [`super::decision::authorize`]; this module just parses the
//!   `scope` claim into a [`SmartScopeSet`].

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::scope::{ScopeParseError, SmartScopeSet};

/// Errors from validating or parsing a SMART access token.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("JWT decode/verify failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("scope claim malformed: {0}")]
    ScopeParse(#[from] ScopeParseError),
}

/// Parsed access-token claims.
///
/// SMART tokens carry a mix of OAuth2 / OIDC claims and SMART-specific
/// launch-context claims. We surface every standard SMART claim as a
/// typed field; arbitrary extra claims survive in [`AccessToken::extras`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// `sub` — subject (the authenticated user or client).
    pub sub: String,
    /// `iss` — issuer URL.
    #[serde(default)]
    pub iss: Option<String>,
    /// `aud` — intended audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// `exp` — expiry, seconds since epoch.
    pub exp: i64,
    /// `iat` — issued-at.
    #[serde(default)]
    pub iat: Option<i64>,
    /// `nbf` — not-before.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// `scope` — the space-separated SMART scope string.
    pub scope: String,
    /// `patient` — patient launch context (when present).
    #[serde(default)]
    pub patient: Option<String>,
    /// `encounter` — encounter launch context (when present).
    #[serde(default)]
    pub encounter: Option<String>,
    /// `fhirUser` — reference to the logged-in user as a FHIR resource.
    #[serde(rename = "fhirUser", default)]
    pub fhir_user: Option<String>,
    /// Anything else that was on the token.
    #[serde(flatten)]
    pub extras: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AccessToken {
    /// Parse the `scope` claim into a [`SmartScopeSet`].
    pub fn scope_set(&self) -> Result<SmartScopeSet, ScopeParseError> {
        SmartScopeSet::parse(&self.scope)
    }

    /// Build the [`super::context::LaunchContext`] this token binds.
    pub fn launch_context(&self) -> super::context::LaunchContext {
        super::context::LaunchContext {
            patient_id: self.patient.clone(),
            encounter_id: self.encounter.clone(),
            fhir_user: self.fhir_user.clone(),
        }
    }
}

/// JWT validator parameterised by a verifying key and an expected
/// algorithm. One validator per issuer; callers cache them.
pub struct TokenValidator {
    key: DecodingKey,
    validation: Validation,
}

impl TokenValidator {
    /// Build a validator with an asymmetric key in PEM format.
    pub fn rs256_from_pem(pem: &[u8]) -> Result<Self, TokenError> {
        Ok(Self {
            key: DecodingKey::from_rsa_pem(pem)?,
            validation: Validation::new(Algorithm::RS256),
        })
    }

    /// Build a validator with an ECDSA P-256 key in PEM format.
    pub fn es256_from_pem(pem: &[u8]) -> Result<Self, TokenError> {
        Ok(Self {
            key: DecodingKey::from_ec_pem(pem)?,
            validation: Validation::new(Algorithm::ES256),
        })
    }

    /// Build a validator with a shared-secret HS256 key.
    ///
    /// **Test / dev only.** Production SMART deployments use
    /// asymmetric signing; HS256 means anyone with the verifying
    /// key can mint tokens.
    pub fn hs256_from_secret(secret: &[u8]) -> Self {
        Self {
            key: DecodingKey::from_secret(secret),
            validation: Validation::new(Algorithm::HS256),
        }
    }

    /// Pin the validator to a specific audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.validation.set_audience(&[audience.into()]);
        self
    }

    /// Pin the validator to a specific issuer URL.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.validation.set_issuer(&[issuer.into()]);
        self
    }

    /// Decode and verify a JWT, returning the SMART-shaped claims.
    pub fn decode(&self, jwt: &str) -> Result<AccessToken, TokenError> {
        let token = jsonwebtoken::decode::<AccessToken>(jwt, &self.key, &self.validation)?;
        Ok(token.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn encode_hs256(claims: &serde_json::Value, secret: &[u8]) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("HS256 sign")
    }

    #[test]
    fn round_trips_smart_claims_via_hs256() {
        let secret = b"unit-test-secret";
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "alice@example.org",
            "iss": "https://auth.example.org",
            "aud": "https://fhir.example.org",
            "exp": now + 3600,
            "iat": now,
            "scope": "openid fhirUser patient/Observation.read",
            "patient": "alice-001",
            "fhirUser": "Practitioner/dr-jones"
        });
        let jwt = encode_hs256(&claims, secret);

        let v = TokenValidator::hs256_from_secret(secret)
            .with_audience("https://fhir.example.org")
            .with_issuer("https://auth.example.org");
        let tok = v.decode(&jwt).unwrap();

        assert_eq!(tok.sub, "alice@example.org");
        assert_eq!(tok.patient.as_deref(), Some("alice-001"));
        assert_eq!(tok.fhir_user.as_deref(), Some("Practitioner/dr-jones"));
        let scopes = tok.scope_set().unwrap();
        assert_eq!(scopes.0.len(), 3);
    }

    #[test]
    fn rejects_audience_mismatch() {
        let secret = b"unit-test-secret";
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "x",
            "exp": now + 3600,
            "aud": "https://fhir.example.org",
            "scope": "openid",
        });
        let jwt = encode_hs256(&claims, secret);
        let v = TokenValidator::hs256_from_secret(secret)
            .with_audience("https://different-server.example.org");
        let err = v.decode(&jwt).unwrap_err();
        assert!(matches!(err, TokenError::Jwt(_)));
    }

    #[test]
    fn rejects_expired_token() {
        let secret = b"unit-test-secret";
        let claims = serde_json::json!({
            "sub": "x",
            "exp": 1, // 1970-01-01
            "scope": "openid",
        });
        let jwt = encode_hs256(&claims, secret);
        let v = TokenValidator::hs256_from_secret(secret);
        let err = v.decode(&jwt).unwrap_err();
        assert!(matches!(err, TokenError::Jwt(_)));
    }

    #[test]
    fn launch_context_extracted_from_claims() {
        let secret = b"unit-test-secret";
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "x",
            "exp": now + 3600,
            "scope": "patient/*.read",
            "patient": "alice-001",
            "encounter": "enc-9",
        });
        let jwt = encode_hs256(&claims, secret);
        let v = TokenValidator::hs256_from_secret(secret);
        let tok = v.decode(&jwt).unwrap();
        let ctx = tok.launch_context();
        assert_eq!(ctx.patient_id.as_deref(), Some("alice-001"));
        assert_eq!(ctx.encounter_id.as_deref(), Some("enc-9"));
    }
}
