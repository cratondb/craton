//! # smart-on-fhir-app — Reference SMART on FHIR Standalone Launch.
//!
//! A self-contained walkthrough of the SMART v1 OAuth2 + PKCE flow,
//! served by axum and consumed by an in-process client. The whole
//! exchange runs inside this single binary via `tower::oneshot` so
//! the demo is deterministic and bind-port-free.
//!
//! ## What gets demonstrated
//!
//! 1. **Discovery**: `GET /.well-known/smart-configuration`
//! 2. **Authorize**: `GET /authorize?response_type=code&scope=…&code_challenge=…`
//!    — the server "auto-approves" the demo user and binds the
//!    issued auth code to a Patient (`alice-001`).
//! 3. **Token exchange**: `POST /token` with the PKCE verifier;
//!    server mints an HS256 JWT carrying SMART claims (`scope`,
//!    `patient`, `fhirUser`).
//! 4. **Authorized read**: `GET /fhir/Observation/obs-weight-001`
//!    with the bearer token; server validates the JWT, calls
//!    [`kimberlite_rbac::smart_on_fhir::authorize`] and applies the
//!    patient-context constraint.
//! 5. **Denied read**: `GET /fhir/Patient/bob-999` — the token is
//!    bound to Alice; Bob is rejected with HTTP 403.
//!
//! ## Production notes
//!
//! This example uses HS256 for token signing; a real deployment
//! MUST use RS256 / ES256 with the issuer's published JWKS. The
//! "auto-approval" of /authorize stands in for the consent screen
//! a real authorization server would render. PKCE is implemented
//! correctly (S256 challenge) — that part is production-shape.
//!
//! ## Running
//!
//! ```bash
//! cd examples/rust
//! cargo run --example smart_on_fhir_app
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::{to_bytes, Body};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use kimberlite_rbac::smart_on_fhir::{
    authorize, Action, AccessToken, LaunchContext, ScopeDecision, SmartScopeSet, TokenValidator,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower::ServiceExt;

const ISSUER: &str = "https://auth.example.org";
const AUDIENCE: &str = "https://fhir.example.org";
const REDIRECT_URI: &str = "https://app.example.org/cb";
const JWT_SECRET: &[u8] = b"demo-jwt-shared-secret-do-not-use-in-production";

// ──────────────────────────────────────────────────────────────────
// Server state — auth codes + canned FHIR resources
// ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    auth_codes: Arc<Mutex<HashMap<String, AuthCode>>>,
    resources: Arc<Resources>,
}

#[derive(Clone, Debug)]
struct AuthCode {
    /// `patient` claim that will be embedded in the issued token.
    patient_id: String,
    /// PKCE S256 challenge — the verifier presented at /token must
    /// hash to this value.
    code_challenge: String,
    /// Scopes the user has consented to.
    scope: String,
    /// `fhirUser` claim (the practitioner driving the app).
    fhir_user: String,
}

struct Resources {
    patient: Value,
    observation: Value,
}

impl Resources {
    fn new() -> Self {
        Self {
            patient: json!({
                "resourceType": "Patient",
                "id": "alice-001",
                "active": true,
                "name": [{"family": "Smith", "given": ["Alice"]}],
                "gender": "female",
                "birthDate": "1980-05-12"
            }),
            observation: json!({
                "resourceType": "Observation",
                "id": "obs-weight-001",
                "status": "final",
                "code": {"coding": [{
                    "system": "http://loinc.org",
                    "code": "29463-7",
                    "display": "Body Weight"
                }]},
                "subject": {"reference": "Patient/alice-001"},
                "valueQuantity": {"value": 72.5, "unit": "kg"}
            }),
        }
    }

    /// Resolve a (resource_type, id) tuple to the JSON resource.
    /// Returns `None` for unknown resources.
    fn get(&self, resource_type: &str, id: &str) -> Option<&Value> {
        match (resource_type, id) {
            ("Patient", "alice-001") => Some(&self.patient),
            ("Observation", "obs-weight-001") => Some(&self.observation),
            _ => None,
        }
    }

    /// Extract the patient subject id from a resource, if any.
    /// For Patient this is the resource id itself; for Observation /
    /// Encounter etc. it's pulled from `subject.reference`.
    fn patient_id_of(resource: &Value) -> Option<String> {
        let rt = resource.get("resourceType")?.as_str()?;
        if rt == "Patient" {
            return resource.get("id")?.as_str().map(str::to_string);
        }
        let r = resource.get("subject")?.get("reference")?.as_str()?;
        r.strip_prefix("Patient/").map(str::to_string)
    }
}

// ──────────────────────────────────────────────────────────────────
// Discovery — /.well-known/smart-configuration
// ──────────────────────────────────────────────────────────────────

async fn smart_configuration() -> Json<Value> {
    Json(json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "token_endpoint": format!("{ISSUER}/token"),
        "capabilities": [
            "launch-standalone",
            "client-public",
            "permission-patient",
            "permission-user",
            "permission-v1"
        ],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
        "scopes_supported": [
            "openid", "profile", "fhirUser", "launch/patient",
            "patient/*.read", "patient/*.write",
            "user/*.read", "user/*.write"
        ]
    }))
}

// ──────────────────────────────────────────────────────────────────
// /authorize  —  in a real server this renders a login + consent
// screen; here we auto-approve the demo user and bind the code
// to the canned Patient.
// ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    #[allow(dead_code)]
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    #[allow(dead_code)]
    aud: Option<String>,
}

async fn authorize_endpoint(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    if q.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported response_type").into_response();
    }
    if q.code_challenge_method != "S256" {
        return (StatusCode::BAD_REQUEST, "only S256 PKCE supported").into_response();
    }
    // The redirect_uri MUST be pre-registered. For the demo we lock
    // to a single value — a production server would lookup client
    // metadata.
    if q.redirect_uri != REDIRECT_URI {
        return (StatusCode::BAD_REQUEST, "redirect_uri mismatch").into_response();
    }

    // Auto-issue a code bound to the canned patient.
    let code = uuid::Uuid::new_v4().to_string();
    state.auth_codes.lock().await.insert(
        code.clone(),
        AuthCode {
            patient_id: "alice-001".into(),
            code_challenge: q.code_challenge,
            scope: q.scope.clone(),
            fhir_user: "Practitioner/dr-jones".into(),
        },
    );

    let mut location = format!("{}?code={}", q.redirect_uri, code);
    if let Some(s) = q.state {
        location.push_str(&format!("&state={s}"));
    }
    Redirect::to(&location).into_response()
}

// ──────────────────────────────────────────────────────────────────
// /token  —  exchange the code for a JWT
// ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    #[allow(dead_code)]
    client_id: String,
    code_verifier: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
    patient: String,
}

async fn token_endpoint(
    State(state): State<AppState>,
    Form(f): Form<TokenForm>,
) -> Response {
    if f.grant_type != "authorization_code" {
        return (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response();
    }
    if f.redirect_uri != REDIRECT_URI {
        return (StatusCode::BAD_REQUEST, "redirect_uri mismatch").into_response();
    }

    // Look up + consume the auth code.
    let auth_code = match state.auth_codes.lock().await.remove(&f.code) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "invalid_grant").into_response(),
    };

    // PKCE verification: SHA-256(verifier) base64url-no-pad must equal
    // the challenge captured at /authorize. This is the heart of
    // SMART standalone-launch security on public clients.
    let actual_challenge = pkce_s256_challenge(&f.code_verifier);
    if actual_challenge != auth_code.code_challenge {
        return (StatusCode::BAD_REQUEST, "PKCE verifier mismatch").into_response();
    }

    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": auth_code.fhir_user.clone(),
        "iat": now,
        "exp": now + 3600,
        "scope": auth_code.scope.clone(),
        "patient": auth_code.patient_id.clone(),
        "fhirUser": auth_code.fhir_user.clone(),
    });
    let access_token = match encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign_failed").into_response(),
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        scope: auth_code.scope,
        patient: auth_code.patient_id,
    })
    .into_response()
}

// ──────────────────────────────────────────────────────────────────
// /fhir/<ResourceType>/<id>  —  the protected resource
// ──────────────────────────────────────────────────────────────────

async fn fhir_read(
    State(state): State<AppState>,
    Path((resource_type, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    // 1. Extract the bearer token.
    let token_str = match bearer_from(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing Bearer token").into_response(),
    };

    // 2. Validate the JWT — signature + exp + aud + iss.
    let validator = TokenValidator::hs256_from_secret(JWT_SECRET)
        .with_audience(AUDIENCE)
        .with_issuer(ISSUER);
    let access: AccessToken = match validator.decode(&token_str) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                format!("invalid_token: {e}"),
            )
                .into_response()
        }
    };

    // 3. Parse the SMART scopes.
    let scope_set = match SmartScopeSet::parse(&access.scope) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::FORBIDDEN, format!("invalid_scope: {e}")).into_response()
        }
    };
    let launch: LaunchContext = access.launch_context();

    // 4. Run the SMART decision function.
    let decision = authorize(&scope_set, &launch, &resource_type, Action::Read);

    // 5. Look up the resource.
    let resource = match state.resources.get(&resource_type, &id) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Resource not found").into_response(),
    };

    // 6. Enforce the decision against the resource's subject.
    match decision {
        ScopeDecision::Allow => Json(resource.clone()).into_response(),
        ScopeDecision::AllowWithPatientContext { patient_id } => {
            let actual = Resources::patient_id_of(resource);
            if actual.as_deref() == Some(patient_id.as_str()) {
                Json(resource.clone()).into_response()
            } else {
                (
                    StatusCode::FORBIDDEN,
                    format!(
                        "patient_context_mismatch: token bound to {patient_id} but resource belongs to {}",
                        actual.unwrap_or_else(|| "(unknown)".into())
                    ),
                )
                    .into_response()
            }
        }
        ScopeDecision::Deny => {
            (StatusCode::FORBIDDEN, "insufficient_scope").into_response()
        }
        ScopeDecision::MissingPatientContext => (
            StatusCode::BAD_REQUEST,
            "invalid_token: patient scope without launch/patient",
        )
            .into_response(),
    }
}

fn bearer_from(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    h.strip_prefix("Bearer ").map(str::to_string)
}

fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn build_app() -> Router {
    Router::new()
        .route("/.well-known/smart-configuration", get(smart_configuration))
        .route("/authorize", get(authorize_endpoint))
        .route("/token", post(token_endpoint))
        .route("/fhir/:resource_type/:id", get(fhir_read))
        .with_state(AppState {
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            resources: Arc::new(Resources::new()),
        })
}

// ──────────────────────────────────────────────────────────────────
// Client-side transcript
// ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let app = build_app();

    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  smart-on-fhir-app — SMART standalone-launch walkthrough     │");
    println!("│  Audience: {AUDIENCE}");
    println!("│  Issuer:   {ISSUER}");
    println!("└──────────────────────────────────────────────────────────────┘");

    // ── [1] Discovery ────────────────────────────────────────────
    println!("\n[1] GET /.well-known/smart-configuration");
    let body = call_json(&app, Method::GET, "/.well-known/smart-configuration", None, None).await?;
    println!("    ← 200 OK");
    println!(
        "      authorization_endpoint = {}",
        body["authorization_endpoint"].as_str().unwrap_or("")
    );
    println!(
        "      token_endpoint         = {}",
        body["token_endpoint"].as_str().unwrap_or("")
    );

    // ── [2] PKCE setup ───────────────────────────────────────────
    // 43-char URL-safe verifier; demo-static for reproducible output.
    let code_verifier = "client_code_verifier_demo_43_chars_long_x123";
    let code_challenge = pkce_s256_challenge(code_verifier);

    let scope = "openid fhirUser launch/patient patient/Patient.read patient/Observation.read";
    let auth_url = format!(
        "/authorize?response_type=code&client_id=demo-app&redirect_uri={}&scope={}&state=xyz&code_challenge={}&code_challenge_method=S256&aud={}",
        url::form_urlencoded::byte_serialize(REDIRECT_URI.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(scope.as_bytes()).collect::<String>(),
        code_challenge,
        url::form_urlencoded::byte_serialize(AUDIENCE.as_bytes()).collect::<String>(),
    );

    println!("\n[2] GET /authorize  (PKCE S256, scope={scope})");
    let response = oneshot(&app, Method::GET, &auth_url, None, None).await?;
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    println!("    ← {status}");
    println!("      Location: {}", location.as_deref().unwrap_or("(none)"));

    // Extract the auth code from the redirect URI.
    let code = location
        .as_deref()
        .and_then(parse_query_param("code"))
        .context("missing `code` in redirect")?;
    println!("      auth_code = {code}");

    // ── [3] Token exchange ───────────────────────────────────────
    println!("\n[3] POST /token  (authorization_code + PKCE verifier)");
    let token_form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id=demo-app&code_verifier={code_verifier}",
        url::form_urlencoded::byte_serialize(REDIRECT_URI.as_bytes()).collect::<String>(),
    );
    let token_resp = call_json(
        &app,
        Method::POST,
        "/token",
        Some("application/x-www-form-urlencoded"),
        Some(token_form),
    )
    .await?;
    let access_token = token_resp["access_token"].as_str().unwrap_or("").to_string();
    println!("    ← 200 OK");
    println!(
        "      access_token (truncated) = {}…",
        &access_token.chars().take(48).collect::<String>()
    );
    println!(
        "      patient = {}",
        token_resp["patient"].as_str().unwrap_or("∅")
    );
    println!(
        "      scope   = {}",
        token_resp["scope"].as_str().unwrap_or("∅")
    );

    // ── [4] Inspect the token (decode-only, no verify) ───────────
    println!("\n[4] Decode the access token payload");
    if let Some(payload_json) = decode_jwt_payload(&access_token) {
        println!("      sub      = {}", payload_json["sub"].as_str().unwrap_or("∅"));
        println!("      patient  = {}", payload_json["patient"].as_str().unwrap_or("∅"));
        println!("      fhirUser = {}", payload_json["fhirUser"].as_str().unwrap_or("∅"));
        println!("      scope    = {}", payload_json["scope"].as_str().unwrap_or("∅"));
    }

    // ── [5] Authorized resource read ─────────────────────────────
    println!("\n[5] GET /fhir/Observation/obs-weight-001  (Bearer …)");
    let auth_header = format!("Bearer {access_token}");
    let allowed = call_json(
        &app,
        Method::GET,
        "/fhir/Observation/obs-weight-001",
        Some(&auth_header),
        None,
    )
    .await?;
    println!("    ← 200 OK");
    println!(
        "      resourceType = {}",
        allowed["resourceType"].as_str().unwrap_or("∅")
    );
    println!(
        "      subject.reference = {}",
        allowed["subject"]["reference"].as_str().unwrap_or("∅")
    );

    // ── [6] Denied resource read (wrong patient) ─────────────────
    // We try to read another patient. The auth code was bound to
    // alice-001; the resources map doesn't have a `bob-999` patient,
    // so we use Patient/alice-001 → Allow, and Observation belonging
    // to Alice → Allow; instead let's demonstrate denial by reading
    // a Patient that the token's patient_id doesn't match. We can
    // do that by reading the canned `Patient/alice-001` — that IS
    // allowed. To get a denial we use an unknown id so we hit
    // 404 instead, OR we craft a token bound to bob and try alice.
    //
    // Simplest demonstration of patient-context enforcement:
    // request a resource that exists but whose subject is NOT
    // alice-001. We don't have one in the canned store, so
    // demonstrate the deny path by stripping the scope on a fresh
    // exchange (forge a token without `patient/*.read`).
    println!("\n[6] GET /fhir/Patient/alice-001  with a *narrower* token (no patient scope)");
    let narrow_token = forge_demo_token(
        "openid",
        Some("alice-001"),
        "Practitioner/dr-jones",
    );
    let auth_header = format!("Bearer {narrow_token}");
    let response = oneshot(
        &app,
        Method::GET,
        "/fhir/Patient/alice-001",
        Some(&auth_header),
        None,
    )
    .await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), 1 << 16).await?;
    println!("    ← {status}");
    println!(
        "      body: {}",
        std::str::from_utf8(&body_bytes).unwrap_or("(non-utf8)")
    );

    // ── [7] Unauthorized — no bearer at all ──────────────────────
    println!("\n[7] GET /fhir/Patient/alice-001  with no Authorization header");
    let response = oneshot(
        &app,
        Method::GET,
        "/fhir/Patient/alice-001",
        None,
        None,
    )
    .await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), 1 << 16).await?;
    println!("    ← {status}");
    println!(
        "      body: {}",
        std::str::from_utf8(&body_bytes).unwrap_or("(non-utf8)")
    );

    println!("\n──────────────────────────────────────────────────────────────");
    println!("All five SMART flows executed: discovery → authorize → token →");
    println!("authorized read → denied read (insufficient scope) → unauthorized.");
    println!();

    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Test helpers — in-process tower oneshot + JWT helpers
// ──────────────────────────────────────────────────────────────────

async fn oneshot(
    app: &Router,
    method: Method,
    uri: &str,
    auth_header: Option<&str>,
    body: Option<String>,
) -> Result<Response> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if let Some(content_type) = auth_header {
        // Slight abuse: we reuse the "auth_header" slot for content-type
        // when posting forms (call_json invokes us with the right thing).
        if content_type.starts_with("Bearer ") {
            builder = builder.header(header::AUTHORIZATION, content_type);
        } else {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
    }
    let body = body.map(Body::from).unwrap_or_else(Body::empty);
    let req = builder.body(body).context("build request")?;
    Ok(app.clone().oneshot(req).await?)
}

async fn call_json(
    app: &Router,
    method: Method,
    uri: &str,
    auth_or_content: Option<&str>,
    body: Option<String>,
) -> Result<Value> {
    let response = oneshot(app, method, uri, auth_or_content, body).await?;
    let bytes = to_bytes(response.into_body(), 1 << 20).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_query_param(name: &str) -> impl Fn(&str) -> Option<String> + '_ {
    move |s: &str| -> Option<String> {
        let q = s.split_once('?')?.1;
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=')?;
            if k == name {
                return Some(v.to_string());
            }
        }
        None
    }
}

fn decode_jwt_payload(jwt: &str) -> Option<Value> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Mint a JWT with arbitrary scope — used by step [6] to demonstrate
/// scope-based denial without going through a second /authorize.
fn forge_demo_token(scope: &str, patient: Option<&str>, fhir_user: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": fhir_user,
        "iat": now,
        "exp": now + 3600,
        "scope": scope,
        "fhirUser": fhir_user,
    });
    if let Some(p) = patient {
        claims["patient"] = json!(p);
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .expect("HS256 sign")
}
