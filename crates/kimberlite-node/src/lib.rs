//! Node.js N-API bindings for the Kimberlite client.
//!
//! This crate is the native backend for `@kimberlite/client` on npm. It wraps
//! the synchronous Rust `kimberlite-client` with napi-rs async handles so every
//! call from JavaScript returns a `Promise` and does not block the Node event loop.

#![allow(clippy::needless_pass_by_value)] // napi-derive expects owned params

use std::sync::{Arc, Mutex};
use std::time::Duration;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use kimberlite_client::{
    AuditContext, Client, ClientConfig, ClientError, Pool, PoolConfig, PooledClient,
    audit_context::run_with_audit,
};
use kimberlite_types::{DataClass, Offset, Placement, Region, StreamId, TenantId};
use kimberlite_wire::{
    ClusterMode as WireClusterMode, ConsentPurpose as WireConsentPurpose,
    ConsentScope as WireConsentScope, ErasureExemptionBasis as WireExemptionBasis, ErrorCode,
    PushPayload, QueryParam as WireQueryParam, QueryValue as WireQueryValue,
    SubscriptionCloseReason,
};

// ============================================================================
// Public JS-facing types
// ============================================================================

/// Data classification for a stream. Mirrors `kimberlite_types::DataClass`.
#[napi(string_enum)]
pub enum JsDataClass {
    PHI,
    Deidentified,
    PII,
    Sensitive,
    PCI,
    Financial,
    Confidential,
    Public,
}

/// Placement policy for a stream.
#[napi(string_enum)]
pub enum JsPlacement {
    Global,
    UsEast1,
    ApSoutheast2,
}

/// Connection configuration.
#[napi(object)]
pub struct JsClientConfig {
    pub address: String,
    pub tenant_id: BigInt,
    pub auth_token: Option<String>,
    pub read_timeout_ms: Option<u32>,
    pub write_timeout_ms: Option<u32>,
    pub buffer_size_bytes: Option<u32>,
}

/// One SQL parameter value.
#[napi(object)]
pub struct JsQueryParam {
    /// Kind tag: "null" | "bigint" | "text" | "boolean" | "timestamp".
    pub kind: String,
    pub int_value: Option<BigInt>,
    pub text_value: Option<String>,
    pub bool_value: Option<bool>,
    pub timestamp_value: Option<BigInt>,
}

/// One SQL result cell.
#[napi(object)]
pub struct JsQueryValue {
    /// Kind tag: "null" | "bigint" | "text" | "boolean" | "timestamp".
    pub kind: String,
    pub int_value: Option<BigInt>,
    pub text_value: Option<String>,
    pub bool_value: Option<bool>,
    pub timestamp_value: Option<BigInt>,
}

/// Result of a SQL query.
#[napi(object)]
pub struct JsQueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<JsQueryValue>>,
}

/// Result of a stream read.
#[napi(object)]
pub struct JsReadEventsResponse {
    pub events: Vec<Buffer>,
    pub next_offset: Option<BigInt>,
}

/// Result of a DML/DDL `execute()` call.
#[napi(object)]
pub struct JsExecuteResult {
    /// Number of rows inserted / updated / deleted (0 for DDL).
    pub rows_affected: BigInt,
    /// Log offset at which the change was committed.
    pub log_offset: BigInt,
}

/// Handshake result for a new subscription.
#[napi(object)]
pub struct JsSubscribeAck {
    pub subscription_id: BigInt,
    pub start_offset: BigInt,
    pub credits: u32,
}

/// A single event yielded from a subscription, or a close marker.
#[napi(object)]
pub struct JsSubscriptionEvent {
    pub offset: BigInt,
    pub data: Option<Buffer>,
    /// `true` once the subscription has closed; `data` will be `null` and
    /// further `nextEvent()` calls return the same closed marker.
    pub closed: bool,
    /// One of: "ClientCancelled" | "ServerShutdown" | "StreamDeleted"
    /// | "BackpressureTimeout" | "ProtocolError". Only meaningful when
    /// `closed` is true.
    pub close_reason: Option<String>,
}

fn close_reason_to_str(r: SubscriptionCloseReason) -> &'static str {
    match r {
        SubscriptionCloseReason::ClientCancelled => "ClientCancelled",
        SubscriptionCloseReason::ServerShutdown => "ServerShutdown",
        SubscriptionCloseReason::StreamDeleted => "StreamDeleted",
        SubscriptionCloseReason::BackpressureTimeout => "BackpressureTimeout",
        SubscriptionCloseReason::ProtocolError => "ProtocolError",
    }
}

// ============================================================================
// Phase 4 — admin + schema + server info (JS-facing types)
// ============================================================================

#[napi(object)]
pub struct JsTableInfo {
    pub name: String,
    pub column_count: u32,
}

#[napi(object)]
pub struct JsColumnInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

#[napi(object)]
pub struct JsIndexInfo {
    pub name: String,
    pub columns: Vec<String>,
}

#[napi(object)]
pub struct JsDescribeTable {
    pub table_name: String,
    pub columns: Vec<JsColumnInfo>,
}

#[napi(object)]
pub struct JsTenantInfo {
    pub tenant_id: BigInt,
    pub name: Option<String>,
    pub table_count: u32,
    pub created_at_nanos: Option<BigInt>,
}

#[napi(object)]
pub struct JsTenantCreateResult {
    pub tenant: JsTenantInfo,
    pub created: bool,
}

#[napi(object)]
pub struct JsTenantDeleteResult {
    pub deleted: bool,
    pub tables_dropped: u32,
}

#[napi(object)]
pub struct JsApiKeyInfo {
    pub key_id: String,
    pub subject: String,
    pub tenant_id: BigInt,
    pub roles: Vec<String>,
    pub expires_at_nanos: Option<BigInt>,
}

// -- Masking policy (v0.6.0 Tier 2 #7) ------------------------------------

/// JS-facing masking-strategy descriptor. Matches the TS
/// `MaskingStrategy` discriminated union via the `kind` field.
///
/// * `kind = "RedactSsn" | "RedactPhone" | "RedactEmail" | "RedactCreditCard"
///   | "Hash" | "Tokenize" | "Null"` — no extra params.
/// * `kind = "RedactCustom"` — `replacement` is required.
/// * `kind = "Truncate"` — `maxChars` is required.
#[napi(object)]
pub struct JsMaskingStrategy {
    pub kind: String,
    pub replacement: Option<String>,
    pub max_chars: Option<u32>,
}

#[napi(object)]
pub struct JsMaskingPolicyInfo {
    pub name: String,
    pub strategy: JsMaskingStrategy,
    pub exempt_roles: Vec<String>,
    pub default_masked: bool,
    pub attachment_count: u32,
}

#[napi(object)]
pub struct JsMaskingAttachmentInfo {
    pub table_name: String,
    pub column_name: String,
    pub policy_name: String,
}

#[napi(object)]
pub struct JsMaskingPolicyListResponse {
    pub policies: Vec<JsMaskingPolicyInfo>,
    pub attachments: Vec<JsMaskingAttachmentInfo>,
}

#[napi(object)]
pub struct JsApiKeyRegisterResult {
    pub key: String,
    pub info: JsApiKeyInfo,
}

#[napi(object)]
pub struct JsApiKeyRotateResult {
    pub new_key: String,
    pub info: JsApiKeyInfo,
}

#[napi(object)]
pub struct JsServerInfo {
    pub build_version: String,
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
    pub uptime_secs: BigInt,
    /// `"Standalone"` or `"Clustered"`.
    pub cluster_mode: String,
    pub tenant_count: u32,
}

fn cluster_mode_to_str(m: WireClusterMode) -> &'static str {
    match m {
        WireClusterMode::Standalone => "Standalone",
        WireClusterMode::Clustered => "Clustered",
    }
}

fn tenant_info_to_js(info: kimberlite_wire::TenantInfo) -> JsTenantInfo {
    JsTenantInfo {
        tenant_id: BigInt::from(u64::from(info.tenant_id)),
        name: info.name,
        table_count: info.table_count,
        created_at_nanos: info.created_at_nanos.map(BigInt::from),
    }
}

/// Translate a JS-facing `JsMaskingStrategy` into the client's
/// `MaskingStrategySpec`. Keeps the napi binding surface stringly-
/// typed (TS maps a discriminated union to this flat shape) but the
/// Rust client call stays strongly typed.
fn js_strategy_to_spec(
    s: &JsMaskingStrategy,
) -> std::result::Result<kimberlite_client::MaskingStrategySpec, String> {
    use kimberlite_client::MaskingStrategySpec;
    match s.kind.as_str() {
        "RedactSsn" => Ok(MaskingStrategySpec::RedactSsn),
        "RedactPhone" => Ok(MaskingStrategySpec::RedactPhone),
        "RedactEmail" => Ok(MaskingStrategySpec::RedactEmail),
        "RedactCreditCard" => Ok(MaskingStrategySpec::RedactCreditCard),
        "RedactCustom" => s
            .replacement
            .as_ref()
            .map(|r| MaskingStrategySpec::RedactCustom {
                replacement: r.clone(),
            })
            .ok_or_else(|| "RedactCustom requires a `replacement` string".to_string()),
        "Hash" => Ok(MaskingStrategySpec::Hash),
        "Tokenize" => Ok(MaskingStrategySpec::Tokenize),
        "Truncate" => s
            .max_chars
            .map(|n| MaskingStrategySpec::Truncate {
                max_chars: n as usize,
            })
            .ok_or_else(|| "Truncate requires a positive `maxChars` value".to_string()),
        "Null" => Ok(MaskingStrategySpec::Null),
        other => Err(format!("unknown masking strategy kind `{other}`")),
    }
}

/// Translate a wire `MaskingStrategyWire` into the JS shape.
fn wire_strategy_to_js(s: &kimberlite_wire::MaskingStrategyWire) -> JsMaskingStrategy {
    use kimberlite_wire::MaskingStrategyWire;
    match s {
        MaskingStrategyWire::Redact {
            pattern,
            replacement,
        } => {
            let kind = match pattern.as_str() {
                "SSN" => "RedactSsn",
                "PHONE" => "RedactPhone",
                "EMAIL" => "RedactEmail",
                "CC" => "RedactCreditCard",
                _ => "RedactCustom",
            };
            JsMaskingStrategy {
                kind: kind.to_string(),
                replacement: replacement.clone(),
                max_chars: None,
            }
        }
        MaskingStrategyWire::Hash => JsMaskingStrategy {
            kind: "Hash".to_string(),
            replacement: None,
            max_chars: None,
        },
        MaskingStrategyWire::Tokenize => JsMaskingStrategy {
            kind: "Tokenize".to_string(),
            replacement: None,
            max_chars: None,
        },
        MaskingStrategyWire::Truncate { max_chars } => JsMaskingStrategy {
            kind: "Truncate".to_string(),
            replacement: None,
            max_chars: Some(*max_chars as u32),
        },
        MaskingStrategyWire::Null => JsMaskingStrategy {
            kind: "Null".to_string(),
            replacement: None,
            max_chars: None,
        },
    }
}

fn masking_policy_info_to_js(info: kimberlite_wire::MaskingPolicyInfo) -> JsMaskingPolicyInfo {
    JsMaskingPolicyInfo {
        name: info.name,
        strategy: wire_strategy_to_js(&info.strategy),
        exempt_roles: info.exempt_roles,
        default_masked: info.default_masked,
        attachment_count: info.attachment_count,
    }
}

fn api_key_info_to_js(info: kimberlite_wire::ApiKeyInfo) -> JsApiKeyInfo {
    JsApiKeyInfo {
        key_id: info.key_id,
        subject: info.subject,
        tenant_id: BigInt::from(u64::from(info.tenant_id)),
        roles: info.roles,
        expires_at_nanos: info.expires_at_nanos.map(BigInt::from),
    }
}

// ============================================================================
// Phase 5 — Consent + Erasure JS types + helpers
// ============================================================================

/// Purposes a subject can grant consent for. Case-sensitive strings that mirror
/// the `ConsentPurpose` wire enum.
#[napi(string_enum)]
pub enum JsConsentPurpose {
    Marketing,
    Analytics,
    Contractual,
    LegalObligation,
    VitalInterests,
    PublicTask,
    Research,
    Security,
    // HIPAA TPO + extensions
    Treatment,
    Payment,
    Operations,
    PublicHealth,
    Emergency,
}

#[napi(string_enum)]
pub enum JsConsentScope {
    AllData,
    ContactInfo,
    AnalyticsOnly,
    ContractualNecessity,
}

#[napi(string_enum)]
pub enum JsErasureExemptionBasis {
    LegalObligation,
    PublicHealth,
    Archiving,
    LegalClaims,
}

/// GDPR Article 6(1) lawful basis — mirrors the TS `GdprArticle`
/// string-literal union and the wire `GdprArticle` enum. Added in
/// wire protocol v4 (v0.6.0).
#[napi(string_enum)]
pub enum JsGdprArticle {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

/// GDPR Article 6(1) lawful basis + justification passed on
/// `consent.grant` and returned on `ConsentRecord.basis`.
#[napi(object)]
pub struct JsConsentBasis {
    pub article: JsGdprArticle,
    pub justification: Option<String>,
}

fn js_article_to_wire(a: JsGdprArticle) -> kimberlite_wire::GdprArticle {
    use kimberlite_wire::GdprArticle as W;
    match a {
        JsGdprArticle::Consent => W::Consent,
        JsGdprArticle::Contract => W::Contract,
        JsGdprArticle::LegalObligation => W::LegalObligation,
        JsGdprArticle::VitalInterests => W::VitalInterests,
        JsGdprArticle::PublicTask => W::PublicTask,
        JsGdprArticle::LegitimateInterests => W::LegitimateInterests,
    }
}

fn wire_article_to_js(a: kimberlite_wire::GdprArticle) -> JsGdprArticle {
    use kimberlite_wire::GdprArticle as W;
    match a {
        W::Consent => JsGdprArticle::Consent,
        W::Contract => JsGdprArticle::Contract,
        W::LegalObligation => JsGdprArticle::LegalObligation,
        W::VitalInterests => JsGdprArticle::VitalInterests,
        W::PublicTask => JsGdprArticle::PublicTask,
        W::LegitimateInterests => JsGdprArticle::LegitimateInterests,
    }
}

fn js_basis_to_wire(b: &JsConsentBasis) -> kimberlite_wire::ConsentBasis {
    kimberlite_wire::ConsentBasis {
        article: js_article_to_wire(b.article),
        justification: b.justification.clone(),
    }
}

fn wire_basis_to_js(b: kimberlite_wire::ConsentBasis) -> JsConsentBasis {
    JsConsentBasis {
        article: wire_article_to_js(b.article),
        justification: b.justification,
    }
}

fn js_purpose_to_wire(p: JsConsentPurpose) -> WireConsentPurpose {
    match p {
        JsConsentPurpose::Marketing => WireConsentPurpose::Marketing,
        JsConsentPurpose::Analytics => WireConsentPurpose::Analytics,
        JsConsentPurpose::Contractual => WireConsentPurpose::Contractual,
        JsConsentPurpose::LegalObligation => WireConsentPurpose::LegalObligation,
        JsConsentPurpose::VitalInterests => WireConsentPurpose::VitalInterests,
        JsConsentPurpose::PublicTask => WireConsentPurpose::PublicTask,
        JsConsentPurpose::Research => WireConsentPurpose::Research,
        JsConsentPurpose::Security => WireConsentPurpose::Security,
        JsConsentPurpose::Treatment => WireConsentPurpose::Treatment,
        JsConsentPurpose::Payment => WireConsentPurpose::Payment,
        JsConsentPurpose::Operations => WireConsentPurpose::Operations,
        JsConsentPurpose::PublicHealth => WireConsentPurpose::PublicHealth,
        JsConsentPurpose::Emergency => WireConsentPurpose::Emergency,
    }
}

fn wire_purpose_to_js(p: WireConsentPurpose) -> JsConsentPurpose {
    match p {
        WireConsentPurpose::Marketing => JsConsentPurpose::Marketing,
        WireConsentPurpose::Analytics => JsConsentPurpose::Analytics,
        WireConsentPurpose::Contractual => JsConsentPurpose::Contractual,
        WireConsentPurpose::LegalObligation => JsConsentPurpose::LegalObligation,
        WireConsentPurpose::VitalInterests => JsConsentPurpose::VitalInterests,
        WireConsentPurpose::PublicTask => JsConsentPurpose::PublicTask,
        WireConsentPurpose::Research => JsConsentPurpose::Research,
        WireConsentPurpose::Security => JsConsentPurpose::Security,
        WireConsentPurpose::Treatment => JsConsentPurpose::Treatment,
        WireConsentPurpose::Payment => JsConsentPurpose::Payment,
        WireConsentPurpose::Operations => JsConsentPurpose::Operations,
        WireConsentPurpose::PublicHealth => JsConsentPurpose::PublicHealth,
        WireConsentPurpose::Emergency => JsConsentPurpose::Emergency,
    }
}

fn wire_scope_to_js(s: WireConsentScope) -> JsConsentScope {
    match s {
        WireConsentScope::AllData => JsConsentScope::AllData,
        WireConsentScope::ContactInfo => JsConsentScope::ContactInfo,
        WireConsentScope::AnalyticsOnly => JsConsentScope::AnalyticsOnly,
        WireConsentScope::ContractualNecessity => JsConsentScope::ContractualNecessity,
    }
}

fn js_exemption_to_wire(b: JsErasureExemptionBasis) -> WireExemptionBasis {
    match b {
        JsErasureExemptionBasis::LegalObligation => WireExemptionBasis::LegalObligation,
        JsErasureExemptionBasis::PublicHealth => WireExemptionBasis::PublicHealth,
        JsErasureExemptionBasis::Archiving => WireExemptionBasis::Archiving,
        JsErasureExemptionBasis::LegalClaims => WireExemptionBasis::LegalClaims,
    }
}

#[napi(object)]
pub struct JsConsentRecord {
    pub consent_id: String,
    pub subject_id: String,
    pub purpose: JsConsentPurpose,
    pub scope: JsConsentScope,
    pub granted_at_nanos: BigInt,
    pub withdrawn_at_nanos: Option<BigInt>,
    pub expires_at_nanos: Option<BigInt>,
    pub notes: Option<String>,
    /// GDPR Article 6(1) lawful basis + justification. Populated
    /// when the grant supplied a basis; `null` on pre-v4 records.
    pub basis: Option<JsConsentBasis>,
    /// Terms-of-service version the subject responded to. `null` on
    /// pre-v0.6.2 records and on grants that omitted the field.
    pub terms_version: Option<String>,
    /// Whether the subject accepted (`true`, default) or declined
    /// (`false`). Pre-v0.6.2 records always read `true` because
    /// consent grants were acceptance-only.
    pub accepted: bool,
}

#[napi(object)]
pub struct JsConsentGrantResult {
    pub consent_id: String,
    pub granted_at_nanos: BigInt,
}

#[napi(object)]
pub struct JsErasureStatusTag {
    /// One of `Pending | InProgress | Complete | Failed | Exempt`.
    pub kind: String,
    pub streams_remaining: Option<u32>,
    pub erased_at_nanos: Option<BigInt>,
    pub total_records: Option<BigInt>,
    pub reason: Option<String>,
    pub retry_at_nanos: Option<BigInt>,
    pub basis: Option<JsErasureExemptionBasis>,
}

#[napi(object)]
pub struct JsErasureRequestInfo {
    pub request_id: String,
    pub subject_id: String,
    pub requested_at_nanos: BigInt,
    pub deadline_nanos: BigInt,
    pub status: JsErasureStatusTag,
    pub records_erased: BigInt,
    pub streams_affected: Vec<BigInt>,
}

#[napi(object)]
pub struct JsErasureAuditInfo {
    pub request_id: String,
    pub subject_id: String,
    pub requested_at_nanos: BigInt,
    pub completed_at_nanos: BigInt,
    pub records_erased: BigInt,
    pub streams_affected: Vec<BigInt>,
    pub erasure_proof_hex: Option<String>,
}

/// **v0.6.0 Tier 2 #9** — audit-log entry exposed to the TS SDK.
///
/// PHI-safe by construction: `changedFieldNames` lists the field
/// names the underlying action touched; no before/after *values*
/// reach the SDK.
#[napi(object)]
pub struct JsAuditEntry {
    pub event_id: String,
    pub timestamp_nanos: BigInt,
    /// Action kind (e.g. `"ConsentGranted"`, `"ErasureCompleted"`).
    pub action: String,
    pub subject_id: Option<String>,
    pub actor: Option<String>,
    pub tenant_id: Option<BigInt>,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
    pub request_id: Option<String>,
    pub reason: Option<String>,
    pub source_country: Option<String>,
    /// **Field names only.** Never values. Lists the schema of the
    /// underlying action payload so dashboards can render
    /// "what changed" without disclosing the data.
    pub changed_field_names: Vec<String>,
}

/// **v0.8.0** — structured chain-verification report for
/// `verifyAuditChain`. Mirrors `kimberlite_wire::VerifyAuditChainResponse`.
#[napi(object)]
pub struct JsVerifyAuditChainReport {
    pub ok: bool,
    pub event_count: BigInt,
    pub chain_head_hex: String,
    pub mismatch_at_index: Option<BigInt>,
    pub error_message: Option<String>,
}

/// **v0.6.0 Tier 2 #9** — filter for `auditQuery`. All fields
/// optional; unset fields don't constrain the query.
#[napi(object)]
pub struct JsAuditQueryFilter {
    pub subject_id: Option<String>,
    pub action_type: Option<String>,
    pub time_from_nanos: Option<BigInt>,
    pub time_to_nanos: Option<BigInt>,
    pub actor: Option<String>,
    pub limit: Option<u32>,
}

fn audit_event_info_to_js(e: kimberlite_wire::AuditEventInfo) -> JsAuditEntry {
    JsAuditEntry {
        event_id: e.event_id,
        timestamp_nanos: BigInt::from(e.timestamp_nanos),
        action: e.action,
        subject_id: e.subject_id,
        actor: e.actor,
        tenant_id: e.tenant_id.map(BigInt::from),
        ip_address: e.ip_address,
        correlation_id: e.correlation_id,
        request_id: e.request_id,
        reason: e.reason,
        source_country: e.source_country,
        changed_field_names: e.changed_field_names,
    }
}

fn consent_record_to_js(r: kimberlite_wire::ConsentRecord) -> JsConsentRecord {
    JsConsentRecord {
        consent_id: r.consent_id,
        subject_id: r.subject_id,
        purpose: wire_purpose_to_js(r.purpose),
        scope: wire_scope_to_js(r.scope),
        granted_at_nanos: BigInt::from(r.granted_at_nanos),
        withdrawn_at_nanos: r.withdrawn_at_nanos.map(BigInt::from),
        expires_at_nanos: r.expires_at_nanos.map(BigInt::from),
        notes: r.notes,
        basis: r.basis.map(wire_basis_to_js),
        terms_version: r.terms_version,
        accepted: r.accepted,
    }
}

fn erasure_status_to_js(s: kimberlite_wire::ErasureStatusTag) -> JsErasureStatusTag {
    use kimberlite_wire::{ErasureExemptionBasis as Ex, ErasureStatusTag as S};
    fn basis_to_js(b: Ex) -> JsErasureExemptionBasis {
        match b {
            Ex::LegalObligation => JsErasureExemptionBasis::LegalObligation,
            Ex::PublicHealth => JsErasureExemptionBasis::PublicHealth,
            Ex::Archiving => JsErasureExemptionBasis::Archiving,
            Ex::LegalClaims => JsErasureExemptionBasis::LegalClaims,
        }
    }
    match s {
        S::Pending => JsErasureStatusTag {
            kind: "Pending".into(),
            streams_remaining: None,
            erased_at_nanos: None,
            total_records: None,
            reason: None,
            retry_at_nanos: None,
            basis: None,
        },
        S::InProgress { streams_remaining } => JsErasureStatusTag {
            kind: "InProgress".into(),
            streams_remaining: Some(streams_remaining),
            erased_at_nanos: None,
            total_records: None,
            reason: None,
            retry_at_nanos: None,
            basis: None,
        },
        S::Complete {
            erased_at_nanos,
            total_records,
        } => JsErasureStatusTag {
            kind: "Complete".into(),
            streams_remaining: None,
            erased_at_nanos: Some(BigInt::from(erased_at_nanos)),
            total_records: Some(BigInt::from(total_records)),
            reason: None,
            retry_at_nanos: None,
            basis: None,
        },
        S::Failed {
            reason,
            retry_at_nanos,
        } => JsErasureStatusTag {
            kind: "Failed".into(),
            streams_remaining: None,
            erased_at_nanos: None,
            total_records: None,
            reason: Some(reason),
            retry_at_nanos: Some(BigInt::from(retry_at_nanos)),
            basis: None,
        },
        S::Exempt { basis } => JsErasureStatusTag {
            kind: "Exempt".into(),
            streams_remaining: None,
            erased_at_nanos: None,
            total_records: None,
            reason: None,
            retry_at_nanos: None,
            basis: Some(basis_to_js(basis)),
        },
    }
}

fn erasure_request_info_to_js(r: kimberlite_wire::ErasureRequestInfo) -> JsErasureRequestInfo {
    JsErasureRequestInfo {
        request_id: r.request_id,
        subject_id: r.subject_id,
        requested_at_nanos: BigInt::from(r.requested_at_nanos),
        deadline_nanos: BigInt::from(r.deadline_nanos),
        status: erasure_status_to_js(r.status),
        records_erased: BigInt::from(r.records_erased),
        streams_affected: r
            .streams_affected
            .into_iter()
            .map(|s| BigInt::from(u64::from(s)))
            .collect(),
    }
}

fn erasure_audit_info_to_js(a: kimberlite_wire::ErasureAuditInfo) -> JsErasureAuditInfo {
    JsErasureAuditInfo {
        request_id: a.request_id,
        subject_id: a.subject_id,
        requested_at_nanos: BigInt::from(a.requested_at_nanos),
        completed_at_nanos: BigInt::from(a.completed_at_nanos),
        records_erased: BigInt::from(a.records_erased),
        streams_affected: a
            .streams_affected
            .into_iter()
            .map(|s| BigInt::from(u64::from(s)))
            .collect(),
        erasure_proof_hex: a.erasure_proof_hex,
    }
}

// ============================================================================
// Client wrapper
// ============================================================================

/// Async-safe wrapper around the synchronous `kimberlite-client` Client.
///
/// All methods offload I/O to a blocking tokio worker so the Node event loop
/// is never stalled by a socket read.
#[napi]
pub struct KimberliteClient {
    inner: Arc<Mutex<Client>>,
    /// AUDIT-2026-04 S3.9 — SDK-supplied audit attribution staged by
    /// the TS wrapper via [`Self::set_audit_context`] and consumed by
    /// every async method through [`Self::audit_snapshot`]. The Rust
    /// client then carries it onto the wire `Request.audit` so the
    /// server's compliance ledger records actor/reason per call.
    audit: Arc<Mutex<Option<AuditContext>>>,
}

impl KimberliteClient {
    /// Snapshot the currently-staged audit context. Called at the top
    /// of each async method so the audit is captured on the V8 thread
    /// and moved into the blocking worker closure.
    fn audit_snapshot(&self) -> Option<AuditContext> {
        self.audit.lock().expect("audit mutex poisoned").clone()
    }
}

#[napi]
impl KimberliteClient {
    /// Connects to a Kimberlite server and performs the protocol handshake.
    #[napi(factory)]
    pub async fn connect(config: JsClientConfig) -> Result<Self> {
        let addr = config.address;
        let tenant = TenantId::new(config.tenant_id.get_u64().1);
        let cfg = ClientConfig {
            read_timeout: config
                .read_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            write_timeout: config
                .write_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            // v0.6.2: 4 MiB default (was 64 KiB). Framing cap =
            // `buffer_size * 2` = 8 MiB, comfortably above the SDK's
            // 1 MiB `read({ maxBytes })` default. Old default tripped
            // its own framing limit on the SDK's own defaults.
            buffer_size: config
                .buffer_size_bytes
                .map_or(4 * 1024 * 1024, |b| b as usize),
            auth_token: config.auth_token,
            auto_reconnect: true,
        };

        let client = spawn_blocking_client(move || Client::connect(addr, tenant, cfg)).await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
            audit: Arc::new(Mutex::new(None)),
        })
    }

    /// AUDIT-2026-04 S3.9 — stage the audit context for subsequent
    /// client calls. The TS wrapper calls this synchronously from the
    /// V8 event loop before invoking any async method, then clears it
    /// afterwards with [`Self::clear_audit_context`]. Missing fields
    /// are passed as `None`.
    #[napi]
    pub fn set_audit_context(
        &self,
        actor: Option<String>,
        reason: Option<String>,
        correlation_id: Option<String>,
        idempotency_key: Option<String>,
    ) {
        let mut ctx = AuditContext::new(actor.unwrap_or_default(), reason.unwrap_or_default());
        if let Some(id) = idempotency_key {
            ctx = ctx.with_request_id(id);
        }
        if let Some(id) = correlation_id {
            ctx = ctx.with_correlation_id(id);
        }
        *self.audit.lock().expect("audit mutex poisoned") = Some(ctx);
    }

    /// Clear the staged audit context. Called by the TS wrapper after
    /// each async method returns.
    #[napi]
    pub fn clear_audit_context(&self) {
        *self.audit.lock().expect("audit mutex poisoned") = None;
    }

    /// Creates a new stream with the given data classification.
    #[napi]
    pub async fn create_stream(&self, name: String, data_class: JsDataClass) -> Result<BigInt> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let dc = map_data_class(data_class);
        let stream_id = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.create_stream(&name, dc)
        })
        .await?;
        Ok(BigInt::from(u64::from(stream_id)))
    }

    /// Creates a new stream with a specific geographic placement policy.
    #[napi]
    pub async fn create_stream_with_placement(
        &self,
        name: String,
        data_class: JsDataClass,
        placement: JsPlacement,
    ) -> Result<BigInt> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let dc = map_data_class(data_class);
        let p = map_placement(placement);
        let stream_id = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.create_stream_with_placement(&name, dc, p)
        })
        .await?;
        Ok(BigInt::from(u64::from(stream_id)))
    }

    /// Appends events to a stream with optimistic concurrency.
    ///
    /// Returns the offset of the first appended event.
    #[napi]
    pub async fn append(
        &self,
        stream_id: BigInt,
        events: Vec<Buffer>,
        expected_offset: BigInt,
    ) -> Result<BigInt> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = StreamId::from(stream_id.get_u64().1);
        let offset = Offset::from(expected_offset.get_u64().1);
        let payload: Vec<Vec<u8>> = events.into_iter().map(|b| b.to_vec()).collect();

        let first = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.append(sid, payload, offset)
        })
        .await?;
        Ok(BigInt::from(u64::from(first)))
    }

    /// Reads events from a stream starting at `from_offset`.
    #[napi]
    pub async fn read_events(
        &self,
        stream_id: BigInt,
        from_offset: BigInt,
        max_bytes: BigInt,
    ) -> Result<JsReadEventsResponse> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = StreamId::from(stream_id.get_u64().1);
        let from = Offset::from(from_offset.get_u64().1);
        let max = max_bytes.get_u64().1;

        let resp = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.read_events(sid, from, max)
        })
        .await?;

        Ok(JsReadEventsResponse {
            events: resp.events.into_iter().map(Buffer::from).collect(),
            next_offset: resp.next_offset.map(|o| BigInt::from(u64::from(o))),
        })
    }

    /// Returns the number of committed events on `stream_id`.
    ///
    /// O(1) — reads `StreamMetadata.current_offset` server-side. v0.8.0
    /// — replaces full-stream walks for counting.
    #[napi]
    pub async fn stream_length(&self, stream_id: BigInt) -> Result<BigInt> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = StreamId::from(stream_id.get_u64().1);

        let length = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.stream_length(sid)
        })
        .await?;

        Ok(BigInt::from(length))
    }

    /// Executes a SQL query against the server.
    #[napi]
    pub async fn query(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
    ) -> Result<JsQueryResponse> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;

        let resp = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.query(&sql, &wire_params)
        })
        .await?;

        Ok(JsQueryResponse {
            columns: resp.columns,
            rows: resp
                .rows
                .into_iter()
                .map(|row| row.into_iter().map(map_query_value).collect())
                .collect(),
        })
    }

    /// Executes a SQL query at a specific log position (time travel).
    #[napi]
    pub async fn query_at(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
        position: BigInt,
    ) -> Result<JsQueryResponse> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;
        let pos = Offset::from(position.get_u64().1);

        let resp = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.query_at(&sql, &wire_params, pos)
        })
        .await?;

        Ok(JsQueryResponse {
            columns: resp.columns,
            rows: resp
                .rows
                .into_iter()
                .map(|row| row.into_iter().map(map_query_value).collect())
                .collect(),
        })
    }

    /// Executes a DML or DDL SQL statement (INSERT / UPDATE / DELETE / CREATE / ALTER).
    ///
    /// Returns the row-affected count and the log offset at which the change
    /// committed. For DDL statements the row count is typically 0.
    #[napi]
    pub async fn execute(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
    ) -> Result<JsExecuteResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;

        let (rows, offset) = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.execute(&sql, &wire_params)
        })
        .await?;

        Ok(JsExecuteResult {
            rows_affected: BigInt::from(rows),
            log_offset: BigInt::from(offset),
        })
    }

    /// Flushes pending data to disk on the server.
    #[napi]
    pub async fn sync(&self) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.sync()
        })
        .await
    }

    /// Returns the tenant ID this client is connected as.
    #[napi(getter)]
    pub fn tenant_id(&self) -> Result<BigInt> {
        let c = lock_client(&self.inner)?;
        Ok(BigInt::from(u64::from(c.tenant_id())))
    }

    /// Returns the wire request ID of the most recently sent request, or `null`
    /// if no request has been sent yet. Useful for correlating client-side
    /// behaviour with server-side tracing output.
    #[napi(getter)]
    pub fn last_request_id(&self) -> Result<Option<BigInt>> {
        let c = lock_client(&self.inner)?;
        Ok(c.last_request_id().map(BigInt::from))
    }

    /// Subscribe to real-time events on a stream. Returns the assigned
    /// subscription ID and initial credit balance. Drain events with
    /// [`next_subscription_event`](Self::next_subscription_event).
    #[napi]
    pub async fn subscribe(
        &self,
        stream_id: BigInt,
        from_offset: BigInt,
        initial_credits: u32,
        consumer_group: Option<String>,
    ) -> Result<JsSubscribeAck> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = StreamId::from(stream_id.get_u64().1);
        let off = Offset::from(from_offset.get_u64().1);
        let ack = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.subscribe(sid, off, initial_credits, consumer_group)
        })
        .await?;
        Ok(JsSubscribeAck {
            subscription_id: BigInt::from(ack.subscription_id),
            start_offset: BigInt::from(u64::from(ack.start_offset)),
            credits: ack.credits,
        })
    }

    /// Grant additional credits to an active subscription. Returns the new
    /// server-side balance.
    #[napi]
    pub async fn grant_credits(&self, subscription_id: BigInt, additional: u32) -> Result<u32> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = subscription_id.get_u64().1;
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.grant_credits(sid, additional)
        })
        .await
    }

    /// Cancel an active subscription. The server emits a final closed event
    /// which `next_subscription_event` will surface.
    #[napi]
    pub async fn unsubscribe(&self, subscription_id: BigInt) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = subscription_id.get_u64().1;
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.unsubscribe(sid)
        })
        .await
    }

    // --- Phase 4: admin + schema + server info ---------------------------

    #[napi]
    pub async fn list_tables(&self) -> Result<Vec<JsTableInfo>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tables = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.list_tables()
        })
        .await?;
        Ok(tables
            .into_iter()
            .map(|t| JsTableInfo {
                name: t.name,
                column_count: t.column_count,
            })
            .collect())
    }

    #[napi]
    pub async fn describe_table(&self, table_name: String) -> Result<JsDescribeTable> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let resp = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.describe_table(&table_name)
        })
        .await?;
        Ok(JsDescribeTable {
            table_name: resp.table_name,
            columns: resp
                .columns
                .into_iter()
                .map(|c| JsColumnInfo {
                    name: c.name,
                    data_type: c.data_type,
                    nullable: c.nullable,
                    primary_key: c.primary_key,
                })
                .collect(),
        })
    }

    #[napi]
    pub async fn list_indexes(&self, table_name: String) -> Result<Vec<JsIndexInfo>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let indexes = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.list_indexes(&table_name)
        })
        .await?;
        Ok(indexes
            .into_iter()
            .map(|i| JsIndexInfo {
                name: i.name,
                columns: i.columns,
            })
            .collect())
    }

    #[napi]
    pub async fn tenant_create(
        &self,
        tenant_id: BigInt,
        name: Option<String>,
    ) -> Result<JsTenantCreateResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tid = TenantId::new(tenant_id.get_u64().1);
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.tenant_create(tid, name)
        })
        .await?;
        Ok(JsTenantCreateResult {
            tenant: tenant_info_to_js(r.tenant),
            created: r.created,
        })
    }

    #[napi]
    pub async fn tenant_list(&self) -> Result<Vec<JsTenantInfo>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tenants = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.tenant_list()
        })
        .await?;
        Ok(tenants.into_iter().map(tenant_info_to_js).collect())
    }

    #[napi]
    pub async fn tenant_delete(&self, tenant_id: BigInt) -> Result<JsTenantDeleteResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tid = TenantId::new(tenant_id.get_u64().1);
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.tenant_delete(tid)
        })
        .await?;
        Ok(JsTenantDeleteResult {
            deleted: r.deleted,
            tables_dropped: r.tables_dropped,
        })
    }

    #[napi]
    pub async fn tenant_get(&self, tenant_id: BigInt) -> Result<JsTenantInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tid = TenantId::new(tenant_id.get_u64().1);
        let info = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.tenant_get(tid)
        })
        .await?;
        Ok(tenant_info_to_js(info))
    }

    #[napi]
    pub async fn api_key_register(
        &self,
        subject: String,
        tenant_id: BigInt,
        roles: Vec<String>,
        expires_at_nanos: Option<BigInt>,
    ) -> Result<JsApiKeyRegisterResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tid = TenantId::new(tenant_id.get_u64().1);
        let exp = expires_at_nanos.map(|n| n.get_u64().1);
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.api_key_register(subject, tid, roles, exp)
        })
        .await?;
        Ok(JsApiKeyRegisterResult {
            key: r.key,
            info: api_key_info_to_js(r.info),
        })
    }

    #[napi]
    pub async fn api_key_revoke(&self, key: String) -> Result<bool> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.api_key_revoke(&key)
        })
        .await
    }

    #[napi]
    pub async fn api_key_list(&self, tenant_id: Option<BigInt>) -> Result<Vec<JsApiKeyInfo>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let tid = tenant_id.map(|n| TenantId::new(n.get_u64().1));
        let keys = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.api_key_list(tid)
        })
        .await?;
        Ok(keys.into_iter().map(api_key_info_to_js).collect())
    }

    #[napi]
    pub async fn api_key_rotate(&self, old_key: String) -> Result<JsApiKeyRotateResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.api_key_rotate(&old_key)
        })
        .await?;
        Ok(JsApiKeyRotateResult {
            new_key: r.new_key,
            info: api_key_info_to_js(r.info),
        })
    }

    #[napi]
    pub async fn server_info(&self) -> Result<JsServerInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let info = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.server_info()
        })
        .await?;
        Ok(JsServerInfo {
            build_version: info.build_version,
            protocol_version: u32::from(info.protocol_version),
            capabilities: info.capabilities,
            uptime_secs: BigInt::from(info.uptime_secs),
            cluster_mode: cluster_mode_to_str(info.cluster_mode).to_string(),
            tenant_count: info.tenant_count,
        })
    }

    // --- Phase 6: Masking policy catalogue (v0.6.0 Tier 2 #7) ---------

    #[napi]
    pub async fn masking_policy_create(
        &self,
        name: String,
        strategy: JsMaskingStrategy,
        exempt_roles: Vec<String>,
    ) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let spec = js_strategy_to_spec(&strategy).map_err(napi::Error::from_reason)?;
        let exempt_refs: Vec<String> = exempt_roles;
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            let roles: Vec<&str> = exempt_refs.iter().map(String::as_str).collect();
            c.masking_policy_create(&name, spec, &roles)
        })
        .await
    }

    #[napi]
    pub async fn masking_policy_drop(&self, name: String) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.masking_policy_drop(&name)
        })
        .await
    }

    #[napi]
    pub async fn masking_policy_attach(
        &self,
        table: String,
        column: String,
        policy_name: String,
    ) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.masking_policy_attach(&table, &column, &policy_name)
        })
        .await
    }

    #[napi]
    pub async fn masking_policy_detach(&self, table: String, column: String) -> Result<()> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.masking_policy_detach(&table, &column)
        })
        .await
    }

    #[napi]
    pub async fn masking_policy_list(
        &self,
        include_attachments: bool,
    ) -> Result<JsMaskingPolicyListResponse> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let resp = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.masking_policy_list(include_attachments)
        })
        .await?;
        Ok(JsMaskingPolicyListResponse {
            policies: resp
                .policies
                .into_iter()
                .map(masking_policy_info_to_js)
                .collect(),
            attachments: resp
                .attachments
                .into_iter()
                .map(|a| JsMaskingAttachmentInfo {
                    table_name: a.table_name,
                    column_name: a.column_name,
                    policy_name: a.policy_name,
                })
                .collect(),
        })
    }

    // --- Phase 5: consent + erasure -----------------------------------

    /// v0.6.2 — `terms_version` (`Option<String>`) records the
    /// terms-of-service version the subject responded to; `null`/
    /// omitted preserves pre-v0.6.2 behaviour. `accepted`
    /// (`Option<bool>`) records the acceptance state; `null`/omitted
    /// defaults to `true`. Pass `accepted = Some(false)` to capture
    /// an explicit decline (still a compliance event).
    #[napi]
    pub async fn consent_grant(
        &self,
        subject_id: String,
        purpose: JsConsentPurpose,
        basis: Option<JsConsentBasis>,
        terms_version: Option<String>,
        accepted: Option<bool>,
    ) -> Result<JsConsentGrantResult> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_purpose = js_purpose_to_wire(purpose);
        let wire_basis = basis.as_ref().map(js_basis_to_wire);
        let accepted_value = accepted.unwrap_or(true);
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.consent_grant_with_terms(
                subject_id,
                wire_purpose,
                None,
                wire_basis,
                terms_version,
                accepted_value,
            )
        })
        .await?;
        Ok(JsConsentGrantResult {
            consent_id: r.consent_id,
            granted_at_nanos: BigInt::from(r.granted_at_nanos),
        })
    }

    #[napi]
    pub async fn consent_withdraw(&self, consent_id: String) -> Result<BigInt> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.consent_withdraw(&consent_id)
        })
        .await?;
        Ok(BigInt::from(r.withdrawn_at_nanos))
    }

    #[napi]
    pub async fn consent_check(
        &self,
        subject_id: String,
        purpose: JsConsentPurpose,
    ) -> Result<bool> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_purpose = js_purpose_to_wire(purpose);
        spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.consent_check(&subject_id, wire_purpose)
        })
        .await
    }

    #[napi]
    pub async fn consent_list(
        &self,
        subject_id: String,
        valid_only: bool,
    ) -> Result<Vec<JsConsentRecord>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let records = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.consent_list(&subject_id, valid_only)
        })
        .await?;
        Ok(records.into_iter().map(consent_record_to_js).collect())
    }

    #[napi]
    pub async fn erasure_request(&self, subject_id: String) -> Result<JsErasureRequestInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_request(&subject_id)
        })
        .await?;
        Ok(erasure_request_info_to_js(r))
    }

    #[napi]
    pub async fn erasure_mark_progress(
        &self,
        request_id: String,
        stream_ids: Vec<BigInt>,
    ) -> Result<JsErasureRequestInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let streams: Vec<StreamId> = stream_ids
            .into_iter()
            .map(|b| StreamId::from(b.get_u64().1))
            .collect();
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_mark_progress(&request_id, streams)
        })
        .await?;
        Ok(erasure_request_info_to_js(r))
    }

    #[napi]
    pub async fn erasure_mark_stream_erased(
        &self,
        request_id: String,
        stream_id: BigInt,
        records_erased: BigInt,
    ) -> Result<JsErasureRequestInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let sid = StreamId::from(stream_id.get_u64().1);
        let recs = records_erased.get_u64().1;
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_mark_stream_erased(&request_id, sid, recs)
        })
        .await?;
        Ok(erasure_request_info_to_js(r))
    }

    #[napi]
    pub async fn erasure_complete(&self, request_id: String) -> Result<JsErasureAuditInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let audit = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_complete(&request_id)
        })
        .await?;
        Ok(erasure_audit_info_to_js(audit))
    }

    #[napi]
    pub async fn erasure_exempt(
        &self,
        request_id: String,
        basis: JsErasureExemptionBasis,
    ) -> Result<JsErasureRequestInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let wire_basis = js_exemption_to_wire(basis);
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_exempt(&request_id, wire_basis)
        })
        .await?;
        Ok(erasure_request_info_to_js(r))
    }

    #[napi]
    pub async fn erasure_status(&self, request_id: String) -> Result<JsErasureRequestInfo> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let r = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_status(&request_id)
        })
        .await?;
        Ok(erasure_request_info_to_js(r))
    }

    #[napi]
    pub async fn erasure_list(&self) -> Result<Vec<JsErasureAuditInfo>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let list = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.erasure_list()
        })
        .await?;
        Ok(list.into_iter().map(erasure_audit_info_to_js).collect())
    }

    /// **v0.6.0 Tier 2 #9** — query the compliance audit log.
    ///
    /// Returns PHI-safe entries — `changedFieldNames` lists the
    /// fields an action touched without disclosing any values.
    #[napi]
    pub async fn audit_query(&self, filter: JsAuditQueryFilter) -> Result<Vec<JsAuditEntry>> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let subject_id = filter.subject_id;
        let action_type = filter.action_type;
        let time_from = filter.time_from_nanos.map(|b| b.get_u64().1);
        let time_to = filter.time_to_nanos.map(|b| b.get_u64().1);
        let actor = filter.actor;
        let limit = filter.limit;
        let list = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.audit_query(subject_id, action_type, time_from, time_to, actor, limit)
        })
        .await?;
        Ok(list.into_iter().map(audit_event_info_to_js).collect())
    }

    /// Walks the compliance audit log's SHA-256 hash chain server-side
    /// and returns a structured verification report. v0.8.0.
    #[napi]
    pub async fn verify_audit_chain(&self) -> Result<JsVerifyAuditChainReport> {
        let client = self.inner.clone();
        let audit = self.audit_snapshot();
        let report = spawn_blocking_with_audit(audit, move || {
            let mut c = client.lock().expect("client mutex poisoned");
            c.verify_audit_chain()
        })
        .await?;
        Ok(JsVerifyAuditChainReport {
            ok: report.ok,
            event_count: BigInt::from(report.event_count),
            chain_head_hex: report.chain_head_hex,
            mismatch_at_index: report.mismatch_at_index.map(BigInt::from),
            error_message: report.error_message,
        })
    }

    /// Block (on a worker thread) until the next event for the given
    /// subscription ID arrives. Returns a close-marker event once the
    /// subscription has ended.
    #[napi]
    pub async fn next_subscription_event(
        &self,
        subscription_id: BigInt,
    ) -> Result<JsSubscriptionEvent> {
        let client = self.inner.clone();
        // next_subscription_event is a read-only poll; we don't need
        // audit attribution on the underlying next_push call. The
        // _audit binding above exists only because of the bulk refactor.
        let _audit = self.audit_snapshot();
        let sid = subscription_id.get_u64().1;
        tokio::task::spawn_blocking(
            move || -> std::result::Result<JsSubscriptionEvent, ClientError> {
                let mut c = client.lock().expect("client mutex poisoned");
                loop {
                    match c.next_push()? {
                        Some(push) => match push.payload {
                            PushPayload::SubscriptionEvents {
                                subscription_id: sub,
                                start_offset,
                                mut events,
                                credits_remaining: _,
                            } if sub == sid => {
                                if let Some(first) = events.drain(..1).next() {
                                    return Ok(JsSubscriptionEvent {
                                        offset: BigInt::from(u64::from(start_offset)),
                                        data: Some(Buffer::from(first)),
                                        closed: false,
                                        close_reason: None,
                                    });
                                }
                            }
                            PushPayload::SubscriptionClosed {
                                subscription_id: sub,
                                reason,
                            } if sub == sid => {
                                return Ok(JsSubscriptionEvent {
                                    offset: BigInt::from(0u64),
                                    data: None,
                                    closed: true,
                                    close_reason: Some(close_reason_to_str(reason).to_string()),
                                });
                            }
                            _ => {} // Push for another subscription — keep reading.
                        },
                        None => {
                            return Err(ClientError::Connection(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "server closed connection",
                            )));
                        }
                    }
                }
            },
        )
        .await
        .map_err(|e| Error::from_reason(format!("blocking task join error: {e}")))?
        .map_err(client_error_to_napi)
    }
}

// ============================================================================
// Connection pool
// ============================================================================

/// Configuration for [`KimberlitePool`].
#[napi(object)]
pub struct JsPoolConfig {
    pub address: String,
    pub tenant_id: BigInt,
    pub auth_token: Option<String>,
    /// Maximum concurrent connections (default 10).
    pub max_size: Option<u32>,
    /// Milliseconds to wait on `acquire` before rejecting; 0 = wait forever.
    pub acquire_timeout_ms: Option<u32>,
    /// Milliseconds an idle connection lingers before eviction; 0 = never.
    pub idle_timeout_ms: Option<u32>,
    pub read_timeout_ms: Option<u32>,
    pub write_timeout_ms: Option<u32>,
    pub buffer_size_bytes: Option<u32>,
}

/// Snapshot of pool utilisation, returned from `pool.stats()`.
#[napi(object)]
pub struct JsPoolStats {
    pub max_size: u32,
    pub open: u32,
    pub idle: u32,
    pub in_use: u32,
    pub shutdown: bool,
}

/// Thread-safe connection pool.
///
/// ```ts
/// const pool = await KimberlitePool.create({
///   address: '127.0.0.1:5432',
///   tenantId: 1n,
///   maxSize: 8,
/// });
/// const client = await pool.acquire();
/// try {
///   await client.query('SELECT 1');
/// } finally {
///   client.release();
/// }
/// ```
#[napi]
pub struct KimberlitePool {
    inner: Pool,
}

#[napi]
impl KimberlitePool {
    /// Create a new pool. Connections are not opened eagerly; the first
    /// `acquire()` triggers a `Client::connect`. Returns a Promise for
    /// JS API symmetry with `KimberliteClient.connect`, though the pool
    /// is constructed synchronously.
    #[napi(factory)]
    #[allow(clippy::unused_async)]
    pub async fn create(config: JsPoolConfig) -> Result<Self> {
        let tenant_id = TenantId::new(config.tenant_id.get_u64().1);
        let client_config = ClientConfig {
            read_timeout: config
                .read_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            write_timeout: config
                .write_timeout_ms
                .map(|ms| Duration::from_millis(u64::from(ms))),
            // v0.6.2: 4 MiB default (was 64 KiB). Framing cap =
            // `buffer_size * 2` = 8 MiB, comfortably above the SDK's
            // 1 MiB `read({ maxBytes })` default. Old default tripped
            // its own framing limit on the SDK's own defaults.
            buffer_size: config
                .buffer_size_bytes
                .map_or(4 * 1024 * 1024, |b| b as usize),
            auth_token: config.auth_token,
            auto_reconnect: true,
        };

        let pool_config = PoolConfig {
            max_size: config.max_size.map_or(10, |n| n as usize),
            acquire_timeout: match config.acquire_timeout_ms {
                Some(0) => None,
                Some(n) => Some(Duration::from_millis(u64::from(n))),
                None => Some(Duration::from_secs(30)),
            },
            idle_timeout: match config.idle_timeout_ms {
                Some(0) => None,
                Some(n) => Some(Duration::from_millis(u64::from(n))),
                None => Some(Duration::from_secs(300)),
            },
            client_config,
        };

        let inner = Pool::new(config.address.as_str(), tenant_id, pool_config)
            .map_err(client_error_to_napi)?;
        Ok(Self { inner })
    }

    /// Acquire a client from the pool. Blocks until one is available or the
    /// `acquireTimeoutMs` elapses.
    #[napi]
    pub async fn acquire(&self) -> Result<KimberlitePooledClient> {
        let pool = self.inner.clone();
        let guard = tokio::task::spawn_blocking(move || pool.acquire())
            .await
            .map_err(|e| Error::from_reason(format!("blocking task join error: {e}")))?
            .map_err(client_error_to_napi)?;
        Ok(KimberlitePooledClient {
            guard: Arc::new(Mutex::new(Some(guard))),
        })
    }

    /// Returns pool utilisation statistics.
    #[napi]
    pub fn stats(&self) -> JsPoolStats {
        let s = self.inner.stats();
        JsPoolStats {
            max_size: s.max_size as u32,
            open: s.open as u32,
            idle: s.idle as u32,
            in_use: s.in_use as u32,
            shutdown: s.shutdown,
        }
    }

    /// Shut the pool down. Subsequent acquires fail; in-flight clients close
    /// when released.
    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// Pool-borrowed client. Mirrors `KimberliteClient`'s surface but belongs to
/// a pool — call `release()` or `discard()` when done.
#[napi]
pub struct KimberlitePooledClient {
    guard: Arc<Mutex<Option<PooledClient>>>,
}

#[napi]
impl KimberlitePooledClient {
    /// Return the client to the pool. Idempotent.
    #[napi]
    pub fn release(&self) {
        // Dropping the PooledClient returns it to the pool.
        let mut slot = self.guard.lock().expect("pool guard mutex poisoned");
        slot.take();
    }

    /// Drop the underlying connection instead of returning it to the pool.
    /// Use after a fatal protocol error.
    #[napi]
    pub fn discard(&self) {
        let mut slot = self.guard.lock().expect("pool guard mutex poisoned");
        if let Some(guard) = slot.take() {
            guard.discard();
        }
    }

    #[napi(getter)]
    pub fn tenant_id(&self) -> Result<BigInt> {
        self.with_client(|c| Ok(BigInt::from(u64::from(c.tenant_id()))))
    }

    #[napi(getter)]
    pub fn last_request_id(&self) -> Result<Option<BigInt>> {
        self.with_client(|c| Ok(c.last_request_id().map(BigInt::from)))
    }

    #[napi]
    pub async fn create_stream(&self, name: String, data_class: JsDataClass) -> Result<BigInt> {
        let guard = self.guard.clone();
        let dc = map_data_class(data_class);
        let id = spawn_blocking_pooled(guard, move |c| c.create_stream(&name, dc)).await?;
        Ok(BigInt::from(u64::from(id)))
    }

    #[napi]
    pub async fn create_stream_with_placement(
        &self,
        name: String,
        data_class: JsDataClass,
        placement: JsPlacement,
    ) -> Result<BigInt> {
        let guard = self.guard.clone();
        let dc = map_data_class(data_class);
        let p = map_placement(placement);
        let id =
            spawn_blocking_pooled(guard, move |c| c.create_stream_with_placement(&name, dc, p))
                .await?;
        Ok(BigInt::from(u64::from(id)))
    }

    #[napi]
    pub async fn append(
        &self,
        stream_id: BigInt,
        events: Vec<Buffer>,
        expected_offset: BigInt,
    ) -> Result<BigInt> {
        let guard = self.guard.clone();
        let sid = StreamId::from(stream_id.get_u64().1);
        let offset = Offset::from(expected_offset.get_u64().1);
        let payload: Vec<Vec<u8>> = events.into_iter().map(|b| b.to_vec()).collect();
        let first = spawn_blocking_pooled(guard, move |c| c.append(sid, payload, offset)).await?;
        Ok(BigInt::from(u64::from(first)))
    }

    #[napi]
    pub async fn read_events(
        &self,
        stream_id: BigInt,
        from_offset: BigInt,
        max_bytes: BigInt,
    ) -> Result<JsReadEventsResponse> {
        let guard = self.guard.clone();
        let sid = StreamId::from(stream_id.get_u64().1);
        let from = Offset::from(from_offset.get_u64().1);
        let max = max_bytes.get_u64().1;
        let resp = spawn_blocking_pooled(guard, move |c| c.read_events(sid, from, max)).await?;
        Ok(JsReadEventsResponse {
            events: resp.events.into_iter().map(Buffer::from).collect(),
            next_offset: resp.next_offset.map(|o| BigInt::from(u64::from(o))),
        })
    }

    #[napi]
    pub async fn query(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
    ) -> Result<JsQueryResponse> {
        let guard = self.guard.clone();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;
        let resp = spawn_blocking_pooled(guard, move |c| c.query(&sql, &wire_params)).await?;
        Ok(JsQueryResponse {
            columns: resp.columns,
            rows: resp
                .rows
                .into_iter()
                .map(|row| row.into_iter().map(map_query_value).collect())
                .collect(),
        })
    }

    #[napi]
    pub async fn query_at(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
        position: BigInt,
    ) -> Result<JsQueryResponse> {
        let guard = self.guard.clone();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;
        let pos = Offset::from(position.get_u64().1);
        let resp =
            spawn_blocking_pooled(guard, move |c| c.query_at(&sql, &wire_params, pos)).await?;
        Ok(JsQueryResponse {
            columns: resp.columns,
            rows: resp
                .rows
                .into_iter()
                .map(|row| row.into_iter().map(map_query_value).collect())
                .collect(),
        })
    }

    #[napi]
    pub async fn execute(
        &self,
        sql: String,
        params: Option<Vec<JsQueryParam>>,
    ) -> Result<JsExecuteResult> {
        let guard = self.guard.clone();
        let wire_params: Vec<WireQueryParam> = params
            .unwrap_or_default()
            .into_iter()
            .map(map_query_param)
            .collect::<Result<Vec<_>>>()?;
        let (rows, offset) =
            spawn_blocking_pooled(guard, move |c| c.execute(&sql, &wire_params)).await?;
        Ok(JsExecuteResult {
            rows_affected: BigInt::from(rows),
            log_offset: BigInt::from(offset),
        })
    }

    #[napi]
    pub async fn sync(&self) -> Result<()> {
        let guard = self.guard.clone();
        spawn_blocking_pooled(guard, Client::sync).await
    }

    fn with_client<T>(&self, f: impl FnOnce(&Client) -> Result<T>) -> Result<T> {
        let slot = self.guard.lock().expect("pool guard mutex poisoned");
        match slot.as_ref() {
            Some(guard) => f(guard),
            None => Err(Error::from_reason(
                "[KMB_ERR_NotConnected] pooled client has been released",
            )),
        }
    }
}

async fn spawn_blocking_pooled<F, T>(guard: Arc<Mutex<Option<PooledClient>>>, f: F) -> Result<T>
where
    F: FnOnce(&mut Client) -> std::result::Result<T, ClientError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut slot = guard.lock().expect("pool guard mutex poisoned");
        let Some(pooled) = slot.as_mut() else {
            return Err(ClientError::NotConnected);
        };
        f(pooled)
    })
    .await
    .map_err(|e| Error::from_reason(format!("blocking task join error: {e}")))?
    .map_err(client_error_to_napi)
}

// ============================================================================
// Helpers
// ============================================================================

fn lock_client(inner: &Arc<Mutex<Client>>) -> Result<std::sync::MutexGuard<'_, Client>> {
    inner
        .lock()
        .map_err(|e| Error::from_reason(format!("client mutex poisoned: {e}")))
}

async fn spawn_blocking_client<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> std::result::Result<T, ClientError> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking_with_audit(None, f).await
}

/// AUDIT-2026-04 S3.9 — variant of [`spawn_blocking_client`] that
/// installs the SDK-supplied [`AuditContext`] on the worker thread
/// before running `f`, so the inner Rust client attaches the audit
/// metadata to its outgoing wire `Request.audit`.
///
/// Callers pass `Some(audit)` when they want attribution forwarded;
/// `None` degrades gracefully to the unattributed path.
async fn spawn_blocking_with_audit<F, T>(audit: Option<AuditContext>, f: F) -> Result<T>
where
    F: FnOnce() -> std::result::Result<T, ClientError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || match audit {
        Some(ctx) => run_with_audit(ctx, f),
        None => f(),
    })
    .await
    .map_err(|e| Error::from_reason(format!("blocking task join error: {e}")))?
    .map_err(client_error_to_napi)
}

fn client_error_to_napi(err: ClientError) -> Error {
    // Preserve the wire error code via a `[KMB_ERR_<code>]` prefix so the TS
    // wrapper can dispatch to a typed error subclass. The native `Status`
    // remains coarse for compatibility with generic JS consumers.
    let status = match &err {
        ClientError::Connection(_) | ClientError::Server { .. } => Status::GenericFailure,
        ClientError::NotConnected | ClientError::Timeout => Status::Cancelled,
        ClientError::Wire(_)
        | ClientError::ResponseMismatch { .. }
        | ClientError::UnexpectedResponse { .. }
        | ClientError::HandshakeFailed(_) => Status::InvalidArg,
    };

    let code_tag: &str = match &err {
        ClientError::Server { code, .. } => error_code_tag(*code),
        ClientError::Connection(_) => "Connection",
        ClientError::Timeout => "Timeout",
        ClientError::NotConnected => "NotConnected",
        ClientError::HandshakeFailed(_) => "HandshakeFailed",
        ClientError::Wire(_) => "Wire",
        ClientError::ResponseMismatch { .. } => "ResponseMismatch",
        ClientError::UnexpectedResponse { .. } => "UnexpectedResponse",
    };

    Error::new(status, format!("[KMB_ERR_{code_tag}] {err}"))
}

fn error_code_tag(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Unknown => "Unknown",
        ErrorCode::InternalError => "InternalError",
        ErrorCode::InvalidRequest => "InvalidRequest",
        ErrorCode::AuthenticationFailed => "AuthenticationFailed",
        ErrorCode::TenantNotFound => "TenantNotFound",
        ErrorCode::StreamNotFound => "StreamNotFound",
        ErrorCode::TableNotFound => "TableNotFound",
        ErrorCode::QueryParseError => "QueryParseError",
        ErrorCode::QueryExecutionError => "QueryExecutionError",
        ErrorCode::PositionAhead => "PositionAhead",
        ErrorCode::StreamAlreadyExists => "StreamAlreadyExists",
        ErrorCode::InvalidOffset => "InvalidOffset",
        ErrorCode::StorageError => "StorageError",
        ErrorCode::ProjectionLag => "ProjectionLag",
        ErrorCode::RateLimited => "RateLimited",
        ErrorCode::NotLeader => "NotLeader",
        ErrorCode::OffsetMismatch => "OffsetMismatch",
        ErrorCode::SubscriptionNotFound => "SubscriptionNotFound",
        ErrorCode::SubscriptionClosed => "SubscriptionClosed",
        ErrorCode::SubscriptionBackpressure => "SubscriptionBackpressure",
        ErrorCode::ApiKeyNotFound => "ApiKeyNotFound",
        ErrorCode::TenantAlreadyExists => "TenantAlreadyExists",
        ErrorCode::ConsentNotFound => "ConsentNotFound",
        ErrorCode::ConsentExpired => "ConsentExpired",
        ErrorCode::ErasureNotFound => "ErasureNotFound",
        ErrorCode::ErasureAlreadyComplete => "ErasureAlreadyComplete",
        ErrorCode::ErasureExempt => "ErasureExempt",
        ErrorCode::BreachNotFound => "BreachNotFound",
        ErrorCode::ExportNotFound => "ExportNotFound",
        ErrorCode::UniqueConstraintViolation => "UniqueConstraintViolation",
        ErrorCode::TenantIdTooLarge => "TenantIdTooLarge",
        ErrorCode::RowVersionChainTooLarge => "RowVersionChainTooLarge",
    }
}

fn map_data_class(dc: JsDataClass) -> DataClass {
    match dc {
        JsDataClass::PHI => DataClass::PHI,
        JsDataClass::Deidentified => DataClass::Deidentified,
        JsDataClass::PII => DataClass::PII,
        JsDataClass::Sensitive => DataClass::Sensitive,
        JsDataClass::PCI => DataClass::PCI,
        JsDataClass::Financial => DataClass::Financial,
        JsDataClass::Confidential => DataClass::Confidential,
        JsDataClass::Public => DataClass::Public,
    }
}

fn map_placement(p: JsPlacement) -> Placement {
    match p {
        JsPlacement::Global => Placement::Global,
        JsPlacement::UsEast1 => Placement::Region(Region::USEast1),
        JsPlacement::ApSoutheast2 => Placement::Region(Region::APSoutheast2),
    }
}

fn map_query_param(p: JsQueryParam) -> Result<WireQueryParam> {
    match p.kind.as_str() {
        "null" => Ok(WireQueryParam::Null),
        "bigint" => {
            let v = p
                .int_value
                .ok_or_else(|| Error::from_reason("bigint param missing int_value"))?;
            Ok(WireQueryParam::BigInt(v.get_i64().0))
        }
        "text" => {
            let v = p
                .text_value
                .ok_or_else(|| Error::from_reason("text param missing text_value"))?;
            Ok(WireQueryParam::Text(v))
        }
        "boolean" => {
            let v = p
                .bool_value
                .ok_or_else(|| Error::from_reason("boolean param missing bool_value"))?;
            Ok(WireQueryParam::Boolean(v))
        }
        "timestamp" => {
            let v = p
                .timestamp_value
                .ok_or_else(|| Error::from_reason("timestamp param missing timestamp_value"))?;
            Ok(WireQueryParam::Timestamp(v.get_i64().0))
        }
        other => Err(Error::from_reason(format!("unknown param kind: {other}"))),
    }
}

fn map_query_value(v: WireQueryValue) -> JsQueryValue {
    match v {
        WireQueryValue::Null => JsQueryValue {
            kind: "null".into(),
            int_value: None,
            text_value: None,
            bool_value: None,
            timestamp_value: None,
        },
        WireQueryValue::BigInt(i) => JsQueryValue {
            kind: "bigint".into(),
            int_value: Some(BigInt::from(i)),
            text_value: None,
            bool_value: None,
            timestamp_value: None,
        },
        WireQueryValue::Text(s) => JsQueryValue {
            kind: "text".into(),
            int_value: None,
            text_value: Some(s),
            bool_value: None,
            timestamp_value: None,
        },
        WireQueryValue::Boolean(b) => JsQueryValue {
            kind: "boolean".into(),
            int_value: None,
            text_value: None,
            bool_value: Some(b),
            timestamp_value: None,
        },
        WireQueryValue::Timestamp(t) => JsQueryValue {
            kind: "timestamp".into(),
            int_value: None,
            text_value: None,
            bool_value: None,
            timestamp_value: Some(BigInt::from(t)),
        },
    }
}
