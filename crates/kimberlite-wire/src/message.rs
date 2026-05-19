//! Request and response message types for the wire protocol.
//!
//! Messages are serialized using postcard for efficient binary encoding.

use bytes::Bytes;
use kimberlite_types::{DataClass, Offset, Placement, StreamId, TenantId};
use serde::{Deserialize, Serialize};

use crate::error::{WireError, WireResult};
use crate::frame::Frame;

/// Unique identifier for a request, used to match responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

impl RequestId {
    /// Creates a new request ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// SDK-supplied audit attribution carried on every request.
///
/// Populated from the caller's ambient audit context (Rust `AuditContext`,
/// Python `contextvars.ContextVar`, TS `AsyncLocalStorage`, Go
/// `context.Context`, Java `ThreadLocal`). The server merges this with the
/// authenticated identity when writing to the `ComplianceAuditLog` — the
/// SDK actor overrides the raw identity string so UIs can attribute an
/// action to the logged-in operator rather than the service account that
/// holds the API key.
///
/// All fields are optional. Servers that care about attribution should
/// reject mutation requests whose `actor` + authenticated identity both
/// resolve to `None`, but read paths may tolerate missing metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditMetadata {
    /// Human- or service-friendly identifier of the principal. Opaque to
    /// the server; typically an email, user UUID, or role name.
    pub actor: Option<String>,
    /// Free-form "why" for the access — critical for break-glass reads
    /// and HIPAA minimum-necessary justification.
    pub reason: Option<String>,
    /// Distributed-tracing correlation id (e.g. an HTTP `X-Request-Id`).
    /// Propagated into `ComplianceAuditEvent.correlation_id` where
    /// applicable.
    pub correlation_id: Option<String>,
    /// Caller-chosen idempotency key. Servers SHOULD deduplicate retries
    /// sharing the same key within a short window.
    pub idempotency_key: Option<String>,
}

// ============================================================================
// Request Types
// ============================================================================

/// A client request to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request identifier.
    pub id: RequestId,
    /// Tenant context for the request.
    pub tenant_id: TenantId,
    /// SDK-supplied audit attribution. `None` when the caller did not
    /// establish an audit context — servers should fall back to the
    /// authenticated identity for attribution in that case.
    pub audit: Option<AuditMetadata>,
    /// The request payload.
    pub payload: RequestPayload,
}

impl Request {
    /// Creates a new request without audit attribution.
    ///
    /// Equivalent to `Request::with_audit(id, tenant_id, None, payload)`.
    pub fn new(id: RequestId, tenant_id: TenantId, payload: RequestPayload) -> Self {
        Self::with_audit(id, tenant_id, None, payload)
    }

    /// Creates a new request carrying SDK-supplied audit attribution.
    pub fn with_audit(
        id: RequestId,
        tenant_id: TenantId,
        audit: Option<AuditMetadata>,
        payload: RequestPayload,
    ) -> Self {
        Self {
            id,
            tenant_id,
            audit,
            payload,
        }
    }

    /// Encodes the request to a frame.
    pub fn to_frame(&self) -> WireResult<Frame> {
        let payload =
            postcard::to_allocvec(self).map_err(|e| WireError::Serialization(e.to_string()))?;
        Ok(Frame::new(Bytes::from(payload)))
    }

    /// Decodes a request from a frame.
    pub fn from_frame(frame: &Frame) -> WireResult<Self> {
        postcard::from_bytes(&frame.payload).map_err(WireError::from)
    }
}

/// Request payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestPayload {
    /// Handshake to establish connection.
    Handshake(HandshakeRequest),
    /// Create a new stream.
    CreateStream(CreateStreamRequest),
    /// Append events to a stream.
    AppendEvents(AppendEventsRequest),
    /// Execute a SQL query.
    Query(QueryRequest),
    /// Execute a SQL query at a specific position.
    QueryAt(QueryAtRequest),
    /// Read events from a stream.
    ReadEvents(ReadEventsRequest),
    /// Get a stream's current length (event count) without paging events.
    ///
    /// v0.8.0 — replaces full-stream walks for counting, which notebar
    /// hit on every Group-1 telemetry site. Reads
    /// `StreamMetadata.current_offset` server-side; O(1).
    StreamInfo(StreamInfoRequest),
    /// Subscribe to real-time events on a stream.
    Subscribe(SubscribeRequest),
    /// Sync all data to disk.
    Sync(SyncRequest),
    /// Grant additional flow-control credits to an existing subscription.
    SubscribeCredit(SubscribeCreditRequest),
    /// Cancel an existing subscription.
    Unsubscribe(UnsubscribeRequest),

    // ---- Phase 4: schema introspection (admin.v1) -------------------
    /// List all tables in the caller's tenant.
    ListTables(ListTablesRequest),
    /// Describe a table's columns + primary key.
    DescribeTable(DescribeTableRequest),
    /// List indexes on a table.
    ListIndexes(ListIndexesRequest),

    // ---- Phase 4: tenant management (admin-only) --------------------
    /// Register a new tenant in the server's registry.
    TenantCreate(TenantCreateRequest),
    /// List every tenant the server knows about.
    TenantList(TenantListRequest),
    /// Delete a tenant — drops all tables and removes from registry.
    TenantDelete(TenantDeleteRequest),
    /// Return summary info for a tenant.
    TenantGet(TenantGetRequest),

    // ---- Phase 4: API-key lifecycle (admin-only) --------------------
    /// Issue a new API key (returns plaintext once).
    ApiKeyRegister(ApiKeyRegisterRequest),
    /// Revoke a plaintext API key.
    ApiKeyRevoke(ApiKeyRevokeRequest),
    /// List API keys' metadata (no plaintext).
    ApiKeyList(ApiKeyListRequest),
    /// Atomic rotate — issue new, revoke old, return the new plaintext.
    ApiKeyRotate(ApiKeyRotateRequest),

    // ---- Phase 4: server info ---------------------------------------
    /// Get server version + capabilities + uptime.
    GetServerInfo(GetServerInfoRequest),

    // ---- Phase 5: Consent (GDPR Article 7) --------------------------
    ConsentGrant(ConsentGrantRequest),
    ConsentWithdraw(ConsentWithdrawRequest),
    ConsentCheck(ConsentCheckRequest),
    ConsentList(ConsentListRequest),

    // ---- Phase 5: Erasure (GDPR Article 17) -------------------------
    ErasureRequest(ErasureRequestRequest),
    ErasureMarkProgress(ErasureMarkProgressRequest),
    ErasureMarkStreamErased(ErasureMarkStreamErasedRequest),
    ErasureComplete(ErasureCompleteRequest),
    ErasureExempt(ErasureExemptRequest),
    ErasureStatus(ErasureStatusRequest),
    ErasureList(ErasureListRequest),

    // ---- Phase 6: Audit ----------------------------------------------
    AuditQuery(AuditQueryRequest),
    /// v0.8.0 — walk the compliance audit log's SHA-256 hash chain
    /// and return a structured verification report.
    VerifyAuditChain(VerifyAuditChainRequest),

    // ---- Phase 6: Export (GDPR Article 20) ---------------------------
    ExportSubject(ExportSubjectRequest),
    VerifyExport(VerifyExportRequest),

    // ---- Phase 6: Breach (HIPAA §164.404 / GDPR Article 33) ----------
    BreachReportIndicator(BreachReportIndicatorRequest),
    BreachQueryStatus(BreachQueryStatusRequest),
    BreachConfirm(BreachConfirmRequest),
    BreachResolve(BreachResolveRequest),

    // ---- Phase 6: Masking Policy catalogue (v0.6.0 Tier 2 #7) --------
    //
    // Mutating operations (CREATE / ALTER SET / ALTER DROP / DROP
    // MASKING POLICY) flow through the existing SQL `execute` path —
    // no new RPC shape needed there. Only the read surface requires a
    // dedicated RPC because there is no SELECT-like SQL for it today.
    /// List every masking policy in the caller's tenant catalogue.
    MaskingPolicyList(MaskingPolicyListRequest),
}

/// Handshake request to establish connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Client protocol version.
    pub client_version: u16,
    /// Optional authentication token.
    pub auth_token: Option<String>,
}

/// Create stream request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStreamRequest {
    /// Stream name.
    pub name: String,
    /// Data classification.
    pub data_class: DataClass,
    /// Placement policy.
    pub placement: Placement,
}

/// Append events request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEventsRequest {
    /// Target stream.
    pub stream_id: StreamId,
    /// Events to append.
    pub events: Vec<Vec<u8>>,
    /// Expected stream offset for optimistic concurrency control.
    pub expected_offset: Offset,
}

/// SQL query request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    /// SQL query string.
    pub sql: String,
    /// Query parameters.
    pub params: Vec<QueryParam>,
    /// Optional structured break-glass reason.
    ///
    /// When present, the server records the query as a break-glass access
    /// with this reason attached to the audit event — bypassing the
    /// legacy `WITH BREAK_GLASS REASON='...'` SQL prefix (which is
    /// retained for backward compat but injection-adjacent). SDKs SHOULD
    /// pass the reason here instead of splicing it into `sql`.
    #[serde(default)]
    pub break_glass_reason: Option<String>,
}

/// SQL query at specific position request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAtRequest {
    /// SQL query string.
    pub sql: String,
    /// Query parameters.
    pub params: Vec<QueryParam>,
    /// Log position to query at.
    pub position: Offset,
    /// Optional structured break-glass reason (see `QueryRequest`).
    #[serde(default)]
    pub break_glass_reason: Option<String>,
}

/// Query parameter value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryParam {
    /// Null value.
    Null,
    /// 64-bit integer.
    BigInt(i64),
    /// Text string.
    Text(String),
    /// Boolean.
    Boolean(bool),
    /// Timestamp (nanoseconds since epoch).
    Timestamp(i64),
}

/// Read events request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadEventsRequest {
    /// Source stream.
    pub stream_id: StreamId,
    /// Starting offset (inclusive).
    pub from_offset: Offset,
    /// Maximum bytes to read.
    pub max_bytes: u64,
}

/// Get a stream's current length without paging events.
///
/// Reads `StreamMetadata.current_offset` server-side and returns it as a
/// `u64`. Saves callers from issuing a full-stream `ReadEvents` walk
/// just to count rows. Future versions may grow additional metadata
/// fields on the response (postcard tolerates additive fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfoRequest {
    /// Target stream.
    pub stream_id: StreamId,
}

/// Subscribe to real-time events on a stream.
///
/// The server will push events as they are appended to the stream,
/// starting from `from_offset`. The client controls flow with a credit
/// system: the server sends up to `initial_credits` events before waiting
/// for the client to grant more credits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// Stream to subscribe to.
    pub stream_id: StreamId,
    /// Starting offset (inclusive).
    pub from_offset: Offset,
    /// Maximum events the server may send before needing more credits.
    pub initial_credits: u32,
    /// Optional consumer group name for coordinated consumption.
    pub consumer_group: Option<String>,
}

/// Sync request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {}

/// Grant additional flow-control credits to an active subscription.
///
/// The server stops sending push frames for a subscription once its credit
/// balance reaches zero; this request replenishes the balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeCreditRequest {
    /// Subscription returned from the original `Subscribe` response.
    pub subscription_id: u64,
    /// Number of additional events the server may push before waiting again.
    pub additional_credits: u32,
}

/// Cancel a subscription. The server closes its send queue and emits a
/// single `SubscriptionClosed` push before forgetting the subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// Subscription to cancel.
    pub subscription_id: u64,
}

// ============================================================================
// Phase 4 — schema introspection
// ============================================================================

/// Request to list every table in the caller's tenant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListTablesRequest {}

/// Summary metadata for a single table (from `ListTables` / `TenantGet`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    /// Number of columns in the table (useful for CLI / dashboard summaries).
    pub column_count: u32,
}

/// Response for [`ListTablesRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTablesResponse {
    pub tables: Vec<TableInfo>,
}

/// Request to describe a single table's columns + primary key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeTableRequest {
    pub table_name: String,
}

/// Column metadata returned by [`DescribeTableResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    /// Column type rendered as a SQL type string (e.g. `"BIGINT"`, `"TEXT"`).
    pub data_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

/// Response for [`DescribeTableRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeTableResponse {
    pub table_name: String,
    pub columns: Vec<ColumnInfo>,
}

/// Request to list indexes defined on a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIndexesRequest {
    pub table_name: String,
}

/// Index metadata returned by [`ListIndexesResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    pub name: String,
    pub columns: Vec<String>,
}

/// Response for [`ListIndexesRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIndexesResponse {
    pub indexes: Vec<IndexInfo>,
}

// ============================================================================
// Phase 4 — tenant management
// ============================================================================

/// Tenant summary. Populated by `TenantList` and `TenantGet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInfo {
    pub tenant_id: TenantId,
    /// Optional human-readable name assigned at create time.
    pub name: Option<String>,
    pub table_count: u32,
    /// Unix-nanosecond timestamp when the tenant was first registered,
    /// or `None` if the server cannot determine it.
    pub created_at_nanos: Option<u64>,
}

/// Request to register a tenant.
///
/// `tenant_id` is required; `name` is an optional label stored in the server's
/// in-memory registry. If the tenant already exists the response carries the
/// existing registration (idempotent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreateRequest {
    pub tenant_id: TenantId,
    pub name: Option<String>,
}

/// Response for [`TenantCreateRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreateResponse {
    pub tenant: TenantInfo,
    /// `true` if this call created the registration; `false` if it was
    /// already present (idempotent re-registration).
    pub created: bool,
}

/// Request to list every tenant on the server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantListRequest {}

/// Response for [`TenantListRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantListResponse {
    pub tenants: Vec<TenantInfo>,
}

/// Request to delete a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDeleteRequest {
    pub tenant_id: TenantId,
}

/// Response for [`TenantDeleteRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDeleteResponse {
    pub deleted: bool,
    pub tables_dropped: u32,
}

/// Request for a tenant summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantGetRequest {
    pub tenant_id: TenantId,
}

/// Response for [`TenantGetRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantGetResponse {
    pub tenant: TenantInfo,
}

// ============================================================================
// Phase 4 — API-key lifecycle
// ============================================================================

/// API-key metadata (never includes plaintext or hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    /// Short identifier of the key (first 8 chars of the hash, hex-encoded).
    pub key_id: String,
    pub subject: String,
    pub tenant_id: TenantId,
    pub roles: Vec<String>,
    pub expires_at_nanos: Option<u64>,
}

/// Request to issue a new API key.
///
/// The server generates a cryptographically random key, stores its hash, and
/// returns the plaintext exactly once. Callers must persist the plaintext —
/// it cannot be recovered later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRegisterRequest {
    pub subject: String,
    pub tenant_id: TenantId,
    pub roles: Vec<String>,
    /// Optional expiry as Unix nanoseconds. `None` = non-expiring.
    pub expires_at_nanos: Option<u64>,
}

/// Response for [`ApiKeyRegisterRequest`].
///
/// `key` is returned in plaintext exactly once. Store it immediately — the
/// server retains only a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRegisterResponse {
    pub key: String,
    pub info: ApiKeyInfo,
}

/// Request to revoke an existing API key by plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRevokeRequest {
    pub key: String,
}

/// Response for [`ApiKeyRevokeRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRevokeResponse {
    pub revoked: bool,
}

/// Request to list API keys, optionally filtered by tenant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiKeyListRequest {
    pub tenant_id: Option<TenantId>,
}

/// Response for [`ApiKeyListRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyListResponse {
    pub keys: Vec<ApiKeyInfo>,
}

/// Request to rotate an existing API key.
///
/// Semantically: issue a new key with identical subject/tenant/roles/expiry,
/// revoke the old plaintext, and return the new plaintext. The two steps
/// are performed atomically with respect to `AuthService`'s internal lock
/// so concurrent callers cannot observe an intermediate state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRotateRequest {
    pub old_key: String,
}

/// Response for [`ApiKeyRotateRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRotateResponse {
    pub new_key: String,
    pub info: ApiKeyInfo,
}

// ============================================================================
// Phase 4 — server info
// ============================================================================

/// Request the server's canonical info block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetServerInfoRequest {}

/// Replication / cluster mode the server is running in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterMode {
    /// Single-node direct mode (no replication).
    Standalone,
    /// Multi-node cluster with VSR consensus.
    Clustered,
}

/// Response for [`GetServerInfoRequest`].
///
/// Returns the authoritative view of what the server supports — replaces
/// the fixed `HandshakeResponse.capabilities` in v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoResponse {
    /// Semantic version of the server binary (e.g. `"0.5.0"`).
    pub build_version: String,
    /// Wire protocol version (currently `2`).
    pub protocol_version: u16,
    /// Capability strings the server advertises (e.g. `"subscribe.v2"`).
    pub capabilities: Vec<String>,
    /// Seconds since the server started.
    pub uptime_secs: u64,
    pub cluster_mode: ClusterMode,
    /// Number of registered tenants.
    pub tenant_count: u32,
}

// ============================================================================
// Phase 5 — Consent (GDPR Article 7)
// ============================================================================

/// Purposes a subject can grant consent for. Mirrors
/// `kimberlite_compliance::purpose::Purpose`. The five `Treatment`,
/// `Payment`, `Operations`, `PublicHealth`, `Emergency` variants are
/// HIPAA TPO + extensions — added when the database focused on
/// healthcare; pre-existing wire payloads (which only use the GDPR
/// variants) round-trip unchanged because postcard variant tags are
/// append-only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentPurpose {
    Marketing,
    Analytics,
    Contractual,
    LegalObligation,
    VitalInterests,
    PublicTask,
    Research,
    Security,
    Treatment,
    Payment,
    Operations,
    PublicHealth,
    Emergency,
}

/// Scope of a consent grant. Mirrors
/// `kimberlite_compliance::consent::ConsentScope`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentScope {
    AllData,
    ContactInfo,
    AnalyticsOnly,
    ContractualNecessity,
}

/// GDPR Article 6(1) lawful basis for processing personal data.
///
/// Mirrors the TS `GdprArticle` string-literal union and the Python
/// `ConsentBasis.article` enum. Captured on `ConsentGrantRequest` so
/// regulated industries (clinical ops, financial compliance) can
/// record the paragraph letter alongside a free-form justification
/// for the audit trail.
///
/// Wire protocol v4 (v0.6.0) — absent on v3 payloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GdprArticle {
    /// (a) the data subject has given consent.
    Consent,
    /// (b) necessary for performance of a contract.
    Contract,
    /// (c) necessary for compliance with a legal obligation.
    LegalObligation,
    /// (d) necessary to protect vital interests.
    VitalInterests,
    /// (e) necessary for a task carried out in the public interest.
    PublicTask,
    /// (f) necessary for the purposes of legitimate interests.
    LegitimateInterests,
}

/// GDPR Article 6(1) lawful basis + caller-supplied justification.
///
/// Added in wire protocol v4. `Option<ConsentBasis>` encodes as a
/// single tag byte `0x00` when absent (postcard variable-length
/// encoding), so a v3 payload — which lacks the field entirely —
/// round-trips into a v4 struct with `basis = None` as long as the
/// outer `Option<ConsentBasis>` sits at the tail of the struct
/// (which it does for both `ConsentGrantRequest` and
/// `ConsentRecord`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentBasis {
    /// The GDPR Article 6(1)(a)–(f) lettered basis.
    pub article: GdprArticle,
    /// Free-form justification captured at grant time.
    pub justification: Option<String>,
}

/// A consent record returned by `ConsentList` / lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// UUID as a string (wire types don't depend on uuid/chrono).
    pub consent_id: String,
    pub subject_id: String,
    pub purpose: ConsentPurpose,
    pub scope: ConsentScope,
    /// Unix nanoseconds when consent was granted.
    pub granted_at_nanos: u64,
    /// Unix nanoseconds when withdrawn, if withdrawn.
    pub withdrawn_at_nanos: Option<u64>,
    /// Unix nanoseconds for the expiry, if bounded.
    pub expires_at_nanos: Option<u64>,
    pub notes: Option<String>,
    /// GDPR Article 6(1) lawful basis + justification. Populated
    /// when the grant call supplied a [`ConsentBasis`]; `None` on
    /// records granted before v4 or on grants that omitted the
    /// basis. Added in wire protocol v4 (v0.6.0).
    #[serde(default)]
    pub basis: Option<ConsentBasis>,
    /// Terms-of-service version the subject responded to. `None`
    /// on v0.6.1 records and on grants that omitted the field.
    /// Added in v0.6.2 (wire protocol stays at v4 — tail-positioned
    /// optional with serde default keeps round-trip compatible).
    #[serde(default)]
    pub terms_version: Option<String>,
    /// Whether the subject accepted (`true`, default) or declined
    /// (`false`). v0.6.1 records deserialize as `true` because
    /// consent grants were acceptance-only. Added in v0.6.2.
    #[serde(default = "default_accepted_wire")]
    pub accepted: bool,
}

/// Request to grant consent for a subject + purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentGrantRequest {
    pub subject_id: String,
    pub purpose: ConsentPurpose,
    /// Optional scope; defaults to `AllData` when absent.
    pub scope: Option<ConsentScope>,
    /// GDPR Article 6(1) lawful basis + justification. Added in
    /// wire protocol v4 (v0.6.0). Absent on v3 payloads.
    #[serde(default)]
    pub basis: Option<ConsentBasis>,
    /// Terms-of-service version the subject responded to. `None`
    /// on v0.6.1 payloads and on grants that omit the field. Added
    /// in v0.6.2 (wire stays at v4 — see `ConsentRecord` note).
    #[serde(default)]
    pub terms_version: Option<String>,
    /// Whether the subject accepted (`true`, default) or declined
    /// (`false`). v0.6.1 payloads default to `true`. Added in v0.6.2.
    #[serde(default = "default_accepted_wire")]
    pub accepted: bool,
}

/// v0.6.2 — `#[serde(default)]` value for `accepted` on
/// `ConsentRecord` and `ConsentGrantRequest`. Pre-v0.6.2 wire
/// payloads omit the field; deserialize them as `true` so
/// upgraded servers/clients keep round-tripping cleanly with
/// pre-v0.6.2 peers.
fn default_accepted_wire() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentGrantResponse {
    pub consent_id: String,
    pub granted_at_nanos: u64,
}

/// Request to withdraw consent by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentWithdrawRequest {
    pub consent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentWithdrawResponse {
    pub withdrawn_at_nanos: u64,
}

/// Check if a subject has a valid consent for a purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentCheckRequest {
    pub subject_id: String,
    pub purpose: ConsentPurpose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentCheckResponse {
    pub is_valid: bool,
}

/// List every consent record for a subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentListRequest {
    pub subject_id: String,
    /// When `true`, only return non-withdrawn, non-expired consents.
    /// Defaults to `false` (full history).
    pub valid_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentListResponse {
    pub consents: Vec<ConsentRecord>,
}

// ============================================================================
// Phase 5 — Erasure (GDPR Article 17)
// ============================================================================

/// Reason a request is exempt from erasure. Mirrors
/// `kimberlite_compliance::erasure::ExemptionBasis`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErasureExemptionBasis {
    LegalObligation,
    PublicHealth,
    Archiving,
    LegalClaims,
}

/// Status of an erasure request. Mirrors
/// `kimberlite_compliance::erasure::ErasureStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErasureStatusTag {
    Pending,
    InProgress {
        streams_remaining: u32,
    },
    Complete {
        erased_at_nanos: u64,
        total_records: u64,
    },
    Failed {
        reason: String,
        retry_at_nanos: u64,
    },
    Exempt {
        basis: ErasureExemptionBasis,
    },
}

/// Detail record for a single erasure request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRequestInfo {
    pub request_id: String,
    pub subject_id: String,
    pub requested_at_nanos: u64,
    /// 30-day deadline by default.
    pub deadline_nanos: u64,
    pub status: ErasureStatusTag,
    pub records_erased: u64,
    pub streams_affected: Vec<StreamId>,
}

/// Record from the erasure audit trail (one per completed request).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureAuditInfo {
    pub request_id: String,
    pub subject_id: String,
    pub requested_at_nanos: u64,
    pub completed_at_nanos: u64,
    pub records_erased: u64,
    pub streams_affected: Vec<StreamId>,
    /// Hex-encoded SHA-256 proof. Callers who need the raw bytes should
    /// decode via `hex::decode`.
    pub erasure_proof_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRequestRequest {
    pub subject_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRequestResponse {
    pub request: ErasureRequestInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureMarkProgressRequest {
    pub request_id: String,
    pub streams: Vec<StreamId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureMarkProgressResponse {
    pub request: ErasureRequestInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureMarkStreamErasedRequest {
    pub request_id: String,
    pub stream_id: StreamId,
    pub records_erased: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureMarkStreamErasedResponse {
    pub request: ErasureRequestInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCompleteRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCompleteResponse {
    pub audit: ErasureAuditInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureExemptRequest {
    pub request_id: String,
    pub basis: ErasureExemptionBasis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureExemptResponse {
    pub request: ErasureRequestInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureStatusRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureStatusResponse {
    pub request: ErasureRequestInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErasureListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureListResponse {
    /// Every in-flight / completed / exempt erasure request (from audit log).
    pub audit: Vec<ErasureAuditInfo>,
}

// ============================================================================
// Phase 6 — Audit
// ============================================================================

/// Filter for [`AuditQueryRequest`]. All fields are optional; unset fields
/// don't constrain the query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQueryRequest {
    pub subject_id: Option<String>,
    /// Action-type prefix (`"Consent"`, `"Erasure"`, `"Breach"`, ...).
    pub action_type: Option<String>,
    pub time_from_nanos: Option<u64>,
    pub time_to_nanos: Option<u64>,
    pub actor: Option<String>,
    pub limit: Option<u32>,
}

/// **v0.6.0 Tier 2 #9** — SDK-safe audit entry.
///
/// Carries **no** before/after values from the action payload — only
/// [`Self::changed_field_names`] lists the *names* of the fields the
/// action touched. This is the type the Rust / Python / TypeScript
/// SDKs expose via `client.compliance.audit.query(...)`.
///
/// # Invariant — no value leakage
///
/// The encoded bytes of this struct must not contain any value from
/// the underlying `ComplianceAuditAction` payload. Enforced by the
/// property test
/// `audit_sdk_entry_never_leaks_values` in `kimberlite-compliance`
/// and reinforced at the wire boundary by the projection in
/// `kimberlite-server::server::handle_audit_query`.
///
/// # Previous shape (pre-v0.6.0)
///
/// The older `AuditEventInfo` shape shipped in v0.5.0 carried a
/// full `action_json: String` blob of the serialised action — that
/// leaked before/after values and is explicitly replaced here per
/// v0.6.0 Tier 2 #9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventInfo {
    /// UUID (string) of the underlying `ComplianceAuditEvent`.
    pub event_id: String,
    /// When the event occurred, nanoseconds since Unix epoch.
    pub timestamp_nanos: u64,
    /// Action kind tag (e.g. `"ConsentGranted"`, `"ErasureCompleted"`).
    /// Stable per variant. This replaces the v0.5.0 `action_kind` name.
    pub action: String,
    /// Subject id extracted from the action payload, if the action
    /// has one. Actions without a subject (e.g. `FieldMasked`)
    /// encode `None` here.
    pub subject_id: Option<String>,
    pub actor: Option<String>,
    pub tenant_id: Option<u64>,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
    /// Request id for erasure-lifecycle actions.
    pub request_id: Option<String>,
    /// Free-form reason (GDPR Article 17(3) exemption basis when
    /// applicable). `None` for actions that don't carry a reason.
    pub reason: Option<String>,
    pub source_country: Option<String>,
    /// **Field names only** — never values. Lists the schema of the
    /// underlying action payload so dashboards can render
    /// "what changed" without disclosing the data.
    pub changed_field_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    pub events: Vec<AuditEventInfo>,
}

/// v0.8.0 — request to verify the compliance audit log's SHA-256
/// hash chain. Currently no fields; the tenant scope is taken from
/// the request envelope. Future versions may grow `since_nanos` /
/// `until_nanos` for sub-range verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyAuditChainRequest {}

/// v0.8.0 — structured chain-verification report. `ok == true` means
/// the chain is intact; on failure, `mismatch_at_index` and
/// `error_message` name the earliest broken event so a regulator-
/// visible report can pinpoint the tampering location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAuditChainResponse {
    /// Whole-chain verdict.
    pub ok: bool,
    /// Number of events walked. Valid even when `ok == false`.
    pub event_count: u64,
    /// Hex-encoded SHA-256 chain head (current `event_hash` of the
    /// last event, or `"00" * 32` for an empty log). Always present
    /// — even on failure — because the head is read directly off the
    /// log structure rather than recomputed.
    pub chain_head_hex: String,
    /// Earliest mismatched event index when `ok == false`. `None`
    /// when the chain is intact.
    pub mismatch_at_index: Option<u64>,
    /// Display form of the underlying audit-chain error. `None`
    /// when the chain is intact.
    pub error_message: Option<String>,
}

// ============================================================================
// Phase 6 — Export (GDPR Article 20)
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSubjectRequest {
    pub subject_id: String,
    pub requester_id: String,
    pub format: ExportFormat,
    /// Streams to include. Empty = all streams the caller can see.
    pub stream_ids: Vec<StreamId>,
    /// Max records per stream (0 = unbounded, bounded server-side).
    pub max_records_per_stream: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortabilityExportInfo {
    pub export_id: String,
    pub subject_id: String,
    pub requester_id: String,
    pub requested_at_nanos: u64,
    pub completed_at_nanos: u64,
    pub format: ExportFormat,
    pub streams_included: Vec<StreamId>,
    pub record_count: u64,
    /// Hex-encoded SHA-256 of the serialised export body.
    pub content_hash_hex: String,
    /// Hex-encoded HMAC signature, if the server configured a signing key.
    pub signature_hex: Option<String>,
    /// Raw exported body (JSON or CSV) — base64-encoded to keep the
    /// wire message valid UTF-8.
    pub body_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSubjectResponse {
    pub export: PortabilityExportInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyExportRequest {
    pub export_id: String,
    /// Re-supplied body (base64). Server recomputes `SHA-256` and checks
    /// signature if present.
    pub body_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyExportResponse {
    pub valid: bool,
    /// `true` if the HMAC signature matched. `false` if the server had no
    /// signing key configured.
    pub signature_valid: bool,
}

// ============================================================================
// Phase 6 — Breach (HIPAA §164.404 / GDPR Article 33)
// ============================================================================

/// Kind of breach indicator the caller is reporting. Mirrors
/// `kimberlite_compliance::breach::BreachIndicator` variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreachIndicatorPayload {
    MassDataExport {
        records: u64,
        data_classes: Vec<kimberlite_types::DataClass>,
    },
    UnauthorizedAccessPattern {
        denied_attempts: u64,
        window_secs: u64,
    },
    PrivilegeEscalation {
        from_role: String,
        to_role: String,
    },
    AnomalousQueryVolume {
        queries_per_min: u64,
        baseline: u64,
    },
    UnusualAccessTime {
        hour: u8,
    },
    DataExfiltrationPattern {
        bytes_exported: u64,
        data_classes: Vec<kimberlite_types::DataClass>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BreachSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreachStatusTag {
    Detected,
    UnderInvestigation,
    Confirmed {
        notification_sent_at_nanos: Option<u64>,
    },
    FalsePositive {
        dismissed_by: String,
        reason: String,
    },
    Resolved {
        resolved_at_nanos: u64,
        remediation: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEventInfo {
    pub event_id: String,
    pub detected_at_nanos: u64,
    pub indicator: BreachIndicatorPayload,
    pub severity: BreachSeverity,
    pub affected_subjects: Option<u64>,
    pub affected_data_classes: Vec<kimberlite_types::DataClass>,
    pub notification_deadline_nanos: u64,
    pub status: BreachStatusTag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReportInfo {
    pub event: BreachEventInfo,
    pub timeline: Vec<String>,
    pub affected_subject_count: u64,
    pub data_categories: Vec<kimberlite_types::DataClass>,
    pub remediation_steps: Vec<String>,
    pub notification_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReportIndicatorRequest {
    pub indicator: BreachIndicatorPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReportIndicatorResponse {
    /// `Some` if the indicator triggered a breach; `None` if below threshold.
    pub event: Option<BreachEventInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachQueryStatusRequest {
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachQueryStatusResponse {
    pub report: BreachReportInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachConfirmRequest {
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachConfirmResponse {
    pub notification_sent_at_nanos: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachResolveRequest {
    pub event_id: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachResolveResponse {
    pub resolved_at_nanos: u64,
}

// ============================================================================
// Phase 6: Masking Policy catalogue (v0.6.0 Tier 2 #7)
// ============================================================================
//
// Wire-local mirror of the kernel's `MaskingStrategyKind`. Kept here
// rather than in `kimberlite-types` so the kimberlite-wire ↔ kernel
// dependency direction stays one-way (wire leaf-like). Translation
// happens in the server handler.

/// Wire-level enum for a masking policy's strategy. 1:1 with the kernel's
/// `MaskingStrategyKind`. Uses the default externally-tagged serde form
/// because `postcard` (the kimberlite-wire serialiser) does not support
/// `#[serde(tag = "...")]` internally-tagged enums.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskingStrategyWire {
    /// `REDACT_SSN` / `REDACT_PHONE` / `REDACT_EMAIL` / `REDACT_CC`
    /// patterns plus the `REDACT_CUSTOM { replacement }` form.
    Redact {
        /// Pattern label: "SSN" | "PHONE" | "EMAIL" | "CC" | "CUSTOM".
        pattern: String,
        /// Only populated when `pattern == "CUSTOM"`.
        replacement: Option<String>,
    },
    /// SHA-256 hex digest.
    Hash,
    /// BLAKE3-derived deterministic token.
    Tokenize,
    /// Keep first `max_chars`, pad with `"..."`.
    Truncate { max_chars: u64 },
    /// Replace with empty/NULL.
    Null,
}

/// Summary metadata for a single masking policy (from `MaskingPolicyList`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingPolicyInfo {
    /// Policy name, unique per tenant.
    pub name: String,
    /// The decomposed strategy (kernel's `MaskingStrategyKind`).
    pub strategy: MaskingStrategyWire,
    /// Roles exempt from masking (they see the raw value). Lower-cased.
    pub exempt_roles: Vec<String>,
    /// `true` when roles not in `exempt_roles` see the masked value — the
    /// only currently-reachable form from DDL. Kept as an explicit field
    /// for forward compat with inverted-guard syntaxes.
    pub default_masked: bool,
    /// Number of `(table, column)` pairs this policy is attached to.
    /// Lets clients render "used by N columns" without a second RPC.
    pub attachment_count: u32,
}

/// Summary of a single masking-policy attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingAttachmentInfo {
    /// Owning table name.
    pub table_name: String,
    /// Attached column name.
    pub column_name: String,
    /// Name of the attached policy (look up via `MaskingPolicyList`).
    pub policy_name: String,
}

/// Request: list every masking policy in the caller's tenant catalogue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaskingPolicyListRequest {
    /// When `true`, the response additionally enumerates every
    /// `(table, column)` attachment. Defaults to `false` (policies only)
    /// to keep the common "did my CREATE succeed" path small.
    #[serde(default)]
    pub include_attachments: bool,
}

/// Response to [`MaskingPolicyListRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingPolicyListResponse {
    /// Every policy in the tenant's catalogue. Order is
    /// catalogue-insertion (kernel `BTreeMap` by name).
    pub policies: Vec<MaskingPolicyInfo>,
    /// Populated only when `include_attachments = true` on the request.
    /// Empty otherwise.
    #[serde(default)]
    pub attachments: Vec<MaskingAttachmentInfo>,
}

// ============================================================================
// Response Types
// ============================================================================

/// A server response to a client request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Request ID this is responding to.
    pub request_id: RequestId,
    /// The response payload.
    pub payload: ResponsePayload,
}

impl Response {
    /// Creates a new response.
    pub fn new(request_id: RequestId, payload: ResponsePayload) -> Self {
        Self {
            request_id,
            payload,
        }
    }

    /// Creates an error response.
    pub fn error(request_id: RequestId, code: ErrorCode, message: String) -> Self {
        Self {
            request_id,
            payload: ResponsePayload::Error(ErrorResponse { code, message }),
        }
    }

    /// Encodes the response to a frame.
    pub fn to_frame(&self) -> WireResult<Frame> {
        let payload =
            postcard::to_allocvec(self).map_err(|e| WireError::Serialization(e.to_string()))?;
        Ok(Frame::new(Bytes::from(payload)))
    }

    /// Decodes a response from a frame.
    pub fn from_frame(frame: &Frame) -> WireResult<Self> {
        postcard::from_bytes(&frame.payload).map_err(WireError::from)
    }
}

// ============================================================================
// Push (server-initiated) messages
// ============================================================================

/// A server-initiated push frame (no `RequestId`; correlated by
/// `subscription_id` inside the payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Push {
    pub payload: PushPayload,
}

impl Push {
    pub fn new(payload: PushPayload) -> Self {
        Self { payload }
    }
}

/// Payload of a server-initiated [`Push`] frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PushPayload {
    /// A batch of stream events for an active subscription. The server sends
    /// these as events arrive, bounded by the subscription's credit balance.
    SubscriptionEvents {
        subscription_id: u64,
        /// Starting offset of the first event in `events`.
        start_offset: Offset,
        /// Event payloads, in stream order.
        events: Vec<Vec<u8>>,
        /// Remaining server-side credit balance after this batch.
        credits_remaining: u32,
    },
    /// Subscription has been closed. No further push frames will arrive.
    SubscriptionClosed {
        subscription_id: u64,
        reason: SubscriptionCloseReason,
    },
}

/// Why a subscription ended.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubscriptionCloseReason {
    /// Client explicitly called `Unsubscribe`.
    ClientCancelled,
    /// Server shutting down / losing leadership.
    ServerShutdown,
    /// Stream was deleted.
    StreamDeleted,
    /// Client failed to keep up and hit the backpressure hard-limit.
    BackpressureTimeout,
    /// Protocol error on the subscription (e.g. unknown subscription ID).
    ProtocolError,
}

// ============================================================================
// Message enum (top-level wire multiplexer, v2)
// ============================================================================

/// Top-level wire message — discriminates client requests, server responses,
/// and server-initiated push frames.
///
/// Added in protocol v2. Use [`Message::from_frame`] / [`Message::to_frame`]
/// to encode and decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),
    Response(Response),
    Push(Push),
}

impl Message {
    /// Encodes this message to a wire [`Frame`].
    pub fn to_frame(&self) -> WireResult<Frame> {
        let payload =
            postcard::to_allocvec(self).map_err(|e| WireError::Serialization(e.to_string()))?;
        Ok(Frame::new(Bytes::from(payload)))
    }

    /// Decodes a [`Frame`] into a message.
    pub fn from_frame(frame: &Frame) -> WireResult<Self> {
        postcard::from_bytes(&frame.payload).map_err(WireError::from)
    }
}

/// Response payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponsePayload {
    /// Error response.
    Error(ErrorResponse),
    /// Handshake response.
    Handshake(HandshakeResponse),
    /// Create stream response.
    CreateStream(CreateStreamResponse),
    /// Append events response.
    AppendEvents(AppendEventsResponse),
    /// Query response.
    Query(QueryResponse),
    /// Query at response.
    QueryAt(QueryResponse),
    /// Read events response.
    ReadEvents(ReadEventsResponse),
    /// Stream info response — `StreamInfoRequest` carrying the
    /// stream's current length (event count). v0.8.0.
    StreamInfo(StreamInfoResponse),
    /// Subscribe response (initial acknowledgment).
    Subscribe(SubscribeResponse),
    /// Sync response.
    Sync(SyncResponse),
    /// Acknowledgement for `SubscribeCredit` / `Unsubscribe`.
    SubscriptionAck(SubscriptionAckResponse),

    // ---- Phase 4 ----
    ListTables(ListTablesResponse),
    DescribeTable(DescribeTableResponse),
    ListIndexes(ListIndexesResponse),
    TenantCreate(TenantCreateResponse),
    TenantList(TenantListResponse),
    TenantDelete(TenantDeleteResponse),
    TenantGet(TenantGetResponse),
    ApiKeyRegister(ApiKeyRegisterResponse),
    ApiKeyRevoke(ApiKeyRevokeResponse),
    ApiKeyList(ApiKeyListResponse),
    ApiKeyRotate(ApiKeyRotateResponse),
    ServerInfo(ServerInfoResponse),

    // ---- Phase 5 — Consent ----
    ConsentGrant(ConsentGrantResponse),
    ConsentWithdraw(ConsentWithdrawResponse),
    ConsentCheck(ConsentCheckResponse),
    ConsentList(ConsentListResponse),

    // ---- Phase 5 — Erasure ----
    ErasureRequest(ErasureRequestResponse),
    ErasureMarkProgress(ErasureMarkProgressResponse),
    ErasureMarkStreamErased(ErasureMarkStreamErasedResponse),
    ErasureComplete(ErasureCompleteResponse),
    ErasureExempt(ErasureExemptResponse),
    ErasureStatus(ErasureStatusResponse),
    ErasureList(ErasureListResponse),

    // Phase 6
    AuditQuery(AuditQueryResponse),
    /// v0.8.0 — chain verification report.
    VerifyAuditChain(VerifyAuditChainResponse),
    ExportSubject(ExportSubjectResponse),
    VerifyExport(VerifyExportResponse),
    BreachReportIndicator(BreachReportIndicatorResponse),
    BreachQueryStatus(BreachQueryStatusResponse),
    BreachConfirm(BreachConfirmResponse),
    BreachResolve(BreachResolveResponse),

    // Phase 6: Masking Policy catalogue (v0.6.0 Tier 2 #7)
    MaskingPolicyList(MaskingPolicyListResponse),
}

/// Generic ack for subscription lifecycle requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionAckResponse {
    pub subscription_id: u64,
    /// Remaining credit balance (after grant) or `0` for Unsubscribe.
    pub credits_remaining: u32,
}

/// Error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code.
    pub code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// Error codes for wire protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum ErrorCode {
    /// Unknown error.
    Unknown = 0,
    /// Internal server error.
    InternalError = 1,
    /// Invalid request format.
    InvalidRequest = 2,
    /// Authentication failed.
    AuthenticationFailed = 3,
    /// Tenant not found.
    TenantNotFound = 4,
    /// Stream not found.
    StreamNotFound = 5,
    /// Table not found.
    TableNotFound = 6,
    /// Query parse error.
    QueryParseError = 7,
    /// Query execution error.
    QueryExecutionError = 8,
    /// Position ahead of current.
    PositionAhead = 9,
    /// Stream already exists.
    StreamAlreadyExists = 10,
    /// Invalid stream offset.
    InvalidOffset = 11,
    /// Storage error.
    StorageError = 12,
    /// Projection lag.
    ProjectionLag = 13,
    /// Rate limit exceeded.
    RateLimited = 14,
    /// Not the leader - client should retry on another node.
    ///
    /// This error is returned in cluster mode when a write request
    /// is sent to a follower replica. The error message may include
    /// a leader hint to help the client redirect.
    NotLeader = 15,
    /// Offset mismatch — optimistic concurrency conflict.
    ///
    /// The client's expected offset doesn't match the stream's current
    /// offset. This is a retryable conflict: re-read the stream position
    /// and retry the append.
    OffsetMismatch = 16,
    /// Subscription ID not found on the server.
    ///
    /// The subscription was never created or has already been closed.
    SubscriptionNotFound = 17,
    /// Subscription has been closed (by the server or via `Unsubscribe`).
    ///
    /// Any further requests targeting the subscription ID are rejected.
    SubscriptionClosed = 18,
    /// Subscription backpressure — the client owes credits before more
    /// events can be pushed.
    SubscriptionBackpressure = 19,
    /// API key not found in the server's registry. Returned by revoke / rotate
    /// / list when the plaintext key doesn't match any stored hash.
    ApiKeyNotFound = 20,
    /// `TenantCreate` received an ID that already has a registration with
    /// a *different* human-readable name. Idempotent registrations (same
    /// tenant_id, same name or no name) do not produce this error.
    TenantAlreadyExists = 21,
    /// Consent record not found (wrong consent_id or already withdrawn).
    ConsentNotFound = 22,
    /// Consent has expired. The grant exists but is no longer valid.
    ConsentExpired = 23,
    /// Erasure request not found by `request_id`.
    ErasureNotFound = 24,
    /// Erasure request has already been completed — further mutations
    /// rejected.
    ErasureAlreadyComplete = 25,
    /// Erasure request is exempt from processing under GDPR Art. 17(3).
    ErasureExempt = 26,
    /// Breach event not found by `event_id`.
    BreachNotFound = 27,
    /// Export not found or already finalised.
    ExportNotFound = 28,
    /// Duplicate primary-key value detected on INSERT.
    ///
    /// Distinguishes the most common DML constraint failure from the
    /// generic `QueryExecutionError`, so SDK callers can map it to a
    /// typed error class without parsing message strings. Notebar's
    /// webhook-dedup loop is the canonical consumer.
    UniqueConstraintViolation = 29,

    /// Tenant id exceeds the `StreamId` encoding limit (u32::MAX).
    ///
    /// `StreamId` is a bit-packed `u64` with the tenant id in the upper
    /// 32 bits. A tenant id above that ceiling silently truncates the
    /// upper bits and corrupts per-tenant filtering downstream
    /// (kernel state, audit log, projection store, replication). v0.9.1
    /// adds this error code so the SDK can present a clear, actionable
    /// failure instead of a misleading `StreamAlreadyExists` later in
    /// the flow.
    ///
    /// Triggered by notebar's `nextTenantId()` on macOS PIDs > 2^15;
    /// the canonical mitigation is on the caller side (mask the PID to
    /// fit u32). See `docs/operating/kimberlite-upstream-queue.md`.
    TenantIdTooLarge = 30,

    /// A single B+tree leaf entry (one key + its MVCC version chain)
    /// has outgrown the page byte budget. Splitting can't save the
    /// write because both halves of a split would still hold the same
    /// fat entry. Caused by repeated upsert-in-place on the same
    /// primary key — every overwrite appends a version, so a hot row
    /// updated dozens of times accumulates a chain that no longer
    /// fits.
    ///
    /// v0.9.0 returned the generic [`Self::StorageError`] for this
    /// case ("page overflow: need N bytes, have M"), which gave SDK
    /// callers no actionable signal. v0.9.1 promotes it to a typed
    /// code so the SDK can render a clear error pointing at the hot
    /// row and the operator can decide between rate-limiting writes
    /// on that key, rotating keys, or waiting for v0.10.0's
    /// retention-horizon compaction.
    RowVersionChainTooLarge = 31,
}

/// Handshake response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Server protocol version.
    pub server_version: u16,
    /// Whether authentication succeeded.
    pub authenticated: bool,
    /// Server capabilities.
    pub capabilities: Vec<String>,
}

/// Create stream response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStreamResponse {
    /// The created stream ID.
    pub stream_id: StreamId,
}

/// Append events response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEventsResponse {
    /// Offset of the first appended event.
    pub first_offset: Offset,
    /// Number of events appended.
    pub count: u32,
}

/// Query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Column names.
    pub columns: Vec<String>,
    /// Rows of data.
    pub rows: Vec<Vec<QueryValue>>,
}

/// Query result value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryValue {
    /// Null value.
    Null,
    /// 64-bit integer.
    BigInt(i64),
    /// Text string.
    Text(String),
    /// Boolean.
    Boolean(bool),
    /// Timestamp (nanoseconds since epoch).
    Timestamp(i64),
}

/// Read events response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadEventsResponse {
    /// The events.
    pub events: Vec<Vec<u8>>,
    /// Next offset to read from (for pagination).
    pub next_offset: Option<Offset>,
}

/// Response for [`StreamInfoRequest`] — current stream length.
///
/// `length` is the next-to-be-written offset on the stream, which is
/// also the count of committed events (offsets are 0-indexed and
/// monotonic). v0.8.0 — paired with the SDK-side `streamLength` /
/// `stream_length` helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfoResponse {
    /// Number of committed events on the stream. O(1) read of
    /// `StreamMetadata.current_offset`.
    pub length: u64,
}

/// Subscribe response (initial acknowledgment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// Subscription ID for this subscription.
    pub subscription_id: u64,
    /// The offset the server will start streaming from.
    pub start_offset: Offset,
    /// Initial credits acknowledged by the server.
    pub credits: u32,
}

/// Sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Whether sync completed successfully.
    pub success: bool,
}

#[cfg(test)]
mod message_tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let request = Request::new(
            RequestId::new(1),
            TenantId::new(42),
            RequestPayload::CreateStream(CreateStreamRequest {
                name: "test-stream".to_string(),
                data_class: DataClass::Public,
                placement: Placement::Global,
            }),
        );

        // Encode to frame
        let frame = request.to_frame().unwrap();

        // Decode from frame
        let decoded = Request::from_frame(&frame).unwrap();

        assert_eq!(decoded.id, request.id);
        assert_eq!(u64::from(decoded.tenant_id), 42);
    }

    #[test]
    fn test_response_roundtrip() {
        let response = Response::new(
            RequestId::new(1),
            ResponsePayload::CreateStream(CreateStreamResponse {
                stream_id: StreamId::new(100),
            }),
        );

        // Encode to frame
        let frame = response.to_frame().unwrap();

        // Decode from frame
        let decoded = Response::from_frame(&frame).unwrap();

        assert_eq!(decoded.request_id, response.request_id);
    }

    #[test]
    fn test_error_response() {
        let response = Response::error(
            RequestId::new(1),
            ErrorCode::StreamNotFound,
            "stream 123 not found".to_string(),
        );

        let frame = response.to_frame().unwrap();
        let decoded = Response::from_frame(&frame).unwrap();

        if let ResponsePayload::Error(err) = decoded.payload {
            assert_eq!(err.code, ErrorCode::StreamNotFound);
            assert_eq!(err.message, "stream 123 not found");
        } else {
            panic!("expected error payload");
        }
    }

    #[test]
    fn test_query_params() {
        let request = Request::new(
            RequestId::new(2),
            TenantId::new(1),
            RequestPayload::Query(QueryRequest {
                sql: "SELECT * FROM events WHERE id = $1".to_string(),
                params: vec![
                    QueryParam::BigInt(42),
                    QueryParam::Text("hello".to_string()),
                    QueryParam::Boolean(true),
                    QueryParam::Null,
                ],
                break_glass_reason: None,
            }),
        );

        let frame = request.to_frame().unwrap();
        let decoded = Request::from_frame(&frame).unwrap();

        if let RequestPayload::Query(q) = decoded.payload {
            assert_eq!(q.params.len(), 4);
        } else {
            panic!("expected query payload");
        }
    }
}
