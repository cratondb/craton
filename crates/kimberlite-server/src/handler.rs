//! Request handler that routes requests to Kimberlite.

use kimberlite::{Kimberlite, Offset};
use kimberlite_query::Value;
use kimberlite_rbac::enforcement::PolicyEnforcer;
use kimberlite_rbac::policy::StandardPolicies;
use kimberlite_rbac::roles::Role;
use kimberlite_types::Timestamp;
use kimberlite_wire::{
    AppendEventsResponse, CreateStreamResponse, ErrorCode, ErrorResponse, HandshakeResponse,
    PROTOCOL_VERSION, QueryParam, QueryResponse, QueryValue, ReadEventsResponse, Request,
    RequestPayload, Response, ResponsePayload, StreamInfoResponse, SyncResponse,
};
use tracing::instrument;

use crate::auth::{AuthService, AuthenticatedIdentity};
use crate::error::{ServerError, ServerResult};
use crate::metrics;
use crate::replication::CommandSubmitter;

/// Handles requests by routing them to the appropriate Kimberlite operations.
pub struct RequestHandler {
    /// The command submitter (wraps Kimberlite with optional replication).
    /// Shared with the HTTP sidecar's chaos worker via `Arc` so neither
    /// component owns it exclusively.
    submitter: std::sync::Arc<CommandSubmitter>,
    /// Authentication service for validating handshake tokens.
    auth_service: AuthService,
}

impl RequestHandler {
    /// Creates a new request handler with a command submitter and auth service.
    pub fn new(submitter: std::sync::Arc<CommandSubmitter>, auth_service: AuthService) -> Self {
        Self {
            submitter,
            auth_service,
        }
    }

    /// Creates a new request handler with direct Kimberlite access (no replication).
    #[allow(dead_code)] // Available for direct testing without replication
    pub fn new_direct(db: Kimberlite) -> Self {
        Self {
            submitter: std::sync::Arc::new(CommandSubmitter::Direct { db }),
            auth_service: AuthService::new(crate::auth::AuthMode::None),
        }
    }

    /// Returns a reference to the underlying Kimberlite instance.
    pub fn kimberlite(&self) -> &Kimberlite {
        self.submitter.kimberlite()
    }

    /// Returns a reference to the authentication service.
    pub fn auth_service(&self) -> &AuthService {
        &self.auth_service
    }

    /// True if this handler's submitter is backed by a replicated cluster
    /// (vs a single-node direct submitter). Used by the admin
    /// `GetServerInfo` handler to report the cluster mode.
    pub fn kimberlite_submitter_is_replicated(&self) -> bool {
        self.submitter.is_replicated()
    }

    /// Handles a request and returns a response plus an optional updated identity.
    ///
    /// The returned `Option<AuthenticatedIdentity>` is `Some` only when a
    /// successful Handshake establishes a new identity for the connection.
    #[instrument(skip_all, fields(request_id))]
    pub fn handle(
        &self,
        request: Request,
        conn_identity: Option<&AuthenticatedIdentity>,
    ) -> (Response, Option<AuthenticatedIdentity>) {
        let request_id = request.id;
        tracing::Span::current().record("request_id", request_id.0);

        match self.handle_inner(request, conn_identity) {
            Ok((payload, new_identity)) => (Response::new(request_id, payload), new_identity),
            Err(e) => {
                let (code, message) = error_to_wire(&e);
                (Response::error(request_id, code, message), None)
            }
        }
    }

    #[instrument(skip_all, fields(op))]
    fn handle_inner(
        &self,
        request: Request,
        conn_identity: Option<&AuthenticatedIdentity>,
    ) -> ServerResult<(ResponsePayload, Option<AuthenticatedIdentity>)> {
        // ----------------------------------------------------------------
        // Handshake is handled first — it establishes the identity.
        // ----------------------------------------------------------------
        if let RequestPayload::Handshake(ref req) = request.payload {
            tracing::Span::current().record("op", "handshake");

            // Version check
            if req.client_version != PROTOCOL_VERSION {
                return Ok((
                    ResponsePayload::Error(ErrorResponse {
                        code: ErrorCode::InvalidRequest,
                        message: format!(
                            "unsupported client version: {}, server is {}",
                            req.client_version, PROTOCOL_VERSION
                        ),
                    }),
                    None,
                ));
            }

            // Authenticate using the real auth service
            let auth_result = self.auth_service.authenticate(req.auth_token.as_deref());
            let authenticated = auth_result.is_ok();

            // Record auth metrics
            let method = if req.auth_token.as_deref().is_some_and(|t| t.contains('.')) {
                "jwt"
            } else if req.auth_token.is_some() {
                "api_key"
            } else {
                "none"
            };
            metrics::record_auth_attempt(method, authenticated);

            // Reject if a token was supplied but validation failed.
            if let Err(ref e) = auth_result {
                if req.auth_token.is_some() {
                    return Err(ServerError::Unauthorized(format!(
                        "authentication failed: {e}"
                    )));
                }
            }

            let new_identity = auth_result.ok();

            return Ok((
                ResponsePayload::Handshake(HandshakeResponse {
                    server_version: PROTOCOL_VERSION,
                    authenticated,
                    capabilities: vec![
                        "query".to_string(),
                        "append".to_string(),
                        "subscribe".to_string(),
                    ],
                }),
                new_identity,
            ));
        }

        // ----------------------------------------------------------------
        // All non-Handshake operations require an authenticated identity.
        // ----------------------------------------------------------------
        let auth_mode_is_none = matches!(self.auth_service.mode(), crate::auth::AuthMode::None);

        let identity: AuthenticatedIdentity = if auth_mode_is_none {
            // Auth-less mode: synthesise an anonymous Admin identity whose
            // tenant_id tracks the request so that the tenant-isolation check
            // below always passes.  The stored connection identity (tenant 0
            // from the anonymous Handshake) is intentionally ignored here.
            AuthenticatedIdentity {
                subject: "anonymous".to_string(),
                tenant_id: request.tenant_id,
                roles: vec!["Admin".to_string()],
                method: crate::auth::AuthMethod::Anonymous,
            }
        } else {
            // Auth is required: the connection must have completed a Handshake.
            conn_identity.cloned().ok_or_else(|| {
                ServerError::Unauthorized("must authenticate via Handshake first".to_string())
            })?
        };

        // ----------------------------------------------------------------
        // Tenant isolation check: non-Admin callers may only access their
        // own tenant.  Skipped in AuthMode::None (covered by the passthrough
        // identity above).
        // ----------------------------------------------------------------
        let is_admin = auth_mode_is_none
            || identity
                .roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case("Admin"));

        if !is_admin && request.tenant_id != identity.tenant_id {
            return Err(ServerError::Unauthorized(format!(
                "tenant ID mismatch: token is for tenant {}, request targets tenant {}",
                u64::from(identity.tenant_id),
                u64::from(request.tenant_id),
            )));
        }

        let tenant = self.kimberlite().tenant(request.tenant_id);

        // Build RBAC enforcer from the authenticated identity's roles.
        // Admin mode synthesises an anonymous Admin identity so the enforcer
        // always permits all operations in unauthenticated deployments.
        let enforcer = build_policy_enforcer(&identity);

        let payload = match request.payload {
            RequestPayload::Handshake(_) => unreachable!("handled above"),

            RequestPayload::CreateStream(req) => {
                tracing::Span::current().record("op", "create_stream");
                // RBAC: write operations require a role with write permission.
                if !enforcer.policy().role.can_write() {
                    return Err(ServerError::Unauthorized(format!(
                        "role {:?} does not have write access",
                        enforcer.policy().role
                    )));
                }
                // RBAC: stream-name access control (Auditor can only access audit_* streams).
                enforcer
                    .enforce_stream_access(&req.name)
                    .map_err(|e| ServerError::Unauthorized(e.to_string()))?;
                let stream_id = tenant.create_stream(&req.name, req.data_class)?;
                ResponsePayload::CreateStream(CreateStreamResponse { stream_id })
            }

            RequestPayload::AppendEvents(req) => {
                tracing::Span::current().record("op", "append_events");
                // RBAC: Analyst and Auditor roles are read-only.
                if !enforcer.policy().role.can_write() {
                    return Err(ServerError::Unauthorized(format!(
                        "role {:?} does not have write access",
                        enforcer.policy().role
                    )));
                }
                let first_offset =
                    tenant.append(req.stream_id, req.events.clone(), req.expected_offset)?;
                ResponsePayload::AppendEvents(AppendEventsResponse {
                    first_offset,
                    count: req.events.len() as u32,
                })
            }

            RequestPayload::Query(req) => {
                tracing::Span::current().record("op", "query");
                let params = convert_params(&req.params);

                // AUDIT-2026-04 S4.8 — wire protocol v3 carries the
                // break-glass reason as a structured field. Log it
                // here so the regulator-visible tracing signal fires
                // whether the SDK passed it structurally or via the
                // legacy `WITH BREAK_GLASS REASON='...'` SQL prefix
                // (handled downstream by `kimberlite-query`).
                if let Some(reason) = req.break_glass_reason.as_deref() {
                    tracing::warn!(
                        break_glass_reason = %reason,
                        source = "wire_field",
                        "BREAK_GLASS query — regulator-visible audit signal",
                    );
                }

                let trimmed_sql = strip_sql_comments(&req.sql);
                let is_select =
                    trimmed_sql.len() >= 6 && trimmed_sql[..6].eq_ignore_ascii_case("SELECT");
                let is_show =
                    trimmed_sql.len() >= 4 && trimmed_sql[..4].eq_ignore_ascii_case("SHOW");

                if is_select || is_show {
                    // RBAC: inject row-level security WHERE clause from enforcer.
                    let where_clause = enforcer
                        .generate_where_clause()
                        .map_err(|e| ServerError::Unauthorized(e.to_string()))?;
                    let effective_sql = inject_rbac_where(&req.sql, &where_clause);
                    let result = tenant.query(&effective_sql, &params)?;
                    // RBAC: filter result columns based on policy.
                    let base_response = convert_query_result(&result)?;
                    ResponsePayload::Query(filter_query_response(base_response, &enforcer))
                } else {
                    // DML: Analyst and Auditor roles are read-only.
                    if !enforcer.policy().role.can_write() {
                        return Err(ServerError::Unauthorized(format!(
                            "role {:?} does not have write access",
                            enforcer.policy().role
                        )));
                    }
                    let exec_result = tenant.execute(&req.sql, &params)?;
                    ResponsePayload::Query(QueryResponse {
                        columns: vec!["rows_affected".to_string(), "log_offset".to_string()],
                        rows: vec![vec![
                            QueryValue::BigInt(exec_result.rows_affected() as i64),
                            QueryValue::BigInt(exec_result.log_offset().as_u64() as i64),
                        ]],
                    })
                }
            }

            RequestPayload::QueryAt(req) => {
                tracing::Span::current().record("op", "query_at");
                let params = convert_params(&req.params);
                let result = tenant.query_at(&req.sql, &params, req.position)?;
                ResponsePayload::QueryAt(convert_query_result(&result)?)
            }

            RequestPayload::ReadEvents(req) => {
                tracing::Span::current().record("op", "read_events");
                let events = tenant.read_events(req.stream_id, req.from_offset, req.max_bytes)?;

                let next_offset = if events.is_empty() {
                    None
                } else {
                    Some(Offset::new(req.from_offset.as_u64() + events.len() as u64))
                };

                ResponsePayload::ReadEvents(ReadEventsResponse {
                    events: events.into_iter().map(|b| b.to_vec()).collect(),
                    next_offset,
                })
            }

            RequestPayload::StreamInfo(req) => {
                tracing::Span::current().record("op", "stream_info");
                let length = tenant.stream_length(req.stream_id)?;
                ResponsePayload::StreamInfo(StreamInfoResponse { length })
            }

            RequestPayload::Sync(_) => {
                tracing::Span::current().record("op", "sync");
                self.kimberlite().sync()?;
                ResponsePayload::Sync(SyncResponse { success: true })
            }

            // Subscription lifecycle (push-frame semantics implemented at the
            // connection layer; see crates/kimberlite-server/src/subscriptions.rs).
            // The request handler itself is stateless, so these requests are
            // rejected here and must be intercepted earlier in the dispatch
            // path (see `Server::try_handle_subscription_request`). Subscribe
            // was previously handled in-line with a deterministic
            // `subscription_id` derivation from `tenant_id` and `stream_id`;
            // that path was removed in AUDIT-2026-04 M-1 because the IDs it
            // produced were predictable and diverged from the per-connection
            // counter used by the real path.
            RequestPayload::Subscribe(_)
            | RequestPayload::SubscribeCredit(_)
            | RequestPayload::Unsubscribe(_) => {
                return Err(ServerError::Replication(
                    "subscription lifecycle requests must be handled at the connection layer"
                        .to_string(),
                ));
            }

            // Phase 4 admin.v1 and Phase 5/6 compliance payloads (ListTables,
            // DescribeTable, TenantCreate, ApiKey*, GetServerInfo,
            // Consent*, Erasure*, Export*, Breach*, etc.) are intercepted
            // at the connection layer in `server.rs` via
            // `try_handle_admin_request` / `try_handle_compliance_request`
            // — they never reach this stateless handler in normal flow.
            // Returning an error here is a defensive fallback; a request
            // arriving here would indicate a dispatch-layer bug.
            _ => {
                return Err(ServerError::Replication(
                    "request payload must be handled at the connection layer".to_string(),
                ));
            }
        };

        // Non-Handshake requests do not update the stored identity.
        Ok((payload, None))
    }
}

/// Builds a [`PolicyEnforcer`] from the authenticated identity.
///
/// Selects the least-restrictive (highest-privilege) role from the
/// identity's role list and constructs the corresponding standard policy.
/// Defaults to `User` when no recognised role is present.
fn build_policy_enforcer(identity: &AuthenticatedIdentity) -> PolicyEnforcer {
    let role = identity
        .roles
        .iter()
        .filter_map(|r| match r.to_ascii_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "analyst" => Some(Role::Analyst),
            "user" => Some(Role::User),
            "auditor" => Some(Role::Auditor),
            _ => None,
        })
        .max() // Least restrictive (highest enum variant) wins
        .unwrap_or(Role::User);

    let policy = match role {
        Role::Admin => StandardPolicies::admin(),
        Role::Analyst => StandardPolicies::analyst(),
        Role::Auditor => StandardPolicies::auditor(),
        Role::User => StandardPolicies::user(identity.tenant_id),
    };

    PolicyEnforcer::new(policy)
}

/// Injects a row-level security WHERE clause into a SELECT statement.
///
/// Uses a subquery wrapper to avoid fragile SQL string manipulation.
/// If `where_clause` is empty, the SQL is returned unchanged.
fn inject_rbac_where(sql: &str, where_clause: &str) -> String {
    if where_clause.is_empty() {
        return sql.to_string();
    }
    // Wrap as subquery so the WHERE is applied to the full original result set.
    // This is safe because Kimberlite's SQL engine supports subquery FROM.
    format!("SELECT * FROM ({sql}) AS _rbac_filter WHERE {where_clause}")
}

/// Filters query response columns based on the RBAC policy.
///
/// Columns denied by the policy are removed from both the column list
/// and every data row. Returns the response unchanged if all columns
/// are permitted.
fn filter_query_response(mut response: QueryResponse, enforcer: &PolicyEnforcer) -> QueryResponse {
    let allowed_columns = enforcer.filter_columns(&response.columns);

    // Fast path: all columns are allowed.
    if allowed_columns.len() == response.columns.len() {
        return response;
    }

    // Build index of allowed column positions.
    let allowed_indices: Vec<usize> = response
        .columns
        .iter()
        .enumerate()
        .filter(|(_, col)| enforcer.policy().allows_column(col))
        .map(|(i, _)| i)
        .collect();

    let filtered_rows: Vec<Vec<QueryValue>> = response
        .rows
        .iter()
        .map(|row| allowed_indices.iter().map(|&i| row[i].clone()).collect())
        .collect();

    response.columns = allowed_columns;
    response.rows = filtered_rows;
    response
}

/// Converts wire query parameters to Kimberlite query values.
fn convert_params(params: &[QueryParam]) -> Vec<Value> {
    params
        .iter()
        .map(|p| match p {
            QueryParam::Null => Value::Null,
            QueryParam::BigInt(v) => Value::BigInt(*v),
            QueryParam::Text(v) => Value::Text(v.clone()),
            QueryParam::Boolean(v) => Value::Boolean(*v),
            // Negative timestamps are treated as 0 (epoch)
            QueryParam::Timestamp(v) => {
                #[allow(clippy::cast_sign_loss)]
                let nanos = if *v < 0 { 0 } else { *v as u64 };
                Value::Timestamp(Timestamp::from_nanos(nanos))
            }
        })
        .collect()
}

/// Converts a Kimberlite query result to a wire response.
///
/// Returns an error if the result contains an unbound placeholder value.
fn convert_query_result(result: &kimberlite_query::QueryResult) -> ServerResult<QueryResponse> {
    let columns = result.columns.iter().map(ToString::to_string).collect();

    let mut rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        let mut wire_row = Vec::with_capacity(row.len());
        for v in row {
            let qv = match v {
                Value::Null => QueryValue::Null,
                Value::TinyInt(n) => QueryValue::BigInt(i64::from(*n)),
                Value::SmallInt(n) => QueryValue::BigInt(i64::from(*n)),
                Value::Integer(n) => QueryValue::BigInt(i64::from(*n)),
                Value::BigInt(n) => QueryValue::BigInt(*n),
                Value::Real(f) => QueryValue::Text(f.to_string()),
                Value::Decimal(val, scale) => {
                    let divisor = 10_i128.pow(u32::from(*scale));
                    let float_val = *val as f64 / divisor as f64;
                    QueryValue::Text(float_val.to_string())
                }
                Value::Text(s) => QueryValue::Text(s.clone()),
                Value::Bytes(b) => {
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(b);
                    QueryValue::Text(encoded)
                }
                Value::Boolean(b) => QueryValue::Boolean(*b),
                Value::Date(days) => QueryValue::Text(format!("Date({days})")),
                Value::Time(nanos) => QueryValue::Text(format!("Time({nanos})")),
                #[allow(clippy::cast_possible_wrap)]
                Value::Timestamp(t) => QueryValue::Timestamp(t.as_nanos() as i64),
                Value::Uuid(bytes) => {
                    let uuid_str = format!(
                        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        bytes[0],
                        bytes[1],
                        bytes[2],
                        bytes[3],
                        bytes[4],
                        bytes[5],
                        bytes[6],
                        bytes[7],
                        bytes[8],
                        bytes[9],
                        bytes[10],
                        bytes[11],
                        bytes[12],
                        bytes[13],
                        bytes[14],
                        bytes[15]
                    );
                    QueryValue::Text(uuid_str)
                }
                Value::Json(j) => QueryValue::Text(j.to_string()),
                Value::Placeholder(idx) => {
                    return Err(ServerError::Replication(format!(
                        "unbound placeholder ${idx} in query result — bind parameters before executing"
                    )));
                }
            };
            wire_row.push(qv);
        }
        rows.push(wire_row);
    }

    Ok(QueryResponse { columns, rows })
}

/// Converts a server error to a wire error code and message.
fn error_to_wire(error: &ServerError) -> (ErrorCode, String) {
    match error {
        ServerError::Wire(e) => (ErrorCode::InvalidRequest, e.to_string()),
        ServerError::Database(e) => match e {
            kimberlite::KimberliteError::TenantNotFound(_) => {
                (ErrorCode::TenantNotFound, e.to_string())
            }
            kimberlite::KimberliteError::StreamNotFound(_) => {
                (ErrorCode::StreamNotFound, e.to_string())
            }
            kimberlite::KimberliteError::TableNotFound(_) => {
                (ErrorCode::TableNotFound, e.to_string())
            }
            kimberlite::KimberliteError::TenantIdTooLarge { .. } => {
                (ErrorCode::TenantIdTooLarge, e.to_string())
            }
            kimberlite::KimberliteError::PositionAhead { .. } => {
                (ErrorCode::PositionAhead, e.to_string())
            }
            kimberlite::KimberliteError::ProjectionLag { .. } => {
                (ErrorCode::ProjectionLag, e.to_string())
            }
            kimberlite::KimberliteError::Query(qe) => match qe {
                kimberlite_query::QueryError::DuplicatePrimaryKey { .. } => {
                    (ErrorCode::UniqueConstraintViolation, qe.to_string())
                }
                kimberlite_query::QueryError::ParseError(_)
                | kimberlite_query::QueryError::SqlTooComplex { .. } => {
                    (ErrorCode::QueryParseError, qe.to_string())
                }
                _ => (ErrorCode::QueryExecutionError, qe.to_string()),
            },
            kimberlite::KimberliteError::Store(se) => match se {
                kimberlite::StoreError::EntryTooLarge { .. } => {
                    (ErrorCode::RowVersionChainTooLarge, se.to_string())
                }
                _ => (ErrorCode::StorageError, se.to_string()),
            },
            kimberlite::KimberliteError::Storage(_) => (ErrorCode::StorageError, e.to_string()),
            kimberlite::KimberliteError::Kernel(ke) => {
                if let kimberlite::KernelError::UnexpectedStreamOffset { .. } = &ke {
                    (ErrorCode::OffsetMismatch, ke.to_string())
                } else {
                    let msg = ke.to_string();
                    if msg.contains("not found") {
                        (ErrorCode::StreamNotFound, msg)
                    } else if msg.contains("already exists") || msg.contains("unique") {
                        (ErrorCode::StreamAlreadyExists, msg)
                    } else {
                        (ErrorCode::InternalError, msg)
                    }
                }
            }
            _ => (ErrorCode::InternalError, e.to_string()),
        },
        ServerError::Io(e) => (ErrorCode::InternalError, e.to_string()),
        ServerError::ConnectionClosed => {
            (ErrorCode::InternalError, "connection closed".to_string())
        }
        ServerError::MaxConnectionsReached(n) => (
            ErrorCode::InternalError,
            format!("max connections reached: {n}"),
        ),
        ServerError::InvalidTenant => (ErrorCode::TenantNotFound, "invalid tenant".to_string()),
        ServerError::BindFailed { addr, source } => (
            ErrorCode::InternalError,
            format!("bind failed on {addr}: {source}"),
        ),
        ServerError::Tls(msg) => (ErrorCode::InternalError, format!("TLS error: {msg}")),
        ServerError::Unauthorized(msg) => (ErrorCode::AuthenticationFailed, msg.clone()),
        ServerError::Shutdown => (ErrorCode::InternalError, "server shutdown".to_string()),
        ServerError::Replication(msg) => (ErrorCode::InternalError, format!("replication: {msg}")),
        ServerError::NotLeader { view, leader_hint } => {
            let hint = leader_hint.map_or_else(|| "unknown".to_string(), |addr| addr.to_string());
            (
                ErrorCode::NotLeader,
                format!("not the leader (view: {view}, leader hint: {hint})"),
            )
        }
        ServerError::ClusterConfig(msg) => (
            ErrorCode::InternalError,
            format!("cluster configuration error: {msg}"),
        ),
        ServerError::ServerBusy => (
            ErrorCode::RateLimited,
            "server busy, try again later".to_string(),
        ),
        ServerError::CommitTimeout { timeout_ms } => (
            ErrorCode::RateLimited,
            format!("no_quorum: commit timed out after {timeout_ms}ms"),
        ),
        ServerError::InvalidRuntimeConfig(msg) => (
            ErrorCode::InternalError,
            format!("invalid runtime configuration: {msg}"),
        ),
    }
}

/// Strips leading SQL comments (`--` line comments and `/* */` block comments)
/// and whitespace to reveal the first real SQL keyword.
fn strip_sql_comments(sql: &str) -> String {
    let mut s = sql.trim_start();
    loop {
        if s.starts_with("--") {
            // Skip to end of line
            match s.find('\n') {
                Some(pos) => s = s[pos + 1..].trim_start(),
                None => return String::new(),
            }
        } else if s.starts_with("/*") {
            // Skip to closing */
            match s.find("*/") {
                Some(pos) => s = s[pos + 2..].trim_start(),
                None => return String::new(),
            }
        } else {
            break;
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_types::{Offset, StreamId, TenantId};
    use kimberlite_wire::{RequestId, SubscribeRequest};
    use tempfile::TempDir;

    fn new_handler() -> (RequestHandler, TempDir) {
        let temp = TempDir::new().expect("temp dir");
        let db = Kimberlite::open(temp.path()).expect("open db");
        (RequestHandler::new_direct(db), temp)
    }

    /// AUDIT-2026-04 M-1: the request handler must refuse to service
    /// `Subscribe` directly. Subscription lifecycle is owned by the
    /// connection layer (`Server::try_handle_subscription_request`).
    /// This test guards the invariant so a future dispatch-order
    /// regression cannot silently re-introduce the deterministic
    /// `tenant_id * magic + stream_id` id derivation.
    #[test]
    fn subscribe_rejected_at_stateless_handler() {
        let (handler, _temp) = new_handler();
        let request = Request::new(
            RequestId::new(1),
            TenantId::new(1),
            RequestPayload::Subscribe(SubscribeRequest {
                stream_id: StreamId::new(1),
                from_offset: Offset::new(0),
                initial_credits: 1,
                consumer_group: None,
            }),
        );

        let (response, identity) = handler.handle(request, None);

        assert!(identity.is_none(), "Subscribe must not set an identity");
        match response.payload {
            ResponsePayload::Error(err) => {
                assert_eq!(err.code, ErrorCode::InternalError);
                assert!(
                    err.message.contains("connection layer"),
                    "error should name the connection layer; got {:?}",
                    err.message,
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Regression for the same class of bug across the other two
    /// subscription lifecycle payloads.
    #[test]
    fn subscribe_credit_and_unsubscribe_rejected_at_stateless_handler() {
        use kimberlite_wire::{SubscribeCreditRequest, UnsubscribeRequest};
        let (handler, _temp) = new_handler();

        for payload in [
            RequestPayload::SubscribeCredit(SubscribeCreditRequest {
                subscription_id: 7,
                additional_credits: 1,
            }),
            RequestPayload::Unsubscribe(UnsubscribeRequest { subscription_id: 7 }),
        ] {
            let request = Request::new(RequestId::new(2), TenantId::new(1), payload);
            let (response, _) = handler.handle(request, None);
            assert!(
                matches!(response.payload, ResponsePayload::Error(_)),
                "lifecycle payload must error at the handler"
            );
        }
    }
}
