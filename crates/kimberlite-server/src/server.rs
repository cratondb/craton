//! TCP server implementation using mio for non-blocking I/O.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kimberlite::Kimberlite;
use kimberlite_compliance::audit::{Actor, ComplianceAuditAction, ComponentName};
use kimberlite_types::TenantId;
use kimberlite_wire::{
    ApiKeyInfo, ApiKeyListResponse, ApiKeyRegisterResponse, ApiKeyRevokeResponse,
    ApiKeyRotateResponse, ClusterMode, ColumnInfo, ConsentBasis as WireConsentBasis,
    ConsentCheckResponse, ConsentGrantResponse, ConsentListResponse,
    ConsentPurpose as WireConsentPurpose, ConsentRecord as WireConsentRecord,
    ConsentScope as WireConsentScope, ConsentWithdrawResponse, DescribeTableResponse,
    ErasureAuditInfo, ErasureCompleteResponse, ErasureExemptResponse,
    ErasureExemptionBasis as WireExemptionBasis, ErasureListResponse, ErasureMarkProgressResponse,
    ErasureMarkStreamErasedResponse, ErasureRequestInfo, ErasureRequestResponse,
    ErasureStatusResponse, ErasureStatusTag, ErrorCode, ListIndexesResponse, ListTablesResponse,
    MaskingAttachmentInfo, MaskingPolicyInfo, MaskingPolicyListResponse, MaskingStrategyWire, Push,
    PushPayload, Request, RequestPayload, Response, ResponsePayload, ServerInfoResponse,
    SubscribeResponse, SubscriptionAckResponse, SubscriptionCloseReason, TableInfo,
    TenantCreateResponse, TenantDeleteResponse, TenantGetResponse, TenantInfo, TenantListResponse,
};
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};
use tracing::{debug, error, info, trace, warn};

#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook_mio::v1_0::Signals;

use crate::auth::AuthService;
use crate::chaos::ChaosHandle;
use crate::config::ServerConfig;
use crate::connection::Connection;
use crate::error::{ServerError, ServerResult};
use crate::handler::RequestHandler;
use crate::health::HealthChecker;
use crate::http::HttpSidecar;
use crate::metrics;
use crate::replication::CommandSubmitter;
use crate::tenant_registry::{RegistryError, TenantRegistry};

/// Token for the listener socket.
const LISTENER_TOKEN: Token = Token(0);

/// Token for signal handling.
const SIGNAL_TOKEN: Token = Token(1);

/// Maximum events to process per poll iteration.
const MAX_EVENTS: usize = 1024;

/// Default shutdown drain timeout.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time the main event loop will block between subscription pumps.
///
/// Keeps tail-of-log push frames flowing even when the subscribed client is
/// otherwise idle and no I/O events fire.
const SUBSCRIPTION_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// TCP server for `Kimberlite`.
///
/// Uses mio's poll-based event loop for handling multiple connections
/// without async runtimes.
pub struct Server {
    config: ServerConfig,
    poll: Poll,
    listener: TcpListener,
    connections: HashMap<Token, Connection>,
    handler: RequestHandler,
    next_token: usize,
    /// Whether shutdown has been requested.
    shutdown_requested: Arc<AtomicBool>,
    /// Health checker.
    health_checker: HealthChecker,
    /// HTTP sidecar for metrics/health endpoints.
    http_sidecar: Option<HttpSidecar>,
    /// Signal handler for SIGTERM/SIGINT (Unix only).
    #[cfg(unix)]
    signals: Option<Signals>,
    /// In-memory tenant registry backing the admin-API tenant ops.
    tenant_registry: Arc<TenantRegistry>,
    /// Wall-clock instant at which the event loop was constructed, used to
    /// report uptime via `GetServerInfo`.
    started_at: Instant,
}

impl Server {
    /// Creates a new server with the given configuration.
    pub fn new(config: ServerConfig, db: Kimberlite) -> ServerResult<Self> {
        let poll = Poll::new()?;

        // Bind the listener
        let addr = config.bind_addr;
        let mut listener =
            TcpListener::bind(addr).map_err(|e| ServerError::BindFailed { addr, source: e })?;

        // Register the listener with the poll
        poll.registry()
            .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)?;

        // Create auth service
        let auth_service = AuthService::new(config.auth.clone());

        if matches!(config.auth, crate::auth::AuthMode::None) {
            warn!(
                "AuthMode::None is active — all connections accepted without authentication. \
                 Pass --allow-unauthenticated to suppress this warning in development."
            );
        }

        // Create command submitter with replication mode. Wrapped in Arc
        // so the HTTP sidecar's chaos worker can share a handle with the
        // binary-protocol handler without either owning it exclusively.
        // Constructed BEFORE the health checker so we can attach it for
        // VSR-aware `/readyz` checks.
        let submitter = Arc::new(CommandSubmitter::new(
            &config.replication,
            db,
            &config.data_dir,
        )?);

        // Create health checker. Attaches the submitter so `/readyz`
        // can require VSR bootstrap + Normal status + lag-under-threshold;
        // `/metrics` can refresh the cluster gauges from a fresh
        // `ReplicationStatus` snapshot per scrape.
        let health_checker =
            HealthChecker::new(&config.data_dir).with_submitter(Arc::clone(&submitter));

        // Install the cluster command router on the underlying
        // `Kimberlite` so that wire-level writes (which go through the
        // tenant API → `Kimberlite::submit`) are routed through VSR
        // instead of applied directly to the local projection. Without
        // this, replicated mode never replicated writes from the wire
        // protocol — the `CommandSubmitter` was reachable only via the
        // chaos worker, not the binary-protocol handler. Installed in
        // every replicated mode (single-node + cluster); single-node
        // VSR also benefits from durable submit semantics.
        if submitter.is_replicated() {
            let router =
                std::sync::Arc::new(crate::replication::ClusterCommandRouter::new(&submitter));
            submitter
                .kimberlite()
                .set_command_router(router)
                .map_err(|e| {
                    ServerError::Replication(format!("failed to install ClusterCommandRouter: {e}"))
                })?;
            info!(
                "Server listening on {} with {:?} replication",
                addr,
                submitter.status().mode
            );
        } else {
            info!("Server listening on {}", addr);
        }

        // Chaos HTTP endpoints activate only when the operator opts in via
        // env var. Production builds must NOT expose the probe contract by
        // default; chaos VMs set `KMB_ENABLE_CHAOS_ENDPOINTS=1` in their
        // init script.
        let chaos_enabled = std::env::var("KMB_ENABLE_CHAOS_ENDPOINTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let chaos_handle = if chaos_enabled {
            match submitter.subscribe_applied_commits(1024) {
                Some(rx) => {
                    info!("chaos HTTP endpoints enabled (KMB_ENABLE_CHAOS_ENDPOINTS=1)");
                    Some(ChaosHandle::spawn(
                        Arc::clone(&submitter),
                        rx,
                        config.data_dir.clone(),
                    ))
                }
                None => {
                    warn!(
                        "KMB_ENABLE_CHAOS_ENDPOINTS=1 set but replication is not in cluster \
                         mode — chaos endpoints require VSR commit fanout. Disabling."
                    );
                    None
                }
            }
        } else {
            None
        };

        // Bind HTTP sidecar for metrics/health/chaos if configured.
        let http_sidecar = if let Some(http_addr) = config.metrics_bind_addr {
            match HttpSidecar::bind_with_chaos(http_addr, &poll, chaos_handle) {
                Ok(sidecar) => Some(sidecar),
                Err(e) => {
                    warn!("Failed to bind HTTP sidecar on {http_addr}: {e}");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            poll,
            listener,
            connections: HashMap::new(),
            handler: RequestHandler::new(submitter, auth_service),
            next_token: 2, // Start at 2 since 0 is LISTENER_TOKEN and 1 is SIGNAL_TOKEN
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            health_checker,
            http_sidecar,
            #[cfg(unix)]
            signals: None,
            tenant_registry: Arc::new(TenantRegistry::new()),
            started_at: Instant::now(),
        })
    }

    /// Creates a new server with signal handling enabled.
    ///
    /// On Unix: handles SIGTERM and SIGINT.
    /// On Windows: handles Ctrl+C and Ctrl+Break.
    pub fn with_signal_handling(config: ServerConfig, db: Kimberlite) -> ServerResult<Self> {
        let mut server = Self::new(config, db)?;

        #[cfg(unix)]
        {
            // Set up signal handling for SIGTERM and SIGINT
            let mut signals = Signals::new([SIGTERM, SIGINT]).map_err(ServerError::Io)?;

            // Register signals with the poll
            server
                .poll
                .registry()
                .register(&mut signals, SIGNAL_TOKEN, Interest::READABLE)?;

            server.signals = Some(signals);
            info!("Signal handling enabled (SIGTERM/SIGINT)");
        }

        #[cfg(windows)]
        {
            // Set up Ctrl+C handler for Windows
            let shutdown_flag = Arc::clone(&server.shutdown_requested);
            ctrlc::set_handler(move || {
                info!("Received Ctrl+C, initiating graceful shutdown");
                shutdown_flag.store(true, Ordering::SeqCst);
            })
            .map_err(|e| ServerError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

            info!("Signal handling enabled (Ctrl+C)");
        }

        Ok(server)
    }

    /// Returns the address the server is listening on.
    pub fn local_addr(&self) -> ServerResult<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Runs the server event loop.
    ///
    /// This method blocks until the server is shut down.
    pub fn run(&mut self) -> ServerResult<()> {
        let mut events = Events::with_capacity(MAX_EVENTS);

        info!("Server event loop started");

        loop {
            // Wait for events, but wake up at least every subscription
            // poll interval so active subscriptions get their tail pushed
            // even while the subscribed client is otherwise idle.
            let timeout = self
                .has_active_subscriptions()
                .then_some(SUBSCRIPTION_POLL_INTERVAL);
            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }

            // Two-pass dispatch: listener events first so client accepts
            // don't get starved when a large per-connection burst arrives
            // in the same wakeup. Under view-change churn the protocol
            // layer can queue dozens of per-connection writes; accepting
            // first keeps the kernel's accept backlog from overflowing
            // (which surfaces as `EAGAIN` / dropped SYN-ACK retransmits
            // on the test bench, and as "connection refused" on the
            // client). HTTP probe accepts are cheap and ride the same
            // bus.
            self.dispatch_listener_events(&events)?;
            self.dispatch_per_connection_events(&events)?;

            // Pump subscriptions on timeout wakeups OR to drain any
            // newly-available events for subscriptions on other connections.
            if self.has_active_subscriptions() {
                self.pump_all_subscriptions();
                self.flush_pending_writes()?;
            }

            // Clean up closed connections
            self.cleanup_closed();
        }
    }

    /// First-pass dispatch: drain the client-data and HTTP-probe accept
    /// queues before doing per-connection I/O. See [`Self::run`].
    fn dispatch_listener_events(&mut self, events: &Events) -> ServerResult<()> {
        for event in events {
            match event.token() {
                LISTENER_TOKEN => {
                    self.accept_connections()?;
                }
                crate::http::HTTP_LISTENER_TOKEN => {
                    if let Some(ref sidecar) = self.http_sidecar {
                        sidecar.handle_accept(&self.health_checker);
                    }
                }
                _ => { /* per-connection event — second pass */ }
            }
        }
        Ok(())
    }

    /// Second-pass dispatch: per-connection readable/writable events.
    fn dispatch_per_connection_events(&mut self, events: &Events) -> ServerResult<()> {
        for event in events {
            match event.token() {
                LISTENER_TOKEN | crate::http::HTTP_LISTENER_TOKEN => {
                    /* handled in the first pass */
                }
                token => {
                    if event.is_readable() {
                        self.handle_readable(token)?;
                    }
                    if event.is_writable() {
                        self.handle_writable(token)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// True if any connection has at least one active subscription.
    fn has_active_subscriptions(&self) -> bool {
        self.connections
            .values()
            .any(|c| !c.subscriptions.is_empty())
    }

    /// After queueing push frames, ensure each affected connection has
    /// WRITABLE interest registered so mio will flush the buffer.
    fn flush_pending_writes(&mut self) -> ServerResult<()> {
        let tokens: Vec<Token> = self
            .connections
            .iter()
            .filter(|(_, c)| !c.write_buf.is_empty())
            .map(|(t, _)| *t)
            .collect();
        for token in tokens {
            self.update_interest(token)?;
        }
        Ok(())
    }

    /// Runs a single iteration of the event loop.
    ///
    /// Useful for testing or custom event loops. Uses the same two-pass
    /// listener-first dispatch as [`Self::run`].
    pub fn poll_once(&mut self, timeout: Option<std::time::Duration>) -> ServerResult<()> {
        let mut events = Events::with_capacity(MAX_EVENTS);

        self.poll.poll(&mut events, timeout)?;

        self.dispatch_listener_events(&events)?;
        self.dispatch_per_connection_events(&events)?;

        self.cleanup_closed();
        Ok(())
    }

    /// Accepts new connections from the listener.
    fn accept_connections(&mut self) -> ServerResult<()> {
        loop {
            match self.listener.accept() {
                Ok((mut stream, addr)) => {
                    // Disable Nagle's algorithm for low-latency client messaging
                    if let Err(e) = stream.set_nodelay(true) {
                        tracing::warn!("Failed to set TCP_NODELAY for {}: {}", addr, e);
                    }

                    // Check connection limit
                    if self.connections.len() >= self.config.max_connections {
                        warn!(
                            "Max connections reached, rejecting connection from {}",
                            addr
                        );
                        // Just drop the stream to reject
                        continue;
                    }

                    // Allocate a token for this connection
                    let token = Token(self.next_token);
                    self.next_token += 1;

                    // Register the stream
                    self.poll
                        .registry()
                        .register(&mut stream, token, Interest::READABLE)?;

                    // Create the connection (with rate limiting if configured)
                    let conn = if let Some(rate_config) = self.config.rate_limit {
                        Connection::with_rate_limit(
                            token,
                            stream,
                            self.config.read_buffer_size,
                            rate_config,
                        )
                    } else {
                        Connection::new(token, stream, self.config.read_buffer_size)
                    };
                    self.connections.insert(token, conn);

                    // Record metrics
                    metrics::record_connection_accepted();

                    debug!("Accepted connection from {} (token {:?})", addr, token);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No more connections to accept
                    break;
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Intercepts protocol-v2 subscription lifecycle requests so they can
    /// operate on the per-connection `SubscriptionRegistry`.
    ///
    /// Returns `Some(response)` if the request was a subscription op; callers
    /// must not also dispatch through the stateless request handler.
    fn try_handle_subscription_request(
        &mut self,
        token: Token,
        request: &Request,
    ) -> Option<Response> {
        match &request.payload {
            RequestPayload::Subscribe(req) => {
                let conn = self.connections.get_mut(&token)?;
                // Validate the stream exists by reading zero bytes from it.
                if let Err(e) = self
                    .handler
                    .kimberlite()
                    .tenant(request.tenant_id)
                    .read_events(req.stream_id, req.from_offset, 0)
                {
                    return Some(Response::error(
                        request.id,
                        ErrorCode::StreamNotFound,
                        e.to_string(),
                    ));
                }
                let sub_id = conn.subscriptions.register(
                    request.tenant_id,
                    req.stream_id,
                    req.from_offset,
                    req.initial_credits,
                    req.consumer_group.clone(),
                );
                trace!(
                    "Registered subscription {} on stream {:?} for token {:?}",
                    sub_id, req.stream_id, token
                );
                Some(Response::new(
                    request.id,
                    ResponsePayload::Subscribe(SubscribeResponse {
                        subscription_id: sub_id,
                        start_offset: req.from_offset,
                        credits: req.initial_credits,
                    }),
                ))
            }
            RequestPayload::SubscribeCredit(req) => {
                let conn = self.connections.get_mut(&token)?;
                match conn
                    .subscriptions
                    .grant_credits(req.subscription_id, req.additional_credits)
                {
                    Some(new_balance) => Some(Response::new(
                        request.id,
                        ResponsePayload::SubscriptionAck(SubscriptionAckResponse {
                            subscription_id: req.subscription_id,
                            credits_remaining: new_balance,
                        }),
                    )),
                    None => Some(Response::error(
                        request.id,
                        ErrorCode::SubscriptionNotFound,
                        format!("subscription {} not found", req.subscription_id),
                    )),
                }
            }
            RequestPayload::Unsubscribe(req) => {
                let conn = self.connections.get_mut(&token)?;
                if conn.subscriptions.remove(req.subscription_id).is_some() {
                    let _ = conn.queue_push(Push::new(PushPayload::SubscriptionClosed {
                        subscription_id: req.subscription_id,
                        reason: SubscriptionCloseReason::ClientCancelled,
                    }));
                    Some(Response::new(
                        request.id,
                        ResponsePayload::SubscriptionAck(SubscriptionAckResponse {
                            subscription_id: req.subscription_id,
                            credits_remaining: 0,
                        }),
                    ))
                } else {
                    Some(Response::error(
                        request.id,
                        ErrorCode::SubscriptionNotFound,
                        format!("subscription {} not found", req.subscription_id),
                    ))
                }
            }
            _ => None,
        }
    }

    /// Intercepts Phase 4 admin + schema + server-info requests. All are
    /// admin-only (gated on `Role::Admin` or AuthMode::None); non-Admin
    /// callers receive `AuthenticationFailed`.
    fn try_handle_admin_request(&mut self, token: Token, request: &Request) -> Option<Response> {
        // Every request we match here also implies admin-only. We perform
        // the role check up-front so the later arms can assume admin.
        let is_admin = self.connection_is_admin(token);

        let require_admin = || {
            Response::error(
                request.id,
                ErrorCode::AuthenticationFailed,
                "admin operations require the Admin role".to_string(),
            )
        };

        match &request.payload {
            RequestPayload::ListTables(_) => Some(self.handle_list_tables(request)),
            RequestPayload::DescribeTable(req) => {
                Some(self.handle_describe_table(request, &req.table_name))
            }
            RequestPayload::ListIndexes(req) => {
                Some(self.handle_list_indexes(request, &req.table_name))
            }
            RequestPayload::TenantCreate(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_tenant_create(request, req.tenant_id, req.name.clone()))
            }
            RequestPayload::TenantList(_) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_tenant_list(request))
            }
            RequestPayload::TenantDelete(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_tenant_delete(request, req.tenant_id))
            }
            RequestPayload::TenantGet(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_tenant_get(request, req.tenant_id))
            }
            RequestPayload::ApiKeyRegister(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_api_key_register(
                    request,
                    req.subject.clone(),
                    req.tenant_id,
                    req.roles.clone(),
                    req.expires_at_nanos,
                ))
            }
            RequestPayload::ApiKeyRevoke(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_api_key_revoke(request, &req.key))
            }
            RequestPayload::ApiKeyList(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_api_key_list(request, req.tenant_id))
            }
            RequestPayload::ApiKeyRotate(req) => {
                if !is_admin {
                    return Some(require_admin());
                }
                Some(self.handle_api_key_rotate(request, &req.old_key))
            }
            RequestPayload::GetServerInfo(_) => Some(self.handle_server_info(request)),
            _ => None,
        }
    }

    fn connection_is_admin(&self, token: Token) -> bool {
        let auth_mode_is_none = matches!(
            self.handler.auth_service().mode(),
            crate::auth::AuthMode::None
        );
        if auth_mode_is_none {
            return true;
        }
        self.connections
            .get(&token)
            .and_then(|c| c.authenticated_identity.as_ref())
            .is_some_and(|id| id.roles.iter().any(|r| r.eq_ignore_ascii_case("Admin")))
    }

    /// Resolve the [`Actor`] for a request: prefer SDK-supplied
    /// `request.audit.actor`, fall back to the authenticated identity
    /// (via the first connection with a matching tenant), else attribute
    /// to the compliance-api system component.
    ///
    /// AUDIT-2026-04 S3.9 — this is the single choke point where wire
    /// `AuditMetadata` meets the server's `ComplianceAuditLog` so every
    /// compliance-tracked mutation preserves client attribution.
    fn actor_from_request(&self, request: &Request) -> Actor {
        if let Some(audit) = request.audit.as_ref() {
            if let Some(actor) = audit.actor.as_ref().filter(|s| !s.is_empty()) {
                return Actor::Authenticated(actor.clone());
            }
        }
        for conn in self.connections.values() {
            if let Some(id) = conn.authenticated_identity.as_ref() {
                if id.tenant_id == request.tenant_id {
                    return Actor::Authenticated(id.subject.clone());
                }
            }
        }
        Actor::System(ComponentName::Other("compliance-api".to_string()))
    }

    /// Append a compliance audit event with the SDK-supplied actor, best-effort.
    /// Failure to append is logged but does not fail the underlying request —
    /// the mutation has already committed and the client shouldn't be punished
    /// for a transient audit-log write hiccup.
    fn record_audit_event(&self, request: &Request, action: ComplianceAuditAction) {
        let actor = self.actor_from_request(request);
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        if let Err(e) = tenant.audit_log_append_with_actor(action, actor) {
            tracing::warn!(
                tenant_id = %request.tenant_id,
                request_id = request.id.0,
                error = %e,
                "failed to append compliance audit event"
            );
        }
    }

    fn handle_list_tables(&mut self, request: &Request) -> Response {
        self.tenant_registry.touch(request.tenant_id);
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        match tenant.query("SHOW TABLES", &[]) {
            Ok(result) => {
                let tables = result
                    .rows
                    .into_iter()
                    .filter_map(|row| {
                        let name = match row.first() {
                            Some(kimberlite_query::Value::Text(s)) => s.clone(),
                            _ => return None,
                        };
                        let column_count = match row.get(1) {
                            Some(kimberlite_query::Value::BigInt(n)) => *n as u32,
                            Some(kimberlite_query::Value::Integer(n)) => *n as u32,
                            _ => 0,
                        };
                        Some(TableInfo { name, column_count })
                    })
                    .collect();
                Response::new(
                    request.id,
                    ResponsePayload::ListTables(ListTablesResponse { tables }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    /// List every masking policy in the caller's tenant catalogue.
    ///
    /// Mutating operations (CREATE / ALTER SET / ALTER DROP / DROP MASKING
    /// POLICY) flow through the SQL execute path; only the read surface
    /// has its own RPC. Translates kernel-native [`MaskingPolicySummary`]
    /// into the wire-stable [`MaskingPolicyInfo`] at this boundary so the
    /// serialised form is independent of internal kernel enum changes.
    ///
    /// v0.6.0 Tier 2 #7 — Stage 0.0c/0.0d/0.0e.
    fn handle_masking_policy_list(
        &mut self,
        request: &Request,
        include_attachments: bool,
    ) -> Response {
        self.tenant_registry.touch(request.tenant_id);
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        match tenant.masking_policy_snapshot(include_attachments) {
            Ok((policies_native, attachments_native)) => {
                let policies: Vec<MaskingPolicyInfo> = policies_native
                    .into_iter()
                    .map(|p| MaskingPolicyInfo {
                        name: p.name,
                        strategy: kernel_strategy_to_wire(&p.strategy),
                        exempt_roles: p.role_guard.exempt_roles,
                        default_masked: p.role_guard.default_masked,
                        attachment_count: p.attachment_count,
                    })
                    .collect();
                let attachments: Vec<MaskingAttachmentInfo> = attachments_native
                    .into_iter()
                    .map(|a| MaskingAttachmentInfo {
                        table_name: a.table_name,
                        column_name: a.column_name,
                        policy_name: a.policy_name,
                    })
                    .collect();
                Response::new(
                    request.id,
                    ResponsePayload::MaskingPolicyList(MaskingPolicyListResponse {
                        policies,
                        attachments,
                    }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_describe_table(&mut self, request: &Request, table_name: &str) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let sql = format!("SHOW COLUMNS FROM {table_name}");
        match tenant.query(&sql, &[]) {
            Ok(result) => {
                let columns = result
                    .rows
                    .into_iter()
                    .filter_map(|row| {
                        let name = match row.first() {
                            Some(kimberlite_query::Value::Text(s)) => s.clone(),
                            _ => return None,
                        };
                        let data_type = match row.get(1) {
                            Some(kimberlite_query::Value::Text(s)) => s.clone(),
                            _ => "UNKNOWN".to_string(),
                        };
                        let nullable = match row.get(2) {
                            Some(kimberlite_query::Value::Boolean(b)) => *b,
                            _ => true,
                        };
                        let primary_key = match row.get(3) {
                            Some(kimberlite_query::Value::Boolean(b)) => *b,
                            _ => false,
                        };
                        Some(ColumnInfo {
                            name,
                            data_type,
                            nullable,
                            primary_key,
                        })
                    })
                    .collect();
                Response::new(
                    request.id,
                    ResponsePayload::DescribeTable(DescribeTableResponse {
                        table_name: table_name.to_string(),
                        columns,
                    }),
                )
            }
            Err(e) => {
                let msg = e.to_string();
                let code = if msg.contains("not found") || msg.contains("does not exist") {
                    ErrorCode::TableNotFound
                } else {
                    ErrorCode::InternalError
                };
                Response::error(request.id, code, msg)
            }
        }
    }

    fn handle_list_indexes(&mut self, request: &Request, table_name: &str) -> Response {
        // Validate the table exists via SHOW TABLES. Returning index metadata
        // requires exposing `kernel_state.indexes()` through a `Kimberlite`
        // accessor; that exposure is tracked in ROADMAP v0.6 alongside a
        // proper `SHOW INDEXES` SQL grammar. Until then we return an empty
        // list for known tables so admin UIs can render a "no indexes" state
        // without surfacing a misleading error.
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let Ok(show) = tenant.query("SHOW TABLES", &[]) else {
            return Response::error(
                request.id,
                ErrorCode::InternalError,
                "failed to enumerate tables".to_string(),
            );
        };
        let exists = show.rows.iter().any(
            |row| matches!(row.first(), Some(kimberlite_query::Value::Text(s)) if s == table_name),
        );
        if !exists {
            return Response::error(
                request.id,
                ErrorCode::TableNotFound,
                format!("table {table_name} not found"),
            );
        }
        Response::new(
            request.id,
            ResponsePayload::ListIndexes(ListIndexesResponse {
                indexes: Vec::new(),
            }),
        )
    }

    fn handle_tenant_create(
        &mut self,
        request: &Request,
        tenant_id: TenantId,
        name: Option<String>,
    ) -> Response {
        match self.tenant_registry.register(tenant_id, name.clone()) {
            Ok((entry, created)) => {
                let info = TenantInfo {
                    tenant_id,
                    name: entry.name,
                    table_count: self.tenant_table_count(tenant_id),
                    created_at_nanos: Some(entry.created_at_nanos),
                };
                Response::new(
                    request.id,
                    ResponsePayload::TenantCreate(TenantCreateResponse {
                        tenant: info,
                        created,
                    }),
                )
            }
            Err(RegistryError::AlreadyExistsDifferentName { .. }) => Response::error(
                request.id,
                ErrorCode::TenantAlreadyExists,
                "tenant already exists with a different name".to_string(),
            ),
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_tenant_list(&mut self, request: &Request) -> Response {
        let tenants: Vec<TenantInfo> = self
            .tenant_registry
            .list()
            .into_iter()
            .map(|(tenant_id, entry)| TenantInfo {
                tenant_id,
                name: entry.name,
                table_count: self.tenant_table_count(tenant_id),
                created_at_nanos: Some(entry.created_at_nanos),
            })
            .collect();
        Response::new(
            request.id,
            ResponsePayload::TenantList(TenantListResponse { tenants }),
        )
    }

    fn handle_tenant_delete(&mut self, request: &Request, tenant_id: TenantId) -> Response {
        let tenant = self.handler.kimberlite().tenant(tenant_id);
        let mut tables_dropped = 0u32;
        if let Ok(result) = tenant.query("SHOW TABLES", &[]) {
            for row in result.rows {
                if let Some(kimberlite_query::Value::Text(name)) = row.first() {
                    let drop_sql = format!("DROP TABLE {name}");
                    if tenant.execute(&drop_sql, &[]).is_ok() {
                        tables_dropped += 1;
                    }
                }
            }
        }
        let deleted = self.tenant_registry.remove(tenant_id);
        Response::new(
            request.id,
            ResponsePayload::TenantDelete(TenantDeleteResponse {
                deleted,
                tables_dropped,
            }),
        )
    }

    fn handle_tenant_get(&mut self, request: &Request, tenant_id: TenantId) -> Response {
        match self.tenant_registry.get(tenant_id) {
            Some(entry) => Response::new(
                request.id,
                ResponsePayload::TenantGet(TenantGetResponse {
                    tenant: TenantInfo {
                        tenant_id,
                        name: entry.name,
                        table_count: self.tenant_table_count(tenant_id),
                        created_at_nanos: Some(entry.created_at_nanos),
                    },
                }),
            ),
            None => Response::error(
                request.id,
                ErrorCode::TenantNotFound,
                format!("tenant {} not registered", u64::from(tenant_id)),
            ),
        }
    }

    fn handle_api_key_register(
        &mut self,
        request: &Request,
        subject: String,
        tenant_id: TenantId,
        roles: Vec<String>,
        expires_at_nanos: Option<u64>,
    ) -> Response {
        let expires_at =
            expires_at_nanos.map(|ns| std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns));
        match self
            .handler
            .auth_service()
            .issue_api_key(subject, tenant_id, roles, expires_at)
        {
            Ok((key, listing)) => Response::new(
                request.id,
                ResponsePayload::ApiKeyRegister(ApiKeyRegisterResponse {
                    key,
                    info: ApiKeyInfo {
                        key_id: listing.key_id,
                        subject: listing.subject,
                        tenant_id: listing.tenant_id,
                        roles: listing.roles,
                        expires_at_nanos: listing.expires_at_nanos,
                    },
                }),
            ),
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_api_key_revoke(&mut self, request: &Request, key: &str) -> Response {
        match self.handler.auth_service().revoke_api_key(key) {
            Ok(revoked) => {
                if revoked {
                    Response::new(
                        request.id,
                        ResponsePayload::ApiKeyRevoke(ApiKeyRevokeResponse { revoked: true }),
                    )
                } else {
                    Response::error(
                        request.id,
                        ErrorCode::ApiKeyNotFound,
                        "API key not found".to_string(),
                    )
                }
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_api_key_list(
        &mut self,
        request: &Request,
        tenant_filter: Option<TenantId>,
    ) -> Response {
        match self.handler.auth_service().list_api_keys(tenant_filter) {
            Ok(listings) => {
                let keys = listings
                    .into_iter()
                    .map(|l| ApiKeyInfo {
                        key_id: l.key_id,
                        subject: l.subject,
                        tenant_id: l.tenant_id,
                        roles: l.roles,
                        expires_at_nanos: l.expires_at_nanos,
                    })
                    .collect();
                Response::new(
                    request.id,
                    ResponsePayload::ApiKeyList(ApiKeyListResponse { keys }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_api_key_rotate(&mut self, request: &Request, old_key: &str) -> Response {
        match self.handler.auth_service().rotate_api_key(old_key) {
            Ok((new_key, listing)) => Response::new(
                request.id,
                ResponsePayload::ApiKeyRotate(ApiKeyRotateResponse {
                    new_key,
                    info: ApiKeyInfo {
                        key_id: listing.key_id,
                        subject: listing.subject,
                        tenant_id: listing.tenant_id,
                        roles: listing.roles,
                        expires_at_nanos: listing.expires_at_nanos,
                    },
                }),
            ),
            Err(_) => Response::error(
                request.id,
                ErrorCode::ApiKeyNotFound,
                "old API key not found".to_string(),
            ),
        }
    }

    fn handle_server_info(&mut self, request: &Request) -> Response {
        let cluster_mode = if self.handler.kimberlite_submitter_is_replicated() {
            ClusterMode::Clustered
        } else {
            ClusterMode::Standalone
        };
        let capabilities = vec![
            "query".to_string(),
            "append".to_string(),
            "subscribe.v2".to_string(),
            "admin.v1".to_string(),
            "schema.v1".to_string(),
            "server_info.v1".to_string(),
        ];
        Response::new(
            request.id,
            ResponsePayload::ServerInfo(ServerInfoResponse {
                build_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: kimberlite_wire::PROTOCOL_VERSION,
                capabilities,
                uptime_secs: self.started_at.elapsed().as_secs(),
                cluster_mode,
                tenant_count: self.tenant_registry.len() as u32,
            }),
        )
    }

    /// Intercepts Phase 5 compliance requests (consent + erasure).
    ///
    /// These ops are tenant-scoped and do not require Admin — any
    /// authenticated identity for that tenant can call them. Admin-role
    /// enforcement for cross-tenant scans is handled one layer up.
    fn try_handle_compliance_request(&mut self, request: &Request) -> Option<Response> {
        match &request.payload {
            RequestPayload::ConsentGrant(req) => Some(self.handle_consent_grant(
                request,
                req.subject_id.clone(),
                req.purpose,
                req.scope,
                req.basis.clone(),
                req.terms_version.clone(),
                req.accepted,
            )),
            RequestPayload::ConsentWithdraw(req) => {
                Some(self.handle_consent_withdraw(request, &req.consent_id))
            }
            RequestPayload::ConsentCheck(req) => {
                Some(self.handle_consent_check(request, &req.subject_id, req.purpose))
            }
            RequestPayload::ConsentList(req) => {
                Some(self.handle_consent_list(request, &req.subject_id, req.valid_only))
            }
            RequestPayload::ErasureRequest(req) => {
                Some(self.handle_erasure_request(request, &req.subject_id))
            }
            RequestPayload::ErasureMarkProgress(req) => {
                Some(self.handle_erasure_mark_progress(request, &req.request_id, &req.streams))
            }
            RequestPayload::ErasureMarkStreamErased(req) => {
                Some(self.handle_erasure_mark_stream_erased(
                    request,
                    &req.request_id,
                    req.stream_id,
                    req.records_erased,
                ))
            }
            RequestPayload::ErasureComplete(req) => {
                Some(self.handle_erasure_complete(request, &req.request_id))
            }
            RequestPayload::ErasureExempt(req) => {
                Some(self.handle_erasure_exempt(request, &req.request_id, req.basis))
            }
            RequestPayload::ErasureStatus(req) => {
                Some(self.handle_erasure_status(request, &req.request_id))
            }
            RequestPayload::ErasureList(_) => Some(self.handle_erasure_list(request)),

            // Phase 6 — audit / export / breach (ROADMAP v0.5.0 item C).
            // Each handler is server-authoritative: the SDK wrappers already
            // round-trip, but the server was stubbed at `InternalError`.
            // These paths route through audit_log_query / export_engine /
            // breach_detector on the live kimberlite instance and emit a
            // compliance-audit entry per mutation.
            RequestPayload::AuditQuery(req) => Some(self.handle_audit_query(request, req.clone())),
            RequestPayload::VerifyAuditChain(_) => Some(self.handle_verify_audit_chain(request)),
            RequestPayload::ExportSubject(req) => {
                Some(self.handle_export_subject(request, req.clone()))
            }
            RequestPayload::VerifyExport(req) => {
                Some(self.handle_verify_export(request, req.clone()))
            }
            RequestPayload::BreachReportIndicator(req) => {
                Some(self.handle_breach_report_indicator(request, req.clone()))
            }
            RequestPayload::BreachQueryStatus(req) => {
                Some(self.handle_breach_query_status(request, req.clone()))
            }
            RequestPayload::BreachConfirm(req) => {
                Some(self.handle_breach_confirm(request, req.clone()))
            }
            RequestPayload::BreachResolve(req) => {
                Some(self.handle_breach_resolve(request, req.clone()))
            }
            // Phase 6 — masking policy catalogue list (v0.6.0 Tier 2 #7)
            RequestPayload::MaskingPolicyList(req) => {
                Some(self.handle_masking_policy_list(request, req.include_attachments))
            }
            _ => None,
        }
    }

    fn handle_consent_grant(
        &mut self,
        request: &Request,
        subject_id: String,
        purpose: WireConsentPurpose,
        scope: Option<WireConsentScope>,
        basis: Option<WireConsentBasis>,
        terms_version: Option<String>,
        accepted: bool,
    ) -> Response {
        self.tenant_registry.touch(request.tenant_id);
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let native_purpose = wire_to_native_purpose(purpose);
        let native_scope = scope
            .map_or(kimberlite_compliance::consent::ConsentScope::AllData, |s| {
                wire_to_native_scope(s)
            });
        let scope_label = scope.map_or_else(|| "default".to_string(), |s| format!("{s:?}"));
        let native_basis = basis.as_ref().map(wire_to_native_basis);
        let basis_label = basis_audit_label(basis.as_ref());
        let result = tenant.grant_consent_with_options(
            &subject_id,
            native_purpose,
            kimberlite_compliance::consent::GrantOptions {
                scope: native_scope,
                basis: native_basis,
                terms_version: terms_version.clone(),
                accepted,
            },
        );
        drop(tenant);
        match result {
            Ok(consent_id) => {
                self.record_audit_event(
                    request,
                    ComplianceAuditAction::ConsentGranted {
                        subject_id: subject_id.clone(),
                        purpose: format!("{native_purpose:?}"),
                        scope: basis_label
                            .map_or(scope_label.clone(), |b| format!("{scope_label}|basis={b}")),
                        terms_version: terms_version.clone(),
                        accepted,
                    },
                );
                Response::new(
                    request.id,
                    ResponsePayload::ConsentGrant(ConsentGrantResponse {
                        consent_id: consent_id.to_string(),
                        granted_at_nanos: now_nanos_u64(),
                    }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_consent_withdraw(&mut self, request: &Request, consent_id: &str) -> Response {
        let uuid = match uuid::Uuid::parse_str(consent_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid consent_id: {consent_id}"),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let subject_id = tenant
            .get_consent(uuid)
            .ok()
            .flatten()
            .map(|rec| rec.subject_id);
        let result = tenant.withdraw_consent(uuid);
        drop(tenant);
        match result {
            Ok(()) => {
                self.record_audit_event(
                    request,
                    ComplianceAuditAction::ConsentWithdrawn {
                        subject_id: subject_id.unwrap_or_default(),
                        consent_id: uuid,
                    },
                );
                Response::new(
                    request.id,
                    ResponsePayload::ConsentWithdraw(ConsentWithdrawResponse {
                        withdrawn_at_nanos: now_nanos_u64(),
                    }),
                )
            }
            Err(e) => {
                let msg = e.to_string();
                let code = if msg.contains("not found") {
                    ErrorCode::ConsentNotFound
                } else if msg.contains("expired") {
                    ErrorCode::ConsentExpired
                } else {
                    ErrorCode::InternalError
                };
                Response::error(request.id, code, msg)
            }
        }
    }

    fn handle_consent_check(
        &mut self,
        request: &Request,
        subject_id: &str,
        purpose: WireConsentPurpose,
    ) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let native_purpose = wire_to_native_purpose(purpose);
        match tenant.check_consent(subject_id, native_purpose) {
            Ok(is_valid) => Response::new(
                request.id,
                ResponsePayload::ConsentCheck(ConsentCheckResponse { is_valid }),
            ),
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_consent_list(
        &mut self,
        request: &Request,
        subject_id: &str,
        valid_only: bool,
    ) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        match tenant.get_consents_for_subject(subject_id) {
            Ok(records) => {
                let consents: Vec<WireConsentRecord> = records
                    .into_iter()
                    .filter(|r| {
                        !valid_only
                            || (r.withdrawn_at.is_none()
                                && r.expires_at.is_none_or(|t| t > chrono::Utc::now()))
                    })
                    .map(consent_record_to_wire)
                    .collect();
                Response::new(
                    request.id,
                    ResponsePayload::ConsentList(ConsentListResponse { consents }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_erasure_request(&mut self, request: &Request, subject_id: &str) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let result = tenant.request_erasure(subject_id);
        // **v0.6.0 Tier 2 #8 — auto-discovery on the wire.** After
        // opening the request, walk the tenant's catalog and populate
        // `affected_streams` with every PHI/PII/Sensitive stream that
        // carries a `subject_id` column. SDKs read this list from the
        // returned `ErasureRequestInfo` and drive `mark_progress` /
        // per-stream erasure against it — no wire change needed.
        let discovered = tenant.discover_phi_pii_streams().ok();
        drop(tenant);
        match result {
            Ok(mut req) => {
                if let Some(streams) = discovered {
                    req.affected_streams = streams;
                }
                self.record_audit_event(
                    request,
                    ComplianceAuditAction::ErasureRequested {
                        subject_id: subject_id.to_string(),
                        request_id: req.request_id,
                    },
                );
                Response::new(
                    request.id,
                    ResponsePayload::ErasureRequest(ErasureRequestResponse {
                        request: erasure_request_to_wire(&req),
                    }),
                )
            }
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    fn handle_erasure_mark_progress(
        &mut self,
        request: &Request,
        request_id: &str,
        streams: &[kimberlite_types::StreamId],
    ) -> Response {
        let uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    "invalid request_id".to_string(),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        if let Err(e) = tenant.mark_erasure_in_progress(uuid, streams.to_vec()) {
            return Response::error(
                request.id,
                erasure_error_code(&e.to_string()),
                e.to_string(),
            );
        }
        self.respond_with_erasure_request(request, uuid, |r| {
            ResponsePayload::ErasureMarkProgress(ErasureMarkProgressResponse {
                request: erasure_request_to_wire(r),
            })
        })
    }

    fn handle_erasure_mark_stream_erased(
        &mut self,
        request: &Request,
        request_id: &str,
        stream_id: kimberlite_types::StreamId,
        records_erased: u64,
    ) -> Response {
        let uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    "invalid request_id".to_string(),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        if let Err(e) = tenant.mark_stream_erased(uuid, stream_id, records_erased) {
            return Response::error(
                request.id,
                erasure_error_code(&e.to_string()),
                e.to_string(),
            );
        }
        self.respond_with_erasure_request(request, uuid, |r| {
            ResponsePayload::ErasureMarkStreamErased(ErasureMarkStreamErasedResponse {
                request: erasure_request_to_wire(r),
            })
        })
    }

    fn handle_erasure_complete(&mut self, request: &Request, request_id: &str) -> Response {
        let uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    "invalid request_id".to_string(),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let result = tenant.complete_erasure(uuid);
        drop(tenant);
        match result {
            Ok(audit) => {
                self.record_audit_event(
                    request,
                    ComplianceAuditAction::ErasureCompleted {
                        subject_id: audit.subject_id.clone(),
                        records_erased: audit.records_erased,
                        request_id: uuid,
                    },
                );
                Response::new(
                    request.id,
                    ResponsePayload::ErasureComplete(ErasureCompleteResponse {
                        audit: erasure_audit_to_wire(&audit),
                    }),
                )
            }
            Err(e) => Response::error(
                request.id,
                erasure_error_code(&e.to_string()),
                e.to_string(),
            ),
        }
    }

    fn handle_erasure_exempt(
        &mut self,
        request: &Request,
        request_id: &str,
        basis: WireExemptionBasis,
    ) -> Response {
        let uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    "invalid request_id".to_string(),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let native_basis = wire_to_native_exemption(basis);
        let subject_id = tenant
            .get_erasure_request(uuid)
            .ok()
            .flatten()
            .map(|r| r.subject_id)
            .unwrap_or_default();
        let exempt_result = tenant.exempt_from_erasure(uuid, native_basis);
        drop(tenant);
        if let Err(e) = exempt_result {
            return Response::error(
                request.id,
                erasure_error_code(&e.to_string()),
                e.to_string(),
            );
        }
        self.record_audit_event(
            request,
            ComplianceAuditAction::ErasureExempted {
                subject_id,
                request_id: uuid,
                basis: format!("{native_basis:?}"),
            },
        );
        self.respond_with_erasure_request(request, uuid, |r| {
            ResponsePayload::ErasureExempt(ErasureExemptResponse {
                request: erasure_request_to_wire(r),
            })
        })
    }

    fn handle_erasure_status(&mut self, request: &Request, request_id: &str) -> Response {
        let uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    "invalid request_id".to_string(),
                );
            }
        };
        self.respond_with_erasure_request(request, uuid, |r| {
            ResponsePayload::ErasureStatus(ErasureStatusResponse {
                request: erasure_request_to_wire(r),
            })
        })
    }

    fn handle_erasure_list(&mut self, request: &Request) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        match tenant.erasure_audit_trail() {
            Ok(records) => Response::new(
                request.id,
                ResponsePayload::ErasureList(ErasureListResponse {
                    audit: records.iter().map(erasure_audit_to_wire).collect(),
                }),
            ),
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    // ========================================================================
    // Phase 6 — audit / export / breach handlers (ROADMAP v0.5.0 item C).
    // ========================================================================
    //
    // Invariants every handler holds:
    //   * tenant-scoped — every call resolves to `request.tenant_id`;
    //     cross-tenant leakage would be a compliance-grade breach.
    //   * audit-logged — every mutation (export produced, breach confirmed,
    //     breach resolved) appends a ComplianceAuditAction entry on the
    //     hash-chained audit log. Read-only paths (audit_query, breach
    //     query_status, verify_export) do NOT audit — they're the
    //     observation side of the workflow, not the mutation side.
    //   * idempotency-friendly — verify_export re-hashes deterministically;
    //     calling it twice returns the same `{valid, signature_valid}`.
    //   * wire-type invariants enforced at the boundary — uuid parse errors
    //     surface `ErrorCode::InvalidRequest`; missing events surface
    //     `ErrorCode::ExportNotFound` rather than a confusing `InternalError`.

    fn handle_audit_query(
        &mut self,
        request: &Request,
        req: kimberlite_wire::AuditQueryRequest,
    ) -> Response {
        use chrono::DateTime;
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);

        // Wire → native filter conversion. All fields are optional; unset
        // fields don't constrain the query. Nanos → DateTime<Utc> uses
        // from_timestamp_nanos which wraps on overflow; the wire type is
        // u64 so overflow is impossible within meaningful time ranges.
        let filter = kimberlite_compliance::audit::AuditQuery {
            subject_id: req.subject_id.clone(),
            action_type: req.action_type.clone(),
            actor: req.actor.clone(),
            tenant_id: Some(u64::from(request.tenant_id)),
            limit: req.limit.map(|n| n as usize),
            time_from: req
                .time_from_nanos
                .map(|ns| DateTime::from_timestamp_nanos(ns as i64)),
            time_to: req
                .time_to_nanos
                .map(|ns| DateTime::from_timestamp_nanos(ns as i64)),
        };

        // Query returns event IDs; the wire surface needs full
        // AuditEventInfo, so pull the events out by id.
        let event_ids = match tenant.audit_log_query(&filter) {
            Ok(ids) => ids,
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };
        let events = match tenant.audit_log_get_events(&event_ids) {
            Ok(events) => events,
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };

        // v0.6.0 Tier 2 #9 — project to the SDK-safe shape.
        //
        // `ComplianceAuditEvent::to_sdk_entry` strips every value
        // from the action payload and keeps only the schema
        // (`changed_field_names`). The raw action struct NEVER
        // reaches the wire — only its projected form does. This is
        // the invariant the `audit_sdk_entry_never_leaks_values`
        // property test locks in.
        let wire_events: Vec<kimberlite_wire::AuditEventInfo> = events
            .into_iter()
            .map(|ev| {
                let entry = ev.to_sdk_entry();
                kimberlite_wire::AuditEventInfo {
                    event_id: entry.event_id.to_string(),
                    timestamp_nanos: entry.occurred_at.timestamp_nanos_opt().unwrap_or(0).max(0)
                        as u64,
                    action: entry.action,
                    subject_id: entry.subject_id,
                    actor: entry.actor,
                    tenant_id: ev.tenant_id,
                    ip_address: ev.ip_address.clone(),
                    correlation_id: entry.correlation_id.map(|u| u.to_string()),
                    request_id: entry.request_id.map(|u| u.to_string()),
                    reason: entry.reason,
                    source_country: ev.source_country.clone(),
                    changed_field_names: entry.changed_field_names,
                }
            })
            .collect();

        Response::new(
            request.id,
            ResponsePayload::AuditQuery(kimberlite_wire::AuditQueryResponse {
                events: wire_events,
            }),
        )
    }

    fn handle_verify_audit_chain(&mut self, request: &Request) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let payload = match tenant.audit_log_verify_chain() {
            Ok((event_count, head)) => kimberlite_wire::VerifyAuditChainResponse {
                ok: true,
                event_count,
                chain_head_hex: hex_encode(&head),
                mismatch_at_index: None,
                error_message: None,
            },
            Err(e) => {
                use kimberlite_compliance::audit::AuditChainError;
                let mismatch_at = match &e {
                    AuditChainError::PrevHashMismatch { index }
                    | AuditChainError::EventHashMismatch { index } => Some(*index as u64),
                    AuditChainError::FirstEventPrevHashNonZero => Some(0),
                    AuditChainError::ChainHeadMismatch
                    | AuditChainError::CanonicalizationFailed => None,
                };
                let head = tenant.audit_log_chain_head_hex();
                kimberlite_wire::VerifyAuditChainResponse {
                    ok: false,
                    event_count: 0,
                    chain_head_hex: head,
                    mismatch_at_index: mismatch_at,
                    error_message: Some(e.to_string()),
                }
            }
        };
        Response::new(request.id, ResponsePayload::VerifyAuditChain(payload))
    }

    fn handle_export_subject(
        &mut self,
        request: &Request,
        req: kimberlite_wire::ExportSubjectRequest,
    ) -> Response {
        use base64::Engine;
        self.tenant_registry.touch(request.tenant_id);
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);

        // Default subject column mirrors the erasure executor's convention.
        let records = match tenant.collect_subject_export_records(
            &req.subject_id,
            "subject_id",
            &req.stream_ids,
            req.max_records_per_stream,
        ) {
            Ok(rs) => rs,
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };
        if records.is_empty() {
            return Response::error(
                request.id,
                ErrorCode::ExportNotFound,
                format!("no data found for subject {}", req.subject_id),
            );
        }
        let native_format = wire_to_native_export_format(req.format);
        let (export, body_bytes) = match tenant.export_subject_data_with_body(
            &req.subject_id,
            &records,
            native_format,
            &req.requester_id,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };

        // ComplianceAuditAction::DataExported exists (GDPR Article 20
        // framing); map our wire ExportFormat to its String surface.
        self.record_audit_event(
            request,
            ComplianceAuditAction::DataExported {
                subject_id: req.subject_id.clone(),
                export_id: export.export_id,
                format: format!("{native_format:?}"),
                record_count: export.record_count,
            },
        );

        let info = kimberlite_wire::PortabilityExportInfo {
            export_id: export.export_id.to_string(),
            subject_id: export.subject_id,
            requester_id: export.requester_id,
            requested_at_nanos: export
                .requested_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .max(0) as u64,
            completed_at_nanos: export
                .completed_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .max(0) as u64,
            format: req.format,
            streams_included: export.streams_included,
            record_count: export.record_count,
            content_hash_hex: hex_encode(export.content_hash.as_bytes()),
            signature_hex: export.signature.as_ref().map(|sig| hex_encode(sig)),
            body_base64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
        };
        Response::new(
            request.id,
            ResponsePayload::ExportSubject(kimberlite_wire::ExportSubjectResponse { export: info }),
        )
    }

    fn handle_verify_export(
        &mut self,
        request: &Request,
        req: kimberlite_wire::VerifyExportRequest,
    ) -> Response {
        use base64::Engine;
        let export_uuid = match uuid::Uuid::parse_str(&req.export_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid export_id: {}", req.export_id),
                );
            }
        };
        let body_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.body_base64) {
            Ok(b) => b,
            Err(e) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid body_base64: {e}"),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let (valid, signature_valid) = match tenant.verify_subject_export(export_uuid, &body_bytes)
        {
            Ok(pair) => pair,
            Err(e) => {
                return Response::error(request.id, ErrorCode::ExportNotFound, e.to_string());
            }
        };
        Response::new(
            request.id,
            ResponsePayload::VerifyExport(kimberlite_wire::VerifyExportResponse {
                valid,
                signature_valid,
            }),
        )
    }

    fn handle_breach_report_indicator(
        &mut self,
        request: &Request,
        req: kimberlite_wire::BreachReportIndicatorRequest,
    ) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let event_result = match &req.indicator {
            kimberlite_wire::BreachIndicatorPayload::MassDataExport {
                records,
                data_classes,
            } => tenant.check_breach_mass_export(*records, data_classes),
            kimberlite_wire::BreachIndicatorPayload::UnauthorizedAccessPattern { .. } => {
                tenant.check_breach_denied_access()
            }
            kimberlite_wire::BreachIndicatorPayload::PrivilegeEscalation { from_role, to_role } => {
                tenant.check_breach_privilege_escalation(from_role, to_role)
            }
            kimberlite_wire::BreachIndicatorPayload::AnomalousQueryVolume { .. } => {
                tenant.check_breach_query_volume()
            }
            kimberlite_wire::BreachIndicatorPayload::UnusualAccessTime { hour } => {
                tenant.check_breach_unusual_access_time(*hour)
            }
            kimberlite_wire::BreachIndicatorPayload::DataExfiltrationPattern {
                bytes_exported,
                data_classes,
            } => tenant.check_breach_data_exfiltration(*bytes_exported, data_classes),
        };
        let event = match event_result {
            Ok(e) => e,
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };
        if let Some(ref e) = event {
            self.record_audit_event(
                request,
                ComplianceAuditAction::BreachDetected {
                    event_id: e.event_id,
                    severity: format!("{:?}", e.severity),
                    indicator: breach_indicator_kind(&e.indicator).to_string(),
                    affected_subjects: Vec::new(),
                },
            );
        }
        let wire_event = event.as_ref().map(native_breach_event_to_wire);
        Response::new(
            request.id,
            ResponsePayload::BreachReportIndicator(
                kimberlite_wire::BreachReportIndicatorResponse { event: wire_event },
            ),
        )
    }

    fn handle_breach_query_status(
        &mut self,
        request: &Request,
        req: kimberlite_wire::BreachQueryStatusRequest,
    ) -> Response {
        let event_uuid = match uuid::Uuid::parse_str(&req.event_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid event_id: {}", req.event_id),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let report = match tenant.breach_report(event_uuid) {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Response::error(
                    request.id,
                    ErrorCode::BreachNotFound,
                    format!("breach event {event_uuid} not found"),
                );
            }
            Err(e) => {
                return Response::error(request.id, ErrorCode::InternalError, e.to_string());
            }
        };
        Response::new(
            request.id,
            ResponsePayload::BreachQueryStatus(kimberlite_wire::BreachQueryStatusResponse {
                report: native_breach_report_to_wire(&report),
            }),
        )
    }

    fn handle_breach_confirm(
        &mut self,
        request: &Request,
        req: kimberlite_wire::BreachConfirmRequest,
    ) -> Response {
        let event_uuid = match uuid::Uuid::parse_str(&req.event_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid event_id: {}", req.event_id),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let ts = match tenant.confirm_breach(event_uuid) {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                let code = if msg.contains("not found") {
                    ErrorCode::BreachNotFound
                } else {
                    ErrorCode::InternalError
                };
                return Response::error(request.id, code, msg);
            }
        };
        self.record_audit_event(
            request,
            ComplianceAuditAction::BreachNotified {
                event_id: event_uuid,
                notified_at: ts,
                affected_subjects: Vec::new(),
            },
        );
        Response::new(
            request.id,
            ResponsePayload::BreachConfirm(kimberlite_wire::BreachConfirmResponse {
                notification_sent_at_nanos: ts.timestamp_nanos_opt().unwrap_or(0).max(0) as u64,
            }),
        )
    }

    fn handle_breach_resolve(
        &mut self,
        request: &Request,
        req: kimberlite_wire::BreachResolveRequest,
    ) -> Response {
        let event_uuid = match uuid::Uuid::parse_str(&req.event_id) {
            Ok(u) => u,
            Err(_) => {
                return Response::error(
                    request.id,
                    ErrorCode::InvalidRequest,
                    format!("invalid event_id: {}", req.event_id),
                );
            }
        };
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        let ts = match tenant.resolve_breach(event_uuid, &req.remediation) {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                let code = if msg.contains("not found") {
                    ErrorCode::BreachNotFound
                } else {
                    ErrorCode::InternalError
                };
                return Response::error(request.id, code, msg);
            }
        };
        self.record_audit_event(
            request,
            ComplianceAuditAction::BreachResolved {
                event_id: event_uuid,
                remediation: req.remediation.clone(),
                affected_subjects: Vec::new(),
            },
        );
        Response::new(
            request.id,
            ResponsePayload::BreachResolve(kimberlite_wire::BreachResolveResponse {
                resolved_at_nanos: ts.timestamp_nanos_opt().unwrap_or(0).max(0) as u64,
            }),
        )
    }

    fn respond_with_erasure_request(
        &self,
        request: &Request,
        uuid: uuid::Uuid,
        build: impl FnOnce(&kimberlite_compliance::erasure::ErasureRequest) -> ResponsePayload,
    ) -> Response {
        let tenant = self.handler.kimberlite().tenant(request.tenant_id);
        match tenant.get_erasure_request(uuid) {
            Ok(Some(r)) => Response::new(request.id, build(&r)),
            Ok(None) => Response::error(
                request.id,
                ErrorCode::ErasureNotFound,
                format!("erasure request {uuid} not found"),
            ),
            Err(e) => Response::error(request.id, ErrorCode::InternalError, e.to_string()),
        }
    }

    /// Counts tables owned by a specific tenant. Since `kernel_state` is
    /// global (no tenant dimension), this runs a SQL `SHOW TABLES` on the
    /// tenant handle which the query engine scopes correctly.
    fn tenant_table_count(&self, tenant_id: TenantId) -> u32 {
        self.handler
            .kimberlite()
            .tenant(tenant_id)
            .query("SHOW TABLES", &[])
            .map(|r| r.rows.len() as u32)
            .unwrap_or(0)
    }

    /// Drains ready events for every active subscription on this connection
    /// and queues them as `Push` frames on the connection's write buffer.
    fn pump_connection_subscriptions(&mut self, token: Token) {
        let kb = self.handler.kimberlite();
        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };
        if conn.subscriptions.is_empty() || conn.closing {
            return;
        }
        let pushes = conn.subscriptions.pump(kb);
        for push in pushes {
            if let Err(e) = conn.queue_push(push) {
                error!("Error encoding push frame for {:?}: {}", token, e);
                conn.closing = true;
                break;
            }
        }
    }

    /// Pumps subscriptions for every connection. Called periodically on poll
    /// timeouts and after each request batch so even quiet clients make
    /// subscription progress.
    fn pump_all_subscriptions(&mut self) {
        let tokens: Vec<Token> = self.connections.keys().copied().collect();
        for token in tokens {
            self.pump_connection_subscriptions(token);
        }
    }

    /// Handles readable events on a connection.
    fn handle_readable(&mut self, token: Token) -> ServerResult<()> {
        let Some(conn) = self.connections.get_mut(&token) else {
            warn!("Readable event for unknown token {:?}", token);
            return Ok(());
        };

        // Update activity timestamp
        conn.touch();

        // Read data from the socket
        match conn.read() {
            Ok(true) => {
                // Connection still open, process requests
                self.process_requests(token);
                // Flush any ready subscription events to the same connection.
                self.pump_connection_subscriptions(token);
            }
            Ok(false) => {
                // Connection closed by peer
                debug!("Connection {:?} closed by peer", token);
                if let Some(c) = self.connections.get_mut(&token) {
                    c.closing = true;
                }
            }
            Err(e) => {
                error!("Error reading from {:?}: {}", token, e);
                if let Some(c) = self.connections.get_mut(&token) {
                    c.closing = true;
                }
            }
        }

        // Update interest if needed
        self.update_interest(token)?;
        Ok(())
    }

    /// Handles writable events on a connection.
    fn handle_writable(&mut self, token: Token) -> ServerResult<()> {
        let Some(conn) = self.connections.get_mut(&token) else {
            warn!("Writable event for unknown token {:?}", token);
            return Ok(());
        };

        match conn.write() {
            Ok(true) => {
                // All data written
                trace!("All data written to {:?}", token);
            }
            Ok(false) => {
                // More data to write
                trace!("More data to write to {:?}", token);
            }
            Err(e) => {
                error!("Error writing to {:?}: {}", token, e);
                conn.closing = true;
            }
        }

        // Update interest
        self.update_interest(token)?;
        Ok(())
    }

    /// Processes pending requests on a connection.
    fn process_requests(&mut self, token: Token) {
        loop {
            let Some(conn) = self.connections.get_mut(&token) else {
                return;
            };

            // Check if there's enough data for a frame
            if !conn.has_pending_data() {
                break;
            }

            // Try to decode a request
            match conn.try_decode_request() {
                Ok(Some(request)) => {
                    trace!("Received request {:?} from {:?}", request.id, token);

                    // Apply per-tenant rate limit if tenant tags are configured
                    // and this connection doesn't have a tenant-specific limiter yet
                    if let Some(ref tag_config) = self.config.tenant_tags {
                        let conn = self.connections.get_mut(&token).expect("just checked");
                        if conn.tenant_priority.is_none() {
                            let tenant_id = u64::from(request.tenant_id);
                            let priority = tag_config.priority_for(tenant_id);
                            let rate_config = tag_config.rate_limit_for(tenant_id);
                            conn.set_tenant_rate_limit(priority, rate_config);
                        }
                    }

                    // Check rate limit before processing
                    let Some(conn) = self.connections.get_mut(&token) else {
                        return;
                    };

                    if !conn.check_rate_limit() {
                        warn!("Rate limit exceeded for {:?}", token);
                        metrics::record_rate_limited();
                        let response = Response::error(
                            request.id,
                            ErrorCode::RateLimited,
                            "rate limit exceeded".to_string(),
                        );
                        if let Err(e) = conn.queue_response(&response) {
                            error!("Error encoding rate limit response: {}", e);
                            conn.closing = true;
                        }
                        continue;
                    }

                    // v2 subscription lifecycle — intercept before the
                    // stateless handler so we have access to the connection's
                    // subscription registry.
                    if let Some(response) = self.try_handle_subscription_request(token, &request) {
                        if let Some(c) = self.connections.get_mut(&token) {
                            if let Err(e) = c.queue_response(&response) {
                                error!("Error encoding subscription response: {}", e);
                                c.closing = true;
                            }
                        }
                        continue;
                    }

                    // Phase 4 admin/schema/server-info requests — intercepted
                    // here so they can touch the tenant registry + auth service
                    // without threading state through the stateless handler.
                    if let Some(response) = self.try_handle_admin_request(token, &request) {
                        if let Some(c) = self.connections.get_mut(&token) {
                            if let Err(e) = c.queue_response(&response) {
                                error!("Error encoding admin response: {}", e);
                                c.closing = true;
                            }
                        }
                        continue;
                    }

                    // Phase 5 compliance requests — consent + erasure.
                    if let Some(response) = self.try_handle_compliance_request(&request) {
                        if let Some(c) = self.connections.get_mut(&token) {
                            if let Err(e) = c.queue_response(&response) {
                                error!("Error encoding compliance response: {}", e);
                                c.closing = true;
                            }
                        }
                        continue;
                    }

                    // Clone the connection's current identity before calling the
                    // handler (we need &mut self.connections later).
                    let conn_identity_opt = self
                        .connections
                        .get(&token)
                        .and_then(|c| c.authenticated_identity.clone());

                    // Handle the request.
                    let (response, new_identity) =
                        self.handler.handle(request, conn_identity_opt.as_ref());

                    // Store the identity returned by a successful Handshake.
                    if let Some(identity) = new_identity {
                        if let Some(conn) = self.connections.get_mut(&token) {
                            conn.authenticated_identity = Some(identity);
                        }
                    }

                    // Queue the response
                    if let Some(c) = self.connections.get_mut(&token) {
                        if let Err(e) = c.queue_response(&response) {
                            error!("Error encoding response: {}", e);
                            c.closing = true;
                        }
                    }
                }
                Ok(None) => {
                    // Need more data
                    break;
                }
                Err(e) => {
                    error!("Error decoding request from {:?}: {}", token, e);
                    if let Some(c) = self.connections.get_mut(&token) {
                        c.closing = true;
                    }
                    break;
                }
            }
        }
    }

    /// Updates the interest flags for a connection.
    fn update_interest(&mut self, token: Token) -> ServerResult<()> {
        let Some(conn) = self.connections.get_mut(&token) else {
            return Ok(());
        };

        let interest = conn.interest();
        self.poll
            .registry()
            .reregister(&mut conn.stream, token, interest)?;

        Ok(())
    }

    /// Cleans up connections that have been marked as closing or are idle.
    fn cleanup_closed(&mut self) {
        let idle_timeout = self.config.idle_timeout;

        let to_close: Vec<Token> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                if c.closing {
                    return true;
                }
                // Check idle timeout
                if let Some(timeout) = idle_timeout {
                    if c.is_idle(timeout) {
                        return true;
                    }
                }
                false
            })
            .map(|(t, _)| *t)
            .collect();

        for token in to_close {
            if let Some(mut conn) = self.connections.remove(&token) {
                if conn.closing {
                    debug!("Closing connection {:?}", token);
                } else {
                    debug!("Closing idle connection {:?}", token);
                }
                let _ = self.poll.registry().deregister(&mut conn.stream);

                // Record metrics
                metrics::record_connection_closed();
            }
        }
    }

    /// Returns the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Returns a handle that can be used to request shutdown from another thread.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown_requested: Arc::clone(&self.shutdown_requested),
        }
    }

    /// Requests graceful shutdown.
    ///
    /// The server will stop accepting new connections and drain existing ones.
    pub fn shutdown(&self) {
        info!("Shutdown requested");
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Returns true if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Runs the server with graceful shutdown support.
    ///
    /// This method blocks until shutdown is requested and all connections are drained.
    /// If signal handling was enabled via `with_signal_handling`, the server will
    /// automatically shut down on SIGTERM or SIGINT.
    pub fn run_with_shutdown(&mut self) -> ServerResult<()> {
        let mut events = Events::with_capacity(MAX_EVENTS);

        info!("Server event loop started (with shutdown support)");

        loop {
            // Check if shutdown was requested
            if self.is_shutdown_requested() {
                info!("Shutdown requested, draining connections...");
                return self.drain_connections();
            }

            // Wait for events with a timeout to check shutdown periodically
            let timeout = Some(Duration::from_millis(100));
            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }

            // Process events
            for event in &events {
                match event.token() {
                    LISTENER_TOKEN => {
                        if !self.is_shutdown_requested() {
                            self.accept_connections()?;
                        }
                    }
                    SIGNAL_TOKEN => {
                        // Handle signals
                        self.handle_signals();
                    }
                    crate::http::HTTP_LISTENER_TOKEN => {
                        if let Some(ref sidecar) = self.http_sidecar {
                            sidecar.handle_accept(&self.health_checker);
                        }
                    }
                    token => {
                        if event.is_readable() {
                            self.handle_readable(token)?;
                        }
                        if event.is_writable() {
                            self.handle_writable(token)?;
                        }
                    }
                }
            }

            // Clean up closed connections
            self.cleanup_closed();
        }
    }

    /// Handles incoming signals (SIGTERM/SIGINT on Unix).
    #[cfg(unix)]
    fn handle_signals(&mut self) {
        if let Some(signals) = &mut self.signals {
            for signal in signals.pending() {
                match signal {
                    SIGTERM => {
                        info!("Received SIGTERM, initiating graceful shutdown");
                        self.shutdown();
                    }
                    SIGINT => {
                        info!("Received SIGINT, initiating graceful shutdown");
                        self.shutdown();
                    }
                    _ => {
                        debug!("Received signal {}, ignoring", signal);
                    }
                }
            }
        }
    }

    /// Stub for Windows - signal handling is done via ctrlc handler.
    #[cfg(windows)]
    fn handle_signals(&mut self) {
        // On Windows, Ctrl+C is handled by the ctrlc handler set in with_signal_handling
        // This method is called when SIGNAL_TOKEN is triggered, but on Windows that won't happen
    }

    /// Drains all active connections gracefully.
    ///
    /// Waits up to `SHUTDOWN_DRAIN_TIMEOUT` for connections to complete.
    fn drain_connections(&mut self) -> ServerResult<()> {
        let deadline = Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
        let mut events = Events::with_capacity(MAX_EVENTS);

        // Mark all connections as closing (no new requests)
        for conn in self.connections.values_mut() {
            conn.closing = true;
        }

        // Continue processing until all connections are drained or timeout
        while !self.connections.is_empty() && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = Some(remaining.min(Duration::from_millis(100)));

            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }

            for event in &events {
                let token = event.token();
                if token == LISTENER_TOKEN {
                    continue; // Don't accept new connections
                }
                if event.is_readable() {
                    let _ = self.handle_readable(token);
                }
                if event.is_writable() {
                    let _ = self.handle_writable(token);
                }
            }

            self.cleanup_closed();
        }

        let remaining = self.connections.len();
        if remaining > 0 {
            warn!(
                "Shutdown timeout reached with {} connections still active",
                remaining
            );
        } else {
            info!("All connections drained successfully");
        }

        Ok(())
    }

    /// Returns the health checker.
    pub fn health_checker(&self) -> &HealthChecker {
        &self.health_checker
    }

    /// Returns the authentication service.
    pub fn auth_service(&self) -> &AuthService {
        self.handler.auth_service()
    }

    /// Returns the Prometheus metrics.
    pub fn metrics(&self) -> String {
        metrics::Metrics::global().render()
    }
}

/// A handle that can be used to request shutdown from another thread.
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown_requested: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Requests graceful shutdown.
    pub fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Returns true if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Phase 5 — helpers for wire ↔ compliance-crate type conversions.
// ============================================================================

fn now_nanos_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

// =========================================================================
// Phase 6 helpers (ROADMAP v0.5.0 item C).
//
// Hex-encoder — avoids a new workspace-level hex dependency. The pattern
// `format!("{:02x}", b)` is the canonical lowercase-hex representation
// used elsewhere in the codebase (install.sh SHA256SUMS, export audit).
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn wire_to_native_export_format(
    fmt: kimberlite_wire::ExportFormat,
) -> kimberlite_compliance::export::ExportFormat {
    match fmt {
        kimberlite_wire::ExportFormat::Json => kimberlite_compliance::export::ExportFormat::Json,
        kimberlite_wire::ExportFormat::Csv => kimberlite_compliance::export::ExportFormat::Csv,
    }
}

fn breach_indicator_kind(i: &kimberlite_compliance::breach::BreachIndicator) -> &'static str {
    use kimberlite_compliance::breach::BreachIndicator as BI;
    match i {
        BI::MassDataExport { .. } => "MassDataExport",
        BI::UnauthorizedAccessPattern { .. } => "UnauthorizedAccessPattern",
        BI::PrivilegeEscalation { .. } => "PrivilegeEscalation",
        BI::AnomalousQueryVolume { .. } => "AnomalousQueryVolume",
        BI::UnusualAccessTime { .. } => "UnusualAccessTime",
        BI::DataExfiltrationPattern { .. } => "DataExfiltrationPattern",
    }
}

fn native_breach_indicator_to_wire(
    i: &kimberlite_compliance::breach::BreachIndicator,
) -> kimberlite_wire::BreachIndicatorPayload {
    use kimberlite_compliance::breach::BreachIndicator as BI;
    use kimberlite_wire::BreachIndicatorPayload as WP;
    match i {
        BI::MassDataExport { records, .. } => WP::MassDataExport {
            records: *records,
            data_classes: Vec::new(),
        },
        BI::UnauthorizedAccessPattern {
            denied_attempts,
            window_secs,
        } => WP::UnauthorizedAccessPattern {
            denied_attempts: *denied_attempts,
            window_secs: *window_secs,
        },
        BI::PrivilegeEscalation { from_role, to_role } => WP::PrivilegeEscalation {
            from_role: from_role.clone(),
            to_role: to_role.clone(),
        },
        BI::AnomalousQueryVolume {
            queries_per_min,
            baseline,
        } => WP::AnomalousQueryVolume {
            queries_per_min: *queries_per_min,
            baseline: *baseline,
        },
        BI::UnusualAccessTime { hour, .. } => WP::UnusualAccessTime { hour: *hour },
        BI::DataExfiltrationPattern { bytes_exported, .. } => WP::DataExfiltrationPattern {
            bytes_exported: *bytes_exported,
            data_classes: Vec::new(),
        },
    }
}

fn native_breach_severity_to_wire(
    s: kimberlite_compliance::breach::BreachSeverity,
) -> kimberlite_wire::BreachSeverity {
    use kimberlite_compliance::breach::BreachSeverity as NS;
    use kimberlite_wire::BreachSeverity as WS;
    match s {
        NS::Low => WS::Low,
        NS::Medium => WS::Medium,
        NS::High => WS::High,
        NS::Critical => WS::Critical,
    }
}

fn native_breach_status_to_wire(
    s: &kimberlite_compliance::breach::BreachStatus,
) -> kimberlite_wire::BreachStatusTag {
    use kimberlite_compliance::breach::BreachStatus as NS;
    use kimberlite_wire::BreachStatusTag as WS;
    match s {
        NS::Detected => WS::Detected,
        NS::UnderInvestigation => WS::UnderInvestigation,
        NS::Confirmed {
            notification_sent_at,
        } => WS::Confirmed {
            notification_sent_at_nanos: notification_sent_at
                .and_then(|dt| dt.timestamp_nanos_opt())
                .and_then(|n| u64::try_from(n).ok()),
        },
        NS::FalsePositive {
            dismissed_by,
            reason,
        } => WS::FalsePositive {
            dismissed_by: dismissed_by.clone(),
            reason: reason.clone(),
        },
        NS::Resolved {
            resolved_at,
            remediation,
        } => WS::Resolved {
            resolved_at_nanos: resolved_at
                .timestamp_nanos_opt()
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(0),
            remediation: remediation.clone(),
        },
    }
}

fn native_breach_event_to_wire(
    e: &kimberlite_compliance::breach::BreachEvent,
) -> kimberlite_wire::BreachEventInfo {
    kimberlite_wire::BreachEventInfo {
        event_id: e.event_id.to_string(),
        detected_at_nanos: e
            .detected_at
            .timestamp_nanos_opt()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0),
        indicator: native_breach_indicator_to_wire(&e.indicator),
        severity: native_breach_severity_to_wire(e.severity),
        affected_subjects: e.affected_subjects,
        affected_data_classes: e.affected_data_classes.clone(),
        notification_deadline_nanos: e
            .notification_deadline
            .timestamp_nanos_opt()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0),
        status: native_breach_status_to_wire(&e.status),
    }
}

fn native_breach_report_to_wire(
    r: &kimberlite_compliance::breach::BreachReport,
) -> kimberlite_wire::BreachReportInfo {
    kimberlite_wire::BreachReportInfo {
        event: native_breach_event_to_wire(&r.event),
        timeline: r.timeline.clone(),
        affected_subject_count: r.affected_subject_count,
        data_categories: r.data_categories.clone(),
        remediation_steps: r.remediation_steps.clone(),
        notification_status: r.notification_status.clone(),
    }
}

fn wire_to_native_purpose(purpose: WireConsentPurpose) -> kimberlite_compliance::purpose::Purpose {
    use kimberlite_compliance::purpose::Purpose;
    match purpose {
        WireConsentPurpose::Marketing => Purpose::Marketing,
        WireConsentPurpose::Analytics => Purpose::Analytics,
        WireConsentPurpose::Contractual => Purpose::Contractual,
        WireConsentPurpose::LegalObligation => Purpose::LegalObligation,
        WireConsentPurpose::VitalInterests => Purpose::VitalInterests,
        WireConsentPurpose::PublicTask => Purpose::PublicTask,
        WireConsentPurpose::Research => Purpose::Research,
        WireConsentPurpose::Security => Purpose::Security,
        WireConsentPurpose::Treatment => Purpose::Treatment,
        WireConsentPurpose::Payment => Purpose::Payment,
        WireConsentPurpose::Operations => Purpose::Operations,
        WireConsentPurpose::PublicHealth => Purpose::PublicHealth,
        WireConsentPurpose::Emergency => Purpose::Emergency,
    }
}

fn native_to_wire_purpose(p: kimberlite_compliance::purpose::Purpose) -> WireConsentPurpose {
    use kimberlite_compliance::purpose::Purpose;
    match p {
        Purpose::Marketing => WireConsentPurpose::Marketing,
        Purpose::Analytics => WireConsentPurpose::Analytics,
        Purpose::Contractual => WireConsentPurpose::Contractual,
        Purpose::LegalObligation => WireConsentPurpose::LegalObligation,
        Purpose::VitalInterests => WireConsentPurpose::VitalInterests,
        Purpose::PublicTask => WireConsentPurpose::PublicTask,
        Purpose::Research => WireConsentPurpose::Research,
        Purpose::Security => WireConsentPurpose::Security,
        Purpose::Treatment => WireConsentPurpose::Treatment,
        Purpose::Payment => WireConsentPurpose::Payment,
        Purpose::Operations => WireConsentPurpose::Operations,
        Purpose::PublicHealth => WireConsentPurpose::PublicHealth,
        Purpose::Emergency => WireConsentPurpose::Emergency,
    }
}

fn native_to_wire_scope(s: kimberlite_compliance::consent::ConsentScope) -> WireConsentScope {
    use kimberlite_compliance::consent::ConsentScope as N;
    match s {
        N::AllData => WireConsentScope::AllData,
        N::ContactInfo => WireConsentScope::ContactInfo,
        N::AnalyticsOnly => WireConsentScope::AnalyticsOnly,
        N::ContractualNecessity => WireConsentScope::ContractualNecessity,
    }
}

fn wire_to_native_scope(s: WireConsentScope) -> kimberlite_compliance::consent::ConsentScope {
    use kimberlite_compliance::consent::ConsentScope as N;
    match s {
        WireConsentScope::AllData => N::AllData,
        WireConsentScope::ContactInfo => N::ContactInfo,
        WireConsentScope::AnalyticsOnly => N::AnalyticsOnly,
        WireConsentScope::ContractualNecessity => N::ContractualNecessity,
    }
}

fn wire_to_native_basis(b: &WireConsentBasis) -> kimberlite_compliance::consent::ConsentBasis {
    use kimberlite_compliance::consent::{ConsentBasis as NBasis, GdprArticle as NArt};
    use kimberlite_wire::GdprArticle as WArt;
    let article = match b.article {
        WArt::Consent => NArt::Consent,
        WArt::Contract => NArt::Contract,
        WArt::LegalObligation => NArt::LegalObligation,
        WArt::VitalInterests => NArt::VitalInterests,
        WArt::PublicTask => NArt::PublicTask,
        WArt::LegitimateInterests => NArt::LegitimateInterests,
    };
    NBasis {
        article,
        justification: b.justification.clone(),
    }
}

fn native_to_wire_basis(b: &kimberlite_compliance::consent::ConsentBasis) -> WireConsentBasis {
    use kimberlite_compliance::consent::GdprArticle as NArt;
    use kimberlite_wire::GdprArticle as WArt;
    let article = match b.article {
        NArt::Consent => WArt::Consent,
        NArt::Contract => WArt::Contract,
        NArt::LegalObligation => WArt::LegalObligation,
        NArt::VitalInterests => WArt::VitalInterests,
        NArt::PublicTask => WArt::PublicTask,
        NArt::LegitimateInterests => WArt::LegitimateInterests,
    };
    WireConsentBasis {
        article,
        justification: b.justification.clone(),
    }
}

/// Collapse a `ConsentBasis` into a short audit-log string.
/// `None` → `None`; `Some(basis)` → `"Consent"` or
/// `"Consent:<justification>"`.
fn basis_audit_label(basis: Option<&WireConsentBasis>) -> Option<String> {
    basis.map(|b| {
        let article = format!("{:?}", b.article);
        match &b.justification {
            Some(j) if !j.is_empty() => format!("{article}:{j}"),
            _ => article,
        }
    })
}

fn wire_to_native_exemption(
    basis: WireExemptionBasis,
) -> kimberlite_compliance::erasure::ExemptionBasis {
    use kimberlite_compliance::erasure::ExemptionBasis as E;
    match basis {
        WireExemptionBasis::LegalObligation => E::LegalObligation,
        WireExemptionBasis::PublicHealth => E::PublicHealth,
        WireExemptionBasis::Archiving => E::Archiving,
        WireExemptionBasis::LegalClaims => E::LegalClaims,
    }
}

fn native_to_wire_exemption(
    basis: kimberlite_compliance::erasure::ExemptionBasis,
) -> WireExemptionBasis {
    use kimberlite_compliance::erasure::ExemptionBasis as E;
    match basis {
        E::LegalObligation => WireExemptionBasis::LegalObligation,
        E::PublicHealth => WireExemptionBasis::PublicHealth,
        E::Archiving => WireExemptionBasis::Archiving,
        E::LegalClaims => WireExemptionBasis::LegalClaims,
    }
}

fn consent_record_to_wire(r: kimberlite_compliance::consent::ConsentRecord) -> WireConsentRecord {
    WireConsentRecord {
        consent_id: r.consent_id.to_string(),
        subject_id: r.subject_id,
        purpose: native_to_wire_purpose(r.purpose),
        scope: native_to_wire_scope(r.scope),
        granted_at_nanos: datetime_to_nanos(r.granted_at),
        withdrawn_at_nanos: r.withdrawn_at.map(datetime_to_nanos),
        expires_at_nanos: r.expires_at.map(datetime_to_nanos),
        notes: r.notes,
        basis: r.basis.as_ref().map(native_to_wire_basis),
        terms_version: r.terms_version,
        accepted: r.accepted,
    }
}

fn erasure_request_to_wire(
    r: &kimberlite_compliance::erasure::ErasureRequest,
) -> ErasureRequestInfo {
    ErasureRequestInfo {
        request_id: r.request_id.to_string(),
        subject_id: r.subject_id.clone(),
        requested_at_nanos: datetime_to_nanos(r.requested_at),
        deadline_nanos: datetime_to_nanos(r.deadline),
        status: erasure_status_to_wire(&r.status),
        records_erased: r.records_erased,
        streams_affected: r.affected_streams.clone(),
    }
}

fn erasure_status_to_wire(s: &kimberlite_compliance::erasure::ErasureStatus) -> ErasureStatusTag {
    use kimberlite_compliance::erasure::ErasureStatus;
    match s {
        ErasureStatus::Pending => ErasureStatusTag::Pending,
        ErasureStatus::InProgress { streams_remaining } => ErasureStatusTag::InProgress {
            streams_remaining: *streams_remaining as u32,
        },
        ErasureStatus::Complete {
            erased_at,
            total_records,
        } => ErasureStatusTag::Complete {
            erased_at_nanos: datetime_to_nanos(*erased_at),
            total_records: *total_records,
        },
        ErasureStatus::Failed { reason, retry_at } => ErasureStatusTag::Failed {
            reason: reason.clone(),
            retry_at_nanos: datetime_to_nanos(*retry_at),
        },
        ErasureStatus::Exempt { basis } => ErasureStatusTag::Exempt {
            basis: native_to_wire_exemption(*basis),
        },
    }
}

fn erasure_audit_to_wire(
    r: &kimberlite_compliance::erasure::ErasureAuditRecord,
) -> ErasureAuditInfo {
    ErasureAuditInfo {
        request_id: r.request_id.to_string(),
        subject_id: r.subject_id.clone(),
        requested_at_nanos: datetime_to_nanos(r.requested_at),
        completed_at_nanos: r.completed_at.map_or(0, datetime_to_nanos),
        records_erased: r.records_erased,
        streams_affected: r.streams_affected.clone(),
        erasure_proof_hex: r.erasure_proof.as_ref().map(hex_encode_hash),
    }
}

fn datetime_to_nanos(dt: chrono::DateTime<chrono::Utc>) -> u64 {
    let secs = dt.timestamp();
    let sub_nanos = u64::from(dt.timestamp_subsec_nanos());
    if secs < 0 {
        return 0;
    }
    let secs = secs as u64;
    secs.saturating_mul(1_000_000_000).saturating_add(sub_nanos)
}

fn hex_encode_hash(h: &kimberlite_types::Hash) -> String {
    h.as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn erasure_error_code(msg: &str) -> ErrorCode {
    if msg.contains("not found") {
        ErrorCode::ErasureNotFound
    } else if msg.contains("already complete") || msg.contains("already Complete") {
        ErrorCode::ErasureAlreadyComplete
    } else if msg.contains("Exempt") || msg.contains("exempt") {
        ErrorCode::ErasureExempt
    } else {
        ErrorCode::InternalError
    }
}

/// Translate the kernel's `MaskingStrategyKind` into the wire-stable
/// `MaskingStrategyWire`. v0.6.0 Tier 2 #7 — the wire shape survives
/// internal kernel enum changes, so this mapping is part of the
/// protocol contract.
fn kernel_strategy_to_wire(
    kind: &kimberlite_kernel::masking::MaskingStrategyKind,
) -> MaskingStrategyWire {
    use kimberlite_kernel::masking::{MaskingStrategyKind, RedactPatternKind};
    match kind {
        MaskingStrategyKind::Redact(pat) => {
            let (pattern, replacement) = match pat {
                RedactPatternKind::Ssn => ("SSN".to_string(), None),
                RedactPatternKind::Phone => ("PHONE".to_string(), None),
                RedactPatternKind::Email => ("EMAIL".to_string(), None),
                RedactPatternKind::CreditCard => ("CC".to_string(), None),
                RedactPatternKind::Custom { replacement } => {
                    ("CUSTOM".to_string(), Some(replacement.clone()))
                }
            };
            MaskingStrategyWire::Redact {
                pattern,
                replacement,
            }
        }
        MaskingStrategyKind::Hash => MaskingStrategyWire::Hash,
        MaskingStrategyKind::Tokenize => MaskingStrategyWire::Tokenize,
        MaskingStrategyKind::Truncate { max_chars } => MaskingStrategyWire::Truncate {
            max_chars: *max_chars as u64,
        },
        MaskingStrategyKind::Null => MaskingStrategyWire::Null,
    }
}
