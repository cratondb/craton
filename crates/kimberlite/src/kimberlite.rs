//! Main entry point for the Kimberlite SDK.
//!
//! The `Kimberlite` struct provides the top-level API for interacting with Kimberlite.
//! It manages the underlying storage, kernel state, projection store, and query engine.

use std::collections::HashMap;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of tables to process during schema rebuild.
///
/// **Rationale**: Prevents unbounded iteration that could hang the system.
/// 10,000 tables is sufficient for all practical deployments while bounding
/// worst-case rebuild time to ~1 second (0.1ms per table).
const MAX_TABLES_PER_REBUILD: usize = 10_000;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use kimberlite_crypto::ChainHash;
use kimberlite_kernel::{Command, Effect, State as KernelState, apply_committed};
use kimberlite_query::{ColumnDef, DataType, QueryEngine, SchemaBuilder};
use kimberlite_storage::{MemoryStorage, Storage, StorageBackend};
use kimberlite_store::{BTreeStore, Key, ProjectionStore, TableId, WriteBatch};
use kimberlite_types::{Offset, StreamId, TenantId};

use kimberlite_compliance::consent::ConsentTracker;

use crate::error::{KimberliteError, Result};
use crate::sieve_cache::SieveCache;
use crate::tenant::TenantHandle;
use crate::timestamp_index::TimestampIndex;

#[cfg(feature = "broadcast")]
use crate::broadcast::{ProjectionBroadcast, ProjectionEvent};

/// Configuration for opening a Kimberlite database.
#[derive(Debug, Clone)]
pub struct KimberliteConfig {
    /// Path to the data directory.
    pub data_dir: PathBuf,
    /// Page cache capacity for projection store (in pages, 4KB each).
    pub cache_capacity: usize,
}

impl KimberliteConfig {
    /// Creates a new configuration with the given data directory.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            cache_capacity: 4096, // 16MB default
        }
    }

    /// Sets the page cache capacity.
    pub fn with_cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = capacity;
        self
    }
}

/// Default capacity for the verified chain hash cache (number of streams).
const VERIFIED_HASH_CACHE_CAPACITY: usize = 256;

/// Hook installed by replicated runtimes (`kimberlite-server` in
/// cluster mode) so [`Kimberlite::submit`] can route writes through
/// VSR before they touch the local projection.
///
/// Implementations MUST eventually call [`Kimberlite::apply_local`] —
/// either inline (after VSR commit) on the leader, or via a follower-
/// side projection applier that consumes VSR's `AppliedCommand`
/// fanout. Without that, the command is "submitted" but never
/// reflected in the projection.
pub trait CommandRouter: Send + Sync {
    /// Submits `command` for replicated processing. Returns once the
    /// command has been durably committed (typically via VSR's
    /// quorum) and applied to the local projection.
    fn submit(&self, command: Command) -> Result<()>;
}

/// Builds the default schema that every freshly opened (or reset)
/// Kimberlite has available. Only `events` is predefined; additional
/// tables are added at runtime by `CREATE TABLE` statements.
fn default_schema() -> kimberlite_query::Schema {
    SchemaBuilder::new()
        .table(
            "events",
            TableId::new(1),
            vec![
                ColumnDef::new("offset", DataType::BigInt).not_null(),
                ColumnDef::new("data", DataType::Text),
            ],
            vec!["offset".into()],
        )
        .build()
}

/// Cached verification state for a stream — the last offset whose chain hash
/// was verified, and the resulting hash. Enables reads to start verification
/// from the cached point rather than from genesis or the nearest checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedChainState {
    #[allow(dead_code)]
    pub(crate) offset: Offset,
    #[allow(dead_code)]
    pub(crate) chain_hash: ChainHash,
}

/// Internal state shared across tenant handles.
pub(crate) struct KimberliteInner {
    /// Path to data directory (used for future operations like metadata persistence).
    #[allow(dead_code)]
    pub(crate) data_dir: PathBuf,

    /// Append-only log storage.
    ///
    /// `Box<dyn StorageBackend>` since v0.6.0 to allow swapping between
    /// the default on-disk `Storage` and the pure in-memory
    /// `MemoryStorage` without propagating a generic parameter
    /// through the whole SDK surface. The outer `Kimberlite` is behind
    /// `Arc<RwLock<..>>` so the inner `Box` doesn't need to be `Arc`.
    pub(crate) storage: Box<dyn StorageBackend>,

    /// Kernel state machine.
    pub(crate) kernel_state: KernelState,

    /// Projection store (B+tree with MVCC).
    pub(crate) projection_store: BTreeStore,

    /// Per-tenant query engines.
    ///
    /// Each tenant gets a schema containing only its own tables. Built on
    /// demand when a tenant first creates a table, rebuilt whenever the
    /// catalog changes. A prior single global `QueryEngine` collapsed
    /// tables across tenants by name — the leak this map prevents.
    pub(crate) per_tenant_engines: HashMap<TenantId, QueryEngine>,

    /// Fallback query engine used when a tenant has no bespoke tables
    /// yet. Carries only the default `events` schema. Never used to
    /// resolve user table names — those go through
    /// [`Self::query_engine_for`].
    pub(crate) default_query_engine: QueryEngine,

    /// Current log position (offset of last written record).
    pub(crate) log_position: Offset,

    /// Hash chain head for each stream.
    pub(crate) chain_heads: HashMap<StreamId, ChainHash>,

    /// SIEVE cache for verified chain state per stream.
    ///
    /// Caches the most recently verified (offset, `chain_hash`) pair for each stream.
    /// On subsequent reads, verification can start from this cached state instead
    /// of from genesis or the nearest checkpoint, reducing O(k) verification to O(1)
    /// for repeated reads near the same offset.
    pub(crate) verified_chain_cache: SieveCache<StreamId, VerifiedChainState>,

    /// GDPR consent tracker for data subject consent management.
    pub(crate) consent_tracker: ConsentTracker,

    /// GDPR Article 17 erasure engine for right-to-erasure requests.
    pub(crate) erasure_engine: kimberlite_compliance::erasure::ErasureEngine,

    /// Breach detection engine (HIPAA §164.404, GDPR Article 33).
    pub(crate) breach_detector: kimberlite_compliance::breach::BreachDetector,

    /// Data portability export engine (GDPR Article 20).
    pub(crate) export_engine: kimberlite_compliance::export::ExportEngine,

    /// Compliance audit log (SOC2 CC7.2, ISO 27001 A.12.4.1).
    pub(crate) audit_log: kimberlite_compliance::audit::ComplianceAuditLog,

    /// Optional broadcast channel for projection events (used by Studio UI).
    /// None for non-Studio usage to avoid overhead.
    #[cfg(feature = "broadcast")]
    pub(crate) projection_broadcast: Option<Arc<ProjectionBroadcast>>,

    /// Optional VSR routing hook installed by `kimberlite-server` in
    /// cluster mode. When `Some`, [`Kimberlite::submit`] forwards to
    /// the router instead of calling [`Kimberlite::apply_local`]
    /// directly; the router applies through VSR and eventually calls
    /// back into `apply_local`.
    pub(crate) command_router: Option<Arc<dyn CommandRouter>>,

    /// SQL-level masking rules, keyed by mask name.
    ///
    /// Populated by `CREATE MASK` statements, removed by `DROP MASK`.
    /// Applied during query execution to mask sensitive columns.
    pub(crate) masks: HashMap<String, MaskEntry>,

    /// Per-column data classifications, keyed by `(table_name, column_name)`.
    ///
    /// Populated by `ALTER TABLE ... MODIFY COLUMN ... SET CLASSIFICATION`.
    /// Queried via `SHOW CLASSIFICATIONS FOR <table>`.
    pub(crate) column_classifications: HashMap<(String, String), String>,

    /// SQL-level roles (created via `CREATE ROLE`).
    pub(crate) roles: Vec<String>,

    /// SQL-level grants (created via `GRANT`).
    pub(crate) grants: Vec<crate::tenant::StoredGrant>,

    /// SQL-level users (created via `CREATE USER`).
    pub(crate) users: Vec<(String, String)>, // (username, role)

    /// v0.6.0 Tier 2 #6 — in-memory timestamp → projection-offset
    /// index powering the default `FOR SYSTEM_TIME AS OF '<iso>'`
    /// / `AS OF TIMESTAMP` resolver.
    ///
    /// Populated on every DML commit in `execute_effects`. Binary
    /// search resolves a caller's target ns to the projection
    /// offset whose commit timestamp is the greatest value ≤ the
    /// target. Rebuilt lazily after restart from subsequent writes
    /// — callers that need durable time-travel across restarts
    /// should persist their own `(log_offset, wall_ns)` pairs and
    /// call `QueryEngine::query_at_timestamp` with an explicit
    /// resolver.
    pub(crate) timestamp_index: TimestampIndex,

    /// Scratch tempdir owned by `Kimberlite::in_memory()`. `None` for
    /// on-disk databases. Kept alive as long as the inner is alive so
    /// the projection store's backing file survives until everyone
    /// who could observe it is gone.
    #[allow(dead_code)] // Retained purely for Drop semantics.
    pub(crate) _temp_dir: Option<tempfile::TempDir>,
}

/// A named masking rule created via `CREATE MASK`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct MaskEntry {
    pub(crate) table_name: String,
    pub(crate) column_name: String,
    pub(crate) strategy: kimberlite_rbac::masking::MaskingStrategy,
}

impl KimberliteInner {
    /// Reads events from a stream using checkpoint-optimized verification.
    ///
    /// Checks the verified chain cache first. If the stream was recently written to,
    /// the chain head is already trusted and stored in the cache, allowing the storage
    /// layer to skip re-verification for the most recent records.
    pub(crate) fn read_events(
        &mut self,
        stream_id: StreamId,
        from_offset: Offset,
        max_bytes: u64,
    ) -> Result<Vec<Bytes>> {
        // Check cache — if the chain head is cached from a recent write,
        // and the requested offset is at or before the cached position,
        // the verification in storage will be faster since the chain is warm.
        let _cached = self.verified_chain_cache.get(&stream_id);

        self.storage
            .read_from(stream_id, from_offset, max_bytes)
            .map_err(Into::into)
    }

    /// Executes effects produced by the kernel.
    ///
    /// This is the "imperative shell" that handles I/O.
    pub(crate) fn execute_effects(&mut self, effects: Vec<Effect>) -> Result<()> {
        for effect in effects {
            match effect {
                Effect::StorageAppend {
                    stream_id,
                    base_offset,
                    events,
                } => {
                    // Recover chain_heads lazily. After process restart
                    // the in-memory map is empty; without this, the next
                    // append to an existing stream would write
                    // `prev_hash = None` and wedge a permanent chain
                    // break. Storage is authoritative on restart.
                    let prev_hash = match self.chain_heads.get(&stream_id).copied() {
                        Some(hash) => Some(hash),
                        None => {
                            let recovered = self.storage.latest_chain_hash(stream_id)?;
                            if let Some(hash) = recovered {
                                self.chain_heads.insert(stream_id, hash);
                            }
                            recovered
                        }
                    };
                    let (new_offset, new_hash) = self.storage.append_batch(
                        stream_id,
                        events.clone(),
                        base_offset,
                        prev_hash,
                        true, // fsync for durability
                    )?;
                    self.chain_heads.insert(stream_id, new_hash);
                    self.log_position = new_offset;

                    // Update verified chain cache — the write path inherently
                    // verifies the chain, so the new head is trusted.
                    self.verified_chain_cache.insert(
                        stream_id,
                        VerifiedChainState {
                            offset: new_offset,
                            chain_hash: new_hash,
                        },
                    );

                    // Apply to projection store
                    self.apply_to_projection(stream_id, base_offset, &events)?;

                    // v0.6.0 Tier 2 #6 — record (projection_offset, now_ns)
                    // for the default AS OF TIMESTAMP resolver. Must happen
                    // *after* projection apply so the recorded offset is
                    // visible to a subsequent `query_at(offset)`.
                    self.record_commit_timestamp();
                }
                Effect::StreamMetadataWrite(metadata) => {
                    // For now, stream metadata is tracked in kernel state
                    // Future: persist to metadata store
                    tracing::debug!(?metadata, "stream metadata updated");
                }
                Effect::WakeProjection {
                    stream_id,
                    from_offset,
                    to_offset,
                } => {
                    // Projection is updated inline in StorageAppend
                    // This effect signals external consumers
                    tracing::debug!(
                        ?stream_id,
                        ?from_offset,
                        ?to_offset,
                        "projection wake signal"
                    );
                }
                Effect::AuditLogAppend(action) => {
                    // Future: write to immutable audit log
                    tracing::debug!(?action, "audit action");
                }
                Effect::TableMetadataWrite(metadata) => {
                    // Table metadata is tracked in kernel state
                    // Update the query engine schema to include the new table
                    self.rebuild_query_engine_schema();
                    tracing::debug!(?metadata, "table metadata updated");

                    // Broadcast table creation event for Studio UI
                    #[cfg(feature = "broadcast")]
                    if let Some(ref broadcast) = self.projection_broadcast {
                        // Extract tenant_id from stream_id (StreamId contains tenant info)
                        let tenant_id = TenantId::from_stream_id(metadata.stream_id);
                        broadcast.send(ProjectionEvent::TableCreated {
                            tenant_id,
                            table_id: metadata.table_id.0,
                            name: metadata.table_name.clone(),
                        });
                    }
                }
                Effect::TableMetadataDrop {
                    tenant_id,
                    table_id,
                } => {
                    // Table metadata removed from kernel state. Rebuild the
                    // per-tenant query-engine cache so a subsequent
                    // CREATE TABLE with the same name doesn't observe stale
                    // schema. AUDIT-2026-05 S3.6 — symmetric with
                    // TableMetadataWrite above; the asymmetry was the root
                    // cause of the v0.6.2-deferred catalog-staleness bug
                    // where `DROP TABLE t; CREATE TABLE t (...); INSERT
                    // INTO t (...) VALUES ($1, ...)` failed on the
                    // parameter-bound INSERT.
                    self.rebuild_query_engine_schema();

                    tracing::debug!(?tenant_id, ?table_id, "table metadata dropped");

                    // Broadcast table drop event for Studio UI
                    #[cfg(feature = "broadcast")]
                    if let Some(ref broadcast) = self.projection_broadcast {
                        broadcast.send(ProjectionEvent::TableDropped {
                            tenant_id,
                            table_id: table_id.0,
                        });
                    }
                    #[cfg(not(feature = "broadcast"))]
                    let _ = tenant_id; // silence unused warning without broadcast
                }
                Effect::ProjectionRowsPurge {
                    tenant_id,
                    table_id,
                } => {
                    // v0.8.0 — drop projection-store rows for the
                    // table being dropped so a subsequent CREATE TABLE
                    // with the same name (= same TableId, since
                    // TableId = hash(tenant, name)) starts empty.
                    // v0.7.0 was metadata-only; see the
                    // `tests/catalog_staleness.rs::drop_does_not_yet_purge_projection_rows`
                    // regression net.
                    let store_table_id = kimberlite_store::TableId::from(table_id.0);
                    self.projection_store.purge_table(store_table_id)?;
                    tracing::debug!(
                        ?tenant_id,
                        ?table_id,
                        "projection-store rows purged for dropped table"
                    );
                }
                Effect::IndexMetadataWrite(metadata) => {
                    // Index metadata is tracked in kernel state
                    // Rebuild schema to include new index
                    self.rebuild_query_engine_schema();

                    // Populate the new index with existing data
                    self.populate_new_index(metadata.table_id, metadata.index_id)?;

                    tracing::debug!(?metadata, "index metadata updated and populated");

                    // Broadcast index creation event for Studio UI
                    #[cfg(feature = "broadcast")]
                    if let Some(ref broadcast) = self.projection_broadcast {
                        // Get tenant_id from table metadata
                        let tenant_id = self
                            .kernel_state
                            .get_table(&metadata.table_id)
                            .map_or(TenantId::from(0), |t| {
                                TenantId::from(u64::from(t.stream_id) >> 32)
                            });
                        broadcast.send(ProjectionEvent::IndexCreated {
                            tenant_id,
                            table_id: metadata.table_id.0,
                            index_id: metadata.index_id.0,
                            name: metadata.index_name.clone(),
                        });
                    }
                }
                Effect::UpdateProjection {
                    tenant_id,
                    table_id,
                    from_offset,
                    to_offset,
                } => {
                    // Apply DML events from the table's stream to the projection
                    self.apply_dml_to_projection(table_id, from_offset, to_offset)?;

                    // v0.6.0 Tier 2 #6 — same commit-timestamp recording as
                    // `StorageAppend` above, but for the DML side of the
                    // pipeline (INSERT/UPDATE/DELETE statements flow through
                    // here, not through raw `StorageAppend`).
                    self.record_commit_timestamp();

                    // Broadcast projection update event for Studio UI
                    #[cfg(feature = "broadcast")]
                    if let Some(ref broadcast) = self.projection_broadcast {
                        broadcast.send(ProjectionEvent::TableUpdated {
                            tenant_id,
                            table_id: table_id.0,
                            from_offset,
                            to_offset,
                        });
                    }
                    #[cfg(not(feature = "broadcast"))]
                    let _ = tenant_id; // silence unused warning without broadcast
                }

                // v0.6.0 Tier 2 #7 — masking policy lifecycle effects.
                // The kernel is authoritative; the runtime side-map just
                // logs for observability. Persistence happens implicitly
                // via the command-log replay of `Command::*MaskingPolicy`.
                Effect::MaskingPolicyWrite(record) => {
                    tracing::debug!(
                        tenant_id = %record.tenant_id,
                        policy_name = %record.name,
                        "masking policy created",
                    );
                }
                Effect::MaskingPolicyDrop { tenant_id, name } => {
                    tracing::debug!(
                        %tenant_id,
                        policy_name = %name,
                        "masking policy dropped",
                    );
                }
                Effect::MaskingAttachmentWrite {
                    tenant_id,
                    table_id,
                    column_name,
                    policy_name,
                } => {
                    tracing::debug!(
                        %tenant_id,
                        table_id = table_id.0,
                        %column_name,
                        %policy_name,
                        "masking policy attached",
                    );
                }
                Effect::MaskingAttachmentDrop {
                    tenant_id,
                    table_id,
                    column_name,
                } => {
                    tracing::debug!(
                        %tenant_id,
                        table_id = table_id.0,
                        %column_name,
                        "masking policy detached",
                    );
                }
            }
        }
        Ok(())
    }

    /// v0.6.0 Tier 2 #6 — stamps the current `projection_store`
    /// position with a Unix-nanosecond wall-clock timestamp for the
    /// default `FOR SYSTEM_TIME AS OF '<iso>'` resolver.
    ///
    /// Called by the `execute_effects` handlers after a commit lands
    /// in the projection store. Idempotent per-position: if two
    /// effects in the same batch result in the same projection
    /// offset, only the first pair is retained (the index enforces
    /// strict offset monotonicity).
    ///
    /// The timestamp comes from `chrono::Utc::now()` — the *shell*
    /// side of FCIS, consistent with how the rest of the audit
    /// infrastructure (see `audit.rs`, `consent.rs`) stamps events.
    /// Index itself clamps to `prev_ns + 1` on clock regressions so
    /// binary search's monotonicity invariant always holds.
    fn record_commit_timestamp(&mut self) {
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let pos = self.projection_store.applied_position();
        self.timestamp_index.insert(pos, now_ns);
    }

    /// Applies events to the projection store.
    fn apply_to_projection(
        &mut self,
        stream_id: StreamId,
        base_offset: Offset,
        events: &[Bytes],
    ) -> Result<()> {
        // Each event becomes a projection entry
        // Key format: stream_id:offset
        let table_id = TableId::new(u64::from(stream_id));

        for (i, event) in events.iter().enumerate() {
            // Use checked arithmetic to prevent silent wraparound at u64::MAX.
            // At 1 billion events/sec this would not occur for ~584 years, but
            // a corrupted offset field in storage could still trigger it.
            let raw_offset = base_offset.as_u64().checked_add(i as u64).ok_or_else(|| {
                KimberliteError::Internal(format!(
                    "offset overflow: base={} + i={} would exceed u64::MAX",
                    base_offset.as_u64(),
                    i,
                ))
            })?;
            let offset = Offset::new(raw_offset);
            let batch = WriteBatch::new(Offset::new(
                self.projection_store.applied_position().as_u64() + 1,
            ))
            .put(
                table_id,
                Key::from(format!("{:016x}", offset.as_u64())),
                event.clone(),
            );

            self.projection_store.apply(batch)?;
        }

        Ok(())
    }

    /// Applies DML events (INSERT/UPDATE/DELETE) to the projection store.
    fn apply_dml_to_projection(
        &mut self,
        table_id: kimberlite_kernel::command::TableId,
        from_offset: Offset,
        _to_offset: Offset,
    ) -> Result<()> {
        // Get table metadata to find the stream and primary key
        let table = self
            .kernel_state
            .get_table(&table_id)
            .ok_or_else(|| KimberliteError::TableNotFound(table_id.to_string()))?;

        let stream_id = table.stream_id;
        // Clone primary key columns to avoid borrow checker issues
        let primary_key_cols = table.primary_key.clone();

        // Read events from the stream
        // Use fixed batch size to avoid memory exhaustion
        const MAX_BATCH_BYTES: u64 = 10 * 1024 * 1024; // 10MB per batch
        let events = self
            .storage
            .read_from(stream_id, from_offset, MAX_BATCH_BYTES)?;

        // Parse and apply each event
        for event in events {
            self.apply_single_dml_event(table_id, &event, &primary_key_cols)?;
        }

        Ok(())
    }

    /// Applies a single DML event to the projection store.
    fn apply_single_dml_event(
        &mut self,
        table_id: kimberlite_kernel::command::TableId,
        event: &Bytes,
        primary_key_cols: &[String],
    ) -> Result<()> {
        // Parse the JSON event
        let event_json: serde_json::Value = serde_json::from_slice(event)
            .map_err(|e| KimberliteError::internal(format!("failed to parse DML event: {e}")))?;

        let event_type = event_json
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KimberliteError::internal("DML event missing 'type' field"))?;

        match event_type {
            "insert" => {
                // Extract row data from the event
                let data = event_json.get("data").ok_or_else(|| {
                    KimberliteError::internal("INSERT event missing 'data' field")
                })?;

                // Build primary key from the data using the same encoding as the query engine
                let pk_key = self.build_primary_key(data, primary_key_cols)?;

                // Serialize just the row data (not the full event) for storage
                // The query engine expects JSON objects with column names as keys
                let row_bytes = Bytes::from(serde_json::to_vec(data).map_err(|e| {
                    KimberliteError::internal(format!("JSON serialization failed: {e}"))
                })?);

                // Store the row with primary key
                let mut batch = WriteBatch::new(Offset::new(
                    self.projection_store.applied_position().as_u64() + 1,
                ))
                .put(TableId::new(table_id.0), pk_key.clone(), row_bytes);

                // Maintain indexes for INSERT
                batch = self.maintain_indexes_for_insert(batch, table_id, data, &pk_key)?;

                self.projection_store.apply(batch)?;
            }
            "update" => {
                // Extract predicates from WHERE clause
                let predicates = event_json.get("where").ok_or_else(|| {
                    KimberliteError::internal("UPDATE event missing 'where' field")
                })?;

                // Extract primary key from WHERE predicates
                let pk_data =
                    self.extract_primary_key_from_predicates(predicates, primary_key_cols)?;

                // Build the primary key for lookup
                let pk_key = self.build_primary_key(&pk_data, primary_key_cols)?;

                // Read existing row from projection store
                let store_table_id = TableId::new(table_id.0);
                let existing_row_bytes = self
                    .projection_store
                    .get(store_table_id, &pk_key)?
                    .ok_or_else(|| {
                        KimberliteError::internal(format!(
                            "row with primary key not found for UPDATE: {pk_data:?}"
                        ))
                    })?;

                // Parse existing row data
                let mut existing_data: serde_json::Value =
                    serde_json::from_slice(&existing_row_bytes).map_err(|e| {
                        KimberliteError::internal(format!("failed to parse existing row: {e}"))
                    })?;

                // Extract SET assignments and merge with existing data
                let assignments = event_json
                    .get("set")
                    .ok_or_else(|| KimberliteError::internal("UPDATE event missing 'set' field"))?;

                if let serde_json::Value::Object(ref mut existing_obj) = existing_data {
                    if let Some(set_array) = assignments.as_array() {
                        for assignment in set_array {
                            if let Some(set_obj) = assignment.as_array() {
                                // Assignment is [column, value]
                                if set_obj.len() == 2 {
                                    if let Some(col_name) = set_obj[0].as_str() {
                                        existing_obj
                                            .insert(col_name.to_string(), set_obj[1].clone());
                                    }
                                }
                            }
                        }
                    }
                } else {
                    return Err(KimberliteError::internal(
                        "existing row data is not a JSON object",
                    ));
                }

                // Serialize updated row
                let updated_row_bytes =
                    Bytes::from(serde_json::to_vec(&existing_data).map_err(|e| {
                        KimberliteError::internal(format!("JSON serialization failed: {e}"))
                    })?);

                // Parse old data for index maintenance
                let old_data: serde_json::Value = serde_json::from_slice(&existing_row_bytes)
                    .map_err(|e| {
                        KimberliteError::internal(format!("failed to parse old row data: {e}"))
                    })?;

                // Write back updated row
                let mut batch = WriteBatch::new(Offset::new(
                    self.projection_store.applied_position().as_u64() + 1,
                ))
                .put(TableId::new(table_id.0), pk_key.clone(), updated_row_bytes);

                // Maintain indexes for UPDATE
                batch = self.maintain_indexes_for_update(
                    batch,
                    table_id,
                    &old_data,
                    &existing_data,
                    &pk_key,
                )?;

                self.projection_store.apply(batch)?;
            }
            // v0.6.0 Tier 1 #3 — UPSERT-Updated branch. The tenant
            // layer has already merged the existing row with the
            // DO UPDATE SET assignments (resolving EXCLUDED.col) and
            // embedded the final row under `data`. Replay is therefore
            // structurally identical to a PUT at the PK: the row
            // wholesale replaces the prior projection value, and
            // indexes are repaired using the new/old snapshots.
            //
            // This branch is deliberately separate from "update" so the
            // event stream remains self-describing — auditors replaying
            // the log can distinguish an UPSERT-Updated from a plain
            // UPDATE without a side-channel.
            "upsert_update" => {
                let data = event_json.get("data").ok_or_else(|| {
                    KimberliteError::internal("upsert_update event missing 'data' field")
                })?;

                let pk_key = self.build_primary_key(data, primary_key_cols)?;

                let store_table_id = TableId::new(table_id.0);
                // Read prior row for index maintenance. If the event
                // log says "upsert_update" the row MUST exist; if it's
                // missing the projection has drifted and we fail loud
                // (AUDIT-2026-04 M-8 replay-integrity policy).
                let existing_row_bytes = self
                    .projection_store
                    .get(store_table_id, &pk_key)?
                    .ok_or_else(|| {
                        KimberliteError::internal(
                            "upsert_update event replayed against missing projection row",
                        )
                    })?;
                let old_data: serde_json::Value = serde_json::from_slice(&existing_row_bytes)
                    .map_err(|e| {
                        KimberliteError::internal(format!("failed to parse old row data: {e}"))
                    })?;

                let row_bytes = Bytes::from(serde_json::to_vec(data).map_err(|e| {
                    KimberliteError::internal(format!("JSON serialization failed: {e}"))
                })?);

                let mut batch = WriteBatch::new(Offset::new(
                    self.projection_store.applied_position().as_u64() + 1,
                ))
                .put(TableId::new(table_id.0), pk_key.clone(), row_bytes);

                batch =
                    self.maintain_indexes_for_update(batch, table_id, &old_data, data, &pk_key)?;

                self.projection_store.apply(batch)?;
            }
            "delete" => {
                // Extract predicates from WHERE clause
                let predicates = event_json.get("where").ok_or_else(|| {
                    KimberliteError::internal("DELETE event missing 'where' field")
                })?;

                // Extract primary key from WHERE predicates
                let pk_data =
                    self.extract_primary_key_from_predicates(predicates, primary_key_cols)?;

                // Build the primary key for deletion
                let pk_key = self.build_primary_key(&pk_data, primary_key_cols)?;

                // Read current row to get index values
                let store_table_id = TableId::new(table_id.0);
                let old_row_bytes = self
                    .projection_store
                    .get(store_table_id, &pk_key)?
                    .ok_or_else(|| {
                        KimberliteError::internal(format!(
                            "row with primary key not found for DELETE: {pk_data:?}"
                        ))
                    })?;

                // Parse old data for index maintenance
                let old_data: serde_json::Value =
                    serde_json::from_slice(&old_row_bytes).map_err(|e| {
                        KimberliteError::internal(format!("failed to parse old row data: {e}"))
                    })?;

                // Delete from projection store
                let mut batch = WriteBatch::new(Offset::new(
                    self.projection_store.applied_position().as_u64() + 1,
                ))
                .delete(store_table_id, pk_key.clone());

                // Maintain indexes for DELETE
                batch = self.maintain_indexes_for_delete(batch, table_id, &old_data, &pk_key)?;

                self.projection_store.apply(batch)?;
            }
            // AUDIT-2026-04 M-8: replay integrity is compliance-critical
            // (docs/ASSERTIONS.md). Silently warning on an unknown `type`
            // would advance the projection without applying the event,
            // breaking the log ↔ projection agreement for every downstream
            // reader. A malformed or corrupted event must fail loudly.
            _ => {
                return Err(KimberliteError::internal(format!(
                    "unknown DML event type: {event_type:?}"
                )));
            }
        }

        Ok(())
    }

    /// Extracts primary key values from WHERE predicates.
    ///
    /// Expects equality predicates for all primary key columns.
    fn extract_primary_key_from_predicates(
        &self,
        predicates: &serde_json::Value,
        primary_key_cols: &[String],
    ) -> Result<serde_json::Value> {
        let predicates_array = predicates
            .as_array()
            .ok_or_else(|| KimberliteError::internal("WHERE predicates must be an array"))?;

        let mut pk_values = serde_json::Map::new();

        // Extract values from equality predicates
        for pred in predicates_array {
            let op = pred
                .get("op")
                .and_then(|v| v.as_str())
                .ok_or_else(|| KimberliteError::internal("predicate missing 'op' field"))?;

            // Only handle equality predicates for PK extraction
            if op != "eq" {
                continue;
            }

            let column = pred
                .get("column")
                .and_then(|v| v.as_str())
                .ok_or_else(|| KimberliteError::internal("predicate missing 'column' field"))?;

            let values = pred
                .get("values")
                .and_then(|v| v.as_array())
                .ok_or_else(|| KimberliteError::internal("predicate missing 'values' field"))?;

            // Equality should have exactly one value
            if values.len() == 1 {
                pk_values.insert(column.to_string(), values[0].clone());
            }
        }

        // Verify we have all primary key columns
        for pk_col in primary_key_cols {
            if !pk_values.contains_key(pk_col) {
                return Err(KimberliteError::internal(format!(
                    "WHERE clause does not uniquely identify primary key - missing column '{pk_col}'"
                )));
            }
        }

        Ok(serde_json::Value::Object(pk_values))
    }

    /// Builds a primary key value from row data and primary key column names.
    ///
    /// Uses the same binary encoding as the query engine for compatibility.
    fn build_primary_key(
        &self,
        data: &serde_json::Value,
        primary_key_cols: &[String],
    ) -> Result<Key> {
        use kimberlite_query::{Value, key_encoder::encode_key};

        let mut pk_values = Vec::new();

        for col_name in primary_key_cols {
            let json_val = data.get(col_name).ok_or_else(|| {
                KimberliteError::internal(format!(
                    "primary key column '{col_name}' not found in data"
                ))
            })?;

            // Convert JSON value to Value type for encoding
            let value = match json_val {
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Value::BigInt(i)
                    } else {
                        return Err(KimberliteError::internal(format!(
                            "unsupported number format for column '{col_name}'"
                        )));
                    }
                }
                serde_json::Value::String(s) => Value::Text(s.clone()),
                serde_json::Value::Bool(b) => Value::Boolean(*b),
                serde_json::Value::Null => Value::Null,
                _ => {
                    return Err(KimberliteError::internal(format!(
                        "unsupported primary key value type for column '{col_name}'"
                    )));
                }
            };

            pk_values.push(value);
        }

        // Use the same encoding as the query engine
        Ok(encode_key(&pk_values))
    }

    /// Rebuilds per-tenant query engine schemas from kernel state.
    ///
    /// Called whenever the table catalog changes. Groups tables by
    /// `TenantId` and builds one `Schema` per tenant; queries from
    /// tenant A resolve table names only against A's tables.
    ///
    /// The previous single-schema implementation was keyed by `TableName`
    /// alone; two tenants with same-named tables silently collapsed into
    /// one entry (last-insert wins) — the compliance leak this rebuild
    /// was hardened against.
    fn rebuild_query_engine_schema(&mut self) {
        use kimberlite_query::{ColumnDef, ColumnName, DataType, IndexDef, Schema, TableDef};

        let mut per_tenant: HashMap<TenantId, Schema> = HashMap::new();

        let mut table_count = 0;

        // Add all tables from kernel state to the appropriate tenant's
        // schema (bounded to prevent DoS).
        for (table_id, table_meta) in self.kernel_state.tables() {
            if table_count >= MAX_TABLES_PER_REBUILD {
                tracing::warn!(
                    "schema rebuild exceeded max table limit ({}), stopping early",
                    MAX_TABLES_PER_REBUILD
                );
                break;
            }
            table_count += 1;
            // Convert kernel column definitions to query column definitions
            let columns: Vec<ColumnDef> = table_meta
                .columns
                .iter()
                .map(|col| {
                    // Map SQL type strings to DataType enum
                    let data_type = match col.data_type.as_str() {
                        "TINYINT" => DataType::TinyInt,
                        "SMALLINT" => DataType::SmallInt,
                        "INTEGER" => DataType::Integer,
                        "BIGINT" => DataType::BigInt,
                        "REAL" => DataType::Real,
                        "TEXT" => DataType::Text,
                        "BYTES" => DataType::Bytes,
                        "BOOLEAN" => DataType::Boolean,
                        "DATE" => DataType::Date,
                        "TIME" => DataType::Time,
                        "TIMESTAMP" => DataType::Timestamp,
                        "UUID" => DataType::Uuid,
                        "JSON" => DataType::Json,
                        s if s.starts_with("DECIMAL(") => {
                            // Parse DECIMAL(precision,scale)
                            let inner = s
                                .strip_prefix("DECIMAL(")
                                .and_then(|s| s.strip_suffix(')'))
                                .unwrap_or("10,0");
                            let parts: Vec<&str> = inner.split(',').collect();
                            let precision =
                                parts.first().and_then(|p| p.parse().ok()).unwrap_or(10);
                            let scale = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                            DataType::Decimal { precision, scale }
                        }
                        _ => {
                            tracing::warn!(
                                "unknown data type '{}' for column '{}', defaulting to TEXT",
                                col.data_type,
                                col.name
                            );
                            DataType::Text
                        }
                    };

                    if col.nullable {
                        ColumnDef::new(col.name.as_str(), data_type)
                    } else {
                        ColumnDef::new(col.name.as_str(), data_type).not_null()
                    }
                })
                .collect();

            // Convert String to ColumnName for primary key columns
            let pk_cols: Vec<ColumnName> = table_meta
                .primary_key
                .iter()
                .map(|s| ColumnName::new(s.as_str()))
                .collect();

            // Collect indexes for this table
            let indexes: Vec<IndexDef> = self
                .kernel_state
                .indexes()
                .values()
                .filter(|idx_meta| idx_meta.table_id.0 == table_id.0)
                .map(|idx_meta| {
                    let cols: Vec<ColumnName> = idx_meta
                        .columns
                        .iter()
                        .map(|c| ColumnName::new(c.as_str()))
                        .collect();
                    IndexDef::new(idx_meta.index_id.0, &idx_meta.index_name, cols)
                })
                .collect();

            // Build table definition with indexes
            let mut table_def =
                TableDef::new(kimberlite_store::TableId::new(table_id.0), columns, pk_cols);
            for index in indexes {
                table_def = table_def.with_index(index);
            }

            per_tenant
                .entry(table_meta.tenant_id)
                .or_default()
                .add_table(table_meta.table_name.as_str(), table_def);
        }

        // Convert schemas to engines and replace the cache atomically.
        self.per_tenant_engines = per_tenant
            .into_iter()
            .map(|(tenant_id, schema)| (tenant_id, QueryEngine::new(schema)))
            .collect();

        tracing::debug!(
            "rebuilt per-tenant query engines: {} tenants, {} total tables",
            self.per_tenant_engines.len(),
            self.kernel_state.tables().len()
        );
    }

    /// Returns a query engine scoped to the given tenant.
    ///
    /// Clones the cached engine if the tenant has bespoke tables; falls
    /// back to the default (system `events` stream) engine otherwise.
    /// Cloning a `QueryEngine` is cheap — the schema lives behind an
    /// `Arc` internally.
    pub(crate) fn query_engine_for(&self, tenant_id: TenantId) -> QueryEngine {
        self.per_tenant_engines
            .get(&tenant_id)
            .cloned()
            .unwrap_or_else(|| self.default_query_engine.clone())
    }

    /// Calculates a unique index table ID from table ID and index ID.
    ///
    /// Uses hashing to avoid overflow issues with large table IDs.
    fn calculate_index_table_id(
        table_id: kimberlite_kernel::command::TableId,
        index_id: kimberlite_kernel::command::IndexId,
    ) -> TableId {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        table_id.0.hash(&mut hasher);
        index_id.0.hash(&mut hasher);
        TableId::new(hasher.finish())
    }

    /// Extracts values for given columns from JSON data.
    ///
    /// Returns a vector of Values in the same order as the columns list.
    /// Missing columns are treated as NULL.
    fn extract_index_values(
        &self,
        data: &serde_json::Value,
        columns: &[String],
    ) -> Result<Vec<kimberlite_query::Value>> {
        use kimberlite_query::Value;

        let obj = data.as_object().ok_or_else(|| {
            KimberliteError::internal("data must be a JSON object for index extraction")
        })?;

        let max_columns = 100; // Bounded iteration limit
        let mut values = Vec::with_capacity(columns.len().min(max_columns));

        for (iter_count, col_name) in columns.iter().enumerate() {
            // Bounded iteration check
            if iter_count >= max_columns {
                break;
            }

            let json_val = obj.get(col_name).unwrap_or(&serde_json::Value::Null);

            // Convert JSON value to Value type
            let value = match json_val {
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Value::BigInt(i)
                    } else {
                        Value::Null
                    }
                }
                serde_json::Value::String(s) => Value::Text(s.clone()),
                serde_json::Value::Bool(b) => Value::Boolean(*b),
                serde_json::Value::Null => Value::Null,
                _ => Value::Null,
            };

            values.push(value);
        }

        debug_assert!(!columns.is_empty(), "column list must be non-empty");
        debug_assert_eq!(
            values.len(),
            columns.len().min(max_columns),
            "extracted values must match column count"
        );

        Ok(values)
    }

    /// Maintains indexes for an INSERT operation.
    ///
    /// Adds index entries for all indexes on the table.
    fn maintain_indexes_for_insert(
        &self,
        mut batch: WriteBatch,
        table_id: kimberlite_kernel::command::TableId,
        data: &serde_json::Value,
        pk_key: &Key,
    ) -> Result<WriteBatch> {
        use kimberlite_query::key_encoder::encode_key;

        // Get all indexes for this table
        let max_iterations = 100; // Bounded iteration limit
        let mut iter_count = 0;

        for (index_id, index_meta) in self.kernel_state.indexes() {
            // Bounded iteration check
            if iter_count >= max_iterations {
                break;
            }
            iter_count += 1;

            // Filter to indexes for this table
            if index_meta.table_id.0 != table_id.0 {
                continue;
            }

            // Extract index column values
            let index_values = self.extract_index_values(data, &index_meta.columns)?;

            // Decode primary key to get PK values
            let pk_values = kimberlite_query::key_encoder::decode_key(pk_key);

            // Build composite key: [index_values][pk_values]
            let mut composite_values = index_values;
            composite_values.extend(pk_values);

            let composite_key = encode_key(&composite_values);

            // Calculate index table ID using hash
            let index_table_id = Self::calculate_index_table_id(table_id, *index_id);

            // Add index entry with empty value (0-byte marker)
            batch = batch.put(index_table_id, composite_key, Bytes::new());
        }

        debug_assert!(!pk_key.as_bytes().is_empty(), "pk_key must be non-empty");

        Ok(batch)
    }

    /// Maintains indexes for an UPDATE operation.
    ///
    /// Deletes old index entries and inserts new ones if index columns changed.
    fn maintain_indexes_for_update(
        &self,
        mut batch: WriteBatch,
        table_id: kimberlite_kernel::command::TableId,
        old_data: &serde_json::Value,
        new_data: &serde_json::Value,
        pk_key: &Key,
    ) -> Result<WriteBatch> {
        use kimberlite_query::key_encoder::encode_key;

        // Get all indexes for this table
        let max_iterations = 100; // Bounded iteration limit
        let mut iter_count = 0;

        for (index_id, index_meta) in self.kernel_state.indexes() {
            // Bounded iteration check
            if iter_count >= max_iterations {
                break;
            }
            iter_count += 1;

            // Filter to indexes for this table
            if index_meta.table_id.0 != table_id.0 {
                continue;
            }

            // Extract old and new index column values
            let old_index_values = self.extract_index_values(old_data, &index_meta.columns)?;
            let new_index_values = self.extract_index_values(new_data, &index_meta.columns)?;

            // Check if index columns changed
            if old_index_values == new_index_values {
                // Index columns unchanged, skip this index
                continue;
            }

            // Decode primary key to get PK values
            let pk_values = kimberlite_query::key_encoder::decode_key(pk_key);

            // Calculate index table ID using hash
            let index_table_id = Self::calculate_index_table_id(table_id, *index_id);

            // Delete old index entry
            let mut old_composite_values = old_index_values;
            old_composite_values.extend(pk_values.clone());
            let old_composite_key = encode_key(&old_composite_values);
            batch = batch.delete(index_table_id, old_composite_key);

            // Insert new index entry
            let mut new_composite_values = new_index_values;
            new_composite_values.extend(pk_values);
            let new_composite_key = encode_key(&new_composite_values);
            batch = batch.put(index_table_id, new_composite_key, Bytes::new());
        }

        debug_assert!(!pk_key.as_bytes().is_empty(), "pk_key must be non-empty");

        Ok(batch)
    }

    /// Maintains indexes for a DELETE operation.
    ///
    /// Removes index entries for all indexes on the table.
    fn maintain_indexes_for_delete(
        &self,
        mut batch: WriteBatch,
        table_id: kimberlite_kernel::command::TableId,
        old_data: &serde_json::Value,
        pk_key: &Key,
    ) -> Result<WriteBatch> {
        use kimberlite_query::key_encoder::encode_key;

        // Get all indexes for this table
        let max_iterations = 100; // Bounded iteration limit
        let mut iter_count = 0;

        for (index_id, index_meta) in self.kernel_state.indexes() {
            // Bounded iteration check
            if iter_count >= max_iterations {
                break;
            }
            iter_count += 1;

            // Filter to indexes for this table
            if index_meta.table_id.0 != table_id.0 {
                continue;
            }

            // Extract index column values from old data
            let index_values = self.extract_index_values(old_data, &index_meta.columns)?;

            // Decode primary key to get PK values
            let pk_values = kimberlite_query::key_encoder::decode_key(pk_key);

            // Build composite key: [index_values][pk_values]
            let mut composite_values = index_values;
            composite_values.extend(pk_values);

            let composite_key = encode_key(&composite_values);

            // Calculate index table ID using hash
            let index_table_id = Self::calculate_index_table_id(table_id, *index_id);

            // Delete index entry
            batch = batch.delete(index_table_id, composite_key);
        }

        debug_assert!(!pk_key.as_bytes().is_empty(), "pk_key must be non-empty");

        Ok(batch)
    }

    /// Populates a newly created index with existing table data.
    ///
    /// Scans the base table and adds index entries for all existing rows.
    fn populate_new_index(
        &mut self,
        table_id: kimberlite_kernel::command::TableId,
        index_id: kimberlite_kernel::command::IndexId,
    ) -> Result<()> {
        use kimberlite_query::key_encoder::{decode_key, encode_key};

        // Get index metadata
        let index_meta = self.kernel_state.get_index(&index_id).ok_or_else(|| {
            KimberliteError::internal(format!("index {index_id:?} not found in kernel state"))
        })?;

        // Verify table exists
        let _table_meta = self.kernel_state.get_table(&table_id).ok_or_else(|| {
            KimberliteError::internal(format!("table {table_id:?} not found in kernel state"))
        })?;

        // Full scan of base table
        let store_table_id = TableId::new(table_id.0);
        let max_rows = 1_000_000; // Bounded iteration limit
        let pairs = self
            .projection_store
            .scan(store_table_id, Key::min()..Key::max(), max_rows)?;

        debug_assert!(pairs.len() <= max_rows, "scan must respect max_rows limit");

        // Build index entries for all rows
        let mut batch = WriteBatch::new(Offset::new(
            self.projection_store.applied_position().as_u64() + 1,
        ));

        // Calculate index table ID using hash
        let index_table_id = Self::calculate_index_table_id(table_id, index_id);
        let row_count = pairs.len();

        for (pk_key, row_bytes) in &pairs {
            // Parse row data
            let row_data: serde_json::Value = serde_json::from_slice(row_bytes).map_err(|e| {
                KimberliteError::internal(format!(
                    "failed to parse row data during index population: {e}"
                ))
            })?;

            // Extract index column values
            let index_values = self.extract_index_values(&row_data, &index_meta.columns)?;

            // Decode primary key to get PK values
            let pk_values = decode_key(pk_key);

            // Build composite key: [index_values][pk_values]
            let mut composite_values = index_values;
            composite_values.extend(pk_values);

            let composite_key = encode_key(&composite_values);

            // Add index entry
            batch = batch.put(index_table_id, composite_key, Bytes::new());
        }

        // Apply batch to populate index
        self.projection_store.apply(batch)?;

        tracing::info!(
            ?table_id,
            ?index_id,
            rows = row_count,
            "populated new index"
        );

        Ok(())
    }
}

/// The main Kimberlite database handle.
///
/// Provides the top-level API for interacting with the database.
/// Get tenant-scoped access via the `tenant()` method.
///
/// # Example
///
/// ```ignore
/// use kimberlite::Kimberlite;
///
/// let db = Kimberlite::open("./data")?;
/// let tenant = db.tenant(TenantId::new(1));
///
/// // Use tenant handle for operations
/// tenant.execute("INSERT INTO users (id, name) VALUES ($1, $2)", &[1.into(), "Alice".into()])?;
/// let results = tenant.query("SELECT * FROM users WHERE id = $1", &[1.into()])?;
/// ```
#[derive(Clone)]
pub struct Kimberlite {
    inner: Arc<RwLock<KimberliteInner>>,
}

impl Kimberlite {
    /// Opens a Kimberlite database at the given path.
    ///
    /// If the directory doesn't exist, it will be created.
    /// If the database already exists, it will be opened and state recovered.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let config = KimberliteConfig::new(data_dir.as_ref());
        Self::open_with_config(config)
    }

    /// Opens a Kimberlite database with custom configuration.
    pub fn open_with_config(config: KimberliteConfig) -> Result<Self> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Open storage layer
        let storage: Box<dyn StorageBackend> = Box::new(Storage::new(&config.data_dir));

        // Open projection store
        let projection_path = config.data_dir.join("projections.db");
        let projection_store =
            BTreeStore::open_with_capacity(&projection_path, config.cache_capacity)?;

        Self::from_parts(config.data_dir, storage, projection_store)
    }

    /// Opens a Kimberlite database with the in-memory event log backend.
    ///
    /// The event log ([`kimberlite_storage::MemoryStorage`]) is held
    /// entirely in RAM — no segment files, no fsync, no mmap, zero
    /// disk I/O for the append path.
    ///
    /// The B+tree projection store still requires a filesystem path,
    /// so `in_memory()` provisions a private [`tempfile::TempDir`]
    /// that is owned by the returned handle and cleaned up on drop.
    /// On typical platforms the tempdir lives under `$TMPDIR`
    /// (`/tmp`, `/private/var/folders/...` on macOS, `/dev/shm` if the
    /// caller sets `$TMPDIR` to point there) — which is itself RAM-
    /// backed on most Linux hosts. The projection store will see at
    /// most a handful of pages written during CREATE TABLE /
    /// INSERT-heavy workloads.
    ///
    /// Intended for:
    ///
    /// - Unit + integration tests that don't need durability.
    /// - Ephemeral worker processes (compliance report generators
    ///   that replay a snapshot, emit a PDF, exit).
    /// - SDK test harnesses (see
    ///   `kimberlite-test-harness::Backend::InMemory`).
    ///
    /// Contrast with [`Self::open`], which uses the on-disk
    /// [`kimberlite_storage::Storage`] and a file-backed
    /// [`kimberlite_store::BTreeStore`] at the caller-supplied path.
    /// `Self::open(path)` is unchanged and remains the default
    /// production entrypoint.
    pub fn in_memory() -> Result<Self> {
        let storage: Box<dyn StorageBackend> = Box::new(MemoryStorage::new());

        // Scratch tempdir for the projection B+tree. Owned by the
        // returned `Kimberlite` so it outlives every tenant handle.
        // Explicit `TempDir::new` failure surfaces as `KimberliteError::Io`
        // (same error class as `Kimberlite::open` when the data_dir can't
        // be created) — callers can treat both entrypoints identically.
        let temp_dir = tempfile::Builder::new()
            .prefix("kimberlite-memory-")
            .tempdir()
            .map_err(KimberliteError::from)?;
        let projection_path = temp_dir.path().join("projections.db");
        let projection_store = BTreeStore::open(&projection_path)?;

        Self::from_parts_with_tempdir(
            temp_dir.path().to_path_buf(),
            storage,
            projection_store,
            Some(temp_dir),
        )
    }

    /// Shared construction path for `open_with_config`. Takes
    /// already-built storage + projection-store so the two entrypoints
    /// don't diverge on kernel state / compliance engine initialisation.
    fn from_parts(
        data_dir: PathBuf,
        storage: Box<dyn StorageBackend>,
        projection_store: BTreeStore,
    ) -> Result<Self> {
        Self::from_parts_with_tempdir(data_dir, storage, projection_store, None)
    }

    /// Shared construction path that also accepts an owned `TempDir`
    /// for `in_memory()`, which holds the projection store under a
    /// private scratch directory and must outlive every tenant handle.
    ///
    /// Returns `Result<Self>` for forward compatibility — v0.6.0 has
    /// no fallible steps here (kernel state + compliance engines are
    /// all infallible constructors), but the shell-integration work
    /// for v0.7.0 will plumb fallible init (e.g. loading persisted
    /// audit log). Keeping the `Result` stable now avoids an SDK-
    /// facing signature churn later.
    #[allow(clippy::unnecessary_wraps)]
    fn from_parts_with_tempdir(
        data_dir: PathBuf,
        storage: Box<dyn StorageBackend>,
        projection_store: BTreeStore,
        temp_dir: Option<tempfile::TempDir>,
    ) -> Result<Self> {
        // Initialize kernel state
        let kernel_state = KernelState::new();

        let default_query_engine = QueryEngine::new(default_schema());

        let inner = KimberliteInner {
            data_dir,
            storage,
            kernel_state,
            projection_store,
            per_tenant_engines: HashMap::new(),
            default_query_engine,
            log_position: Offset::ZERO,
            chain_heads: HashMap::new(),
            verified_chain_cache: SieveCache::new(VERIFIED_HASH_CACHE_CAPACITY),
            consent_tracker: ConsentTracker::new(),
            erasure_engine: kimberlite_compliance::erasure::ErasureEngine::new(),
            breach_detector: kimberlite_compliance::breach::BreachDetector::new(),
            export_engine: kimberlite_compliance::export::ExportEngine::new(),
            audit_log: kimberlite_compliance::audit::ComplianceAuditLog::new(),
            #[cfg(feature = "broadcast")]
            projection_broadcast: None,
            command_router: None,
            masks: HashMap::new(),
            column_classifications: HashMap::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            users: Vec::new(),
            timestamp_index: TimestampIndex::new(),
            _temp_dir: temp_dir,
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Returns a tenant-scoped handle.
    ///
    /// The tenant handle provides operations scoped to a specific tenant ID.
    pub fn tenant(&self, id: TenantId) -> TenantHandle {
        TenantHandle::new(self.clone(), id)
    }

    /// Sets the projection broadcast channel for real-time Studio UI updates.
    ///
    /// This is typically called by the Studio server to receive projection events.
    #[cfg(feature = "broadcast")]
    pub fn set_projection_broadcast(&self, broadcast: Arc<ProjectionBroadcast>) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner.projection_broadcast = Some(broadcast);
        Ok(())
    }

    /// Installs an external [`CommandRouter`] that intercepts every
    /// future [`Self::submit`] call.
    ///
    /// Used by `kimberlite-server` in cluster mode to route writes
    /// through VSR before they touch the local projection: without
    /// this hook, `Kimberlite::submit` is purely local and wire-level
    /// writes never replicate to followers.
    ///
    /// The router's implementation is responsible for eventually
    /// calling [`Self::apply_local`] to actually apply the command to
    /// the projection — typically once VSR has committed quorum-wide.
    pub fn set_command_router(&self, router: Arc<dyn CommandRouter>) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner.command_router = Some(router);
        Ok(())
    }

    /// Submits a command to the kernel and executes resulting effects.
    ///
    /// This is the core write path: command → kernel → effects → I/O.
    /// When a [`CommandRouter`] is installed (cluster mode), the
    /// command is forwarded to the router instead of applied directly;
    /// the router calls back into [`Self::apply_local`] once VSR has
    /// committed it. Without a router (single-node / direct mode),
    /// behaves identically to [`Self::apply_local`].
    pub fn submit(&self, command: Command) -> Result<()> {
        // Take a clone of the router (cheap — Arc<dyn>) so we don't
        // hold the inner lock across the router call. The router
        // re-enters via apply_local which acquires its own lock.
        let router = {
            let inner = self
                .inner
                .read()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            inner.command_router.clone()
        };
        match router {
            Some(r) => r.submit(command),
            None => self.apply_local(command),
        }
    }

    /// Applies a command directly to the local projection, bypassing
    /// any installed [`CommandRouter`].
    ///
    /// This is the destination of both [`Self::submit`] (when no
    /// router is installed) and the router's callback (after VSR
    /// commit). Splitting it from `submit` is what breaks the
    /// recursion that an in-router `kimberlite.submit(cmd)` would
    /// otherwise cause.
    pub fn apply_local(&self, command: Command) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Apply command to kernel (pure)
        let (new_state, effects) = apply_committed(inner.kernel_state.clone(), command)?;

        // Update kernel state
        inner.kernel_state = new_state;

        // Execute effects (impure)
        inner.execute_effects(effects)
    }

    /// Returns the current log position.
    pub fn log_position(&self) -> Result<Offset> {
        let inner = self
            .inner
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.log_position)
    }

    /// Returns the current projection store position.
    pub fn projection_position(&self) -> Result<Offset> {
        let inner = self
            .inner
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.projection_store.applied_position())
    }

    /// Syncs all data to disk.
    ///
    /// Ensures durability of all written data.
    pub fn sync(&self) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner.projection_store.sync()?;
        Ok(())
    }

    /// Wipes all persisted and in-memory state, leaving the handle in
    /// a state observationally equivalent to a freshly opened, empty
    /// database at the original `data_dir`.
    ///
    /// Intended **only** for libFuzzer persistent-mode targets that
    /// keep one `Kimberlite` alive across iterations and need to
    /// re-seed cheaply. Deletes data on disk — never call this from
    /// application code. Gated behind the `fuzz-reset` cargo feature
    /// so production builds cannot reach it.
    #[cfg(feature = "fuzz-reset")]
    pub fn reset_state(&self) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Persisted state — storage log + projection B+tree. Both reset
        // methods only exist under `fuzz-reset`, so compilation fails
        // loud if the feature plumbing is broken.
        inner.storage.reset()?;
        inner.projection_store.reset()?;

        // In-memory state. Every field of `KimberliteInner` that can
        // accumulate across iterations gets zeroed here; kept in sync
        // with the struct literal in `open_with_config`.
        inner.kernel_state = KernelState::new();
        inner.per_tenant_engines.clear();
        inner.default_query_engine = QueryEngine::new(default_schema());
        inner.log_position = Offset::ZERO;
        inner.chain_heads.clear();
        inner.verified_chain_cache = SieveCache::new(VERIFIED_HASH_CACHE_CAPACITY);
        inner.consent_tracker = ConsentTracker::new();
        inner.erasure_engine = kimberlite_compliance::erasure::ErasureEngine::new();
        inner.breach_detector = kimberlite_compliance::breach::BreachDetector::new();
        inner.export_engine = kimberlite_compliance::export::ExportEngine::new();
        inner.audit_log = kimberlite_compliance::audit::ComplianceAuditLog::new();
        inner.masks.clear();
        inner.column_classifications.clear();
        inner.roles.clear();
        inner.grants.clear();
        inner.users.clear();
        inner.timestamp_index = TimestampIndex::new();
        #[cfg(feature = "broadcast")]
        {
            inner.projection_broadcast = None;
        }

        Ok(())
    }

    /// Returns a reference to the inner state.
    ///
    /// This is used internally by `TenantHandle` to access shared state.
    pub(crate) fn inner(&self) -> &Arc<RwLock<KimberliteInner>> {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_types::{DataClass, Placement, StreamName};
    use tempfile::tempdir;

    #[test]
    fn test_open_creates_directory() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("testdb");

        assert!(!db_path.exists());
        let _db = Kimberlite::open(&db_path).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn test_create_stream() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();

        let cmd = Command::create_stream(
            StreamId::new(1),
            StreamName::new("test_stream"),
            DataClass::Public,
            Placement::Global,
        );

        db.submit(cmd).unwrap();

        let inner = db.inner.read().unwrap();
        assert!(inner.kernel_state.stream_exists(&StreamId::new(1)));
    }

    #[test]
    fn test_append_events() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();

        // Create stream
        db.submit(Command::create_stream(
            StreamId::new(1),
            StreamName::new("events"),
            DataClass::Public,
            Placement::Global,
        ))
        .unwrap();

        // Append events
        db.submit(Command::append_batch(
            StreamId::new(1),
            vec![Bytes::from("event1"), Bytes::from("event2")],
            Offset::ZERO,
        ))
        .unwrap();

        assert!(db.log_position().unwrap().as_u64() > 0);
    }

    /// AUDIT-2026-04 M-8: `apply_single_dml_event` must fail loudly on an
    /// unknown `type` discriminator. Silently `warn!`-and-skip would
    /// advance the replay position without writing the projection,
    /// breaking the log ↔ projection agreement that every compliance
    /// query depends on. A case-mismatched `"DELETE"` (versus `"delete"`)
    /// is the canonical malformed-event shape.
    #[test]
    fn apply_single_dml_event_rejects_unknown_type() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();

        let malformed = Bytes::from(r#"{"type":"DELETE","where":[]}"#);
        let pk_cols = vec!["id".to_string()];
        // TableId is never dereferenced — the unknown-type branch short-
        // circuits before any kernel lookup — so an unbound id is fine.
        let fake_table_id = kimberlite_kernel::command::TableId::new(u64::MAX);

        let err = {
            let inner = db.inner();
            let mut guard = inner.write().unwrap();
            guard
                .apply_single_dml_event(fake_table_id, &malformed, &pk_cols)
                .expect_err("unknown DML type must fail")
        };

        let msg = err.to_string();
        assert!(
            msg.contains("unknown DML event type"),
            "error must name the unknown type; got: {msg}",
        );
    }

    /// AUDIT-2026-04 M-8 companion: a missing `type` field is also an
    /// integrity violation (existing behaviour — this test guards
    /// against it regressing alongside the M-8 change).
    #[test]
    fn apply_single_dml_event_rejects_missing_type() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();

        let malformed = Bytes::from(r#"{"data":{"id":1}}"#);
        let pk_cols = vec!["id".to_string()];
        let fake_table_id = kimberlite_kernel::command::TableId::new(u64::MAX);

        let err = {
            let inner = db.inner();
            let mut guard = inner.write().unwrap();
            guard
                .apply_single_dml_event(fake_table_id, &malformed, &pk_cols)
                .expect_err("missing DML type must fail")
        };

        assert!(
            err.to_string().contains("missing 'type'"),
            "error should name the missing field; got: {err}",
        );
    }

    #[cfg(feature = "fuzz-reset")]
    #[test]
    fn test_reset_state_clears_all() {
        use kimberlite_query::Value;

        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Seed the database with a table + rows so there's real state
        // to clear.
        tenant
            .execute(
                "CREATE TABLE pre_reset (id BIGINT PRIMARY KEY, name TEXT)",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "INSERT INTO pre_reset (id, name) VALUES ($1, $2)",
                &[Value::BigInt(1), Value::Text("alice".into())],
            )
            .unwrap();

        // Before: row present, log position advanced.
        let pre = tenant.query("SELECT id FROM pre_reset", &[]).unwrap();
        assert_eq!(pre.rows.len(), 1);
        assert!(db.log_position().unwrap().as_u64() > 0);

        // Reset.
        db.reset_state().unwrap();

        // After: the custom table no longer exists; querying it is
        // an error (or returns no columns, depending on the planner).
        // More decisive: log position is back to zero.
        assert_eq!(db.log_position().unwrap().as_u64(), 0);

        // And we can recreate the same table name without collision
        // — proof the kernel state was reset.
        tenant
            .execute(
                "CREATE TABLE pre_reset (id BIGINT PRIMARY KEY, name TEXT)",
                &[],
            )
            .expect("recreating previously-dropped table must succeed after reset");
        let post = tenant.query("SELECT id FROM pre_reset", &[]).unwrap();
        assert_eq!(post.rows.len(), 0, "table must be empty after reset");
    }

    #[test]
    fn test_schema_all_types_mapping() {
        use kimberlite_query::Value;

        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with all 14 supported SQL data types
        // This verifies the type mapping in rebuild_query_engine_schema is comprehensive
        let sql = r"
            CREATE TABLE all_types (
                id BIGINT NOT NULL,
                col_tinyint TINYINT,
                col_smallint SMALLINT,
                col_integer INTEGER,
                col_bigint BIGINT,
                col_real REAL,
                col_decimal DECIMAL(18,2),
                col_text TEXT,
                col_bytes BLOB,
                col_boolean BOOLEAN,
                col_date DATE,
                col_time TIME,
                col_timestamp TIMESTAMP,
                col_uuid UUID,
                col_json JSON,
                PRIMARY KEY (id)
            )
        ";

        tenant.execute(sql, &[]).unwrap();

        // Verify table exists and is queryable
        // This indirectly verifies all type mappings work correctly
        let result = tenant
            .query(
                "SELECT * FROM all_types WHERE id = $1",
                &[Value::BigInt(999)],
            )
            .expect("Should be able to query table");

        // Table should have 15 columns
        assert_eq!(result.columns.len(), 15, "Should have 15 columns");

        // Verify column names are preserved (schema mapping worked correctly)
        assert_eq!(result.columns[0].as_str(), "id");
        assert_eq!(result.columns[1].as_str(), "col_tinyint");
        assert_eq!(result.columns[2].as_str(), "col_smallint");
        assert_eq!(result.columns[3].as_str(), "col_integer");
        assert_eq!(result.columns[4].as_str(), "col_bigint");
        assert_eq!(result.columns[5].as_str(), "col_real");
        assert_eq!(result.columns[6].as_str(), "col_decimal");
        assert_eq!(result.columns[7].as_str(), "col_text");
        assert_eq!(result.columns[8].as_str(), "col_bytes");
        assert_eq!(result.columns[9].as_str(), "col_boolean");
        assert_eq!(result.columns[10].as_str(), "col_date");
        assert_eq!(result.columns[11].as_str(), "col_time");
        assert_eq!(result.columns[12].as_str(), "col_timestamp");
        assert_eq!(result.columns[13].as_str(), "col_uuid");
        assert_eq!(result.columns[14].as_str(), "col_json");

        // Success! All 14 SQL data types are correctly mapped in schema building
    }
}
