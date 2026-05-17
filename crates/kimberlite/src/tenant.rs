//! Tenant-scoped handle for database operations.
//!
//! A `TenantHandle` provides operations scoped to a specific tenant ID.
//! All data isolation and access control is handled at this layer.

use bytes::Bytes;
use kimberlite_kernel::Command;
use kimberlite_kernel::command::{ColumnDefinition, IndexId, TableId};
use kimberlite_query::{
    ColumnName, OnConflictAction, ParsedAlterTable, ParsedCreateIndex, ParsedCreateTable,
    ParsedDelete, ParsedInsert, ParsedUpdate, QueryResult, UpsertExpr, Value,
    key_encoder::encode_key,
};
use kimberlite_store::ProjectionStore;
use kimberlite_types::{DataClass, Offset, Placement, StreamId, StreamName, TenantId};
use serde_json::json;

use crate::error::{KimberliteError, Result};
use crate::kimberlite::Kimberlite;

/// A stored GRANT entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StoredGrant {
    /// Granted columns (None = all).
    pub columns: Option<Vec<String>>,
    /// Table name.
    pub table_name: String,
    /// Role name.
    pub role_name: String,
}

/// Result of executing a DDL/DML statement.
#[derive(Debug, Clone)]
pub enum ExecuteResult {
    /// Standard DML result (rows affected, log offset)
    Standard {
        rows_affected: u64,
        log_offset: Offset,
    },
    /// DML with RETURNING clause (includes returned rows)
    WithReturning {
        rows_affected: u64,
        log_offset: Offset,
        returned: QueryResult,
    },
}

/// Snapshot of a masking-policy definition plus its attachment count.
///
/// Returned by [`TenantHandle::masking_policy_snapshot`]. The strategy
/// and role-guard are kernel-native types (`MaskingStrategyKind`,
/// `RoleGuard`) so callers that want typed access — the Rust client,
/// server handler, in-process embedders — avoid a stringly-typed round
/// trip through the wire layer. The RPC path translates to
/// `kimberlite_wire::MaskingPolicyInfo` at the boundary.
#[derive(Debug, Clone)]
pub struct MaskingPolicySummary {
    /// Policy name, unique per tenant.
    pub name: String,
    /// The decomposed masking strategy.
    pub strategy: kimberlite_kernel::masking::MaskingStrategyKind,
    /// Role guard (exempt roles + default-masked flag).
    pub role_guard: kimberlite_kernel::masking::RoleGuard,
    /// Number of `(table, column)` pairs this policy is attached to.
    pub attachment_count: u32,
}

/// Snapshot of a single masking-policy attachment.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)] // three distinct SQL identifiers
pub struct MaskingAttachmentSummary {
    /// Owning table name.
    pub table_name: String,
    /// Attached column name.
    pub column_name: String,
    /// Name of the attached policy.
    pub policy_name: String,
}

impl ExecuteResult {
    /// Get the number of rows affected by the operation.
    pub fn rows_affected(&self) -> u64 {
        match self {
            ExecuteResult::Standard { rows_affected, .. } => *rows_affected,
            ExecuteResult::WithReturning { rows_affected, .. } => *rows_affected,
        }
    }

    /// Get the log offset of the operation.
    pub fn log_offset(&self) -> Offset {
        match self {
            ExecuteResult::Standard { log_offset, .. } => *log_offset,
            ExecuteResult::WithReturning { log_offset, .. } => *log_offset,
        }
    }

    /// Get the returned rows, if this is a `WithReturning` result.
    pub fn returned(&self) -> Option<&QueryResult> {
        match self {
            ExecuteResult::Standard { .. } => None,
            ExecuteResult::WithReturning { returned, .. } => Some(returned),
        }
    }
}

/// Controls whether consent validation is enforced for data operations.
///
/// # Variants
///
/// - `Required` — Operations on personal data require valid consent (default).
///   `append_with_consent()` and `query_with_consent()` will fail if
///   no consent exists.
/// - `Optional` — Consent is checked but operations proceed with a warning
///   if consent is missing.
/// - `Disabled` — No consent checks are performed. Use the
///   standard `append()`/`query()` methods directly when consent is
///   not applicable (e.g., non-personal data).
///
/// # Privacy by Default (GDPR Article 25)
///
/// The default is `Required` to ensure compliance with GDPR's "data protection
/// by design and by default" principle. For non-personal data or specific use
/// cases where consent is not applicable, explicitly set mode to `Disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsentMode {
    /// Consent must be validated before processing personal data (default).
    #[default]
    Required,
    /// Consent is checked but missing consent only logs a warning.
    Optional,
    /// No consent enforcement.
    Disabled,
}

/// A tenant-scoped handle for database operations.
///
/// All operations through this handle are scoped to the tenant ID
/// specified when creating the handle.
///
/// # Example
///
/// ```ignore
/// let db = Kimberlite::open("./data")?;
/// let tenant = db.tenant(TenantId::new(1));
///
/// // Create a stream for this tenant
/// tenant.create_stream("orders", DataClass::Public)?;
///
/// // Append events
/// tenant.append("orders", vec![b"order_created".to_vec()], Offset::ZERO)?;
///
/// // Query data
/// let results = tenant.query("SELECT * FROM events LIMIT 10", &[])?;
/// ```
#[derive(Clone)]
pub struct TenantHandle {
    db: Kimberlite,
    tenant_id: TenantId,
    consent_mode: ConsentMode,
}

impl TenantHandle {
    /// Creates a new tenant handle.
    ///
    /// The default consent mode is `Required` to ensure compliance with GDPR
    /// Article 25 (data protection by default). Use `.with_consent_mode()`
    /// to change the mode if needed.
    pub(crate) fn new(db: Kimberlite, tenant_id: TenantId) -> Self {
        Self {
            db,
            tenant_id,
            consent_mode: ConsentMode::Required,
        }
    }

    /// Returns the tenant ID for this handle.
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Sets the consent enforcement mode for this handle.
    ///
    /// - `ConsentMode::Required` — operations on personal data will fail
    ///   without valid consent.
    /// - `ConsentMode::Optional` — missing consent logs a warning but
    ///   allows the operation.
    /// - `ConsentMode::Disabled` — no consent checks (default).
    pub fn with_consent_mode(mut self, mode: ConsentMode) -> Self {
        self.consent_mode = mode;
        self
    }

    /// Returns the current consent mode.
    pub fn consent_mode(&self) -> ConsentMode {
        self.consent_mode
    }

    /// Creates a new stream for this tenant.
    ///
    /// # Arguments
    ///
    /// * `name` - Stream name (must be unique within the tenant)
    /// * `data_class` - Data classification (`PHI`, `NonPHI`, etc.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// tenant.create_stream("audit_log", DataClass::PHI)?;
    /// ```
    pub fn create_stream(
        &self,
        name: impl Into<String>,
        data_class: DataClass,
    ) -> Result<StreamId> {
        let stream_name = StreamName::new(name);

        // Idempotent by stream_name: if a stream with this name already
        // exists for this tenant, return its id. This makes application-level
        // bootstrap code (`ensureStream` / projection-table setup / repo
        // constructors) safe to call on every cold start without an
        // external "already created" log.
        //
        // Also allocates a fresh local_id for genuinely new streams by
        // scanning for the next unused slot in this tenant's 32-bit space.
        // The prior implementation hard-coded `local_id=1`, which meant
        // the *second* stream per tenant collided unconditionally — every
        // multi-stream-per-tenant app (notebar has ~10 of them) tripped it.
        {
            let inner = self
                .db
                .inner()
                .read()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            for (id, meta) in inner.kernel_state.streams().iter() {
                if id.tenant_id() == self.tenant_id && meta.stream_name == stream_name {
                    return Ok(*id);
                }
            }
            drop(inner);
        }

        let stream_id = self.allocate_local_stream_id()?;

        self.db.submit(Command::create_stream(
            stream_id,
            stream_name,
            data_class,
            Placement::Global,
        ))?;

        Ok(stream_id)
    }

    /// Allocate the next unused local_id in this tenant's 32-bit namespace.
    ///
    /// Linear scan is O(S) in the per-tenant stream count which is bounded
    /// at small clinic sizes (a Notebar tenant has ~10 streams — patient,
    /// appointment, clinical_note, invoice, etc.). A proper counter on
    /// `State` is the eventual home; keeping this local avoids a wire
    /// format change until that work is scheduled.
    fn allocate_local_stream_id(&self) -> Result<StreamId> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let mut max_local: u32 = 0;
        for (id, _) in inner.kernel_state.streams().iter() {
            if id.tenant_id() == self.tenant_id {
                let local = id.local_id();
                if local > max_local {
                    max_local = local;
                }
            }
        }
        drop(inner);
        let next = max_local
            .checked_add(1)
            .ok_or_else(|| KimberliteError::internal("tenant stream-id space exhausted"))?;
        Ok(StreamId::from_tenant_and_local(self.tenant_id, next))
    }

    /// Creates a stream with automatic ID allocation.
    pub fn create_stream_auto(&self, name: impl Into<String>, data_class: DataClass) -> Result<()> {
        let stream_name = StreamName::new(name);

        self.db.submit(Command::create_stream_with_auto_id(
            stream_name,
            data_class,
            Placement::Global,
        ))
    }

    /// Appends events to a stream with optimistic concurrency control.
    ///
    /// The caller must provide the expected current offset of the stream.
    /// If another writer has appended since the caller last read the offset,
    /// the kernel will return `KernelError::UnexpectedStreamOffset`.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to append to
    /// * `events` - Events to append
    /// * `expected_offset` - The offset the caller expects the stream to be at
    ///
    /// # Returns
    ///
    /// Returns the offset of the first appended event.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let events = vec![
    ///     b"event1".to_vec(),
    ///     b"event2".to_vec(),
    /// ];
    /// let offset = tenant.append(stream_id, events, Offset::ZERO)?;
    /// ```
    pub fn append(
        &self,
        stream_id: StreamId,
        events: Vec<Vec<u8>>,
        expected_offset: Offset,
    ) -> Result<Offset> {
        let events: Vec<Bytes> = events.into_iter().map(Bytes::from).collect();

        self.db
            .submit(Command::append_batch(stream_id, events, expected_offset))?;

        Ok(expected_offset)
    }

    /// Executes a write operation via SQL.
    ///
    /// Note: In Kimberlite, writes go through the append-only log.
    /// SQL writes are translated to stream appends.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL statement (INSERT, UPDATE, DELETE, CREATE TABLE, etc.)
    /// * `params` - Query parameters
    ///
    /// # Example
    ///
    /// ```ignore
    /// tenant.execute(
    ///     "INSERT INTO users (id, name) VALUES ($1, $2)",
    ///     &[Value::BigInt(1), Value::Text("Alice".into())],
    /// )?;
    /// ```
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<ExecuteResult> {
        use kimberlite_query::{ParsedStatement, parse_statement};

        // Parse the SQL statement
        let parsed = parse_statement(sql)?;

        match parsed {
            ParsedStatement::Select(_) | ParsedStatement::Union(_) => {
                // SELECT/UNION goes through query path, not execute
                Err(KimberliteError::Query(
                    kimberlite_query::QueryError::UnsupportedFeature(
                        "use query() for SELECT/UNION statements".to_string(),
                    ),
                ))
            }

            ParsedStatement::CreateTable(create_table) => {
                let name = create_table.table_name.clone();
                let result = self.execute_create_table(create_table)?;
                if !name.starts_with("_kimberlite_") {
                    self.audit_log("CREATE", &name, None);
                }
                Ok(result)
            }

            ParsedStatement::DropTable { name, if_exists } => {
                self.execute_drop_table(&name, if_exists)
            }

            ParsedStatement::AlterTable(alter_table) => self.execute_alter_table(alter_table),

            ParsedStatement::CreateIndex(create_index) => self.execute_create_index(create_index),

            ParsedStatement::Insert(ref insert) => {
                // v0.6.0 Tier 1 #3 — `INSERT ... ON CONFLICT` routes to
                // the atomic upsert path; plain INSERT keeps the
                // existing code path untouched so upgrade risk is zero.
                if insert.on_conflict.is_some() {
                    self.execute_upsert(insert.clone(), params)
                } else {
                    self.execute_insert(insert.clone(), params)
                }
            }

            ParsedStatement::Update(ref update) => self.execute_update(update.clone(), params),

            ParsedStatement::Delete(ref delete) => self.execute_delete(delete.clone(), params),

            ParsedStatement::CreateMask(create_mask) => self.execute_create_mask(create_mask),

            ParsedStatement::DropMask(mask_name) => self.execute_drop_mask(&mask_name),

            ParsedStatement::CreateMaskingPolicy(policy) => {
                self.execute_create_masking_policy(policy)
            }

            ParsedStatement::DropMaskingPolicy(name) => self.execute_drop_masking_policy(&name),

            ParsedStatement::AttachMaskingPolicy(attach) => {
                self.execute_attach_masking_policy(attach)
            }

            ParsedStatement::DetachMaskingPolicy(detach) => {
                self.execute_detach_masking_policy(detach)
            }

            ParsedStatement::SetClassification(set_class) => {
                self.execute_set_classification(set_class)
            }

            ParsedStatement::ShowClassifications(_)
            | ParsedStatement::ShowTables
            | ParsedStatement::ShowColumns(_) => Err(KimberliteError::Query(
                kimberlite_query::QueryError::UnsupportedFeature(
                    "use query() for SHOW statements".to_string(),
                ),
            )),

            ParsedStatement::CreateRole(role_name) => self.execute_create_role(&role_name),

            ParsedStatement::Grant(grant) => self.execute_grant(grant),

            ParsedStatement::CreateUser(create_user) => self.execute_create_user(create_user),
        }
    }

    /// Executes a SQL query against the current state.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL SELECT statement
    /// * `params` - Query parameters
    ///
    /// # Returns
    ///
    /// Query results as rows.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let results = tenant.query(
    ///     "SELECT * FROM events WHERE offset > $1 LIMIT 10",
    ///     &[Value::BigInt(100)],
    /// )?;
    /// for row in results.rows() {
    ///     println!("{:?}", row);
    /// }
    /// ```
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        // v0.6.0 Tier 2 #6 — extract AT OFFSET or FOR SYSTEM_TIME AS OF /
        // AS OF TIMESTAMP before any other dispatch. Offset syntax goes
        // through `query_at` for position-ahead validation; timestamp
        // syntax goes through `query_at_timestamp` with the runtime's
        // in-memory timestamp index as the resolver.
        let (cleaned_sql, time_travel) = kimberlite_query::extract_time_travel(sql);
        match time_travel {
            Some(kimberlite_query::TimeTravel::Offset(o)) => {
                return self.query_at(&cleaned_sql, params, Offset::new(o));
            }
            Some(kimberlite_query::TimeTravel::TimestampNs(ns)) => {
                return self.query_at_timestamp(&cleaned_sql, params, ns);
            }
            None => {}
        }

        // Pre-parse to check for custom statements that return result sets.
        if let Ok(Some(parsed)) = kimberlite_query::try_parse_custom_statement(sql) {
            match parsed {
                kimberlite_query::ParsedStatement::ShowClassifications(table_name) => {
                    return self.execute_show_classifications(&table_name);
                }
                kimberlite_query::ParsedStatement::ShowTables => {
                    return self.execute_show_tables();
                }
                kimberlite_query::ParsedStatement::ShowColumns(table_name) => {
                    return self.execute_show_columns(&table_name);
                }
                _ => {}
            }
        }

        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Pick the engine scoped to this tenant. Cloning is cheap — the
        // inner schema is reference-counted — and sidesteps the borrow
        // checker around the mutable projection_store.
        let engine = inner.query_engine_for(self.tenant_id);
        let mut result = engine.query(&mut inner.projection_store, sql, params)?;

        // Apply SQL-level masks (from CREATE MASK statements).
        //
        // AUDIT-2026-04 M-7: pass `sql` so the masker can resolve output
        // aliases back to their source columns. `SELECT ssn AS id FROM
        // patients` keeps the `ssn` mask applied under its alias.
        if !inner.masks.is_empty() {
            apply_sql_masks(&mut result, &inner.masks, sql);
        }

        Ok(result)
    }

    /// Executes a SQL query at a specific log position (point-in-time query).
    ///
    /// This is essential for compliance: query the state as it was at a
    /// specific point in the log.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL SELECT statement
    /// * `params` - Query parameters
    /// * `position` - Log position to query at
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get state as of log position 1000
    /// let results = tenant.query_at(
    ///     "SELECT * FROM users WHERE id = $1",
    ///     &[Value::BigInt(42)],
    ///     Offset::new(1000),
    /// )?;
    /// ```
    pub fn query_at(&self, sql: &str, params: &[Value], position: Offset) -> Result<QueryResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Validate position is not ahead of current
        let current_pos =
            kimberlite_store::ProjectionStore::applied_position(&inner.projection_store);
        if position > current_pos {
            return Err(KimberliteError::PositionAhead {
                requested: position,
                current: current_pos,
            });
        }

        // Tenant-scoped engine. See `query` above.
        let engine = inner.query_engine_for(self.tenant_id);
        let result = engine.query_at(&mut inner.projection_store, sql, params, position)?;

        Ok(result)
    }

    /// Executes a SQL query at a specific wall-clock instant.
    ///
    /// v0.6.0 Tier 2 #6 — the runtime-layer landing for `FOR
    /// SYSTEM_TIME AS OF '<iso>'` / `AS OF TIMESTAMP '<iso>'`. Resolves
    /// `target_ns` (Unix-nanosecond UTC) to a projection offset using
    /// the runtime's in-memory timestamp index and dispatches through
    /// `query_at`.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL SELECT statement (inline `FOR SYSTEM_TIME AS OF`
    ///   clause is allowed but redundant — the clause is stripped and
    ///   re-applied via `target_ns`).
    /// * `params` - Query parameters
    /// * `target_ns` - Unix-nanosecond UTC timestamp to query at.
    ///
    /// # Errors
    ///
    /// - [`kimberlite_query::QueryError::AsOfBeforeRetentionHorizon`]
    ///   when `target_ns` is older than the earliest retained event.
    /// - [`kimberlite_query::QueryError::UnsupportedFeature`] when the
    ///   log has no entries yet (freshly opened DB).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // "What did patient 42 look like at 2026-01-15T00:00:00Z?"
    /// let target_ns = chrono::DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
    ///     .unwrap()
    ///     .timestamp_nanos_opt()
    ///     .unwrap();
    /// let results = tenant.query_at_timestamp(
    ///     "SELECT * FROM patients WHERE id = $1",
    ///     &[Value::BigInt(42)],
    ///     target_ns,
    /// )?;
    /// ```
    pub fn query_at_timestamp(
        &self,
        sql: &str,
        params: &[Value],
        target_ns: i64,
    ) -> Result<QueryResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Resolve against the in-memory index up-front, before handing
        // off to the query engine. We need to hold the write lock
        // across both the lookup and the query_at call so concurrent
        // writes can't race a new commit into the index between the
        // two.
        let resolution = inner.timestamp_index.resolve(target_ns);
        // Snapshot the tenant-scoped engine after the resolver runs —
        // query_at_timestamp_resolved consumes the resolver by value
        // and the engine needs `&mut projection_store`, so a closure
        // that captures `&inner` would conflict.
        let engine = inner.query_engine_for(self.tenant_id);
        let result = engine.query_at_timestamp_resolved(
            &mut inner.projection_store,
            sql,
            params,
            target_ns,
            move |_| resolution,
        )?;

        Ok(result)
    }

    /// Returns the current log position for this tenant.
    pub fn log_position(&self) -> Result<Offset> {
        self.db.log_position()
    }

    /// Snapshot this tenant's masking-policy catalogue.
    ///
    /// Returns a typed view of every `(name, strategy, role_guard)`
    /// triple plus — when requested — the `(table, column, policy)`
    /// attachments. Read-only; mutations flow through `execute(…)`
    /// with MASKING POLICY DDL.
    ///
    /// v0.6.0 Tier 2 #7 — Stage 0.0c. The server translates these
    /// native records to `kimberlite_wire::MaskingPolicy*` types at
    /// the RPC boundary.
    pub fn masking_policy_snapshot(
        &self,
        include_attachments: bool,
    ) -> Result<(Vec<MaskingPolicySummary>, Vec<MaskingAttachmentSummary>)> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let raw_attachments: Vec<(kimberlite_kernel::command::TableId, String, String)> = inner
            .kernel_state
            .masking_attachments_for_tenant(self.tenant_id)
            .map(|(t, col, pname)| (t, col.to_string(), pname.to_string()))
            .collect();

        let policies: Vec<MaskingPolicySummary> = inner
            .kernel_state
            .masking_policies_for_tenant(self.tenant_id)
            .map(|rec| {
                let attachment_count = raw_attachments
                    .iter()
                    .filter(|(_, _, pname)| pname == &rec.name)
                    .count() as u32;
                MaskingPolicySummary {
                    name: rec.name.clone(),
                    strategy: rec.strategy.clone(),
                    role_guard: rec.role_guard.clone(),
                    attachment_count,
                }
            })
            .collect();

        let attachments = if include_attachments {
            raw_attachments
                .iter()
                .filter_map(|(table_id, column_name, policy_name)| {
                    let table_name = inner
                        .kernel_state
                        .tables()
                        .iter()
                        .find(|(tid, _)| *tid == table_id)
                        .map(|(_, meta)| meta.table_name.clone())?;
                    Some(MaskingAttachmentSummary {
                        table_name,
                        column_name: column_name.clone(),
                        policy_name: policy_name.clone(),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        // Postcondition: every attachment (when returned) names a
        // policy in the list — guards against a tenant-id threading bug.
        debug_assert!(
            attachments
                .iter()
                .all(|att| policies.iter().any(|p| p.name == att.policy_name)),
            "attachment references a policy not in the returned list"
        );

        Ok((policies, attachments))
    }

    /// Reads events from a stream starting at an offset.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to read from
    /// * `from_offset` - Starting offset (inclusive)
    /// * `max_bytes` - Maximum number of bytes to read
    ///
    /// # Example
    ///
    /// ```ignore
    /// let events = tenant.read_events(stream_id, Offset::ZERO, 1024 * 1024_u64)?;
    /// for event in events {
    ///     process(event);
    /// }
    /// ```
    pub fn read_events(
        &self,
        stream_id: StreamId,
        from_offset: Offset,
        max_bytes: u64,
    ) -> Result<Vec<Bytes>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let events = inner.read_events(stream_id, from_offset, max_bytes)?;
        Ok(events)
    }

    /// Returns the number of committed events on `stream_id`.
    ///
    /// O(1) read of `StreamMetadata.current_offset`. v0.8.0 — replaces
    /// the full-stream `read_events` walk that callers like notebar
    /// were using just to count.
    pub fn stream_length(&self, stream_id: StreamId) -> Result<u64> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let meta = inner
            .kernel_state
            .get_stream(&stream_id)
            .ok_or(KimberliteError::StreamNotFound(stream_id))?;
        Ok(meta.current_offset.as_u64())
    }

    // ========================================================================
    // DDL/DML Implementation Helpers
    // ========================================================================

    /// Ensures system tables (`_kimberlite_audit`, `_kimberlite_consent`) exist.
    ///
    /// Called lazily on the first user CREATE TABLE. Idempotent — skips tables
    /// that already exist in the kernel state.
    fn ensure_system_tables(&self) -> Result<()> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let has_audit = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, "_kimberlite_audit")
            .is_some();
        let has_consent = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, "_kimberlite_consent")
            .is_some();

        drop(inner);

        if !has_audit {
            self.create_system_table(
                "_kimberlite_audit",
                vec![
                    ("timestamp", "TEXT"),
                    ("user", "TEXT"),
                    ("operation", "TEXT"),
                    ("table_name", "TEXT"),
                    ("record_id", "TEXT"),
                ],
            )?;
        }

        if !has_consent {
            self.create_system_table(
                "_kimberlite_consent",
                vec![
                    ("subject_id", "TEXT"),
                    ("purpose", "TEXT"),
                    ("granted", "BOOLEAN"),
                ],
            )?;
        }

        Ok(())
    }

    /// Creates a system table with the given name and columns.
    /// The first column is used as the primary key.
    fn create_system_table(&self, name: &str, cols: Vec<(&str, &str)>) -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.tenant_id.hash(&mut hasher);
        name.hash(&mut hasher);
        let table_id = TableId::new(hasher.finish());

        let columns: Vec<ColumnDefinition> = cols
            .iter()
            .map(|(col_name, col_type)| ColumnDefinition {
                name: (*col_name).to_string(),
                data_type: (*col_type).to_string(),
                nullable: true,
            })
            .collect();

        let primary_key = vec![cols[0].0.to_string()];

        let cmd = Command::CreateTable {
            tenant_id: self.tenant_id,
            table_id,
            table_name: name.to_string(),
            columns,
            primary_key,
        };

        self.db.submit(cmd)?;
        Ok(())
    }

    /// Inserts a row into `_kimberlite_audit` (best-effort, does not fail the operation).
    ///
    /// Skips logging for operations on system tables (`_kimberlite_*`) to
    /// prevent infinite recursion.
    fn audit_log(&self, operation: &str, table_name: &str, record_id: Option<&str>) {
        // Never audit system table operations (prevents recursion)
        if table_name.starts_with("_kimberlite_") {
            return;
        }

        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let record_id_value = match record_id {
            Some(id) => format!("'{}'", id.replace('\'', "''")),
            None => "NULL".to_string(),
        };
        let sql = format!(
            "INSERT INTO _kimberlite_audit (timestamp, user, operation, table_name, record_id) \
             VALUES ('{timestamp}', 'admin', '{operation}', '{table_name}', {record_id_value})"
        );

        // Best-effort: don't fail the main operation if audit logging fails
        if let Err(e) = self.execute(&sql, &[]) {
            tracing::debug!(error = %e, "audit log insert failed (system table may not exist yet)");
        }
    }

    /// Formats primary key values as a human-readable record ID string.
    /// For single-column PKs: "1", for composite: "1,abc".
    fn format_record_id(pk_values: &[Value]) -> String {
        pk_values
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn execute_create_table(&self, create_table: ParsedCreateTable) -> Result<ExecuteResult> {
        // Validate that a primary key is defined
        if create_table.primary_key.is_empty() {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::ParseError(format!(
                    "table '{}' must have a PRIMARY KEY defined",
                    create_table.table_name
                )),
            ));
        }

        // IF NOT EXISTS: short-circuit only when *this tenant* already owns a
        // table of that name. A prior global iteration over `tables()` let a
        // different tenant's entry satisfy the check, so tenant B's CREATE
        // "succeeded" silently against tenant A's catalog — the isolation
        // leak this path is hardened against.
        if create_table.if_not_exists {
            let inner = self
                .db
                .inner()
                .read()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            let exists = inner
                .kernel_state
                .table_by_tenant_name(self.tenant_id, &create_table.table_name)
                .is_some();
            drop(inner);
            if exists {
                return Ok(ExecuteResult::Standard {
                    rows_affected: 0,
                    log_offset: self.log_position()?,
                });
            }
        }

        // Derive a table_id that's unique across tenants and names.
        // The kernel now enforces (tenant_id, table_name) uniqueness on the
        // index side; this hash keeps table_id collisions statistically
        // improbable without needing a kernel-side id allocator.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.tenant_id.hash(&mut hasher);
        create_table.table_name.hash(&mut hasher);
        let table_id = TableId::new(hasher.finish());

        // Convert parsed columns to kernel ColumnDefinitions
        let columns = create_table
            .columns
            .into_iter()
            .map(|col| ColumnDefinition {
                name: col.name,
                data_type: col.data_type,
                nullable: col.nullable,
            })
            .collect();

        let cmd = Command::CreateTable {
            tenant_id: self.tenant_id,
            table_id,
            table_name: create_table.table_name.clone(),
            columns,
            primary_key: create_table.primary_key,
        };

        self.db.submit(cmd)?;

        // Auto-create system tables on first user table creation
        if !create_table.table_name.starts_with("_kimberlite_") {
            self.ensure_system_tables().ok(); // Best-effort
        }

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_drop_table(&self, table_name: &str, if_exists: bool) -> Result<ExecuteResult> {
        // Look up the table within THIS tenant only — a global scan would
        // silently cascade a DROP into another tenant's catalog.
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let table_meta = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, table_name);

        let table_id = match table_meta {
            Some(meta) => meta.table_id,
            None if if_exists => {
                // v0.6.2: `DROP TABLE IF EXISTS` is idempotent. Return a
                // successful no-op instead of `TableNotFound` so the
                // statement can run repeatedly (test fixture cleanup,
                // migration up/down, etc.) without try/catch wrappers
                // at every call site.
                drop(inner);
                return Ok(ExecuteResult::Standard {
                    rows_affected: 0,
                    log_offset: self.log_position()?,
                });
            }
            None => return Err(KimberliteError::TableNotFound(table_name.to_string())),
        };

        drop(inner);

        let cmd = Command::DropTable {
            tenant_id: self.tenant_id,
            table_id,
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    /// Executes an `ALTER TABLE ... ADD/DROP COLUMN` against the kernel.
    ///
    /// Resolves the table by `(tenant, table_name)` — a global lookup would
    /// cascade into another tenant's catalog (same rule as DROP TABLE).
    /// The kernel's `AlterTableAddColumn` / `AlterTableDropColumn` handlers
    /// enforce the schema-version monotonicity invariant, column-name
    /// uniqueness, and the primary-key-not-droppable rule.
    ///
    /// ROADMAP v0.5.0 item B — "ALTER TABLE end-to-end kernel execution".
    fn execute_alter_table(&self, alter_table: ParsedAlterTable) -> Result<ExecuteResult> {
        use kimberlite_query::AlterTableOperation;

        // Resolve the table under this tenant, not globally.
        let table_id = {
            let inner = self
                .db
                .inner()
                .read()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            inner
                .kernel_state
                .table_by_tenant_name(self.tenant_id, &alter_table.table_name)
                .map(|meta| meta.table_id)
                .ok_or_else(|| KimberliteError::TableNotFound(alter_table.table_name.clone()))?
        };

        let cmd = match alter_table.operation {
            AlterTableOperation::AddColumn(parsed_col) => Command::AlterTableAddColumn {
                tenant_id: self.tenant_id,
                table_id,
                column: ColumnDefinition {
                    name: parsed_col.name,
                    data_type: parsed_col.data_type,
                    nullable: parsed_col.nullable,
                },
            },
            AlterTableOperation::DropColumn(column_name) => Command::AlterTableDropColumn {
                tenant_id: self.tenant_id,
                table_id,
                column_name,
            },
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_create_index(&self, create_index: ParsedCreateIndex) -> Result<ExecuteResult> {
        // Tenant-scoped lookup; global scan would allow indexing another
        // tenant's table.
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let table_id = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &create_index.table_name)
            .map(|meta| meta.table_id)
            .ok_or_else(|| KimberliteError::TableNotFound(create_index.table_name.clone()))?;

        drop(inner);

        // Auto-allocate index ID based on hash of table name + index name
        // This avoids overflow issues with large table IDs
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        table_id.hash(&mut hasher);
        create_index.index_name.hash(&mut hasher);
        let index_id = IndexId::new(hasher.finish());

        let cmd = Command::CreateIndex {
            tenant_id: self.tenant_id,
            index_id,
            table_id,
            index_name: create_index.index_name,
            columns: create_index.columns,
        };

        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_create_mask(
        &self,
        create_mask: kimberlite_query::ParsedCreateMask,
    ) -> Result<ExecuteResult> {
        use kimberlite_rbac::masking::{MaskingStrategy, RedactPattern};

        let strategy = match create_mask.strategy.as_str() {
            "REDACT" => MaskingStrategy::Redact(RedactPattern::Ssn),
            "REDACT_SSN" => MaskingStrategy::Redact(RedactPattern::Ssn),
            "REDACT_EMAIL" => MaskingStrategy::Redact(RedactPattern::Email),
            "REDACT_PHONE" => MaskingStrategy::Redact(RedactPattern::Phone),
            "REDACT_CREDIT_CARD" => MaskingStrategy::Redact(RedactPattern::CreditCard),
            "HASH" => MaskingStrategy::Hash,
            "TOKENIZE" => MaskingStrategy::Tokenize,
            "NULL" => MaskingStrategy::Null,
            other => {
                return Err(KimberliteError::Query(
                    kimberlite_query::QueryError::ParseError(format!(
                        "unknown masking strategy '{other}'. \
                         Valid strategies: REDACT, REDACT_SSN, REDACT_EMAIL, REDACT_PHONE, \
                         REDACT_CREDIT_CARD, HASH, TOKENIZE, NULL"
                    )),
                ));
            }
        };

        // Verify table exists
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let table_exists = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &create_mask.table_name)
            .is_some();

        if !table_exists {
            return Err(KimberliteError::TableNotFound(
                create_mask.table_name.clone(),
            ));
        }
        drop(inner);

        // Store the mask
        let entry = crate::kimberlite::MaskEntry {
            table_name: create_mask.table_name,
            column_name: create_mask.column_name,
            strategy,
        };

        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        inner.masks.insert(create_mask.mask_name, entry);

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    fn execute_drop_mask(&self, mask_name: &str) -> Result<ExecuteResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        if inner.masks.remove(mask_name).is_none() {
            return Err(KimberliteError::internal(format!(
                "mask '{mask_name}' not found"
            )));
        }

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    // ========================================================================
    // MASKING POLICY DDL (v0.6.0 Tier 2 #7 — tenant-scoped catalogue form)
    // ========================================================================

    /// Translate parser-level `ParsedMaskingStrategy` into the kernel's
    /// `MaskingStrategyKind`. Kept outside the query crate so the parser
    /// does not depend on the kernel.
    fn translate_masking_strategy(
        parsed: kimberlite_query::ParsedMaskingStrategy,
    ) -> kimberlite_kernel::masking::MaskingStrategyKind {
        use kimberlite_kernel::masking::{MaskingStrategyKind, RedactPatternKind};
        use kimberlite_query::ParsedMaskingStrategy;
        match parsed {
            ParsedMaskingStrategy::RedactSsn => MaskingStrategyKind::Redact(RedactPatternKind::Ssn),
            ParsedMaskingStrategy::RedactPhone => {
                MaskingStrategyKind::Redact(RedactPatternKind::Phone)
            }
            ParsedMaskingStrategy::RedactEmail => {
                MaskingStrategyKind::Redact(RedactPatternKind::Email)
            }
            ParsedMaskingStrategy::RedactCreditCard => {
                MaskingStrategyKind::Redact(RedactPatternKind::CreditCard)
            }
            ParsedMaskingStrategy::RedactCustom { replacement } => {
                MaskingStrategyKind::Redact(RedactPatternKind::Custom { replacement })
            }
            ParsedMaskingStrategy::Hash => MaskingStrategyKind::Hash,
            ParsedMaskingStrategy::Tokenize => MaskingStrategyKind::Tokenize,
            ParsedMaskingStrategy::Truncate { max_chars } => {
                MaskingStrategyKind::Truncate { max_chars }
            }
            ParsedMaskingStrategy::Null => MaskingStrategyKind::Null,
        }
    }

    fn execute_create_masking_policy(
        &self,
        policy: kimberlite_query::ParsedCreateMaskingPolicy,
    ) -> Result<ExecuteResult> {
        use kimberlite_kernel::masking::RoleGuard;

        // Pressurecraft: defence-in-depth against a parser regression —
        // the parser rejects empty EXEMPT ROLES lists, and the kernel
        // will also tolerate them. Catch here too so a bad DDL is
        // rejected before we acquire the write lock.
        if policy.exempt_roles.is_empty() {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::ParseError(
                    "EXEMPT ROLES list must contain at least one role".to_string(),
                ),
            ));
        }

        let strategy = Self::translate_masking_strategy(policy.strategy);
        let role_guard = RoleGuard {
            exempt_roles: policy.exempt_roles,
            default_masked: true,
        };

        let cmd = Command::CreateMaskingPolicy {
            tenant_id: self.tenant_id,
            name: policy.name,
            strategy,
            role_guard,
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_drop_masking_policy(&self, policy_name: &str) -> Result<ExecuteResult> {
        let cmd = Command::DropMaskingPolicy {
            tenant_id: self.tenant_id,
            name: policy_name.to_string(),
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_attach_masking_policy(
        &self,
        attach: kimberlite_query::ParsedAttachMaskingPolicy,
    ) -> Result<ExecuteResult> {
        let table_id = self.resolve_table_id(&attach.table_name)?;
        let cmd = Command::AttachMaskingPolicy {
            tenant_id: self.tenant_id,
            table_id,
            column_name: attach.column_name,
            policy_name: attach.policy_name,
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    fn execute_detach_masking_policy(
        &self,
        detach: kimberlite_query::ParsedDetachMaskingPolicy,
    ) -> Result<ExecuteResult> {
        let table_id = self.resolve_table_id(&detach.table_name)?;
        let cmd = Command::DetachMaskingPolicy {
            tenant_id: self.tenant_id,
            table_id,
            column_name: detach.column_name,
        };
        self.db.submit(cmd)?;

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: self.log_position()?,
        })
    }

    /// Look up a table's `TableId` by name under this tenant's catalogue.
    /// Returns `TableNotFound` if the table does not exist for the tenant.
    fn resolve_table_id(&self, table_name: &str) -> Result<TableId> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let table_id = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, table_name)
            .map(|t| t.table_id)
            .ok_or_else(|| KimberliteError::TableNotFound(table_name.to_string()))?;
        Ok(table_id)
    }

    fn execute_set_classification(
        &self,
        set_class: kimberlite_query::ParsedSetClassification,
    ) -> Result<ExecuteResult> {
        // Verify table exists
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let table_meta = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &set_class.table_name)
            .cloned();

        let table_meta = table_meta
            .ok_or_else(|| KimberliteError::TableNotFound(set_class.table_name.clone()))?;

        // Verify column exists
        let column_exists = table_meta
            .columns
            .iter()
            .any(|c| c.name == set_class.column_name);

        if !column_exists {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::ParseError(format!(
                    "column '{}' not found in table '{}'",
                    set_class.column_name, set_class.table_name
                )),
            ));
        }

        drop(inner);

        // Store the classification
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let key = (set_class.table_name.clone(), set_class.column_name.clone());
        inner
            .column_classifications
            .insert(key, set_class.classification.clone());

        tracing::info!(
            tenant_id = %self.tenant_id,
            table = %set_class.table_name,
            column = %set_class.column_name,
            classification = %set_class.classification,
            "Column classification set"
        );

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    fn execute_show_classifications(&self, table_name: &str) -> Result<QueryResult> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Verify the *current tenant* owns a table by this name. A prior
        // global iteration treated any other tenant's table as satisfying
        // this check, which let set_classification/show_classifications
        // leak into another tenant's catalog.
        let table_exists = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, table_name)
            .is_some();

        if !table_exists {
            return Err(KimberliteError::TableNotFound(table_name.to_string()));
        }

        // Collect classifications for this table, sorted by column name
        let mut rows: Vec<Vec<Value>> = inner
            .column_classifications
            .iter()
            .filter(|((t, _), _)| t == table_name)
            .map(|((_, col), class)| vec![Value::Text(col.clone()), Value::Text(class.clone())])
            .collect();
        rows.sort_by(|a, b| a[0].to_string().cmp(&b[0].to_string()));

        Ok(QueryResult {
            columns: vec![
                kimberlite_query::ColumnName::new("column"),
                kimberlite_query::ColumnName::new("classification"),
            ],
            rows,
        })
    }

    fn execute_show_tables(&self) -> Result<QueryResult> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let mut rows: Vec<Vec<Value>> = inner
            .kernel_state
            .tables_for_tenant(self.tenant_id)
            .map(|meta| {
                vec![
                    Value::Text(meta.table_name.clone()),
                    Value::BigInt(meta.columns.len() as i64),
                ]
            })
            .collect();
        rows.sort_by(|a, b| a[0].to_string().cmp(&b[0].to_string()));

        Ok(QueryResult {
            columns: vec![
                kimberlite_query::ColumnName::new("table_name"),
                kimberlite_query::ColumnName::new("column_count"),
            ],
            rows,
        })
    }

    fn execute_show_columns(&self, table_name: &str) -> Result<QueryResult> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let table_meta = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, table_name)
            .cloned();

        let meta =
            table_meta.ok_or_else(|| KimberliteError::TableNotFound(table_name.to_string()))?;

        let rows: Vec<Vec<Value>> = meta
            .columns
            .iter()
            .map(|col| {
                vec![
                    Value::Text(col.name.clone()),
                    Value::Text(col.data_type.clone()),
                    Value::Boolean(col.nullable),
                ]
            })
            .collect();

        Ok(QueryResult {
            columns: vec![
                kimberlite_query::ColumnName::new("column_name"),
                kimberlite_query::ColumnName::new("data_type"),
                kimberlite_query::ColumnName::new("nullable"),
            ],
            rows,
        })
    }

    fn execute_create_role(&self, role_name: &str) -> Result<ExecuteResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        if inner.roles.iter().any(|r| r == role_name) {
            return Err(KimberliteError::internal(format!(
                "role '{role_name}' already exists"
            )));
        }
        inner.roles.push(role_name.to_string());

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    fn execute_grant(&self, grant: kimberlite_query::ParsedGrant) -> Result<ExecuteResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        inner.grants.push(StoredGrant {
            columns: grant.columns,
            table_name: grant.table_name,
            role_name: grant.role_name,
        });

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    fn execute_create_user(
        &self,
        create_user: kimberlite_query::ParsedCreateUser,
    ) -> Result<ExecuteResult> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        // Verify role exists
        if !inner.roles.iter().any(|r| r == &create_user.role) {
            return Err(KimberliteError::internal(format!(
                "role '{}' does not exist",
                create_user.role
            )));
        }

        inner.users.push((create_user.username, create_user.role));

        Ok(ExecuteResult::Standard {
            rows_affected: 0,
            log_offset: inner.log_position,
        })
    }

    fn execute_insert(&self, insert: ParsedInsert, params: &[Value]) -> Result<ExecuteResult> {
        // Look up table metadata
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let (table_id, table_meta) = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &insert.table)
            .map(|meta| (meta.table_id, meta.clone()))
            .ok_or_else(|| KimberliteError::TableNotFound(insert.table.clone()))?;

        drop(inner);

        // Determine column names to use
        let column_names: Vec<String> = if insert.columns.is_empty() {
            // No columns specified - use all columns from table definition in order
            table_meta
                .columns
                .iter()
                .map(|col| col.name.clone())
                .collect()
        } else {
            // Validate that specified columns exist
            validate_columns_exist(&insert.columns, &table_meta.columns)?;
            insert.columns.clone()
        };

        // Process each row
        let mut rows_affected = 0;
        let mut last_offset = self.log_position()?;
        let mut inserted_pk_keys = Vec::new(); // Track PKs for RETURNING

        for row_values in &insert.values {
            // Validate value count matches column count for this row
            if column_names.len() != row_values.len() {
                return Err(KimberliteError::Query(
                    kimberlite_query::QueryError::TypeMismatch {
                        expected: format!("{} values", column_names.len()),
                        actual: format!("{} values provided", row_values.len()),
                    },
                ));
            }

            // Bind parameters to placeholders for this row
            let bound_values = bind_parameters(row_values, params)?;

            // Validate column types and constraints for this row
            validate_insert_values(
                &column_names,
                &bound_values,
                &table_meta.columns,
                &table_meta.primary_key,
            )?;

            // Build primary key for duplicate detection
            let mut pk_values = Vec::new();
            for pk_col in &table_meta.primary_key {
                let col_idx = column_names
                    .iter()
                    .position(|name| name == pk_col)
                    .ok_or_else(|| {
                        KimberliteError::internal(format!(
                            "Primary key column '{pk_col}' not found in INSERT columns"
                        ))
                    })?;
                pk_values.push(bound_values[col_idx].clone());
            }

            let pk_key = encode_key(&pk_values);

            // Check for duplicate primary key
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;

            // Convert kernel TableId to store TableId
            let store_table_id = kimberlite_store::TableId::from(table_id.0);

            if inner
                .projection_store
                .get(store_table_id, &pk_key)?
                .is_some()
            {
                return Err(KimberliteError::Query(
                    kimberlite_query::QueryError::DuplicatePrimaryKey {
                        table: insert.table.clone(),
                        key: pk_values,
                    },
                ));
            }

            drop(inner);

            // Serialize row data as JSON event
            let mut row_map = serde_json::Map::new();
            for (col, val) in column_names.iter().zip(bound_values.iter()) {
                row_map.insert(col.clone(), value_to_json(val));
            }

            let event = json!({
                "type": "insert",
                "table": insert.table,
                "data": row_map,
            });

            let row_data = Bytes::from(serde_json::to_vec(&event).map_err(|e| {
                KimberliteError::internal(format!("JSON serialization failed: {e}"))
            })?);

            let cmd = Command::Insert {
                tenant_id: self.tenant_id,
                table_id,
                row_data,
            };
            self.db.submit(cmd)?;

            rows_affected += 1;
            last_offset = self.log_position()?;

            // Audit log with the actual record ID
            let record_id = Self::format_record_id(&pk_values);
            self.audit_log("INSERT", &insert.table, Some(&record_id));

            // Track PK for RETURNING clause
            if insert.returning.is_some() {
                inserted_pk_keys.push(pk_key.clone());
            }
        }

        // If RETURNING clause present, query back the inserted rows
        if let Some(returning_cols) = &insert.returning {
            // Validate that all RETURNING columns exist
            validate_columns_exist(returning_cols, &table_meta.columns)?;

            let mut returned_rows = Vec::new();
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;

            let store_table_id = kimberlite_store::TableId::from(table_id.0);

            for pk_key in &inserted_pk_keys {
                // Query the row from projection store
                if let Some(row_bytes) = inner.projection_store.get(store_table_id, pk_key)? {
                    // Deserialize row data
                    let row_json: serde_json::Value =
                        serde_json::from_slice(&row_bytes).map_err(|e| {
                            KimberliteError::internal(format!("Failed to deserialize row: {e}"))
                        })?;

                    // Extract requested columns
                    let mut row_values = Vec::new();
                    if let Some(obj) = row_json.as_object() {
                        for col in returning_cols {
                            let value = obj.get(col).ok_or_else(|| {
                                KimberliteError::internal(format!(
                                    "Column '{col}' not found in row"
                                ))
                            })?;
                            row_values.push(json_to_value(value)?);
                        }
                    } else {
                        return Err(KimberliteError::internal("Row is not a JSON object"));
                    }

                    returned_rows.push(row_values);
                }
            }

            drop(inner);

            Ok(ExecuteResult::WithReturning {
                rows_affected,
                log_offset: last_offset,
                returned: QueryResult {
                    columns: returning_cols
                        .iter()
                        .map(|s| ColumnName::new(s.clone()))
                        .collect(),
                    rows: returned_rows,
                },
            })
        } else {
            Ok(ExecuteResult::Standard {
                rows_affected,
                log_offset: last_offset,
            })
        }
    }

    /// v0.6.0 Tier 1 #3 — `INSERT ... ON CONFLICT (...) DO { UPDATE | NOTHING }`.
    ///
    /// Atomic: one event per upsert, no dual-write window. The notebar
    /// `upsertRow` helper's UPDATE-then-INSERT pair is collapsed to a
    /// single `Command::Upsert`. Composes with RETURNING — we reuse the
    /// same projection-probe infrastructure the plain INSERT path uses.
    ///
    /// Semantics:
    /// - No prior row at the conflict key → `rowsAffected = 1`, resolution `Inserted`.
    /// - Prior row exists, `DO UPDATE` → `rowsAffected = 1`, resolution `Updated`.
    /// - Prior row exists, `DO NOTHING` → `rowsAffected = 0`, resolution `NoOp`.
    ///
    /// The `conflict_exists` flag is computed at this layer (a B+tree
    /// point-lookup) and passed into the pure kernel — the kernel
    /// itself does no IO.
    #[allow(clippy::too_many_lines)]
    fn execute_upsert(&self, insert: ParsedInsert, params: &[Value]) -> Result<ExecuteResult> {
        let oc = insert
            .on_conflict
            .as_ref()
            .ok_or_else(|| KimberliteError::internal("execute_upsert without on_conflict"))?
            .clone();

        // Look up table metadata.
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let (table_id, table_meta) = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &insert.table)
            .map(|meta| (meta.table_id, meta.clone()))
            .ok_or_else(|| KimberliteError::TableNotFound(insert.table.clone()))?;
        drop(inner);

        // Column list — default to the full table schema order when
        // the INSERT omits a column list (same convention as plain INSERT).
        let column_names: Vec<String> = if insert.columns.is_empty() {
            table_meta.columns.iter().map(|c| c.name.clone()).collect()
        } else {
            validate_columns_exist(&insert.columns, &table_meta.columns)?;
            insert.columns.clone()
        };

        // Validate the conflict target matches the primary key. v0.6.0
        // only accepts upserts on the PK — unique constraints land later.
        if oc.target.len() != table_meta.primary_key.len()
            || oc
                .target
                .iter()
                .any(|c| !table_meta.primary_key.contains(c))
        {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::UnsupportedFeature(format!(
                    "ON CONFLICT target {:?} must match the primary key {:?}",
                    oc.target, table_meta.primary_key,
                )),
            ));
        }

        let mut rows_affected: u64 = 0;
        let mut last_offset = self.log_position()?;
        let mut touched_pk_keys: Vec<kimberlite_store::Key> = Vec::new();

        for row_values in &insert.values {
            if column_names.len() != row_values.len() {
                return Err(KimberliteError::Query(
                    kimberlite_query::QueryError::TypeMismatch {
                        expected: format!("{} values", column_names.len()),
                        actual: format!("{} values provided", row_values.len()),
                    },
                ));
            }

            let bound_values = bind_parameters(row_values, params)?;
            validate_insert_values(
                &column_names,
                &bound_values,
                &table_meta.columns,
                &table_meta.primary_key,
            )?;

            // Build PK from the bound row values.
            let mut pk_values = Vec::new();
            for pk_col in &table_meta.primary_key {
                let idx = column_names
                    .iter()
                    .position(|n| n == pk_col)
                    .ok_or_else(|| {
                        KimberliteError::internal(format!(
                            "primary key column '{pk_col}' missing from INSERT columns"
                        ))
                    })?;
                pk_values.push(bound_values[idx].clone());
            }
            let pk_key = encode_key(&pk_values);

            // Probe the projection store for an existing row (single
            // B+tree point-lookup — the "kernel does no IO" boundary).
            let (conflict_exists, existing_row_json) = {
                let mut inner = self
                    .db
                    .inner()
                    .write()
                    .map_err(|_| KimberliteError::internal("lock poisoned"))?;
                let store_table_id = kimberlite_store::TableId::from(table_id.0);
                let existing = inner.projection_store.get(store_table_id, &pk_key)?;
                match existing {
                    None => (false, None),
                    Some(bytes) => {
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(|e| {
                                KimberliteError::internal(format!(
                                    "projection row not valid JSON: {e}"
                                ))
                            })?;
                        (true, Some(parsed))
                    }
                }
            };

            // Decide the kernel-level knobs from the parsed clause.
            let do_nothing = matches!(oc.action, OnConflictAction::DoNothing);

            // Build the effective row payload. `Inserted` uses the
            // incoming VALUES row as-is. `Updated` merges the existing
            // row's columns with the `SET col = <expr>` assignments,
            // resolving `EXCLUDED.col` back-references against the
            // incoming row. `NoOp` builds no payload.
            let row_data_bytes = if !conflict_exists {
                // INSERTED path — identical shape to the plain INSERT event.
                let mut row_map = serde_json::Map::new();
                for (col, val) in column_names.iter().zip(bound_values.iter()) {
                    row_map.insert(col.clone(), value_to_json(val));
                }
                let event = json!({
                    "type": "insert",
                    "table": insert.table,
                    "data": row_map,
                });
                Some(Bytes::from(serde_json::to_vec(&event).map_err(|e| {
                    KimberliteError::internal(format!("JSON serialization failed: {e}"))
                })?))
            } else if do_nothing {
                None
            } else {
                // UPDATED path — start from the existing row (so columns
                // not touched by SET remain unchanged), then apply each
                // assignment from `DO UPDATE SET ...`.
                let OnConflictAction::DoUpdate { ref assignments } = oc.action else {
                    // Unreachable — matched `do_nothing` above.
                    return Err(KimberliteError::internal(
                        "upsert: reached Updated branch with non-DoUpdate action",
                    ));
                };

                let existing = existing_row_json.ok_or_else(|| {
                    KimberliteError::internal(
                        "upsert: conflict_exists==true but existing row missing",
                    )
                })?;
                let mut merged = match existing {
                    serde_json::Value::Object(m) => m,
                    _ => {
                        return Err(KimberliteError::internal(
                            "upsert: existing projection row is not a JSON object",
                        ));
                    }
                };

                // Resolve each RHS expression — EXCLUDED.col pulls from
                // the incoming row; literal/placeholder values go
                // through param binding.
                for (col, rhs) in assignments {
                    if !table_meta.columns.iter().any(|c| c.name == *col) {
                        return Err(KimberliteError::Query(
                            kimberlite_query::QueryError::ParseError(format!(
                                "column '{col}' does not exist in table"
                            )),
                        ));
                    }
                    let resolved: Value = match rhs {
                        UpsertExpr::Excluded(excl_col) => {
                            let idx = column_names
                                .iter()
                                .position(|n| n == excl_col)
                                .ok_or_else(|| {
                                    KimberliteError::Query(
                                        kimberlite_query::QueryError::ParseError(format!(
                                            "EXCLUDED.{excl_col} references a column not in the INSERT list"
                                        )),
                                    )
                                })?;
                            bound_values[idx].clone()
                        }
                        UpsertExpr::Value(v) => {
                            // Bind placeholders the same way plain
                            // UPDATE/INSERT does.
                            if let Value::Placeholder(p) = v {
                                if *p == 0 || *p > params.len() {
                                    return Err(KimberliteError::Query(
                                        kimberlite_query::QueryError::ParseError(format!(
                                            "parameter ${p} out of bounds (have {} parameters)",
                                            params.len()
                                        )),
                                    ));
                                }
                                params[*p - 1].clone()
                            } else {
                                v.clone()
                            }
                        }
                    };
                    merged.insert(col.clone(), value_to_json(&resolved));
                }

                let event = json!({
                    "type": "upsert_update",
                    "table": insert.table,
                    "data": serde_json::Value::Object(merged),
                });
                Some(Bytes::from(serde_json::to_vec(&event).map_err(|e| {
                    KimberliteError::internal(format!("JSON serialization failed: {e}"))
                })?))
            };

            // Submit the single atomic Upsert command. `row_data` on
            // the NoOp path is a dummy empty payload — the kernel
            // discards it without touching storage.
            let cmd = Command::Upsert {
                tenant_id: self.tenant_id,
                table_id,
                row_data: row_data_bytes.clone().unwrap_or_else(Bytes::new),
                conflict_exists,
                do_nothing,
            };
            self.db.submit(cmd)?;

            // Rows-affected bookkeeping — the kernel's resolution is
            // the source of truth: 1 for insert, 1 for update, 0 for no-op.
            if !conflict_exists || !do_nothing {
                rows_affected += 1;
            }
            last_offset = self.log_position()?;

            let record_id = Self::format_record_id(&pk_values);
            let op_tag = if !conflict_exists {
                "UPSERT_INSERT"
            } else if do_nothing {
                "UPSERT_NOOP"
            } else {
                "UPSERT_UPDATE"
            };
            self.audit_log(op_tag, &insert.table, Some(&record_id));

            if insert.returning.is_some() && row_data_bytes.is_some() {
                touched_pk_keys.push(pk_key);
            }
        }

        // RETURNING — reuse the same projection-probe pattern the plain
        // INSERT path uses (tenant.rs:1299-1352). NoOp rows are omitted
        // from RETURNING, matching PostgreSQL's semantics.
        if let Some(returning_cols) = &insert.returning {
            validate_columns_exist(returning_cols, &table_meta.columns)?;

            let mut returned_rows = Vec::new();
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            let store_table_id = kimberlite_store::TableId::from(table_id.0);

            for pk_key in &touched_pk_keys {
                if let Some(row_bytes) = inner.projection_store.get(store_table_id, pk_key)? {
                    let row_json: serde_json::Value =
                        serde_json::from_slice(&row_bytes).map_err(|e| {
                            KimberliteError::internal(format!("Failed to deserialize row: {e}"))
                        })?;

                    let mut row_values = Vec::new();
                    if let Some(obj) = row_json.as_object() {
                        for col in returning_cols {
                            let value = obj.get(col).ok_or_else(|| {
                                KimberliteError::internal(format!(
                                    "Column '{col}' not found in row"
                                ))
                            })?;
                            row_values.push(json_to_value(value)?);
                        }
                    } else {
                        return Err(KimberliteError::internal("Row is not a JSON object"));
                    }
                    returned_rows.push(row_values);
                }
            }

            drop(inner);

            Ok(ExecuteResult::WithReturning {
                rows_affected,
                log_offset: last_offset,
                returned: QueryResult {
                    columns: returning_cols
                        .iter()
                        .map(|s| ColumnName::new(s.clone()))
                        .collect(),
                    rows: returned_rows,
                },
            })
        } else {
            Ok(ExecuteResult::Standard {
                rows_affected,
                log_offset: last_offset,
            })
        }
    }

    fn execute_update(&self, update: ParsedUpdate, params: &[Value]) -> Result<ExecuteResult> {
        // Look up table metadata
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let (table_id, table_meta) = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &update.table)
            .map(|meta| (meta.table_id, meta.clone()))
            .ok_or_else(|| KimberliteError::TableNotFound(update.table.clone()))?;

        // Bind parameters in SET assignments
        let bound_assignments: Vec<(String, Value)> = update
            .assignments
            .into_iter()
            .map(|(col, val)| {
                let bound_val = if let Value::Placeholder(idx) = val {
                    if idx == 0 || idx > params.len() {
                        return Err(KimberliteError::Query(
                            kimberlite_query::QueryError::ParseError(format!(
                                "parameter ${idx} out of bounds (have {} parameters)",
                                params.len()
                            )),
                        ));
                    }
                    params[idx - 1].clone()
                } else {
                    val
                };
                Ok((col, bound_val))
            })
            .collect::<Result<Vec<_>>>()?;

        // Build a SELECT query to find all matching rows
        let select = kimberlite_query::ParsedSelect {
            table: update.table.clone(),
            joins: vec![],
            columns: Some(
                table_meta
                    .primary_key
                    .iter()
                    .map(|c| c.clone().into())
                    .collect(),
            ),
            column_aliases: None,
            case_columns: vec![],
            predicates: update.predicates.clone(),
            order_by: vec![],
            limit: None,
            offset: None,
            aggregates: vec![],
            aggregate_filters: vec![],
            group_by: vec![],
            distinct: false,
            having: vec![],
            ctes: vec![],
            window_fns: vec![],
            scalar_projections: vec![],
        };

        // Plan and execute the query
        let engine = inner.query_engine_for(self.tenant_id);
        let schema = engine.schema().clone();
        let plan = kimberlite_query::plan_query(&schema, &select, params)?;
        let table_def = schema
            .get_table(&update.table.clone().into())
            .ok_or_else(|| KimberliteError::TableNotFound(update.table.clone()))?;
        let matching_rows =
            kimberlite_query::execute(&mut inner.projection_store, &plan, table_def)?;

        drop(inner);

        // For each matched row, submit an UPDATE command
        let mut rows_affected = 0;
        let mut last_offset = self.log_position()?;
        let mut updated_pk_keys = Vec::new(); // Track PKs for RETURNING

        for row in &matching_rows.rows {
            // Build WHERE clause with primary key values
            let mut pk_predicates = Vec::new();
            for (idx, pk_col) in table_meta.primary_key.iter().enumerate() {
                pk_predicates.push((pk_col.clone(), row[idx].clone()));
            }

            let predicates_json: Vec<serde_json::Value> = pk_predicates
                .iter()
                .map(|(col, val)| {
                    json!({
                        "op": "eq",
                        "column": col,
                        "values": [value_to_json(val)],
                    })
                })
                .collect();

            let event = json!({
                "type": "update",
                "table": update.table,
                "set": bound_assignments,
                "where": predicates_json,
            });

            let row_data = Bytes::from(serde_json::to_vec(&event).map_err(|e| {
                KimberliteError::internal(format!("JSON serialization failed: {e}"))
            })?);

            let cmd = Command::Update {
                tenant_id: self.tenant_id,
                table_id,
                row_data,
            };
            self.db.submit(cmd)?;

            rows_affected += 1;
            last_offset = self.log_position()?;

            // Audit log with the actual record ID
            let pk_values: Vec<Value> = table_meta
                .primary_key
                .iter()
                .enumerate()
                .map(|(idx, _)| row[idx].clone())
                .collect();
            let record_id = Self::format_record_id(&pk_values);
            self.audit_log("UPDATE", &update.table, Some(&record_id));

            // Track PK for RETURNING clause
            if update.returning.is_some() {
                updated_pk_keys.push(encode_key(&pk_values));
            }
        }

        // If RETURNING clause present, query back the updated rows
        if let Some(returning_cols) = &update.returning {
            // Validate that all RETURNING columns exist
            validate_columns_exist(returning_cols, &table_meta.columns)?;

            let mut returned_rows = Vec::new();
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;

            let store_table_id = kimberlite_store::TableId::from(table_id.0);

            for pk_key in &updated_pk_keys {
                // Query the updated row from projection store
                if let Some(row_bytes) = inner.projection_store.get(store_table_id, pk_key)? {
                    // Deserialize row data
                    let row_json: serde_json::Value =
                        serde_json::from_slice(&row_bytes).map_err(|e| {
                            KimberliteError::internal(format!("Failed to deserialize row: {e}"))
                        })?;

                    // Extract requested columns
                    let mut row_values = Vec::new();
                    if let Some(obj) = row_json.as_object() {
                        for col in returning_cols {
                            let value = obj.get(col).ok_or_else(|| {
                                KimberliteError::internal(format!(
                                    "Column '{col}' not found in row"
                                ))
                            })?;
                            row_values.push(json_to_value(value)?);
                        }
                    } else {
                        return Err(KimberliteError::internal("Row is not a JSON object"));
                    }

                    returned_rows.push(row_values);
                }
            }

            drop(inner);

            Ok(ExecuteResult::WithReturning {
                rows_affected,
                log_offset: last_offset,
                returned: QueryResult {
                    columns: returning_cols
                        .iter()
                        .map(|s| ColumnName::new(s.clone()))
                        .collect(),
                    rows: returned_rows,
                },
            })
        } else {
            Ok(ExecuteResult::Standard {
                rows_affected,
                log_offset: last_offset,
            })
        }
    }

    fn execute_delete(&self, delete: ParsedDelete, params: &[Value]) -> Result<ExecuteResult> {
        // Look up table metadata
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let (table_id, table_meta) = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, &delete.table)
            .map(|meta| (meta.table_id, meta.clone()))
            .ok_or_else(|| KimberliteError::TableNotFound(delete.table.clone()))?;

        // Build a SELECT query to find all matching rows
        let select = kimberlite_query::ParsedSelect {
            table: delete.table.clone(),
            joins: vec![],
            columns: Some(
                table_meta
                    .primary_key
                    .iter()
                    .map(|c| c.clone().into())
                    .collect(),
            ),
            column_aliases: None,
            case_columns: vec![],
            predicates: delete.predicates.clone(),
            order_by: vec![],
            limit: None,
            offset: None,
            aggregates: vec![],
            aggregate_filters: vec![],
            group_by: vec![],
            distinct: false,
            having: vec![],
            ctes: vec![],
            window_fns: vec![],
            scalar_projections: vec![],
        };

        // Plan and execute the query
        let engine = inner.query_engine_for(self.tenant_id);
        let schema = engine.schema().clone();
        let plan = kimberlite_query::plan_query(&schema, &select, params)?;
        let table_def = schema
            .get_table(&delete.table.clone().into())
            .ok_or_else(|| KimberliteError::TableNotFound(delete.table.clone()))?;
        let matching_rows =
            kimberlite_query::execute(&mut inner.projection_store, &plan, table_def)?;

        drop(inner);

        // AUDIT-2026-05 S3.5 — DELETE row-count fidelity. The
        // executed plan reports the matched-row count; the kernel
        // submission loop must produce the same count out the
        // back. A discrepancy means we either silently dropped a
        // row (kernel rejected) or double-counted, both of which
        // mislead `rows_affected` consumers.
        let expected_rows = matching_rows.rows.len();

        // For each matched row, submit a DELETE command
        let mut rows_affected: u64 = 0;
        let mut last_offset = self.log_position()?;
        let mut deleted_rows: Vec<Vec<Value>> = Vec::new(); // Store row data for RETURNING (before deletion)

        for row in &matching_rows.rows {
            // If RETURNING, capture the full row before deletion
            if let Some(returning_cols) = &delete.returning {
                // Validate that all RETURNING columns exist
                if deleted_rows.is_empty() {
                    validate_columns_exist(returning_cols, &table_meta.columns)?;
                }

                // Build PK key and query the full row
                let pk_values: Vec<Value> = table_meta
                    .primary_key
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| row[idx].clone())
                    .collect();
                let pk_key = encode_key(&pk_values);

                let mut inner = self
                    .db
                    .inner()
                    .write()
                    .map_err(|_| KimberliteError::internal("lock poisoned"))?;

                let store_table_id = kimberlite_store::TableId::from(table_id.0);

                if let Some(row_bytes) = inner.projection_store.get(store_table_id, &pk_key)? {
                    // Deserialize row data
                    let row_json: serde_json::Value =
                        serde_json::from_slice(&row_bytes).map_err(|e| {
                            KimberliteError::internal(format!("Failed to deserialize row: {e}"))
                        })?;

                    // Extract requested columns
                    let mut row_values = Vec::new();
                    if let Some(obj) = row_json.as_object() {
                        for col in returning_cols {
                            let value = obj.get(col).ok_or_else(|| {
                                KimberliteError::internal(format!(
                                    "Column '{col}' not found in row"
                                ))
                            })?;
                            row_values.push(json_to_value(value)?);
                        }
                    } else {
                        return Err(KimberliteError::internal("Row is not a JSON object"));
                    }

                    deleted_rows.push(row_values);
                }

                drop(inner);
            }

            // Build WHERE clause with primary key values
            let mut pk_predicates = Vec::new();
            for (idx, pk_col) in table_meta.primary_key.iter().enumerate() {
                pk_predicates.push((pk_col.clone(), row[idx].clone()));
            }

            let predicates_json: Vec<serde_json::Value> = pk_predicates
                .iter()
                .map(|(col, val)| {
                    json!({
                        "op": "eq",
                        "column": col,
                        "values": [value_to_json(val)],
                    })
                })
                .collect();

            let event = json!({
                "type": "delete",
                "table": delete.table,
                "where": predicates_json,
            });

            let row_data = Bytes::from(serde_json::to_vec(&event).map_err(|e| {
                KimberliteError::internal(format!("JSON serialization failed: {e}"))
            })?);

            let cmd = Command::Delete {
                tenant_id: self.tenant_id,
                table_id,
                row_data,
            };
            self.db.submit(cmd)?;

            // Audit log with the actual record ID
            let pk_values: Vec<Value> = table_meta
                .primary_key
                .iter()
                .enumerate()
                .map(|(idx, _)| row[idx].clone())
                .collect();
            let record_id = Self::format_record_id(&pk_values);
            self.audit_log("DELETE", &delete.table, Some(&record_id));

            rows_affected += 1;
            last_offset = self.log_position()?;
        }

        // Postcondition: rows_affected must equal the planner's
        // matched-row count. Drift here is a kernel-submission
        // bug, not user error — surface it loudly. AUDIT-2026-05 S3.5.
        assert_eq!(
            rows_affected as usize, expected_rows,
            "DELETE rows_affected drift: planner matched {expected_rows} rows, kernel submit loop reported {rows_affected}",
        );

        // Return result with or without RETURNING data
        if let Some(returning_cols) = delete.returning {
            Ok(ExecuteResult::WithReturning {
                rows_affected,
                log_offset: last_offset,
                returned: QueryResult {
                    columns: returning_cols
                        .iter()
                        .map(|s| ColumnName::new(s.clone()))
                        .collect(),
                    rows: deleted_rows,
                },
            })
        } else {
            Ok(ExecuteResult::Standard {
                rows_affected,
                log_offset: last_offset,
            })
        }
    }

    // ========================================================================
    // RBAC & Compliance Integration (Phase 3.2 & 3.3)
    // ========================================================================

    /// Executes a SQL query with RBAC policy enforcement.
    ///
    /// This method provides HIPAA-ready / GDPR-ready query execution:
    /// - **Column filtering**: Removes unauthorized columns from results
    /// - **Row-level security**: Injects WHERE clauses based on policy
    /// - **Audit logging**: Records all access attempts
    /// - **Consent validation**: Checks GDPR consent before data access
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL SELECT statement
    /// * `params` - Query parameters
    /// * `policy` - Access control policy (extracted from JWT token)
    ///
    /// # Returns
    ///
    /// Returns filtered query results or an error if access is denied.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Extract policy from authenticated user
    /// let policy = identity.extract_policy()?;
    ///
    /// // Execute query with RBAC enforcement
    /// let results = tenant.query_with_policy(
    ///     "SELECT name, ssn FROM patients",
    ///     &[],
    ///     &policy,
    /// )?;
    /// // Result: SSN column removed if user lacks permission
    /// ```
    ///
    /// # Compliance
    ///
    /// - **HIPAA §164.312(a)(4)**: Access control enforcement
    /// - **GDPR Article 6**: Lawful basis for processing
    /// - **GDPR Article 32**: Security of processing
    pub fn query_with_policy(
        &self,
        sql: &str,
        params: &[Value],
        policy: &kimberlite_rbac::AccessPolicy,
    ) -> Result<QueryResult> {
        use kimberlite_query::rbac_filter::RbacFilter;

        // Parse SQL using sqlparser directly for RBAC rewriting
        let dialect = sqlparser::dialect::GenericDialect {};
        let statements = sqlparser::parser::Parser::parse_sql(&dialect, sql)
            .map_err(|e| KimberliteError::internal(format!("SQL parse error: {e}")))?;

        let stmt = statements
            .into_iter()
            .next()
            .ok_or_else(|| KimberliteError::internal("Empty SQL statement"))?;

        // RBAC enforcement: Rewrite query to enforce policy
        let filter = RbacFilter::new(policy.clone());
        let rewritten = filter
            .rewrite_statement(stmt)
            .map_err(|e| KimberliteError::internal(format!("RBAC filter failed: {e}")))?;

        let filtered_sql = rewritten.statement.to_string();

        // Execute the filtered query
        let result = self.query(&filtered_sql, params)?;

        // Apply field masking if a masking policy is configured.
        //
        // AUDIT-2026-04 M-7: masks are keyed by *source* column, not the
        // potentially-aliased output name. `rewritten.column_aliases`
        // maps each surviving output column back to the identifier the
        // RBAC enforcer checked, so `SELECT ssn AS id FROM patients`
        // continues to mask `ssn` under its alias `id`.
        let result = if let Some(masking_policy) = &policy.masking_policy {
            self.apply_masking_to_result(
                result,
                masking_policy,
                policy.role,
                &rewritten.column_aliases,
            )?
        } else {
            result
        };

        // Audit: Log query access
        tracing::info!(
            tenant_id = %self.tenant_id,
            role = ?policy.role,
            sql = %sql,
            filtered_sql = %filtered_sql,
            rows_returned = result.rows.len(),
            "RBAC query executed"
        );

        Ok(result)
    }

    /// Applies field masking to query results based on the masking policy.
    ///
    /// For each row, checks each column against the masking policy and applies
    /// the appropriate masking strategy (redact, hash, tokenize, truncate, null)
    /// based on the user's role.
    ///
    /// Masks are keyed by **source column** — the underlying sensitive
    /// attribute — not by the result-set output name. `column_aliases`
    /// supplies the `(output, source)` pairs produced by RBAC rewriting
    /// so that `SELECT ssn AS id` still hits the `ssn` mask under its
    /// alias (AUDIT-2026-04 M-7).
    ///
    /// # Compliance
    ///
    /// - **HIPAA §164.312(a)(1)**: Minimum necessary — field-level data masking
    fn apply_masking_to_result(
        &self,
        mut result: QueryResult,
        masking_policy: &kimberlite_rbac::masking::MaskingPolicy,
        role: kimberlite_rbac::Role,
        column_aliases: &[(String, String)],
    ) -> Result<QueryResult> {
        // Build an output-name → source-name map. Columns absent from
        // the alias map (e.g. queries that bypassed `rewrite_statement`
        // entirely) fall back to their output name — preserving
        // pre-M-7 behaviour for callers that do not supply aliases.
        let alias_map: std::collections::HashMap<&str, &str> = column_aliases
            .iter()
            .map(|(out, src)| (out.as_str(), src.as_str()))
            .collect();

        let column_names: Vec<(String, String)> = result
            .columns
            .iter()
            .map(|c| {
                let out = c.as_str().to_string();
                let src = alias_map
                    .get(out.as_str())
                    .map_or_else(|| out.clone(), |s| (*s).to_string());
                (out, src)
            })
            .collect();

        for row in &mut result.rows {
            for (i, (out_name, src_name)) in column_names.iter().enumerate() {
                if let Some(mask) = masking_policy.mask_for_column(src_name) {
                    if mask.should_mask(&role) {
                        if let Some(value) = row.get(i) {
                            // AUDIT-2026-04 L-1: preserve source type where
                            // the strategy allows rather than coercing every
                            // masked cell to `Value::Text`.
                            let masked =
                                apply_mask_preserving_type(value, mask, role).map_err(|e| {
                                    KimberliteError::internal(format!(
                                        "Masking failed for column '{out_name}' \
                                         (source '{src_name}'): {e}"
                                    ))
                                })?;
                            row[i] = masked;
                        }
                    }
                }
            }
        }

        tracing::debug!(
            tenant_id = %self.tenant_id,
            columns_masked = masking_policy.masks().len(),
            rows_processed = result.rows.len(),
            "Field masking applied to query results"
        );

        Ok(result)
    }

    /// Executes a SQL statement with RBAC policy enforcement.
    ///
    /// Similar to `query_with_policy()` but for DML/DDL statements.
    ///
    /// # Compliance
    ///
    /// - **HIPAA §164.312(a)(1)**: Access control
    /// - **SOC2 CC6.3**: Logical access controls
    pub fn execute_with_policy(
        &self,
        sql: &str,
        params: &[Value],
        policy: &kimberlite_rbac::AccessPolicy,
    ) -> Result<ExecuteResult> {
        use kimberlite_query::{ParsedStatement, parse_statement};

        // Parse SQL to AST
        let parsed = parse_statement(sql)?;

        // RBAC enforcement: Check if user has permission for this operation
        let (allowed, operation) = match &parsed {
            ParsedStatement::Insert(_) => (policy.role.can_write(), "INSERT"),
            ParsedStatement::Update(_) => (policy.role.can_write(), "UPDATE"),
            ParsedStatement::Delete(_) => (policy.role.can_delete(), "DELETE"),
            ParsedStatement::CreateTable(_)
            | ParsedStatement::DropTable { .. }
            | ParsedStatement::AlterTable(_)
            | ParsedStatement::CreateIndex(_)
            | ParsedStatement::CreateMask(_)
            | ParsedStatement::DropMask(_)
            | ParsedStatement::CreateMaskingPolicy(_)
            | ParsedStatement::DropMaskingPolicy(_)
            | ParsedStatement::AttachMaskingPolicy(_)
            | ParsedStatement::DetachMaskingPolicy(_)
            | ParsedStatement::SetClassification(_)
            | ParsedStatement::CreateRole(_)
            | ParsedStatement::Grant(_)
            | ParsedStatement::CreateUser(_) => {
                (policy.role == kimberlite_rbac::Role::Admin, "DDL")
            }
            ParsedStatement::Select(_)
            | ParsedStatement::Union(_)
            | ParsedStatement::ShowClassifications(_)
            | ParsedStatement::ShowTables
            | ParsedStatement::ShowColumns(_) => (true, "QUERY"),
        };

        if !allowed {
            tracing::warn!(
                tenant_id = %self.tenant_id,
                role = ?policy.role,
                operation = %operation,
                "Access denied: insufficient permissions"
            );
            return Err(KimberliteError::internal(format!(
                "Access denied: {operation} operation requires additional permissions"
            )));
        }

        // For UPDATE/DELETE, use original SQL (RBAC permission check above is sufficient).
        // Row-level security WHERE clauses are not yet supported for DML.
        let filtered_sql = sql.to_string();

        // Execute the filtered statement
        let result = self.execute(&filtered_sql, params)?;

        // Audit: Log DML/DDL operation
        tracing::info!(
            tenant_id = %self.tenant_id,
            role = ?policy.role,
            operation = %operation,
            sql = %sql,
            rows_affected = result.rows_affected(),
            "RBAC execute completed"
        );

        Ok(result)
    }

    /// Validates GDPR consent before processing personal data.
    ///
    /// Checks if valid consent exists for the given subject and purpose.
    /// For purposes that do not require consent (e.g., `LegalObligation`),
    /// validation succeeds without a consent record.
    ///
    /// # Arguments
    ///
    /// * `subject_id` - Data subject identifier (e.g., patient ID, user ID)
    /// * `purpose` - Purpose for data processing (e.g., Treatment, Analytics)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if consent is valid or not required, or an error if
    /// consent is missing/withdrawn.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 6(1)(a)**: Consent as lawful basis
    /// - **GDPR Article 7**: Conditions for consent
    pub fn validate_consent(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<()> {
        // Purposes that don't require explicit consent (lawful basis exists)
        if !purpose.requires_consent() {
            tracing::debug!(
                tenant_id = %self.tenant_id,
                subject_id = %subject_id,
                purpose = ?purpose,
                "Consent not required for this purpose (lawful basis)"
            );
            return Ok(());
        }

        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let has_consent = inner.consent_tracker.check_consent(subject_id, purpose);

        if !has_consent {
            tracing::warn!(
                tenant_id = %self.tenant_id,
                subject_id = %subject_id,
                purpose = ?purpose,
                "Consent validation failed: no valid consent found"
            );
            return Err(KimberliteError::internal(format!(
                "Consent required: no valid consent for subject '{subject_id}' with purpose {purpose:?}"
            )));
        }

        tracing::debug!(
            tenant_id = %self.tenant_id,
            subject_id = %subject_id,
            purpose = ?purpose,
            "Consent validated successfully"
        );

        Ok(())
    }

    /// Evaluates ABAC policy for a given access request.
    ///
    /// Provides fine-grained, context-aware access control that augments RBAC.
    /// Considers user attributes (role, clearance), resource attributes
    /// (data classification, stream), and environment (time, country).
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 25**: Privacy by design (context-aware access)
    /// - **`FedRAMP` AC-3**: Location-based access enforcement
    /// - **PCI DSS Req 7**: Need-to-know access
    pub fn evaluate_abac(
        &self,
        policy: &kimberlite_abac::AbacPolicy,
        user: &kimberlite_abac::UserAttributes,
        resource: &kimberlite_abac::ResourceAttributes,
        env: &kimberlite_abac::EnvironmentAttributes,
    ) -> kimberlite_abac::Decision {
        let decision = kimberlite_abac::evaluate(policy, user, resource, env);

        tracing::info!(
            tenant_id = %self.tenant_id,
            effect = ?decision.effect,
            matched_rule = ?decision.matched_rule,
            reason = %decision.reason,
            "ABAC evaluation completed"
        );

        decision
    }

    /// Grants GDPR consent for a data subject and purpose.
    ///
    /// Records consent in the consent tracker. The returned UUID can be used
    /// to withdraw consent later.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 7(1)**: Demonstrable consent
    pub fn grant_consent(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<uuid::Uuid> {
        self.grant_consent_with_basis(
            subject_id,
            purpose,
            kimberlite_compliance::consent::ConsentScope::AllData,
            None,
        )
    }

    /// Grants consent with an explicit scope + optional GDPR
    /// Article 6(1) lawful basis. Threaded through from wire
    /// protocol v4 (v0.6.0); `basis = None` preserves pre-v4
    /// semantics. Delegates to [`Self::grant_consent_with_options`]
    /// with `terms_version = None` and `accepted = true`.
    ///
    /// # Compliance
    /// - **GDPR Article 6(1)**: lawful basis capture
    /// - **GDPR Article 7(1)**: demonstrable consent
    pub fn grant_consent_with_basis(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
        scope: kimberlite_compliance::consent::ConsentScope,
        basis: Option<kimberlite_compliance::consent::ConsentBasis>,
    ) -> Result<uuid::Uuid> {
        self.grant_consent_with_options(
            subject_id,
            purpose,
            kimberlite_compliance::consent::GrantOptions {
                scope,
                basis,
                ..kimberlite_compliance::consent::GrantOptions::default()
            },
        )
    }

    /// Grants consent with the full v0.6.2 options surface — scope,
    /// GDPR Article 6(1) basis, terms-of-service version, and an
    /// explicit `accepted` flag (default `true`). Captures both
    /// acceptances and explicit declines (`accepted = false`) in
    /// the audit trail.
    ///
    /// # Compliance
    /// - **GDPR Article 6(1)**: lawful basis capture
    /// - **GDPR Article 7(1)**: demonstrable consent
    /// - **GDPR Article 7(3)**: capturing explicit decline alongside acceptance
    pub fn grant_consent_with_options(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
        options: kimberlite_compliance::consent::GrantOptions,
    ) -> Result<uuid::Uuid> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let basis_article = options.basis.as_ref().map(|b| b.article);
        let scope_for_log = options.scope;
        let terms_version_for_log = options.terms_version.clone();
        let accepted_for_log = options.accepted;

        let consent_id = inner
            .consent_tracker
            .grant_consent_with_options(subject_id, purpose, options)
            .map_err(|e| KimberliteError::internal(format!("Consent grant failed: {e}")))?;

        tracing::info!(
            tenant_id = %self.tenant_id,
            subject_id = %subject_id,
            purpose = ?purpose,
            scope = ?scope_for_log,
            basis = ?basis_article,
            terms_version = ?terms_version_for_log,
            accepted = accepted_for_log,
            consent_id = %consent_id,
            "Consent granted"
        );

        Ok(consent_id)
    }

    /// Returns every consent record for a subject, including withdrawn and
    /// expired ones. Useful for admin UIs and audit exports.
    ///
    /// # Compliance
    /// - **GDPR Article 7(1)**: Demonstrable consent (history must be queryable).
    pub fn get_consents_for_subject(
        &self,
        subject_id: &str,
    ) -> Result<Vec<kimberlite_compliance::consent::ConsentRecord>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner
            .consent_tracker
            .get_consents_for_subject(subject_id)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Returns a single consent record by ID, or `None` if not found.
    pub fn get_consent(
        &self,
        consent_id: uuid::Uuid,
    ) -> Result<Option<kimberlite_compliance::consent::ConsentRecord>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.consent_tracker.get_consent(consent_id).cloned())
    }

    /// Checks whether a subject has an active (non-withdrawn, non-expired)
    /// consent for the given purpose.
    pub fn check_consent(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<bool> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.consent_tracker.check_consent(subject_id, purpose))
    }

    /// Withdraws GDPR consent by consent ID.
    ///
    /// After withdrawal, subsequent `validate_consent` calls for the same
    /// subject and purpose will fail.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 7(3)**: Withdrawal as easy as giving consent
    pub fn withdraw_consent(&self, consent_id: uuid::Uuid) -> Result<()> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        inner
            .consent_tracker
            .withdraw_consent(consent_id)
            .map_err(|e| KimberliteError::internal(format!("Consent withdrawal failed: {e}")))?;

        tracing::info!(
            consent_id = %consent_id,
            "Consent withdrawn"
        );

        Ok(())
    }

    // =========================================================================
    // Consent-Aware Operations
    // =========================================================================

    /// Appends events to a stream with consent validation.
    ///
    /// When `consent_mode` is `Required`, validates that the subject has
    /// granted consent for the given purpose before appending. When
    /// `Optional`, logs a warning if consent is missing but proceeds.
    /// When `Disabled`, behaves identically to `append()`.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 6(1)(a)**: Consent as lawful basis for processing
    pub fn append_with_consent(
        &self,
        stream_id: StreamId,
        events: Vec<Vec<u8>>,
        expected_offset: Offset,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<Offset> {
        self.check_consent_if_required(subject_id, purpose)?;
        self.append(stream_id, events, expected_offset)
    }

    /// Executes a SQL query with consent validation.
    ///
    /// When `consent_mode` is `Required`, validates that the subject has
    /// granted consent for the given purpose before querying. When
    /// `Optional`, logs a warning if consent is missing but proceeds.
    /// When `Disabled`, behaves identically to `query()`.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 6(1)(a)**: Consent as lawful basis for processing
    pub fn query_with_consent(
        &self,
        sql: &str,
        params: &[Value],
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<QueryResult> {
        self.check_consent_if_required(subject_id, purpose)?;
        self.query(sql, params)
    }

    /// Reads events from a stream with consent validation.
    ///
    /// When `consent_mode` is `Required`, validates that the subject has
    /// granted consent for the given purpose before reading. When
    /// `Optional`, logs a warning if consent is missing but proceeds.
    /// When `Disabled`, behaves identically to `read_events()`.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 6(1)(a)**: Consent as lawful basis for processing
    pub fn read_events_with_consent(
        &self,
        stream_id: StreamId,
        from_offset: Offset,
        max_bytes: u64,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<Vec<Bytes>> {
        self.check_consent_if_required(subject_id, purpose)?;
        self.read_events(stream_id, from_offset, max_bytes)
    }

    /// Checks consent based on the current `consent_mode`.
    ///
    /// - `Required`: calls `validate_consent()` and returns the error if
    ///   consent is missing.
    /// - `Optional`: calls `validate_consent()` and logs a warning on failure
    ///   but returns `Ok(())`.
    /// - `Disabled`: no-op, always returns `Ok(())`.
    fn check_consent_if_required(
        &self,
        subject_id: &str,
        purpose: kimberlite_compliance::purpose::Purpose,
    ) -> Result<()> {
        match self.consent_mode {
            ConsentMode::Disabled => Ok(()),
            ConsentMode::Required => self.validate_consent(subject_id, purpose),
            ConsentMode::Optional => {
                if let Err(e) = self.validate_consent(subject_id, purpose) {
                    tracing::warn!(
                        tenant_id = %self.tenant_id,
                        subject_id = %subject_id,
                        purpose = ?purpose,
                        error = %e,
                        "Consent not found (optional mode — proceeding with warning)"
                    );
                }
                Ok(())
            }
        }
    }

    // =========================================================================
    // Data Classification (v0.6.0 Tier 2 #8)
    // =========================================================================

    /// **v0.6.0 Tier 2 #8.** Tag an existing table's backing stream
    /// with a data classification (`PHI`, `PII`, `Sensitive`, ...).
    ///
    /// `CREATE TABLE` currently creates the backing stream with
    /// `DataClass::Public` by default (kernel has no SQL-level
    /// classification syntax yet). Callers that want a table to be
    /// auto-discovered by [`Self::erase_subject`] must tag it with one
    /// of `PHI` / `PII` / `Sensitive` using this method.
    ///
    /// Note: the classification is an in-memory catalog patch. It
    /// survives process restarts only if the runtime persists kernel
    /// state snapshots (WAL-based deployments replay the prior
    /// classification via `StreamMetadataWrite` effects). A dedicated
    /// `RetagStream` command + durable Effect is tracked on ROADMAP
    /// v0.7.0.
    ///
    /// # Errors
    ///
    /// - `KimberliteError::internal("table not found")` if the tenant
    ///   has no table by that name.
    pub fn tag_table_data_class(&self, table_name: &str, data_class: DataClass) -> Result<()> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let stream_id = inner
            .kernel_state
            .table_by_tenant_name(self.tenant_id, table_name)
            .map(|t| t.stream_id)
            .ok_or_else(|| {
                KimberliteError::internal(format!(
                    "table '{table_name}' not found for tenant {}",
                    self.tenant_id
                ))
            })?;
        let new_state =
            std::mem::take(&mut inner.kernel_state).with_stream_data_class(stream_id, data_class);
        inner.kernel_state = new_state;
        tracing::info!(
            tenant_id = %self.tenant_id,
            table = %table_name,
            data_class = ?data_class,
            "tagged table with data classification"
        );
        Ok(())
    }

    // =========================================================================
    // Erasure (GDPR Article 17)
    // =========================================================================

    /// Requests erasure of all data for a subject (Right to Erasure).
    ///
    /// Creates a pending erasure request with a 30-day deadline.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 17**: Right to erasure
    pub fn request_erasure(
        &self,
        subject_id: &str,
    ) -> Result<kimberlite_compliance::erasure::ErasureRequest> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let request = inner
            .erasure_engine
            .request_erasure(subject_id)
            .map_err(|e| KimberliteError::internal(format!("Erasure request failed: {e}")))?;

        tracing::info!(
            tenant_id = %self.tenant_id,
            subject_id = %subject_id,
            request_id = %request.request_id,
            deadline = %request.deadline,
            "Erasure requested"
        );

        Ok(request)
    }

    /// Marks an erasure request as in-progress on the given streams.
    ///
    /// # Compliance
    /// - **GDPR Article 17(1)**: Operator must start erasure without undue delay.
    pub fn mark_erasure_in_progress(
        &self,
        request_id: uuid::Uuid,
        streams: Vec<kimberlite_types::StreamId>,
    ) -> Result<()> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner
            .erasure_engine
            .mark_in_progress(request_id, streams)
            .map_err(|e| KimberliteError::internal(format!("Erasure in-progress failed: {e}")))
    }

    /// Records that one stream has been erased as part of a larger request.
    pub fn mark_stream_erased(
        &self,
        request_id: uuid::Uuid,
        stream_id: kimberlite_types::StreamId,
        records_erased: u64,
    ) -> Result<()> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner
            .erasure_engine
            .mark_stream_erased(request_id, stream_id, records_erased)
            .map_err(|e| KimberliteError::internal(format!("mark_stream_erased failed: {e}")))
    }

    /// **AUDIT-2026-04 C-1 — signed erasure orchestration.** Perform
    /// the full erasure act for this request end-to-end using a
    /// caller-supplied [`kimberlite_compliance::erasure::ErasureExecutor`],
    /// producing a signed attestation bound to the pre-erasure chain
    /// heads and DEK-shred digests.
    ///
    /// Prefer this over the legacy [`Self::complete_erasure`] — that
    /// path binds the proof only to a self-reported count and is
    /// retained for back-compat.
    ///
    /// # Lock scope
    ///
    /// The internal engine call holds the write lock across executor
    /// invocations. The supplied executor must **not** re-enter
    /// `TenantHandle` methods that would acquire the lock, or the
    /// call will deadlock. In practice the executor only needs
    /// `Storage` + `Command::Delete` + `DataEncryptionKey::shred` —
    /// none of which require the outer lock.
    ///
    /// # Errors
    ///
    /// See [`kimberlite_compliance::erasure::ErasureError`].
    pub fn execute_erasure(
        &self,
        request_id: uuid::Uuid,
        executor: &mut dyn kimberlite_compliance::erasure::ErasureExecutor,
        attestation_key: &kimberlite_compliance::erasure::AttestationKey,
    ) -> Result<kimberlite_compliance::erasure::ErasureAuditRecord> {
        // Nanosecond timestamp for the attestation. `timestamp_nanos_opt`
        // is `None` only far outside the supported range (~1677-2262);
        // `unwrap_or(0)` is the intentional fallback.
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).max(0) as u64;

        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let audit = inner
            .erasure_engine
            .execute_erasure(
                request_id,
                self.tenant_id,
                executor,
                attestation_key,
                now_ns,
            )
            .map_err(|e| KimberliteError::internal(format!("execute_erasure failed: {e}")))?;

        tracing::info!(
            tenant_id = %self.tenant_id,
            request_id = %request_id,
            records_erased = audit.records_erased,
            "Erasure executed with signed attestation"
        );

        Ok(audit)
    }

    /// **AUDIT-2026-04 C-1 — one-call erasure.** Convenience wrapper
    /// that drives the full GDPR Article 17 lifecycle for a single
    /// data subject end-to-end.
    ///
    /// **v0.6.0 Tier 2 #8 — auto-discovery.** If the caller does not
    /// supply an explicit stream list, this walks the tenant's catalog
    /// and auto-discovers every stream tagged `PHI`/`PII`/`Sensitive`
    /// whose table schema carries a `subject_id` column
    /// (configurable via the `DEFAULT_SUBJECT_COLUMN` constant in
    /// the `erasure_executor` module). This is
    /// the production default — callers that need fine-grained scope
    /// override can pass [`Self::erase_subject_with_streams`].
    ///
    /// **v0.6.0 Tier 2 #8 — idempotence.** If a prior `erase_subject`
    /// call has already completed for this `subject_id`, a noop-replay
    /// audit record is appended and the original signed receipt is
    /// returned unchanged. No new cryptographic shred event occurs.
    /// Regulators see the exact same commitment as the first call,
    /// with a distinct audit entry flagged `is_noop_replay = true`.
    ///
    /// This is the entry point production callers should use; the
    /// lower-level [`Self::request_erasure`] /
    /// [`Self::mark_erasure_in_progress`] / [`Self::execute_erasure`]
    /// triple remains available for callers that need to interleave
    /// custom logic between phases.
    ///
    /// # Errors
    ///
    /// Propagates any [`KimberliteError`] from the underlying engine
    /// or executor (kernel rejection, lock poisoning, I/O failure).
    pub fn erase_subject(
        &self,
        subject_id: &str,
        attestation_key: &kimberlite_compliance::erasure::AttestationKey,
    ) -> Result<kimberlite_compliance::erasure::ErasureAuditRecord> {
        self.erase_subject_inner(subject_id, attestation_key, None)
    }

    /// **v0.6.0 Tier 2 #8 — override path.** Explicit-streams variant
    /// of [`Self::erase_subject`]. Skips auto-discovery and uses the
    /// caller-supplied `streams` list verbatim.
    ///
    /// Useful when the caller wants to erase a subject from a subset
    /// of streams (e.g., "only the events stream, leave the audit
    /// trail alone") or when auto-discovery's PHI/PII filter would
    /// skip a stream that the caller knows to contain subject data.
    pub fn erase_subject_with_streams(
        &self,
        subject_id: &str,
        streams: Vec<StreamId>,
        attestation_key: &kimberlite_compliance::erasure::AttestationKey,
    ) -> Result<kimberlite_compliance::erasure::ErasureAuditRecord> {
        self.erase_subject_inner(subject_id, attestation_key, Some(streams))
    }

    /// Shared orchestration for [`Self::erase_subject`] (auto-discovery)
    /// and [`Self::erase_subject_with_streams`] (explicit override).
    ///
    /// `streams_override = None` triggers the auto-discovery walk;
    /// `Some(list)` uses the list verbatim. Both paths share the
    /// idempotence-replay short-circuit and the rest of the lifecycle.
    fn erase_subject_inner(
        &self,
        subject_id: &str,
        attestation_key: &kimberlite_compliance::erasure::AttestationKey,
        streams_override: Option<Vec<StreamId>>,
    ) -> Result<kimberlite_compliance::erasure::ErasureAuditRecord> {
        // --- Idempotence short-circuit ----------------------------------
        // If we've already erased this subject, re-emit the original
        // signed receipt with a noop-replay audit entry and return.
        // No new request is opened, no new shred event is triggered.
        {
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            if let Some(original) = inner
                .erasure_engine
                .find_completed_by_subject(subject_id)
                .cloned()
            {
                let noop = inner.erasure_engine.record_noop_replay(&original);
                tracing::info!(
                    tenant_id = %self.tenant_id,
                    subject_id = %subject_id,
                    original_request_id = %original.request_id,
                    "erase_subject returned noop replay (subject already erased)"
                );
                return Ok(noop);
            }
        }

        let request = self.request_erasure(subject_id)?;

        // --- Stream discovery -------------------------------------------
        // Either use the caller's explicit list or auto-walk
        // PHI/PII-tagged streams with a subject_id column. Then trim
        // to the streams that actually have committed data (an empty
        // stream would produce a zero-witness the attestation can't
        // bind a meaningful proof to).
        let candidate_streams: Vec<StreamId> = match streams_override {
            Some(list) => list,
            None => self.discover_phi_pii_streams()?,
        };

        let streams: Vec<StreamId> = {
            let mut inner = self
                .db
                .inner()
                .write()
                .map_err(|_| KimberliteError::internal("lock poisoned"))?;
            // Dedup defensively: the auto-discovery walk uses a
            // BTreeSet, but explicit callers might pass duplicates.
            // `execute_erasure` asserts the post-dedup invariant and
            // would otherwise panic on a duplicate, which is correct
            // behaviour for a caller bug but less friendly for the
            // override path.
            let deduped: Vec<StreamId> = candidate_streams
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let mut populated = Vec::with_capacity(deduped.len());
            for sid in deduped {
                let head = inner
                    .storage
                    .latest_chain_hash(sid)
                    .map_err(|e| KimberliteError::internal(format!("chain head lookup: {e}")))?;
                if head.is_some() {
                    populated.push(sid);
                }
            }
            populated
        };

        if streams.is_empty() {
            // Nothing responsive for this tenant + subject. Surface
            // this as a Display-friendly error rather than calling
            // into the engine's panicking empty-stream path.
            return Err(KimberliteError::internal(format!(
                "tenant {} has no PHI/PII streams with committed data; \
                 nothing to erase for subject {subject_id}",
                self.tenant_id
            )));
        }

        self.mark_erasure_in_progress(request.request_id, streams.clone())?;

        // The compliance crate's `ErasureScope` enforces
        // `stream_id.tenant_id() == subject_tenant` against the
        // bit-packed StreamId convention. The current kernel's
        // `with_new_stream` allocates from a flat counter (high bits
        // are zero) — so we derive `subject_tenant` from the streams'
        // actual bits and rely on the runtime-layer isolation we
        // already enforced (filter tables by `t.tenant_id ==
        // self.tenant_id` above). All streams must agree on that
        // derived tenant; if they don't we refuse rather than risk
        // erasing across mixed tenants.
        let derived_tenant = streams[0].tenant_id();
        if !streams.iter().all(|s| s.tenant_id() == derived_tenant) {
            return Err(KimberliteError::internal(
                "tenant streams disagree on bit-packed tenant_id; \
                 refuse to attestate across mixed-tenant scope",
            ));
        }

        // Run the executor under the inner write lock; mem::take the
        // engine out so the executor can mutably borrow the rest of
        // `inner` without aliasing.
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).max(0) as u64;

        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let mut engine = std::mem::take(&mut inner.erasure_engine);
        let mut executor = crate::erasure_executor::KernelBackedErasureExecutor::new(&mut inner);
        let result = engine.execute_erasure(
            request.request_id,
            derived_tenant,
            &mut executor,
            attestation_key,
            now_ns,
        );
        // Restore engine even on error so subsequent calls observe a
        // populated audit trail; the engine itself was mutated in
        // place during the call.
        inner.erasure_engine = engine;

        let audit = result
            .map_err(|e| KimberliteError::internal(format!("execute_erasure failed: {e}")))?;

        tracing::info!(
            tenant_id = %self.tenant_id,
            request_id = %request.request_id,
            records_erased = audit.records_erased,
            streams_erased = audit.streams_affected.len(),
            "erase_subject completed with signed attestation"
        );

        Ok(audit)
    }

    /// **v0.6.0 Tier 2 #8 — auto-discovery walk.** Returns every stream
    /// owned by this tenant that:
    /// 1. is tagged `DataClass::PHI`, `DataClass::PII`, or
    ///    `DataClass::Sensitive` (the three classes GDPR Article 17
    ///    + HIPAA § 164.524 right-to-erasure applies to), and
    /// 2. backs a table with a column named `subject_id` (the
    ///    conventional default — configurable via the
    ///    `DEFAULT_SUBJECT_COLUMN` constant in the
    ///    `erasure_executor` module).
    ///
    /// System tables (`_kimberlite_*`) are excluded unconditionally:
    /// they hold audit metadata about erasure acts themselves and
    /// must survive the erasure.
    ///
    /// The returned list is deduplicated and sorted by `StreamId` for
    /// deterministic ordering — downstream the executor iterates in
    /// this order and the signed proof's bundle root depends on it.
    pub fn discover_phi_pii_streams(&self) -> Result<Vec<StreamId>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let subject_column = crate::erasure_executor::DEFAULT_SUBJECT_COLUMN;
        let mut discovered: std::collections::BTreeSet<StreamId> =
            std::collections::BTreeSet::new();
        for table in inner.kernel_state.tables().values() {
            if table.tenant_id != self.tenant_id {
                continue;
            }
            if table.table_name.starts_with("_kimberlite_") {
                continue;
            }
            // Column-name match: the table must declare a
            // `subject_id` column for auto-discovery to include it.
            // Case-insensitive: SQL identifiers canonicalize to
            // lowercase in Kimberlite's query layer, but defensive
            // callers sometimes upper-case them.
            let has_subject_col = table
                .columns
                .iter()
                .any(|c| c.name.eq_ignore_ascii_case(subject_column));
            if !has_subject_col {
                continue;
            }
            // PHI/PII/Sensitive tag check: look up the backing stream
            // and consult its data_class.
            let Some(meta) = inner.kernel_state.get_stream(&table.stream_id) else {
                continue;
            };
            if matches!(
                meta.data_class,
                DataClass::PHI | DataClass::PII | DataClass::Sensitive
            ) {
                discovered.insert(table.stream_id);
            }
        }
        Ok(discovered.into_iter().collect())
    }

    /// Finalises an erasure request, computing the cryptographic proof and
    /// returning the immutable audit record.
    ///
    /// **AUDIT-2026-04 H-4**: this still calls the legacy
    /// `complete_erasure` that binds only to a self-reported count.
    /// Prefer [`Self::execute_erasure`], which binds the proof to the
    /// pre-erasure merkle roots + DEK-shred digests produced by a
    /// runtime-provided [`kimberlite_compliance::erasure::ErasureExecutor`].
    /// The `#[allow(deprecated)]` marker here exists so any future
    /// migration of existing call sites is explicit.
    #[allow(deprecated)] // AUDIT-2026-04 H-4 legacy path retained for back-compat
    pub fn complete_erasure(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<kimberlite_compliance::erasure::ErasureAuditRecord> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let audit = inner
            .erasure_engine
            .complete_erasure(request_id)
            .map_err(|e| KimberliteError::internal(format!("Erasure completion failed: {e}")))?;
        tracing::info!(
            tenant_id = %self.tenant_id,
            request_id = %request_id,
            records_erased = audit.records_erased,
            "Erasure completed"
        );
        Ok(audit)
    }

    /// Marks an erasure request as exempt from processing (GDPR Art. 17(3)).
    pub fn exempt_from_erasure(
        &self,
        request_id: uuid::Uuid,
        basis: kimberlite_compliance::erasure::ExemptionBasis,
    ) -> Result<()> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner
            .erasure_engine
            .exempt_from_erasure(request_id, basis)
            .map_err(|e| KimberliteError::internal(format!("Erasure exemption failed: {e}")))
    }

    /// Look up a single erasure request by ID.
    pub fn get_erasure_request(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<Option<kimberlite_compliance::erasure::ErasureRequest>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.erasure_engine.get_request(request_id).cloned())
    }

    /// Snapshot of the erasure audit trail.
    pub fn erasure_audit_trail(
        &self,
    ) -> Result<Vec<kimberlite_compliance::erasure::ErasureAuditRecord>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.erasure_engine.get_audit_trail().to_vec())
    }

    /// Checks for overdue erasure requests.
    ///
    /// Returns requests that have passed their 30-day deadline.
    pub fn check_erasure_deadlines(&self) -> Result<Vec<uuid::Uuid>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let overdue: Vec<uuid::Uuid> = inner
            .erasure_engine
            .check_deadlines(chrono::Utc::now())
            .iter()
            .map(|r| r.request_id)
            .collect();

        if !overdue.is_empty() {
            tracing::warn!(
                tenant_id = %self.tenant_id,
                overdue_count = overdue.len(),
                "Overdue erasure requests detected"
            );
        }

        Ok(overdue)
    }

    // =========================================================================
    // Breach Detection (HIPAA §164.404, GDPR Article 33)
    // =========================================================================

    /// Checks for mass data export breach indicators.
    ///
    /// # Compliance
    ///
    /// - **HIPAA §164.404**: Breach notification
    /// - **GDPR Article 33**: Notification of breach to supervisory authority
    pub fn check_breach_mass_export(
        &self,
        records_exported: u64,
        data_classes: &[kimberlite_types::DataClass],
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let event = inner
            .breach_detector
            .check_mass_export(records_exported, data_classes);

        if let Some(ref evt) = event {
            tracing::error!(
                tenant_id = %self.tenant_id,
                event_id = %evt.event_id,
                severity = ?evt.severity,
                "Breach indicator detected: mass export"
            );
        }

        Ok(event)
    }

    /// Checks for breach notification deadlines (72h).
    pub fn check_breach_deadlines(&self) -> Result<Vec<uuid::Uuid>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let overdue: Vec<uuid::Uuid> = inner
            .breach_detector
            .check_notification_deadlines(chrono::Utc::now())
            .iter()
            .map(|e| e.event_id)
            .collect();

        Ok(overdue)
    }

    // =========================================================================
    // Phase 6 breach-reporting surface (ROADMAP v0.5.0 item C)
    //
    // Exposes the full BreachDetector state machine — report an indicator,
    // inspect, confirm (sets notification-sent timestamp), resolve — as
    // tenant-scoped methods so the server handlers can wire the wire-
    // protocol surface end-to-end without cracking open the DB's internal
    // lock. All four paths audit-log via ComplianceAuditAction::BreachXxx
    // so HIPAA §164.308(a)(6) can reconstruct the workflow from the
    // hash-chained audit log alone.
    // =========================================================================

    /// Thin pass-through to
    /// [`BreachDetector::check_denied_access`](kimberlite_compliance::breach::BreachDetector::check_denied_access).
    /// Used by the Phase 6 server handler when the wire carries an
    /// `UnauthorizedAccessPattern` indicator.
    pub fn check_breach_denied_access(
        &self,
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner
            .breach_detector
            .check_denied_access(chrono::Utc::now()))
    }

    /// Thin pass-through to
    /// [`BreachDetector::check_privilege_escalation`](kimberlite_compliance::breach::BreachDetector::check_privilege_escalation).
    pub fn check_breach_privilege_escalation(
        &self,
        from_role: &str,
        to_role: &str,
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner
            .breach_detector
            .check_privilege_escalation(from_role, to_role))
    }

    /// Thin pass-through to
    /// [`BreachDetector::check_query_volume`](kimberlite_compliance::breach::BreachDetector::check_query_volume).
    pub fn check_breach_query_volume(
        &self,
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.breach_detector.check_query_volume(chrono::Utc::now()))
    }

    /// Thin pass-through to
    /// [`BreachDetector::check_unusual_access_time`](kimberlite_compliance::breach::BreachDetector::check_unusual_access_time).
    pub fn check_breach_unusual_access_time(
        &self,
        hour: u8,
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.breach_detector.check_unusual_access_time(hour))
    }

    /// Thin pass-through to
    /// [`BreachDetector::check_data_exfiltration`](kimberlite_compliance::breach::BreachDetector::check_data_exfiltration).
    pub fn check_breach_data_exfiltration(
        &self,
        bytes_exported: u64,
        data_classes: &[kimberlite_types::DataClass],
    ) -> Result<Option<kimberlite_compliance::breach::BreachEvent>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner
            .breach_detector
            .check_data_exfiltration(bytes_exported, data_classes))
    }

    /// Fetch a breach event + its report by event id.
    pub fn breach_report(
        &self,
        event_id: uuid::Uuid,
    ) -> Result<Option<kimberlite_compliance::breach::BreachReport>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        Ok(inner.breach_detector.generate_report(event_id).ok())
    }

    /// Transition a breach event to `Confirmed`. Sets the
    /// notification-sent timestamp.
    pub fn confirm_breach(&self, event_id: uuid::Uuid) -> Result<chrono::DateTime<chrono::Utc>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner
            .breach_detector
            .confirm(event_id)
            .map_err(|e| KimberliteError::internal(format!("breach confirm failed: {e}")))?;
        // BreachDetector stamps its own notification_sent timestamp;
        // expose "now" at the tenant boundary as a good-enough
        // approximation for wire responses. BreachDetector owns the
        // authoritative time on the event itself.
        Ok(chrono::Utc::now())
    }

    /// Transition a breach event to `Resolved` with a remediation note.
    pub fn resolve_breach(
        &self,
        event_id: uuid::Uuid,
        remediation: &str,
    ) -> Result<chrono::DateTime<chrono::Utc>> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        inner
            .breach_detector
            .resolve(event_id, remediation)
            .map_err(|e| KimberliteError::internal(format!("breach resolve failed: {e}")))?;
        Ok(chrono::Utc::now())
    }

    // =========================================================================
    // Data Portability Export (GDPR Article 20)
    // =========================================================================

    /// Exports all data for a subject in the specified format.
    ///
    /// # Compliance
    ///
    /// - **GDPR Article 20**: Right to data portability
    pub fn export_subject_data(
        &self,
        subject_id: &str,
        records: &[kimberlite_compliance::export::ExportRecord],
        format: kimberlite_compliance::export::ExportFormat,
        requester_id: &str,
    ) -> Result<kimberlite_compliance::export::PortabilityExport> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let export = inner
            .export_engine
            .export_subject_data(subject_id, records, format, requester_id)
            .map_err(|e| KimberliteError::internal(format!("Export failed: {e}")))?;

        tracing::info!(
            tenant_id = %self.tenant_id,
            subject_id = %subject_id,
            export_id = %export.export_id,
            record_count = export.record_count,
            "Subject data exported"
        );

        Ok(export)
    }

    /// Collect every projection row across this tenant's tables whose
    /// `subject_column` cell equals `subject_id`, rendered as
    /// [`ExportRecord`](kimberlite_compliance::export::ExportRecord)s ready
    /// for `export_subject_data_with_body`.
    ///
    /// The column name is configurable for apps that don't use the
    /// convention `subject_id`; the default matches the erasure executor
    /// (`DEFAULT_SUBJECT_COLUMN`). Stream restriction: when `stream_ids`
    /// is non-empty, only records from those streams are included.
    /// `max_records_per_stream` bounds work per stream to prevent a
    /// single malicious subject scan from running unbounded under DoS.
    ///
    /// ROADMAP v0.5.0 item C — "Phase 6 compliance-endpoint server
    /// handlers".
    pub fn collect_subject_export_records(
        &self,
        subject_id: &str,
        subject_column: &str,
        stream_ids: &[kimberlite_types::StreamId],
        max_records_per_stream: u64,
    ) -> Result<Vec<kimberlite_compliance::export::ExportRecord>> {
        use kimberlite_store::{Key, TableId as StoreTableId};

        // Write lock needed because ProjectionStore::scan takes &mut self
        // (it advances iterator bookkeeping inside the store). The caller
        // is a read-only operation at the SQL level, so the lock scope is
        // kept tight — we drop it as soon as rows are collected.
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let stream_filter: std::collections::HashSet<kimberlite_types::StreamId> =
            stream_ids.iter().copied().collect();
        let apply_stream_filter = !stream_filter.is_empty();
        // Upper bound per stream; `0` == unbounded, capped by
        // ProjectionStore's internal MAX to keep the scan deterministic.
        let per_stream_cap = if max_records_per_stream == 0 {
            u64::MAX
        } else {
            max_records_per_stream
        };
        let now = chrono::Utc::now();

        let mut out: Vec<kimberlite_compliance::export::ExportRecord> = Vec::new();

        // Snapshot the (table_id, stream_id, table_name) tuples before we
        // start mutating the projection store. tables() hands out borrows
        // into kernel_state; scan() needs &mut on projection_store which
        // is in the same struct — the two borrows conflict without this
        // copy step.
        let snapshot: Vec<(
            kimberlite_kernel::command::TableId,
            kimberlite_types::StreamId,
            String,
        )> = inner
            .kernel_state
            .tables()
            .iter()
            .filter(|(_, m)| m.tenant_id == self.tenant_id)
            .filter(|(_, m)| !apply_stream_filter || stream_filter.contains(&m.stream_id))
            .map(|(id, m)| (*id, m.stream_id, m.table_name.clone()))
            .collect();

        for (table_id, stream_id, stream_name) in snapshot {
            let pairs = inner
                .projection_store
                .scan(
                    StoreTableId::new(table_id.0),
                    Key::min()..Key::max(),
                    per_stream_cap.min(u64::from(u32::MAX)) as usize,
                )
                .map_err(|e| KimberliteError::internal(format!("projection scan failed: {e}")))?;
            for (_pk, row_bytes) in pairs {
                let row: serde_json::Value = match serde_json::from_slice(&row_bytes) {
                    Ok(v) => v,
                    Err(_) => continue, // Skip malformed rows rather than fail the export.
                };
                let subject_matches = row
                    .as_object()
                    .and_then(|obj| obj.get(subject_column))
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == subject_id);
                if !subject_matches {
                    continue;
                }
                out.push(kimberlite_compliance::export::ExportRecord {
                    stream_id,
                    stream_name: stream_name.clone(),
                    offset: 0, // Exported rows carry the projection row; offset
                    // is not reconstructable from MVCC without an
                    // extra lookup. v0.6.0 can extend this.
                    data: row,
                    timestamp: now,
                });
            }
        }
        Ok(out)
    }

    /// Like [`export_subject_data`](Self::export_subject_data) but also
    /// returns the serialised body bytes for wire transmission.
    ///
    /// ROADMAP v0.5.0 item C — "Phase 6 compliance-endpoint server
    /// handlers". The Phase 6 `ExportSubject` handler needs the body
    /// bytes to base64-encode into `PortabilityExportInfo::body_base64`.
    pub fn export_subject_data_with_body(
        &self,
        subject_id: &str,
        records: &[kimberlite_compliance::export::ExportRecord],
        format: kimberlite_compliance::export::ExportFormat,
        requester_id: &str,
    ) -> Result<(kimberlite_compliance::export::PortabilityExport, Vec<u8>)> {
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let (export, body) = inner
            .export_engine
            .export_subject_data_with_body(subject_id, records, format, requester_id)
            .map_err(|e| KimberliteError::internal(format!("Export failed: {e}")))?;

        Ok((export, body))
    }

    // =========================================================================
    // Compliance Audit Log (SOC2 CC7.2, ISO 27001 A.12.4.1)
    // =========================================================================

    /// Appends an event to the compliance audit log.
    ///
    /// AUDIT-2026-04 L-2: `actor: None` produces an `Actor::Anonymous`
    /// event, which is forensically noisy — prefer
    /// [`audit_log_append_with_actor`](Self::audit_log_append_with_actor)
    /// where the caller can name a [`kimberlite_compliance::audit::Actor`]
    /// variant (typically `System(...)` for scheduled jobs).
    ///
    /// # Compliance
    ///
    /// - **SOC2 CC7.2**: Comprehensive audit trails
    /// - **ISO 27001 A.12.4.1**: Event logging
    pub fn audit_log_append(
        &self,
        action: kimberlite_compliance::audit::ComplianceAuditAction,
        actor: Option<&str>,
    ) -> Result<uuid::Uuid> {
        use kimberlite_compliance::audit::Actor;
        let typed = actor.map_or(Actor::Anonymous, |s| Actor::Authenticated(s.to_string()));
        self.audit_log_append_with_actor(action, typed)
    }

    /// Typed variant of [`audit_log_append`](Self::audit_log_append).
    ///
    /// AUDIT-2026-04 L-2 / L-6: preferred entry point for new code.
    /// The scope is fixed to this tenant — a call on `TenantHandle`
    /// cannot produce `Scope::Global` or `Scope::System` rows by
    /// construction.
    pub fn audit_log_append_with_actor(
        &self,
        action: kimberlite_compliance::audit::ComplianceAuditAction,
        actor: kimberlite_compliance::audit::Actor,
    ) -> Result<uuid::Uuid> {
        use kimberlite_compliance::audit::Scope;
        let mut inner = self
            .db
            .inner()
            .write()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let event_id =
            inner
                .audit_log
                .append_with_actor(action, actor, Scope::Tenant(self.tenant_id));

        Ok(event_id)
    }

    /// Queries the compliance audit log with filters.
    pub fn audit_log_query(
        &self,
        filter: &kimberlite_compliance::audit::AuditQuery,
    ) -> Result<Vec<uuid::Uuid>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;

        let events: Vec<uuid::Uuid> = inner
            .audit_log
            .query(filter)
            .iter()
            .map(|e| e.event_id)
            .collect();

        Ok(events)
    }

    /// Walk the compliance audit log's SHA-256 hash chain end-to-end
    /// and return a structured verification report. v0.8.0 — replaces
    /// the previous TS/Python/Rust client-side stubs with a real
    /// server-walked attestation.
    ///
    /// On success, returns `(event_count, chain_head)` so the caller
    /// can stamp the result into a regulator-visible report. On
    /// failure, returns an
    /// [`kimberlite_compliance::audit::AuditChainError`] that names the
    /// earliest broken event.
    /// Returns the hex-encoded SHA-256 chain head of the compliance
    /// audit log. v0.8.0 — paired with [`Self::audit_log_verify_chain`].
    /// Always succeeds; an empty log returns `"00" * 32`.
    pub fn audit_log_chain_head_hex(&self) -> String {
        let inner = match self.db.inner().read() {
            Ok(g) => g,
            Err(_) => return "0".repeat(64),
        };
        use std::fmt::Write as _;
        let head = inner.audit_log.chain_head();
        let mut s = String::with_capacity(64);
        for byte in head.iter() {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }

    pub fn audit_log_verify_chain(
        &self,
    ) -> std::result::Result<(u64, [u8; 32]), kimberlite_compliance::audit::AuditChainError> {
        let inner = match self.db.inner().read() {
            Ok(g) => g,
            Err(_) => return Err(kimberlite_compliance::audit::AuditChainError::ChainHeadMismatch),
        };
        inner.audit_log.verify_chain()?;
        let count = inner
            .audit_log
            .query(&kimberlite_compliance::audit::AuditQuery {
                tenant_id: Some(u64::from(self.tenant_id)),
                ..Default::default()
            })
            .len() as u64;
        Ok((count, inner.audit_log.chain_head()))
    }

    /// Resolve a list of event IDs to full
    /// [`kimberlite_compliance::audit::ComplianceAuditEvent`] records.
    ///
    /// Used by the Phase 6 `AuditQuery` server handler (ROADMAP v0.5.0
    /// item C) to return the hash-chained event payloads — not just IDs —
    /// over the wire. IDs not found are skipped silently rather than
    /// erroring; the caller controls the filter that produced the list.
    pub fn audit_log_get_events(
        &self,
        ids: &[uuid::Uuid],
    ) -> Result<Vec<kimberlite_compliance::audit::ComplianceAuditEvent>> {
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(ev) = inner.audit_log.get_event(*id) {
                out.push(ev.clone());
            }
        }
        Ok(out)
    }

    /// Verify an export's integrity: look up the export by id, compute the
    /// SHA-256 of the supplied body, and compare. Returns
    /// `(content_valid, signature_valid)`. ROADMAP v0.5.0 item C.
    ///
    /// `content_valid` is `true` iff the caller's body hashes to the
    /// export's recorded `content_hash`. `signature_valid` is `true` iff
    /// the export carried an HMAC signature that verifies over the
    /// supplied body; `false` when no signing key was configured at
    /// export time (signature-less exports aren't invalid — they just
    /// lack authenticity proof beyond the content hash).
    pub fn verify_subject_export(
        &self,
        export_id: uuid::Uuid,
        body: &[u8],
    ) -> Result<(bool, bool)> {
        use kimberlite_compliance::export::ExportEngine;
        let inner = self
            .db
            .inner()
            .read()
            .map_err(|_| KimberliteError::internal("lock poisoned"))?;
        let export = inner
            .export_engine
            .get_export(export_id)
            .ok_or_else(|| KimberliteError::internal(format!("export {export_id} not found")))?;
        let recomputed = ExportEngine::compute_content_hash(body);
        let content_valid = recomputed == export.content_hash;
        let signature_valid = export.signature.as_ref().is_some_and(|_| {
            // With no HMAC signing key material plumbed through the
            // server today, we conservatively report false. When the
            // signing key wiring lands in v0.6.0, this branch verifies
            // the HMAC.
            false
        });
        Ok((content_valid, signature_valid))
    }
}

/// Validates that all specified columns exist in the table schema.
fn validate_columns_exist(
    columns: &[String],
    table_columns: &[kimberlite_kernel::command::ColumnDefinition],
) -> Result<()> {
    for col_name in columns {
        if !table_columns.iter().any(|c| &c.name == col_name) {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::ParseError(format!(
                    "column '{col_name}' does not exist in table"
                )),
            ));
        }
    }
    Ok(())
}

/// Validates that values match their column types and constraints.
fn validate_insert_values(
    column_names: &[String],
    values: &[Value],
    table_columns: &[kimberlite_kernel::command::ColumnDefinition],
    primary_key_cols: &[String],
) -> Result<()> {
    for (col_name, value) in column_names.iter().zip(values.iter()) {
        // Find the column definition
        let col_def = table_columns
            .iter()
            .find(|c| &c.name == col_name)
            .ok_or_else(|| {
                KimberliteError::Query(kimberlite_query::QueryError::ParseError(format!(
                    "column '{col_name}' not found in table schema"
                )))
            })?;

        // Check NOT NULL constraint
        if !col_def.nullable && value.is_null() {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::TypeMismatch {
                    expected: format!("non-NULL value for column '{col_name}'"),
                    actual: "NULL".to_string(),
                },
            ));
        }

        // Check primary key NULL constraint
        if primary_key_cols.contains(col_name) && value.is_null() {
            return Err(KimberliteError::Query(
                kimberlite_query::QueryError::TypeMismatch {
                    expected: format!("non-NULL value for primary key column '{col_name}'"),
                    actual: "NULL".to_string(),
                },
            ));
        }

        // Type validation (basic check - NULL is compatible with any type)
        if !value.is_null() {
            let expected_type = match col_def.data_type.as_str() {
                "BIGINT" => Some(kimberlite_query::DataType::BigInt),
                "TEXT" => Some(kimberlite_query::DataType::Text),
                "BOOLEAN" => Some(kimberlite_query::DataType::Boolean),
                "TIMESTAMP" => Some(kimberlite_query::DataType::Timestamp),
                "BYTES" => Some(kimberlite_query::DataType::Bytes),
                _ => None,
            };

            if let Some(expected) = expected_type {
                if !value.is_compatible_with(expected) {
                    return Err(KimberliteError::Query(
                        kimberlite_query::QueryError::TypeMismatch {
                            expected: format!("{expected:?} for column '{col_name}'"),
                            actual: format!("{:?}", value.data_type()),
                        },
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Converts a predicate to a JSON-serializable format.
#[allow(dead_code)]
fn predicate_to_json(
    pred: &kimberlite_query::Predicate,
    params: &[Value],
) -> Result<serde_json::Value> {
    use kimberlite_query::{Predicate, PredicateValue};

    let (op, col, values) = match pred {
        Predicate::Eq(col, val) => ("eq", col.as_str(), vec![val]),
        Predicate::Lt(col, val) => ("lt", col.as_str(), vec![val]),
        Predicate::Le(col, val) => ("le", col.as_str(), vec![val]),
        Predicate::Gt(col, val) => ("gt", col.as_str(), vec![val]),
        Predicate::Ge(col, val) => ("ge", col.as_str(), vec![val]),
        Predicate::In(col, vals) => ("in", col.as_str(), vals.iter().collect()),
        Predicate::NotIn(col, vals) => ("not_in", col.as_str(), vals.iter().collect()),
        Predicate::NotBetween(col, low, high) => ("not_between", col.as_str(), vec![low, high]),
        Predicate::ScalarCmp { op, .. } => {
            // Scalar-expression comparisons don't fit the column/values
            // shape of the audit record — emit a structural placeholder
            // so audit logs are still valid JSON.
            return Ok(serde_json::json!({
                "op": "scalar_cmp",
                "cmp": format!("{:?}", op),
            }));
        }
        Predicate::Like(col, pattern) => {
            // Convert LIKE pattern to PredicateValue::String for processing
            return Ok(serde_json::json!({
                "op": "like",
                "column": col.as_str(),
                "pattern": pattern,
            }));
        }
        Predicate::NotLike(col, pattern) => {
            return Ok(serde_json::json!({
                "op": "not_like",
                "column": col.as_str(),
                "pattern": pattern,
            }));
        }
        Predicate::ILike(col, pattern) => {
            return Ok(serde_json::json!({
                "op": "ilike",
                "column": col.as_str(),
                "pattern": pattern,
            }));
        }
        Predicate::NotILike(col, pattern) => {
            return Ok(serde_json::json!({
                "op": "not_ilike",
                "column": col.as_str(),
                "pattern": pattern,
            }));
        }
        Predicate::IsNull(col) => {
            return Ok(serde_json::json!({
                "op": "is_null",
                "column": col.as_str(),
            }));
        }
        Predicate::IsNotNull(col) => {
            return Ok(serde_json::json!({
                "op": "is_not_null",
                "column": col.as_str(),
            }));
        }
        Predicate::Or(left_preds, right_preds) => {
            // Recursively convert OR predicates
            let left_json: Result<Vec<serde_json::Value>> = left_preds
                .iter()
                .map(|p| predicate_to_json(p, params))
                .collect();
            let right_json: Result<Vec<serde_json::Value>> = right_preds
                .iter()
                .map(|p| predicate_to_json(p, params))
                .collect();

            return Ok(serde_json::json!({
                "op": "or",
                "left": left_json?,
                "right": right_json?,
            }));
        }
        Predicate::JsonExtractEq {
            column,
            path,
            as_text,
            value,
        } => {
            return Ok(serde_json::json!({
                "op": if *as_text { "json_extract_text_eq" } else { "json_extract_eq" },
                "column": column.as_str(),
                "path": path,
                "value": format!("{value:?}"),
            }));
        }
        Predicate::JsonContains { column, value } => {
            return Ok(serde_json::json!({
                "op": "json_contains",
                "column": column.as_str(),
                "value": format!("{value:?}"),
            }));
        }
        Predicate::InSubquery { column, .. } => {
            return Ok(serde_json::json!({
                "op": "in_subquery",
                "column": column.as_str(),
            }));
        }
        Predicate::Exists { negated, .. } => {
            return Ok(serde_json::json!({
                "op": if *negated { "not_exists" } else { "exists" },
            }));
        }
        Predicate::Always(b) => {
            return Ok(serde_json::json!({
                "op": if *b { "always_true" } else { "always_false" },
            }));
        }
    };

    // Convert predicate values to actual values (binding parameters)
    let bound_values: Result<Vec<serde_json::Value>> = values
        .into_iter()
        .map(|pv| {
            let val = match pv {
                PredicateValue::Int(n) => Value::BigInt(*n),
                PredicateValue::String(s) => Value::Text(s.clone()),
                PredicateValue::Bool(b) => Value::Boolean(*b),
                PredicateValue::Null => Value::Null,
                PredicateValue::Literal(v) => v.clone(),
                PredicateValue::Param(idx) => {
                    if *idx == 0 || *idx > params.len() {
                        return Err(KimberliteError::Query(
                            kimberlite_query::QueryError::ParseError(format!(
                                "parameter ${idx} out of bounds (have {} parameters)",
                                params.len()
                            )),
                        ));
                    }
                    params[idx - 1].clone()
                }
                PredicateValue::ColumnRef(_) => {
                    return Err(KimberliteError::Query(
                        kimberlite_query::QueryError::UnsupportedFeature(
                            "column references not supported in RETURNING clause".to_string(),
                        ),
                    ));
                }
            };
            Ok(value_to_json(&val))
        })
        .collect();

    Ok(json!({
        "op": op,
        "column": col,
        "values": bound_values?,
    }))
}

/// Binds parameters to placeholders in a list of values.
///
/// Replaces all `Value::Placeholder(idx)` with the corresponding value from `params`.
/// Parameter indices are 1-indexed (i.e., $1, $2, ...).
///
/// # Errors
///
/// Returns an error if:
/// - A placeholder index is out of bounds
/// - Parameter count doesn't match placeholder count
fn bind_parameters(values: &[Value], params: &[Value]) -> Result<Vec<Value>> {
    let mut bound = Vec::with_capacity(values.len());

    for value in values {
        match value {
            Value::Placeholder(idx) => {
                // Parameter indices are 1-indexed ($1, $2, ...)
                if *idx == 0 || *idx > params.len() {
                    return Err(KimberliteError::Query(
                        kimberlite_query::QueryError::ParseError(format!(
                            "parameter ${idx} out of bounds (have {} parameters)",
                            params.len()
                        )),
                    ));
                }
                // idx is 1-indexed, so subtract 1 for array access
                bound.push(params[idx - 1].clone());
            }
            other => bound.push(other.clone()),
        }
    }

    Ok(bound)
}

/// Converts a `Value` to a `serde_json::Value`.
///
/// # Panics
///
/// Panics if the value is a `Placeholder` (should be bound before conversion).
fn value_to_json(val: &Value) -> serde_json::Value {
    // Use the Value::to_json() method which handles all types
    val.to_json()
}

/// Converts a JSON value to a `kimberlite_query::Value`.
/// Makes reasonable assumptions about types (e.g., numbers become `BigInt`).
fn json_to_value(json: &serde_json::Value) -> Result<Value> {
    match json {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Bool(b) => Ok(Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            // Try i64 first (BigInt), then f64 (Real)
            if let Some(i) = n.as_i64() {
                Ok(Value::BigInt(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Real(f))
            } else {
                Err(KimberliteError::internal(format!(
                    "Unsupported number type: {n}"
                )))
            }
        }
        serde_json::Value::String(s) => {
            // Could be Text, Bytes (base64), UUID, or Decimal
            // For simplicity, assume Text
            Ok(Value::Text(s.clone()))
        }
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            // Assume JSON type
            Ok(Value::Json(json.clone()))
        }
    }
}

/// Applies `mask` to `value` and returns a `Value` that preserves the
/// source type where the masking strategy allows.
///
/// - `MaskingStrategy::Null` → `Value::Null` (typed null, not an empty
///   `Value::Text`).
/// - `MaskingStrategy::Truncate { .. }` → preserves `Value::BigInt` /
///   `Value::Integer` / `Value::SmallInt` / `Value::TinyInt` /
///   `Value::Real` when the truncated text round-trips through the
///   corresponding numeric parse. A lossy truncation (e.g. truncating a
///   large int to fewer digits) that no longer parses back is demoted
///   to `Value::Text` rather than silently producing a wrong number.
/// - `MaskingStrategy::Redact` / `Hash` / `Tokenize` → `Value::Text`.
///   These strategies intrinsically yield strings.
///
/// AUDIT-2026-04 L-1: the previous implementation converted every
/// masked cell to `Value::Text` unconditionally, breaking typed SDK
/// deserialisation on otherwise-safe strategies.
fn apply_mask_preserving_type(
    value: &Value,
    mask: &kimberlite_rbac::masking::FieldMask,
    role: kimberlite_rbac::Role,
) -> std::result::Result<Value, kimberlite_rbac::masking::MaskingError> {
    use kimberlite_rbac::masking::{MaskingStrategy, apply_mask};

    // Null strategy collapses to a typed Null regardless of source type.
    if matches!(mask.strategy, MaskingStrategy::Null) {
        return Ok(Value::Null);
    }

    let value_bytes = value.to_string().into_bytes();
    let masked = apply_mask(&value_bytes, mask, &role)?;
    let masked_str = String::from_utf8_lossy(&masked).to_string();

    // Truncate keeps the source type when the truncated text parses
    // back cleanly. Any parse failure degrades to Value::Text so we
    // don't smuggle a wrong numeric value through the pipeline.
    if matches!(mask.strategy, MaskingStrategy::Truncate { .. }) {
        return Ok(match value {
            Value::TinyInt(_) => masked_str
                .parse::<i8>()
                .map_or_else(|_| Value::Text(masked_str.clone()), Value::TinyInt),
            Value::SmallInt(_) => masked_str
                .parse::<i16>()
                .map_or_else(|_| Value::Text(masked_str.clone()), Value::SmallInt),
            Value::Integer(_) => masked_str
                .parse::<i32>()
                .map_or_else(|_| Value::Text(masked_str.clone()), Value::Integer),
            Value::BigInt(_) => masked_str
                .parse::<i64>()
                .map_or_else(|_| Value::Text(masked_str.clone()), Value::BigInt),
            Value::Real(_) => masked_str
                .parse::<f64>()
                .map_or_else(|_| Value::Text(masked_str.clone()), Value::Real),
            _ => Value::Text(masked_str),
        });
    }

    // Redact, Hash, Tokenize → string by construction.
    Ok(Value::Text(masked_str))
}

/// Applies SQL-level masks (from `CREATE MASK` statements) to query results.
///
/// For each mask, finds matching columns in the result and replaces their
/// values with the masked representation (e.g. "****" for REDACT).
///
/// AUDIT-2026-04 M-7: masks are keyed on the mask entry's source column
/// name. When the caller supplies the parsed SQL, `column_aliases`
/// resolves each result-set column back to its source identifier so
/// that `SELECT ssn AS id FROM patients` still masks the `ssn` column
/// under its alias `id`. When no alias map is available (e.g. an
/// internal call that re-parsing would be wasteful for) the function
/// falls back to keying on the output column name — the pre-M-7 shape.
fn apply_sql_masks(
    result: &mut QueryResult,
    masks: &std::collections::HashMap<String, crate::kimberlite::MaskEntry>,
    sql: &str,
) {
    use kimberlite_rbac::masking::FieldMask;
    use kimberlite_rbac::roles::Role;

    // Resolve (output → source) aliases from the SQL so aliased
    // sensitive columns still hit their mask. Parse failures fall back
    // to identity keying — the engine already parsed this SQL
    // successfully to produce `result`, so a parse failure here is
    // unusual and the fall-through preserves pre-M-7 behaviour rather
    // than dropping masks.
    let alias_map: std::collections::HashMap<String, String> = {
        let dialect = sqlparser::dialect::GenericDialect {};
        sqlparser::parser::Parser::parse_sql(&dialect, sql)
            .ok()
            .and_then(|mut stmts| stmts.pop())
            .map(|stmt| kimberlite_query::rbac_filter::column_aliases(&stmt))
            .unwrap_or_default()
            .into_iter()
            .collect()
    };

    // Build column index: mask entry → (position, source column)
    let col_positions: Vec<(usize, &crate::kimberlite::MaskEntry)> = masks
        .values()
        .filter_map(|entry| {
            result
                .columns
                .iter()
                .position(|c| {
                    let out = c.as_str();
                    let src = alias_map.get(out).map_or(out, String::as_str);
                    src == entry.column_name
                })
                .map(|pos| (pos, entry))
        })
        .collect();

    if col_positions.is_empty() {
        return;
    }

    for row in &mut result.rows {
        for &(pos, entry) in &col_positions {
            if pos < row.len() {
                // `try_new` skips the row if the column name was somehow
                // stored empty (defence-in-depth — the policy loader should
                // have already rejected it).
                let Ok(field_mask) = FieldMask::try_new(&entry.column_name, entry.strategy.clone())
                else {
                    continue;
                };
                // AUDIT-2026-04 L-1: keep `Truncate` on integers and
                // reals typed, and collapse `Null` to `Value::Null`
                // rather than an empty `Value::Text`.
                if let Ok(masked) = apply_mask_preserving_type(&row[pos], &field_mask, Role::User) {
                    row[pos] = masked;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_tenant_create_stream() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let stream_id = tenant.create_stream("test", DataClass::Public).unwrap();
        let stream_id_val: u64 = stream_id.into();
        assert!(stream_id_val > 0);
    }

    #[test]
    fn test_create_stream_is_idempotent_by_name() {
        // Regression: before this, a second `create_stream(same_name, …)`
        // raised StreamAlreadyExists even though the caller's intent was
        // clearly "ensure this stream exists." Repeatable bootstrap is
        // load-bearing for every app that creates streams on startup.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let first = tenant
            .create_stream("patient_events", DataClass::PHI)
            .unwrap();
        let second = tenant
            .create_stream("patient_events", DataClass::PHI)
            .unwrap();
        assert_eq!(first, second, "same-name create must return the same id");
    }

    #[test]
    fn test_create_stream_allocates_unique_ids_per_name() {
        // Regression: the previous impl hard-coded `local_id=1` so every
        // stream after the first in a tenant collided on StreamAlreadyExists.
        // Notebar has ~10 streams per tenant (patient_events, appointment_events,
        // invoice_events, …) and cannot boot without this.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let a = tenant
            .create_stream("patient_events", DataClass::PHI)
            .unwrap();
        let b = tenant
            .create_stream("appointment_events", DataClass::PHI)
            .unwrap();
        let c = tenant
            .create_stream("invoice_events", DataClass::Financial)
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_create_stream_name_idempotence_is_per_tenant() {
        // A stream named 'foo' in tenant 1 must not cause
        // `create_stream("foo", …)` in tenant 2 to short-circuit to tenant 1's id.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();

        let t1 = db.tenant(TenantId::new(1));
        let t2 = db.tenant(TenantId::new(2));

        let a = t1.create_stream("foo", DataClass::Public).unwrap();
        let b = t2.create_stream("foo", DataClass::Public).unwrap();
        assert_ne!(a, b);
        assert_eq!(TenantId::from_stream_id(a), TenantId::new(1));
        assert_eq!(TenantId::from_stream_id(b), TenantId::new(2));
    }

    #[test]
    fn test_tenant_append_and_read() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let stream_id = tenant.create_stream("events", DataClass::Public).unwrap();

        // Append events
        tenant
            .append(
                stream_id,
                vec![b"event1".to_vec(), b"event2".to_vec()],
                Offset::ZERO,
            )
            .unwrap();

        // Read back
        let events = tenant
            .read_events(stream_id, Offset::ZERO, 1024 * 1024_u64)
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(&events[0][..], b"event1");
        assert_eq!(&events[1][..], b"event2");
    }

    #[test]
    fn test_tenant_create_table_via_sql() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Execute CREATE TABLE - should succeed without error
        let result = tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // DDL doesn't affect rows
        assert_eq!(result.rows_affected(), 0);
    }

    #[test]
    fn test_create_table_if_not_exists_is_idempotent() {
        // Regression: without IF-NOT-EXISTS support, the second
        // `CREATE TABLE IF NOT EXISTS` call hit `StreamAlreadyExists`, which
        // forced every client (including healthcare app schema bootstraps)
        // to track created-tables externally or wrap in ugly try/catch.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let sql = "CREATE TABLE IF NOT EXISTS users \
                   (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))";

        tenant.execute(sql, &[]).expect("first create must succeed");
        tenant
            .execute(sql, &[])
            .expect("second create with IF NOT EXISTS must succeed (idempotent)");

        // Confirm the table is usable after the no-op create.
        let insert = tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();
        assert_eq!(insert.rows_affected(), 1);
    }

    #[test]
    fn test_create_table_without_if_not_exists_still_errors() {
        // Regression guard: a plain `CREATE TABLE` on an existing table
        // must keep erroring — we're fixing IF NOT EXISTS, not weakening
        // the default contract.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let sql = "CREATE TABLE users \
                   (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))";

        tenant.execute(sql, &[]).expect("first create must succeed");
        let second = tenant.execute(sql, &[]);
        assert!(
            second.is_err(),
            "bare CREATE TABLE on existing table should still error, got {second:?}",
        );
    }

    #[test]
    fn test_tenant_insert_via_sql() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table first
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert row
        let result = tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        assert_eq!(result.rows_affected(), 1);
        assert!(result.log_offset().as_u64() > 0);
    }

    #[test]
    fn test_tenant_execute_rejects_select() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // SELECT should be rejected by execute()
        let result = tenant.execute("SELECT * FROM users", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_tenant_insert_and_query() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert rows
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        tenant
            .execute("INSERT INTO users (id, name) VALUES (2, 'Bob')", &[])
            .unwrap();

        // Query the data back
        let result = tenant.query("SELECT * FROM users ORDER BY id", &[]);

        match result {
            Ok(qr) => {
                // Verify we got the rows back
                assert_eq!(qr.rows.len(), 2, "should have 2 rows");

                // Check column names
                assert_eq!(qr.columns.len(), 2);
                assert_eq!(qr.columns[0].as_str(), "id");
                assert_eq!(qr.columns[1].as_str(), "name");

                // Check first row
                assert_eq!(qr.rows[0][0], Value::BigInt(1));
                assert_eq!(qr.rows[0][1], Value::Text("Alice".to_string()));

                // Check second row
                assert_eq!(qr.rows[1][0], Value::BigInt(2));
                assert_eq!(qr.rows[1][1], Value::Text("Bob".to_string()));
            }
            Err(e) => {
                panic!("Query failed: {e}");
            }
        }
    }

    #[test]
    fn test_query_with_where_clause() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert rows
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        tenant
            .execute("INSERT INTO users (id, name) VALUES (2, 'Bob')", &[])
            .unwrap();

        // Query with WHERE clause
        let result = tenant
            .query("SELECT name FROM users WHERE id = 2", &[])
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0], Value::Text("Bob".to_string()));
    }

    #[test]
    fn test_query_select_specific_columns() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with multiple columns
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, age BIGINT, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert row
        tenant
            .execute(
                "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 30)",
                &[],
            )
            .unwrap();

        // Query specific columns
        let result = tenant
            .query("SELECT name, age FROM users WHERE id = 1", &[])
            .unwrap();

        assert_eq!(result.columns.len(), 2);
        assert_eq!(result.columns[0].as_str(), "name");
        assert_eq!(result.columns[1].as_str(), "age");

        assert_eq!(result.rows[0][0], Value::Text("Alice".to_string()));
        assert_eq!(result.rows[0][1], Value::BigInt(30));
    }

    #[test]
    fn test_multiple_table_operations() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create first table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Create second table
        tenant
            .execute(
                "CREATE TABLE orders (order_id BIGINT NOT NULL, user_id BIGINT NOT NULL, amount BIGINT, PRIMARY KEY (order_id))",
                &[],
            )
            .unwrap();

        // Insert into both tables
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        tenant
            .execute(
                "INSERT INTO orders (order_id, user_id, amount) VALUES (100, 1, 5000)",
                &[],
            )
            .unwrap();

        // Verify both tables exist
        // (indirectly verified by successful inserts)
    }

    #[test]
    fn test_create_and_drop_table() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE temp (id BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Drop table
        let result = tenant.execute("DROP TABLE temp", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_duplicate_table_creation_fails() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Try to create same table again
        let result = tenant.execute(
            "CREATE TABLE users (id BIGINT NOT NULL, PRIMARY KEY (id))",
            &[],
        );

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_create_index() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Create index
        let result = tenant.execute("CREATE INDEX idx_name ON users (name)", &[]);
        if let Err(e) = &result {
            eprintln!("CREATE INDEX error: {e:?}");
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_operation() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        // Update
        let result = tenant.execute("UPDATE users SET name = 'Alice Updated' WHERE id = 1", &[]);
        if let Err(ref e) = result {
            eprintln!("UPDATE failed: {e:?}");
        }
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rows_affected(), 1);
    }

    #[test]
    fn test_delete_operation() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        // Delete
        let result = tenant.execute("DELETE FROM users WHERE id = 1", &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rows_affected(), 1);
    }

    #[test]
    fn test_composite_primary_key() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with composite primary key
        tenant
            .execute(
                "CREATE TABLE orders (
                    user_id BIGINT NOT NULL,
                    order_id BIGINT NOT NULL,
                    amount BIGINT,
                    PRIMARY KEY (user_id, order_id)
                )",
                &[],
            )
            .unwrap();

        // Insert with composite key
        let result = tenant.execute(
            "INSERT INTO orders (user_id, order_id, amount) VALUES (1, 100, 5000)",
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_table_requires_primary_key() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Try to create table without PRIMARY KEY
        let result = tenant.execute(
            "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL)",
            &[],
        );

        // Should fail
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("must have a PRIMARY KEY"),
            "Expected PRIMARY KEY error, got: {err_msg}"
        );
    }

    #[test]
    fn test_insert_without_column_names() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE patients (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // INSERT without specifying column names
        tenant
            .execute("INSERT INTO patients VALUES (1, 'Jane Doe')", &[])
            .unwrap();

        // Query the data back
        let result = tenant.query("SELECT * FROM patients", &[]).unwrap();

        // Verify we got the row back with correct values
        assert_eq!(result.rows.len(), 1, "should have 1 row");
        assert_eq!(result.rows[0][0], Value::BigInt(1));
        assert_eq!(result.rows[0][1], Value::Text("Jane Doe".to_string()));
    }

    // ========================================================================
    // Comprehensive Tests for SQL Engine Fixes
    // ========================================================================

    #[test]
    fn test_parameterized_insert() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // INSERT with parameters
        tenant
            .execute(
                "INSERT INTO users (id, name) VALUES ($1, $2)",
                &[Value::BigInt(42), Value::Text("Alice".to_string())],
            )
            .unwrap();

        // Query back
        let result = tenant
            .query("SELECT * FROM users WHERE id = 42", &[])
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0], Value::BigInt(42));
        assert_eq!(result.rows[0][1], Value::Text("Alice".to_string()));
        // Verify no NULL values
        assert!(!result.rows[0].iter().any(kimberlite_query::Value::is_null));
    }

    #[test]
    fn test_update_then_select_roundtrip() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert
        tenant
            .execute("INSERT INTO users VALUES (1, 'Alice')", &[])
            .unwrap();

        // Update
        tenant
            .execute("UPDATE users SET name = 'Bob' WHERE id = 1", &[])
            .unwrap();

        // Query back - should return updated value
        let result = tenant
            .query("SELECT name FROM users WHERE id = 1", &[])
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0], Value::Text("Bob".to_string()));
    }

    #[test]
    fn test_delete_then_select_empty() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert
        tenant
            .execute("INSERT INTO users VALUES (1, 'Alice')", &[])
            .unwrap();

        // Delete
        tenant
            .execute("DELETE FROM users WHERE id = 1", &[])
            .unwrap();

        // Query back - should be empty
        let result = tenant
            .query("SELECT * FROM users WHERE id = 1", &[])
            .unwrap();

        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn test_null_in_not_null_column_rejected() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with NOT NULL constraint
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Try to insert NULL into NOT NULL column
        let result = tenant.execute(
            "INSERT INTO users (id, name) VALUES ($1, $2)",
            &[Value::BigInt(1), Value::Null],
        );

        // Should fail
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("NULL") || err_msg.contains("non-NULL"));
    }

    #[test]
    fn test_null_in_primary_key_rejected() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Try to insert NULL into primary key
        let result = tenant.execute(
            "INSERT INTO users (id, name) VALUES ($1, $2)",
            &[Value::Null, Value::Text("Alice".to_string())],
        );

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_column_name_rejected() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Try to insert into non-existent column
        let result = tenant.execute(
            "INSERT INTO users (id, invalid_column) VALUES (1, 'Alice')",
            &[],
        );

        // Should fail
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid_column") || err_msg.contains("does not exist"));
    }

    #[test]
    fn test_composite_primary_key_update_delete() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with composite primary key
        tenant
            .execute(
                "CREATE TABLE orders (
                    user_id BIGINT NOT NULL,
                    order_id BIGINT NOT NULL,
                    amount BIGINT,
                    PRIMARY KEY (user_id, order_id)
                )",
                &[],
            )
            .unwrap();

        // Insert
        tenant
            .execute(
                "INSERT INTO orders (user_id, order_id, amount) VALUES (1, 100, 5000)",
                &[],
            )
            .unwrap();

        // Update with composite key WHERE clause
        tenant
            .execute(
                "UPDATE orders SET amount = 6000 WHERE user_id = 1 AND order_id = 100",
                &[],
            )
            .unwrap();

        // Verify update
        let result = tenant
            .query(
                "SELECT amount FROM orders WHERE user_id = 1 AND order_id = 100",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0], Value::BigInt(6000));

        // Delete with composite key
        tenant
            .execute(
                "DELETE FROM orders WHERE user_id = 1 AND order_id = 100",
                &[],
            )
            .unwrap();

        // Verify deletion
        let result = tenant
            .query(
                "SELECT * FROM orders WHERE user_id = 1 AND order_id = 100",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn test_tenant_multi_row_insert() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, age BIGINT, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert 3 rows in a single statement
        let result = tenant
            .execute(
                "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 25), (2, 'Bob', 30), (3, 'Charlie', 35)",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows_affected(), 3, "Should insert 3 rows");

        // Verify all rows were inserted
        let query_result = tenant
            .query("SELECT id, name, age FROM users ORDER BY id", &[])
            .unwrap();

        assert_eq!(query_result.rows.len(), 3);
        assert_eq!(query_result.rows[0][0], Value::BigInt(1));
        assert_eq!(query_result.rows[0][1], Value::Text("Alice".to_string()));
        assert_eq!(query_result.rows[0][2], Value::BigInt(25));

        assert_eq!(query_result.rows[1][0], Value::BigInt(2));
        assert_eq!(query_result.rows[1][1], Value::Text("Bob".to_string()));
        assert_eq!(query_result.rows[1][2], Value::BigInt(30));

        assert_eq!(query_result.rows[2][0], Value::BigInt(3));
        assert_eq!(query_result.rows[2][1], Value::Text("Charlie".to_string()));
        assert_eq!(query_result.rows[2][2], Value::BigInt(35));
    }

    #[test]
    fn test_tenant_multi_row_insert_100_rows() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE numbers (id BIGINT NOT NULL, value BIGINT, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Build INSERT with 100 rows
        let mut values = Vec::new();
        for i in 1..=100 {
            values.push(format!("({}, {})", i, i * 10));
        }
        let sql = format!(
            "INSERT INTO numbers (id, value) VALUES {}",
            values.join(", ")
        );

        let result = tenant.execute(&sql, &[]).unwrap();

        assert_eq!(result.rows_affected(), 100, "Should insert 100 rows");

        // Verify count
        let query_result = tenant.query("SELECT COUNT(*) FROM numbers", &[]).unwrap();

        assert_eq!(query_result.rows.len(), 1);
        assert_eq!(query_result.rows[0][0], Value::BigInt(100));
    }

    #[test]
    fn test_duplicate_key_detection() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert first row - should succeed
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        // Insert same id again - should fail with DuplicatePrimaryKey
        let result = tenant.execute("INSERT INTO users (id, name) VALUES (1, 'Bob')", &[]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            KimberliteError::Query(kimberlite_query::QueryError::DuplicatePrimaryKey {
                ref table,
                ref key,
            }) => {
                assert_eq!(table, "users");
                assert_eq!(key, &vec![Value::BigInt(1)]);
            }
            other => panic!("Expected DuplicatePrimaryKey, got {other:?}"),
        }
    }

    #[test]
    fn test_duplicate_key_detection_in_batch() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert first row
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        // Try batch insert with duplicate - should fail on the duplicate
        let result = tenant.execute(
            "INSERT INTO users (id, name) VALUES (2, 'Bob'), (1, 'Duplicate'), (3, 'Charlie')",
            &[],
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            KimberliteError::Query(kimberlite_query::QueryError::DuplicatePrimaryKey {
                ref table,
                ref key,
            }) => {
                assert_eq!(table, "users");
                assert_eq!(key, &vec![Value::BigInt(1)]);
            }
            other => panic!("Expected DuplicatePrimaryKey, got {other:?}"),
        }

        // Verify only the first new row (Bob) was inserted before the error
        let query_result = tenant.query("SELECT COUNT(*) FROM users", &[]).unwrap();

        // Should have Alice (original) + Bob (first in batch before duplicate)
        assert_eq!(query_result.rows[0][0], Value::BigInt(2));
    }

    #[test]
    fn test_multi_row_update_accurate_count() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, status TEXT NOT NULL, age BIGINT, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert multiple rows
        tenant
            .execute(
                "INSERT INTO users (id, status, age) VALUES (1, 'inactive', 25), (2, 'inactive', 30), (3, 'active', 35), (4, 'inactive', 40)",
                &[],
            )
            .unwrap();

        // Update multiple rows - should affect 3 rows with status='inactive'
        let result = tenant
            .execute(
                "UPDATE users SET status = 'active' WHERE status = 'inactive'",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows_affected(), 3, "Should update 3 inactive users");

        // Verify all rows are now active
        let query_result = tenant
            .query("SELECT COUNT(*) FROM users WHERE status = 'active'", &[])
            .unwrap();

        assert_eq!(query_result.rows[0][0], Value::BigInt(4));
    }

    #[test]
    fn test_multi_row_delete_accurate_count() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, age BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert multiple rows
        tenant
            .execute(
                "INSERT INTO users (id, age) VALUES (1, 20), (2, 25), (3, 30), (4, 35), (5, 40)",
                &[],
            )
            .unwrap();

        // Delete rows where age >= 30 - should affect 3 rows
        let result = tenant
            .execute("DELETE FROM users WHERE age >= 30", &[])
            .unwrap();

        assert_eq!(
            result.rows_affected(),
            3,
            "Should delete 3 users with age >= 30"
        );

        // Verify only 2 rows remain
        let query_result = tenant.query("SELECT COUNT(*) FROM users", &[]).unwrap();

        assert_eq!(query_result.rows[0][0], Value::BigInt(2));

        // Verify remaining rows have age < 30
        let query_result = tenant
            .query("SELECT id FROM users ORDER BY id", &[])
            .unwrap();

        assert_eq!(query_result.rows.len(), 2);
        assert_eq!(query_result.rows[0][0], Value::BigInt(1));
        assert_eq!(query_result.rows[1][0], Value::BigInt(2));
    }

    /// Notebar blocker N2 (notebar/docs/operating/kimberlite-upstream-queue.md).
    /// `DELETE FROM <t>` with no WHERE must delete every row and report the
    /// matched count back as `rows_affected`. Before the fix this was
    /// silently a no-op that returned 0.
    #[test]
    fn test_delete_all_rows_no_where_clause() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, age BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO users (id, age) VALUES (1, 20), (2, 25), (3, 30), (4, 35), (5, 40)",
                &[],
            )
            .unwrap();

        let result = tenant.execute("DELETE FROM users", &[]).unwrap();
        assert_eq!(
            result.rows_affected(),
            5,
            "DELETE FROM users with no WHERE must report all 5 rows"
        );

        let count = tenant.query("SELECT COUNT(*) FROM users", &[]).unwrap();
        assert_eq!(
            count.rows[0][0],
            Value::BigInt(0),
            "DELETE FROM users with no WHERE must leave the table empty"
        );
    }

    /// Notebar blocker N3 (notebar/docs/operating/kimberlite-upstream-queue.md).
    /// After `DROP TABLE x; CREATE TABLE x ...` the pre-drop rows must not
    /// reappear under the new catalog entry.
    #[test]
    fn test_drop_then_recreate_table_starts_empty() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob')",
                &[],
            )
            .unwrap();

        tenant.execute("DROP TABLE users", &[]).unwrap();

        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        let count = tenant.query("SELECT COUNT(*) FROM users", &[]).unwrap();
        assert_eq!(
            count.rows[0][0],
            Value::BigInt(0),
            "recreated table must start empty; pre-drop rows leaked"
        );
    }

    /// Notebar blocker N4 (notebar/docs/operating/kimberlite-upstream-queue.md).
    /// `DROP TABLE IF EXISTS missing` must succeed as a no-op rather than
    /// returning TableNotFound.
    #[test]
    fn test_drop_table_if_exists_on_missing_table_is_noop() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let result = tenant.execute("DROP TABLE IF EXISTS missing_table", &[]);
        assert!(
            result.is_ok(),
            "DROP TABLE IF EXISTS on a missing table must be a no-op, got: {result:?}"
        );
    }

    #[test]
    fn test_insert_returning_single_row() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert with RETURNING
        let result = tenant
            .execute(
                "INSERT INTO users (id, name) VALUES (1, 'Alice') RETURNING id, name",
                &[],
            )
            .unwrap();

        // Verify result type
        assert_eq!(result.rows_affected(), 1);
        assert!(result.returned().is_some());

        let returned = result.returned().unwrap();
        assert_eq!(returned.columns.len(), 2);
        assert_eq!(returned.rows.len(), 1);
        assert_eq!(returned.rows[0][0], Value::BigInt(1));
        assert_eq!(returned.rows[0][1], Value::Text("Alice".to_string()));
    }

    #[test]
    fn test_insert_returning_multiple_rows() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Multi-row insert with RETURNING
        let result = tenant
            .execute(
                "INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie') RETURNING id, name",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows_affected(), 3);
        let returned = result.returned().unwrap();
        assert_eq!(returned.rows.len(), 3);

        // Verify each returned row
        assert_eq!(returned.rows[0][0], Value::BigInt(1));
        assert_eq!(returned.rows[0][1], Value::Text("Alice".to_string()));
        assert_eq!(returned.rows[1][0], Value::BigInt(2));
        assert_eq!(returned.rows[1][1], Value::Text("Bob".to_string()));
        assert_eq!(returned.rows[2][0], Value::BigInt(3));
        assert_eq!(returned.rows[2][1], Value::Text("Charlie".to_string()));
    }

    #[test]
    fn test_update_returning() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table and insert data
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, age BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO users (id, name, age) VALUES (1, 'Alice', 25), (2, 'Bob', 30)",
                &[],
            )
            .unwrap();

        // Update with RETURNING
        let result = tenant
            .execute(
                "UPDATE users SET age = 26 WHERE id = 1 RETURNING id, name, age",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows_affected(), 1);
        let returned = result.returned().unwrap();
        assert_eq!(returned.rows.len(), 1);

        // Verify returned row has updated value
        assert_eq!(returned.rows[0][0], Value::BigInt(1));
        assert_eq!(returned.rows[0][1], Value::Text("Alice".to_string()));
        assert_eq!(returned.rows[0][2], Value::BigInt(26)); // Updated age
    }

    #[test]
    fn test_delete_returning() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table and insert data
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie')",
                &[],
            )
            .unwrap();

        // Delete with RETURNING
        let result = tenant
            .execute(
                "DELETE FROM users WHERE id IN (1, 2) RETURNING id, name",
                &[],
            )
            .unwrap();

        assert_eq!(result.rows_affected(), 2);
        let returned = result.returned().unwrap();
        assert_eq!(returned.rows.len(), 2);

        // Verify returned deleted rows
        assert_eq!(returned.rows[0][0], Value::BigInt(1));
        assert_eq!(returned.rows[0][1], Value::Text("Alice".to_string()));
        assert_eq!(returned.rows[1][0], Value::BigInt(2));
        assert_eq!(returned.rows[1][1], Value::Text("Bob".to_string()));

        // Verify rows are actually deleted
        let query_result = tenant
            .query("SELECT id FROM users ORDER BY id", &[])
            .unwrap();
        assert_eq!(query_result.rows.len(), 1); // Only Charlie remains
        assert_eq!(query_result.rows[0][0], Value::BigInt(3));
    }

    #[test]
    fn test_returning_partial_columns() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create table with multiple columns
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, age BIGINT NOT NULL, email TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert with RETURNING only some columns
        let result = tenant
            .execute(
                "INSERT INTO users (id, name, age, email) VALUES (1, 'Alice', 25, 'alice@example.com') RETURNING id, email",
                &[],
            )
            .unwrap();

        let returned = result.returned().unwrap();
        assert_eq!(returned.columns.len(), 2);
        assert_eq!(returned.rows[0].len(), 2);
        assert_eq!(returned.rows[0][0], Value::BigInt(1));
        assert_eq!(
            returned.rows[0][1],
            Value::Text("alice@example.com".to_string())
        );
    }

    // =========================================================================
    // RBAC End-to-End Tests
    // =========================================================================

    /// Helper: sets up a tenant with a patients table containing test data.
    fn setup_patients_table() -> (tempfile::TempDir, TenantHandle) {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute(
                "CREATE TABLE patients (
                    id BIGINT NOT NULL,
                    name TEXT NOT NULL,
                    ssn TEXT,
                    email TEXT,
                    tenant_id BIGINT NOT NULL,
                    PRIMARY KEY (id)
                )",
                &[],
            )
            .unwrap();

        // Insert test data
        tenant
            .execute(
                "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
                &[
                    Value::BigInt(1),
                    Value::Text("Alice".into()),
                    Value::Text("123-45-6789".into()),
                    Value::Text("alice@example.com".into()),
                    Value::BigInt(1),
                ],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
                &[
                    Value::BigInt(2),
                    Value::Text("Bob".into()),
                    Value::Text("987-65-4321".into()),
                    Value::Text("bob@example.com".into()),
                    Value::BigInt(2),
                ],
            )
            .unwrap();

        (dir, tenant)
    }

    #[test]
    fn test_rbac_admin_reads_all_columns() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::admin();

        let result = tenant
            .query_with_policy("SELECT id, name, ssn FROM patients", &[], &policy)
            .unwrap();

        // Admin sees all columns including SSN
        assert_eq!(result.columns.len(), 3);
        assert!(result.columns.iter().any(|c| c.as_str() == "ssn"));
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn test_rbac_user_gets_row_filter() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::user(TenantId::new(1));

        let result = tenant
            .query_with_policy("SELECT id, name FROM patients", &[], &policy)
            .unwrap();

        // User policy injects WHERE tenant_id = 1, so only tenant 1's rows
        assert_eq!(result.rows.len(), 1);
        // First row should be Alice (tenant_id = 1)
        assert_eq!(result.rows[0][1], Value::Text("Alice".into()));
    }

    #[test]
    fn test_rbac_auditor_stream_restriction() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::auditor();

        // Auditor can only access audit_* streams, so querying patients should fail
        let result = tenant.query_with_policy("SELECT id, name FROM patients", &[], &policy);

        assert!(
            result.is_err(),
            "Auditor should not access non-audit tables"
        );
    }

    #[test]
    fn test_rbac_execute_admin_can_insert() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::admin();

        let result = tenant.execute_with_policy(
            "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
            &[
                Value::BigInt(3),
                Value::Text("Charlie".into()),
                Value::Text("111-22-3333".into()),
                Value::Text("charlie@example.com".into()),
                Value::BigInt(1),
            ],
            &policy,
        );

        assert!(result.is_ok(), "Admin should be able to INSERT");
    }

    #[test]
    fn test_rbac_execute_analyst_cannot_insert() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::analyst();

        let result = tenant.execute_with_policy(
            "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
            &[
                Value::BigInt(3),
                Value::Text("Charlie".into()),
                Value::Text("111-22-3333".into()),
                Value::Text("charlie@example.com".into()),
                Value::BigInt(1),
            ],
            &policy,
        );

        assert!(result.is_err(), "Analyst should not be able to INSERT");
    }

    #[test]
    fn test_rbac_execute_auditor_cannot_write() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::auditor();

        let result = tenant.execute_with_policy(
            "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
            &[
                Value::BigInt(3),
                Value::Text("Charlie".into()),
                Value::Text("111-22-3333".into()),
                Value::Text("charlie@example.com".into()),
                Value::BigInt(1),
            ],
            &policy,
        );

        assert!(result.is_err(), "Auditor should not be able to INSERT");
    }

    #[test]
    fn test_rbac_execute_user_can_insert_cannot_delete() {
        let (_dir, tenant) = setup_patients_table();
        let policy = kimberlite_rbac::StandardPolicies::user(TenantId::new(1));

        // User can INSERT (own data)
        let insert_result = tenant.execute_with_policy(
            "INSERT INTO patients (id, name, ssn, email, tenant_id) VALUES ($1, $2, $3, $4, $5)",
            &[
                Value::BigInt(3),
                Value::Text("Charlie".into()),
                Value::Text("111-22-3333".into()),
                Value::Text("charlie@example.com".into()),
                Value::BigInt(1),
            ],
            &policy,
        );
        assert!(insert_result.is_ok(), "User should be able to INSERT");

        // User cannot DELETE (compliance requirement)
        let delete_result = tenant.execute_with_policy(
            "DELETE FROM patients WHERE id = $1",
            &[Value::BigInt(1)],
            &policy,
        );
        assert!(delete_result.is_err(), "User should not be able to DELETE");
    }

    #[test]
    fn test_rbac_execute_only_admin_can_ddl() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let admin_policy = kimberlite_rbac::StandardPolicies::admin();
        let user_policy = kimberlite_rbac::StandardPolicies::user(TenantId::new(1));
        let analyst_policy = kimberlite_rbac::StandardPolicies::analyst();

        // Admin can CREATE TABLE
        let admin_result = tenant.execute_with_policy(
            "CREATE TABLE admin_table (id BIGINT NOT NULL, PRIMARY KEY (id))",
            &[],
            &admin_policy,
        );
        assert!(admin_result.is_ok(), "Admin should be able to CREATE TABLE");

        // User cannot CREATE TABLE
        let user_result = tenant.execute_with_policy(
            "CREATE TABLE user_table (id BIGINT NOT NULL, PRIMARY KEY (id))",
            &[],
            &user_policy,
        );
        assert!(
            user_result.is_err(),
            "User should not be able to CREATE TABLE"
        );

        // Analyst cannot CREATE TABLE
        let analyst_result = tenant.execute_with_policy(
            "CREATE TABLE analyst_table (id BIGINT NOT NULL, PRIMARY KEY (id))",
            &[],
            &analyst_policy,
        );
        assert!(
            analyst_result.is_err(),
            "Analyst should not be able to CREATE TABLE"
        );
    }

    // =========================================================================
    // Consent Integration Tests
    // =========================================================================

    #[test]
    fn test_consent_grant_and_validate() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        use kimberlite_compliance::purpose::Purpose;

        // Marketing requires consent — validation should fail without consent
        let result = tenant.validate_consent("user@example.com", Purpose::Marketing);
        assert!(result.is_err(), "Should fail without consent");

        // Grant consent
        let consent_id = tenant
            .grant_consent("user@example.com", Purpose::Marketing)
            .unwrap();

        // Now validation should succeed
        let result = tenant.validate_consent("user@example.com", Purpose::Marketing);
        assert!(result.is_ok(), "Should succeed with consent");

        // Withdraw consent
        tenant.withdraw_consent(consent_id).unwrap();

        // Validation should fail again
        let result = tenant.validate_consent("user@example.com", Purpose::Marketing);
        assert!(result.is_err(), "Should fail after withdrawal");
    }

    #[test]
    fn test_consent_not_required_for_legal_obligation() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        use kimberlite_compliance::purpose::Purpose;

        // LegalObligation doesn't require consent
        let result = tenant.validate_consent("user@example.com", Purpose::LegalObligation);
        assert!(result.is_ok(), "LegalObligation should not require consent");
    }

    #[test]
    fn test_consent_not_required_for_public_data() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        use kimberlite_compliance::purpose::Purpose;

        // Security purpose doesn't require explicit consent
        let result = tenant.validate_consent("user@example.com", Purpose::Security);
        assert!(
            result.is_ok(),
            "Security purpose should not require consent"
        );
    }

    #[test]
    fn test_inner_join_execution() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create two tables
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "CREATE TABLE orders (id BIGINT NOT NULL, user_id BIGINT NOT NULL, amount TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert data into users
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        tenant
            .execute("INSERT INTO users (id, name) VALUES (2, 'Bob')", &[])
            .unwrap();

        // Insert data into orders (Alice has 2 orders, Bob has none)
        tenant
            .execute(
                "INSERT INTO orders (id, user_id, amount) VALUES (1, 1, '100.00')",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "INSERT INTO orders (id, user_id, amount) VALUES (2, 1, '200.00')",
                &[],
            )
            .unwrap();

        // Execute INNER JOIN with SELECT *
        let result = tenant.query(
            "SELECT * FROM users JOIN orders ON users.id = orders.user_id",
            &[],
        );

        if let Err(ref e) = result {
            eprintln!("INNER JOIN query failed: {e:?}");
        }
        let result = result.unwrap();

        // Verify results: should have 2 rows (Alice's 2 orders)
        assert_eq!(result.rows.len(), 2, "should have 2 rows from INNER JOIN");

        // Check that we got data from both tables (users: id, name; orders: id, user_id, amount)
        // Each row should have 5 columns total: users.id, users.name, orders.id, orders.user_id, orders.amount
        assert_eq!(result.rows[0].len(), 5, "joined row should have 5 columns");

        // Both rows should be for Alice (user_id=1, name="Alice")
        assert_eq!(result.rows[0][0], Value::BigInt(1)); // users.id
        assert_eq!(result.rows[0][1], Value::Text("Alice".to_string())); // users.name

        assert_eq!(result.rows[1][0], Value::BigInt(1)); // users.id
        assert_eq!(result.rows[1][1], Value::Text("Alice".to_string())); // users.name
    }

    #[test]
    fn test_left_join_with_nulls() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Create two tables
        tenant
            .execute(
                "CREATE TABLE users (id BIGINT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        tenant
            .execute(
                "CREATE TABLE orders (id BIGINT NOT NULL, user_id BIGINT NOT NULL, PRIMARY KEY (id))",
                &[],
            )
            .unwrap();

        // Insert data (Alice has an order, Bob doesn't)
        tenant
            .execute("INSERT INTO users (id, name) VALUES (1, 'Alice')", &[])
            .unwrap();

        tenant
            .execute("INSERT INTO users (id, name) VALUES (2, 'Bob')", &[])
            .unwrap();

        tenant
            .execute("INSERT INTO orders (id, user_id) VALUES (1, 1)", &[])
            .unwrap();

        // Execute LEFT JOIN (without ORDER BY for now - ORDER BY with qualified names not yet supported)
        let result = tenant.query(
            "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id",
            &[],
        );

        if let Err(ref e) = result {
            eprintln!("LEFT JOIN query failed: {e:?}");
        }
        let result = result.unwrap();

        // Verify results: should have 2 rows (Alice + Bob)
        assert_eq!(result.rows.len(), 2, "should have 2 rows from LEFT JOIN");

        // Each row has 5 columns: users.id, users.name, orders.id, orders.user_id (or NULLs)
        // Alice should have a matching order (user_id=1 matches orders.user_id=1)
        assert_eq!(result.rows[0][0], Value::BigInt(1)); // users.id
        assert_eq!(result.rows[0][1], Value::Text("Alice".to_string())); // users.name
        assert_eq!(result.rows[0][2], Value::BigInt(1)); // orders.id
        assert_eq!(result.rows[0][3], Value::BigInt(1)); // orders.user_id

        // Bob should have NULLs for order columns (user_id=2 has no matching orders)
        assert_eq!(result.rows[1][0], Value::BigInt(2)); // users.id
        assert_eq!(result.rows[1][1], Value::Text("Bob".to_string())); // users.name
        assert_eq!(result.rows[1][2], Value::Null); // orders.id (NULL)
        assert_eq!(result.rows[1][3], Value::Null); // orders.user_id (NULL)
    }

    // ========================================================================
    // Classification integration tests
    // ========================================================================

    #[test]
    fn test_set_and_show_classification() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        // Precondition: create table
        tenant
            .execute(
                "CREATE TABLE patients (id INT PRIMARY KEY, ssn TEXT, diagnosis TEXT)",
                &[],
            )
            .unwrap();

        // Set classifications
        tenant
            .execute(
                "ALTER TABLE patients MODIFY COLUMN ssn SET CLASSIFICATION 'PHI'",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "ALTER TABLE patients MODIFY COLUMN diagnosis SET CLASSIFICATION 'MEDICAL'",
                &[],
            )
            .unwrap();

        // Postcondition: show classifications returns both entries
        let result = tenant
            .query("SHOW CLASSIFICATIONS FOR patients", &[])
            .unwrap();

        assert_eq!(result.columns.len(), 2);
        assert_eq!(result.columns[0].as_str(), "column");
        assert_eq!(result.columns[1].as_str(), "classification");
        assert_eq!(result.rows.len(), 2);

        // Rows are sorted by column name: diagnosis < ssn
        assert_eq!(result.rows[0][0], Value::Text("diagnosis".to_string()));
        assert_eq!(result.rows[0][1], Value::Text("MEDICAL".to_string()));
        assert_eq!(result.rows[1][0], Value::Text("ssn".to_string()));
        assert_eq!(result.rows[1][1], Value::Text("PHI".to_string()));
    }

    #[test]
    fn test_classification_nonexistent_table() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let result = tenant.execute(
            "ALTER TABLE nonexistent MODIFY COLUMN x SET CLASSIFICATION 'PHI'",
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_classification_nonexistent_column() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE t (id INT PRIMARY KEY, name TEXT)", &[])
            .unwrap();

        let result = tenant.execute(
            "ALTER TABLE t MODIFY COLUMN nonexistent SET CLASSIFICATION 'PHI'",
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_show_classifications_empty() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE t (id INT PRIMARY KEY)", &[])
            .unwrap();

        // No classifications set yet — should return empty result
        let result = tenant.query("SHOW CLASSIFICATIONS FOR t", &[]).unwrap();
        assert_eq!(result.columns.len(), 2);
        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn test_show_classifications_nonexistent_table() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let result = tenant.query("SHOW CLASSIFICATIONS FOR nonexistent", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_classification_overwrite() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE t (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();

        // Set initial classification
        tenant
            .execute(
                "ALTER TABLE t MODIFY COLUMN ssn SET CLASSIFICATION 'PII'",
                &[],
            )
            .unwrap();

        // Overwrite with different classification
        tenant
            .execute(
                "ALTER TABLE t MODIFY COLUMN ssn SET CLASSIFICATION 'PHI'",
                &[],
            )
            .unwrap();

        // Postcondition: should show latest classification
        let result = tenant.query("SHOW CLASSIFICATIONS FOR t", &[]).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][1], Value::Text("PHI".to_string()));
    }

    // ========================================================================
    // CREATE MASK integration tests
    // ========================================================================

    #[test]
    fn test_create_mask_and_query() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE patients (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();
        tenant
            .execute("INSERT INTO patients VALUES (1, '123-45-6789')", &[])
            .unwrap();

        // Precondition: SSN is visible
        let result = tenant.query("SELECT * FROM patients", &[]).unwrap();
        assert_eq!(result.rows[0][1], Value::Text("123-45-6789".to_string()));

        // Create mask
        tenant
            .execute("CREATE MASK ssn_mask ON patients.ssn USING REDACT", &[])
            .unwrap();

        // Postcondition: SSN is masked
        let result = tenant.query("SELECT * FROM patients", &[]).unwrap();
        assert_ne!(result.rows[0][1], Value::Text("123-45-6789".to_string()));

        // Drop mask
        tenant.execute("DROP MASK ssn_mask", &[]).unwrap();

        // Postcondition: SSN is visible again
        let result = tenant.query("SELECT * FROM patients", &[]).unwrap();
        assert_eq!(result.rows[0][1], Value::Text("123-45-6789".to_string()));
    }

    #[test]
    fn test_create_mask_nonexistent_table() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let result = tenant.execute("CREATE MASK m ON nonexistent.col USING HASH", &[]);
        assert!(result.is_err());
    }

    /// AUDIT-2026-04 M-7: aliasing a sensitive column must not smuggle
    /// the raw value through the mask pass. Today's parser discards
    /// aliases on identifier projections (see
    /// `kimberlite-query/src/parser.rs:1302`), so the result column
    /// keeps the source name — and the mask already hits it. The
    /// `column_aliases` plumbing this test guards is defence in depth:
    /// if a future parser change starts honouring aliases (or a
    /// computed-column path surfaces an aliased sensitive attribute),
    /// the mask lookup still resolves back to `ssn` rather than
    /// missing on the alias.
    #[test]
    fn create_mask_respects_column_alias() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE patients (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();
        tenant
            .execute("INSERT INTO patients VALUES (1, '123-45-6789')", &[])
            .unwrap();
        tenant
            .execute("CREATE MASK ssn_mask ON patients.ssn USING REDACT", &[])
            .unwrap();

        // Baseline: the mask hits the bare column name.
        let plain = tenant.query("SELECT ssn FROM patients", &[]).unwrap();
        assert_ne!(plain.rows[0][0], Value::Text("123-45-6789".to_string()));

        // Regression: aliasing the sensitive column must still mask it.
        // The mask stays active regardless of which of the result-set
        // column names (alias or source) the mask happens to key on.
        let aliased = tenant.query("SELECT ssn AS id FROM patients", &[]).unwrap();
        assert_ne!(
            aliased.rows[0][0],
            Value::Text("123-45-6789".to_string()),
            "alias must not reveal the masked `ssn` value",
        );
    }

    /// AUDIT-2026-04 L-1: `Truncate` that doesn't actually truncate
    /// (value fits within `max_chars`) must keep the integer type
    /// rather than coercing the whole cell to `Value::Text`. Typed
    /// SDK deserialisers rely on this. When truncation happens the
    /// source bytes get `"..."` appended by `apply_truncate`, which
    /// no longer parses as a number — that case is covered by
    /// `mask_truncate_degrades_to_text_on_parse_failure` below.
    #[test]
    fn mask_truncate_preserves_integer_type_when_no_truncation() {
        use kimberlite_rbac::masking::{FieldMask, MaskingStrategy};
        use kimberlite_rbac::roles::Role;

        let mask = FieldMask::new("salary", MaskingStrategy::Truncate { max_chars: 5 });
        // 123 has length 3 ≤ 5 → apply_truncate returns the bytes
        // unchanged → parses back to BigInt(123).
        let out = apply_mask_preserving_type(&Value::BigInt(123), &mask, Role::User).unwrap();
        assert_eq!(out, Value::BigInt(123));
    }

    /// AUDIT-2026-04 L-1: `Null` strategy must produce a typed
    /// `Value::Null`, not an empty `Value::Text("")`.
    #[test]
    fn mask_null_produces_typed_null() {
        use kimberlite_rbac::masking::{FieldMask, MaskingStrategy};
        use kimberlite_rbac::roles::Role;

        let mask = FieldMask::new("ssn", MaskingStrategy::Null);
        let out =
            apply_mask_preserving_type(&Value::Text("123-45-6789".to_string()), &mask, Role::User)
                .unwrap();
        assert_eq!(out, Value::Null);
    }

    /// AUDIT-2026-04 L-1: `Redact` still returns `Value::Text` —
    /// pattern-aware redaction is intrinsically a string operation.
    #[test]
    fn mask_redact_returns_text() {
        use kimberlite_rbac::masking::{FieldMask, MaskingStrategy, RedactPattern};
        use kimberlite_rbac::roles::Role;

        let mask = FieldMask::new("ssn", MaskingStrategy::Redact(RedactPattern::Ssn));
        let out =
            apply_mask_preserving_type(&Value::Text("123-45-6789".to_string()), &mask, Role::User)
                .unwrap();
        assert!(matches!(out, Value::Text(_)));
    }

    /// AUDIT-2026-04 L-1: if a `Truncate` result no longer parses
    /// back to the source numeric type, fall through to `Value::Text`
    /// rather than fabricating a bogus typed value.
    #[test]
    fn mask_truncate_degrades_to_text_on_parse_failure() {
        use kimberlite_rbac::masking::{FieldMask, MaskingStrategy};
        use kimberlite_rbac::roles::Role;

        // `Truncate { max_chars: 0 }` on 42 produces "..." which
        // doesn't parse as i64 — must degrade to text, not panic.
        let mask = FieldMask::new("x", MaskingStrategy::Truncate { max_chars: 0 });
        let out = apply_mask_preserving_type(&Value::BigInt(42), &mask, Role::User).unwrap();
        assert!(matches!(out, Value::Text(_)), "got {out:?}");
    }

    /// AUDIT-2026-04 M-7 unit: `column_aliases` returns the (output,
    /// source) mapping for each aliased identifier, so that a future
    /// code path honouring `AS` still routes mask lookups to the
    /// source column.
    #[test]
    fn column_aliases_maps_identifier_aliases_to_source() {
        use kimberlite_query::rbac_filter::column_aliases;
        use sqlparser::dialect::GenericDialect;
        use sqlparser::parser::Parser;

        let stmts =
            Parser::parse_sql(&GenericDialect {}, "SELECT ssn AS id, name FROM patients").unwrap();
        let pairs = column_aliases(stmts.first().unwrap());
        assert_eq!(
            pairs,
            vec![
                ("id".to_string(), "ssn".to_string()),
                ("name".to_string(), "name".to_string()),
            ]
        );
    }

    #[test]
    fn test_drop_mask_nonexistent() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let result = tenant.execute("DROP MASK nonexistent", &[]);
        assert!(result.is_err());
    }

    // ========================================================================
    // MASKING POLICY DDL end-to-end tests (v0.6.0 Tier 2 #7)
    // ========================================================================
    //
    // These tests walk the full path: SQL DDL → parser → executor →
    // Command::* → apply_committed → State update. Each test asserts
    // the kernel state directly via `State::masking_policy(_exists|…)`
    // so a regression anywhere between parser + kernel trips the test.

    fn assert_masking_policy_exists(db: &Kimberlite, tenant_id: TenantId, name: &str) {
        let inner = db.inner().read().unwrap();
        assert!(
            inner.kernel_state.masking_policy_exists(tenant_id, name),
            "expected masking policy `{name}` to exist for tenant {tenant_id:?}"
        );
    }

    fn assert_masking_policy_missing(db: &Kimberlite, tenant_id: TenantId, name: &str) {
        let inner = db.inner().read().unwrap();
        assert!(
            !inner.kernel_state.masking_policy_exists(tenant_id, name),
            "expected masking policy `{name}` to be gone for tenant {tenant_id:?}"
        );
    }

    #[test]
    fn test_create_masking_policy_via_ddl_lands_in_kernel_state() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_id = TenantId::new(1);
        let tenant = db.tenant(tenant_id);

        tenant
            .execute(
                "CREATE MASKING POLICY ssn_policy STRATEGY REDACT_SSN \
                 EXEMPT ROLES ('clinician', 'billing')",
                &[],
            )
            .expect("CREATE MASKING POLICY should succeed");

        assert_masking_policy_exists(&db, tenant_id, "ssn_policy");

        // The strategy + role guard round-trip intact.
        let inner = db.inner().read().unwrap();
        let rec = inner
            .kernel_state
            .masking_policy(tenant_id, "ssn_policy")
            .expect("policy must be retrievable");
        use kimberlite_kernel::masking::{MaskingStrategyKind, RedactPatternKind};
        assert!(matches!(
            rec.strategy,
            MaskingStrategyKind::Redact(RedactPatternKind::Ssn)
        ));
        assert_eq!(rec.role_guard.exempt_roles, vec!["clinician", "billing"]);
        assert!(rec.role_guard.default_masked);
    }

    #[test]
    fn test_create_masking_policy_each_strategy_variant() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_id = TenantId::new(1);
        let tenant = db.tenant(tenant_id);

        // Walk every strategy keyword the parser recognises to catch a
        // missing arm in `translate_masking_strategy`. Each policy name
        // is distinct so they all coexist in state.
        let cases: &[(&str, &str)] = &[
            (
                "p_ssn",
                "CREATE MASKING POLICY p_ssn STRATEGY REDACT_SSN EXEMPT ROLES ('r')",
            ),
            (
                "p_phone",
                "CREATE MASKING POLICY p_phone STRATEGY REDACT_PHONE EXEMPT ROLES ('r')",
            ),
            (
                "p_email",
                "CREATE MASKING POLICY p_email STRATEGY REDACT_EMAIL EXEMPT ROLES ('r')",
            ),
            (
                "p_cc",
                "CREATE MASKING POLICY p_cc STRATEGY REDACT_CC EXEMPT ROLES ('r')",
            ),
            (
                "p_custom",
                "CREATE MASKING POLICY p_custom STRATEGY REDACT_CUSTOM '***' EXEMPT ROLES ('r')",
            ),
            (
                "p_hash",
                "CREATE MASKING POLICY p_hash STRATEGY HASH EXEMPT ROLES ('r')",
            ),
            (
                "p_tok",
                "CREATE MASKING POLICY p_tok STRATEGY TOKENIZE EXEMPT ROLES ('r')",
            ),
            (
                "p_trunc",
                "CREATE MASKING POLICY p_trunc STRATEGY TRUNCATE 4 EXEMPT ROLES ('r')",
            ),
            (
                "p_null",
                "CREATE MASKING POLICY p_null STRATEGY NULL EXEMPT ROLES ('r')",
            ),
        ];

        for (name, sql) in cases {
            tenant
                .execute(sql, &[])
                .unwrap_or_else(|e| panic!("`{sql}` failed: {e:?}"));
            assert_masking_policy_exists(&db, tenant_id, name);
        }

        assert_eq!(
            db.inner()
                .read()
                .unwrap()
                .kernel_state
                .masking_policy_count(),
            9
        );
    }

    #[test]
    fn test_drop_masking_policy_removes_from_state() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_id = TenantId::new(1);
        let tenant = db.tenant(tenant_id);

        tenant
            .execute(
                "CREATE MASKING POLICY gone STRATEGY HASH EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();
        assert_masking_policy_exists(&db, tenant_id, "gone");

        tenant.execute("DROP MASKING POLICY gone", &[]).unwrap();
        assert_masking_policy_missing(&db, tenant_id, "gone");
    }

    #[test]
    fn test_attach_and_detach_masking_policy_roundtrip() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_id = TenantId::new(1);
        let tenant = db.tenant(tenant_id);

        tenant
            .execute(
                "CREATE TABLE patients (id INT PRIMARY KEY, medicare_number TEXT)",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "CREATE MASKING POLICY mc STRATEGY REDACT_SSN EXEMPT ROLES ('clinician')",
                &[],
            )
            .unwrap();

        // Attach
        tenant
            .execute(
                "ALTER TABLE patients ALTER COLUMN medicare_number SET MASKING POLICY mc",
                &[],
            )
            .unwrap();

        // Attachment is observable in kernel state.
        {
            let inner = db.inner().read().unwrap();
            let table_id = inner
                .kernel_state
                .table_by_tenant_name(tenant_id, "patients")
                .expect("patients table must exist")
                .table_id;
            let attachment =
                inner
                    .kernel_state
                    .masking_attachment(tenant_id, table_id, "medicare_number");
            assert!(
                attachment.is_some(),
                "attachment must exist after SET MASKING POLICY"
            );
            assert!(
                inner
                    .kernel_state
                    .masking_policy_has_attachments(tenant_id, "mc")
            );
        }

        // Detach
        tenant
            .execute(
                "ALTER TABLE patients ALTER COLUMN medicare_number DROP MASKING POLICY",
                &[],
            )
            .unwrap();

        {
            let inner = db.inner().read().unwrap();
            let table_id = inner
                .kernel_state
                .table_by_tenant_name(tenant_id, "patients")
                .unwrap()
                .table_id;
            assert!(
                inner
                    .kernel_state
                    .masking_attachment(tenant_id, table_id, "medicare_number")
                    .is_none(),
                "attachment must be gone after DROP MASKING POLICY"
            );
            assert!(
                !inner
                    .kernel_state
                    .masking_policy_has_attachments(tenant_id, "mc")
            );
        }
    }

    #[test]
    fn test_drop_masking_policy_rejects_while_attached() {
        // PostgreSQL-style dependency guard — dropping a policy with a
        // live attachment would silently leak an un-masked column.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_id = TenantId::new(1);
        let tenant = db.tenant(tenant_id);

        tenant
            .execute("CREATE TABLE patients (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();
        tenant
            .execute(
                "CREATE MASKING POLICY keep STRATEGY REDACT_SSN EXEMPT ROLES ('clinician')",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "ALTER TABLE patients ALTER COLUMN ssn SET MASKING POLICY keep",
                &[],
            )
            .unwrap();

        // Must fail — policy still referenced by the column attachment.
        let result = tenant.execute("DROP MASKING POLICY keep", &[]);
        assert!(
            result.is_err(),
            "DROP MASKING POLICY must reject while attached"
        );

        // After detaching, drop succeeds.
        tenant
            .execute(
                "ALTER TABLE patients ALTER COLUMN ssn DROP MASKING POLICY",
                &[],
            )
            .unwrap();
        tenant.execute("DROP MASKING POLICY keep", &[]).unwrap();
        assert_masking_policy_missing(&db, tenant_id, "keep");
    }

    #[test]
    fn test_attach_masking_policy_rejects_nonexistent_table() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute(
                "CREATE MASKING POLICY p STRATEGY HASH EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();
        let result = tenant.execute(
            "ALTER TABLE nonexistent ALTER COLUMN c SET MASKING POLICY p",
            &[],
        );
        assert!(matches!(result, Err(KimberliteError::TableNotFound(_))));
    }

    #[test]
    fn test_masking_policy_snapshot_empty_catalogue() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        let (policies, attachments) = tenant.masking_policy_snapshot(true).unwrap();
        assert!(policies.is_empty());
        assert!(attachments.is_empty());
    }

    #[test]
    fn test_masking_policy_snapshot_lists_policies_and_counts_attachments() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE t1 (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();
        tenant
            .execute("CREATE TABLE t2 (id INT PRIMARY KEY, email TEXT)", &[])
            .unwrap();
        tenant
            .execute(
                "CREATE MASKING POLICY p_ssn STRATEGY REDACT_SSN EXEMPT ROLES ('clinician')",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "CREATE MASKING POLICY p_hash STRATEGY HASH EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();
        // Attach p_ssn to two columns, p_hash to none.
        tenant
            .execute(
                "ALTER TABLE t1 ALTER COLUMN ssn SET MASKING POLICY p_ssn",
                &[],
            )
            .unwrap();
        tenant
            .execute(
                "ALTER TABLE t2 ALTER COLUMN email SET MASKING POLICY p_ssn",
                &[],
            )
            .unwrap();

        let (policies, attachments) = tenant.masking_policy_snapshot(true).unwrap();
        assert_eq!(policies.len(), 2);
        let p_ssn = policies.iter().find(|p| p.name == "p_ssn").unwrap();
        assert_eq!(p_ssn.attachment_count, 2);
        let p_hash = policies.iter().find(|p| p.name == "p_hash").unwrap();
        assert_eq!(p_hash.attachment_count, 0);

        assert_eq!(attachments.len(), 2);
        for att in &attachments {
            assert_eq!(att.policy_name, "p_ssn");
        }
    }

    #[test]
    fn test_masking_policy_snapshot_include_attachments_false_skips_walk() {
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant = db.tenant(TenantId::new(1));

        tenant
            .execute("CREATE TABLE t (id INT PRIMARY KEY, ssn TEXT)", &[])
            .unwrap();
        tenant
            .execute(
                "CREATE MASKING POLICY p STRATEGY HASH EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();
        tenant
            .execute("ALTER TABLE t ALTER COLUMN ssn SET MASKING POLICY p", &[])
            .unwrap();

        // With include_attachments = false, the attachment list is empty
        // even though a real attachment exists. attachment_count on the
        // policy is still populated because that's always cheap.
        let (policies, attachments) = tenant.masking_policy_snapshot(false).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].attachment_count, 1);
        assert!(attachments.is_empty());
    }

    #[test]
    fn test_masking_policy_is_tenant_scoped() {
        // Regression: a policy created for tenant A must not be visible
        // to tenant B. The kernel command carries `tenant_id` explicitly
        // so this is really a check that the planner threaded the right
        // id through, not just a kernel state test.
        let dir = tempdir().unwrap();
        let db = Kimberlite::open(dir.path()).unwrap();
        let tenant_a = db.tenant(TenantId::new(1));
        let tenant_b = db.tenant(TenantId::new(2));

        tenant_a
            .execute(
                "CREATE MASKING POLICY shared_name STRATEGY HASH EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();

        assert_masking_policy_exists(&db, TenantId::new(1), "shared_name");
        assert_masking_policy_missing(&db, TenantId::new(2), "shared_name");

        // Tenant B can create a policy with the same name — isolated catalogue.
        tenant_b
            .execute(
                "CREATE MASKING POLICY shared_name STRATEGY TOKENIZE EXEMPT ROLES ('admin')",
                &[],
            )
            .unwrap();
        assert_masking_policy_exists(&db, TenantId::new(2), "shared_name");
    }
}
