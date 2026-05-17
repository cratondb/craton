//! SQL parsing for the query engine.
//!
//! Wraps `sqlparser` to parse a minimal SQL subset:
//! - SELECT with column list or *
//! - FROM single table or subquery
//! - JOIN (INNER, LEFT) with table or subquery
//! - WITH (Common Table Expressions / CTEs)
//! - WHERE with comparison predicates
//! - ORDER BY
//! - LIMIT
//! - CREATE TABLE, DROP TABLE, CREATE INDEX (DDL)
//! - INSERT, UPDATE, DELETE (DML)

use kimberlite_types::NonEmptyVec;
use sqlparser::ast::{
    BinaryOperator, ColumnDef as SqlColumnDef, DataType as SqlDataType, Expr, ObjectName,
    OrderByExpr, Query, Select, SelectItem, SetExpr, Statement, Value as SqlValue,
};
use sqlparser::dialect::{Dialect, GenericDialect};
use sqlparser::parser::Parser;

/// Kimberlite's SQL dialect: GenericDialect plus PostgreSQL-style aggregate
/// `FILTER (WHERE ...)` support. Wrapping GenericDialect avoids pulling in
/// PostgreSqlDialect's other quirks while still enabling the SQL:2003 FILTER
/// clause.
#[derive(Debug)]
struct KimberliteDialect {
    inner: GenericDialect,
}

impl KimberliteDialect {
    const fn new() -> Self {
        Self {
            inner: GenericDialect {},
        }
    }
}

impl Dialect for KimberliteDialect {
    fn is_identifier_start(&self, ch: char) -> bool {
        self.inner.is_identifier_start(ch)
    }

    fn is_identifier_part(&self, ch: char) -> bool {
        self.inner.is_identifier_part(ch)
    }

    fn supports_filter_during_aggregation(&self) -> bool {
        true
    }
}

use crate::error::{QueryError, Result};
use crate::expression::ScalarExpr;
use crate::schema::{ColumnName, DataType};
use crate::value::Value;

// ============================================================================
// Parsed Statement Types
// ============================================================================

/// Top-level parsed SQL statement.
#[derive(Debug, Clone)]
pub enum ParsedStatement {
    /// SELECT query
    Select(ParsedSelect),
    /// UNION / UNION ALL of two or more SELECT queries
    Union(ParsedUnion),
    /// CREATE TABLE DDL
    CreateTable(ParsedCreateTable),
    /// DROP TABLE DDL.
    ///
    /// `if_exists = true` corresponds to `DROP TABLE IF EXISTS …` —
    /// the executor returns `Ok` (rows_affected = 0) when the named
    /// table doesn't exist, instead of `TableNotFound`. Idempotent
    /// drops were a v0.7.0 ROADMAP item until v0.6.2 picked up the
    /// fix while clearing test-infrastructure flake.
    DropTable { name: String, if_exists: bool },
    /// ALTER TABLE DDL
    AlterTable(ParsedAlterTable),
    /// CREATE INDEX DDL
    CreateIndex(ParsedCreateIndex),
    /// INSERT DML
    Insert(ParsedInsert),
    /// UPDATE DML
    Update(ParsedUpdate),
    /// DELETE DML
    Delete(ParsedDelete),
    /// CREATE MASK DDL (legacy v0.4.x per-column form)
    CreateMask(ParsedCreateMask),
    /// DROP MASK DDL (legacy v0.4.x per-column form)
    DropMask(String),
    /// CREATE MASKING POLICY DDL (v0.6.0 tenant-scoped catalogue form)
    CreateMaskingPolicy(ParsedCreateMaskingPolicy),
    /// DROP MASKING POLICY DDL — carries the policy name
    DropMaskingPolicy(String),
    /// ALTER TABLE ... ALTER COLUMN ... SET MASKING POLICY `<name>`
    AttachMaskingPolicy(ParsedAttachMaskingPolicy),
    /// ALTER TABLE ... ALTER COLUMN ... DROP MASKING POLICY
    DetachMaskingPolicy(ParsedDetachMaskingPolicy),
    /// ALTER TABLE ... MODIFY COLUMN ... SET CLASSIFICATION
    SetClassification(ParsedSetClassification),
    /// `SHOW CLASSIFICATIONS FOR <table>`
    ShowClassifications(String),
    /// SHOW TABLES
    ShowTables,
    /// `SHOW COLUMNS FROM <table>`
    ShowColumns(String),
    /// `CREATE ROLE <name>`
    CreateRole(String),
    /// GRANT privileges ON table TO role
    Grant(ParsedGrant),
    /// `CREATE USER <name> WITH ROLE <role>`
    CreateUser(ParsedCreateUser),
}

/// Parsed GRANT statement.
#[derive(Debug, Clone)]
pub struct ParsedGrant {
    /// Granted privilege columns (None = all columns).
    pub columns: Option<Vec<String>>,
    /// Table name.
    pub table_name: String,
    /// Role name granted to.
    pub role_name: String,
}

/// Parsed CREATE USER statement.
#[derive(Debug, Clone)]
pub struct ParsedCreateUser {
    /// Username.
    pub username: String,
    /// Role to assign.
    pub role: String,
}

/// Parsed `ALTER TABLE <t> MODIFY COLUMN <c> SET CLASSIFICATION '<class>'`.
#[derive(Debug, Clone)]
pub struct ParsedSetClassification {
    /// Table name.
    pub table_name: String,
    /// Column name.
    pub column_name: String,
    /// Classification label (e.g. "PHI", "PII", "PCI", "MEDICAL").
    pub classification: String,
}

/// Parsed `CREATE MASK <name> ON <table>.<column> USING <strategy>` statement.
#[derive(Debug, Clone)]
pub struct ParsedCreateMask {
    /// Mask name (e.g. "ssn_mask").
    pub mask_name: String,
    /// Table name.
    pub table_name: String,
    /// Column name.
    pub column_name: String,
    /// Masking strategy keyword (e.g. "REDACT", "HASH", "TOKENIZE", "NULL").
    pub strategy: String,
}

/// Parser-level mirror of the kernel's `MaskingStrategyKind`. Kept
/// independent of `kimberlite-kernel` so the query crate does not
/// depend on the kernel; translation happens in the planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedMaskingStrategy {
    /// `STRATEGY REDACT_SSN` — SSN pattern redaction (`***-**-6789`).
    RedactSsn,
    /// `STRATEGY REDACT_PHONE` — phone pattern (`***-***-4567`).
    RedactPhone,
    /// `STRATEGY REDACT_EMAIL` — email pattern (`j***@example.com`).
    RedactEmail,
    /// `STRATEGY REDACT_CC` — credit-card pattern (`****-****-****-1234`).
    RedactCreditCard,
    /// `STRATEGY REDACT_CUSTOM '<replacement>'` — fixed replacement string.
    RedactCustom {
        /// The literal replacement string (stripped of surrounding quotes).
        replacement: String,
    },
    /// `STRATEGY HASH` — SHA-256 hex digest.
    Hash,
    /// `STRATEGY TOKENIZE` — BLAKE3-derived deterministic token.
    Tokenize,
    /// `STRATEGY TRUNCATE <n>` — keep first `n` chars, pad with `"..."`.
    Truncate {
        /// Number of leading characters to preserve.
        max_chars: usize,
    },
    /// `STRATEGY NULL` — replace with empty/NULL.
    Null,
}

/// Parsed `CREATE MASKING POLICY <name> STRATEGY <kind> [<arg>] EXEMPT ROLES (<r>, ...)` statement.
///
/// Tenant-scoped catalogue form from v0.6.0. Decomposes at parse time
/// into a [`ParsedMaskingStrategy`] plus the list of exempt roles; the
/// planner translates to the kernel's `MaskingStrategyKind` + `RoleGuard`.
#[derive(Debug, Clone)]
pub struct ParsedCreateMaskingPolicy {
    /// Policy name, unique per tenant.
    pub name: String,
    /// Masking strategy.
    pub strategy: ParsedMaskingStrategy,
    /// Roles that see the raw (unmasked) value. Lower-cased at parse
    /// time so the kernel `RoleGuard` can compare case-insensitively.
    pub exempt_roles: Vec<String>,
}

/// Parsed `ALTER TABLE <t> ALTER COLUMN <c> SET MASKING POLICY <policy>` statement.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)] // three distinct SQL identifiers; suffix disambiguates, not decoration
pub struct ParsedAttachMaskingPolicy {
    /// Target table name.
    pub table_name: String,
    /// Target column name.
    pub column_name: String,
    /// Name of the policy to attach (must already exist in the tenant's catalogue).
    pub policy_name: String,
}

/// Parsed `ALTER TABLE <t> ALTER COLUMN <c> DROP MASKING POLICY` statement.
#[derive(Debug, Clone)]
pub struct ParsedDetachMaskingPolicy {
    /// Target table name.
    pub table_name: String,
    /// Target column name (must currently have an attached policy).
    pub column_name: String,
}

/// SQL set operation linking two SELECT queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOp {
    /// `UNION` (or `UNION ALL`) — combine both sides.
    Union,
    /// `INTERSECT` — rows present in both sides.
    Intersect,
    /// `EXCEPT` — rows in left side not present in right side.
    Except,
}

/// Parsed `UNION` / `INTERSECT` / `EXCEPT` statement (with or without `ALL`).
#[derive(Debug, Clone)]
pub struct ParsedUnion {
    /// Which set operation.
    pub op: SetOp,
    /// Left side SELECT.
    pub left: ParsedSelect,
    /// Right side SELECT.
    pub right: ParsedSelect,
    /// Whether to keep duplicates (`UNION ALL` / `INTERSECT ALL` / `EXCEPT ALL`).
    /// `false` is the dedup form. `false` matches PostgreSQL default semantics.
    pub all: bool,
}

/// Join type for multi-table queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinType {
    /// INNER JOIN
    Inner,
    /// LEFT OUTER JOIN
    Left,
    /// RIGHT OUTER JOIN — symmetric to `Left`.
    Right,
    /// FULL OUTER JOIN — left ∪ right with NULL padding on either side.
    Full,
    /// CROSS JOIN — Cartesian product, no `ON` predicate.
    Cross,
}

/// Parsed JOIN clause.
#[derive(Debug, Clone)]
pub struct ParsedJoin {
    /// Table name to join (or alias of a derived table).
    pub table: String,
    /// Join type (INNER or LEFT).
    pub join_type: JoinType,
    /// ON condition predicates.
    pub on_condition: Vec<Predicate>,
}

/// A Common Table Expression (CTE) parsed from a WITH clause.
#[derive(Debug, Clone)]
pub struct ParsedCte {
    /// CTE alias name.
    pub name: String,
    /// The anchor (non-recursive) SELECT.
    pub query: ParsedSelect,
    /// For `WITH RECURSIVE` CTEs, the recursive arm that references `name`.
    /// `None` for ordinary CTEs.
    pub recursive_arm: Option<ParsedSelect>,
}

/// A CASE WHEN computed column in the SELECT clause.
///
/// Example: `SELECT CASE WHEN age >= 18 THEN 'adult' ELSE 'minor' END AS age_group`
#[derive(Debug, Clone)]
pub struct ComputedColumn {
    /// Alias name (required — must use `AS alias`).
    pub alias: ColumnName,
    /// WHEN ... THEN ... arms, evaluated in order.
    pub when_clauses: Vec<CaseWhenArm>,
    /// ELSE value. Defaults to NULL if not specified.
    pub else_value: Value,
}

/// A single WHEN condition → THEN result arm of a CASE expression.
#[derive(Debug, Clone)]
pub struct CaseWhenArm {
    /// Predicates for the WHEN condition (from WHERE-like parsing).
    pub condition: Vec<Predicate>,
    /// Result value (must be a literal).
    pub result: Value,
}

/// A parsed `LIMIT` or `OFFSET` clause expression.
///
/// Either an integer literal known at parse time, or a `$N` parameter
/// placeholder resolved against the bound parameter slice at planning time.
/// Mirrors the late-binding pattern used by `PredicateValue::Param` in WHERE
/// clauses (`planner.rs::resolve_value`); see `planner.rs::resolve_limit` for
/// the resolution helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitExpr {
    /// Literal value known at parse time.
    Literal(usize),
    /// Bound at execution time from the params slice (1-indexed).
    Param(usize),
}

/// Parsed SELECT statement.
#[derive(Debug, Clone)]
pub struct ParsedSelect {
    /// Table name from FROM clause.
    pub table: String,
    /// JOIN clauses.
    pub joins: Vec<ParsedJoin>,
    /// Selected columns (None = SELECT *).
    pub columns: Option<Vec<ColumnName>>,
    /// Optional alias per selected column (parallel with `columns` when
    /// `columns` is `Some`). `None` entries mean the column was not
    /// aliased; the output column name uses the source column name.
    /// ROADMAP v0.5.0 item A — SELECT alias preservation. Prior to
    /// v0.5.0 aliases were discarded at parse time, breaking every UI
    /// app that used `SELECT col AS new_name`.
    pub column_aliases: Option<Vec<Option<String>>>,
    /// CASE WHEN computed columns from the SELECT clause.
    pub case_columns: Vec<ComputedColumn>,
    /// WHERE predicates.
    pub predicates: Vec<Predicate>,
    /// ORDER BY clauses.
    pub order_by: Vec<OrderByClause>,
    /// LIMIT value (literal or `$N` parameter).
    pub limit: Option<LimitExpr>,
    /// OFFSET value (literal or `$N` parameter). Resolved alongside `limit`.
    pub offset: Option<LimitExpr>,
    /// Aggregate functions in SELECT clause.
    pub aggregates: Vec<AggregateFunction>,
    /// Per-aggregate `FILTER (WHERE ...)` predicates.
    ///
    /// Parallel with `aggregates` (same length). `None` means no filter.
    /// Evaluated against each input row during accumulation; only rows
    /// matching the filter contribute to that aggregate. Common in clinical
    /// dashboards: `COUNT(*) FILTER (WHERE status = 'abnormal')`.
    pub aggregate_filters: Vec<Option<Vec<Predicate>>>,
    /// GROUP BY columns.
    pub group_by: Vec<ColumnName>,
    /// Whether DISTINCT is specified.
    pub distinct: bool,
    /// HAVING predicates (applied after GROUP BY aggregation).
    pub having: Vec<HavingCondition>,
    /// Common Table Expressions (CTEs) from WITH clause.
    pub ctes: Vec<ParsedCte>,
    /// AUDIT-2026-04 S3.2 — window functions in SELECT clause.
    /// Applied as a post-pass over the base result; see
    /// `crate::window::apply_window_fns`.
    pub window_fns: Vec<ParsedWindowFn>,
    /// Scalar-function projections in SELECT clause (v0.5.1).
    ///
    /// Applied as a post-pass over the base scan rows: each projection
    /// evaluates a [`ScalarExpr`] against the row and appends the
    /// result (with the alias or a synthesised default name) to the
    /// output columns. Parallel to `aggregates`, `case_columns`, and
    /// `window_fns`; empty vec means no scalar projection pass.
    pub scalar_projections: Vec<ParsedScalarProjection>,
}

/// v0.5.1 — a scalar-expression projection in a SELECT clause, e.g.
/// `UPPER(name) AS upper_name` or `COALESCE(x, 0)`.
#[derive(Debug, Clone)]
pub struct ParsedScalarProjection {
    /// The expression to evaluate per row.
    pub expr: ScalarExpr,
    /// Output column name — the `AS alias` if present, otherwise a
    /// PostgreSQL-style synthesised default (e.g. `upper`, `coalesce`).
    pub output_name: ColumnName,
    /// Original user-supplied alias, if any. Preserved separately from
    /// `output_name` so downstream consumers can distinguish aliased
    /// vs. synthesised columns.
    pub alias: Option<String>,
}

/// AUDIT-2026-04 S3.2 — a parsed `<fn>(args) OVER (PARTITION BY ...
/// ORDER BY ...)` window function in a SELECT projection.
#[derive(Debug, Clone)]
pub struct ParsedWindowFn {
    /// Which window function (ROW_NUMBER, RANK, …).
    pub function: crate::window::WindowFunction,
    /// `PARTITION BY` columns. Empty = whole result is one partition.
    pub partition_by: Vec<ColumnName>,
    /// `ORDER BY` columns inside the OVER clause.
    pub order_by: Vec<OrderByClause>,
    /// Optional `AS alias` from the SELECT item.
    pub alias: Option<String>,
}

/// A condition in the HAVING clause.
///
/// HAVING conditions reference aggregate results (e.g., `HAVING COUNT(*) > 5`).
#[derive(Debug, Clone)]
pub enum HavingCondition {
    /// Compare an aggregate function result to a literal value.
    AggregateComparison {
        /// The aggregate function being compared.
        aggregate: AggregateFunction,
        /// Comparison operator.
        op: HavingOp,
        /// Value to compare against.
        value: Value,
    },
}

/// Comparison operators for HAVING conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HavingOp {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Parsed CREATE TABLE statement.
///
/// `columns` is a [`NonEmptyVec`] — an empty column list (e.g. from the
/// sqlparser-accepted but semantically meaningless `CREATE TABLE#USER`)
/// cannot be constructed. Regression: `fuzz_sql_parser` surfaced 12 crashes
/// in the first EPYC nightly by feeding such inputs; the type now rejects
/// them at construction.
#[derive(Debug, Clone)]
pub struct ParsedCreateTable {
    pub table_name: String,
    pub columns: NonEmptyVec<ParsedColumn>,
    pub primary_key: Vec<String>,
    /// When true (from `CREATE TABLE IF NOT EXISTS`), creating a table that
    /// already exists is a no-op rather than an error.
    pub if_not_exists: bool,
}

/// Parsed column definition.
#[derive(Debug, Clone)]
pub struct ParsedColumn {
    pub name: String,
    pub data_type: String, // "BIGINT", "TEXT", "BOOLEAN", "TIMESTAMP", "BYTES"
    pub nullable: bool,
}

/// Parsed ALTER TABLE statement.
#[derive(Debug, Clone)]
pub struct ParsedAlterTable {
    pub table_name: String,
    pub operation: AlterTableOperation,
}

/// ALTER TABLE operation.
#[derive(Debug, Clone)]
pub enum AlterTableOperation {
    /// ADD COLUMN
    AddColumn(ParsedColumn),
    /// DROP COLUMN
    DropColumn(String),
}

/// Parsed CREATE INDEX statement.
#[derive(Debug, Clone)]
pub struct ParsedCreateIndex {
    pub index_name: String,
    pub table_name: String,
    pub columns: Vec<String>,
}

/// Parsed INSERT statement.
///
/// `on_conflict` is `None` for a plain `INSERT`; `Some(...)` for
/// `INSERT ... ON CONFLICT`. v0.6.0 Tier 1 #3.
#[derive(Debug, Clone)]
pub struct ParsedInsert {
    pub table: String,
    pub columns: Vec<String>,
    pub values: Vec<Vec<Value>>,        // Each Vec<Value> is one row
    pub returning: Option<Vec<String>>, // Columns to return after insert
    /// ON CONFLICT clause, if present. See [`OnConflictClause`].
    pub on_conflict: Option<OnConflictClause>,
}

/// Parsed `ON CONFLICT (cols) DO ...` clause attached to an INSERT.
///
/// v0.6.0 Tier 1 #3 — the scope is deliberately narrow:
/// - `target` is a list of column names (no `ON CONSTRAINT <name>` form
///   yet; we'd add it via a new variant if required)
/// - `action` is either DO NOTHING or DO UPDATE SET ... with no WHERE
///   clause (PostgreSQL supports conditional DO UPDATE; we intentionally
///   defer that until a concrete compliance customer asks for it to
///   keep the kernel surface minimal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnConflictClause {
    /// Columns that together form the conflict key. Typically the
    /// primary key; can be any subset that matches a unique constraint
    /// when those land (post-v0.6).
    pub target: Vec<String>,
    /// What to do when a row at `target` already exists.
    pub action: OnConflictAction,
}

/// The action to take when `ON CONFLICT (target)` fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnConflictAction {
    /// `DO NOTHING` — no mutation, `rowsAffected = 0`, but the audit log
    /// still records the upsert attempt (via `AuditAction::UpsertApplied`
    /// with resolution `NoOp`).
    DoNothing,
    /// `DO UPDATE SET col = <expr>, ...` — replace the conflicting row
    /// with the result of evaluating each assignment. `EXCLUDED.col`
    /// references the value from the would-be-inserted row.
    DoUpdate {
        /// Column assignments. `EXCLUDED.col` references are represented
        /// as `UpsertExpr::Excluded(col)` so the tenant-layer dispatcher
        /// can substitute values from the INSERT's row payload.
        assignments: Vec<(String, UpsertExpr)>,
    },
}

/// Expression permitted on the RHS of `SET col = <expr>` inside
/// `ON CONFLICT ... DO UPDATE`.
///
/// Intentionally restricted: callers either want a literal value or an
/// `EXCLUDED.col` back-reference. Arbitrary scalar expressions would
/// punch through the kernel's determinism boundary and are out of scope
/// for v0.6.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertExpr {
    /// A plain literal or parameter placeholder.
    Value(Value),
    /// `EXCLUDED.<col>` — pick the value from the would-be-inserted row.
    Excluded(String),
}

/// Parsed UPDATE statement.
#[derive(Debug, Clone)]
pub struct ParsedUpdate {
    pub table: String,
    pub assignments: Vec<(String, Value)>, // column = value pairs
    pub predicates: Vec<Predicate>,
    pub returning: Option<Vec<String>>, // Columns to return after update
}

/// Parsed DELETE statement.
#[derive(Debug, Clone)]
pub struct ParsedDelete {
    pub table: String,
    pub predicates: Vec<Predicate>,
    pub returning: Option<Vec<String>>, // Columns to return after delete
}

/// Aggregate function in SELECT clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateFunction {
    /// COUNT(*) - count all rows
    CountStar,
    /// COUNT(column) - count non-NULL values in column
    Count(ColumnName),
    /// SUM(column) - sum values in column
    Sum(ColumnName),
    /// AVG(column) - average values in column
    Avg(ColumnName),
    /// MIN(column) - minimum value in column
    Min(ColumnName),
    /// MAX(column) - maximum value in column
    Max(ColumnName),
}

/// A comparison predicate from the WHERE clause.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// column = value or column = $N
    Eq(ColumnName, PredicateValue),
    /// column < value
    Lt(ColumnName, PredicateValue),
    /// column <= value
    Le(ColumnName, PredicateValue),
    /// column > value
    Gt(ColumnName, PredicateValue),
    /// column >= value
    Ge(ColumnName, PredicateValue),
    /// column IN (value, value, ...)
    In(ColumnName, Vec<PredicateValue>),
    /// column NOT IN (value, value, ...)
    NotIn(ColumnName, Vec<PredicateValue>),
    /// column NOT BETWEEN low AND high
    NotBetween(ColumnName, PredicateValue, PredicateValue),
    /// column LIKE 'pattern'
    Like(ColumnName, String),
    /// column NOT LIKE 'pattern'
    NotLike(ColumnName, String),
    /// column ILIKE 'pattern' (case-insensitive LIKE)
    ILike(ColumnName, String),
    /// column NOT ILIKE 'pattern'
    NotILike(ColumnName, String),
    /// column IS NULL
    IsNull(ColumnName),
    /// column IS NOT NULL
    IsNotNull(ColumnName),
    /// JSON path extraction with comparison.
    ///
    /// `data->'key' = value`  → `as_text=false` (compare as JSON value)
    /// `data->>'key' = value` → `as_text=true`  (compare as text)
    JsonExtractEq {
        /// The JSON column being extracted from.
        column: ColumnName,
        /// The key path (single-level for now).
        path: String,
        /// `true` for `->>` (text result), `false` for `->` (JSON result).
        as_text: bool,
        /// Value to compare extracted result against.
        value: PredicateValue,
    },
    /// JSON containment: `column @> value` — `column` (a JSON value) contains `value`.
    JsonContains {
        column: ColumnName,
        value: PredicateValue,
    },
    /// `column IN (SELECT ...)` / `column NOT IN (SELECT ...)`.
    ///
    /// - Uncorrelated form: pre-executed in `pre_execute_subqueries` and
    ///   rewritten to `Predicate::In` / `Predicate::NotIn` before planning.
    /// - Correlated form: detected in the same pass, left in place, and
    ///   handled by the correlated-loop executor (v0.6.0).
    ///
    /// See `docs/reference/sql/correlated-subqueries.md`.
    InSubquery {
        column: ColumnName,
        subquery: Box<ParsedSelect>,
        /// `true` for `NOT IN (SELECT ...)`.
        negated: bool,
    },
    /// `EXISTS (SELECT ...)` and `NOT EXISTS (...)`.
    ///
    /// - Uncorrelated form: pre-executed and rewritten to `Always(bool)`.
    /// - Correlated form: left in place for the correlated-loop executor.
    Exists {
        subquery: Box<ParsedSelect>,
        negated: bool,
    },
    /// Constant truth value: matches every row (`true`) or no rows (`false`).
    ///
    /// Produced by the subquery pre-execution pass: an `EXISTS` whose inner
    /// query returns rows becomes `Always(true)`, an empty `EXISTS` becomes
    /// `Always(false)`. Decoupling these from regular column predicates means
    /// the rest of the planner doesn't need to invent sentinel columns.
    Always(bool),
    /// OR of multiple predicates
    Or(Vec<Predicate>, Vec<Predicate>),
    /// Comparison between two arbitrary scalar expressions.
    ///
    /// Used for any WHERE predicate where one or both sides is a
    /// function call, `CAST`, or `||` operator — e.g.
    /// `UPPER(name) = 'ALICE'`, `COALESCE(x, 0) > 10`,
    /// `CAST(s AS INTEGER) = $1`. The bare column/literal predicates
    /// above stay on the hot path; this variant is the fallback when
    /// the bare shape doesn't match.
    ScalarCmp {
        lhs: ScalarExpr,
        op: ScalarCmpOp,
        rhs: ScalarExpr,
    },
}

/// Comparison operator for a [`Predicate::ScalarCmp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarCmpOp {
    Eq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Predicate {
    /// Returns the column name this predicate operates on.
    ///
    /// Returns None for OR predicates which may reference multiple columns.
    #[allow(dead_code)]
    pub fn column(&self) -> Option<&ColumnName> {
        match self {
            Predicate::Eq(col, _)
            | Predicate::Lt(col, _)
            | Predicate::Le(col, _)
            | Predicate::Gt(col, _)
            | Predicate::Ge(col, _)
            | Predicate::In(col, _)
            | Predicate::NotIn(col, _)
            | Predicate::NotBetween(col, _, _)
            | Predicate::Like(col, _)
            | Predicate::NotLike(col, _)
            | Predicate::ILike(col, _)
            | Predicate::NotILike(col, _)
            | Predicate::IsNull(col)
            | Predicate::IsNotNull(col)
            | Predicate::JsonExtractEq { column: col, .. }
            | Predicate::JsonContains { column: col, .. }
            | Predicate::InSubquery { column: col, .. } => Some(col),
            Predicate::Or(_, _)
            | Predicate::Exists { .. }
            | Predicate::Always(_)
            | Predicate::ScalarCmp { .. } => None,
        }
    }
}

/// A value in a predicate (literal or parameter reference).
#[derive(Debug, Clone)]
pub enum PredicateValue {
    /// Literal integer.
    Int(i64),
    /// Literal string.
    String(String),
    /// Literal boolean.
    Bool(bool),
    /// NULL literal.
    Null,
    /// Parameter placeholder ($1, $2, etc.) - 1-indexed.
    Param(usize),
    /// Literal value (for any type).
    Literal(Value),
    /// Column reference (for JOIN predicates): table.column or just column.
    /// Format: "table.column" or "column"
    ColumnRef(String),
}

/// ORDER BY clause.
#[derive(Debug, Clone)]
pub struct OrderByClause {
    /// Column to order by.
    pub column: ColumnName,
    /// Ascending (true) or descending (false).
    pub ascending: bool,
}

// ============================================================================
// Parser
// ============================================================================

/// Parses a SQL statement string into a `ParsedStatement`.
pub fn parse_statement(sql: &str) -> Result<ParsedStatement> {
    crate::depth_check::check_sql_depth(sql)?;

    // Pre-parse custom extensions that sqlparser doesn't understand.
    if let Some(parsed) = try_parse_custom_statement(sql)? {
        return Ok(parsed);
    }

    let dialect = KimberliteDialect::new();
    let statements =
        Parser::parse_sql(&dialect, sql).map_err(|e| QueryError::ParseError(e.to_string()))?;

    if statements.len() != 1 {
        return Err(QueryError::ParseError(format!(
            "expected exactly 1 statement, got {}",
            statements.len()
        )));
    }

    match &statements[0] {
        Statement::Query(query) => parse_query_to_statement(query),
        Statement::CreateTable(create_table) => {
            let parsed = parse_create_table(create_table)?;
            Ok(ParsedStatement::CreateTable(parsed))
        }
        Statement::Drop {
            object_type,
            names,
            if_exists,
            ..
        } => {
            if !matches!(object_type, sqlparser::ast::ObjectType::Table) {
                return Err(QueryError::UnsupportedFeature(
                    "only DROP TABLE is supported".to_string(),
                ));
            }
            if names.len() != 1 {
                return Err(QueryError::ParseError(
                    "expected exactly 1 table in DROP TABLE".to_string(),
                ));
            }
            let table_name = object_name_to_string(&names[0]);
            Ok(ParsedStatement::DropTable {
                name: table_name,
                if_exists: *if_exists,
            })
        }
        Statement::CreateIndex(create_index) => {
            let parsed = parse_create_index(create_index)?;
            Ok(ParsedStatement::CreateIndex(parsed))
        }
        Statement::Insert(insert) => {
            let parsed = parse_insert(insert)?;
            Ok(ParsedStatement::Insert(parsed))
        }
        Statement::Update(update) => {
            let parsed = parse_update(
                &update.table,
                &update.assignments,
                update.selection.as_ref(),
                update.returning.as_ref(),
            )?;
            Ok(ParsedStatement::Update(parsed))
        }
        Statement::Delete(delete) => {
            let parsed = parse_delete_stmt(delete)?;
            Ok(ParsedStatement::Delete(parsed))
        }
        Statement::AlterTable(alter_table) => {
            let parsed = parse_alter_table(&alter_table.name, &alter_table.operations)?;
            Ok(ParsedStatement::AlterTable(parsed))
        }
        Statement::CreateRole(create_role) => {
            if create_role.names.len() != 1 {
                return Err(QueryError::ParseError(
                    "expected exactly 1 role name".to_string(),
                ));
            }
            let role_name = object_name_to_string(&create_role.names[0]);
            Ok(ParsedStatement::CreateRole(role_name))
        }
        Statement::Grant(grant) => {
            let objects = grant.objects.as_ref().ok_or_else(|| {
                QueryError::ParseError(
                    "GRANT requires an ON clause specifying the target objects".to_string(),
                )
            })?;
            parse_grant(&grant.privileges, objects, &grant.grantees)
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "statement type not supported: {other:?}"
        ))),
    }
}

/// Attempts to parse custom SQL extensions that `sqlparser` does not support.
///
/// Returns `Ok(Some(..))` if the statement is a recognized extension,
/// `Ok(None)` if it should be delegated to sqlparser, or `Err` on parse failure.
///
/// Supported extensions:
/// - `CREATE MASKING POLICY <name> STRATEGY <kind> [<arg>] EXEMPT ROLES (<r>, ...)`
/// - `DROP MASKING POLICY <name>`
/// - `ALTER TABLE <t> ALTER COLUMN <c> SET MASKING POLICY <name>`
/// - `ALTER TABLE <t> ALTER COLUMN <c> DROP MASKING POLICY`
/// - `CREATE MASK <name> ON <table>.<column> USING <strategy>` (legacy v0.4.x)
/// - `DROP MASK <name>` (legacy v0.4.x)
/// - `ALTER TABLE <t> MODIFY COLUMN <c> SET CLASSIFICATION '<class>'`
/// - `SHOW CLASSIFICATIONS FOR <table>` / `SHOW TABLES` / `SHOW COLUMNS FROM <t>`
/// - `CREATE USER <name> WITH ROLE <role>`
pub fn try_parse_custom_statement(sql: &str) -> Result<Option<ParsedStatement>> {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    let upper = trimmed.to_ascii_uppercase();

    // CREATE MASKING POLICY must come BEFORE CREATE MASK (shared prefix).
    if upper.starts_with("CREATE MASKING POLICY") {
        return parse_create_masking_policy(trimmed).map(Some);
    }

    // DROP MASKING POLICY must come BEFORE DROP MASK (shared prefix).
    if upper.starts_with("DROP MASKING POLICY") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // Expected: DROP MASKING POLICY <name>
        if tokens.len() != 4 {
            return Err(QueryError::ParseError(
                "expected: DROP MASKING POLICY <name>".to_string(),
            ));
        }
        return Ok(Some(ParsedStatement::DropMaskingPolicy(
            tokens[3].to_string(),
        )));
    }

    // ALTER TABLE ... ALTER COLUMN ... { SET | DROP } MASKING POLICY ...
    if upper.starts_with("ALTER TABLE") && upper.contains("MASKING POLICY") {
        return parse_alter_masking_policy(trimmed).map(Some);
    }

    // CREATE MASK <name> ON <table>.<column> USING <strategy>
    if upper.starts_with("CREATE MASK") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // Expected: CREATE MASK <name> ON <table>.<column> USING <strategy>
        if tokens.len() != 7 {
            return Err(QueryError::ParseError(
                "expected: CREATE MASK <name> ON <table>.<column> USING <strategy>".to_string(),
            ));
        }
        if !tokens[3].eq_ignore_ascii_case("ON") {
            return Err(QueryError::ParseError(format!(
                "expected ON after mask name, got '{}'",
                tokens[3]
            )));
        }
        if !tokens[5].eq_ignore_ascii_case("USING") {
            return Err(QueryError::ParseError(format!(
                "expected USING after column reference, got '{}'",
                tokens[5]
            )));
        }

        // Parse table.column
        let table_col = tokens[4];
        let dot_pos = table_col.find('.').ok_or_else(|| {
            QueryError::ParseError(format!(
                "expected <table>.<column> but got '{table_col}' (missing '.')"
            ))
        })?;
        let table_name = table_col[..dot_pos].to_string();
        let column_name = table_col[dot_pos + 1..].to_string();

        if table_name.is_empty() || column_name.is_empty() {
            return Err(QueryError::ParseError(
                "table name and column name must not be empty".to_string(),
            ));
        }

        let strategy = tokens[6].to_ascii_uppercase();

        return Ok(Some(ParsedStatement::CreateMask(ParsedCreateMask {
            mask_name: tokens[2].to_string(),
            table_name,
            column_name,
            strategy,
        })));
    }

    // DROP MASK <name>
    if upper.starts_with("DROP MASK") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() != 3 {
            return Err(QueryError::ParseError(
                "expected: DROP MASK <name>".to_string(),
            ));
        }
        return Ok(Some(ParsedStatement::DropMask(tokens[2].to_string())));
    }

    // ALTER TABLE <table> MODIFY COLUMN <col> SET CLASSIFICATION '<class>'
    if upper.starts_with("ALTER TABLE") && upper.contains("SET CLASSIFICATION") {
        return parse_set_classification(trimmed);
    }

    // SHOW CLASSIFICATIONS FOR <table>
    if upper.starts_with("SHOW CLASSIFICATIONS") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // Expected: SHOW CLASSIFICATIONS FOR <table>
        if tokens.len() != 4 {
            return Err(QueryError::ParseError(
                "expected: SHOW CLASSIFICATIONS FOR <table>".to_string(),
            ));
        }
        if !tokens[2].eq_ignore_ascii_case("FOR") {
            return Err(QueryError::ParseError(format!(
                "expected FOR after CLASSIFICATIONS, got '{}'",
                tokens[2]
            )));
        }
        return Ok(Some(ParsedStatement::ShowClassifications(
            tokens[3].to_string(),
        )));
    }

    // SHOW TABLES
    if upper == "SHOW TABLES" {
        return Ok(Some(ParsedStatement::ShowTables));
    }

    // SHOW COLUMNS FROM <table>
    if upper.starts_with("SHOW COLUMNS") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // Expected: SHOW COLUMNS FROM <table>
        if tokens.len() != 4 {
            return Err(QueryError::ParseError(
                "expected: SHOW COLUMNS FROM <table>".to_string(),
            ));
        }
        if !tokens[2].eq_ignore_ascii_case("FROM") {
            return Err(QueryError::ParseError(format!(
                "expected FROM after COLUMNS, got '{}'",
                tokens[2]
            )));
        }
        return Ok(Some(ParsedStatement::ShowColumns(tokens[3].to_string())));
    }

    // CREATE USER <name> WITH ROLE <role>
    if upper.starts_with("CREATE USER") {
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // Expected: CREATE USER <name> WITH ROLE <role>
        if tokens.len() != 6 {
            return Err(QueryError::ParseError(
                "expected: CREATE USER <name> WITH ROLE <role>".to_string(),
            ));
        }
        if !tokens[3].eq_ignore_ascii_case("WITH") {
            return Err(QueryError::ParseError(format!(
                "expected WITH after username, got '{}'",
                tokens[3]
            )));
        }
        if !tokens[4].eq_ignore_ascii_case("ROLE") {
            return Err(QueryError::ParseError(format!(
                "expected ROLE after WITH, got '{}'",
                tokens[4]
            )));
        }
        return Ok(Some(ParsedStatement::CreateUser(ParsedCreateUser {
            username: tokens[2].to_string(),
            role: tokens[5].to_string(),
        })));
    }

    Ok(None)
}

/// Parse `CREATE MASKING POLICY <name> STRATEGY <kind> [<arg>] EXEMPT ROLES (<r>, ...)`.
///
/// Tokenisation is whitespace-based but the EXEMPT ROLES list preserves
/// the parenthesised argument as one lexical unit before re-splitting on
/// commas, so `EXEMPT ROLES ('a', 'b')` and `EXEMPT ROLES('a','b')` both
/// parse. Roles are lower-cased at parse time to match the kernel's
/// `RoleGuard` case-insensitive comparison.
fn parse_create_masking_policy(trimmed: &str) -> Result<ParsedStatement> {
    // `CREATE MASKING POLICY` is 3 keywords — split the remainder by
    // isolating the `EXEMPT ROLES (...)` tail so the interior of the
    // parens is not re-tokenised on whitespace.
    let after_keyword = trimmed
        .get("CREATE MASKING POLICY".len()..)
        .ok_or_else(|| QueryError::ParseError("missing policy body".to_string()))?
        .trim_start();

    // Find `EXEMPT ROLES` (case-insensitive); everything before it is
    // the header `<name> STRATEGY <kind> [<arg>]`.
    let upper_body = after_keyword.to_ascii_uppercase();
    let exempt_pos = upper_body.find("EXEMPT ROLES").ok_or_else(|| {
        QueryError::ParseError(
            "expected: CREATE MASKING POLICY <name> STRATEGY <kind> [<arg>] EXEMPT ROLES (<r>, ...)"
                .to_string(),
        )
    })?;

    let header = after_keyword[..exempt_pos].trim();
    let exempt_tail = after_keyword[exempt_pos + "EXEMPT ROLES".len()..].trim();

    let (name, strategy) = parse_masking_policy_header(header)?;
    let exempt_roles = parse_exempt_roles_list(exempt_tail)?;

    Ok(ParsedStatement::CreateMaskingPolicy(
        ParsedCreateMaskingPolicy {
            name,
            strategy,
            exempt_roles,
        },
    ))
}

/// Parse the header portion `<name> STRATEGY <kind> [<arg>]`.
fn parse_masking_policy_header(header: &str) -> Result<(String, ParsedMaskingStrategy)> {
    let tokens: Vec<&str> = header.split_whitespace().collect();
    if tokens.len() < 3 {
        return Err(QueryError::ParseError(
            "expected: <name> STRATEGY <kind> [<arg>]".to_string(),
        ));
    }
    let name = tokens[0].to_string();
    if name.is_empty() {
        return Err(QueryError::ParseError(
            "policy name must not be empty".to_string(),
        ));
    }
    if !tokens[1].eq_ignore_ascii_case("STRATEGY") {
        return Err(QueryError::ParseError(format!(
            "expected STRATEGY after policy name, got '{}'",
            tokens[1]
        )));
    }

    let strategy = parse_masking_strategy(&tokens[2..])?;
    Ok((name, strategy))
}

/// Parse `<STRATEGY_KIND> [<arg>]` from already-split tokens.
fn parse_masking_strategy(tokens: &[&str]) -> Result<ParsedMaskingStrategy> {
    debug_assert!(
        !tokens.is_empty(),
        "caller must pass at least the strategy keyword"
    );
    let kind = tokens[0].to_ascii_uppercase();
    match kind.as_str() {
        "REDACT_SSN" => {
            expect_no_strategy_arg(tokens, "REDACT_SSN").map(|()| ParsedMaskingStrategy::RedactSsn)
        }
        "REDACT_PHONE" => expect_no_strategy_arg(tokens, "REDACT_PHONE")
            .map(|()| ParsedMaskingStrategy::RedactPhone),
        "REDACT_EMAIL" => expect_no_strategy_arg(tokens, "REDACT_EMAIL")
            .map(|()| ParsedMaskingStrategy::RedactEmail),
        "REDACT_CC" => expect_no_strategy_arg(tokens, "REDACT_CC")
            .map(|()| ParsedMaskingStrategy::RedactCreditCard),
        "REDACT_CUSTOM" => {
            if tokens.len() != 2 {
                return Err(QueryError::ParseError(
                    "REDACT_CUSTOM requires a single quoted replacement string".to_string(),
                ));
            }
            let replacement = unquote_string_literal(tokens[1]).ok_or_else(|| {
                QueryError::ParseError(
                    "REDACT_CUSTOM replacement must be a single-quoted string".to_string(),
                )
            })?;
            Ok(ParsedMaskingStrategy::RedactCustom { replacement })
        }
        "HASH" => {
            expect_no_strategy_arg(tokens, "HASH")?;
            Ok(ParsedMaskingStrategy::Hash)
        }
        "TOKENIZE" => {
            expect_no_strategy_arg(tokens, "TOKENIZE")?;
            Ok(ParsedMaskingStrategy::Tokenize)
        }
        "TRUNCATE" => {
            if tokens.len() != 2 {
                return Err(QueryError::ParseError(
                    "TRUNCATE requires a positive integer character count".to_string(),
                ));
            }
            let max_chars = tokens[1].parse::<usize>().map_err(|_| {
                QueryError::ParseError(format!(
                    "TRUNCATE argument must be a non-negative integer, got '{}'",
                    tokens[1]
                ))
            })?;
            if max_chars == 0 {
                return Err(QueryError::ParseError(
                    "TRUNCATE character count must be > 0".to_string(),
                ));
            }
            Ok(ParsedMaskingStrategy::Truncate { max_chars })
        }
        "NULL" => {
            expect_no_strategy_arg(tokens, "NULL")?;
            Ok(ParsedMaskingStrategy::Null)
        }
        _ => Err(QueryError::ParseError(format!(
            "unknown masking strategy '{kind}' — expected one of REDACT_SSN, REDACT_PHONE, \
             REDACT_EMAIL, REDACT_CC, REDACT_CUSTOM, HASH, TOKENIZE, TRUNCATE, NULL"
        ))),
    }
}

fn expect_no_strategy_arg(tokens: &[&str], kind: &str) -> Result<()> {
    if tokens.len() != 1 {
        return Err(QueryError::ParseError(format!(
            "{kind} takes no arguments (found {} extra token(s))",
            tokens.len() - 1
        )));
    }
    Ok(())
}

/// Strip surrounding single quotes from `'foo'` → `foo`. Returns `None`
/// if the token is not a well-formed single-quoted string.
fn unquote_string_literal(token: &str) -> Option<String> {
    let bytes = token.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'\'' || bytes[bytes.len() - 1] != b'\'' {
        return None;
    }
    Some(token[1..token.len() - 1].to_string())
}

/// Parse `(role1, role2, ...)` into a lower-cased role list.
///
/// Accepts quoted (`'clinician'`) and unquoted (`clinician`) roles; both
/// are normalised to lower case so the kernel `RoleGuard` does not need
/// to do per-comparison case folding. Empty list is rejected — a policy
/// with no exempt roles masks everyone and is almost certainly a bug.
fn parse_exempt_roles_list(tail: &str) -> Result<Vec<String>> {
    let trimmed = tail.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return Err(QueryError::ParseError(
            "EXEMPT ROLES must be followed by a parenthesised list: EXEMPT ROLES (r1, r2, ...)"
                .to_string(),
        ));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let roles: Vec<String> = inner
        .split(',')
        .map(|s| s.trim().trim_matches('\'').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if roles.is_empty() {
        return Err(QueryError::ParseError(
            "EXEMPT ROLES list must contain at least one role".to_string(),
        ));
    }
    Ok(roles)
}

/// Parse `ALTER TABLE <t> ALTER COLUMN <c> { SET | DROP } MASKING POLICY [<name>]`.
fn parse_alter_masking_policy(trimmed: &str) -> Result<ParsedStatement> {
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    // SET form:  ALTER TABLE t ALTER COLUMN c SET MASKING POLICY p   (10 tokens)
    // DROP form: ALTER TABLE t ALTER COLUMN c DROP MASKING POLICY    (9 tokens)
    if tokens.len() < 9 || tokens.len() > 10 {
        return Err(QueryError::ParseError(
            "expected: ALTER TABLE <t> ALTER COLUMN <c> { SET | DROP } MASKING POLICY [<name>]"
                .to_string(),
        ));
    }
    if !tokens[0].eq_ignore_ascii_case("ALTER")
        || !tokens[1].eq_ignore_ascii_case("TABLE")
        || !tokens[3].eq_ignore_ascii_case("ALTER")
        || !tokens[4].eq_ignore_ascii_case("COLUMN")
        || !tokens[7].eq_ignore_ascii_case("MASKING")
        || !tokens[8].eq_ignore_ascii_case("POLICY")
    {
        return Err(QueryError::ParseError(format!(
            "malformed ALTER ... MASKING POLICY statement: '{trimmed}'"
        )));
    }
    let table_name = tokens[2].to_string();
    let column_name = tokens[5].to_string();
    let action = tokens[6].to_ascii_uppercase();
    match action.as_str() {
        "SET" => {
            if tokens.len() != 10 {
                return Err(QueryError::ParseError(
                    "SET MASKING POLICY requires a policy name".to_string(),
                ));
            }
            Ok(ParsedStatement::AttachMaskingPolicy(
                ParsedAttachMaskingPolicy {
                    table_name,
                    column_name,
                    policy_name: tokens[9].to_string(),
                },
            ))
        }
        "DROP" => {
            if tokens.len() != 9 {
                return Err(QueryError::ParseError(
                    "DROP MASKING POLICY takes no arguments after POLICY".to_string(),
                ));
            }
            Ok(ParsedStatement::DetachMaskingPolicy(
                ParsedDetachMaskingPolicy {
                    table_name,
                    column_name,
                },
            ))
        }
        _ => Err(QueryError::ParseError(format!(
            "expected SET or DROP after column name, got '{action}'"
        ))),
    }
}

/// Time-travel coordinate extracted from a SQL string.
///
/// Kimberlite supports two forms:
/// - `AT OFFSET <n>` (Kimberlite extension) — raw log offset.
/// - `FOR SYSTEM_TIME AS OF '<iso8601>'` / `AS OF '<iso8601>'`
///   (SQL:2011 temporal) — wall-clock timestamp. Resolved to an
///   offset via the audit log's commit-timestamp index by the
///   caller (see [`crate::QueryEngine::query_at_timestamp`]).
///
/// AUDIT-2026-04 L-4: the audit flagged the absence of timestamp
/// syntax as a compliance-vertical blocker (healthcare "what did
/// the chart say on 2026-01-15?", finance point-in-time
/// reporting). This type is the parser-layer landing for both
/// syntaxes; the timestamp→offset resolver is a runtime-layer
/// concern kept separate to avoid the query crate taking a
/// dependency on the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeTravel {
    /// Raw log offset.
    Offset(u64),
    /// Unix-nanosecond timestamp — caller must resolve to an
    /// offset.
    TimestampNs(i64),
}

/// Extracts `AT OFFSET <n>` from a SQL string.
///
/// Kimberlite extends standard SQL with `AT OFFSET <n>` for point-in-time queries.
/// Since `sqlparser` does not understand this clause, we strip it before parsing
/// and return the offset separately.
///
/// Handles the clause appearing after FROM, after WHERE, or at the end of the
/// statement (before an optional semicolon and optional LIMIT/ORDER BY).
///
/// # Returns
///
/// `(cleaned_sql, Some(offset))` if `AT OFFSET <n>` was found,
/// `(original_sql, None)` otherwise.
///
/// # Examples
///
/// ```ignore
/// let (sql, offset) = extract_at_offset("SELECT * FROM patients AT OFFSET 3");
/// assert_eq!(sql, "SELECT * FROM patients");
/// assert_eq!(offset, Some(3));
/// ```
pub fn extract_at_offset(sql: &str) -> (String, Option<u64>) {
    // Case-insensitive search for "AT OFFSET" followed by a number.
    // We search from the end to avoid false matches in string literals.
    let upper = sql.to_ascii_uppercase();

    // Find the last occurrence of "AT OFFSET" — this avoids matching inside
    // string literals or column aliases in most practical cases.
    let Some(at_pos) = upper.rfind("AT OFFSET") else {
        return (sql.to_string(), None);
    };

    // Verify "AT" is preceded by whitespace (not part of another word like "FORMAT")
    if at_pos > 0 {
        let prev_byte = sql.as_bytes()[at_pos - 1];
        if prev_byte != b' ' && prev_byte != b'\t' && prev_byte != b'\n' && prev_byte != b'\r' {
            return (sql.to_string(), None);
        }
    }

    // Extract the rest after "AT OFFSET" (length 9)
    let after_at_offset = &sql[at_pos + 9..].trim_start();

    // Parse the offset number — take digits, reject everything else up to
    // whitespace/semicolon/end-of-string.
    let num_end = after_at_offset
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_at_offset.len());

    if num_end == 0 {
        // "AT OFFSET" not followed by a number — not our syntax
        return (sql.to_string(), None);
    }

    let num_str = &after_at_offset[..num_end];
    let Ok(offset) = num_str.parse::<u64>() else {
        return (sql.to_string(), None);
    };

    // Verify nothing unexpected follows the number (only whitespace, semicolons,
    // or nothing). This prevents matching "AT OFFSET 3abc" or similar.
    let remainder = after_at_offset[num_end..].trim();
    if !remainder.is_empty() && remainder != ";" {
        return (sql.to_string(), None);
    }

    // Build the cleaned SQL: everything before "AT OFFSET", trimmed.
    let before = sql[..at_pos].trim_end();
    let cleaned = before.to_string();

    (cleaned, Some(offset))
}

/// Extracts a [`TimeTravel`] coordinate from a SQL string, covering
/// both `AT OFFSET <n>` and the SQL:2011 temporal forms
/// `FOR SYSTEM_TIME AS OF '<iso8601>'` and `AS OF '<iso8601>'`.
///
/// AUDIT-2026-04 L-4 — healthcare workloads (subject-access, OCR
/// review, payer dispute, malpractice litigation) routinely ask
/// "what did the record look like on date X?"
/// The offset form is compositional with Kimberlite's log-native
/// storage; the timestamp form is the user-facing ergonomic. The
/// caller resolves timestamps to offsets via the audit log's
/// commit-timestamp index (see
/// [`crate::QueryEngine::query_at_timestamp`]).
///
/// # Returns
///
/// `(cleaned_sql, Some(TimeTravel::...))` if either syntax was
/// found; `(original_sql, None)` otherwise. The parsing is
/// deterministic and case-insensitive on the keywords.
///
/// # Examples
///
/// ```ignore
/// let (sql, tt) = extract_time_travel(
///     "SELECT * FROM charts FOR SYSTEM_TIME AS OF '2026-01-15T00:00:00Z'"
/// );
/// assert_eq!(sql, "SELECT * FROM charts");
/// // tt parsed as TimeTravel::TimestampNs(...)
/// ```
pub fn extract_time_travel(sql: &str) -> (String, Option<TimeTravel>) {
    // Try offset syntax first (back-compat with existing callers).
    let (after_offset_sql, offset) = extract_at_offset(sql);
    if let Some(o) = offset {
        return (after_offset_sql, Some(TimeTravel::Offset(o)));
    }

    // Try timestamp syntax. We match, in order:
    //   FOR SYSTEM_TIME AS OF '<iso>'
    //   AS OF '<iso>'
    // Only the parenthesis-less form — the plan does not cover
    // `BETWEEN` / `FROM ... TO ...` ranges (follow-up work).
    let upper = sql.to_ascii_uppercase();

    // Prefer the longer, more specific "FOR SYSTEM_TIME AS OF"
    // form because a bare "AS OF" could collide with aliases in
    // weirdly-formatted SQL. In practice Kimberlite's SQL subset
    // doesn't use AS-without-alias, so the risk is low, but
    // preferring the specific keyword is a cheap invariant.
    let (keyword_pos, keyword_len) = if let Some(p) = upper.rfind("FOR SYSTEM_TIME AS OF") {
        (p, "FOR SYSTEM_TIME AS OF".len())
    } else if let Some(p) = upper.rfind("AS OF") {
        // Guard: preceded by whitespace and followed by a quote —
        // avoids matching `alias AS OF_something`.
        let after = sql[p + "AS OF".len()..].trim_start();
        if !after.starts_with('\'') {
            return (sql.to_string(), None);
        }
        (p, "AS OF".len())
    } else {
        return (sql.to_string(), None);
    };

    // Verify keyword boundary.
    if keyword_pos > 0 {
        let prev = sql.as_bytes()[keyword_pos - 1];
        if !matches!(prev, b' ' | b'\t' | b'\n' | b'\r') {
            return (sql.to_string(), None);
        }
    }

    let after_keyword = sql[keyword_pos + keyword_len..].trim_start();
    if !after_keyword.starts_with('\'') {
        return (sql.to_string(), None);
    }

    // Find the closing quote. Kimberlite's time-travel literal is
    // an ISO-8601 string — no embedded single quotes to escape —
    // so a simple scan is correct.
    let ts_start = 1; // skip opening '
    let ts_end = match after_keyword[1..].find('\'') {
        Some(i) => i + 1,
        None => return (sql.to_string(), None),
    };
    let ts_str = &after_keyword[ts_start..ts_end];

    // Parse ISO-8601 via chrono.
    let ts_ns = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(dt) => dt.timestamp_nanos_opt(),
        Err(_) => return (sql.to_string(), None),
    };
    let ts_ns = match ts_ns {
        Some(n) => n,
        None => return (sql.to_string(), None),
    };

    // Verify nothing unexpected follows the literal.
    let remainder = after_keyword[ts_end + 1..].trim();
    if !remainder.is_empty() && remainder != ";" {
        return (sql.to_string(), None);
    }

    let before = sql[..keyword_pos].trim_end();
    (before.to_string(), Some(TimeTravel::TimestampNs(ts_ns)))
}

/// Parses `ALTER TABLE <t> MODIFY COLUMN <c> SET CLASSIFICATION '<class>'`.
///
/// Extracts the table name, column name, and classification label.
/// The classification value must be quoted with single quotes.
fn parse_set_classification(sql: &str) -> Result<Option<ParsedStatement>> {
    let tokens: Vec<&str> = sql.split_whitespace().collect();
    // ALTER TABLE <t> MODIFY COLUMN <c> SET CLASSIFICATION '<class>'
    // 0     1     2   3      4      5   6   7              8
    if tokens.len() != 9 {
        return Err(QueryError::ParseError(
            "expected: ALTER TABLE <table> MODIFY COLUMN <column> SET CLASSIFICATION '<class>'"
                .to_string(),
        ));
    }

    if !tokens[3].eq_ignore_ascii_case("MODIFY") {
        return Err(QueryError::ParseError(format!(
            "expected MODIFY, got '{}'",
            tokens[3]
        )));
    }
    if !tokens[4].eq_ignore_ascii_case("COLUMN") {
        return Err(QueryError::ParseError(format!(
            "expected COLUMN after MODIFY, got '{}'",
            tokens[4]
        )));
    }
    if !tokens[6].eq_ignore_ascii_case("SET") {
        return Err(QueryError::ParseError(format!(
            "expected SET, got '{}'",
            tokens[6]
        )));
    }
    if !tokens[7].eq_ignore_ascii_case("CLASSIFICATION") {
        return Err(QueryError::ParseError(format!(
            "expected CLASSIFICATION, got '{}'",
            tokens[7]
        )));
    }

    let table_name = tokens[2].to_string();
    let column_name = tokens[5].to_string();

    // Strip single quotes from classification value
    let raw_class = tokens[8];
    let classification = raw_class
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| {
            QueryError::ParseError(format!(
                "classification must be quoted with single quotes, got '{raw_class}'"
            ))
        })?
        .to_string();

    assert!(!table_name.is_empty(), "table name must not be empty");
    assert!(!column_name.is_empty(), "column name must not be empty");
    assert!(
        !classification.is_empty(),
        "classification must not be empty"
    );

    Ok(Some(ParsedStatement::SetClassification(
        ParsedSetClassification {
            table_name,
            column_name,
            classification,
        },
    )))
}

/// Parses a GRANT statement from sqlparser AST.
fn parse_grant(
    privileges: &sqlparser::ast::Privileges,
    objects: &sqlparser::ast::GrantObjects,
    grantees: &[sqlparser::ast::Grantee],
) -> Result<ParsedStatement> {
    use sqlparser::ast::{Action, GrantObjects, GranteeName, Privileges};

    // Extract columns from SELECT privilege (if specified)
    let columns = match privileges {
        Privileges::Actions(actions) => {
            let mut cols = None;
            for action in actions {
                if let Action::Select { columns: Some(c) } = action {
                    cols = Some(c.iter().map(|i| i.value.clone()).collect());
                }
            }
            cols
        }
        Privileges::All { .. } => None,
    };

    // Extract table name
    let table_name = match objects {
        GrantObjects::Tables(tables) => {
            if tables.len() != 1 {
                return Err(QueryError::ParseError(
                    "expected exactly 1 table in GRANT".to_string(),
                ));
            }
            object_name_to_string(&tables[0])
        }
        _ => {
            return Err(QueryError::UnsupportedFeature(
                "GRANT only supports table-level privileges".to_string(),
            ));
        }
    };

    // Extract role name from first grantee
    if grantees.len() != 1 {
        return Err(QueryError::ParseError(
            "expected exactly 1 grantee in GRANT".to_string(),
        ));
    }
    let role_name = match &grantees[0].name {
        Some(GranteeName::ObjectName(name)) => object_name_to_string(name),
        _ => {
            return Err(QueryError::ParseError(
                "expected a role name in GRANT".to_string(),
            ));
        }
    };

    Ok(ParsedStatement::Grant(ParsedGrant {
        columns,
        table_name,
        role_name,
    }))
}

/// Parses a query, returning either a Select or Union statement.
fn parse_query_to_statement(query: &Query) -> Result<ParsedStatement> {
    // Parse CTEs from WITH clause
    let ctes = match &query.with {
        Some(with) => parse_ctes(with)?,
        None => vec![],
    };

    match query.body.as_ref() {
        SetExpr::Select(select) => {
            let parsed_select = parse_select(select)?;

            // Parse ORDER BY from query (not select)
            let order_by = match &query.order_by {
                Some(ob) => parse_order_by(ob)?,
                None => vec![],
            };

            // Parse LIMIT and OFFSET from query
            let limit = parse_limit(query_limit_expr(query)?)?;
            let offset = parse_offset_clause(query_offset(query))?;

            // Merge top-level CTEs with any inline CTEs from subqueries
            let mut all_ctes = ctes;
            all_ctes.extend(parsed_select.ctes);

            Ok(ParsedStatement::Select(ParsedSelect {
                table: parsed_select.table,
                joins: parsed_select.joins,
                columns: parsed_select.columns,
                column_aliases: parsed_select.column_aliases,
                case_columns: parsed_select.case_columns,
                predicates: parsed_select.predicates,
                order_by,
                limit,
                offset,
                aggregates: parsed_select.aggregates,
                aggregate_filters: parsed_select.aggregate_filters,
                group_by: parsed_select.group_by,
                distinct: parsed_select.distinct,
                having: parsed_select.having,
                ctes: all_ctes,
                window_fns: parsed_select.window_fns,
                scalar_projections: parsed_select.scalar_projections,
            }))
        }
        SetExpr::SetOperation {
            op,
            set_quantifier,
            left,
            right,
        } => {
            use sqlparser::ast::SetOperator;
            use sqlparser::ast::SetQuantifier;

            let parsed_op = match op {
                SetOperator::Union => SetOp::Union,
                SetOperator::Intersect => SetOp::Intersect,
                // EXCEPT and MINUS are equivalent (PostgreSQL/Oracle naming).
                SetOperator::Except | SetOperator::Minus => SetOp::Except,
            };

            let all = matches!(set_quantifier, SetQuantifier::All);

            // Parse left and right as simple SELECTs
            let left_select = match left.as_ref() {
                SetExpr::Select(s) => parse_select(s)?,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "nested set operations not supported".to_string(),
                    ));
                }
            };
            let right_select = match right.as_ref() {
                SetExpr::Select(s) => parse_select(s)?,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "nested set operations not supported".to_string(),
                    ));
                }
            };

            Ok(ParsedStatement::Union(ParsedUnion {
                op: parsed_op,
                left: left_select,
                right: right_select,
                all,
            }))
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported query type: {other:?}"
        ))),
    }
}

/// Parses a JOIN clause from the AST, returning any inline CTEs from subqueries.
fn parse_join_with_subqueries(join: &sqlparser::ast::Join) -> Result<(ParsedJoin, Vec<ParsedCte>)> {
    use sqlparser::ast::{JoinConstraint, JoinOperator};

    // Extract join type.
    //
    // sqlparser 0.61 distinguishes plain `JOIN` / `LEFT JOIN` / `RIGHT JOIN`
    // from their explicit `OUTER` forms via separate variants. We accept both
    // because sqlparser 0.54 collapsed them onto `Inner` / `LeftOuter` /
    // `RightOuter`; the SQL semantics are unchanged.
    let join_type = match &join.join_operator {
        JoinOperator::Inner(_) | JoinOperator::Join(_) => JoinType::Inner,
        JoinOperator::LeftOuter(_) | JoinOperator::Left(_) => JoinType::Left,
        JoinOperator::RightOuter(_) | JoinOperator::Right(_) => JoinType::Right,
        JoinOperator::FullOuter(_) => JoinType::Full,
        JoinOperator::CrossJoin(_) => JoinType::Cross,
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "join type not supported: {other:?}"
            )));
        }
    };

    // Extract table name or subquery
    let mut inline_ctes = Vec::new();
    let table = match &join.relation {
        sqlparser::ast::TableFactor::Table { name, .. } => object_name_to_string(name),
        sqlparser::ast::TableFactor::Derived {
            subquery, alias, ..
        } => {
            let alias_name = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .ok_or_else(|| {
                    QueryError::ParseError("subquery in JOIN requires an alias".to_string())
                })?;

            // Parse the subquery as a SELECT
            let inner = match subquery.body.as_ref() {
                SetExpr::Select(s) => parse_select(s)?,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "subquery body must be a simple SELECT".to_string(),
                    ));
                }
            };

            let order_by = match &subquery.order_by {
                Some(ob) => parse_order_by(ob)?,
                None => vec![],
            };
            let limit = parse_limit(query_limit_expr(subquery)?)?;

            inline_ctes.push(ParsedCte {
                name: alias_name.clone(),
                query: ParsedSelect {
                    order_by,
                    limit,
                    ..inner
                },
                recursive_arm: None,
            });

            alias_name
        }
        _ => {
            return Err(QueryError::UnsupportedFeature(
                "unsupported JOIN relation type".to_string(),
            ));
        }
    };

    // Extract ON / USING condition. CROSS JOIN has no condition.
    let on_condition = match &join.join_operator {
        JoinOperator::CrossJoin(_) => Vec::new(),
        JoinOperator::Inner(constraint)
        | JoinOperator::Join(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::Left(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::Right(constraint)
        | JoinOperator::FullOuter(constraint) => match constraint {
            JoinConstraint::On(expr) => parse_join_condition(expr)?,
            JoinConstraint::Using(idents) => {
                // USING (a, b) → ON left.a = right.a AND left.b = right.b.
                // sqlparser models each USING column as an ObjectName for
                // compatibility with qualified identifiers in some dialects;
                // we accept only single-part bare column names here.
                let mut preds = Vec::new();
                for name in idents {
                    if name.0.len() != 1 {
                        return Err(QueryError::UnsupportedFeature(format!(
                            "USING column must be a bare identifier, got {name}"
                        )));
                    }
                    let col_name = name.0[0]
                        .as_ident()
                        .ok_or_else(|| {
                            QueryError::UnsupportedFeature(format!(
                                "USING column must be a bare identifier, got {name}"
                            ))
                        })?
                        .value
                        .clone();
                    preds.push(Predicate::Eq(
                        ColumnName::new(col_name.clone()),
                        PredicateValue::ColumnRef(col_name),
                    ));
                }
                preds
            }
            JoinConstraint::Natural => {
                return Err(QueryError::UnsupportedFeature(
                    "NATURAL JOIN is not supported; use ON or USING explicitly".to_string(),
                ));
            }
            JoinConstraint::None => {
                return Err(QueryError::UnsupportedFeature(
                    "join without ON or USING clause not supported".to_string(),
                ));
            }
        },
        _ => {
            return Err(QueryError::UnsupportedFeature(
                "join without ON clause not supported".to_string(),
            ));
        }
    };

    Ok((
        ParsedJoin {
            table,
            join_type,
            on_condition,
        },
        inline_ctes,
    ))
}

/// Parses a JOIN ON condition into a list of predicates.
/// Handles AND combinations: ON a.id = b.id AND a.status = 'active'
fn parse_join_condition(expr: &Expr) -> Result<Vec<Predicate>> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            let mut predicates = parse_join_condition(left)?;
            predicates.extend(parse_join_condition(right)?);
            Ok(predicates)
        }
        _ => {
            // Single predicate - reuse existing WHERE parser logic
            parse_where_expr(expr)
        }
    }
}

fn parse_select(select: &Select) -> Result<ParsedSelect> {
    // Parse DISTINCT flag
    let distinct = select.distinct.is_some();

    // Parse FROM - must be exactly one table
    if select.from.len() != 1 {
        return Err(QueryError::ParseError(format!(
            "expected exactly 1 table in FROM clause, got {}",
            select.from.len()
        )));
    }

    let from = &select.from[0];

    // Collect CTEs generated from subqueries (derived tables)
    let mut inline_ctes = Vec::new();

    // Parse JOINs (may generate inline CTEs from subquery joins)
    let mut joins = Vec::new();
    for join in &from.joins {
        let (parsed_join, join_ctes) = parse_join_with_subqueries(join)?;
        joins.push(parsed_join);
        inline_ctes.extend(join_ctes);
    }

    let table = match &from.relation {
        sqlparser::ast::TableFactor::Table { name, .. } => object_name_to_string(name),
        sqlparser::ast::TableFactor::Derived {
            subquery, alias, ..
        } => {
            let alias_name = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .ok_or_else(|| {
                    QueryError::ParseError("subquery in FROM requires an alias".to_string())
                })?;

            // Parse the subquery as a SELECT
            let inner = match subquery.body.as_ref() {
                SetExpr::Select(s) => parse_select(s)?,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "subquery body must be a simple SELECT".to_string(),
                    ));
                }
            };

            let order_by = match &subquery.order_by {
                Some(ob) => parse_order_by(ob)?,
                None => vec![],
            };
            let limit = parse_limit(query_limit_expr(subquery)?)?;

            inline_ctes.push(ParsedCte {
                name: alias_name.clone(),
                query: ParsedSelect {
                    order_by,
                    limit,
                    ..inner
                },
                recursive_arm: None,
            });

            alias_name
        }
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "unsupported FROM clause: {other:?}"
            )));
        }
    };

    // Parse SELECT columns (skips CASE WHEN expressions; they're handled separately below)
    let (columns, column_aliases) = parse_select_items(&select.projection)?;

    // Parse CASE WHEN computed columns from SELECT
    let case_columns = parse_case_columns_from_select_items(&select.projection)?;

    // Parse WHERE predicates
    let predicates = match &select.selection {
        Some(expr) => parse_where_expr(expr)?,
        None => vec![],
    };

    // Parse GROUP BY clause
    let group_by = match &select.group_by {
        sqlparser::ast::GroupByExpr::Expressions(exprs, _) if !exprs.is_empty() => {
            parse_group_by_expr(exprs)?
        }
        sqlparser::ast::GroupByExpr::All(_) => {
            return Err(QueryError::UnsupportedFeature(
                "GROUP BY ALL is not supported".to_string(),
            ));
        }
        sqlparser::ast::GroupByExpr::Expressions(_, _) => vec![],
    };

    // Parse aggregates from SELECT clause (with optional FILTER (WHERE ...))
    let (aggregates, aggregate_filters) = parse_aggregates_from_select_items(&select.projection)?;

    // Parse HAVING clause
    let having = match &select.having {
        Some(expr) => parse_having_expr(expr)?,
        None => vec![],
    };

    // AUDIT-2026-04 S3.2 — extract window functions (`OVER (...)`)
    // from the SELECT projection. Empty vec means no window pass.
    let window_fns = parse_window_fns_from_select_items(&select.projection)?;

    // v0.5.1 — extract scalar-function projections (UPPER, CAST, ||, …)
    // from the SELECT projection. Empty vec means no scalar pass.
    let scalar_projections = parse_scalar_columns_from_select_items(&select.projection)?;

    Ok(ParsedSelect {
        table,
        joins,
        columns,
        column_aliases,
        case_columns,
        predicates,
        order_by: vec![],
        limit: None,
        offset: None,
        aggregates,
        aggregate_filters,
        group_by,
        distinct,
        having,
        ctes: inline_ctes,
        window_fns,
        scalar_projections,
    })
}

/// Parses WITH clause CTEs.
///
/// Recursive CTEs (`WITH RECURSIVE name AS (anchor UNION [ALL] recursive)`)
/// are decomposed into the anchor SELECT plus the recursive arm. The
/// recursive arm references `name` as a virtual table which the executor
/// materialises iteratively.
fn parse_ctes(with: &sqlparser::ast::With) -> Result<Vec<ParsedCte>> {
    let max_ctes = 16;
    let mut ctes = Vec::new();

    for (i, cte) in with.cte_tables.iter().enumerate() {
        if i >= max_ctes {
            return Err(QueryError::UnsupportedFeature(format!(
                "too many CTEs (max {max_ctes})"
            )));
        }

        let name = cte.alias.name.value.clone();

        // For recursive CTEs the body is a SetOperation:
        //   anchor UNION [ALL] recursive
        // We treat the LEFT side as the anchor and the RIGHT side as the
        // recursive arm. Non-set bodies are treated as ordinary CTEs.
        let (inner_select, recursive_arm) = match cte.query.body.as_ref() {
            SetExpr::Select(s) => (parse_select(s)?, None),
            SetExpr::SetOperation {
                op, left, right, ..
            } if with.recursive => {
                use sqlparser::ast::SetOperator;
                if !matches!(op, SetOperator::Union) {
                    return Err(QueryError::UnsupportedFeature(
                        "recursive CTE body must use UNION (not INTERSECT/EXCEPT)".to_string(),
                    ));
                }
                let anchor = match left.as_ref() {
                    SetExpr::Select(s) => parse_select(s)?,
                    _ => {
                        return Err(QueryError::UnsupportedFeature(
                            "recursive CTE anchor must be a simple SELECT".to_string(),
                        ));
                    }
                };
                let recursive = match right.as_ref() {
                    SetExpr::Select(s) => parse_select(s)?,
                    _ => {
                        return Err(QueryError::UnsupportedFeature(
                            "recursive CTE recursive arm must be a simple SELECT".to_string(),
                        ));
                    }
                };
                (anchor, Some(recursive))
            }
            _ => {
                return Err(QueryError::UnsupportedFeature(
                    "CTE body must be a simple SELECT (or anchor UNION recursive for WITH RECURSIVE)".to_string(),
                ));
            }
        };

        // Apply ORDER BY and LIMIT from the CTE query
        let order_by = match &cte.query.order_by {
            Some(ob) => parse_order_by(ob)?,
            None => vec![],
        };
        let limit = parse_limit(query_limit_expr(&cte.query)?)?;

        ctes.push(ParsedCte {
            name,
            query: ParsedSelect {
                order_by,
                limit,
                ..inner_select
            },
            recursive_arm,
        });
    }

    Ok(ctes)
}

/// Parses a HAVING clause expression into conditions.
///
/// Supports: `HAVING aggregate_fn(col) op value` with AND combinations.
/// Example: `HAVING COUNT(*) > 5 AND SUM(amount) < 1000`
fn parse_having_expr(expr: &Expr) -> Result<Vec<HavingCondition>> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            let mut conditions = parse_having_expr(left)?;
            conditions.extend(parse_having_expr(right)?);
            Ok(conditions)
        }
        Expr::BinaryOp { left, op, right } => {
            // Left side must be an aggregate function
            let aggregate = match left.as_ref() {
                Expr::Function(_) => {
                    let (agg, _filter) = try_parse_aggregate(left)?.ok_or_else(|| {
                        QueryError::UnsupportedFeature(
                            "HAVING requires aggregate functions (COUNT, SUM, AVG, MIN, MAX)"
                                .to_string(),
                        )
                    })?;
                    agg
                }
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "HAVING clause must reference aggregate functions".to_string(),
                    ));
                }
            };

            // Right side must be a literal value
            let value = expr_to_value(right)?;

            // Map the operator
            let having_op = match op {
                BinaryOperator::Eq => HavingOp::Eq,
                BinaryOperator::Lt => HavingOp::Lt,
                BinaryOperator::LtEq => HavingOp::Le,
                BinaryOperator::Gt => HavingOp::Gt,
                BinaryOperator::GtEq => HavingOp::Ge,
                other => {
                    return Err(QueryError::UnsupportedFeature(format!(
                        "unsupported HAVING operator: {other:?}"
                    )));
                }
            };

            Ok(vec![HavingCondition::AggregateComparison {
                aggregate,
                op: having_op,
                value,
            }])
        }
        Expr::Nested(inner) => parse_having_expr(inner),
        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported HAVING expression: {other:?}"
        ))),
    }
}

/// Returns `(columns, aliases)` where `aliases[i]` is `Some(alias)` when
/// the i-th selected column was written `col AS alias` or `col alias`, and
/// `None` otherwise. When the SELECT is a bare `*`, both returned options
/// are `None`.
///
/// ROADMAP v0.5.0 item A — SELECT alias preservation. v0.4.x discarded
/// aliases at parse time; this function is the source of truth for the
/// output-column-name substitution performed later in the planner.
/// `(columns, aliases)` — each parallel to the SELECT projection list. A
/// `None` pair signals `SELECT *`; otherwise both are `Some` and the same
/// length. `aliases[i]` is `Some("name")` if the i-th item was written
/// `col AS name` (or `col name`), `None` if the projection was an
/// unaliased bare column.
type ParsedSelectList = (Option<Vec<ColumnName>>, Option<Vec<Option<String>>>);

fn parse_select_items(items: &[SelectItem]) -> Result<ParsedSelectList> {
    let mut columns = Vec::new();
    let mut aliases: Vec<Option<String>> = Vec::new();

    for item in items {
        // Arms with empty bodies are kept grouped by skip-reason
        // (aggregate/CASE vs v0.5.1 scalar functions vs `||`) so the
        // grouping survives future refactors. Merging them would lose
        // the comment-as-documentation.
        #[allow(clippy::match_same_arms)]
        match item {
            SelectItem::Wildcard(_) => {
                // SELECT * - return None to indicate all columns. Aliases
                // are not applicable when the projection is the wildcard.
                return Ok((None, None));
            }
            SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                columns.push(ColumnName::new(ident.value.clone()));
                aliases.push(None);
            }
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(idents)) if idents.len() == 2 => {
                // table.column - just use the column name
                columns.push(ColumnName::new(idents[1].value.clone()));
                aliases.push(None);
            }
            SelectItem::ExprWithAlias {
                expr: Expr::Identifier(ident),
                alias,
            } => {
                columns.push(ColumnName::new(ident.value.clone()));
                aliases.push(Some(alias.value.clone()));
            }
            SelectItem::ExprWithAlias {
                expr: Expr::CompoundIdentifier(idents),
                alias,
            } if idents.len() == 2 => {
                // table.column AS alias
                columns.push(ColumnName::new(idents[1].value.clone()));
                aliases.push(Some(alias.value.clone()));
            }
            SelectItem::UnnamedExpr(Expr::Function(_))
            | SelectItem::ExprWithAlias {
                expr: Expr::Function(_) | Expr::Case { .. },
                ..
            } => {
                // Aggregate functions, CASE WHEN, window functions, and
                // scalar-function projections all have dedicated passes
                // elsewhere. Skip them here.
            }
            // v0.5.1: scalar-function projections / CAST / `||` handled by
            // `parse_scalar_columns_from_select_items`. Skip so bare
            // `columns` / `column_aliases` stay aligned.
            SelectItem::UnnamedExpr(Expr::Cast { .. })
            | SelectItem::ExprWithAlias {
                expr: Expr::Cast { .. },
                ..
            } => {}
            SelectItem::UnnamedExpr(Expr::BinaryOp {
                op: BinaryOperator::StringConcat,
                ..
            })
            | SelectItem::ExprWithAlias {
                expr:
                    Expr::BinaryOp {
                        op: BinaryOperator::StringConcat,
                        ..
                    },
                ..
            } => {}
            other => {
                return Err(QueryError::UnsupportedFeature(format!(
                    "unsupported SELECT item: {other:?}"
                )));
            }
        }
    }

    Ok((Some(columns), Some(aliases)))
}

/// Parses aggregate functions from SELECT items.
///
/// Returns `(aggregates, filters)` where `filters[i]` is the optional
/// `FILTER (WHERE ...)` for `aggregates[i]`. The two vectors are 1:1 length.
/// `(aggregates, filters)` — two parallel vectors of the same length.
/// `filters[i]` is `Some(pred)` when the i-th aggregate carried a
/// `FILTER (WHERE pred)` clause, `None` otherwise.
type ParsedAggregateList = (Vec<AggregateFunction>, Vec<Option<Vec<Predicate>>>);

fn parse_aggregates_from_select_items(items: &[SelectItem]) -> Result<ParsedAggregateList> {
    let mut aggregates = Vec::new();
    let mut filters = Vec::new();

    for item in items {
        match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                if let Some((agg, filter)) = try_parse_aggregate(expr)? {
                    aggregates.push(agg);
                    filters.push(filter);
                }
            }
            _ => {
                // SELECT * has no aggregates; ignore other select items (Wildcard, QualifiedWildcard, etc.)
            }
        }
    }

    Ok((aggregates, filters))
}

/// Parses CASE WHEN computed columns from SELECT items.
///
/// Extracts `CASE WHEN cond THEN val ... ELSE val END AS alias` expressions.
/// An alias is required so the column has a name in the output.
fn parse_case_columns_from_select_items(items: &[SelectItem]) -> Result<Vec<ComputedColumn>> {
    let mut case_cols = Vec::new();

    for item in items {
        if let SelectItem::ExprWithAlias {
            expr:
                Expr::Case {
                    operand,
                    conditions,
                    else_result,
                    ..
                },
            alias,
        } = item
        {
            // Simple CASE (CASE x WHEN v THEN ...) desugars to searched CASE
            // by synthesising `x = v` for each WHEN arm. This means downstream
            // planning, materialisation, and execution remain unchanged — only
            // the parser front-end is extended.
            let mut when_clauses = Vec::new();
            for case_when in conditions {
                let cond_expr = &case_when.condition;
                let result_expr = &case_when.result;
                let condition = match operand.as_deref() {
                    None => parse_where_expr(cond_expr)?,
                    Some(operand_expr) => parse_where_expr(&Expr::BinaryOp {
                        left: Box::new(operand_expr.clone()),
                        op: BinaryOperator::Eq,
                        right: Box::new(cond_expr.clone()),
                    })?,
                };
                let result = expr_to_value(result_expr)?;
                when_clauses.push(CaseWhenArm { condition, result });
            }

            let else_value = match else_result {
                Some(expr) => expr_to_value(expr)?,
                None => Value::Null,
            };

            case_cols.push(ComputedColumn {
                alias: ColumnName::new(alias.value.clone()),
                when_clauses,
                else_value,
            });
        }
    }

    Ok(case_cols)
}

/// v0.5.1 — extract scalar-function / CAST / `||` projections from
/// SELECT items. Skips bare columns, aggregates, CASE, and window
/// functions (those have dedicated passes). Returns one entry per
/// scalar projection in left-to-right order.
///
/// The output column name prefers the user-supplied alias; when no
/// alias is given, a PostgreSQL-style default is synthesised from
/// the outermost function name (`UPPER`, `COALESCE`, `CAST`, `CONCAT`,
/// …). CAST defaults are lowercased for consistency with PG.
fn parse_scalar_columns_from_select_items(
    items: &[SelectItem],
) -> Result<Vec<ParsedScalarProjection>> {
    let mut out = Vec::new();
    for item in items {
        let (expr, alias) = match item {
            SelectItem::UnnamedExpr(e) => (e, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
            _ => continue,
        };

        if !is_scalar_projection_shape(expr) {
            continue;
        }

        let scalar = expr_to_scalar_expr(expr)?;
        let output_name = alias
            .clone()
            .unwrap_or_else(|| synthesize_column_name(expr));
        out.push(ParsedScalarProjection {
            expr: scalar,
            output_name: ColumnName::new(output_name),
            alias,
        });
    }
    Ok(out)
}

/// Is this expression shape a scalar projection we should handle? Bare
/// columns, aggregate function calls, CASE, and window functions stay
/// on their dedicated passes and return `false` here.
fn is_scalar_projection_shape(expr: &Expr) -> bool {
    match expr {
        Expr::Function(func) => {
            // Window and aggregate functions have dedicated passes.
            if func.over.is_some() {
                return false;
            }
            let name = func.name.to_string().to_uppercase();
            !matches!(name.as_str(), "COUNT" | "SUM" | "AVG" | "MIN" | "MAX")
        }
        Expr::Cast { .. }
        | Expr::BinaryOp {
            op: BinaryOperator::StringConcat,
            ..
        } => true,
        _ => false,
    }
}

/// Synthesise a default output-column name for an un-aliased scalar
/// projection. Uses the outermost function/operator name, lowercased,
/// matching PostgreSQL's rendering of `SELECT UPPER(x)` → `"upper"`.
fn synthesize_column_name(expr: &Expr) -> String {
    match expr {
        Expr::Function(func) => func.name.to_string().to_lowercase(),
        Expr::Cast { .. } => "cast".to_string(),
        Expr::BinaryOp {
            op: BinaryOperator::StringConcat,
            ..
        } => "concat".to_string(),
        _ => "expr".to_string(),
    }
}

/// AUDIT-2026-04 S3.2 — extract window functions (`<fn>(args) OVER
/// (...)`) from SELECT projection items. Returns one entry per
/// window-function projection in left-to-right order.
fn parse_window_fns_from_select_items(items: &[SelectItem]) -> Result<Vec<ParsedWindowFn>> {
    let mut out = Vec::new();
    for item in items {
        let (expr, alias) = match item {
            SelectItem::UnnamedExpr(e) => (e, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
            _ => continue,
        };
        if let Some(parsed) = try_parse_window_fn(expr, alias)? {
            out.push(parsed);
        }
    }
    Ok(out)
}

fn try_parse_window_fn(expr: &Expr, alias: Option<String>) -> Result<Option<ParsedWindowFn>> {
    let Expr::Function(func) = expr else {
        return Ok(None);
    };
    let Some(over) = &func.over else {
        return Ok(None);
    };
    let spec = match over {
        sqlparser::ast::WindowType::WindowSpec(s) => s,
        sqlparser::ast::WindowType::NamedWindow(_) => {
            return Err(QueryError::UnsupportedFeature(
                "named windows (OVER w) are not supported".into(),
            ));
        }
    };
    if spec.window_frame.is_some() {
        return Err(QueryError::UnsupportedFeature(
            "explicit window frames (ROWS/RANGE BETWEEN ...) are not supported; \
             omit the frame clause for default behaviour"
                .into(),
        ));
    }

    let func_name = func.name.to_string().to_uppercase();
    let args = match &func.args {
        sqlparser::ast::FunctionArguments::List(list) => list.args.clone(),
        _ => Vec::new(),
    };
    let function = parse_window_function_name(&func_name, &args)?;

    let partition_by: Vec<ColumnName> = spec
        .partition_by
        .iter()
        .map(parse_column_expr)
        .collect::<Result<_>>()?;
    let order_by: Vec<OrderByClause> = spec
        .order_by
        .iter()
        .map(parse_order_by_expr)
        .collect::<Result<_>>()?;

    Ok(Some(ParsedWindowFn {
        function,
        partition_by,
        order_by,
        alias,
    }))
}

fn parse_column_expr(expr: &Expr) -> Result<ColumnName> {
    match expr {
        Expr::Identifier(ident) => Ok(ColumnName::new(ident.value.clone())),
        Expr::CompoundIdentifier(idents) if idents.len() == 2 => {
            Ok(ColumnName::new(idents[1].value.clone()))
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "window PARTITION BY / argument must be a column reference, got: {other:?}"
        ))),
    }
}

fn parse_window_function_name(
    name: &str,
    args: &[sqlparser::ast::FunctionArg],
) -> Result<crate::window::WindowFunction> {
    use crate::window::WindowFunction;

    let arg_exprs: Vec<&Expr> = args
        .iter()
        .filter_map(|a| match a {
            sqlparser::ast::FunctionArg::Unnamed(sqlparser::ast::FunctionArgExpr::Expr(e)) => {
                Some(e)
            }
            _ => None,
        })
        .collect();

    let single_col = || -> Result<ColumnName> {
        if arg_exprs.is_empty() {
            return Err(QueryError::ParseError(format!(
                "{name} requires a column argument"
            )));
        }
        parse_column_expr(arg_exprs[0])
    };

    let parse_offset = || -> Result<usize> {
        if arg_exprs.len() < 2 {
            return Ok(1);
        }
        match arg_exprs[1] {
            Expr::Value(vws) => match &vws.value {
                SqlValue::Number(n, _) => n
                    .parse::<usize>()
                    .map_err(|_| QueryError::ParseError(format!("invalid {name} offset: {n}"))),
                other => Err(QueryError::UnsupportedFeature(format!(
                    "{name} offset must be a literal integer; got {other:?}"
                ))),
            },
            other => Err(QueryError::UnsupportedFeature(format!(
                "{name} offset must be a literal integer; got {other:?}"
            ))),
        }
    };

    match name {
        "ROW_NUMBER" => Ok(WindowFunction::RowNumber),
        "RANK" => Ok(WindowFunction::Rank),
        "DENSE_RANK" => Ok(WindowFunction::DenseRank),
        "LAG" => Ok(WindowFunction::Lag {
            column: single_col()?,
            offset: parse_offset()?,
        }),
        "LEAD" => Ok(WindowFunction::Lead {
            column: single_col()?,
            offset: parse_offset()?,
        }),
        "FIRST_VALUE" => Ok(WindowFunction::FirstValue {
            column: single_col()?,
        }),
        "LAST_VALUE" => Ok(WindowFunction::LastValue {
            column: single_col()?,
        }),
        other => Err(QueryError::UnsupportedFeature(format!(
            "unknown window function: {other}"
        ))),
    }
}

/// Result of parsing an aggregate function with its optional `FILTER (WHERE ...)`.
type ParsedAggregate = (AggregateFunction, Option<Vec<Predicate>>);

/// Tries to parse an expression as an aggregate function.
/// Returns None if the expression is not an aggregate function.
/// On match, also returns the `FILTER (WHERE ...)` predicates if present.
fn try_parse_aggregate(expr: &Expr) -> Result<Option<ParsedAggregate>> {
    let parsed_filter: Option<Vec<Predicate>> = match expr {
        Expr::Function(func) => match &func.filter {
            Some(filter_expr) => Some(parse_where_expr(filter_expr)?),
            None => None,
        },
        _ => None,
    };
    let func_only = try_parse_aggregate_func(expr)?;
    Ok(func_only.map(|f| (f, parsed_filter)))
}

/// Parses just the aggregate function shape, ignoring any `FILTER` clause.
fn try_parse_aggregate_func(expr: &Expr) -> Result<Option<AggregateFunction>> {
    match expr {
        Expr::Function(func) => {
            // AUDIT-2026-04 S3.2 — `<fn>() OVER (...)` is a window
            // function, not an aggregate. Window detection runs in
            // its own pass; bail out so we don't double-count
            // (e.g. SUM(x) OVER ... or RANK() OVER ...).
            if func.over.is_some() {
                return Ok(None);
            }
            let func_name = func.name.to_string().to_uppercase();

            // Extract function arguments from the FunctionArguments enum
            let args = match &func.args {
                sqlparser::ast::FunctionArguments::List(list) => &list.args,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "non-list function arguments not supported".to_string(),
                    ));
                }
            };

            match func_name.as_str() {
                "COUNT" => {
                    // COUNT(*) or COUNT(column)
                    if args.len() == 1 {
                        match &args[0] {
                            sqlparser::ast::FunctionArg::Unnamed(arg_expr) => match arg_expr {
                                sqlparser::ast::FunctionArgExpr::Wildcard => {
                                    Ok(Some(AggregateFunction::CountStar))
                                }
                                sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(ident)) => {
                                    Ok(Some(AggregateFunction::Count(ColumnName::new(
                                        ident.value.clone(),
                                    ))))
                                }
                                _ => Err(QueryError::UnsupportedFeature(
                                    "COUNT with complex expression not supported".to_string(),
                                )),
                            },
                            _ => Err(QueryError::UnsupportedFeature(
                                "named function arguments not supported".to_string(),
                            )),
                        }
                    } else {
                        Err(QueryError::ParseError(format!(
                            "COUNT expects 1 argument, got {}",
                            args.len()
                        )))
                    }
                }
                "SUM" | "AVG" | "MIN" | "MAX" => {
                    // SUM/AVG/MIN/MAX(column)
                    if args.len() != 1 {
                        return Err(QueryError::ParseError(format!(
                            "{} expects 1 argument, got {}",
                            func_name,
                            args.len()
                        )));
                    }

                    match &args[0] {
                        sqlparser::ast::FunctionArg::Unnamed(arg_expr) => match arg_expr {
                            sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(ident)) => {
                                let column = ColumnName::new(ident.value.clone());
                                match func_name.as_str() {
                                    "SUM" => Ok(Some(AggregateFunction::Sum(column))),
                                    "AVG" => Ok(Some(AggregateFunction::Avg(column))),
                                    "MIN" => Ok(Some(AggregateFunction::Min(column))),
                                    "MAX" => Ok(Some(AggregateFunction::Max(column))),
                                    _ => unreachable!(),
                                }
                            }
                            _ => Err(QueryError::UnsupportedFeature(format!(
                                "{func_name} with complex expression not supported"
                            ))),
                        },
                        _ => Err(QueryError::UnsupportedFeature(
                            "named function arguments not supported".to_string(),
                        )),
                    }
                }
                _ => {
                    // Not an aggregate function
                    Ok(None)
                }
            }
        }
        _ => {
            // Not a function call
            Ok(None)
        }
    }
}

/// Parses GROUP BY expressions into column names.
fn parse_group_by_expr(exprs: &[Expr]) -> Result<Vec<ColumnName>> {
    let mut columns = Vec::new();

    for expr in exprs {
        match expr {
            Expr::Identifier(ident) => {
                columns.push(ColumnName::new(ident.value.clone()));
            }
            _ => {
                return Err(QueryError::UnsupportedFeature(
                    "complex GROUP BY expressions not supported".to_string(),
                ));
            }
        }
    }

    Ok(columns)
}

/// Maximum nesting depth for WHERE clause expressions.
///
/// Prevents stack overflow from deeply nested queries like:
/// `WHERE ((((...(a = 1)...))))`
///
/// 100 levels is sufficient for all practical queries while preventing
/// malicious or pathological input from exhausting the stack.
const MAX_WHERE_DEPTH: usize = 100;

fn parse_where_expr(expr: &Expr) -> Result<Vec<Predicate>> {
    parse_where_expr_inner(expr, 0)
}

/// Parses a sqlparser `Query` (subquery body) into a `ParsedSelect`.
///
/// Used by `IN (SELECT ...)` and `EXISTS (SELECT ...)` predicate parsing.
/// Rejects nested set operations (UNION/INTERSECT/EXCEPT) inside subqueries
/// — the caller should issue a clear error rather than misinterpreting them.
fn parse_select_from_query(query: &sqlparser::ast::Query) -> Result<ParsedSelect> {
    match query.body.as_ref() {
        SetExpr::Select(s) => {
            let mut parsed = parse_select(s)?;
            if let Some(ob) = &query.order_by {
                parsed.order_by = parse_order_by(ob)?;
            }
            parsed.limit = parse_limit(query_limit_expr(query)?)?;
            parsed.offset = parse_offset_clause(query_offset(query))?;
            Ok(parsed)
        }
        _ => Err(QueryError::UnsupportedFeature(
            "subquery body must be a simple SELECT (no nested UNION/INTERSECT/EXCEPT)".to_string(),
        )),
    }
}

fn parse_where_expr_inner(expr: &Expr, depth: usize) -> Result<Vec<Predicate>> {
    if depth >= MAX_WHERE_DEPTH {
        return Err(QueryError::ParseError(format!(
            "WHERE clause nesting exceeds maximum depth of {MAX_WHERE_DEPTH}"
        )));
    }

    match expr {
        // AND combines multiple predicates
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            let mut predicates = parse_where_expr_inner(left, depth + 1)?;
            predicates.extend(parse_where_expr_inner(right, depth + 1)?);
            Ok(predicates)
        }

        // OR creates a disjunction
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => {
            let left_preds = parse_where_expr_inner(left, depth + 1)?;
            let right_preds = parse_where_expr_inner(right, depth + 1)?;
            Ok(vec![Predicate::Or(left_preds, right_preds)])
        }

        // LIKE / NOT LIKE pattern matching
        Expr::Like {
            expr,
            pattern,
            negated,
            ..
        } => {
            let column = expr_to_column(expr)?;
            let pattern_str = match expr_to_predicate_value(pattern)? {
                PredicateValue::String(s) | PredicateValue::Literal(Value::Text(s)) => s,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "LIKE pattern must be a string literal".to_string(),
                    ));
                }
            };
            let predicate = if *negated {
                Predicate::NotLike(column, pattern_str)
            } else {
                Predicate::Like(column, pattern_str)
            };
            Ok(vec![predicate])
        }

        // ILIKE / NOT ILIKE (case-insensitive)
        Expr::ILike {
            expr,
            pattern,
            negated,
            ..
        } => {
            let column = expr_to_column(expr)?;
            let pattern_str = match expr_to_predicate_value(pattern)? {
                PredicateValue::String(s) | PredicateValue::Literal(Value::Text(s)) => s,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "ILIKE pattern must be a string literal".to_string(),
                    ));
                }
            };
            let predicate = if *negated {
                Predicate::NotILike(column, pattern_str)
            } else {
                Predicate::ILike(column, pattern_str)
            };
            Ok(vec![predicate])
        }

        // IS NULL / IS NOT NULL
        Expr::IsNull(expr) => {
            let column = expr_to_column(expr)?;
            Ok(vec![Predicate::IsNull(column)])
        }

        Expr::IsNotNull(expr) => {
            let column = expr_to_column(expr)?;
            Ok(vec![Predicate::IsNotNull(column)])
        }

        // Comparison operators
        Expr::BinaryOp { left, op, right } => {
            let predicate = parse_comparison(left, op, right)?;
            Ok(vec![predicate])
        }

        // IN list / NOT IN list
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let column = expr_to_column(expr)?;
            let values: Result<Vec<_>> = list.iter().map(expr_to_predicate_value).collect();
            if *negated {
                Ok(vec![Predicate::NotIn(column, values?)])
            } else {
                Ok(vec![Predicate::In(column, values?)])
            }
        }

        // IN (SELECT ...) / NOT IN (SELECT ...) — may be uncorrelated
        // (pre-executed) or correlated (handled by the correlated-loop
        // executor). See `docs/reference/sql/correlated-subqueries.md`.
        Expr::InSubquery {
            expr,
            subquery,
            negated,
        } => {
            let column = expr_to_column(expr)?;
            let inner = parse_select_from_query(subquery)?;
            Ok(vec![Predicate::InSubquery {
                column,
                subquery: Box::new(inner),
                negated: *negated,
            }])
        }

        // EXISTS (SELECT ...) and NOT EXISTS (SELECT ...).
        Expr::Exists { subquery, negated } => {
            let inner = parse_select_from_query(subquery)?;
            Ok(vec![Predicate::Exists {
                subquery: Box::new(inner),
                negated: *negated,
            }])
        }

        // BETWEEN: col BETWEEN low AND high desugars to col >= low AND col <= high.
        // NOT BETWEEN stays as a first-class `Predicate::NotBetween` so the
        // FilterOp can correctly surface SQL three-valued logic (NULL cells
        // evaluate to false, not `NOT (>= AND <=)` = `< OR >` which would
        // exclude some NULL cases surreptitiously).
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => {
            let column = expr_to_column(expr)?;
            let low_val = expr_to_predicate_value(low)?;
            let high_val = expr_to_predicate_value(high)?;

            if *negated {
                return Ok(vec![Predicate::NotBetween(column, low_val, high_val)]);
            }

            kimberlite_properties::sometimes!(
                true,
                "query.between_desugared_to_ge_le",
                "BETWEEN predicate desugared into Ge + Le pair"
            );

            Ok(vec![
                Predicate::Ge(column.clone(), low_val),
                Predicate::Le(column, high_val),
            ])
        }

        // Parenthesized expression
        Expr::Nested(inner) => parse_where_expr_inner(inner, depth + 1),

        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported WHERE expression: {other:?}"
        ))),
    }
}

fn parse_comparison(left: &Expr, op: &BinaryOperator, right: &Expr) -> Result<Predicate> {
    // Unwrap one layer of parens on the LHS so `(data->>'k') = $1` works
    // around the GenericDialect's surprising operator-precedence (it parses
    // `->` and `->>` with lower precedence than `=`).
    let left = match left {
        Expr::Nested(inner) => inner.as_ref(),
        other => other,
    };

    // JSON containment: `data @> json_value` (RHS may be a JSON literal,
    // a parameter, or a string interpreted as JSON).
    if matches!(op, BinaryOperator::AtArrow) {
        let column = expr_to_column(left)?;
        let value = expr_to_predicate_value(right)?;
        return Ok(Predicate::JsonContains { column, value });
    }

    // JSON path-extract on LHS combined with comparison: `data->'key' = v`
    // or `data->>'key' = v`. We only support equality on the extracted side
    // for the v0 JSON op surface; ranges on extracted values would require
    // type-tagging the path result.
    if let Expr::BinaryOp {
        left: json_left,
        op: arrow_op @ (BinaryOperator::Arrow | BinaryOperator::LongArrow),
        right: path_expr,
    } = left
    {
        let as_text = matches!(arrow_op, BinaryOperator::LongArrow);
        let column = expr_to_column(json_left)?;
        let path = match path_expr.as_ref() {
            Expr::Value(vws) => match &vws.value {
                SqlValue::SingleQuotedString(s) | SqlValue::DoubleQuotedString(s) => s.clone(),
                SqlValue::Number(n, _) => n.clone(),
                _ => {
                    return Err(QueryError::UnsupportedFeature(format!(
                        "JSON path key must be a string or integer literal, got {path_expr:?}"
                    )));
                }
            },
            other => {
                return Err(QueryError::UnsupportedFeature(format!(
                    "JSON path key must be a string or integer literal, got {other:?}"
                )));
            }
        };
        let value = expr_to_predicate_value(right)?;
        if !matches!(op, BinaryOperator::Eq) {
            return Err(QueryError::UnsupportedFeature(format!(
                "JSON path extraction supports only `=` comparison; got {op:?}"
            )));
        }
        return Ok(Predicate::JsonExtractEq {
            column,
            path,
            as_text,
            value,
        });
    }

    // Map the SQL comparison operator to one of our predicate shapes.
    // Any operator we don't recognise (`<>`, `!=`) routes through the
    // ScalarCmp fall-through below so rows with scalar LHS/RHS still work.
    let cmp_op = sql_binop_to_scalar_cmp(op);

    // Fast path: bare column on the left, literal / parameter / column
    // reference on the right. Keeps the hot query shape allocation-free.
    if !expr_needs_scalar(left) && !expr_needs_scalar(right) {
        if let (Ok(column), Ok(value)) = (expr_to_column(left), expr_to_predicate_value(right)) {
            return match op {
                BinaryOperator::Eq => Ok(Predicate::Eq(column, value)),
                BinaryOperator::Lt => Ok(Predicate::Lt(column, value)),
                BinaryOperator::LtEq => Ok(Predicate::Le(column, value)),
                BinaryOperator::Gt => Ok(Predicate::Gt(column, value)),
                BinaryOperator::GtEq => Ok(Predicate::Ge(column, value)),
                BinaryOperator::NotEq => {
                    // Route != / <> through ScalarCmp since we don't have
                    // a bare-column NotEq predicate today.
                    Ok(Predicate::ScalarCmp {
                        lhs: ScalarExpr::Column(column),
                        op: ScalarCmpOp::NotEq,
                        rhs: predicate_value_to_scalar_expr(&value),
                    })
                }
                other => Err(QueryError::UnsupportedFeature(format!(
                    "unsupported operator: {other:?}"
                ))),
            };
        }
    }

    // Fallback: one or both sides are scalar expressions — build a
    // `Predicate::ScalarCmp` evaluated per row.
    let lhs = expr_to_scalar_expr(left)?;
    let rhs = expr_to_scalar_expr(right)?;
    let op = cmp_op.ok_or_else(|| {
        QueryError::UnsupportedFeature(format!("unsupported operator in scalar comparison: {op:?}"))
    })?;
    Ok(Predicate::ScalarCmp { lhs, op, rhs })
}

/// Returns `true` if the expression needs the scalar-expression path —
/// i.e. it is a function call, CAST, or `||` operator. Bare columns,
/// literals, parens, and parameters use the fast predicate path.
fn expr_needs_scalar(expr: &Expr) -> bool {
    match expr {
        Expr::Function(_)
        | Expr::Cast { .. }
        | Expr::BinaryOp {
            op: BinaryOperator::StringConcat,
            ..
        } => true,
        Expr::Nested(inner) => expr_needs_scalar(inner),
        _ => false,
    }
}

fn sql_binop_to_scalar_cmp(op: &BinaryOperator) -> Option<ScalarCmpOp> {
    Some(match op {
        BinaryOperator::Eq => ScalarCmpOp::Eq,
        BinaryOperator::NotEq => ScalarCmpOp::NotEq,
        BinaryOperator::Lt => ScalarCmpOp::Lt,
        BinaryOperator::LtEq => ScalarCmpOp::Le,
        BinaryOperator::Gt => ScalarCmpOp::Gt,
        BinaryOperator::GtEq => ScalarCmpOp::Ge,
        _ => return None,
    })
}

fn predicate_value_to_scalar_expr(pv: &PredicateValue) -> ScalarExpr {
    match pv {
        PredicateValue::Int(n) => ScalarExpr::Literal(Value::BigInt(*n)),
        PredicateValue::String(s) => ScalarExpr::Literal(Value::Text(s.clone())),
        PredicateValue::Bool(b) => ScalarExpr::Literal(Value::Boolean(*b)),
        PredicateValue::Null => ScalarExpr::Literal(Value::Null),
        PredicateValue::Param(idx) => ScalarExpr::Literal(Value::Placeholder(*idx)),
        PredicateValue::Literal(v) => ScalarExpr::Literal(v.clone()),
        PredicateValue::ColumnRef(name) => {
            // name may be "table.col" or "col"
            let col = name.rsplit('.').next().unwrap_or(name);
            ScalarExpr::Column(ColumnName::new(col.to_string()))
        }
    }
}

fn expr_to_column(expr: &Expr) -> Result<ColumnName> {
    match expr {
        Expr::Identifier(ident) => Ok(ColumnName::new(ident.value.clone())),
        Expr::CompoundIdentifier(idents) if idents.len() == 2 => {
            // table.column - ignore table for now
            Ok(ColumnName::new(idents[1].value.clone()))
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "expected column name, got {other:?}"
        ))),
    }
}

/// Translate a sqlparser expression into a [`ScalarExpr`].
///
/// This is the bridge between the parser's surface-level AST and the
/// row-level evaluator. Handles literals, column references, CAST,
/// BinaryOp::StringConcat (`||`), and the scalar function family
/// (`UPPER`, `LOWER`, `CONCAT`, `COALESCE`, `NULLIF`, `LENGTH`, `TRIM`,
/// `ABS`, `ROUND`, `CEIL`, `CEILING`, `FLOOR`).
///
/// Everything else — including `CASE`, aggregate functions, window
/// functions, sub-queries, and unknown function names — surfaces as
/// [`QueryError::UnsupportedFeature`]. Those live on their own parsing
/// paths (parse_case_columns, parse_aggregates, parse_window_fns).
pub fn expr_to_scalar_expr(expr: &Expr) -> Result<ScalarExpr> {
    match expr {
        // Literal values (including placeholders) — go through expr_to_value
        // which handles unary-minus, placeholders, etc.
        Expr::Value(_) | Expr::UnaryOp { .. } => Ok(ScalarExpr::Literal(expr_to_value(expr)?)),

        // Column references.
        Expr::Identifier(ident) => Ok(ScalarExpr::Column(ColumnName::new(ident.value.clone()))),
        Expr::CompoundIdentifier(idents) if idents.len() == 2 => {
            Ok(ScalarExpr::Column(ColumnName::new(idents[1].value.clone())))
        }

        // `a || b` — string concatenation. Fold into the existing CONCAT
        // evaluator path so NULL propagation is identical.
        Expr::BinaryOp {
            left,
            op: BinaryOperator::StringConcat,
            right,
        } => Ok(ScalarExpr::Concat(vec![
            expr_to_scalar_expr(left)?,
            expr_to_scalar_expr(right)?,
        ])),

        // CAST(x AS T).
        Expr::Cast {
            expr: inner,
            data_type,
            ..
        } => {
            let target = sql_data_type_to_data_type(data_type)?;
            Ok(ScalarExpr::Cast(
                Box::new(expr_to_scalar_expr(inner)?),
                target,
            ))
        }

        // Parenthesised expression — unwrap transparently.
        Expr::Nested(inner) => expr_to_scalar_expr(inner),

        // Named function call.
        Expr::Function(func) => {
            if func.over.is_some() {
                return Err(QueryError::UnsupportedFeature(
                    "window functions are not valid in this position".to_string(),
                ));
            }
            if func.filter.is_some() {
                return Err(QueryError::UnsupportedFeature(
                    "FILTER clause only applies to aggregate functions".to_string(),
                ));
            }
            let name = func.name.to_string().to_uppercase();
            let args = match &func.args {
                sqlparser::ast::FunctionArguments::List(list) => &list.args,
                _ => {
                    return Err(QueryError::UnsupportedFeature(
                        "non-list function arguments not supported".to_string(),
                    ));
                }
            };

            // Extract argument expressions — named args aren't supported.
            let mut arg_exprs: Vec<&Expr> = Vec::with_capacity(args.len());
            for a in args {
                match a {
                    sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) => arg_exprs.push(e),
                    _ => {
                        return Err(QueryError::UnsupportedFeature(format!(
                            "unsupported argument form in scalar function {name}"
                        )));
                    }
                }
            }

            let want_arity = |n: usize| -> Result<()> {
                if arg_exprs.len() == n {
                    Ok(())
                } else {
                    Err(QueryError::ParseError(format!(
                        "{name} expects {n} argument(s), got {}",
                        arg_exprs.len()
                    )))
                }
            };
            let scalar = |e: &Expr| expr_to_scalar_expr(e);

            match name.as_str() {
                "UPPER" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Upper(Box::new(scalar(arg_exprs[0])?)))
                }
                "LOWER" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Lower(Box::new(scalar(arg_exprs[0])?)))
                }
                "LENGTH" | "CHAR_LENGTH" | "CHARACTER_LENGTH" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Length(Box::new(scalar(arg_exprs[0])?)))
                }
                "TRIM" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Trim(Box::new(scalar(arg_exprs[0])?)))
                }
                "CONCAT" => {
                    if arg_exprs.is_empty() {
                        return Err(QueryError::ParseError(
                            "CONCAT expects at least one argument".to_string(),
                        ));
                    }
                    let parts = arg_exprs
                        .iter()
                        .map(|e| scalar(e))
                        .collect::<Result<Vec<_>>>()?;
                    Ok(ScalarExpr::Concat(parts))
                }
                "ABS" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Abs(Box::new(scalar(arg_exprs[0])?)))
                }
                "ROUND" => match arg_exprs.len() {
                    1 => Ok(ScalarExpr::Round(Box::new(scalar(arg_exprs[0])?))),
                    2 => {
                        // Second arg must be a non-negative integer literal.
                        let n = match expr_to_value(arg_exprs[1])? {
                            Value::BigInt(n) => i32::try_from(n).map_err(|_| {
                                QueryError::ParseError("ROUND scale out of range".to_string())
                            })?,
                            other => {
                                return Err(QueryError::ParseError(format!(
                                    "ROUND scale must be an integer literal, got {other:?}"
                                )));
                            }
                        };
                        Ok(ScalarExpr::RoundScale(Box::new(scalar(arg_exprs[0])?), n))
                    }
                    _ => Err(QueryError::ParseError(format!(
                        "ROUND expects 1 or 2 arguments, got {}",
                        arg_exprs.len()
                    ))),
                },
                "CEIL" | "CEILING" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Ceil(Box::new(scalar(arg_exprs[0])?)))
                }
                "FLOOR" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Floor(Box::new(scalar(arg_exprs[0])?)))
                }
                "COALESCE" => {
                    if arg_exprs.is_empty() {
                        return Err(QueryError::ParseError(
                            "COALESCE expects at least one argument".to_string(),
                        ));
                    }
                    let parts = arg_exprs
                        .iter()
                        .map(|e| scalar(e))
                        .collect::<Result<Vec<_>>>()?;
                    Ok(ScalarExpr::Coalesce(parts))
                }
                "NULLIF" => {
                    want_arity(2)?;
                    Ok(ScalarExpr::Nullif(
                        Box::new(scalar(arg_exprs[0])?),
                        Box::new(scalar(arg_exprs[1])?),
                    ))
                }
                // ---- v0.7.0 scalars ----
                "MOD" => {
                    want_arity(2)?;
                    Ok(ScalarExpr::Mod(
                        Box::new(scalar(arg_exprs[0])?),
                        Box::new(scalar(arg_exprs[1])?),
                    ))
                }
                "POWER" | "POW" => {
                    want_arity(2)?;
                    Ok(ScalarExpr::Power(
                        Box::new(scalar(arg_exprs[0])?),
                        Box::new(scalar(arg_exprs[1])?),
                    ))
                }
                "SQRT" => {
                    want_arity(1)?;
                    Ok(ScalarExpr::Sqrt(Box::new(scalar(arg_exprs[0])?)))
                }
                "SUBSTRING" | "SUBSTR" => {
                    // Two-arg form (`SUBSTRING(s, start)`) or three-arg
                    // form (`SUBSTRING(s, start, length)`). The
                    // SQL-standard `SUBSTRING(s FROM x FOR y)` syntax
                    // is lowered by sqlparser into a function call
                    // with positional args, so the same parser path
                    // handles both surface forms.
                    use kimberlite_types::SubstringRange;
                    match arg_exprs.len() {
                        2 => {
                            let start = match expr_to_value(arg_exprs[1])? {
                                Value::BigInt(n) => n,
                                Value::Integer(n) => i64::from(n),
                                other => {
                                    return Err(QueryError::ParseError(format!(
                                        "SUBSTRING start must be an integer literal, got {other:?}"
                                    )));
                                }
                            };
                            Ok(ScalarExpr::Substring(
                                Box::new(scalar(arg_exprs[0])?),
                                SubstringRange::from_start(start),
                            ))
                        }
                        3 => {
                            let start = match expr_to_value(arg_exprs[1])? {
                                Value::BigInt(n) => n,
                                Value::Integer(n) => i64::from(n),
                                other => {
                                    return Err(QueryError::ParseError(format!(
                                        "SUBSTRING start must be an integer literal, got {other:?}"
                                    )));
                                }
                            };
                            let length = match expr_to_value(arg_exprs[2])? {
                                Value::BigInt(n) => n,
                                Value::Integer(n) => i64::from(n),
                                other => {
                                    return Err(QueryError::ParseError(format!(
                                        "SUBSTRING length must be an integer literal, got {other:?}"
                                    )));
                                }
                            };
                            let range = SubstringRange::try_new(start, length)
                                .map_err(|e| QueryError::ParseError(format!("SUBSTRING: {e}")))?;
                            Ok(ScalarExpr::Substring(
                                Box::new(scalar(arg_exprs[0])?),
                                range,
                            ))
                        }
                        n => Err(QueryError::ParseError(format!(
                            "SUBSTRING expects 2 or 3 arguments, got {n}"
                        ))),
                    }
                }
                "EXTRACT" => {
                    // sqlparser models EXTRACT differently — when
                    // surfaced through the function-call AST it
                    // arrives as a 2-arg call where the first arg is
                    // the field name (string literal). The native
                    // `Expr::Extract { field, expr }` shape is
                    // handled at the top of `expr_to_scalar_expr`.
                    use kimberlite_types::DateField;
                    want_arity(2)?;
                    let field_name = match expr_to_value(arg_exprs[0])? {
                        Value::Text(s) => s,
                        other => {
                            return Err(QueryError::ParseError(format!(
                                "EXTRACT field must be a string literal, got {other:?}"
                            )));
                        }
                    };
                    let field = DateField::parse(&field_name)
                        .map_err(|e| QueryError::ParseError(format!("EXTRACT: {e}")))?;
                    Ok(ScalarExpr::Extract(field, Box::new(scalar(arg_exprs[1])?)))
                }
                "DATE_TRUNC" | "DATETRUNC" => {
                    use kimberlite_types::DateField;
                    want_arity(2)?;
                    let field_name = match expr_to_value(arg_exprs[0])? {
                        Value::Text(s) => s,
                        other => {
                            return Err(QueryError::ParseError(format!(
                                "DATE_TRUNC field must be a string literal, got {other:?}"
                            )));
                        }
                    };
                    let field = DateField::parse(&field_name)
                        .map_err(|e| QueryError::ParseError(format!("DATE_TRUNC: {e}")))?;
                    if !field.is_truncatable() {
                        return Err(QueryError::ParseError(format!(
                            "DATE_TRUNC field {field:?} is not truncatable (use one of YEAR, MONTH, DAY, HOUR, MINUTE, SECOND)"
                        )));
                    }
                    Ok(ScalarExpr::DateTrunc(
                        field,
                        Box::new(scalar(arg_exprs[1])?),
                    ))
                }
                "NOW" => {
                    if !arg_exprs.is_empty() {
                        return Err(QueryError::ParseError(format!(
                            "NOW expects 0 arguments, got {}",
                            arg_exprs.len()
                        )));
                    }
                    Ok(ScalarExpr::Now)
                }
                "CURRENT_TIMESTAMP" => {
                    if !arg_exprs.is_empty() {
                        return Err(QueryError::ParseError(format!(
                            "CURRENT_TIMESTAMP expects 0 arguments, got {}",
                            arg_exprs.len()
                        )));
                    }
                    Ok(ScalarExpr::CurrentTimestamp)
                }
                "CURRENT_DATE" => {
                    if !arg_exprs.is_empty() {
                        return Err(QueryError::ParseError(format!(
                            "CURRENT_DATE expects 0 arguments, got {}",
                            arg_exprs.len()
                        )));
                    }
                    Ok(ScalarExpr::CurrentDate)
                }
                other => Err(QueryError::UnsupportedFeature(format!(
                    "scalar function {other} is not supported"
                ))),
            }
        }

        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported scalar expression: {other:?}"
        ))),
    }
}

/// Convert a sqlparser `SqlDataType` into our schema `DataType` for
/// `CAST` targets. Ignores precision/scale on numerics — we don't
/// currently parameterise `DataType::Decimal` at cast time.
fn sql_data_type_to_data_type(sql_ty: &SqlDataType) -> Result<DataType> {
    Ok(match sql_ty {
        SqlDataType::TinyInt(_) => DataType::TinyInt,
        SqlDataType::SmallInt(_) => DataType::SmallInt,
        SqlDataType::Int(_) | SqlDataType::Integer(_) => DataType::Integer,
        SqlDataType::BigInt(_) => DataType::BigInt,
        SqlDataType::Real | SqlDataType::Float(_) | SqlDataType::Double(_) => DataType::Real,
        SqlDataType::Text | SqlDataType::Varchar(_) | SqlDataType::String(_) => DataType::Text,
        SqlDataType::Boolean | SqlDataType::Bool => DataType::Boolean,
        SqlDataType::Date => DataType::Date,
        SqlDataType::Time(_, _) => DataType::Time,
        SqlDataType::Timestamp(_, _) => DataType::Timestamp,
        SqlDataType::Uuid => DataType::Uuid,
        SqlDataType::JSON => DataType::Json,
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "CAST to {other:?} is not supported"
            )));
        }
    })
}

fn expr_to_predicate_value(expr: &Expr) -> Result<PredicateValue> {
    match expr {
        // Handle column references (for JOIN conditions like users.id = orders.user_id)
        Expr::Identifier(ident) => {
            // Unqualified column reference
            Ok(PredicateValue::ColumnRef(ident.value.clone()))
        }
        Expr::CompoundIdentifier(idents) if idents.len() == 2 => {
            // Qualified column reference: table.column
            Ok(PredicateValue::ColumnRef(format!(
                "{}.{}",
                idents[0].value, idents[1].value
            )))
        }
        Expr::Value(vws) => match &vws.value {
            SqlValue::Number(n, _) => {
                let value = parse_number_literal(n)?;
                match value {
                    Value::BigInt(v) => Ok(PredicateValue::Int(v)),
                    Value::Decimal(_, _) => Ok(PredicateValue::Literal(value)),
                    _ => unreachable!("parse_number_literal only returns BigInt or Decimal"),
                }
            }
            SqlValue::SingleQuotedString(s) | SqlValue::DoubleQuotedString(s) => {
                Ok(PredicateValue::String(s.clone()))
            }
            SqlValue::Boolean(b) => Ok(PredicateValue::Bool(*b)),
            SqlValue::Null => Ok(PredicateValue::Null),
            SqlValue::Placeholder(p) => Ok(PredicateValue::Param(parse_placeholder_index(p)?)),
            other => Err(QueryError::UnsupportedFeature(format!(
                "unsupported value expression: {other:?}"
            ))),
        },
        Expr::UnaryOp {
            op: sqlparser::ast::UnaryOperator::Minus,
            expr,
        } => {
            // Handle negative numbers
            if let Expr::Value(vws) = expr.as_ref()
                && let SqlValue::Number(n, _) = &vws.value
            {
                let value = parse_number_literal(n)?;
                match value {
                    Value::BigInt(v) => Ok(PredicateValue::Int(-v)),
                    Value::Decimal(v, scale) => {
                        Ok(PredicateValue::Literal(Value::Decimal(-v, scale)))
                    }
                    _ => unreachable!("parse_number_literal only returns BigInt or Decimal"),
                }
            } else {
                Err(QueryError::UnsupportedFeature(format!(
                    "unsupported unary minus operand: {expr:?}"
                )))
            }
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported value expression: {other:?}"
        ))),
    }
}

fn parse_order_by(order_by: &sqlparser::ast::OrderBy) -> Result<Vec<OrderByClause>> {
    use sqlparser::ast::OrderByKind;

    let exprs = match &order_by.kind {
        OrderByKind::Expressions(exprs) => exprs,
        OrderByKind::All(_) => {
            return Err(QueryError::UnsupportedFeature(
                "ORDER BY ALL is not supported".to_string(),
            ));
        }
    };

    let mut clauses = Vec::new();
    for expr in exprs {
        clauses.push(parse_order_by_expr(expr)?);
    }

    Ok(clauses)
}

fn parse_order_by_expr(expr: &OrderByExpr) -> Result<OrderByClause> {
    let column = match &expr.expr {
        Expr::Identifier(ident) => ColumnName::new(ident.value.clone()),
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "unsupported ORDER BY expression: {other:?}"
            )));
        }
    };

    let ascending = expr.options.asc.unwrap_or(true);

    Ok(OrderByClause { column, ascending })
}

fn parse_limit(limit: Option<&Expr>) -> Result<Option<LimitExpr>> {
    match limit {
        None => Ok(None),
        Some(Expr::Value(vws)) => match &vws.value {
            SqlValue::Number(n, _) => {
                let v: usize = n
                    .parse()
                    .map_err(|_| QueryError::ParseError(format!("invalid LIMIT value: {n}")))?;
                Ok(Some(LimitExpr::Literal(v)))
            }
            SqlValue::Placeholder(p) => Ok(Some(LimitExpr::Param(parse_placeholder_index(p)?))),
            other => Err(QueryError::UnsupportedFeature(format!(
                "LIMIT must be an integer literal or parameter; got {other:?}"
            ))),
        },
        Some(other) => Err(QueryError::UnsupportedFeature(format!(
            "LIMIT must be an integer literal or parameter; got {other:?}"
        ))),
    }
}

/// Extracts the `LIMIT` expression (if any) from a sqlparser `Query`'s
/// `limit_clause`. Rejects MySQL-style `LIMIT <offset>, <limit>` syntax.
fn query_limit_expr(query: &Query) -> Result<Option<&Expr>> {
    use sqlparser::ast::LimitClause;
    match &query.limit_clause {
        None => Ok(None),
        Some(LimitClause::LimitOffset { limit, .. }) => Ok(limit.as_ref()),
        Some(LimitClause::OffsetCommaLimit { .. }) => Err(QueryError::UnsupportedFeature(
            "MySQL-style `LIMIT <offset>, <limit>` is not supported".to_string(),
        )),
    }
}

/// Extracts the `OFFSET` clause (if any) from a sqlparser `Query`'s
/// `limit_clause`. `OFFSET` is an error in MySQL-style
/// `LIMIT <offset>, <limit>` syntax (handled by `query_limit_expr`).
fn query_offset(query: &Query) -> Option<&sqlparser::ast::Offset> {
    use sqlparser::ast::LimitClause;
    match &query.limit_clause {
        Some(LimitClause::LimitOffset { offset, .. }) => offset.as_ref(),
        _ => None,
    }
}

/// Parses a SQL `OFFSET` clause expression. Mirrors `parse_limit`: accepts
/// integer literals and `$N` parameter placeholders.
fn parse_offset_clause(offset: Option<&sqlparser::ast::Offset>) -> Result<Option<LimitExpr>> {
    let Some(off) = offset else { return Ok(None) };
    match &off.value {
        Expr::Value(vws) => match &vws.value {
            SqlValue::Number(n, _) => {
                let v: usize = n
                    .parse()
                    .map_err(|_| QueryError::ParseError(format!("invalid OFFSET value: {n}")))?;
                Ok(Some(LimitExpr::Literal(v)))
            }
            SqlValue::Placeholder(p) => Ok(Some(LimitExpr::Param(parse_placeholder_index(p)?))),
            other => Err(QueryError::UnsupportedFeature(format!(
                "OFFSET must be an integer literal or parameter; got {other:?}"
            ))),
        },
        other => Err(QueryError::UnsupportedFeature(format!(
            "OFFSET must be an integer literal or parameter; got {other:?}"
        ))),
    }
}

/// Parses a SQL placeholder like `$1`, `$2` into its 1-indexed position.
///
/// `$0` and non-`$N` forms are rejected with a clear error so the caller can
/// surface a useful message regardless of where the placeholder appears
/// (WHERE clause, LIMIT/OFFSET, DML values).
fn parse_placeholder_index(placeholder: &str) -> Result<usize> {
    let num_str = placeholder.strip_prefix('$').ok_or_else(|| {
        QueryError::ParseError(format!("unsupported placeholder format: {placeholder}"))
    })?;
    let idx: usize = num_str.parse().map_err(|_| {
        QueryError::ParseError(format!("invalid parameter placeholder: {placeholder}"))
    })?;
    if idx == 0 {
        return Err(QueryError::ParseError(
            "parameter indices start at $1, not $0".to_string(),
        ));
    }
    Ok(idx)
}

fn object_name_to_string(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|part| match part.as_ident() {
            Some(ident) => ident.value.clone(),
            None => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

// ============================================================================
// DDL Parsers
// ============================================================================

fn parse_create_table(create_table: &sqlparser::ast::CreateTable) -> Result<ParsedCreateTable> {
    let table_name = object_name_to_string(&create_table.name);

    // Reject zero-column tables. sqlparser accepts inputs like
    // `CREATE TABLE#USER` and returns a CreateTable with an empty `columns`
    // vector; Kimberlite tables must have at least one column (no meaningful
    // projection or primary key can exist otherwise). The `NonEmptyVec`
    // constructor below enforces this at the type level; the early-return
    // here gives a domain-specific error message. Regression: fuzz_sql_parser
    // surfaced 12 crashes in the first EPYC nightly from this shape.

    // Extract column definitions
    let mut raw_columns = Vec::new();
    for col_def in &create_table.columns {
        let parsed_col = parse_column_def(col_def)?;
        raw_columns.push(parsed_col);
    }
    let columns = NonEmptyVec::try_new(raw_columns).map_err(|_| {
        crate::error::QueryError::ParseError(format!(
            "CREATE TABLE {table_name} requires at least one column"
        ))
    })?;

    // Extract primary key from constraints
    let mut primary_key = Vec::new();
    for constraint in &create_table.constraints {
        if let sqlparser::ast::TableConstraint::PrimaryKey(pk) = constraint {
            for col in &pk.columns {
                if let Expr::Identifier(ident) = &col.column.expr {
                    primary_key.push(ident.value.clone());
                } else {
                    primary_key.push(col.column.expr.to_string());
                }
            }
        }
    }

    // If no explicit PRIMARY KEY constraint, check for PRIMARY KEY in column definitions
    if primary_key.is_empty() {
        for col_def in &create_table.columns {
            for option in &col_def.options {
                if matches!(&option.option, sqlparser::ast::ColumnOption::PrimaryKey(_)) {
                    primary_key.push(col_def.name.value.clone());
                }
            }
        }
    }

    Ok(ParsedCreateTable {
        table_name,
        columns,
        primary_key,
        if_not_exists: create_table.if_not_exists,
    })
}

fn parse_column_def(col_def: &SqlColumnDef) -> Result<ParsedColumn> {
    let name = col_def.name.value.clone();

    // Map SQL data type to string
    // For DECIMAL, we need to handle precision/scale specially
    let data_type = match &col_def.data_type {
        // Integer types
        SqlDataType::TinyInt(_) => "TINYINT".to_string(),
        SqlDataType::SmallInt(_) => "SMALLINT".to_string(),
        SqlDataType::Int(_) | SqlDataType::Integer(_) => "INTEGER".to_string(),
        SqlDataType::BigInt(_) => "BIGINT".to_string(),

        // Numeric types
        SqlDataType::Real | SqlDataType::Float(_) | SqlDataType::Double(_) => "REAL".to_string(),
        SqlDataType::Decimal(precision_opt) => match precision_opt {
            sqlparser::ast::ExactNumberInfo::PrecisionAndScale(p, s) => {
                format!("DECIMAL({p},{s})")
            }
            sqlparser::ast::ExactNumberInfo::Precision(p) => {
                format!("DECIMAL({p},0)")
            }
            sqlparser::ast::ExactNumberInfo::None => "DECIMAL(18,2)".to_string(),
        },

        // String types
        SqlDataType::Text | SqlDataType::Varchar(_) | SqlDataType::String(_) => "TEXT".to_string(),

        // Binary types
        SqlDataType::Binary(_) | SqlDataType::Varbinary(_) | SqlDataType::Blob(_) => {
            "BYTES".to_string()
        }

        // Boolean type
        SqlDataType::Boolean | SqlDataType::Bool => "BOOLEAN".to_string(),

        // Date/Time types
        SqlDataType::Date => "DATE".to_string(),
        SqlDataType::Time(_, _) => "TIME".to_string(),
        SqlDataType::Timestamp(_, _) => "TIMESTAMP".to_string(),

        // Structured types
        SqlDataType::Uuid => "UUID".to_string(),
        SqlDataType::JSON => "JSON".to_string(),

        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "unsupported data type: {other:?}"
            )));
        }
    };

    // Check for NOT NULL constraint
    let mut nullable = true;
    for option in &col_def.options {
        if matches!(option.option, sqlparser::ast::ColumnOption::NotNull) {
            nullable = false;
        }
    }

    Ok(ParsedColumn {
        name,
        data_type,
        nullable,
    })
}

fn parse_alter_table(
    name: &sqlparser::ast::ObjectName,
    operations: &[sqlparser::ast::AlterTableOperation],
) -> Result<ParsedAlterTable> {
    let table_name = object_name_to_string(name);

    // Only support one operation at a time
    if operations.len() != 1 {
        return Err(QueryError::UnsupportedFeature(
            "ALTER TABLE supports only one operation at a time".to_string(),
        ));
    }

    let operation = match &operations[0] {
        sqlparser::ast::AlterTableOperation::AddColumn { column_def, .. } => {
            let parsed_col = parse_column_def(column_def)?;
            AlterTableOperation::AddColumn(parsed_col)
        }
        sqlparser::ast::AlterTableOperation::DropColumn {
            column_names,
            if_exists: _,
            ..
        } => {
            if column_names.len() != 1 {
                return Err(QueryError::UnsupportedFeature(
                    "ALTER TABLE DROP COLUMN supports exactly one column".to_string(),
                ));
            }
            let col_name = column_names[0].value.clone();
            AlterTableOperation::DropColumn(col_name)
        }
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "ALTER TABLE operation not supported: {other:?}"
            )));
        }
    };

    Ok(ParsedAlterTable {
        table_name,
        operation,
    })
}

fn parse_create_index(create_index: &sqlparser::ast::CreateIndex) -> Result<ParsedCreateIndex> {
    let index_name = match &create_index.name {
        Some(name) => object_name_to_string(name),
        None => {
            return Err(QueryError::ParseError(
                "CREATE INDEX requires an index name".to_string(),
            ));
        }
    };

    let table_name = object_name_to_string(&create_index.table_name);

    let mut columns = Vec::new();
    for col in &create_index.columns {
        columns.push(col.column.expr.to_string());
    }

    Ok(ParsedCreateIndex {
        index_name,
        table_name,
        columns,
    })
}

// ============================================================================
// DML Parsers
// ============================================================================

fn parse_insert(insert: &sqlparser::ast::Insert) -> Result<ParsedInsert> {
    // TableObject might be ObjectName directly - convert to string
    let table = insert.table.to_string();

    // Extract column names
    let columns: Vec<String> = insert.columns.iter().map(|c| c.value.clone()).collect();

    // Extract values from all rows
    let values = match insert.source.as_ref().map(|s| s.body.as_ref()) {
        Some(SetExpr::Values(values)) => {
            let mut all_rows = Vec::new();
            for row in &values.rows {
                let mut parsed_row = Vec::new();
                for expr in row {
                    let val = expr_to_value(expr)?;
                    parsed_row.push(val);
                }
                all_rows.push(parsed_row);
            }
            all_rows
        }
        _ => {
            return Err(QueryError::UnsupportedFeature(
                "only VALUES clause is supported in INSERT".to_string(),
            ));
        }
    };

    // Parse RETURNING clause
    let returning = parse_returning(insert.returning.as_ref())?;

    // v0.6.0 Tier 1 #3 — parse the optional ON CONFLICT clause.
    // sqlparser exposes it as `insert.on: Option<OnInsert>`; we only
    // accept the PostgreSQL `OnConflict` flavour. MySQL's
    // `ON DUPLICATE KEY UPDATE` is out of scope.
    let on_conflict = match insert.on.as_ref() {
        None => None,
        Some(sqlparser::ast::OnInsert::OnConflict(oc)) => Some(parse_on_conflict(oc)?),
        Some(sqlparser::ast::OnInsert::DuplicateKeyUpdate(_)) => {
            return Err(QueryError::UnsupportedFeature(
                "ON DUPLICATE KEY UPDATE is not supported; use ON CONFLICT (cols) DO UPDATE"
                    .to_string(),
            ));
        }
        Some(other) => {
            return Err(QueryError::UnsupportedFeature(format!(
                "unsupported ON clause on INSERT: {other:?}"
            )));
        }
    };

    Ok(ParsedInsert {
        table,
        columns,
        values,
        returning,
        on_conflict,
    })
}

/// v0.6.0 Tier 1 #3 — convert sqlparser's `OnConflict` to our internal
/// representation.
///
/// The scope is deliberately narrow: `target` must be a column list
/// (not `ON CONSTRAINT <name>`), and `DO UPDATE` assignments must be
/// either literal values or `EXCLUDED.col` back-references.
fn parse_on_conflict(oc: &sqlparser::ast::OnConflict) -> Result<OnConflictClause> {
    // Conflict target — only the column-list form is supported.
    let target = match oc.conflict_target.as_ref() {
        Some(sqlparser::ast::ConflictTarget::Columns(cols)) => {
            if cols.is_empty() {
                return Err(QueryError::ParseError(
                    "ON CONFLICT requires at least one target column".to_string(),
                ));
            }
            cols.iter().map(|i| i.value.clone()).collect()
        }
        Some(sqlparser::ast::ConflictTarget::OnConstraint(_)) => {
            return Err(QueryError::UnsupportedFeature(
                "ON CONFLICT ON CONSTRAINT <name> is not supported; use ON CONFLICT (cols) instead"
                    .to_string(),
            ));
        }
        None => {
            return Err(QueryError::UnsupportedFeature(
                "ON CONFLICT without a target column list is not supported".to_string(),
            ));
        }
    };

    let action = match &oc.action {
        sqlparser::ast::OnConflictAction::DoNothing => OnConflictAction::DoNothing,
        sqlparser::ast::OnConflictAction::DoUpdate(du) => {
            if du.selection.is_some() {
                return Err(QueryError::UnsupportedFeature(
                    "ON CONFLICT DO UPDATE WHERE ... is not yet supported".to_string(),
                ));
            }
            let mut assignments = Vec::with_capacity(du.assignments.len());
            for a in &du.assignments {
                let col = a.target.to_string();
                let rhs = parse_upsert_expr(&a.value)?;
                assignments.push((col, rhs));
            }
            OnConflictAction::DoUpdate { assignments }
        }
    };

    Ok(OnConflictClause { target, action })
}

/// Parse the RHS of `SET col = <expr>` inside `DO UPDATE`.
///
/// Accepts:
/// - literal values (mapped via `expr_to_value`)
/// - `EXCLUDED.<col>` back-references — rendered by sqlparser as a
///   compound identifier
fn parse_upsert_expr(expr: &Expr) -> Result<UpsertExpr> {
    // EXCLUDED.col comes through as a CompoundIdentifier with two parts.
    if let Expr::CompoundIdentifier(parts) = expr {
        if parts.len() == 2 && parts[0].value.eq_ignore_ascii_case("EXCLUDED") {
            return Ok(UpsertExpr::Excluded(parts[1].value.clone()));
        }
    }
    // Otherwise fall back to the literal-value path shared with plain
    // INSERT/UPDATE.
    let v = expr_to_value(expr)?;
    Ok(UpsertExpr::Value(v))
}

fn parse_update(
    table: &sqlparser::ast::TableWithJoins,
    assignments: &[sqlparser::ast::Assignment],
    selection: Option<&Expr>,
    returning: Option<&Vec<SelectItem>>,
) -> Result<ParsedUpdate> {
    let table_name = match &table.relation {
        sqlparser::ast::TableFactor::Table { name, .. } => object_name_to_string(name),
        other => {
            return Err(QueryError::UnsupportedFeature(format!(
                "unsupported table in UPDATE: {other:?}"
            )));
        }
    };

    // Parse assignments (SET clauses)
    let mut parsed_assignments = Vec::new();
    for assignment in assignments {
        let col_name = assignment.target.to_string();
        let value = expr_to_value(&assignment.value)?;
        parsed_assignments.push((col_name, value));
    }

    // Parse WHERE clause
    let predicates = match selection {
        Some(expr) => parse_where_expr(expr)?,
        None => vec![],
    };

    // Parse RETURNING clause
    let returning_cols = parse_returning(returning)?;

    Ok(ParsedUpdate {
        table: table_name,
        assignments: parsed_assignments,
        predicates,
        returning: returning_cols,
    })
}

fn parse_delete_stmt(delete: &sqlparser::ast::Delete) -> Result<ParsedDelete> {
    // In sqlparser 0.54, DELETE FROM uses a single `from` table
    use sqlparser::ast::FromTable;

    let table_name = match &delete.from {
        FromTable::WithFromKeyword(tables) => {
            if tables.len() != 1 {
                return Err(QueryError::ParseError(
                    "expected exactly 1 table in DELETE FROM".to_string(),
                ));
            }

            match &tables[0].relation {
                sqlparser::ast::TableFactor::Table { name, .. } => object_name_to_string(name),
                _ => {
                    return Err(QueryError::ParseError(
                        "DELETE only supports simple table names".to_string(),
                    ));
                }
            }
        }
        FromTable::WithoutKeyword(tables) => {
            if tables.len() != 1 {
                return Err(QueryError::ParseError(
                    "expected exactly 1 table in DELETE".to_string(),
                ));
            }

            match &tables[0].relation {
                sqlparser::ast::TableFactor::Table { name, .. } => object_name_to_string(name),
                _ => {
                    return Err(QueryError::ParseError(
                        "DELETE only supports simple table names".to_string(),
                    ));
                }
            }
        }
    };

    // Parse WHERE clause
    let predicates = match &delete.selection {
        Some(expr) => parse_where_expr(expr)?,
        None => vec![],
    };

    // Parse RETURNING clause
    let returning_cols = parse_returning(delete.returning.as_ref())?;

    Ok(ParsedDelete {
        table: table_name,
        predicates,
        returning: returning_cols,
    })
}

/// Parses a RETURNING clause into a list of column names.
fn parse_returning(returning: Option<&Vec<SelectItem>>) -> Result<Option<Vec<String>>> {
    match returning {
        None => Ok(None),
        Some(items) => {
            let mut columns = Vec::new();
            for item in items {
                match item {
                    SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                        columns.push(ident.value.clone());
                    }
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                        // Handle table.column format - just take the column name
                        if let Some(last) = parts.last() {
                            columns.push(last.value.clone());
                        } else {
                            return Err(QueryError::ParseError(
                                "invalid column in RETURNING clause".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(QueryError::UnsupportedFeature(
                            "only simple column names supported in RETURNING clause".to_string(),
                        ));
                    }
                }
            }
            Ok(Some(columns))
        }
    }
}

/// Parses a number literal as either an integer or decimal.
///
/// Uses `rust_decimal` for robust decimal parsing (handles all edge cases correctly).
fn parse_number_literal(n: &str) -> Result<Value> {
    use rust_decimal::Decimal;
    use std::str::FromStr;

    if n.contains('.') {
        // Parse as DECIMAL using rust_decimal for correct handling
        let decimal = Decimal::from_str(n)
            .map_err(|e| QueryError::ParseError(format!("invalid decimal '{n}': {e}")))?;

        // Get scale (number of decimal places)
        let scale = decimal.scale() as u8;

        if scale > 38 {
            return Err(QueryError::ParseError(format!(
                "decimal scale too large (max 38): {n}"
            )));
        }

        // Convert to i128 representation: mantissa * 10^scale
        // rust_decimal stores internally as i128 mantissa with scale
        let mantissa = decimal.mantissa();

        Ok(Value::Decimal(mantissa, scale))
    } else {
        // Parse as integer (BigInt)
        let v: i64 = n
            .parse()
            .map_err(|_| QueryError::ParseError(format!("invalid integer: {n}")))?;
        Ok(Value::BigInt(v))
    }
}

/// Converts a SQL expression to a Value.
fn expr_to_value(expr: &Expr) -> Result<Value> {
    match expr {
        Expr::Value(vws) => match &vws.value {
            SqlValue::Number(n, _) => parse_number_literal(n),
            SqlValue::SingleQuotedString(s) | SqlValue::DoubleQuotedString(s) => {
                Ok(Value::Text(s.clone()))
            }
            SqlValue::Boolean(b) => Ok(Value::Boolean(*b)),
            SqlValue::Null => Ok(Value::Null),
            SqlValue::Placeholder(p) => Ok(Value::Placeholder(parse_placeholder_index(p)?)),
            other => Err(QueryError::UnsupportedFeature(format!(
                "unsupported value expression: {other:?}"
            ))),
        },
        Expr::UnaryOp {
            op: sqlparser::ast::UnaryOperator::Minus,
            expr,
        } => {
            // Handle negative numbers
            if let Expr::Value(vws) = expr.as_ref()
                && let SqlValue::Number(n, _) = &vws.value
            {
                let value = parse_number_literal(n)?;
                match value {
                    Value::BigInt(v) => Ok(Value::BigInt(-v)),
                    Value::Decimal(v, scale) => Ok(Value::Decimal(-v, scale)),
                    _ => unreachable!("parse_number_literal only returns BigInt or Decimal"),
                }
            } else {
                Err(QueryError::UnsupportedFeature(format!(
                    "unsupported unary minus operand: {expr:?}"
                )))
            }
        }
        other => Err(QueryError::UnsupportedFeature(format!(
            "unsupported value expression: {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_test_select(sql: &str) -> ParsedSelect {
        match parse_statement(sql).unwrap() {
            ParsedStatement::Select(s) => s,
            _ => panic!("expected SELECT statement"),
        }
    }

    #[test]
    fn test_parse_simple_select() {
        let result = parse_test_select("SELECT id, name FROM users");
        assert_eq!(result.table, "users");
        assert_eq!(
            result.columns,
            Some(vec![ColumnName::new("id"), ColumnName::new("name")])
        );
        assert!(result.predicates.is_empty());
    }

    #[test]
    fn test_parse_select_star() {
        let result = parse_test_select("SELECT * FROM users");
        assert_eq!(result.table, "users");
        assert!(result.columns.is_none());
    }

    #[test]
    fn test_parse_where_eq() {
        let result = parse_test_select("SELECT * FROM users WHERE id = 42");
        assert_eq!(result.predicates.len(), 1);
        match &result.predicates[0] {
            Predicate::Eq(col, PredicateValue::Int(42)) => {
                assert_eq!(col.as_str(), "id");
            }
            other => panic!("unexpected predicate: {other:?}"),
        }
    }

    #[test]
    fn test_parse_where_string() {
        let result = parse_test_select("SELECT * FROM users WHERE name = 'alice'");
        match &result.predicates[0] {
            Predicate::Eq(col, PredicateValue::String(s)) => {
                assert_eq!(col.as_str(), "name");
                assert_eq!(s, "alice");
            }
            other => panic!("unexpected predicate: {other:?}"),
        }
    }

    #[test]
    fn test_parse_where_and() {
        let result = parse_test_select("SELECT * FROM users WHERE id = 1 AND name = 'bob'");
        assert_eq!(result.predicates.len(), 2);
    }

    #[test]
    fn test_parse_where_in() {
        let result = parse_test_select("SELECT * FROM users WHERE id IN (1, 2, 3)");
        match &result.predicates[0] {
            Predicate::In(col, values) => {
                assert_eq!(col.as_str(), "id");
                assert_eq!(values.len(), 3);
            }
            other => panic!("unexpected predicate: {other:?}"),
        }
    }

    #[test]
    fn test_parse_order_by() {
        let result = parse_test_select("SELECT * FROM users ORDER BY name ASC, id DESC");
        assert_eq!(result.order_by.len(), 2);
        assert_eq!(result.order_by[0].column.as_str(), "name");
        assert!(result.order_by[0].ascending);
        assert_eq!(result.order_by[1].column.as_str(), "id");
        assert!(!result.order_by[1].ascending);
    }

    #[test]
    fn test_parse_limit() {
        let result = parse_test_select("SELECT * FROM users LIMIT 10");
        assert_eq!(result.limit, Some(LimitExpr::Literal(10)));
    }

    #[test]
    fn test_parse_limit_param() {
        let result = parse_test_select("SELECT * FROM users LIMIT $1");
        assert_eq!(result.limit, Some(LimitExpr::Param(1)));
    }

    #[test]
    fn test_parse_offset_literal() {
        let result = parse_test_select("SELECT * FROM users LIMIT 10 OFFSET 5");
        assert_eq!(result.limit, Some(LimitExpr::Literal(10)));
        assert_eq!(result.offset, Some(LimitExpr::Literal(5)));
    }

    #[test]
    fn test_parse_offset_param() {
        let result = parse_test_select("SELECT * FROM users LIMIT $1 OFFSET $2");
        assert_eq!(result.limit, Some(LimitExpr::Param(1)));
        assert_eq!(result.offset, Some(LimitExpr::Param(2)));
    }

    #[test]
    fn test_parse_param() {
        let result = parse_test_select("SELECT * FROM users WHERE id = $1");
        match &result.predicates[0] {
            Predicate::Eq(_, PredicateValue::Param(1)) => {}
            other => panic!("unexpected predicate: {other:?}"),
        }
    }

    #[test]
    fn test_parse_inner_join() {
        let result =
            parse_statement("SELECT * FROM users JOIN orders ON users.id = orders.user_id");
        if let Err(ref e) = result {
            eprintln!("Parse error: {e:?}");
        }
        assert!(result.is_ok());
        match result.unwrap() {
            ParsedStatement::Select(s) => {
                assert_eq!(s.table, "users");
                assert_eq!(s.joins.len(), 1);
                assert_eq!(s.joins[0].table, "orders");
                assert!(matches!(s.joins[0].join_type, JoinType::Inner));
            }
            _ => panic!("expected SELECT statement"),
        }
    }

    #[test]
    fn test_parse_left_join() {
        let result =
            parse_statement("SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id");
        assert!(result.is_ok());
        match result.unwrap() {
            ParsedStatement::Select(s) => {
                assert_eq!(s.table, "users");
                assert_eq!(s.joins.len(), 1);
                assert_eq!(s.joins[0].table, "orders");
                assert!(matches!(s.joins[0].join_type, JoinType::Left));
            }
            _ => panic!("expected SELECT statement"),
        }
    }

    #[test]
    fn test_parse_multi_join() {
        let result = parse_statement(
            "SELECT * FROM users \
             JOIN orders ON users.id = orders.user_id \
             JOIN products ON orders.product_id = products.id",
        );
        assert!(result.is_ok());
        match result.unwrap() {
            ParsedStatement::Select(s) => {
                assert_eq!(s.table, "users");
                assert_eq!(s.joins.len(), 2);
                assert_eq!(s.joins[0].table, "orders");
                assert_eq!(s.joins[1].table, "products");
            }
            _ => panic!("expected SELECT statement"),
        }
    }

    #[test]
    fn test_reject_subquery() {
        let result = parse_statement("SELECT * FROM (SELECT * FROM users)");
        assert!(result.is_err());
    }

    #[test]
    fn test_where_depth_within_limit() {
        // Test reasonable nesting depth (stays within sqlparser limits)
        // Build a query with nested AND/OR to test our depth tracking
        let mut sql = String::from("SELECT * FROM users WHERE ");
        for i in 0..10 {
            if i > 0 {
                sql.push_str(" AND ");
            }
            sql.push('(');
            sql.push_str("id = ");
            sql.push_str(&i.to_string());
            sql.push(')');
        }

        let result = parse_statement(&sql);
        assert!(
            result.is_ok(),
            "Moderate nesting should succeed, but got: {result:?}"
        );
    }

    #[test]
    fn test_where_depth_nested_parens() {
        // Test nested parentheses (this will hit sqlparser limit before ours)
        // Just verify that excessive nesting is rejected by some limit
        let mut sql = String::from("SELECT * FROM users WHERE ");
        for _ in 0..200 {
            sql.push('(');
        }
        sql.push_str("id = 1");
        for _ in 0..200 {
            sql.push(')');
        }

        let result = parse_statement(&sql);
        assert!(
            result.is_err(),
            "Excessive parenthesis nesting should be rejected"
        );
    }

    #[test]
    fn test_where_depth_complex_and_or() {
        // Test complex AND/OR nesting patterns
        let sql = "SELECT * FROM users WHERE \
                   ((id = 1 AND name = 'a') OR (id = 2 AND name = 'b')) AND \
                   ((age > 10 AND age < 20) OR (age > 30 AND age < 40))";

        let result = parse_statement(sql);
        assert!(result.is_ok(), "Complex AND/OR should succeed");
    }

    #[test]
    fn test_parse_having() {
        let result =
            parse_test_select("SELECT name, COUNT(*) FROM users GROUP BY name HAVING COUNT(*) > 5");
        assert_eq!(result.group_by.len(), 1);
        assert_eq!(result.having.len(), 1);
        match &result.having[0] {
            HavingCondition::AggregateComparison {
                aggregate,
                op,
                value,
            } => {
                assert!(matches!(aggregate, AggregateFunction::CountStar));
                assert_eq!(*op, HavingOp::Gt);
                assert_eq!(*value, Value::BigInt(5));
            }
        }
    }

    #[test]
    fn test_parse_having_multiple() {
        let result = parse_test_select(
            "SELECT name, COUNT(*), SUM(age) FROM users GROUP BY name HAVING COUNT(*) > 1 AND SUM(age) < 100",
        );
        assert_eq!(result.having.len(), 2);
    }

    #[test]
    fn test_parse_having_without_group_by() {
        let result = parse_test_select("SELECT COUNT(*) FROM users HAVING COUNT(*) > 0");
        assert!(result.group_by.is_empty());
        assert_eq!(result.having.len(), 1);
    }

    #[test]
    fn test_parse_union() {
        let result = parse_statement("SELECT id FROM users UNION SELECT id FROM orders");
        assert!(result.is_ok());
        match result.unwrap() {
            ParsedStatement::Union(u) => {
                assert_eq!(u.left.table, "users");
                assert_eq!(u.right.table, "orders");
                assert!(!u.all);
            }
            _ => panic!("expected UNION statement"),
        }
    }

    #[test]
    fn test_parse_union_all() {
        let result = parse_statement("SELECT id FROM users UNION ALL SELECT id FROM orders");
        assert!(result.is_ok());
        match result.unwrap() {
            ParsedStatement::Union(u) => {
                assert_eq!(u.left.table, "users");
                assert_eq!(u.right.table, "orders");
                assert!(u.all);
            }
            _ => panic!("expected UNION ALL statement"),
        }
    }

    #[test]
    fn test_parse_create_mask() {
        let result = parse_statement("CREATE MASK ssn_mask ON patients.ssn USING REDACT").unwrap();
        match result {
            ParsedStatement::CreateMask(m) => {
                assert_eq!(m.mask_name, "ssn_mask");
                assert_eq!(m.table_name, "patients");
                assert_eq!(m.column_name, "ssn");
                assert_eq!(m.strategy, "REDACT");
            }
            _ => panic!("expected CREATE MASK statement"),
        }
    }

    #[test]
    fn test_parse_create_mask_with_semicolon() {
        let result = parse_statement("CREATE MASK ssn_mask ON patients.ssn USING REDACT;").unwrap();
        match result {
            ParsedStatement::CreateMask(m) => {
                assert_eq!(m.mask_name, "ssn_mask");
                assert_eq!(m.strategy, "REDACT");
            }
            _ => panic!("expected CREATE MASK statement"),
        }
    }

    #[test]
    fn test_parse_create_mask_hash_strategy() {
        let result = parse_statement("CREATE MASK email_hash ON users.email USING HASH").unwrap();
        match result {
            ParsedStatement::CreateMask(m) => {
                assert_eq!(m.mask_name, "email_hash");
                assert_eq!(m.table_name, "users");
                assert_eq!(m.column_name, "email");
                assert_eq!(m.strategy, "HASH");
            }
            _ => panic!("expected CREATE MASK statement"),
        }
    }

    #[test]
    fn test_parse_create_mask_missing_on() {
        let result = parse_statement("CREATE MASK ssn_mask patients.ssn USING REDACT");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_create_mask_missing_dot() {
        let result = parse_statement("CREATE MASK ssn_mask ON patients_ssn USING REDACT");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_drop_mask() {
        let result = parse_statement("DROP MASK ssn_mask").unwrap();
        match result {
            ParsedStatement::DropMask(name) => {
                assert_eq!(name, "ssn_mask");
            }
            _ => panic!("expected DROP MASK statement"),
        }
    }

    #[test]
    fn test_parse_drop_mask_with_semicolon() {
        let result = parse_statement("DROP MASK ssn_mask;").unwrap();
        match result {
            ParsedStatement::DropMask(name) => {
                assert_eq!(name, "ssn_mask");
            }
            _ => panic!("expected DROP MASK statement"),
        }
    }

    // ========================================================================
    // CREATE / DROP MASKING POLICY + ATTACH / DETACH tests (v0.6.0)
    // ========================================================================

    #[test]
    fn test_parse_create_masking_policy_redact_ssn() {
        let result = parse_statement(
            "CREATE MASKING POLICY ssn_policy STRATEGY REDACT_SSN EXEMPT ROLES ('clinician', 'billing')",
        )
        .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.name, "ssn_policy");
                assert_eq!(p.strategy, ParsedMaskingStrategy::RedactSsn);
                assert_eq!(p.exempt_roles, vec!["clinician", "billing"]);
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_hash_single_role() {
        let result =
            parse_statement("CREATE MASKING POLICY h STRATEGY HASH EXEMPT ROLES (admin)").unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.name, "h");
                assert_eq!(p.strategy, ParsedMaskingStrategy::Hash);
                assert_eq!(p.exempt_roles, vec!["admin"]);
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_tokenize() {
        let result = parse_statement(
            "CREATE MASKING POLICY note_tok STRATEGY TOKENIZE EXEMPT ROLES ('clinician');",
        )
        .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.strategy, ParsedMaskingStrategy::Tokenize);
                assert_eq!(p.exempt_roles, vec!["clinician"]);
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_truncate_with_arg() {
        let result = parse_statement(
            "CREATE MASKING POLICY tr STRATEGY TRUNCATE 4 EXEMPT ROLES ('billing')",
        )
        .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.strategy, ParsedMaskingStrategy::Truncate { max_chars: 4 });
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_redact_custom() {
        let result = parse_statement(
            "CREATE MASKING POLICY c STRATEGY REDACT_CUSTOM '***' EXEMPT ROLES ('admin')",
        )
        .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => match p.strategy {
                ParsedMaskingStrategy::RedactCustom { replacement } => {
                    assert_eq!(replacement, "***");
                }
                other => panic!("expected RedactCustom, got {other:?}"),
            },
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_null_strategy() {
        let result =
            parse_statement("CREATE MASKING POLICY n STRATEGY NULL EXEMPT ROLES ('auditor')")
                .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.strategy, ParsedMaskingStrategy::Null);
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_lowercases_roles() {
        // Roles are case-folded at parse time so RoleGuard::should_mask
        // does not need to re-fold on every read.
        let result = parse_statement(
            "CREATE MASKING POLICY p STRATEGY HASH EXEMPT ROLES ('Clinician', 'NURSE')",
        )
        .unwrap();
        match result {
            ParsedStatement::CreateMaskingPolicy(p) => {
                assert_eq!(p.exempt_roles, vec!["clinician", "nurse"]);
            }
            other => panic!("expected CreateMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_create_masking_policy_rejects_unknown_strategy() {
        let result =
            parse_statement("CREATE MASKING POLICY p STRATEGY SCRAMBLE EXEMPT ROLES ('x')");
        assert!(result.is_err(), "expected unknown-strategy error");
    }

    #[test]
    fn test_parse_create_masking_policy_rejects_zero_truncate() {
        let result =
            parse_statement("CREATE MASKING POLICY p STRATEGY TRUNCATE 0 EXEMPT ROLES ('x')");
        assert!(result.is_err(), "TRUNCATE 0 must be rejected");
    }

    #[test]
    fn test_parse_create_masking_policy_rejects_empty_exempt_list() {
        let result = parse_statement("CREATE MASKING POLICY p STRATEGY HASH EXEMPT ROLES ()");
        assert!(result.is_err(), "empty EXEMPT ROLES list must be rejected");
    }

    #[test]
    fn test_parse_create_masking_policy_rejects_missing_exempt_roles() {
        let result = parse_statement("CREATE MASKING POLICY p STRATEGY HASH");
        assert!(
            result.is_err(),
            "missing EXEMPT ROLES clause must be rejected"
        );
    }

    #[test]
    fn test_parse_drop_masking_policy() {
        let result = parse_statement("DROP MASKING POLICY ssn_policy").unwrap();
        match result {
            ParsedStatement::DropMaskingPolicy(name) => {
                assert_eq!(name, "ssn_policy");
            }
            other => panic!("expected DropMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_drop_masking_policy_with_semicolon() {
        let result = parse_statement("DROP MASKING POLICY ssn_policy;").unwrap();
        match result {
            ParsedStatement::DropMaskingPolicy(name) => {
                assert_eq!(name, "ssn_policy");
            }
            other => panic!("expected DropMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_drop_masking_policy_does_not_swallow_drop_mask() {
        // Regression: the "DROP MASKING POLICY" check must precede
        // the legacy "DROP MASK" branch or the legacy form would never
        // match. Confirm the legacy form still routes correctly.
        let result = parse_statement("DROP MASK ssn_mask").unwrap();
        assert!(matches!(result, ParsedStatement::DropMask(_)));
    }

    #[test]
    fn test_parse_attach_masking_policy() {
        let result = parse_statement(
            "ALTER TABLE patients ALTER COLUMN medicare_number SET MASKING POLICY ssn_policy",
        )
        .unwrap();
        match result {
            ParsedStatement::AttachMaskingPolicy(a) => {
                assert_eq!(a.table_name, "patients");
                assert_eq!(a.column_name, "medicare_number");
                assert_eq!(a.policy_name, "ssn_policy");
            }
            other => panic!("expected AttachMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_detach_masking_policy() {
        let result = parse_statement(
            "ALTER TABLE patients ALTER COLUMN medicare_number DROP MASKING POLICY",
        )
        .unwrap();
        match result {
            ParsedStatement::DetachMaskingPolicy(d) => {
                assert_eq!(d.table_name, "patients");
                assert_eq!(d.column_name, "medicare_number");
            }
            other => panic!("expected DetachMaskingPolicy, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_attach_masking_policy_rejects_missing_policy_name() {
        let result =
            parse_statement("ALTER TABLE patients ALTER COLUMN medicare_number SET MASKING POLICY");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_create_masking_policy_does_not_match_legacy_create_mask() {
        // Regression: "CREATE MASKING POLICY" must not be swallowed by
        // the "CREATE MASK" prefix check.
        let result =
            parse_statement("CREATE MASKING POLICY p STRATEGY HASH EXEMPT ROLES ('admin')")
                .unwrap();
        assert!(matches!(result, ParsedStatement::CreateMaskingPolicy(_)));
    }

    // ========================================================================
    // SET CLASSIFICATION tests
    // ========================================================================

    #[test]
    fn test_parse_set_classification() {
        let result =
            parse_statement("ALTER TABLE patients MODIFY COLUMN ssn SET CLASSIFICATION 'PHI'")
                .unwrap();
        match result {
            ParsedStatement::SetClassification(sc) => {
                assert_eq!(sc.table_name, "patients");
                assert_eq!(sc.column_name, "ssn");
                assert_eq!(sc.classification, "PHI");
            }
            _ => panic!("expected SetClassification statement"),
        }
    }

    #[test]
    fn test_parse_set_classification_with_semicolon() {
        let result = parse_statement(
            "ALTER TABLE patients MODIFY COLUMN diagnosis SET CLASSIFICATION 'MEDICAL';",
        )
        .unwrap();
        match result {
            ParsedStatement::SetClassification(sc) => {
                assert_eq!(sc.table_name, "patients");
                assert_eq!(sc.column_name, "diagnosis");
                assert_eq!(sc.classification, "MEDICAL");
            }
            _ => panic!("expected SetClassification statement"),
        }
    }

    #[test]
    fn test_parse_set_classification_various_labels() {
        for label in &["PHI", "PII", "PCI", "MEDICAL", "FINANCIAL", "CONFIDENTIAL"] {
            let sql = format!("ALTER TABLE t MODIFY COLUMN c SET CLASSIFICATION '{label}'");
            let result = parse_statement(&sql).unwrap();
            match result {
                ParsedStatement::SetClassification(sc) => {
                    assert_eq!(sc.classification, *label);
                }
                _ => panic!("expected SetClassification for {label}"),
            }
        }
    }

    #[test]
    fn test_parse_set_classification_missing_quotes() {
        let result =
            parse_statement("ALTER TABLE patients MODIFY COLUMN ssn SET CLASSIFICATION PHI");
        assert!(result.is_err(), "classification must be single-quoted");
    }

    #[test]
    fn test_parse_set_classification_missing_modify() {
        // Without MODIFY COLUMN, sqlparser handles it (ADD/DROP COLUMN)
        // or returns a different error — not a SetClassification parse error.
        let result = parse_statement("ALTER TABLE patients SET CLASSIFICATION 'PHI'");
        assert!(result.is_err());
    }

    // ========================================================================
    // SHOW CLASSIFICATIONS tests
    // ========================================================================

    #[test]
    fn test_parse_show_classifications() {
        let result = parse_statement("SHOW CLASSIFICATIONS FOR patients").unwrap();
        match result {
            ParsedStatement::ShowClassifications(table) => {
                assert_eq!(table, "patients");
            }
            _ => panic!("expected ShowClassifications statement"),
        }
    }

    #[test]
    fn test_parse_show_classifications_with_semicolon() {
        let result = parse_statement("SHOW CLASSIFICATIONS FOR patients;").unwrap();
        match result {
            ParsedStatement::ShowClassifications(table) => {
                assert_eq!(table, "patients");
            }
            _ => panic!("expected ShowClassifications statement"),
        }
    }

    #[test]
    fn test_parse_show_classifications_missing_for() {
        let result = parse_statement("SHOW CLASSIFICATIONS patients");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_show_classifications_missing_table() {
        let result = parse_statement("SHOW CLASSIFICATIONS FOR");
        assert!(result.is_err());
    }

    // ========================================================================
    // RBAC statement tests
    // ========================================================================

    #[test]
    fn test_parse_create_role() {
        let result = parse_statement("CREATE ROLE billing_clerk").unwrap();
        match result {
            ParsedStatement::CreateRole(name) => {
                assert_eq!(name, "billing_clerk");
            }
            _ => panic!("expected CreateRole"),
        }
    }

    #[test]
    fn test_parse_create_role_with_semicolon() {
        let result = parse_statement("CREATE ROLE doctor;").unwrap();
        match result {
            ParsedStatement::CreateRole(name) => {
                assert_eq!(name, "doctor");
            }
            _ => panic!("expected CreateRole"),
        }
    }

    #[test]
    fn test_parse_grant_select_all_columns() {
        let result = parse_statement("GRANT SELECT ON patients TO doctor").unwrap();
        match result {
            ParsedStatement::Grant(g) => {
                assert!(g.columns.is_none());
                assert_eq!(g.table_name, "patients");
                assert_eq!(g.role_name, "doctor");
            }
            _ => panic!("expected Grant"),
        }
    }

    #[test]
    fn test_parse_grant_select_specific_columns() {
        let result =
            parse_statement("GRANT SELECT (id, name, ssn) ON patients TO billing_clerk").unwrap();
        match result {
            ParsedStatement::Grant(g) => {
                assert_eq!(
                    g.columns,
                    Some(vec!["id".into(), "name".into(), "ssn".into()])
                );
                assert_eq!(g.table_name, "patients");
                assert_eq!(g.role_name, "billing_clerk");
            }
            _ => panic!("expected Grant"),
        }
    }

    #[test]
    fn test_parse_create_user() {
        let result = parse_statement("CREATE USER clerk1 WITH ROLE billing_clerk").unwrap();
        match result {
            ParsedStatement::CreateUser(u) => {
                assert_eq!(u.username, "clerk1");
                assert_eq!(u.role, "billing_clerk");
            }
            _ => panic!("expected CreateUser"),
        }
    }

    #[test]
    fn test_parse_create_user_with_semicolon() {
        let result = parse_statement("CREATE USER admin1 WITH ROLE admin;").unwrap();
        match result {
            ParsedStatement::CreateUser(u) => {
                assert_eq!(u.username, "admin1");
                assert_eq!(u.role, "admin");
            }
            _ => panic!("expected CreateUser"),
        }
    }

    #[test]
    fn test_parse_create_user_missing_role() {
        let result = parse_statement("CREATE USER clerk1 WITH billing_clerk");
        assert!(result.is_err());
    }

    /// Regression: fuzz_sql_parser found that sqlparser accepts inputs
    /// like `CREATE TABLE#USER` as a CreateTable with an empty columns
    /// vector. Kimberlite must reject these at parse time — a zero-column
    /// table has no valid projection, primary key, or DML target.
    #[test]
    fn test_parse_create_table_rejects_zero_columns() {
        // The literal input that seeded the discovery.
        let result = parse_statement("CREATE TABLE#USER");
        assert!(result.is_err(), "zero-column CREATE TABLE must be rejected");

        // The explicit empty-parens form should fail as well. sqlparser may
        // reject it at lex time, may accept it with zero columns — either
        // way, Kimberlite must not return Ok.
        let result = parse_statement("CREATE TABLE t ()");
        assert!(
            result.is_err(),
            "empty-column-list CREATE TABLE must be rejected"
        );
    }

    // ========================================================================
    // UPSERT parser tests (v0.6.0 Tier 1 #3 — ON CONFLICT)
    // ========================================================================

    fn parse_test_insert(sql: &str) -> ParsedInsert {
        match parse_statement(sql).unwrap_or_else(|e| panic!("parse failed: {e}")) {
            ParsedStatement::Insert(i) => i,
            other => panic!("expected INSERT statement, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_insert_on_conflict_do_update() {
        let ins = parse_test_insert(
            "INSERT INTO users (id, name) VALUES (1, 'Alice') \
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
        );
        let oc = ins.on_conflict.expect("on_conflict must be present");
        assert_eq!(oc.target, vec!["id".to_string()]);
        match oc.action {
            OnConflictAction::DoUpdate { assignments } => {
                assert_eq!(assignments.len(), 1);
                assert_eq!(assignments[0].0, "name");
                assert_eq!(
                    assignments[0].1,
                    UpsertExpr::Excluded("name".to_string()),
                    "RHS must be an EXCLUDED.col back-reference"
                );
            }
            other @ OnConflictAction::DoNothing => panic!("expected DoUpdate, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_insert_on_conflict_do_nothing() {
        let ins = parse_test_insert(
            "INSERT INTO users (id, name) VALUES (1, 'Alice') ON CONFLICT (id) DO NOTHING",
        );
        let oc = ins.on_conflict.expect("on_conflict must be present");
        assert_eq!(oc.target, vec!["id".to_string()]);
        assert!(
            matches!(oc.action, OnConflictAction::DoNothing),
            "DO NOTHING must parse to OnConflictAction::DoNothing"
        );
    }

    #[test]
    fn test_parse_plain_insert_has_no_on_conflict() {
        let ins = parse_test_insert("INSERT INTO users (id, name) VALUES (1, 'Alice')");
        assert!(
            ins.on_conflict.is_none(),
            "plain INSERT must not carry an on_conflict clause"
        );
    }

    #[test]
    fn test_parse_insert_on_conflict_multi_column_target() {
        let ins = parse_test_insert(
            "INSERT INTO t (tenant_id, id, v) VALUES (1, 2, 3) \
             ON CONFLICT (tenant_id, id) DO UPDATE SET v = EXCLUDED.v",
        );
        let oc = ins.on_conflict.expect("on_conflict must be present");
        assert_eq!(oc.target, vec!["tenant_id".to_string(), "id".to_string()]);
    }

    #[test]
    fn test_parse_insert_on_conflict_with_returning() {
        let ins = parse_test_insert(
            "INSERT INTO t (id, v) VALUES (1, 2) \
             ON CONFLICT (id) DO UPDATE SET v = EXCLUDED.v RETURNING id, v",
        );
        assert!(ins.on_conflict.is_some());
        assert_eq!(ins.returning, Some(vec!["id".to_string(), "v".to_string()]));
    }

    #[test]
    fn test_parse_insert_on_conflict_rejects_on_constraint_form() {
        // ON CONSTRAINT <name> is deliberately out of scope for v0.6.0.
        let result = parse_statement(
            "INSERT INTO t (id) VALUES (1) ON CONFLICT ON CONSTRAINT pk_t DO NOTHING",
        );
        assert!(
            result.is_err(),
            "ON CONSTRAINT form must be rejected with a clear error"
        );
    }

    #[test]
    fn test_parse_insert_on_conflict_literal_rhs() {
        // RHS can also be a literal value, not only EXCLUDED.col.
        let ins = parse_test_insert(
            "INSERT INTO t (id, v) VALUES (1, 2) \
             ON CONFLICT (id) DO UPDATE SET v = 42",
        );
        let oc = ins.on_conflict.expect("on_conflict must be present");
        match oc.action {
            OnConflictAction::DoUpdate { assignments } => {
                assert_eq!(assignments[0].0, "v");
                assert!(matches!(assignments[0].1, UpsertExpr::Value(_)));
            }
            other @ OnConflictAction::DoNothing => panic!("expected DoUpdate, got {other:?}"),
        }
    }
}
