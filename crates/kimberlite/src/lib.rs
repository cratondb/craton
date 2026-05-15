//! # Kimberlite
//!
//! Compliance-native database for regulated industries.
//!
//! Kimberlite is built on a replicated append-only log with deterministic
//! projection to a custom storage engine. This provides:
//!
//! - **Correctness by design** - Ordered log → deterministic apply → snapshot
//! - **Full audit trail** - Every mutation is captured in the immutable log
//! - **Point-in-time recovery** - Replay from any offset
//! - **Compliance by construction** - Built-in durability and encryption
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                          Kimberlite                             │
//! │  ┌─────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐ │
//! │  │   Log   │ → │  Kernel   │ → │  Store   │ → │  Query   │ │
//! │  │(append) │   │(pure FSM) │   │(B+tree)  │   │  (SQL)   │ │
//! │  └─────────┘   └───────────┘   └──────────┘   └──────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use kimberlite::{Kimberlite, TenantId, DataClass};
//!
//! // Open database
//! let db = Kimberlite::open("./data")?;
//!
//! // Get tenant handle
//! let tenant = db.tenant(TenantId::new(1));
//!
//! // Create a stream
//! let stream_id = tenant.create_stream("events", DataClass::Public)?;
//!
//! // Append events
//! tenant.append(stream_id, vec![b"event1".to_vec(), b"event2".to_vec()], Offset::ZERO)?;
//!
//! // Query (point-in-time support)
//! let results = tenant.query("SELECT * FROM events LIMIT 10", &[])?;
//! ```
//!
//! # Modules
//!
//! - **SDK Layer**: [`Kimberlite`], [`TenantHandle`] - Main API
//! - **Foundation**: Types, crypto, storage primitives
//! - **Query**: SQL subset for compliance lookups

#![cfg_attr(test, allow(clippy::too_many_lines))] // Test functions can be long
#![cfg_attr(test, allow(clippy::unwrap_used))] // Tests use unwrap for simplicity
#![allow(clippy::items_after_statements)] // Helper functions can be defined near their use
#![allow(clippy::unused_self)] // Some methods don't need self but are part of a trait-like interface
#![allow(clippy::needless_range_loop)] // Explicit range loops are clearer in some cases
#![allow(clippy::match_same_arms)] // Sometimes duplicate arms improve clarity
#![allow(clippy::needless_pass_by_value)] // Some parameters are passed by value for API consistency
#![allow(clippy::too_many_lines)] // Some integration functions are necessarily long
#![allow(clippy::explicit_iter_loop)] // Explicit iteration is clearer than .iter()
#![allow(clippy::explicit_counter_loop)] // Explicit loop counters are clearer in integration code

mod erasure_executor;
mod error;
mod kimberlite;
mod sieve_cache;
mod tenant;
mod timestamp_index;

// Kani verification harnesses for bounded model checking
#[cfg(kani)]
mod kani_proofs;

#[cfg(feature = "broadcast")]
pub mod broadcast;

// SDK Layer - Main API
pub use error::{KimberliteError, Result};
pub use kimberlite::{CommandRouter, Kimberlite, KimberliteConfig};
pub use tenant::{ExecuteResult, TenantHandle};

// Re-export core types from kmb-types
pub use kimberlite_types::{
    DataClass, GroupId, Offset, Placement, Region, StreamId, StreamMetadata, StreamName, TenantId,
};

// Re-export crypto primitives
pub use kimberlite_crypto::{ChainHash, chain_hash};

// Re-export field-level encryption
pub use kimberlite_crypto::{
    FieldKey, ReversibleToken, Token, decrypt_field, encrypt_field, tokenize,
};

// Re-export anonymization utilities
pub use kimberlite_crypto::{
    DatePrecision, GeoLevel, KAnonymityResult, MaskStyle, check_k_anonymity, generalize_age,
    generalize_numeric, generalize_zip, mask, redact, truncate_date,
};

// Re-export storage types
pub use kimberlite_storage::{Record, Storage, StorageError};

// Re-export kernel types
pub use kimberlite_kernel::{Command, Effect, KernelError, State, apply_committed};

// Re-export directory
pub use kimberlite_directory::{Directory, DirectoryError};

// Re-export query types for SQL operations
pub use kimberlite_query::{
    ColumnDef, ColumnName, DataType, QueryEngine, QueryError, QueryResult, Row, Schema,
    SchemaBuilder, TableDef, TableName, Value,
};

// Re-export store types for advanced usage
pub use kimberlite_store::{
    BTreeStore, Key, ProjectionStore, StoreError, TableId, WriteBatch, WriteOp,
};

// Re-export RBAC types for role-based access control
pub use kimberlite_rbac::{
    AccessPolicy, ColumnFilter, EnforcementError, Permission, PermissionSet, PolicyEnforcer, Role,
    RowFilter, RowFilterOperator, StandardPolicies, StreamFilter,
};

// Re-export field masking types
pub use kimberlite_rbac::masking::{
    FieldMask, MaskingError, MaskingPolicy, MaskingStrategy, RedactPattern,
};

// Re-export ABAC types for attribute-based access control
pub use kimberlite_abac::{
    AbacPolicy, Decision as AbacDecision, EnvironmentAttributes, PolicyEffect, ResourceAttributes,
    Rule as AbacRule, UserAttributes,
};

// Re-export compliance framework types
pub use kimberlite_compliance::{
    ComplianceError, ComplianceFramework, ComplianceReport, ProofCertificate, ProofStatus,
    Requirement,
};

// Re-export consent management types
pub use kimberlite_compliance::consent::{
    ConsentError, ConsentRecord, ConsentScope, ConsentTracker,
};

// Re-export purpose limitation types
pub use kimberlite_compliance::purpose::Purpose;

// Re-export erasure types (GDPR Article 17)
pub use kimberlite_compliance::erasure::{
    ErasureEngine, ErasureError, ErasureRequest, ErasureStatus, ExemptionBasis,
};

// Re-export breach detection types
pub use kimberlite_compliance::breach::{
    BreachDetector, BreachError, BreachEvent, BreachIndicator, BreachReport, BreachSeverity,
    BreachStatus, BreachThresholds,
};

// Re-export data portability types (GDPR Article 20)
pub use kimberlite_compliance::export::{
    ExportEngine, ExportError, ExportFormat, ExportRecord, PortabilityExport,
};

// Re-export compliance audit types
pub use kimberlite_compliance::audit::{
    AuditQuery, ComplianceAuditAction, ComplianceAuditEvent, ComplianceAuditLog,
};
