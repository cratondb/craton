//! Error types for the Kimberlite SDK.
//!
//! This module provides a unified error type that wraps errors from the
//! underlying subsystems: kernel, storage, projection store, and query engine.

use kimberlite_kernel::KernelError;
use kimberlite_query::QueryError;
use kimberlite_storage::StorageError;
use kimberlite_store::StoreError;
use kimberlite_types::{Offset, StreamId, StreamIdEncodingError, TenantId};
use thiserror::Error;

/// Result type for Kimberlite operations.
pub type Result<T> = std::result::Result<T, KimberliteError>;

/// Errors that can occur during Kimberlite operations.
#[derive(Debug, Error)]
pub enum KimberliteError {
    /// Error from the kernel (state machine).
    #[error("kernel error: {0}")]
    Kernel(#[from] KernelError),

    /// Error from the storage layer (append-only log).
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Error from the projection store (B+tree).
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// Error from the query engine (SQL parsing/execution).
    #[error("query error: {0}")]
    Query(#[from] QueryError),

    /// Tenant not found.
    #[error("tenant not found: {0:?}")]
    TenantNotFound(TenantId),

    /// Tenant id is too large to encode inside a `StreamId`.
    ///
    /// `StreamId` is a bit-packed `u64` with the tenant id in the upper
    /// 32 bits, so tenant ids beyond `u32::MAX` silently truncate and
    /// corrupt per-tenant filtering. This variant surfaces the limit at
    /// the call site (server handshake, `tenant.create_stream`) instead
    /// of letting a downstream component report a mysterious
    /// `StreamAlreadyExists` or cross-tenant data leak.
    #[error(
        "tenant_id {tenant_id} exceeds the StreamId encoding limit of {max}; tenant ids must be <= u32::MAX. \
         Reduce tenant_id below {max} (see kimberlite_types::MAX_TENANT_ID_FOR_STREAM_ID)."
    )]
    TenantIdTooLarge { tenant_id: u64, max: u64 },

    /// Stream not found.
    #[error("stream not found: {0}")]
    StreamNotFound(StreamId),

    /// Table not found in schema.
    #[error("table not found: {0}")]
    TableNotFound(String),

    /// Position is ahead of current log position.
    #[error("position {requested} is ahead of current log position {current}")]
    PositionAhead { requested: Offset, current: Offset },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Projection store is not caught up to the log.
    #[error("projection store at position {store_pos}, log at {log_pos}")]
    ProjectionLag { store_pos: Offset, log_pos: Offset },

    /// Internal error (should not occur in normal operation).
    #[error("internal error: {0}")]
    Internal(String),
}

impl KimberliteError {
    /// Creates an internal error with the given message.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Creates a configuration error with the given message.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<StreamIdEncodingError> for KimberliteError {
    fn from(e: StreamIdEncodingError) -> Self {
        match e {
            StreamIdEncodingError::TenantIdTooLarge { tenant_id, max } => {
                Self::TenantIdTooLarge { tenant_id, max }
            }
        }
    }
}
