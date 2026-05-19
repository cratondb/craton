//! Error types for store operations.

use std::io;

use crate::Key;
use crate::types::{PageId, TableId};

/// Errors that can occur during store operations.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// Filesystem I/O error.
    #[error("filesystem error: {0}")]
    Io(#[from] io::Error),

    /// Page CRC32 checksum mismatch - data corruption detected.
    #[error(
        "page {page_id} corrupted: CRC mismatch (expected {expected:#010x}, got {actual:#010x})"
    )]
    PageCorrupted {
        page_id: PageId,
        expected: u32,
        actual: u32,
    },

    /// Key exceeds maximum allowed length.
    #[error("key too long: {len} bytes exceeds maximum {max}")]
    KeyTooLong { len: usize, max: usize },

    /// Value exceeds maximum size that fits in a page.
    #[error("value too large: {len} bytes exceeds maximum {max}")]
    ValueTooLarge { len: usize, max: usize },

    /// Page has invalid magic bytes.
    #[error("invalid page magic: expected {expected:#010x}, got {actual:#010x}")]
    InvalidPageMagic { expected: u32, actual: u32 },

    /// Page has unsupported version.
    #[error("unsupported page version: {0}")]
    UnsupportedPageVersion(u8),

    /// Superblock has invalid magic bytes.
    #[error("invalid superblock magic")]
    InvalidSuperblockMagic,

    /// Superblock CRC mismatch.
    #[error("superblock corrupted: CRC mismatch")]
    SuperblockCorrupted,

    /// Batch position is not sequential.
    #[error("non-sequential batch: expected position {expected}, got {actual}")]
    NonSequentialBatch { expected: u64, actual: u64 },

    /// Table not found.
    #[error("table {0:?} not found")]
    TableNotFound(TableId),

    /// Page overflow - not enough space for insert.
    #[error("page overflow: need {needed} bytes, have {available}")]
    PageOverflow { needed: usize, available: usize },

    /// A single B+tree leaf entry (one key + its version chain) has
    /// grown larger than what fits on a page, so splitting the leaf
    /// can't help. The typical cause is repeated upsert-in-place on the
    /// same primary key — every overwrite appends a version to the
    /// MVCC chain, so a hot row that's updated dozens of times
    /// accumulates a chain whose `serialized_size` exceeds the page
    /// byte budget.
    ///
    /// v0.9.0 surfaced this as the generic
    /// [`StoreError::PageOverflow`] inside `to_page`, which left
    /// callers with no actionable signal. v0.9.1 promotes it to a
    /// typed variant carrying the offending key + sizes so the SDK
    /// can render a clear error and the operator can pinpoint the hot
    /// row. Proper version-chain compaction driven by a retention
    /// horizon is v0.10.0 work.
    #[error(
        "leaf entry for key {key:?} is {entry_size} bytes — too large for the page budget of \
         {page_budget}. The MVCC version chain has grown unbounded under repeated upserts on the \
         same primary key; bound the update rate per key, or wait for v0.10.0's retention-horizon \
         compaction."
    )]
    EntryTooLarge {
        /// The key whose version chain exceeded the page budget.
        key: Key,
        /// Total serialized size of the leaf entry (key + version chain
        /// + per-version overhead).
        entry_size: usize,
        /// The page-level byte budget the entry must fit into.
        /// Equal to `PAGE_SIZE - PAGE_HEADER_SIZE - CRC_SIZE`.
        page_budget: usize,
    },

    /// Internal B+tree invariant violation.
    #[error("B+tree invariant violation: {0}")]
    BTreeInvariant(String),

    /// Duplicate key in batch.
    #[error("duplicate key in batch: {0:?}")]
    DuplicateKey(Key),

    /// Page not found in cache or on disk.
    #[error("page {0} not found")]
    PageNotFound(PageId),

    /// Store is read-only.
    #[error("store is read-only")]
    ReadOnly,
}
