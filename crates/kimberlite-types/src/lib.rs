//! # kmb-types: Core types for `Kimberlite`
//!
//! This crate contains shared types used across the `Kimberlite` system:
//! - Entity IDs ([`TenantId`], [`StreamId`], [`Offset`], [`GroupId`])
//! - Cryptographic types ([`struct@Hash`])
//! - Temporal types ([`Timestamp`])
//! - Log record types ([`RecordKind`], [`RecordHeader`], [`Checkpoint`], [`CheckpointPolicy`])
//! - Projection tracking ([`AppliedIndex`])
//! - Idempotency ([`IdempotencyId`])
//! - Recovery tracking ([`Generation`], [`RecoveryRecord`], [`RecoveryReason`])
//! - Data classification ([`DataClass`])
//! - Placement rules ([`Placement`], [`Region`])
//! - Stream metadata ([`StreamMetadata`])
//! - Audit actions ([`AuditAction`])
//! - Event persistence ([`EventPersister`], [`PersistError`])
//!
//! This crate opts in to strict PRESSURECRAFT clippy lints. Test-only
//! `unwrap()` / `panic!` are allowed via `cfg_attr(test, ...)`.

#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::too_many_lines
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::too_many_lines
    )
)]

use std::{
    fmt::{Debug, Display},
    ops::{Add, AddAssign, Range, Sub},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

// ============================================================================
// Entity IDs - All Copy (cheap 8-byte values)
// ============================================================================

/// Unique identifier for a tenant (organization/customer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantId(u64);

impl TenantId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Extracts tenant ID from stream ID (upper 32 bits).
    ///
    /// **Bit Layout**:
    /// - Upper 32 bits: `tenant_id` (supports 4.3B tenants)
    /// - Lower 32 bits: `local_stream_id` (4.3B streams per tenant)
    ///
    /// # Examples
    ///
    /// ```
    /// # use kimberlite_types::{TenantId, StreamId};
    /// let stream_id = StreamId::from_tenant_and_local(TenantId::from(5), 1);
    /// assert_eq!(TenantId::from_stream_id(stream_id), TenantId::from(5));
    /// ```
    pub fn from_stream_id(stream_id: StreamId) -> Self {
        TenantId::from(u64::from(stream_id) >> 32)
    }
}

impl Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for TenantId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<TenantId> for u64 {
    fn from(id: TenantId) -> Self {
        id.0
    }
}

/// Unique identifier for a stream within the system.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct StreamId(u64);

impl StreamId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Creates stream ID from tenant ID and local stream number.
    ///
    /// **Bit Layout**:
    /// - Upper 32 bits: `tenant_id` (supports 4.3B tenants)
    /// - Lower 32 bits: `local_stream_id` (4.3B streams per tenant)
    ///
    /// # Examples
    ///
    /// ```
    /// # use kimberlite_types::{TenantId, StreamId};
    /// let stream_id = StreamId::from_tenant_and_local(TenantId::from(5), 1);
    /// assert_eq!(u64::from(stream_id), 21474836481); // (5 << 32) | 1
    /// assert_eq!(TenantId::from_stream_id(stream_id), TenantId::from(5));
    /// ```
    pub fn from_tenant_and_local(tenant_id: TenantId, local_id: u32) -> Self {
        let tenant_bits = u64::from(tenant_id) << 32;
        let local_bits = u64::from(local_id);
        StreamId::from(tenant_bits | local_bits)
    }

    /// Extracts local stream ID (lower 32 bits).
    ///
    /// # Examples
    ///
    /// ```
    /// # use kimberlite_types::{TenantId, StreamId};
    /// let stream_id = StreamId::from_tenant_and_local(TenantId::from(5), 42);
    /// assert_eq!(stream_id.local_id(), 42);
    /// ```
    pub fn local_id(self) -> u32 {
        (u64::from(self) & 0xFFFF_FFFF) as u32
    }

    /// Extracts the tenant id this stream belongs to (upper 32 bits).
    ///
    /// Convenience over `TenantId::from_stream_id(stream_id)` for the
    /// common `id.tenant_id() == other` call sites.
    ///
    /// # Examples
    ///
    /// ```
    /// # use kimberlite_types::{TenantId, StreamId};
    /// let stream_id = StreamId::from_tenant_and_local(TenantId::from(5), 1);
    /// assert_eq!(stream_id.tenant_id(), TenantId::from(5));
    /// ```
    pub fn tenant_id(self) -> TenantId {
        TenantId::from_stream_id(self)
    }
}

impl Add for StreamId {
    type Output = StreamId;

    /// Saturating add. Fuzzers can drive kernel state to `u64::MAX`; the
    /// old unchecked `+` panicked on overflow under debug assertions.
    /// Saturation keeps the type total without producing a smaller id.
    fn add(self, rhs: Self) -> Self::Output {
        StreamId::new(self.0.saturating_add(rhs.0))
    }
}

impl Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for StreamId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<StreamId> for u64 {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

/// Position of an event within a stream.
///
/// Offsets are zero-indexed and sequential. The first event in a stream
/// has offset 0, the second has offset 1, and so on.
///
/// Uses `u64` internally — offsets are never negative by definition.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Offset(u64);

impl Offset {
    pub const ZERO: Offset = Offset(0);

    pub fn new(offset: u64) -> Self {
        Self(offset)
    }

    /// Returns the offset as a `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the offset as a `usize` for indexing.
    ///
    /// # Panics
    ///
    /// Panics on 32-bit platforms if the offset exceeds `usize::MAX`.
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl Display for Offset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Offset {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Offset {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Offset {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl From<u64> for Offset {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Offset> for u64 {
    fn from(offset: Offset) -> Self {
        offset.0
    }
}

/// Unique identifier for a replication group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId(u64);

impl Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl GroupId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl From<u64> for GroupId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<GroupId> for u64 {
    fn from(id: GroupId) -> Self {
        id.0
    }
}

// ============================================================================
// Cryptographic Hash - Copy (fixed 32-byte value)
// ============================================================================

/// Length of cryptographic hashes in bytes (SHA-256 / BLAKE3).
pub const HASH_LENGTH: usize = 32;

/// A 32-byte cryptographic hash.
///
/// This is a foundation type used across `Kimberlite` for:
/// - Hash chain links (`prev_hash` in records)
/// - Verification anchors (in checkpoints and projections)
/// - Content addressing
///
/// The specific algorithm (SHA-256 for compliance, BLAKE3 for internal)
/// is determined by the context where the hash is computed. This type
/// only stores the resulting 32-byte digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; HASH_LENGTH]);

impl Hash {
    /// The genesis hash (all zeros) used as the `prev_hash` for the first record.
    pub const GENESIS: Hash = Hash([0u8; HASH_LENGTH]);

    /// Creates a hash from raw bytes.
    pub fn from_bytes(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; HASH_LENGTH] {
        &self.0
    }

    /// Returns true if this is the genesis hash (all zeros).
    pub fn is_genesis(&self) -> bool {
        self.0 == [0u8; HASH_LENGTH]
    }
}

impl Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 bytes in hex for debugging without exposing full hash
        write!(
            f,
            "Hash({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Full hex representation for display
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl From<[u8; HASH_LENGTH]> for Hash {
    fn from(bytes: [u8; HASH_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; HASH_LENGTH] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// Timestamp - Copy (8-byte value with monotonic guarantee)
// ============================================================================

/// Wall-clock timestamp with monotonic guarantee within the system.
///
/// Compliance requires real-world time for audit trails; monotonicity
/// prevents ordering issues when system clocks are adjusted.
///
/// Stored as nanoseconds since Unix epoch (1970-01-01 00:00:00 UTC).
/// This gives us ~584 years of range, well beyond any practical use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The Unix epoch (1970-01-01 00:00:00 UTC).
    pub const EPOCH: Timestamp = Timestamp(0);

    /// Creates a timestamp from nanoseconds since Unix epoch.
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns the timestamp as nanoseconds since Unix epoch.
    pub fn as_nanos(&self) -> u64 {
        self.0
    }

    /// Returns the timestamp as seconds since Unix epoch (truncates nanoseconds).
    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Creates a timestamp for the current time.
    ///
    /// # Panics
    ///
    /// Panics if the system clock is before Unix epoch (should never happen).
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before Unix epoch");
        Self(duration.as_nanos() as u64)
    }

    /// Creates a timestamp ensuring monotonicity: `max(now, last + 1ns)`.
    ///
    /// This guarantees that each timestamp is strictly greater than the previous,
    /// even if the system clock moves backwards or two events occur in the same
    /// nanosecond.
    ///
    /// # Arguments
    ///
    /// * `last` - The previous timestamp, if any. Pass `None` for the first timestamp.
    pub fn now_monotonic(last: Option<Timestamp>) -> Self {
        let now = Self::now();
        match last {
            Some(prev) => {
                // Ensure strictly increasing: at least prev + 1 nanosecond
                if now.0 <= prev.0 {
                    Timestamp(prev.0.saturating_add(1))
                } else {
                    now
                }
            }
            None => now,
        }
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as seconds.nanoseconds for readability
        let secs = self.0 / 1_000_000_000;
        let nanos = self.0 % 1_000_000_000;
        write!(f, "{secs}.{nanos:09}")
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::EPOCH
    }
}

impl From<u64> for Timestamp {
    fn from(nanos: u64) -> Self {
        Self(nanos)
    }
}

impl From<Timestamp> for u64 {
    fn from(ts: Timestamp) -> Self {
        ts.0
    }
}

// ============================================================================
// Record Types - Copy (small enum and struct)
// ============================================================================

/// The kind of record stored in the log.
///
/// This enum distinguishes between different record types to enable
/// efficient processing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum RecordKind {
    /// Normal application data record.
    #[default]
    Data,
    /// Periodic verification checkpoint (contains cumulative hash).
    Checkpoint,
    /// Logical deletion marker (data is not physically deleted).
    Tombstone,
}

impl RecordKind {
    /// Returns the single-byte discriminant for serialization.
    pub fn as_byte(&self) -> u8 {
        match self {
            RecordKind::Data => 0,
            RecordKind::Checkpoint => 1,
            RecordKind::Tombstone => 2,
        }
    }

    /// Creates a `RecordKind` from its byte discriminant.
    ///
    /// # Errors
    ///
    /// Returns `None` if the byte is not a valid discriminant.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(RecordKind::Data),
            1 => Some(RecordKind::Checkpoint),
            2 => Some(RecordKind::Tombstone),
            _ => None,
        }
    }
}

/// Metadata header for every log record.
///
/// This structure contains all metadata needed to verify and process
/// a log record without reading its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordHeader {
    /// Position in the log (0-indexed).
    pub offset: Offset,
    /// SHA-256 link to the previous record's hash (genesis for first record).
    pub prev_hash: Hash,
    /// When the record was committed (monotonic wall-clock).
    pub timestamp: Timestamp,
    /// Size of the payload in bytes.
    pub payload_len: u32,
    /// Type of record (Data, Checkpoint, Tombstone).
    pub record_kind: RecordKind,
}

impl RecordHeader {
    /// Creates a new record header.
    ///
    /// # Arguments
    ///
    /// * `offset` - Position in the log
    /// * `prev_hash` - Hash of the previous record (or GENESIS for first)
    /// * `timestamp` - When this record was committed
    /// * `payload_len` - Size of the payload in bytes
    /// * `record_kind` - Type of record
    pub fn new(
        offset: Offset,
        prev_hash: Hash,
        timestamp: Timestamp,
        payload_len: u32,
        record_kind: RecordKind,
    ) -> Self {
        Self {
            offset,
            prev_hash,
            timestamp,
            payload_len,
            record_kind,
        }
    }

    /// Returns true if this is the first record in the log.
    pub fn is_genesis(&self) -> bool {
        self.offset == Offset::ZERO && self.prev_hash.is_genesis()
    }
}

// ============================================================================
// Projection Tracking - Copy (small struct for projections)
// ============================================================================

/// Tracks which log entry a projection row was derived from.
///
/// Projections embed this in each row to enable:
/// - Point-in-time queries (find rows at a specific offset)
/// - Verification without walking the hash chain (hash provides direct check)
/// - Audit trails (know exactly which event created/updated a row)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppliedIndex {
    /// The log offset this row was derived from.
    pub offset: Offset,
    /// The hash at this offset for direct verification.
    pub hash: Hash,
}

impl AppliedIndex {
    /// Creates a new applied index.
    pub fn new(offset: Offset, hash: Hash) -> Self {
        Self { offset, hash }
    }

    /// Creates the initial applied index (before any records).
    pub fn genesis() -> Self {
        Self {
            offset: Offset::ZERO,
            hash: Hash::GENESIS,
        }
    }
}

impl Default for AppliedIndex {
    fn default() -> Self {
        Self::genesis()
    }
}

// ============================================================================
// Checkpoints - Copy (verification anchors in the log)
// ============================================================================

/// A periodic verification checkpoint stored in the log.
///
/// Checkpoints are records IN the log (not separate files), which means:
/// - They are part of the hash chain (tamper-evident)
/// - Checkpoint history is immutable
/// - Single source of truth
///
/// Checkpoints enable efficient verified reads by providing trusted
/// anchor points, reducing verification from O(n) to O(k) where k is
/// the distance to the nearest checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Log position of this checkpoint record.
    pub offset: Offset,
    /// Cumulative hash of the chain at this point.
    pub chain_hash: Hash,
    /// Total number of records from genesis to this checkpoint.
    pub record_count: u64,
    /// When this checkpoint was created.
    pub created_at: Timestamp,
}

impl Checkpoint {
    /// Creates a new checkpoint.
    ///
    /// # Preconditions
    ///
    /// - `record_count` should equal `offset.as_u64() + 1` (0-indexed offset)
    pub fn new(offset: Offset, chain_hash: Hash, record_count: u64, created_at: Timestamp) -> Self {
        debug_assert_eq!(
            record_count,
            offset.as_u64() + 1,
            "record_count should equal offset + 1"
        );
        Self {
            offset,
            chain_hash,
            record_count,
            created_at,
        }
    }
}

/// Policy for when to create checkpoints.
///
/// Checkpoints bound the worst-case verification cost. The default policy
/// creates a checkpoint every 1000 records and on graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointPolicy {
    /// Create a checkpoint every N records. Set to 0 to disable.
    pub every_n_records: u64,
    /// Create a checkpoint on graceful shutdown.
    pub on_shutdown: bool,
    /// If true, disable automatic checkpoints (only explicit calls).
    pub explicit_only: bool,
}

impl CheckpointPolicy {
    /// Creates a policy that checkpoints every N records.
    pub fn every(n: u64) -> Self {
        Self {
            every_n_records: n,
            on_shutdown: true,
            explicit_only: false,
        }
    }

    /// Creates a policy that only creates explicit checkpoints.
    pub fn explicit_only() -> Self {
        Self {
            every_n_records: 0,
            on_shutdown: false,
            explicit_only: true,
        }
    }

    /// Returns true if a checkpoint should be created at this offset.
    pub fn should_checkpoint(&self, offset: Offset) -> bool {
        if self.explicit_only {
            return false;
        }
        if self.every_n_records == 0 {
            return false;
        }
        // Checkpoint at offsets that are multiples of every_n_records
        // (offset 999 for every_n_records=1000, etc.)
        (offset.as_u64() + 1) % self.every_n_records == 0
    }
}

impl Default for CheckpointPolicy {
    /// Default policy: checkpoint every 1000 records, on shutdown.
    fn default() -> Self {
        Self {
            every_n_records: 1000,
            on_shutdown: true,
            explicit_only: false,
        }
    }
}

// ============================================================================
// Idempotency - Copy (16-byte identifier for duplicate prevention)
// ============================================================================

/// Length of idempotency IDs in bytes.
pub const IDEMPOTENCY_ID_LENGTH: usize = 16;

/// Unique identifier for duplicate transaction prevention.
///
/// Clients generate an `IdempotencyId` before their first attempt at a
/// transaction. If the transaction needs to be retried (e.g., network
/// timeout), the client reuses the same ID. The server tracks committed
/// IDs to return the same result for duplicate requests.
///
/// Inspired by `FoundationDB`'s idempotency key design.
///
/// # FCIS Pattern
///
/// This type follows the Functional Core / Imperative Shell pattern:
/// - `from_bytes()`: Pure restoration from storage
/// - `from_random_bytes()`: Pure construction from bytes (`pub(crate)`)
/// - `generate()`: Impure shell that invokes CSPRNG
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdempotencyId([u8; IDEMPOTENCY_ID_LENGTH]);

impl IdempotencyId {
    // ========================================================================
    // Functional Core (pure, testable)
    // ========================================================================

    /// Pure construction from random bytes.
    ///
    /// Restricted to `pub(crate)` to prevent misuse with weak random sources.
    /// External callers should use `generate()` or `from_bytes()`.
    pub(crate) fn from_random_bytes(bytes: [u8; IDEMPOTENCY_ID_LENGTH]) -> Self {
        debug_assert!(
            bytes.iter().any(|&b| b != 0),
            "idempotency ID bytes are all zeros"
        );
        Self(bytes)
    }

    /// Restoration from stored bytes (pure).
    ///
    /// Use this when loading an `IdempotencyId` from storage or wire protocol.
    pub fn from_bytes(bytes: [u8; IDEMPOTENCY_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the ID as a byte slice.
    pub fn as_bytes(&self) -> &[u8; IDEMPOTENCY_ID_LENGTH] {
        &self.0
    }

    // ========================================================================
    // Imperative Shell (IO boundary)
    // ========================================================================

    /// Generates a new random idempotency ID using the OS CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG fails, which indicates a catastrophic
    /// system error (e.g., no entropy source available).
    pub fn generate() -> Self {
        let mut bytes = [0u8; IDEMPOTENCY_ID_LENGTH];
        getrandom::fill(&mut bytes).expect("CSPRNG failure is catastrophic");
        Self::from_random_bytes(bytes)
    }
}

impl Debug for IdempotencyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show full hex for debugging (IDs are meant to be logged)
        write!(f, "IdempotencyId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl Display for IdempotencyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Full hex representation
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; IDEMPOTENCY_ID_LENGTH]> for IdempotencyId {
    fn from(bytes: [u8; IDEMPOTENCY_ID_LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<IdempotencyId> for [u8; IDEMPOTENCY_ID_LENGTH] {
    fn from(id: IdempotencyId) -> Self {
        id.0
    }
}

// ============================================================================
// Recovery Tracking - Copy (generation-based recovery for compliance)
// ============================================================================

/// Monotonically increasing recovery generation.
///
/// Each recovery event creates a new generation. This provides natural
/// audit checkpoints and explicit tracking of system recovery events.
///
/// Inspired by `FoundationDB`'s generation-based recovery tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Generation(u64);

impl Generation {
    /// The initial generation (before any recovery).
    pub const INITIAL: Generation = Generation(0);

    /// Creates a generation from a raw value.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation as a u64.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the next generation (incremented by 1).
    pub fn next(&self) -> Self {
        Generation(self.0.saturating_add(1))
    }
}

impl Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gen:{}", self.0)
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl From<u64> for Generation {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Generation> for u64 {
    fn from(generation: Generation) -> Self {
        generation.0
    }
}

/// Reason why a recovery was triggered.
///
/// This is recorded in the recovery log for compliance auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryReason {
    /// Normal node restart (graceful or crash recovery).
    NodeRestart,
    /// Lost quorum and had to recover from remaining replicas.
    QuorumLoss,
    /// Detected data corruption requiring recovery.
    CorruptionDetected,
    /// Operator manually triggered recovery.
    ManualIntervention,
}

impl Display for RecoveryReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryReason::NodeRestart => write!(f, "node_restart"),
            RecoveryReason::QuorumLoss => write!(f, "quorum_loss"),
            RecoveryReason::CorruptionDetected => write!(f, "corruption_detected"),
            RecoveryReason::ManualIntervention => write!(f, "manual_intervention"),
        }
    }
}

/// Records a recovery event with explicit tracking of any data loss.
///
/// Critical for compliance: auditors can see exactly what happened during
/// recovery, including any mutations that were discarded.
///
/// Inspired by `FoundationDB`'s 9-phase recovery with explicit data loss tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    /// New generation after recovery.
    pub generation: Generation,
    /// Previous generation before recovery.
    pub previous_generation: Generation,
    /// Last known committed offset before recovery.
    pub known_committed: Offset,
    /// Offset we recovered to.
    pub recovery_point: Offset,
    /// Range of discarded prepares (if any) - EXPLICIT LOSS TRACKING.
    ///
    /// If `Some`, this range of offsets contained prepared but uncommitted
    /// mutations that were discarded during recovery. This is the critical
    /// compliance field: it explicitly documents any data loss.
    pub discarded_range: Option<Range<Offset>>,
    /// When recovery occurred.
    pub timestamp: Timestamp,
    /// Why recovery was triggered.
    pub reason: RecoveryReason,
}

impl RecoveryRecord {
    /// Creates a new recovery record.
    ///
    /// # Arguments
    ///
    /// * `generation` - The new generation after recovery
    /// * `previous_generation` - The generation before recovery
    /// * `known_committed` - Last known committed offset
    /// * `recovery_point` - The offset we recovered to
    /// * `discarded_range` - Range of discarded uncommitted prepares, if any
    /// * `timestamp` - When recovery occurred
    /// * `reason` - Why recovery was triggered
    ///
    /// # Preconditions
    ///
    /// - `generation` must be greater than `previous_generation`
    /// - `recovery_point` must be <= `known_committed`
    pub fn new(
        generation: Generation,
        previous_generation: Generation,
        known_committed: Offset,
        recovery_point: Offset,
        discarded_range: Option<Range<Offset>>,
        timestamp: Timestamp,
        reason: RecoveryReason,
    ) -> Self {
        debug_assert!(
            generation > previous_generation,
            "new generation must be greater than previous"
        );
        debug_assert!(
            recovery_point <= known_committed,
            "recovery point cannot exceed known committed"
        );

        Self {
            generation,
            previous_generation,
            known_committed,
            recovery_point,
            discarded_range,
            timestamp,
            reason,
        }
    }

    /// Returns true if any data was lost during this recovery.
    pub fn had_data_loss(&self) -> bool {
        self.discarded_range.is_some()
    }

    /// Returns the number of discarded records, if any.
    pub fn discarded_count(&self) -> u64 {
        self.discarded_range
            .as_ref()
            .map_or(0, |r| r.end.as_u64().saturating_sub(r.start.as_u64()))
    }
}

// ============================================================================
// Stream Name - Clone (contains String, but rarely cloned)
// ============================================================================

/// Human-readable name for a stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamName(String);

impl StreamName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for StreamName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for StreamName {
    fn from(name: String) -> Self {
        Self(name)
    }
}

impl From<&str> for StreamName {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl From<StreamName> for String {
    fn from(value: StreamName) -> Self {
        value.0
    }
}

// ============================================================================
// Data Classification - Copy (simple enum, no heap data)
// ============================================================================

/// Classification of data for compliance purposes.
///
/// Supports multi-framework compliance: HIPAA, GDPR, PCI DSS, SOX, ISO 27001, `FedRAMP`.
///
/// # Classification Levels (8 total)
///
/// **Healthcare (HIPAA):**
/// - `PHI`: Protected Health Information
/// - `Deidentified`: De-identified per HIPAA Safe Harbor
///
/// **Privacy (GDPR):**
/// - `PII`: Personally Identifiable Information (GDPR Article 4)
/// - `Sensitive`: Special category data (GDPR Article 9) - race, health, biometrics, etc.
///
/// **Financial (PCI DSS, SOX):**
/// - `PCI`: Payment Card Industry data (card numbers, CVV, etc.)
/// - `Financial`: Financial records subject to SOX regulations
///
/// **General:**
/// - `Confidential`: Internal business data, trade secrets
/// - `Public`: Publicly available data with no restrictions
///
/// # Framework Mappings
///
/// | Level | HIPAA | GDPR | PCI DSS | SOX | ISO 27001 | FedRAMP |
/// |-------|-------|------|---------|-----|-----------|---------|
/// | PHI | ✓ | ✓ (PII) | — | — | ✓ | ✓ |
/// | Deidentified | ✓ | — | — | — | — | — |
/// | PII | — | ✓ | — | — | ✓ | ✓ |
/// | Sensitive | — | ✓ (Art 9) | — | — | ✓ | ✓ |
/// | PCI | — | ✓ (PII) | ✓ | — | ✓ | ✓ |
/// | Financial | — | — | — | ✓ | ✓ | ✓ |
/// | Confidential | — | — | — | — | ✓ | ✓ |
/// | Public | — | — | — | — | — | — |
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DataClass {
    // ========================================================================
    // Healthcare (HIPAA)
    // ========================================================================
    /// Protected Health Information - subject to HIPAA restrictions.
    ///
    /// **Examples:** Medical records, diagnoses, lab results, prescriptions
    ///
    /// **Compliance:** HIPAA Privacy Rule, HIPAA Security Rule
    ///
    /// **Retention:** Minimum 6 years after last treatment (HIPAA § 164.530)
    PHI,

    /// Data that has been de-identified per HIPAA Safe Harbor.
    ///
    /// **Requirements:** All 18 HIPAA identifiers removed (§ 164.514(b)(2))
    ///
    /// **Examples:** Anonymized patient datasets, aggregate statistics
    ///
    /// **Compliance:** HIPAA Safe Harbor Method
    Deidentified,

    // ========================================================================
    // Privacy (GDPR)
    // ========================================================================
    /// Personally Identifiable Information (GDPR Article 4).
    ///
    /// **Examples:** Names, email addresses, IP addresses, location data
    ///
    /// **Compliance:** GDPR Articles 5-11 (lawfulness, consent, purpose limitation)
    ///
    /// **Rights:** Access, rectification, erasure, portability (GDPR Articles 15-20)
    PII,

    /// Special category data (GDPR Article 9).
    ///
    /// **Examples:** Racial/ethnic origin, political opinions, religious beliefs,
    /// trade union membership, genetic data, biometric data, health data, sex life
    ///
    /// **Compliance:** GDPR Article 9 (explicit consent required, stricter controls)
    ///
    /// **Restrictions:** Processing prohibited unless explicit exception applies
    Sensitive,

    // ========================================================================
    // Financial (PCI DSS, SOX)
    // ========================================================================
    /// Payment Card Industry data (PCI DSS).
    ///
    /// **Examples:** Credit card numbers, CVV codes, cardholder data
    ///
    /// **Compliance:** PCI DSS Requirements 1-12
    ///
    /// **Storage:** Never store CVV/CVV2/PIN after authorization
    PCI,

    /// Financial records subject to SOX regulations.
    ///
    /// **Examples:** General ledger, financial statements, audit trails
    ///
    /// **Compliance:** Sarbanes-Oxley Act § 302, § 404
    ///
    /// **Retention:** 7 years minimum (SOX § 802)
    Financial,

    // ========================================================================
    // General
    // ========================================================================
    /// Internal business data, trade secrets.
    ///
    /// **Examples:** Proprietary algorithms, business strategies, internal communications
    ///
    /// **Compliance:** ISO 27001 Annex A.8 (Asset Management)
    ///
    /// **Access:** Restricted to authorized personnel
    Confidential,

    /// Publicly available data with no restrictions.
    ///
    /// **Examples:** Public website content, press releases, published research
    ///
    /// **Compliance:** No special restrictions
    ///
    /// **Access:** Unrestricted
    Public,
}

impl Default for DataClass {
    /// Healthcare-first default: any stream created without an explicit
    /// classification is treated as PHI. This is the opinionated stance
    /// of a healthcare database — if you don't know what's in a stream,
    /// assume the worst for compliance purposes (HIPAA-restricted, 6-year
    /// retention, audit-required, encryption-required).
    ///
    /// Callers that genuinely hold non-PHI data must declare it explicitly.
    fn default() -> Self {
        Self::PHI
    }
}

// ============================================================================
// Placement - Clone (Region::Custom contains String)
// ============================================================================

/// Placement policy for a stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Placement {
    /// Data must remain within the specified region.
    Region(Region),
    /// Data can be replicated globally across all regions.
    Global,
}

/// Geographic region for data placement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Region {
    /// US East (N. Virginia) - us-east-1
    USEast1,
    /// Asia Pacific (Sydney) - ap-southeast-2
    APSoutheast2,
    /// Custom region identifier
    Custom(String),
}

impl Region {
    pub fn custom(name: impl Into<String>) -> Self {
        Self::Custom(name.into())
    }
}

impl Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Region::USEast1 => write!(f, "us-east-1"),
            Region::APSoutheast2 => write!(f, "ap-southeast-2"),
            Region::Custom(custom) => write!(f, "{custom}"),
        }
    }
}

// ============================================================================
// Stream Metadata - Clone (created once per stream, cloned rarely)
// ============================================================================

/// Metadata describing a stream's configuration and current state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamMetadata {
    pub stream_id: StreamId,
    pub stream_name: StreamName,
    pub data_class: DataClass,
    pub placement: Placement,
    pub current_offset: Offset,
}

impl StreamMetadata {
    /// Creates new stream metadata with offset initialized to 0.
    pub fn new(
        stream_id: StreamId,
        stream_name: StreamName,
        data_class: DataClass,
        placement: Placement,
    ) -> Self {
        Self {
            stream_id,
            stream_name,
            data_class,
            placement,
            current_offset: Offset::default(),
        }
    }
}

// ============================================================================
// Batch Payload - NOT Clone (contains Vec<Bytes>, move only)
// ============================================================================

/// A batch of events to append to a stream.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPayload {
    pub stream_id: StreamId,
    /// The events to append (zero-copy Bytes).
    pub events: Vec<Bytes>,
    /// Expected current offset for optimistic concurrency.
    pub expected_offset: Offset,
}

impl BatchPayload {
    pub fn new(stream_id: StreamId, events: Vec<Bytes>, expected_offset: Offset) -> Self {
        Self {
            stream_id,
            events,
            expected_offset,
        }
    }
}

// ============================================================================
// Audit Actions - Clone (for flexibility in logging)
// ============================================================================

/// Actions recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// A new stream was created.
    StreamCreated {
        stream_id: StreamId,
        stream_name: StreamName,
        data_class: DataClass,
        placement: Placement,
    },
    /// Events were appended to a stream.
    EventsAppended {
        stream_id: StreamId,
        count: u32,
        from_offset: Offset,
    },
    /// **AUDIT-2026-04 H-5** — a tenant was sealed for
    /// forensic / audit / legal-hold operations. No mutating
    /// commands (DDL, DML, AppendBatch, CreateStream) will be
    /// accepted against the tenant until an `Unseal` is applied.
    TenantSealed {
        tenant_id: TenantId,
        reason: SealReason,
    },
    /// **AUDIT-2026-04 H-5** — a previously-sealed tenant was
    /// released. Mutating commands are accepted again. Audit trail
    /// retains the seal/unseal pair as structured evidence.
    TenantUnsealed { tenant_id: TenantId },

    // ------------------------------------------------------------------------
    // v0.6.0 Tier 2 #7 — column-level masking policy lifecycle
    // ------------------------------------------------------------------------
    //
    // Every CRUD transition on a masking policy emits an audit record
    // so HIPAA § 164.312(b) audit reviews can reconstruct "who changed
    // which column's mask when". The attachment records intentionally
    // carry the table / column identifiers as strings so auditors don't
    // need a table-id lookup table to read the log.
    /// A new masking policy was declared via `CREATE MASKING POLICY`.
    MaskingPolicyCreated {
        tenant_id: TenantId,
        policy_name: String,
    },
    /// A masking policy was dropped via `DROP MASKING POLICY`.
    MaskingPolicyDropped {
        tenant_id: TenantId,
        policy_name: String,
    },
    /// A column was attached to a masking policy via
    /// `ALTER TABLE … SET MASKING POLICY`.
    MaskingPolicyAttached {
        tenant_id: TenantId,
        table_id: u64,
        column_name: String,
        policy_name: String,
    },
    /// A column's masking policy was detached via
    /// `ALTER TABLE … DROP MASKING POLICY`.
    MaskingPolicyDetached {
        tenant_id: TenantId,
        table_id: u64,
        column_name: String,
    },
    /// **v0.6.0 Tier 1 #3 — UPSERT** — an `INSERT ... ON CONFLICT`
    /// statement was applied atomically. The resolution discriminator
    /// lets compliance auditors distinguish insert-vs-update-vs-noop
    /// without re-reading the row payload.
    UpsertApplied {
        stream_id: StreamId,
        /// Which branch fired: new row inserted, existing row updated,
        /// or the conflict triggered `DO NOTHING`.
        resolution: UpsertResolution,
        /// Offset the single resulting event (if any) lives at. For
        /// `NoOp` the offset equals the pre-upsert head — no event is
        /// emitted, but we record the observed stream position so
        /// audit replays can reconstruct the exact moment the upsert
        /// was applied.
        from_offset: Offset,
    },
}

/// **v0.6.0 Tier 1 #3** — the atomic resolution of a single UPSERT.
///
/// Every `UpsertApplied` event carries exactly one of these. The
/// discriminator is a structural part of the audit payload so
/// downstream readers never have to infer intent from a dual-write
/// sequence — a property the notebar helper's UPDATE+INSERT pair
/// explicitly lacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpsertResolution {
    /// No prior row at the conflict key — the upsert appended a new row.
    Inserted,
    /// A prior row existed — `ON CONFLICT DO UPDATE SET ...` fired and
    /// the row was rewritten with the merged column set.
    Updated,
    /// A prior row existed and the clause was `DO NOTHING`. No storage
    /// mutation, no row-level audit beyond this `UpsertApplied` record.
    NoOp,
}

/// **AUDIT-2026-04 H-5** — why a tenant was sealed.
///
/// This is an enum rather than a free-form string so downstream
/// compliance reports can aggregate on specific operational
/// categories — healthcare auditors expect to see discrete reasons
/// (e.g. `ForensicHold`) not human-written prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SealReason {
    /// Forensic preservation during an incident investigation.
    ForensicHold,
    /// Audit is in progress; writes must freeze until audit completes.
    AuditInProgress,
    /// Breach investigation — preserve state for forensic analysis.
    BreachInvestigation,
    /// Legal hold (discovery / litigation-retention).
    LegalHold,
}

// ============================================================================
// Event Persistence - Trait for durable event log writes
// ============================================================================

/// Abstraction for persisting events to the durable event log.
///
/// This trait is the bridge between the projection layer and the
/// `Kimberlite` replication system. Implementations must block until
/// persistence is confirmed.
///
/// # Healthcare Compliance
///
/// This is the critical path for HIPAA compliance. The implementation must:
/// - **Block until VSR consensus** completes (quorum durability)
/// - **Return `Err`** if consensus fails (triggers rollback)
/// - **Never return `Ok`** unless events are durably stored
///
/// # Implementation Notes
///
/// The implementor (typically `Runtime`) must handle the sync→async bridge:
///
/// ```ignore
/// impl EventPersister for RuntimeHandle {
///     fn persist_blocking(&self, stream_id: StreamId, events: Vec<Bytes>) -> Result<Offset, PersistError> {
///         // Bridge sync callback to async runtime
///         tokio::task::block_in_place(|| {
///             tokio::runtime::Handle::current().block_on(async {
///                 self.inner.append(stream_id, events).await
///             })
///         })
///         .map_err(|e| {
///             tracing::error!(error = %e, "VSR persistence failed");
///             PersistError::ConsensusFailed
///         })
///     }
/// }
/// ```
///
/// # Why `Vec<Bytes>` instead of typed events?
///
/// Events are serialized before reaching this trait. This keeps `kmb-types`
/// decoupled from domain-specific event schemas.
pub trait EventPersister: Send + Sync + Debug {
    /// Persist a batch of serialized events to the durable event log.
    ///
    /// This method **blocks** until VSR consensus confirms the events are
    /// durably stored on a quorum of nodes.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to append events to
    /// * `events` - Serialized events
    ///
    /// # Returns
    ///
    /// * `Ok(offset)` - Events persisted, returns the new stream offset
    /// * `Err(PersistError)` - Persistence failed, caller should rollback
    ///
    /// # Errors
    ///
    /// * [`PersistError::ConsensusFailed`] - VSR quorum unavailable after retries
    /// * [`PersistError::StorageError`] - Disk I/O or serialization failure
    /// * [`PersistError::ShuttingDown`] - System is terminating
    fn persist_blocking(
        &self,
        stream_id: StreamId,
        events: Vec<Bytes>,
    ) -> Result<Offset, PersistError>;
}

/// Error returned when event persistence fails.
///
/// The hook uses this to decide whether to rollback the transaction.
/// Specific underlying errors are logged by the implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    /// VSR consensus failed after retries (quorum unavailable)
    ConsensusFailed,
    /// Storage I/O error
    StorageError,
    /// System is shutting down
    ShuttingDown,
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsensusFailed => write!(f, "consensus failed after retries"),
            Self::StorageError => write!(f, "storage I/O error"),
            Self::ShuttingDown => write!(f, "system is shutting down"),
        }
    }
}

impl std::error::Error for PersistError {}

// ============================================================================
// Compression - Copy (simple enum for codec selection)
// ============================================================================

/// Compression algorithm for record payloads.
///
/// Each record stores its compression kind so that records compressed with
/// different algorithms can coexist in the same segment. The `None` variant
/// means the payload is stored uncompressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum CompressionKind {
    /// No compression (default).
    #[default]
    None = 0,
    /// LZ4 compression (fast, moderate ratio).
    Lz4 = 1,
    /// Zstandard compression (slower, better ratio).
    Zstd = 2,
}

impl CompressionKind {
    /// Returns the single-byte discriminant for serialization.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Creates a `CompressionKind` from its byte discriminant.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd),
            _ => None,
        }
    }
}

impl Display for CompressionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Lz4 => write!(f, "lz4"),
            Self::Zstd => write!(f, "zstd"),
        }
    }
}

/// Flux refinement type annotations (experimental)
///
/// These annotations provide compile-time verification when Flux compiler is enabled.
/// Currently commented out as Flux is experimental, but documents intended properties.
pub mod flux_annotations;

/// Typed-domain primitives for making illegal states unrepresentable.
///
/// Introduced by the fuzz-to-types hardening effort (see
/// `docs-internal/contributing/constructor-audit-2026-04.md`). Re-exports
/// [`NonEmptyVec`](domain::NonEmptyVec), [`SqlIdentifier`](domain::SqlIdentifier),
/// [`BoundedSize`](domain::BoundedSize), and [`ClearanceLevel`](domain::ClearanceLevel).
pub mod domain;

pub use domain::{
    AGGREGATE_BUDGET_DEFAULT_BYTES, AGGREGATE_BUDGET_MIN_BYTES, AggregateMemoryBudget,
    AggregateMemoryBudgetError, BoundedSize, BoundedSizeError, ClearanceLevel, ClearanceLevelError,
    DateField, DateFieldParseError, EmptyVecError, Interval, IntervalConstructionError,
    NANOS_PER_DAY, NegativeSubstringLength, NonEmptyVec, SqlIdentifier, SqlIdentifierError,
    SubstringRange,
};

#[cfg(test)]
mod tests;
