//! VSR protocol messages.
//!
//! This module defines all messages used in the Viewstamped Replication protocol:
//!
//! ## Normal Operation
//! - [`Prepare`] - Leader → Backup: Replicate this operation
//! - [`PrepareOk`] - Backup → Leader: I've persisted the operation
//! - [`Commit`] - Leader → Backup: Operations up to this point are committed
//! - [`Heartbeat`] - Leader → Backup: I'm still alive
//!
//! ## View Change
//! - [`StartViewChange`] - Backup → All: I think the leader is dead
//! - [`DoViewChange`] - Backup → New Leader: Here's my state for the new view
//! - [`StartView`] - New Leader → All: New view is starting
//!
//! ## Recovery & Repair
//! - [`RecoveryRequest`] - Recovering → All: I need to recover
//! - [`RecoveryResponse`] - Healthy → Recovering: Here's recovery info
//! - [`RepairRequest`] - Replica → All: I need specific log entries
//! - [`RepairResponse`] - Replica → Requester: Here are the entries
//! - [`Nack`] - Replica → Requester: I don't have what you asked for
//! - [`StateTransferRequest`] - Replica → All: I need a checkpoint
//! - [`StateTransferResponse`] - Replica → Requester: Here's a checkpoint

use kimberlite_types::Hash;
use serde::{Deserialize, Serialize};

use crate::types::{CommitNumber, LogEntry, Nonce, OpNumber, ReplicaId, ViewNumber};

// ============================================================================
// Message Envelope
// ============================================================================

/// A VSR protocol message with routing information.
///
/// All messages are wrapped in this envelope which provides the sender's
/// identity. The receiver uses this for routing responses and validation.
///
/// **Security (AUDIT-2026-03 M-3):** All messages carry Ed25519 signatures
/// for Byzantine fault tolerance defense-in-depth. Signatures are verified
/// at receive boundaries before processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// The replica that sent this message.
    pub from: ReplicaId,

    /// The intended recipient (if targeted).
    ///
    /// `None` for broadcast messages.
    pub to: Option<ReplicaId>,

    /// The message payload.
    pub payload: MessagePayload,

    /// Ed25519 signature over the canonical serialization of (from, to, payload).
    ///
    /// **Security:** Protects against message tampering, replay attacks, and
    /// Byzantine replicas forging messages. Signature verification is mandatory
    /// at all receive boundaries.
    ///
    /// **Serialization:** Excluded from the signed content (signatures don't sign themselves).
    /// Canonical serialization uses `postcard` for determinism.
    pub signature: Option<Vec<u8>>,
}

impl Message {
    /// Creates a new targeted message (unsigned).
    ///
    /// **Security:** Unsigned messages are only used for testing. Production
    /// code must call `.sign()` before sending.
    pub fn targeted(from: ReplicaId, to: ReplicaId, payload: MessagePayload) -> Self {
        Self {
            from,
            to: Some(to),
            payload,
            signature: None,
        }
    }

    /// Creates a new broadcast message (unsigned).
    ///
    /// **Security:** Unsigned messages are only used for testing. Production
    /// code must call `.sign()` before sending.
    pub fn broadcast(from: ReplicaId, payload: MessagePayload) -> Self {
        Self {
            from,
            to: None,
            payload,
            signature: None,
        }
    }

    /// Returns true if this message is a broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }

    /// Returns true if this message is targeted at a specific replica.
    pub fn is_targeted(&self) -> bool {
        self.to.is_some()
    }

    /// Returns true if this message is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Signs this message with the given signing key.
    ///
    /// **Security (AUDIT-2026-03 M-3):** All messages sent over the network
    /// must be signed. This provides Byzantine fault tolerance defense-in-depth
    /// by preventing message tampering and forgery.
    ///
    /// **Serialization:** Uses `postcard` for canonical, deterministic serialization.
    /// Signature is computed over (from, to, payload) tuple.
    ///
    /// # Example
    /// ```ignore
    /// use kimberlite_crypto::verified::VerifiedSigningKey;
    /// use kimberlite_vsr::message::{Message, MessagePayload, Heartbeat};
    /// use kimberlite_vsr::types::{ReplicaId, ViewNumber, CommitNumber};
    ///
    /// let signing_key = VerifiedSigningKey::generate();
    /// let msg = Message::broadcast(
    ///     ReplicaId::new(0),
    ///     MessagePayload::Heartbeat(Heartbeat::without_clock(ViewNumber::new(0), CommitNumber::ZERO))
    /// );
    /// let signed_msg = msg.sign(&signing_key);
    /// assert!(signed_msg.is_signed());
    /// ```
    pub fn sign(mut self, signing_key: &kimberlite_crypto::verified::VerifiedSigningKey) -> Self {
        // Ensure signature field is None before signing (signatures don't sign themselves)
        self.signature = None;

        // Canonical serialization of (from, to, payload)
        let to_sign = (&self.from, &self.to, &self.payload);
        let serialized = postcard::to_allocvec(&to_sign)
            .expect("Message serialization should never fail (all fields are serializable)");

        // Sign the canonical bytes
        let signature = signing_key.sign(&serialized);
        self.signature = Some(signature.to_bytes().to_vec());

        self
    }

    /// Verifies the signature on this message.
    ///
    /// **Security (AUDIT-2026-03 M-3):** All received messages must be verified
    /// before processing. This prevents Byzantine replicas from tampering with
    /// messages or forging messages from other replicas.
    ///
    /// **Returns:** `Ok(())` if signature is valid, `Err(reason)` otherwise.
    ///
    /// # Example
    /// ```ignore
    /// let signed_msg = msg.sign(&signing_key);
    /// let verifying_key = signing_key.verifying_key();
    /// assert!(signed_msg.verify(&verifying_key).is_ok());
    /// ```
    pub fn verify(
        &self,
        verifying_key: &kimberlite_crypto::verified::VerifiedVerifyingKey,
    ) -> Result<(), String> {
        // Check that message is signed
        let signature_bytes = self
            .signature
            .as_ref()
            .ok_or_else(|| "Message has no signature".to_string())?;

        // Convert signature bytes to VerifiedSignature
        if signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            ));
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature_bytes);
        let signature = kimberlite_crypto::verified::VerifiedSignature::from_bytes(&sig_array);

        // Canonical serialization of (from, to, payload) - must match signing order
        let to_verify = (&self.from, &self.to, &self.payload);
        let serialized = postcard::to_allocvec(&to_verify)
            .expect("Message serialization should never fail (all fields are serializable)");

        // Verify signature
        verifying_key.verify(&serialized, &signature)
    }
}

// ============================================================================
// Message Payload
// ============================================================================

/// The payload of a VSR protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagePayload {
    // === Transport Handshake ===
    /// Dialer → Acceptor: First frame on every freshly-opened TCP
    /// connection. Identifies the sender and proves shared cluster
    /// membership via `cluster_hash`.
    ///
    /// Handled entirely at the transport layer (`TcpTransport`); the
    /// replica state machine never observes a `Hello`. Sent unsigned —
    /// the cluster_hash provides the "you must know our membership"
    /// gate, and per-message signing on subsequent frames provides the
    /// per-replica authenticity guarantee. A future hardening step is
    /// to also sign the Hello with the dialer's VSR key (gated on
    /// transport-side key access).
    Hello(Hello),

    // === Normal Operation ===
    /// Leader → Backup: Replicate this operation.
    Prepare(Prepare),

    /// Backup → Leader: I've persisted the operation.
    PrepareOk(PrepareOk),

    /// Leader → Backup: Operations up to this point are committed.
    Commit(Commit),

    /// Leader → Backup: I'm still alive (no new operations).
    Heartbeat(Heartbeat),

    // === View Change ===
    /// Backup → All: I think the leader is dead.
    StartViewChange(StartViewChange),

    /// Backup → New Leader: Here's my state for the new view.
    DoViewChange(DoViewChange),

    /// New Leader → All: New view is starting.
    StartView(StartView),

    // === Recovery ===
    /// Recovering → All: I need to recover.
    RecoveryRequest(RecoveryRequest),

    /// Healthy → Recovering: Here's recovery info.
    RecoveryResponse(RecoveryResponse),

    // === Repair ===
    /// Replica → All: I need specific log entries.
    RepairRequest(RepairRequest),

    /// Replica → Requester: Here are the entries.
    RepairResponse(RepairResponse),

    /// Replica → Requester: I don't have what you asked for.
    Nack(Nack),

    // === State Transfer ===
    /// Replica → All: I need a checkpoint.
    StateTransferRequest(StateTransferRequest),

    /// Replica → Requester: Here's a checkpoint.
    StateTransferResponse(StateTransferResponse),

    // === Write Reorder Repair ===
    /// Backup → Leader: Fill gaps caused by write reordering.
    WriteReorderGapRequest(WriteReorderGapRequest),

    /// Leader → Backup: Entries to fill reorder gaps.
    WriteReorderGapResponse(WriteReorderGapResponse),
}

impl MessagePayload {
    /// Returns the view number associated with this message, if any.
    pub fn view(&self) -> Option<ViewNumber> {
        match self {
            MessagePayload::Prepare(m) => Some(m.view),
            MessagePayload::PrepareOk(m) => Some(m.view),
            MessagePayload::Commit(m) => Some(m.view),
            MessagePayload::Heartbeat(m) => Some(m.view),
            MessagePayload::StartViewChange(m) => Some(m.view),
            MessagePayload::DoViewChange(m) => Some(m.view),
            MessagePayload::StartView(m) => Some(m.view),
            MessagePayload::RecoveryResponse(m) => Some(m.view),
            MessagePayload::StateTransferResponse(m) => Some(m.checkpoint_view),
            // Messages without view context
            MessagePayload::Hello(_)
            | MessagePayload::RecoveryRequest(_)
            | MessagePayload::RepairRequest(_)
            | MessagePayload::RepairResponse(_)
            | MessagePayload::Nack(_)
            | MessagePayload::StateTransferRequest(_)
            | MessagePayload::WriteReorderGapRequest(_)
            | MessagePayload::WriteReorderGapResponse(_) => None,
        }
    }

    /// Returns a human-readable name for the message type.
    pub fn name(&self) -> &'static str {
        match self {
            MessagePayload::Hello(_) => "Hello",
            MessagePayload::Prepare(_) => "Prepare",
            MessagePayload::PrepareOk(_) => "PrepareOk",
            MessagePayload::Commit(_) => "Commit",
            MessagePayload::Heartbeat(_) => "Heartbeat",
            MessagePayload::StartViewChange(_) => "StartViewChange",
            MessagePayload::DoViewChange(_) => "DoViewChange",
            MessagePayload::StartView(_) => "StartView",
            MessagePayload::RecoveryRequest(_) => "RecoveryRequest",
            MessagePayload::RecoveryResponse(_) => "RecoveryResponse",
            MessagePayload::RepairRequest(_) => "RepairRequest",
            MessagePayload::RepairResponse(_) => "RepairResponse",
            MessagePayload::Nack(_) => "Nack",
            MessagePayload::StateTransferRequest(_) => "StateTransferRequest",
            MessagePayload::StateTransferResponse(_) => "StateTransferResponse",
            MessagePayload::WriteReorderGapRequest(_) => "WriteReorderGapRequest",
            MessagePayload::WriteReorderGapResponse(_) => "WriteReorderGapResponse",
        }
    }
}

// ============================================================================
// Transport Handshake
// ============================================================================

/// Per-connection identity claim sent as the first frame on every
/// freshly-opened TCP connection.
///
/// `cluster_hash` is the BLAKE3-derived membership hash of the dialer's
/// `ClusterAddresses` (`tcp_transport::ClusterAddresses::membership_hash`).
/// Acceptors compare it with their own; mismatched hashes mean the
/// connection misrouted (different cluster, dev/prod mix-up, scrambled
/// config) and the acceptor drops without binding. Matching hashes bind
/// the inbound socket's mio `Token` to `sender_id` so subsequent frames
/// can be authenticated against a transport-verified identity rather
/// than a spoofable `from` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The dialer's replica id.
    pub sender_id: ReplicaId,
    /// BLAKE3 membership hash; see [`tcp_transport::ClusterAddresses::membership_hash`].
    pub cluster_hash: u64,
}

// ============================================================================
// Normal Operation Messages
// ============================================================================

/// Leader → Backup: Replicate this operation.
///
/// The leader sends Prepare messages to all backups for each client request.
/// Backups must persist the operation before responding with `PrepareOk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prepare {
    /// Current view number.
    pub view: ViewNumber,

    /// Operation number being prepared.
    pub op_number: OpNumber,

    /// The log entry to replicate.
    pub entry: LogEntry,

    /// Current commit number.
    ///
    /// Backups use this to learn about commits they may have missed.
    pub commit_number: CommitNumber,

    /// Optional reconfiguration command.
    ///
    /// When present, this Prepare proposes a cluster reconfiguration.
    /// The leader initiates joint consensus (`C_old,new`) and the cluster
    /// requires quorum in BOTH old and new configurations.
    ///
    /// Once this operation is committed, the cluster transitions to `C_new`.
    pub reconfig: Option<crate::reconfiguration::ReconfigCommand>,
}

impl Prepare {
    /// Creates a new Prepare message.
    pub fn new(
        view: ViewNumber,
        op_number: OpNumber,
        entry: LogEntry,
        commit_number: CommitNumber,
    ) -> Self {
        assert_eq!(
            entry.op_number,
            op_number,
            "entry op_number must match message op_number: entry={}, message={}",
            entry.op_number.as_u64(),
            op_number.as_u64()
        );
        assert_eq!(
            entry.view,
            view,
            "entry view must match message view: entry={}, message={}",
            entry.view.as_u64(),
            view.as_u64()
        );

        Self {
            view,
            op_number,
            entry,
            commit_number,
            reconfig: None,
        }
    }

    /// Creates a new Prepare message with a reconfiguration command.
    ///
    /// This initiates joint consensus for cluster reconfiguration.
    pub fn new_with_reconfig(
        view: ViewNumber,
        op_number: OpNumber,
        entry: LogEntry,
        commit_number: CommitNumber,
        reconfig: crate::reconfiguration::ReconfigCommand,
    ) -> Self {
        assert_eq!(
            entry.op_number, op_number,
            "entry op_number must match message op_number"
        );
        assert_eq!(entry.view, view, "entry view must match message view");

        Self {
            view,
            op_number,
            entry,
            commit_number,
            reconfig: Some(reconfig),
        }
    }
}

/// Backup → Leader: I've persisted the operation.
///
/// Backups send `PrepareOk` after durably storing the operation. The leader
/// commits the operation after receiving `PrepareOk` from a quorum.
///
/// `PrepareOk` also carries clock samples from the backup, enabling the leader
/// to collect timing information from all replicas for clock synchronization.
///
/// `PrepareOk` also announces the sender's software version for rolling upgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareOk {
    /// Current view number.
    pub view: ViewNumber,

    /// Operation number being acknowledged.
    pub op_number: OpNumber,

    /// Replica sending the `PrepareOk`.
    pub replica: ReplicaId,

    /// Backup's wall clock timestamp when sending this response (nanoseconds since UNIX epoch).
    ///
    /// Leader uses this along with the round-trip time to calculate clock offset
    /// between leader and backup clocks.
    pub wall_clock_timestamp: i64,

    /// Sender's software version.
    ///
    /// Used for rolling upgrades. Leader tracks all replica versions
    /// and operates at the minimum version to ensure backward compatibility.
    pub version: crate::upgrade::VersionInfo,
}

impl PrepareOk {
    /// Creates a new `PrepareOk` message with clock sample and version.
    ///
    /// # Arguments
    ///
    /// * `view` - Current view number
    /// * `op_number` - Operation being acknowledged
    /// * `replica` - Backup replica ID
    /// * `wall_clock_timestamp` - Backup's wall clock time (for clock sync)
    /// * `version` - Sender's software version (for rolling upgrades)
    pub fn new(
        view: ViewNumber,
        op_number: OpNumber,
        replica: ReplicaId,
        wall_clock_timestamp: i64,
        version: crate::upgrade::VersionInfo,
    ) -> Self {
        Self {
            view,
            op_number,
            replica,
            wall_clock_timestamp,
            version,
        }
    }

    /// Creates a `PrepareOk` without clock sample (for testing).
    ///
    /// Uses zero timestamp and default version. Production code should use `new()`.
    #[cfg(test)]
    pub fn without_clock(view: ViewNumber, op_number: OpNumber, replica: ReplicaId) -> Self {
        Self::new(
            view,
            op_number,
            replica,
            0,
            crate::upgrade::VersionInfo::V0_4_0,
        )
    }
}

///// Leader → Backup: Operations up to this point are committed.
///
/// The leader sends Commit messages to inform backups of newly committed
/// operations. This is often piggybacked on Prepare messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Current view number.
    pub view: ViewNumber,

    /// New commit number.
    pub commit_number: CommitNumber,
}

impl Commit {
    /// Creates a new Commit message.
    pub fn new(view: ViewNumber, commit_number: CommitNumber) -> Self {
        Self {
            view,
            commit_number,
        }
    }
}

///// Leader → Backup: I'm still alive.
///
/// The leader sends periodic heartbeats to maintain its leadership.
/// If backups don't receive heartbeats, they initiate view change.
///
/// Heartbeats also carry clock samples for cluster-wide time synchronization.
/// Backups measure round-trip time and reply with their own clock samples
/// in `PrepareOk` messages.
///
/// Heartbeats also announce the sender's software version for rolling upgrades.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Current view number.
    pub view: ViewNumber,

    /// Current commit number.
    pub commit_number: CommitNumber,

    /// Leader's monotonic timestamp when sending heartbeat (nanoseconds).
    ///
    /// Used by backup to calculate round-trip time (RTT) when it receives
    /// a response. This enables clock synchronization by measuring network delay.
    pub monotonic_timestamp: u128,

    /// Leader's wall clock timestamp when sending heartbeat (nanoseconds since UNIX epoch).
    ///
    /// Combined with RTT measurement, backups can estimate clock offset between
    /// their clock and the leader's clock.
    pub wall_clock_timestamp: i64,

    /// Sender's software version.
    ///
    /// Used for rolling upgrades. Replicas track all versions in the cluster
    /// and operate at the minimum version to ensure backward compatibility.
    pub version: crate::upgrade::VersionInfo,
}

impl Heartbeat {
    /// Creates a new Heartbeat message with clock samples and version.
    ///
    /// # Arguments
    ///
    /// * `view` - Current view number
    /// * `commit_number` - Current commit number
    /// * `monotonic_timestamp` - Sender's monotonic time (for RTT measurement)
    /// * `wall_clock_timestamp` - Sender's wall clock time (for offset calculation)
    /// * `version` - Sender's software version (for rolling upgrades)
    pub fn new(
        view: ViewNumber,
        commit_number: CommitNumber,
        monotonic_timestamp: u128,
        wall_clock_timestamp: i64,
        version: crate::upgrade::VersionInfo,
    ) -> Self {
        Self {
            view,
            commit_number,
            monotonic_timestamp,
            wall_clock_timestamp,
            version,
        }
    }

    /// Creates a Heartbeat without clock samples (for testing).
    ///
    /// Uses zero timestamps and default version. Production code should use `new()`.
    #[cfg(test)]
    pub fn without_clock(view: ViewNumber, commit_number: CommitNumber) -> Self {
        Self::new(
            view,
            commit_number,
            0,
            0,
            crate::upgrade::VersionInfo::V0_4_0,
        )
    }
}

// ============================================================================
// View Change Messages
// ============================================================================

///// Backup → All: I think the leader is dead.
///
/// A backup sends `StartViewChange` when it suspects the leader has failed
/// (e.g., heartbeat timeout). View change proceeds if a quorum agrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartViewChange {
    /// The new view number being proposed.
    pub view: ViewNumber,

    /// Replica initiating the view change.
    pub replica: ReplicaId,
}

impl StartViewChange {
    /// Creates a new `StartViewChange` message.
    pub fn new(view: ViewNumber, replica: ReplicaId) -> Self {
        Self { view, replica }
    }
}

/// Backup → New Leader: Here's my state for the new view.
///
/// After receiving enough `StartViewChange` messages, a backup sends
/// `DoViewChange` to the new leader with its log state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoViewChange {
    /// The new view number.
    pub view: ViewNumber,

    /// Replica sending its state.
    pub replica: ReplicaId,

    /// The last normal view this replica participated in.
    ///
    /// Used to determine which replica has the most up-to-date log.
    pub last_normal_view: ViewNumber,

    /// Highest operation number in this replica's log.
    pub op_number: OpNumber,

    /// Highest committed operation number known to this replica.
    pub commit_number: CommitNumber,

    /// Log entries from `commit_number+1` to `op_number`.
    ///
    /// The new leader uses these to reconstruct the log.
    pub log_tail: Vec<LogEntry>,

    /// BLAKE3 hash over the serialized `log_tail` entries.
    ///
    /// **Security (AUDIT-2026-03 4.4):** The new leader validates this hash
    /// against the received `log_tail` before accepting the message. This
    /// provides integrity proof and defends against log corruption in transit
    /// and Byzantine replicas sending tampered log entries.
    pub log_tail_hash: Hash,

    /// Current reconfiguration state.
    ///
    /// Preserved across view changes to ensure reconfigurations survive
    /// leader failures. The new leader inherits this state and continues
    /// the reconfiguration.
    pub reconfig_state: Option<crate::reconfiguration::ReconfigState>,
}

impl DoViewChange {
    /// Creates a new `DoViewChange` message.
    ///
    /// Automatically computes `log_tail_hash` (BLAKE3) from the provided entries.
    pub fn new(
        view: ViewNumber,
        replica: ReplicaId,
        last_normal_view: ViewNumber,
        op_number: OpNumber,
        commit_number: CommitNumber,
        log_tail: Vec<LogEntry>,
    ) -> Self {
        let log_tail_hash = log_tail_hash_of(&log_tail);
        Self {
            view,
            replica,
            last_normal_view,
            op_number,
            commit_number,
            log_tail_hash,
            log_tail,
            reconfig_state: None,
        }
    }

    /// Creates a new `DoViewChange` message with reconfiguration state.
    ///
    /// Automatically computes `log_tail_hash` (BLAKE3) from the provided entries.
    pub fn new_with_reconfig(
        view: ViewNumber,
        replica: ReplicaId,
        last_normal_view: ViewNumber,
        op_number: OpNumber,
        commit_number: CommitNumber,
        log_tail: Vec<LogEntry>,
        reconfig_state: crate::reconfiguration::ReconfigState,
    ) -> Self {
        let log_tail_hash = log_tail_hash_of(&log_tail);
        Self {
            view,
            replica,
            last_normal_view,
            op_number,
            commit_number,
            log_tail_hash,
            log_tail,
            reconfig_state: Some(reconfig_state),
        }
    }
}

/// New Leader → All: New view is starting.
///
/// The new leader sends `StartView` after collecting `DoViewChange` messages
/// from a quorum and reconstructing the authoritative log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartView {
    /// The new view number.
    pub view: ViewNumber,

    /// Highest operation number in the new view.
    pub op_number: OpNumber,

    /// Highest committed operation number.
    pub commit_number: CommitNumber,

    /// Log entries that backups may be missing.
    ///
    /// Contains entries from `commit_number+1` to `op_number`.
    pub log_tail: Vec<LogEntry>,

    /// BLAKE3 hash over the serialized `log_tail` entries.
    ///
    /// **Security (AUDIT-2026-03 4.4):** Backups validate this hash against
    /// the received `log_tail` before accepting the new view. This provides
    /// integrity proof and defends against log corruption in transit and
    /// Byzantine leaders sending tampered log entries.
    pub log_tail_hash: Hash,

    /// Current reconfiguration state.
    ///
    /// Restored across view changes to ensure reconfigurations survive
    /// leader failures. Backups adopt this state when entering the new view.
    pub reconfig_state: Option<crate::reconfiguration::ReconfigState>,
}

impl StartView {
    /// Creates a new `StartView` message.
    ///
    /// Automatically computes `log_tail_hash` (BLAKE3) from the provided entries.
    pub fn new(
        view: ViewNumber,
        op_number: OpNumber,
        commit_number: CommitNumber,
        log_tail: Vec<LogEntry>,
    ) -> Self {
        let log_tail_hash = log_tail_hash_of(&log_tail);
        Self {
            view,
            op_number,
            commit_number,
            log_tail_hash,
            log_tail,
            reconfig_state: None,
        }
    }

    /// Creates a new `StartView` message with reconfiguration state.
    ///
    /// Automatically computes `log_tail_hash` (BLAKE3) from the provided entries.
    pub fn new_with_reconfig(
        view: ViewNumber,
        op_number: OpNumber,
        commit_number: CommitNumber,
        log_tail: Vec<LogEntry>,
        reconfig_state: crate::reconfiguration::ReconfigState,
    ) -> Self {
        let log_tail_hash = log_tail_hash_of(&log_tail);
        Self {
            view,
            op_number,
            commit_number,
            log_tail_hash,
            log_tail,
            reconfig_state: Some(reconfig_state),
        }
    }
}

// ============================================================================
// Log Tail Integrity Hash
// ============================================================================

/// Computes a BLAKE3 integrity hash over a log tail's serialized entries.
///
/// **Security (AUDIT-2026-03 4.4):** Used to verify that `log_tail` contents
/// in `DoViewChange` and `StartView` messages have not been tampered with in
/// transit. Computed by the sender and validated by the receiver before
/// accepting the message.
pub(crate) fn log_tail_hash_of(log_tail: &[LogEntry]) -> Hash {
    let serialized = postcard::to_allocvec(log_tail)
        .expect("LogEntry serialization should never fail (all fields implement Serialize)");
    let internal = kimberlite_crypto::internal_hash(&serialized);
    Hash::from_bytes(*internal.as_bytes())
}

// ============================================================================
// Recovery Messages
// ============================================================================

/// Recovering → All: I need to recover.
///
/// A replica sends `RecoveryRequest` after restarting when it needs to
/// recover its state from other replicas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Replica requesting recovery.
    pub replica: ReplicaId,

    /// Random nonce to match responses to this request.
    pub nonce: Nonce,

    /// Last known operation number before crash.
    ///
    /// Helps other replicas determine how much state to send.
    pub known_op_number: OpNumber,
}

impl RecoveryRequest {
    /// Creates a new `RecoveryRequest` message.
    pub fn new(replica: ReplicaId, nonce: Nonce, known_op_number: OpNumber) -> Self {
        Self {
            replica,
            nonce,
            known_op_number,
        }
    }
}

/// Healthy → Recovering: Here's recovery info.
///
/// Healthy replicas respond to `RecoveryRequest` with their current state.
/// The recovering replica uses responses from a quorum to recover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryResponse {
    /// Current view number.
    pub view: ViewNumber,

    /// Replica sending the response.
    pub replica: ReplicaId,

    /// Nonce from the request (for matching).
    pub nonce: Nonce,

    /// Highest operation number.
    pub op_number: OpNumber,

    /// Highest committed operation number.
    pub commit_number: CommitNumber,

    /// Log entries the recovering replica may need.
    ///
    /// Only includes entries after the request's `known_op_number`.
    pub log_suffix: Vec<LogEntry>,
}

impl RecoveryResponse {
    /// Creates a new `RecoveryResponse` message.
    pub fn new(
        view: ViewNumber,
        replica: ReplicaId,
        nonce: Nonce,
        op_number: OpNumber,
        commit_number: CommitNumber,
        log_suffix: Vec<LogEntry>,
    ) -> Self {
        Self {
            view,
            replica,
            nonce,
            op_number,
            commit_number,
            log_suffix,
        }
    }
}

// ============================================================================
// Repair Messages
// ============================================================================

/// Replica → All: I need specific log entries.
///
/// A replica sends `RepairRequest` when it detects missing or corrupt
/// entries in its log. This enables transparent repair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRequest {
    /// Replica requesting repair.
    pub replica: ReplicaId,

    /// Random nonce to match responses.
    pub nonce: Nonce,

    /// Range of operation numbers needed (inclusive start, exclusive end).
    pub op_range_start: OpNumber,
    pub op_range_end: OpNumber,
}

impl RepairRequest {
    /// Creates a new `RepairRequest` message.
    pub fn new(
        replica: ReplicaId,
        nonce: Nonce,
        op_range_start: OpNumber,
        op_range_end: OpNumber,
    ) -> Self {
        debug_assert!(
            op_range_start < op_range_end,
            "repair range must be non-empty"
        );
        Self {
            replica,
            nonce,
            op_range_start,
            op_range_end,
        }
    }

    /// Returns the number of operations requested.
    pub fn count(&self) -> u64 {
        self.op_range_end.as_u64() - self.op_range_start.as_u64()
    }
}

/// Replica → Requester: Here are the entries.
///
/// A replica responds to `RepairRequest` with the requested log entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairResponse {
    /// Replica sending the response.
    pub replica: ReplicaId,

    /// Nonce from the request (for matching).
    pub nonce: Nonce,

    /// The requested log entries.
    pub entries: Vec<LogEntry>,
}

impl RepairResponse {
    /// Creates a new `RepairResponse` message.
    pub fn new(replica: ReplicaId, nonce: Nonce, entries: Vec<LogEntry>) -> Self {
        Self {
            replica,
            nonce,
            entries,
        }
    }
}

/// Replica → Requester: I don't have what you asked for.
///
/// A replica sends Nack when it cannot fulfill a `RepairRequest`. This is
/// critical for PAR (Protocol-Aware Recovery) to safely truncate the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nack {
    /// Replica sending the nack.
    pub replica: ReplicaId,

    /// Nonce from the request (for matching).
    pub nonce: Nonce,

    /// The reason for the nack.
    pub reason: NackReason,

    /// Highest operation this replica has seen.
    ///
    /// Helps distinguish "not seen" from "seen but lost".
    pub highest_seen: OpNumber,
}

impl Nack {
    /// Creates a new Nack message.
    pub fn new(
        replica: ReplicaId,
        nonce: Nonce,
        reason: NackReason,
        highest_seen: OpNumber,
    ) -> Self {
        Self {
            replica,
            nonce,
            reason,
            highest_seen,
        }
    }
}

/// Reason why a replica cannot fulfill a repair request.
///
/// This distinction is critical for PAR: we can only safely truncate
/// the log if enough replicas confirm they never saw the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NackReason {
    /// The operation was never received by this replica.
    ///
    /// Safe to truncate if a quorum of replicas report `NotSeen`.
    NotSeen,

    /// The operation was received but is now corrupt or lost.
    ///
    /// NOT safe to truncate - the operation may have been committed.
    SeenButCorrupt,

    /// The replica is in recovery and cannot help.
    Recovering,
}

impl std::fmt::Display for NackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NackReason::NotSeen => write!(f, "not_seen"),
            NackReason::SeenButCorrupt => write!(f, "seen_but_corrupt"),
            NackReason::Recovering => write!(f, "recovering"),
        }
    }
}

// ============================================================================
// State Transfer Messages
// ============================================================================

/// Replica → All: I need a checkpoint.
///
/// A replica sends `StateTransferRequest` when it's too far behind to
/// catch up via log repair and needs a full checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferRequest {
    /// Replica requesting state transfer.
    pub replica: ReplicaId,

    /// Random nonce to match responses.
    pub nonce: Nonce,

    /// Highest checkpoint this replica has.
    ///
    /// Allows responders to send only newer checkpoints.
    pub known_checkpoint: OpNumber,
}

impl StateTransferRequest {
    /// Creates a new `StateTransferRequest` message.
    pub fn new(replica: ReplicaId, nonce: Nonce, known_checkpoint: OpNumber) -> Self {
        Self {
            replica,
            nonce,
            known_checkpoint,
        }
    }
}

/// Replica → Requester: Here's a checkpoint.
///
/// A replica responds to `StateTransferRequest` with a checkpoint.
/// The checkpoint includes a Merkle root for verification and, when the
/// requester's gap is small enough, the committed log entries covering
/// `(request.known_checkpoint, checkpoint_op]`. Including the tail lets
/// the receiver drive each caught-up op through the normal
/// `apply_committed` path so downstream observers (chaos probe, future
/// audit/projection consumers) see the same `AppliedCommit` fanout they
/// get for a live prepare/commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransferResponse {
    /// Replica sending the response.
    pub replica: ReplicaId,

    /// Nonce from the request (for matching).
    pub nonce: Nonce,

    /// View at which the checkpoint was taken.
    pub checkpoint_view: ViewNumber,

    /// Operation number of the checkpoint.
    pub checkpoint_op: OpNumber,

    /// Merkle root of the checkpoint state (BLAKE3).
    pub merkle_root: Hash,

    /// Serialized checkpoint data.
    ///
    /// The format depends on the state machine implementation.
    pub checkpoint_data: Vec<u8>,

    /// Committed log entries covering `(tail_base_op - 1, checkpoint_op]`.
    ///
    /// Shipped only when the requester's gap fits within
    /// [`MAX_STATE_TRANSFER_TAIL_LEN`]; if the sender's log has already
    /// truncated past `request.known_checkpoint` or the gap exceeds the
    /// bound, this is empty and the receiver falls back to the legacy
    /// "jump to checkpoint" path — observers on that replica miss any
    /// ops older than their last seen commit.
    pub log_tail: Vec<LogEntry>,

    /// Op number of the first entry in `log_tail` (i.e.
    /// `request.known_checkpoint + 1`). Undefined when `log_tail` is
    /// empty; `OpNumber::ZERO` is used as a neutral placeholder then so
    /// deserialization stays total.
    pub tail_base_op: OpNumber,

    /// Ed25519 signature over the checkpoint (if signed checkpoints are enabled).
    pub signature: Option<Vec<u8>>,
}

/// Upper bound on the number of log entries shipped in a single
/// `StateTransferResponse`. A chaos-style partition at 200 ops/sec for
/// 60 seconds produces 12 000 entries — 10 000 covers realistic
/// post-partition catch-up while keeping the wire cost bounded.
pub const MAX_STATE_TRANSFER_TAIL_LEN: usize = 10_000;

impl StateTransferResponse {
    /// Creates a new `StateTransferResponse` message.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica: ReplicaId,
        nonce: Nonce,
        checkpoint_view: ViewNumber,
        checkpoint_op: OpNumber,
        merkle_root: Hash,
        checkpoint_data: Vec<u8>,
        log_tail: Vec<LogEntry>,
        tail_base_op: OpNumber,
        signature: Option<Vec<u8>>,
    ) -> Self {
        Self {
            replica,
            nonce,
            checkpoint_view,
            checkpoint_op,
            merkle_root,
            checkpoint_data,
            log_tail,
            tail_base_op,
            signature,
        }
    }
}

// ============================================================================
// Write Reorder Repair Messages
// ============================================================================

/// Backup → Leader: Request to fill gaps caused by write reordering.
///
/// When a backup receives a Prepare with an op number greater than expected
/// (due to write reordering in the network or storage layer), it buffers the
/// out-of-order prepare and sends this request to the leader asking for the
/// missing operations. This is lighter-weight than a full `RepairRequest`
/// because reorder gaps are typically small and transient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReorderGapRequest {
    /// The replica requesting gap fill.
    pub from: ReplicaId,

    /// Random nonce to match responses to this request.
    pub nonce: Nonce,

    /// The specific operation numbers that are missing.
    pub missing_ops: Vec<OpNumber>,
}

impl WriteReorderGapRequest {
    /// Creates a new `WriteReorderGapRequest` message.
    pub fn new(from: ReplicaId, nonce: Nonce, missing_ops: Vec<OpNumber>) -> Self {
        debug_assert!(
            !missing_ops.is_empty(),
            "gap request must have at least one missing op"
        );
        Self {
            from,
            nonce,
            missing_ops,
        }
    }

    /// Returns the number of missing operations requested.
    pub fn count(&self) -> usize {
        self.missing_ops.len()
    }
}

/// Leader → Backup: Response with entries to fill reorder gaps.
///
/// The leader responds to a `WriteReorderGapRequest` with the log entries
/// for the missing operations. The backup then inserts these entries into
/// its log and drains its reorder buffer in sequential order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReorderGapResponse {
    /// The replica sending the response.
    pub from: ReplicaId,

    /// Nonce from the request (for matching).
    pub nonce: Nonce,

    /// The log entries for the requested missing operations.
    pub entries: Vec<LogEntry>,
}

impl WriteReorderGapResponse {
    /// Creates a new `WriteReorderGapResponse` message.
    pub fn new(from: ReplicaId, nonce: Nonce, entries: Vec<LogEntry>) -> Self {
        Self {
            from,
            nonce,
            entries,
        }
    }

    /// Returns the number of entries in the response.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_kernel::Command;
    use kimberlite_types::DataClass;

    fn test_entry() -> LogEntry {
        LogEntry::new(
            OpNumber::new(1),
            ViewNumber::new(0),
            Command::create_stream_with_auto_id(
                "test".into(),
                DataClass::Public,
                kimberlite_types::Placement::Global,
            ),
            None,
            None,
            None,
        )
    }

    #[test]
    fn message_envelope_targeted() {
        let msg = Message::targeted(
            ReplicaId::new(0),
            ReplicaId::new(1),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        assert!(!msg.is_broadcast());
        assert!(msg.is_targeted());
        assert_eq!(msg.to, Some(ReplicaId::new(1)));
    }

    #[test]
    fn message_envelope_broadcast() {
        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::StartViewChange(StartViewChange::new(
                ViewNumber::new(1),
                ReplicaId::new(0),
            )),
        );

        assert!(msg.is_broadcast());
        assert!(!msg.is_targeted());
        assert_eq!(msg.to, None);
    }

    #[test]
    fn prepare_message_invariants() {
        let entry = test_entry();
        let prepare = Prepare::new(
            ViewNumber::new(0),
            OpNumber::new(1),
            entry.clone(),
            CommitNumber::ZERO,
        );

        assert_eq!(prepare.view, entry.view);
        assert_eq!(prepare.op_number, entry.op_number);
    }

    #[test]
    fn repair_request_count() {
        let request = RepairRequest::new(
            ReplicaId::new(0),
            Nonce::default(),
            OpNumber::new(5),
            OpNumber::new(10),
        );

        assert_eq!(request.count(), 5);
    }

    #[test]
    fn nack_reason_display() {
        assert_eq!(format!("{}", NackReason::NotSeen), "not_seen");
        assert_eq!(
            format!("{}", NackReason::SeenButCorrupt),
            "seen_but_corrupt"
        );
        assert_eq!(format!("{}", NackReason::Recovering), "recovering");
    }

    #[test]
    fn message_payload_view() {
        let heartbeat = MessagePayload::Heartbeat(Heartbeat::without_clock(
            ViewNumber::new(5),
            CommitNumber::ZERO,
        ));
        assert_eq!(heartbeat.view(), Some(ViewNumber::new(5)));

        let repair = MessagePayload::RepairRequest(RepairRequest::new(
            ReplicaId::new(0),
            Nonce::default(),
            OpNumber::new(1),
            OpNumber::new(2),
        ));
        assert_eq!(repair.view(), None);
    }

    #[test]
    fn message_payload_name() {
        let heartbeat = MessagePayload::Heartbeat(Heartbeat::without_clock(
            ViewNumber::ZERO,
            CommitNumber::ZERO,
        ));
        assert_eq!(heartbeat.name(), "Heartbeat");

        let prepare = MessagePayload::Prepare(Prepare::new(
            ViewNumber::ZERO,
            OpNumber::new(1),
            test_entry(),
            CommitNumber::ZERO,
        ));
        assert_eq!(prepare.name(), "Prepare");
    }

    #[test]
    fn do_view_change_construction() {
        let dvc = DoViewChange::new(
            ViewNumber::new(2),
            ReplicaId::new(1),
            ViewNumber::new(1),
            OpNumber::new(5),
            CommitNumber::new(OpNumber::new(3)),
            vec![test_entry()],
        );

        assert_eq!(dvc.view, ViewNumber::new(2));
        assert_eq!(dvc.last_normal_view, ViewNumber::new(1));
        assert_eq!(dvc.log_tail.len(), 1);
    }

    // ========================================================================
    // Property-Based Tests (Phase 2.3)
    // ========================================================================

    use proptest::prelude::*;

    /// Property: All messages roundtrip through serialization
    #[test]
    fn prop_prepare_roundtrip() {
        proptest!(|(view in 0u64..1000, _op in 1u64..1000)| {
            let entry = LogEntry::new(
                OpNumber::new(1),
                ViewNumber::new(view),
                Command::create_stream_with_auto_id(
                    "test".into(),
                    DataClass::Public,
                    kimberlite_types::Placement::Global,
                ),
                None,
                None,
                None,
            );
            let prepare = Prepare::new(
                ViewNumber::new(view),
                OpNumber::new(1), // Use fixed op to match entry
                entry,
                CommitNumber::new(OpNumber::new(0)),
            );
            let msg = Message::broadcast(ReplicaId::new(0), MessagePayload::Prepare(prepare.clone()));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
        });
    }

    #[test]
    fn prop_prepare_ok_roundtrip() {
        proptest!(|(view in 0u64..1000, op in 1u64..1000, timestamp in 0i64..1_700_000_000_000_000_000)| {
            let prepare_ok = PrepareOk::new(
                ViewNumber::new(view),
                OpNumber::new(op),
                ReplicaId::new(1),
                timestamp,
                crate::upgrade::VersionInfo::V0_4_0,
            );
            let msg = Message::targeted(ReplicaId::new(1), ReplicaId::new(0), MessagePayload::PrepareOk(prepare_ok));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
        });
    }

    #[test]
    fn prop_commit_roundtrip() {
        proptest!(|(view in 0u64..1000, commit in 0u64..1000)| {
            let commit = Commit {
                view: ViewNumber::new(view),
                commit_number: CommitNumber::new(OpNumber::new(commit)),
            };
            let msg = Message::broadcast(ReplicaId::new(0), MessagePayload::Commit(commit));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
        });
    }

    #[test]
    fn prop_heartbeat_roundtrip() {
        proptest!(|(view in 0u64..1000, commit in 0u64..1000, mono in 0u128..1_000_000_000_000, wall in 0i64..1_700_000_000_000_000_000)| {
            let heartbeat = Heartbeat::new(
                ViewNumber::new(view),
                CommitNumber::new(OpNumber::new(commit)),
                mono,
                wall,
                crate::upgrade::VersionInfo::V0_4_0,
            );
            let msg = Message::broadcast(ReplicaId::new(0), MessagePayload::Heartbeat(heartbeat));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
        });
    }

    #[test]
    fn prop_start_view_change_roundtrip() {
        proptest!(|(view in 1u64..1000)| {
            let svc = StartViewChange::new(ViewNumber::new(view), ReplicaId::new(1));
            let msg = Message::broadcast(ReplicaId::new(1), MessagePayload::StartViewChange(svc));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
        });
    }

    /// Property: Serialization is deterministic (same message → same bytes)
    #[test]
    fn prop_serialization_deterministic() {
        proptest!(|(view in 0u64..1000, commit in 0u64..1000)| {
            let commit = Commit {
                view: ViewNumber::new(view),
                commit_number: CommitNumber::new(OpNumber::new(commit)),
            };
            let msg = Message::broadcast(ReplicaId::new(0), MessagePayload::Commit(commit));

            let serialized1 = serde_json::to_vec(&msg).unwrap();
            let serialized2 = serde_json::to_vec(&msg).unwrap();

            prop_assert_eq!(serialized1, serialized2);
        });
    }

    /// Property: Message sizes are bounded
    #[test]
    fn prop_message_size_bounded() {
        proptest!(|(view in 0u64..1000, commit in 0u64..1000)| {
            let commit = Commit {
                view: ViewNumber::new(view),
                commit_number: CommitNumber::new(OpNumber::new(commit)),
            };
            let msg = Message::broadcast(ReplicaId::new(0), MessagePayload::Commit(commit));

            let serialized = serde_json::to_vec(&msg).unwrap();

            // Commit messages should be small (<500 bytes)
            prop_assert!(serialized.len() < 500);
        });
    }

    /// Property: Malformed messages are rejected (don't panic)
    #[test]
    fn prop_malformed_rejection() {
        proptest!(|(bytes: Vec<u8>)| {
            // Attempt to deserialize random bytes
            let result: Result<Message, _> = serde_json::from_slice(&bytes);

            // Either succeeds (very rare for random bytes) or fails gracefully
            // Property: Function returns without panicking (regardless of result)
            let _ = result;
        });
    }

    /// Property: `RepairRequest` roundtrip with various ranges
    #[test]
    fn prop_repair_request_roundtrip() {
        proptest!(|(start in 1u64..1000, gap in 1u64..100)| {
            let end = start + gap;
            let repair_req = RepairRequest::new(
                ReplicaId::new(1),
                Nonce::default(),
                OpNumber::new(start),
                OpNumber::new(end),
            );
            let msg = Message::broadcast(ReplicaId::new(1), MessagePayload::RepairRequest(repair_req));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
            prop_assert!(serialized.len() < 500);
        });
    }

    /// Property: Nack roundtrip
    #[test]
    fn prop_nack_roundtrip() {
        proptest!(|(op in 1u64..1000)| {
            let nack = Nack::new(
                ReplicaId::new(0),
                Nonce::default(),
                NackReason::NotSeen,
                OpNumber::new(op),
            );
            let msg = Message::targeted(ReplicaId::new(0), ReplicaId::new(1), MessagePayload::Nack(nack));

            let serialized = serde_json::to_vec(&msg).unwrap();
            let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

            prop_assert_eq!(msg, deserialized);
            prop_assert!(serialized.len() < 500);
        });
    }

    // ========================================================================
    // Message Signature Tests (AUDIT-2026-03 M-3)
    // ========================================================================

    use kimberlite_crypto::verified::VerifiedSigningKey;

    #[test]
    fn test_message_sign_and_verify() {
        let signing_key = VerifiedSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        // Sign message
        let signed_msg = msg.sign(&signing_key);
        assert!(signed_msg.is_signed());

        // Verify signature
        assert!(signed_msg.verify(&verifying_key).is_ok());
    }

    #[test]
    fn test_unsigned_message_verification_fails() {
        let signing_key = VerifiedSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        // Unsigned message should fail verification
        assert!(msg.verify(&verifying_key).is_err());
    }

    #[test]
    fn test_wrong_key_verification_fails() {
        let signing_key1 = VerifiedSigningKey::generate();
        let signing_key2 = VerifiedSigningKey::generate();
        let verifying_key2 = signing_key2.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        let signed_msg = msg.sign(&signing_key1);

        // Verification with wrong key should fail
        assert!(signed_msg.verify(&verifying_key2).is_err());
    }

    #[test]
    fn test_tampered_message_verification_fails() {
        let signing_key = VerifiedSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        let mut signed_msg = msg.sign(&signing_key);

        // Tamper with the message payload
        if let MessagePayload::Heartbeat(ref mut heartbeat) = signed_msg.payload {
            heartbeat.view = ViewNumber::new(999); // Tamper
        }

        // Verification should fail for tampered message
        assert!(signed_msg.verify(&verifying_key).is_err());
    }

    #[test]
    fn test_signature_determinism() {
        let seed = [0x42; 32];
        let signing_key = VerifiedSigningKey::from_bytes(&seed);

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        // Sign same message twice
        let signed_msg1 = msg.clone().sign(&signing_key);
        let signed_msg2 = msg.sign(&signing_key);

        // Signatures should be identical
        assert_eq!(signed_msg1.signature, signed_msg2.signature);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let signing_key = VerifiedSigningKey::generate();

        let msg1 = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        let msg2 = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(1), // Different view
                CommitNumber::ZERO,
            )),
        );

        let signed_msg1 = msg1.sign(&signing_key);
        let signed_msg2 = msg2.sign(&signing_key);

        // Different messages should have different signatures
        assert_ne!(signed_msg1.signature, signed_msg2.signature);
    }

    #[test]
    fn test_signature_roundtrip_through_serialization() {
        let signing_key = VerifiedSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Commit(Commit {
                view: ViewNumber::new(5),
                commit_number: CommitNumber::new(OpNumber::new(10)),
            }),
        );

        let signed_msg = msg.sign(&signing_key);

        // Serialize and deserialize
        let serialized = serde_json::to_vec(&signed_msg).unwrap();
        let deserialized: Message = serde_json::from_slice(&serialized).unwrap();

        // Verification should still work after roundtrip
        assert!(deserialized.verify(&verifying_key).is_ok());
    }

    #[test]
    fn test_invalid_signature_length() {
        let signing_key = VerifiedSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let msg = Message::broadcast(
            ReplicaId::new(0),
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        );

        let mut signed_msg = msg.sign(&signing_key);

        // Corrupt signature length
        signed_msg.signature = Some(vec![0u8; 32]); // Wrong length (should be 64)

        // Verification should fail
        let result = signed_msg.verify(&verifying_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature length"));
    }

    /// Property: Signed messages always verify with correct key
    #[test]
    fn prop_signature_correctness() {
        proptest!(|(view in 0u64..1000, commit in 0u64..1000)| {
            let signing_key = VerifiedSigningKey::generate();
            let verifying_key = signing_key.verifying_key();

            let msg = Message::broadcast(
                ReplicaId::new(0),
                MessagePayload::Commit(Commit {
                    view: ViewNumber::new(view),
                    commit_number: CommitNumber::new(OpNumber::new(commit)),
                }),
            );

            let signed_msg = msg.sign(&signing_key);

            prop_assert!(signed_msg.verify(&verifying_key).is_ok());
        });
    }

    /// Property: Signatures are unique for different messages
    #[test]
    fn prop_signature_uniqueness() {
        proptest!(|(view1 in 0u64..1000, view2 in 1000u64..2000)| {
            let signing_key = VerifiedSigningKey::generate();

            let msg1 = Message::broadcast(
                ReplicaId::new(0),
                MessagePayload::Heartbeat(Heartbeat::without_clock(
                    ViewNumber::new(view1),
                    CommitNumber::ZERO,
                )),
            );

            let msg2 = Message::broadcast(
                ReplicaId::new(0),
                MessagePayload::Heartbeat(Heartbeat::without_clock(
                    ViewNumber::new(view2),
                    CommitNumber::ZERO,
                )),
            );

            let signed_msg1 = msg1.sign(&signing_key);
            let signed_msg2 = msg2.sign(&signing_key);

            // Different messages should have different signatures
            prop_assert_ne!(signed_msg1.signature, signed_msg2.signature);
        });
    }
}
