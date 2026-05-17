//! Replica state structure.
//!
//! This module defines [`ReplicaState`], the core state of a VSR replica.
//! The state is designed to be cloneable for simulation testing and
//! follows the FCIS pattern (pure, no I/O).

use std::collections::{HashMap, HashSet};

use kimberlite_kernel::{Command, Effect, State as KernelState, apply_committed};
use kimberlite_types::{Generation, IdempotencyId};

use crate::client_sessions::ClientSessions;
use crate::clock::Clock;
use crate::config::ClusterConfig;
use crate::message::{DoViewChange, MessagePayload, Prepare};
use crate::types::{CommitNumber, LogEntry, OpNumber, ReplicaId, ReplicaStatus, ViewNumber};

use super::recovery::RecoveryState;
use super::repair::RepairState;
use super::{ReplicaEvent, ReplicaOutput, TimeoutKind, msg_broadcast};

// ============================================================================
// Message Replay Detection (AUDIT-2026-03 M-6)
// ============================================================================

/// Unique identifier for a message (for deduplication).
///
/// **Security:** Used to detect Byzantine replay attacks where old messages
/// are re-sent to disrupt consensus.
///
/// `content_hash` distinguishes legitimately-different retransmissions
/// from byte-identical replays. Today only used by `DoViewChange`,
/// where the receiving leader's "use the better message" replacement
/// logic in `view_change.rs::on_do_view_change` would otherwise be
/// shadowed by `(sender, view)`-only dedup — a real bug we hit in
/// the v0.9.x cluster graduation work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MessageId {
    /// Sender replica ID
    pub sender: ReplicaId,
    /// Message type discriminant (0=Prepare, 1=PrepareOk, 2=Commit, etc.)
    pub msg_type: u8,
    /// View number (for view-aware messages)
    pub view: ViewNumber,
    /// Operation number (for op-aware messages like Prepare/PrepareOk)
    pub op_number: Option<OpNumber>,
    /// Hash of message content for variants whose body can legitimately
    /// change between retransmissions. `None` for variants that should
    /// always dedup on `(sender, view, ...)` alone.
    pub content_hash: Option<u64>,
}

impl MessageId {
    /// Creates a MessageId for a Prepare message.
    pub fn prepare(sender: ReplicaId, view: ViewNumber, op_number: OpNumber) -> Self {
        Self {
            sender,
            msg_type: 0,
            view,
            op_number: Some(op_number),
            content_hash: None,
        }
    }

    /// Creates a MessageId for a PrepareOk message.
    pub fn prepare_ok(sender: ReplicaId, view: ViewNumber, op_number: OpNumber) -> Self {
        Self {
            sender,
            msg_type: 1,
            view,
            op_number: Some(op_number),
            content_hash: None,
        }
    }

    /// Creates a MessageId for a Commit message.
    ///
    /// `commit_number` is included in the identity so a leader's periodic
    /// Commit messages (each advancing commit_number by ≥1) don't collide
    /// and falsely trip the replay detector. A true replay of the same
    /// (sender, view, commit_number) triple still matches.
    pub fn commit(sender: ReplicaId, view: ViewNumber, commit_number: CommitNumber) -> Self {
        Self {
            sender,
            msg_type: 2,
            view,
            // Stash commit_number into the op_number slot so the existing
            // HashSet key stays a single tuple — commit_number and
            // op_number occupy disjoint message types.
            op_number: Some(commit_number.as_op_number()),
            content_hash: None,
        }
    }

    /// Creates a MessageId for a Heartbeat message.
    ///
    /// Heartbeats piggyback `commit_number`, but periodic heartbeats
    /// legitimately repeat the same `commit_number` when no new commit
    /// has happened — deduping them would fight the liveness protocol.
    /// The dedup call site for heartbeats was therefore removed; this
    /// constructor is retained only for symmetry + future use.
    #[allow(dead_code)]
    pub fn heartbeat(sender: ReplicaId, view: ViewNumber, commit_number: CommitNumber) -> Self {
        Self {
            sender,
            msg_type: 3,
            view,
            op_number: Some(commit_number.as_op_number()),
            content_hash: None,
        }
    }

    /// Creates a MessageId for a StartViewChange message.
    pub fn start_view_change(sender: ReplicaId, view: ViewNumber) -> Self {
        Self {
            sender,
            msg_type: 4,
            view,
            op_number: None,
            content_hash: None,
        }
    }

    /// Creates a MessageId for a DoViewChange message.
    ///
    /// `content_hash` distinguishes legitimately-different
    /// retransmissions (sender learned a higher `last_normal_view` /
    /// `op_number` since its first send) from byte-identical replays.
    /// Without it, the dedup gate at the call site shadows the leader's
    /// "use the better message" replacement logic — see the v0.9.x
    /// cluster graduation work for the bug repro.
    pub fn do_view_change(sender: ReplicaId, view: ViewNumber, content_hash: u64) -> Self {
        Self {
            sender,
            msg_type: 5,
            view,
            op_number: None,
            content_hash: Some(content_hash),
        }
    }

    /// Creates a MessageId for a StartView message.
    pub fn start_view(sender: ReplicaId, view: ViewNumber) -> Self {
        Self {
            sender,
            msg_type: 6,
            view,
            op_number: None,
            content_hash: None,
        }
    }
}

/// Tracks seen messages to detect replays (AUDIT-2026-03 M-6).
///
/// **Security:** Byzantine replicas may replay old messages to disrupt consensus.
/// This tracker maintains a bounded set of recently seen message IDs and rejects
/// duplicates.
///
/// **Pruning:** Entries for views older than `current_view - 1` are automatically
/// removed to prevent unbounded growth. We keep one old view to handle delayed
/// messages during view change transitions.
#[derive(Debug, Clone, Default)]
pub(crate) struct MessageDedupTracker {
    /// Set of seen message IDs
    seen: HashSet<MessageId>,
    /// Total number of replay attempts detected (for metrics)
    replay_attempts: u64,
}

impl MessageDedupTracker {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a message has been seen before (replay detection).
    ///
    /// Returns `Ok(())` if message is new, `Err(())` if it's a replay.
    ///
    /// **Side effect:** If the message is new, it's added to the tracker.
    pub fn check_and_record(&mut self, msg_id: MessageId) -> Result<(), ()> {
        if self.seen.contains(&msg_id) {
            self.replay_attempts += 1;
            return Err(());
        }
        self.seen.insert(msg_id);
        Ok(())
    }

    /// Prunes entries older than `min_view` to prevent unbounded growth.
    ///
    /// Called when the view advances. We keep entries from `current_view - 1`
    /// to handle delayed messages during view change.
    pub fn prune_old_views(&mut self, min_view: ViewNumber) {
        self.seen.retain(|msg_id| msg_id.view >= min_view);
    }

    /// Returns the total number of replay attempts detected.
    /// Returns the number of replay attempts detected (for monitoring and debugging).
    #[allow(dead_code)]
    pub fn replay_attempts(&self) -> u64 {
        self.replay_attempts
    }

    /// Returns the number of tracked messages (for monitoring and debugging).
    #[allow(dead_code)]
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }
}

// ============================================================================
// Pending Request
// ============================================================================

/// A client request waiting to be prepared.
///
/// Requests are queued when they arrive before the replica becomes leader,
/// or when the replica is not yet in normal operation.
#[derive(Debug, Clone)]
#[allow(dead_code)] // TODO(v0.7.0): Process pending requests in future implementation
pub(crate) struct PendingRequest {
    pub command: Command,
    pub idempotency_id: Option<IdempotencyId>,
    pub client_id: Option<crate::ClientId>,
    pub request_number: Option<u64>,
}

// ============================================================================
// Replica State
// ============================================================================

/// The state of a VSR replica.
///
/// This structure contains all mutable state for a replica. It is designed
/// to be:
/// - **Pure**: All state transitions are deterministic
/// - **Cloneable**: For simulation testing and snapshotting
/// - **Serializable**: For persistence and debugging
///
/// # State Categories
///
/// 1. **Identity**: `replica_id`, `config`
/// 2. **View State**: `view`, `status`, `last_normal_view`
/// 3. **Log State**: `log`, `op_number`, `commit_number`
/// 4. **Tracking**: `prepare_ok_tracker`, view change votes
/// 5. **Application**: `kernel_state`
#[derive(Debug, Clone)]
pub struct ReplicaState {
    // ========================================================================
    // Identity
    // ========================================================================
    /// This replica's ID.
    pub(crate) replica_id: ReplicaId,

    /// Cluster configuration.
    pub(crate) config: ClusterConfig,

    // ========================================================================
    // View State
    // ========================================================================
    /// Current view number.
    pub(crate) view: ViewNumber,

    /// Current replica status.
    pub(crate) status: ReplicaStatus,

    /// Last view in which this replica was in normal status.
    ///
    /// Used during view change to determine which replica has
    /// the most up-to-date log.
    pub(crate) last_normal_view: ViewNumber,

    // ========================================================================
    // Log State
    // ========================================================================
    /// The replicated log of committed entries.
    pub(crate) log: Vec<LogEntry>,

    /// Highest operation number in the log.
    pub(crate) op_number: OpNumber,

    /// Highest committed operation number.
    pub(crate) commit_number: CommitNumber,

    // ========================================================================
    // Leader Tracking (only used when leader)
    // ========================================================================
    /// Tracks `PrepareOK` responses for pending operations.
    ///
    /// Key: operation number, Value: set of replicas that sent `PrepareOK`.
    pub(crate) prepare_ok_tracker: HashMap<OpNumber, HashSet<ReplicaId>>,

    /// Pending client requests waiting to be prepared.
    pub(crate) pending_requests: Vec<PendingRequest>,

    // ========================================================================
    // View Change Tracking
    // ========================================================================
    /// `StartViewChange` votes received for current view change.
    pub(crate) start_view_change_votes: HashSet<ReplicaId>,

    /// `DoViewChange` messages received (as new leader).
    pub(crate) do_view_change_msgs: Vec<DoViewChange>,

    // ========================================================================
    // Recovery & Repair State
    // ========================================================================
    /// Current recovery generation.
    ///
    /// Incremented each time the replica recovers from a crash.
    pub(crate) generation: Generation,

    /// State tracked during recovery (if recovering).
    pub(crate) recovery_state: Option<RecoveryState>,

    /// State tracked during repair (if repairing).
    pub(crate) repair_state: Option<RepairState>,

    /// State tracked during state transfer (if catching up).
    pub(crate) state_transfer_state: Option<super::StateTransferState>,

    // ========================================================================
    // Application State
    // ========================================================================
    /// The kernel (application) state machine.
    pub(crate) kernel_state: KernelState,

    // ========================================================================
    // Clock Synchronization
    // ========================================================================
    /// Cluster-wide synchronized clock.
    ///
    /// Only the primary assigns timestamps. Backups collect clock samples
    /// and send them to the primary in `PrepareOk` messages.
    pub(crate) clock: Clock,

    /// Monotonic timestamps of when each Prepare was broadcast (leader only).
    ///
    /// Used to calculate RTT for clock synchronization when `PrepareOk`
    /// responses arrive. Entries are cleaned up once the operation is committed.
    pub(crate) prepare_send_times: HashMap<OpNumber, u128>,

    // ========================================================================
    // Client Sessions (VRR Paper Bug Fixes)
    // ========================================================================
    /// Client session manager for request deduplication.
    ///
    /// Fixes two bugs found in the VRR paper:
    /// 1. Successive client crashes causing request number collisions
    /// 2. Client lockout after view change due to uncommitted table updates
    ///
    /// `ClientSessions` provides explicit session registration and separates
    /// committed vs uncommitted tracking.
    pub(crate) client_sessions: ClientSessions,

    // ========================================================================
    // Repair Budget (Phase 2)
    // ========================================================================
    /// Repair budget manager for preventing repair storms.
    ///
    /// Uses EWMA to track per-replica latency and routes repairs to
    /// the fastest replicas. Limits inflight requests (max 2 per replica)
    /// and expires stale requests (500ms timeout) to prevent send queue
    /// overflow.
    pub(crate) repair_budget: crate::repair_budget::RepairBudget,

    // ========================================================================
    // Log Scrubber (Phase 3)
    // ========================================================================
    /// Background log scrubber for proactive corruption detection.
    ///
    /// Tours the entire log periodically, validating checksums on every entry.
    /// Detects silent corruption before it causes double-fault data loss.
    /// PRNG-based origin prevents thundering herd across replicas.
    pub(crate) log_scrubber: crate::log_scrubber::LogScrubber,

    // ========================================================================
    // Cluster Reconfiguration (Phase 4)
    // ========================================================================
    /// Current reconfiguration state.
    ///
    /// Tracks whether the cluster is in stable configuration or joint
    /// consensus during reconfiguration. Preserved across view changes.
    pub(crate) reconfig_state: crate::reconfiguration::ReconfigState,

    // ========================================================================
    // Rolling Upgrades (Phase 4)
    // ========================================================================
    /// Upgrade state for rolling version transitions.
    ///
    /// Tracks software versions across all replicas. Cluster operates at
    /// minimum version to ensure backward compatibility. New features are
    /// enabled only when all replicas reach the required version.
    pub(crate) upgrade_state: crate::upgrade::UpgradeState,

    // ========================================================================
    // Standby Replicas (Phase 4.3)
    // ========================================================================
    /// Standby replica state (if replica is in Standby mode).
    ///
    /// Standby replicas receive log updates but don't participate in quorum.
    /// Used for disaster recovery and read scaling. Can be promoted to
    /// active replica on demand.
    pub(crate) standby_state: Option<super::StandbyState>,

    // ========================================================================
    // Write Reorder Repair (Phase 3A)
    // ========================================================================
    /// Buffer for out-of-order prepares during write reordering.
    ///
    /// When a backup receives a Prepare with op > expected, it stores the
    /// entry here and requests the missing ops from the leader. Once the
    /// gaps are filled, entries are drained from this buffer in order.
    pub(crate) reorder_buffer: HashMap<OpNumber, crate::types::LogEntry>,

    /// Monotonic deadlines for gap fill requests (nanoseconds since epoch).
    ///
    /// Each pending gap fill has a 100ms timeout. If the gap is not filled
    /// within this window, the repair escalates to a full `RepairRequest`.
    pub(crate) reorder_deadlines: HashMap<OpNumber, u128>,

    // ========================================================================
    // Performance Profiling (Phase 5)
    // ========================================================================
    /// Timestamps for tracking operation latency.
    ///
    /// These are used for performance profiling to measure end-to-end latency
    /// of consensus operations. Key: `OpNumber`, Value: start time (nanoseconds).
    /// Only present in non-simulation builds (gated by `cfg(not(feature = "sim"))`).
    #[cfg(not(feature = "sim"))]
    pub(crate) prepare_start_times: HashMap<OpNumber, u128>,

    /// Timestamp when view change started (for view change latency).
    /// Only present in non-simulation builds (gated by `cfg(not(feature = "sim"))`).
    #[cfg(not(feature = "sim"))]
    pub(crate) view_change_start_time: Option<u128>,

    // ========================================================================
    // Cryptographic Message Authentication (AUDIT-2026-03 M-3)
    // ========================================================================
    /// Ed25519 signing key for this replica (wrapped in Arc for cheap cloning).
    ///
    /// **Security context:** Every outgoing message must be signed to prevent
    /// Byzantine replicas from forging messages. Coq-verified implementation
    /// from `kimberlite-crypto`.
    ///
    /// **Usage:** Call `message.sign(&signing_key)` before sending.
    ///
    /// **Design:** Wrapped in Arc because:
    /// - SigningKey doesn't implement Clone (prevents accidental key duplication)
    /// - ReplicaState needs Clone for simulation testing
    /// - Arc provides cheap clone via reference counting
    pub(crate) signing_key: std::sync::Arc<kimberlite_crypto::verified::VerifiedSigningKey>,

    /// Ed25519 verifying keys for all replicas in the cluster.
    ///
    /// **Security context:** All incoming messages must be verified before
    /// processing to detect forged or tampered messages. Byzantine replicas
    /// cannot forge signatures without the private key.
    ///
    /// **Usage:** Call `message.verify(&verifying_keys[sender])` on receive.
    pub(crate) verifying_keys:
        std::collections::HashMap<ReplicaId, kimberlite_crypto::verified::VerifiedVerifyingKey>,

    // ========================================================================
    // Replay Attack Protection (AUDIT-2026-03 M-6)
    // ========================================================================
    /// Tracks recently seen messages to detect and reject replays.
    ///
    /// **Security context:** Byzantine replicas may attempt to replay old messages
    /// to disrupt consensus (e.g., replaying old Prepare messages to cause confusion).
    ///
    /// **Design:** Tracks (sender, message_type, view, op_number) tuples for all
    /// protocol messages. Entries are pruned when view advances to prevent unbounded growth.
    ///
    /// **Coverage:** Detects replay attacks including:
    /// - Prepare message replays (duplicate proposals)
    /// - PrepareOk message replays (vote stuffing)
    /// - View change message replays (disrupting new view formation)
    /// - Recovery/repair message replays (resource exhaustion)
    pub(crate) message_dedup_tracker: MessageDedupTracker,
}

impl ReplicaState {
    /// Creates a new replica state with initial values.
    ///
    /// The replica starts in `Normal` status at view 0. If it's the leader
    /// for view 0, it can immediately accept client requests.
    pub fn new(replica_id: ReplicaId, config: ClusterConfig) -> Self {
        debug_assert!(
            config.contains(replica_id),
            "replica must be in cluster config"
        );

        let cluster_size = config.replicas().count();
        let clock = Clock::new(replica_id, cluster_size);
        let client_sessions = ClientSessions::with_defaults();
        let repair_budget = crate::repair_budget::RepairBudget::new(replica_id, cluster_size);
        let log_scrubber = crate::log_scrubber::LogScrubber::new(replica_id, OpNumber::ZERO);
        let reconfig_state = crate::reconfiguration::ReconfigState::new_stable(config.clone());
        let upgrade_state = crate::upgrade::UpgradeState::new(crate::upgrade::VersionInfo::V0_4_0);

        // Generate Ed25519 keypair for message signing (AUDIT-2026-03 M-3)
        //
        // **SECURITY WARNING:** This function uses DETERMINISTIC keys derived from
        // replica_id for testing and simulation ONLY. The same replica_id always
        // produces the same private key, which is cryptographically unsafe in
        // production environments.
        //
        // In production: Use `ReplicaState::new_with_keys()` (TODO(v0.9.0)) which
        // accepts externally-provisioned keys from an HSM or KMS.
        //
        // Runtime guard: panics when called outside test/sim builds to prevent
        // accidental use of deterministic keys in production.
        // Production build guard: panics if called outside test/sim context.
        // TODO(v0.9.0): Replace new() with new_with_keys(signing_key, verifying_keys).
        assert!(
            cfg!(any(test, feature = "sim")),
            "ReplicaState::new() uses deterministic test keys and must not be called              in production. Use ReplicaState::new_with_keys() to supply keys loaded              from secure storage (HSM/KMS). See docs/operating/security.md"
        );

        // TESTING/SIMULATION ONLY: Deterministic keys for reproducibility.
        // The runtime guard above ensures this is never reached in production.
        // Never use in production — same seed = same private key!
        let signing_key = {
            let mut seed = [0u8; 32];
            seed[0] = replica_id.as_u8();
            seed[1..9].copy_from_slice(b"kimbrlte"); // magic constant
            kimberlite_crypto::verified::VerifiedSigningKey::from_bytes(&seed)
        };

        // Collect verifying keys for all replicas in the cluster
        // (derived deterministically for testing; loaded from key store in production)
        let verifying_keys = config
            .replicas()
            .map(|rid| {
                let mut seed = [0u8; 32];
                seed[0] = rid.as_u8();
                seed[1..9].copy_from_slice(b"kimbrlte");
                let sk = kimberlite_crypto::verified::VerifiedSigningKey::from_bytes(&seed);
                (rid, sk.verifying_key())
            })
            .collect();

        let state = Self {
            replica_id,
            config,
            view: ViewNumber::ZERO,
            status: ReplicaStatus::Normal,
            last_normal_view: ViewNumber::ZERO,
            log: Vec::new(),
            op_number: OpNumber::ZERO,
            commit_number: CommitNumber::ZERO,
            prepare_ok_tracker: HashMap::new(),
            pending_requests: Vec::new(),
            start_view_change_votes: HashSet::new(),
            do_view_change_msgs: Vec::new(),
            generation: Generation::INITIAL,
            recovery_state: None,
            repair_state: None,
            state_transfer_state: None,
            kernel_state: KernelState::new(),
            clock,
            client_sessions,
            repair_budget,
            log_scrubber,
            reconfig_state,
            upgrade_state,
            standby_state: None, // Normal replicas start with no standby state
            reorder_buffer: HashMap::new(),
            reorder_deadlines: HashMap::new(),
            prepare_send_times: HashMap::new(),
            #[cfg(not(feature = "sim"))]
            prepare_start_times: HashMap::new(),
            #[cfg(not(feature = "sim"))]
            view_change_start_time: None,
            signing_key: std::sync::Arc::new(signing_key),
            verifying_keys,
            message_dedup_tracker: MessageDedupTracker::new(),
        };

        // Initial invariant check
        debug_assert!(
            state.commit_number.as_op_number() <= state.op_number,
            "new: commit={} > op={}",
            state.commit_number.as_u64(),
            state.op_number.as_u64()
        );

        state
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns this replica's ID.
    pub fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }

    /// Returns the cluster configuration.
    pub fn config(&self) -> &ClusterConfig {
        &self.config
    }

    /// Returns the current view number.
    pub fn view(&self) -> ViewNumber {
        self.view
    }

    /// Returns the current replica status.
    pub fn status(&self) -> ReplicaStatus {
        self.status
    }

    /// Returns the highest operation number.
    pub fn op_number(&self) -> OpNumber {
        self.op_number
    }

    /// Returns the highest committed operation number.
    pub fn commit_number(&self) -> CommitNumber {
        self.commit_number
    }

    /// Returns the kernel state.
    pub fn kernel_state(&self) -> &KernelState {
        &self.kernel_state
    }

    /// Returns the number of entries in the log.
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Returns a log entry by operation number.
    pub fn log_entry(&self, op: OpNumber) -> Option<&LogEntry> {
        if op.is_zero() {
            return None;
        }
        let index = op.as_u64().checked_sub(1)? as usize;
        self.log.get(index)
    }

    /// Returns true if this replica is the leader-of-record for the current
    /// view number — a pure view-table lookup with no status check.
    ///
    /// Used by the protocol layer where the question is "whose view is
    /// this?" (prepare authoring, view-change message routing). For
    /// observability and external "is this replica acting as leader right
    /// now?" predicates, prefer [`Self::is_acting_leader`] — during a view
    /// change two replicas can transiently answer `true` here (the
    /// outgoing primary still owns view N while the incoming primary is
    /// already starting view N+1), which the strict variant rules out.
    pub fn is_leader(&self) -> bool {
        self.config.leader_for_view(self.view) == self.replica_id
    }

    /// Returns true if this replica is the leader of the current view AND
    /// is in `Normal` status — i.e. it is actually acting as leader right
    /// now, not mid-view-change.
    ///
    /// This is the predicate observability (`kimberlite_is_leader` gauge),
    /// submit-side gating, and `/readyz` should use: it answers the
    /// operational question "should this node take writes?" rather than
    /// the protocol question "who owns view N?".
    pub fn is_acting_leader(&self) -> bool {
        self.status == ReplicaStatus::Normal && self.is_leader()
    }

    /// Returns the leader for the current view.
    pub fn leader(&self) -> ReplicaId {
        self.config.leader_for_view(self.view)
    }

    /// Returns true if the replica can process client requests.
    pub fn can_accept_requests(&self) -> bool {
        // Same composition as [`Self::is_acting_leader`] — kept under its
        // original name because the accept-side call sites read more
        // naturally as "can_accept_requests()".
        self.is_acting_leader()
    }

    // ========================================================================
    // Message Signing (AUDIT-2026-03 M-3)
    // ========================================================================

    /// Signs a message with this replica's Ed25519 signing key.
    ///
    /// **Security:** All outgoing messages MUST be signed before sending to prevent
    /// Byzantine replicas from forging messages. This is a defense-in-depth measure
    /// complementing view checks and quorum validation.
    ///
    /// **Usage:** Call this on every message before adding to ReplicaOutput:
    /// ```ignore
    /// let msg = self.sign_message(msg_to(self.replica_id, to, payload));
    /// ```
    ///
    /// **Implementation:** Signs the canonical serialization of (from, to, payload)
    /// using Ed25519. The signature is appended to the message and verified at
    /// receive boundaries.
    pub(crate) fn sign_message(&self, message: crate::Message) -> crate::Message {
        message.sign(&self.signing_key)
    }

    /// Verifies a message's Ed25519 signature.
    ///
    /// **Security:** All incoming messages MUST be verified before processing to detect
    /// forged or tampered messages from Byzantine replicas. This is defense-in-depth
    /// complementing view checks and quorum validation.
    ///
    /// **Usage:** Call this at the start of every message handler:
    /// ```ignore
    /// if let Err(e) = self.verify_message(&message) {
    ///     // Log and reject
    ///     return (self, ReplicaOutput::empty());
    /// }
    /// ```
    ///
    /// **Returns:**
    /// - `Ok(())` if signature is valid
    /// - `Err(String)` if signature is invalid, missing, or sender unknown
    pub(crate) fn verify_message(&self, message: &crate::Message) -> Result<(), String> {
        // Look up sender's verifying key
        let verifying_key = self
            .verifying_keys
            .get(&message.from)
            .ok_or_else(|| format!("Unknown sender: {}", message.from.as_u8()))?;

        // Verify signature
        message.verify(verifying_key)
    }

    // ========================================================================
    // Event Processing (Main Entry Point)
    // ========================================================================

    /// Processes an event and returns the new state and output.
    ///
    /// This is the main entry point for the state machine. All state
    /// transitions go through this method.
    ///
    /// # FCIS Pattern
    ///
    /// This method is pure: it takes ownership of `self`, processes the
    /// event, and returns a new state. The caller is responsible for
    /// executing the output (sending messages, executing effects).
    pub fn process(self, event: ReplicaEvent) -> (Self, ReplicaOutput) {
        match event {
            ReplicaEvent::Message(msg) => self.on_message(*msg),
            ReplicaEvent::Timeout(kind) => self.on_timeout(kind),
            ReplicaEvent::ClientRequest {
                command,
                idempotency_id,
                client_id,
                request_number,
            } => self.on_client_request(command, idempotency_id, client_id, request_number),
            ReplicaEvent::ReconfigCommand(cmd) => self.on_reconfig_command(cmd),
            ReplicaEvent::Tick => self.on_tick(),
            #[cfg(any(test, feature = "sim"))]
            ReplicaEvent::Crash => (self.handle_crash(), ReplicaOutput::empty()),
        }
    }

    /// Handles an incoming message.
    fn on_message(self, msg: crate::Message) -> (Self, ReplicaOutput) {
        // Ignore messages from unknown replicas
        if !self.config.contains(msg.from) {
            return (self, ReplicaOutput::empty());
        }

        // Verify message signature (AUDIT-2026-03 M-3 Phase 4)
        //
        // **Security:** All incoming messages MUST be verified before processing.
        // This defends against Byzantine replicas forging or tampering with messages.
        if let Err(e) = self.verify_message(&msg) {
            tracing::error!(
                replica = %self.replica_id,
                from = %msg.from.as_u8(),
                payload = %msg.payload.name(),
                error = %e,
                "Signature verification failed - rejecting message"
            );
            crate::instrumentation::METRICS.increment_signature_failures();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "signature_verification_failed",
                msg.from,
                0,
                self.op_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // Check if message is for us (if targeted)
        if let Some(to) = msg.to {
            if to != self.replica_id {
                return (self, ReplicaOutput::empty());
            }
        }

        match msg.payload {
            // Transport-layer handshake — `TcpTransport` consumes Hello
            // frames before they reach the event loop. Reaching this arm
            // means the transport leaked one through (programmer error
            // or in-process test transport without the inbound Hello
            // gate); drop it to keep the state machine deterministic.
            MessagePayload::Hello(_) => {
                tracing::warn!(
                    replica = %self.replica_id,
                    from = %msg.from.as_u8(),
                    "Hello reached replica state machine; transport should have stripped it"
                );
                (self, ReplicaOutput::empty())
            }

            // Normal operation
            MessagePayload::Prepare(prepare) => self.on_prepare(msg.from, prepare),
            MessagePayload::PrepareOk(prepare_ok) => self.on_prepare_ok(msg.from, prepare_ok),
            MessagePayload::Commit(commit) => self.on_commit(msg.from, commit),
            MessagePayload::Heartbeat(heartbeat) => self.on_heartbeat(msg.from, heartbeat),

            // View change
            MessagePayload::StartViewChange(svc) => self.on_start_view_change(msg.from, svc),
            MessagePayload::DoViewChange(dvc) => self.on_do_view_change(msg.from, dvc),
            MessagePayload::StartView(sv) => self.on_start_view(msg.from, sv),

            // Recovery
            MessagePayload::RecoveryRequest(ref req) => self.on_recovery_request(msg.from, req),
            MessagePayload::RecoveryResponse(resp) => self.on_recovery_response(msg.from, resp),

            // Repair
            MessagePayload::RepairRequest(ref req) => self.on_repair_request(msg.from, req),
            MessagePayload::RepairResponse(ref resp) => self.on_repair_response(msg.from, resp),
            MessagePayload::Nack(nack) => self.on_nack(msg.from, nack),

            // State transfer
            MessagePayload::StateTransferRequest(ref req) => {
                self.on_state_transfer_request(msg.from, req)
            }
            MessagePayload::StateTransferResponse(resp) => {
                self.on_state_transfer_response(msg.from, resp)
            }

            // Write reorder repair
            MessagePayload::WriteReorderGapRequest(ref req) => {
                super::repair::on_write_reorder_gap_request(self, req)
            }
            MessagePayload::WriteReorderGapResponse(resp) => {
                super::repair::on_write_reorder_gap_response(self, &resp)
            }
        }
    }

    /// Handles a timeout event.
    pub(crate) fn on_timeout(self, kind: TimeoutKind) -> (Self, ReplicaOutput) {
        match kind {
            TimeoutKind::Heartbeat => self.on_heartbeat_timeout(),
            TimeoutKind::Prepare(op) => self.on_prepare_timeout(op),
            TimeoutKind::ViewChange => self.on_view_change_timeout(),
            TimeoutKind::Recovery => self.on_recovery_timeout(),
            TimeoutKind::ClockSync => self.on_clock_sync_timeout(),
            TimeoutKind::Ping => self.on_ping_timeout(),
            TimeoutKind::PrimaryAbdicate => self.on_primary_abdicate_timeout(),
            TimeoutKind::RepairSync => self.on_repair_sync_timeout(),
            TimeoutKind::CommitStall => self.on_commit_stall_timeout(),
            TimeoutKind::CommitMessage => self.on_commit_message_timeout(),
            TimeoutKind::StartViewChangeWindow => self.on_start_view_change_window_timeout(),
            TimeoutKind::Scrub => self.on_scrub_timeout(),
        }
    }

    /// Handles a client request (leader only).
    fn on_client_request(
        mut self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
        client_id: Option<crate::ClientId>,
        request_number: Option<u64>,
    ) -> (Self, ReplicaOutput) {
        // Only leader can accept client requests
        if !self.can_accept_requests() {
            // Queue for later if we might become leader
            self.pending_requests.push(PendingRequest {
                command,
                idempotency_id,
                client_id,
                request_number,
            });
            return (self, ReplicaOutput::empty());
        }

        // Check for duplicate request if client session info provided
        if let (Some(cid), Some(rnum)) = (client_id, request_number) {
            if let Some(session) = self.client_sessions.check_duplicate(cid, rnum) {
                // Duplicate request - return cached effects
                tracing::debug!(
                    client_id = %cid,
                    request_number = rnum,
                    committed_op = %session.committed_op,
                    "duplicate request detected, returning cached reply"
                );

                // Return cached effects from the original execution
                let output = ReplicaOutput {
                    messages: Vec::new(), // No protocol messages for duplicates
                    effects: session.cached_effects.clone(),
                    committed_op: Some(session.committed_op),
                };

                return (self, output);
            }
        }

        self.prepare_new_operation(command, idempotency_id, client_id, request_number)
    }

    /// Handles a cluster reconfiguration command (leader only).
    ///
    /// Initiates joint consensus to safely add/remove replicas without
    /// violating safety guarantees.
    ///
    /// # Safety
    ///
    /// - Only one reconfiguration at a time (rejects if already in joint state)
    /// - Only leader can initiate reconfigurations
    /// - Validates new configuration is valid (odd size, no duplicates)
    fn on_reconfig_command(
        mut self,
        cmd: crate::reconfiguration::ReconfigCommand,
    ) -> (Self, ReplicaOutput) {
        // Only leader can process reconfigurations
        if !self.is_leader() || self.status != ReplicaStatus::Normal {
            tracing::warn!(
                replica = %self.replica_id,
                status = ?self.status,
                "ignoring reconfiguration command, not leader in normal status"
            );
            return (self, ReplicaOutput::empty());
        }

        // Only one reconfiguration at a time
        if !self.reconfig_state.is_stable() {
            tracing::warn!(
                replica = %self.replica_id,
                "rejecting reconfiguration, already in joint consensus"
            );
            return (self, ReplicaOutput::empty());
        }

        // Validate the command
        let new_config = match cmd.validate(&self.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!(
                    replica = %self.replica_id,
                    error = e,
                    command = ?cmd,
                    "reconfiguration command validation failed"
                );
                return (self, ReplicaOutput::empty());
            }
        };

        tracing::info!(
            replica = %self.replica_id,
            command = %cmd.description(),
            old_size = self.config.cluster_size(),
            new_size = new_config.cluster_size(),
            "initiating cluster reconfiguration"
        );

        // Transition to joint consensus
        let joint_op = self.op_number.next();
        self.reconfig_state = crate::reconfiguration::ReconfigState::new_joint(
            self.config.clone(),
            new_config,
            joint_op,
        );

        // Prepare an empty append as a placeholder for the reconfiguration operation
        // The actual reconfiguration is carried in the Prepare message's reconfig field
        let placeholder_cmd = Command::AppendBatch {
            stream_id: kimberlite_types::StreamId::new(0),
            events: vec![],
            expected_offset: kimberlite_types::Offset::ZERO,
        };

        // Prepare operation with reconfiguration
        let op_number = self.op_number.next();
        self.op_number = op_number;

        let entry = LogEntry::new(op_number, self.view, placeholder_cmd, None, None, None);
        self.log.push(entry.clone());

        // Initialize prepare tracker
        let mut voters = HashSet::new();
        voters.insert(self.replica_id);
        self.prepare_ok_tracker.insert(op_number, voters);

        // Create Prepare with reconfiguration
        let prepare =
            Prepare::new_with_reconfig(self.view, op_number, entry, self.commit_number, cmd);

        // Record send time for clock synchronization RTT calculation
        let send_time = Clock::monotonic_nanos();
        self.prepare_send_times.insert(op_number, send_time);

        // Broadcast to all replicas (including new ones)
        let msg = self.sign_message(msg_broadcast(
            self.replica_id,
            MessagePayload::Prepare(prepare),
        ));

        // Check for immediate commit (single-node)
        let (state, mut output) = self.try_commit(op_number);
        output.messages.insert(0, msg);

        (state, output)
    }

    /// Applies a reconfiguration command received in a Prepare message (backup only).
    ///
    /// Called by backups when processing a Prepare message that contains a reconfig command.
    /// The leader has already validated the command and initiated joint consensus.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The reconfiguration command to apply
    /// * `joint_op` - The operation number where joint consensus begins
    ///
    /// # Returns
    ///
    /// Self with updated reconfiguration state.
    pub(crate) fn apply_reconfiguration_command(
        mut self,
        cmd: &crate::reconfiguration::ReconfigCommand,
        joint_op: OpNumber,
    ) -> Self {
        // Only process if currently in stable state
        if !self.reconfig_state.is_stable() {
            tracing::debug!(
                replica = %self.replica_id,
                "backup ignoring reconfiguration, already in joint consensus"
            );
            return self;
        }

        // Validate the command against current config
        let new_config = match cmd.validate(&self.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::error!(
                    replica = %self.replica_id,
                    error = e,
                    command = ?cmd,
                    "backup: reconfiguration command validation failed"
                );
                return self;
            }
        };

        tracing::info!(
            replica = %self.replica_id,
            command = %cmd.description(),
            joint_op = %joint_op,
            old_size = self.config.cluster_size(),
            new_size = new_config.cluster_size(),
            "backup applying cluster reconfiguration"
        );

        // Transition to joint consensus
        self.reconfig_state = crate::reconfiguration::ReconfigState::new_joint(
            self.config.clone(),
            new_config,
            joint_op,
        );

        self
    }

    /// Handles a periodic tick (for housekeeping).
    ///
    /// Called periodically to perform background maintenance:
    /// - Leader sends heartbeats to backups
    /// - Cleanup of old prepare tracking state
    fn on_tick(self) -> (Self, ReplicaOutput) {
        let mut output = ReplicaOutput::empty();

        // If we're leader and in normal operation, generate a heartbeat
        if self.is_leader() && self.status == ReplicaStatus::Normal {
            if let Some(heartbeat_msg) = self.generate_heartbeat() {
                output.messages.push(heartbeat_msg);
            }
        }

        // Clean up old prepare_ok_tracker entries for committed operations
        // (keeping only uncommitted operations to track)
        let mut state = self;
        let committed_op = state.commit_number.as_op_number();
        state.prepare_ok_tracker.retain(|&op, _| op > committed_op);

        (state, output)
    }

    // ========================================================================
    // Leader Operations
    // ========================================================================

    /// Prepares a new operation (leader only).
    #[allow(clippy::needless_pass_by_value)] // Command is cloned into LogEntry
    pub(crate) fn prepare_new_operation(
        mut self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
        client_id: Option<crate::ClientId>,
        request_number: Option<u64>,
    ) -> (Self, ReplicaOutput) {
        assert!(
            self.is_leader(),
            "only leader can prepare - replica {} is not leader in view {}",
            self.replica_id.as_u8(),
            self.view.as_u64()
        );
        assert!(
            self.status == ReplicaStatus::Normal,
            "must be in normal status to prepare - current status: {:?}",
            self.status
        );

        // Assign next op number
        let op_number = self.op_number.next();
        self.op_number = op_number;

        // Record prepare start time for latency tracking
        #[cfg(not(feature = "sim"))]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            self.prepare_start_times.insert(op_number, now);
        }

        // Record uncommitted session if client info provided
        if let (Some(cid), Some(rnum)) = (client_id, request_number) {
            if let Err(e) = self
                .client_sessions
                .record_uncommitted(cid, rnum, op_number)
            {
                tracing::warn!(
                    client_id = %cid,
                    request_number = rnum,
                    error = %e,
                    "failed to record uncommitted session"
                );
            }
        }

        // Create log entry with client session info
        let entry = LogEntry::new(
            op_number,
            self.view,
            command.clone(),
            idempotency_id,
            client_id,
            request_number,
        );

        // Add to log
        self.log.push(entry.clone());

        // Initialize prepare tracker (leader counts itself)
        let mut voters = HashSet::new();
        voters.insert(self.replica_id);
        self.prepare_ok_tracker.insert(op_number, voters);

        // Create Prepare message
        let prepare = Prepare::new(self.view, op_number, entry, self.commit_number);

        // Record send time for clock synchronization RTT calculation
        let send_time = Clock::monotonic_nanos();
        self.prepare_send_times.insert(op_number, send_time);

        // Broadcast to all backups
        let msg = self.sign_message(msg_broadcast(
            self.replica_id,
            MessagePayload::Prepare(prepare),
        ));

        // Check if we already have quorum (single-node case)
        let (state, mut output) = self.try_commit(op_number);

        // Add the prepare message
        output.messages.insert(0, msg);

        (state, output)
    }

    /// Tries to commit operations up to the given op number.
    ///
    /// Returns the new state and any effects from committing.
    pub(crate) fn try_commit(mut self, up_to: OpNumber) -> (Self, ReplicaOutput) {
        let mut output = ReplicaOutput::empty();
        let quorum = self.reconfig_state.quorum_size();

        // Find operations that have quorum
        while self.commit_number.as_op_number() < up_to {
            let next_commit = self.commit_number.as_op_number().next();

            // Check if we have quorum for this operation
            let votes = self
                .prepare_ok_tracker
                .get(&next_commit)
                .map_or(0, std::collections::HashSet::len);

            if votes < quorum {
                break; // Don't have quorum yet
            }

            // DST: quorum requirement must be met before committing
            kimberlite_properties::always!(
                votes >= quorum,
                "vsr.commit_quorum_met",
                "operation must have quorum of PrepareOK before committing"
            );

            // Commit this operation
            let (new_self, commit_output) = self.commit_operation(next_commit);
            self = new_self;
            output.merge(commit_output);
        }

        // Invariant check after all commits
        assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "commit_number must not exceed op_number: commit={} > op={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        (self, output)
    }

    /// Commits a single operation and applies it to the kernel.
    fn commit_operation(mut self, op: OpNumber) -> (Self, ReplicaOutput) {
        assert!(
            op == self.commit_number.as_op_number().next(),
            "must commit operations in sequential order: expected {}, got {}",
            self.commit_number.as_op_number().next().as_u64(),
            op.as_u64()
        );

        // Get the log entry
        let entry = self
            .log_entry(op)
            .expect("log entry must exist for commit")
            .clone();

        // Apply to kernel
        let result = apply_committed(self.kernel_state.clone(), entry.command);

        match result {
            Ok((new_kernel_state, effects)) => {
                self.kernel_state = new_kernel_state;
                self.commit_number = CommitNumber::new(op);

                // Safety invariant: commit_number ≤ op_number (VSR CommitBound).
                // Spec: specs/tla/VSR.cfg::CommitNotExceedOp (INVARIANT).
                // Promoted from debug_assert to production assert 2026-04-17 as
                // part of the FV-EPYC gap-closure — a commit > op is always a
                // consensus-safety bug and must crash loudly rather than
                // silently proceed.
                assert!(
                    self.commit_number.as_op_number() <= self.op_number,
                    "VSR CommitBound violated: commit={} > op={}",
                    self.commit_number.as_u64(),
                    self.op_number.as_u64()
                );

                // Record committed session if client info present
                if let (Some(cid), Some(rnum)) = (entry.client_id, entry.request_number) {
                    // Get synchronized timestamp if available, otherwise use 0
                    #[allow(clippy::cast_sign_loss)]
                    let commit_timestamp = self
                        .clock
                        .realtime_synchronized()
                        .map_or(kimberlite_types::Timestamp::from(0), |ts| {
                            kimberlite_types::Timestamp::from(ts as u64)
                        });

                    if let Err(e) = self.client_sessions.commit_request(
                        cid,
                        rnum,
                        op,
                        op,              // reply_op same as committed_op for now
                        effects.clone(), // Cache effects for idempotent retry
                        commit_timestamp,
                    ) {
                        tracing::warn!(
                            client_id = %cid,
                            request_number = rnum,
                            error = %e,
                            "failed to commit client session"
                        );
                    }
                }

                // Clean up prepare tracker
                self.prepare_ok_tracker.remove(&op);

                // Check if we should transition from joint consensus to stable
                if self
                    .reconfig_state
                    .ready_to_transition(self.commit_number.as_op_number())
                {
                    tracing::info!(
                        replica = %self.replica_id,
                        joint_op = %self.reconfig_state.joint_op().expect("invariant: reconfig_state is Joint here — ready_to_transition() gate above"),
                        commit_number = %self.commit_number,
                        "transitioning from joint consensus to new stable configuration"
                    );

                    // Get the new configuration before transitioning
                    let (_, new_config_opt) = self.reconfig_state.configs();
                    let new_config = new_config_opt
                        .expect("joint state must have new config")
                        .clone();

                    // Transition to new stable state
                    self.reconfig_state.transition_to_new();

                    // Update our cluster configuration to match
                    self.config = new_config;

                    tracing::info!(
                        replica = %self.replica_id,
                        new_cluster_size = self.config.cluster_size(),
                        "reconfiguration complete, now in stable state"
                    );
                }

                // Record prepare latency (prepare send → quorum achieved)
                #[cfg(not(feature = "sim"))]
                if let Some(start_time) = self.prepare_start_times.remove(&op) {
                    use std::time::{Duration, SystemTime, UNIX_EPOCH};
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let elapsed_ns = now.saturating_sub(start_time);
                    crate::instrumentation::METRICS
                        .record_prepare_latency(Duration::from_nanos(elapsed_ns as u64));
                }

                // Create commit message for backups
                let commit_msg = self.sign_message(msg_broadcast(
                    self.replica_id,
                    MessagePayload::Commit(crate::Commit::new(self.view, self.commit_number)),
                ));

                let output = ReplicaOutput::with_messages_and_effects(vec![commit_msg], effects)
                    .with_committed(op);

                (self, output)
            }
            Err(e) => {
                // Kernel error - this shouldn't happen for valid commands
                // In production, we'd need to handle this gracefully
                tracing::error!(error = %e, op = %op, "kernel error during commit");
                (self, ReplicaOutput::empty())
            }
        }
    }

    // ========================================================================
    // State Management
    // ========================================================================

    /// Transitions to a new view.
    pub(crate) fn transition_to_view(mut self, new_view: ViewNumber) -> Self {
        assert!(
            new_view > self.view,
            "view number must increase monotonically: current={}, new={}",
            self.view.as_u64(),
            new_view.as_u64()
        );

        // DST: view monotonicity — fundamental VSR safety property
        kimberlite_properties::always!(
            new_view > self.view,
            "vsr.view_monotonicity",
            "view number must strictly increase on transition"
        );

        if self.status == ReplicaStatus::Normal {
            self.last_normal_view = self.view;
        }

        self.view = new_view;
        self.status = ReplicaStatus::ViewChange;

        // Prune replay detection tracker for old views (AUDIT-2026-03 M-6)
        // Keep 2 views of history to prevent replay of recently-pruned messages.
        // Keeping only 1 view (new_view - 1) discards the just-transitioned-FROM
        // view immediately, allowing replay of messages from that view.
        let min_view = if new_view.as_u64() > 1 {
            ViewNumber::new(new_view.as_u64() - 2)
        } else {
            ViewNumber::ZERO
        };
        self.message_dedup_tracker.prune_old_views(min_view);

        // Record view change start time for latency tracking
        #[cfg(not(feature = "sim"))]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            self.view_change_start_time = Some(now);
        }

        // Clear view change state
        self.start_view_change_votes.clear();
        self.do_view_change_msgs.clear();
        self.prepare_ok_tracker.clear();

        // Discard uncommitted client sessions (VRR paper bug fix)
        // New leader doesn't have uncommitted state from old leader,
        // so we must discard to prevent client lockout
        self.client_sessions.discard_uncommitted();

        self
    }

    /// Enters normal operation in the current view.
    pub(crate) fn enter_normal_status(mut self) -> Self {
        // DST: commit never exceeds op_number when entering normal status
        kimberlite_properties::always!(
            self.commit_number.as_op_number() <= self.op_number,
            "vsr.commit_le_op_on_enter_normal",
            "commit_number must not exceed op_number when entering normal status"
        );

        self.status = ReplicaStatus::Normal;
        self.last_normal_view = self.view;

        // Record view change latency (ViewChange → Normal)
        #[cfg(not(feature = "sim"))]
        if let Some(start_time) = self.view_change_start_time.take() {
            use std::time::{Duration, SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let elapsed_ns = now.saturating_sub(start_time);
            crate::instrumentation::METRICS
                .record_view_change_latency(Duration::from_nanos(elapsed_ns as u64));
        }

        // Clear view change state
        self.start_view_change_votes.clear();
        self.do_view_change_msgs.clear();

        self
    }

    /// Returns the log tail from `commit_number+1` to `op_number`.
    pub(crate) fn log_tail(&self) -> Vec<LogEntry> {
        let start = self.commit_number.as_u64() as usize;
        self.log[start..].to_vec()
    }

    /// Calculates max achievable commit from `DoViewChange` messages.
    ///
    /// Uses multi-source approach: tail ops, pipeline bounds, explicit commits.
    /// Implements "intersection property" - all possibly-committed ops survive.
    /// Inspired by `TigerBeetle`'s VSR implementation.
    pub(crate) fn calculate_max_achievable_commit(&self, best_op_number: OpNumber) -> CommitNumber {
        let mut max_commit = self.commit_number.as_u64();

        // Source 1: Examine DoViewChange messages for valid claims
        for dvc in &self.do_view_change_msgs {
            // Only trust commits that don't exceed replica's op_number
            if dvc.commit_number.as_u64() <= dvc.op_number.as_u64() {
                max_commit = max_commit.max(dvc.commit_number.as_u64());
            } else {
                tracing::warn!(
                    replica = %dvc.replica,
                    claimed_commit = %dvc.commit_number,
                    op_number = %dvc.op_number,
                    "ignoring inflated commit_number"
                );
            }

            // Source 2: Log tail - last op might be committed
            if let Some(last_entry) = dvc.log_tail.last() {
                max_commit = max_commit.max(last_entry.op_number.as_u64());
            }
        }

        // Source 3: Pipeline bounds (conservative estimate)
        // Use configured max_pipeline_depth instead of hardcoded constant
        let pipeline_size = self.config.max_pipeline_depth;
        if best_op_number.as_u64() > pipeline_size {
            let pipeline_bound = best_op_number.as_u64() - pipeline_size;
            max_commit = max_commit.max(pipeline_bound);
        }

        // CRITICAL: Never exceed op_number we're installing
        max_commit = max_commit.min(best_op_number.as_u64());

        // CRITICAL: Monotonic advance only
        max_commit = max_commit.max(self.commit_number.as_u64());

        let result = CommitNumber::new(OpNumber::new(max_commit));

        // Post-condition assertions
        debug_assert!(
            result.as_op_number() <= best_op_number,
            "calculated commit {} exceeds op {}",
            result.as_u64(),
            best_op_number.as_u64()
        );
        debug_assert!(
            result >= self.commit_number,
            "calculated commit {} < current commit {}",
            result.as_u64(),
            self.commit_number.as_u64()
        );

        result
    }

    /// Adds entries to the log, replacing any conflicting entries.
    ///
    /// CRITICAL: Never replaces committed entries (those where op <= `commit_number`).
    /// Committed entries are immutable - we verify they match but don't overwrite.
    pub(crate) fn merge_log_tail(mut self, entries: Vec<LogEntry>) -> Self {
        // Validate entries are in order (Byzantine protection)
        for window in entries.windows(2) {
            if window[0].op_number >= window[1].op_number {
                tracing::error!(
                    prev_op = %window[0].op_number,
                    next_op = %window[1].op_number,
                    "log entries not in ascending order - Byzantine attack detected"
                );

                #[cfg(feature = "sim")]
                crate::instrumentation::record_byzantine_rejection(
                    "log_ordering_violation",
                    self.replica_id,
                    window[1].op_number.as_u64(),
                    window[0].op_number.as_u64(),
                );

                return self; // Reject entire batch
            }
        }

        for entry in entries {
            let index = entry.op_number.as_u64().saturating_sub(1) as usize;

            match index.cmp(&self.log.len()) {
                std::cmp::Ordering::Less => {
                    // Check if entry is committed before replacing
                    let entry_op_number = OpNumber::new(index as u64 + 1);
                    let is_committed = entry_op_number <= self.commit_number.as_op_number();

                    if is_committed {
                        // Committed entry - verify match, don't replace
                        let existing = &self.log[index];
                        if existing.op_number != entry.op_number || existing.view != entry.view {
                            tracing::error!(
                                op = %entry.op_number,
                                commit = %self.commit_number,
                                existing_view = %existing.view,
                                new_view = %entry.view,
                                "attempted to overwrite committed entry with different data"
                            );
                            continue; // Skip - committed entries are immutable
                        }
                        // Entry matches, no need to replace (idempotent)
                    } else {
                        // Uncommitted entry - safe to replace
                        self.log[index] = entry;
                    }
                }
                std::cmp::Ordering::Equal => {
                    // Append new entry
                    self.log.push(entry);
                }
                std::cmp::Ordering::Greater => {
                    // Gap in log - shouldn't happen in normal operation
                    tracing::warn!(
                        expected = self.log.len(),
                        got = index,
                        "gap in log during merge"
                    );
                }
            }

            // Update op_number if needed
            let entry_op = OpNumber::new(index as u64 + 1);
            if entry_op > self.op_number {
                self.op_number = entry_op;
            }
        }

        // Final invariant check
        debug_assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "merge: commit={} > op={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        self
    }

    /// Applies committed entries to the kernel up to the given commit number.
    pub(crate) fn apply_commits_up_to(mut self, new_commit: CommitNumber) -> (Self, Vec<Effect>) {
        let mut all_effects = Vec::new();
        // Captured for the `always!` monotonicity check below. When property
        // macros are compiled to no-ops this variable is unused; the
        // `#[allow(unused_variables)]` keeps clippy quiet in that build mode.
        #[allow(unused_variables)]
        let initial_commit = self.commit_number;

        while self.commit_number < new_commit {
            let next_op = self.commit_number.as_op_number().next();

            if let Some(entry) = self.log_entry(next_op).cloned() {
                match apply_committed(self.kernel_state.clone(), entry.command) {
                    Ok((new_state, effects)) => {
                        self.kernel_state = new_state;
                        self.commit_number = CommitNumber::new(next_op);
                        all_effects.extend(effects);

                        // Record successful operation
                        crate::instrumentation::METRICS.increment_operations();
                        crate::instrumentation::METRICS
                            .set_commit_number(self.commit_number.as_u64());

                        // Invariant check after each commit
                        debug_assert!(
                            self.commit_number.as_op_number() <= self.op_number,
                            "commit_number={} exceeded op_number={}",
                            self.commit_number.as_u64(),
                            self.op_number.as_u64()
                        );
                    }
                    Err(e) => {
                        // Kernel errors during commit are serious - they indicate:
                        // 1. Byzantine leader sent invalid command
                        // 2. State corruption
                        // 3. Bug in kernel logic
                        //
                        // All kernel errors are deterministic (no transient failures),
                        // so we log, instrument, and halt catchup to prevent further damage.
                        tracing::error!(
                            error = %e,
                            op = %next_op,
                            current_commit = %self.commit_number,
                            target_commit = %new_commit,
                            "Byzantine command detected during commit catchup - halting"
                        );

                        // Record failed operation
                        crate::instrumentation::METRICS.increment_operations_failed();

                        // Record Byzantine detection for simulation testing
                        #[cfg(feature = "sim")]
                        crate::instrumentation::record_byzantine_rejection(
                            "invalid_kernel_command",
                            self.replica_id, // Self, because we're applying our own log
                            next_op.as_u64(),
                            self.commit_number.as_u64(),
                        );

                        // Don't advance commit_number - we didn't apply this op
                        // Halt catchup to prevent cascade of failures
                        break;
                    }
                }
            } else {
                tracing::warn!(
                    op = %next_op,
                    current_commit = %self.commit_number,
                    target_commit = %new_commit,
                    op_number = %self.op_number,
                    "missing log entry during catchup"
                );
                break; // Don't advance commit_number past what we can apply
            }
        }

        // Final invariant check
        debug_assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "final: commit_number={} > op_number={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        // DST: commit monotonicity — commit_number can only advance
        kimberlite_properties::always!(
            self.commit_number >= initial_commit,
            "vsr.commit_monotonicity",
            "commit_number must never decrease during apply_commits_up_to"
        );
        // DST: commit-op ordering — fundamental VSR safety
        kimberlite_properties::always!(
            self.commit_number.as_op_number() <= self.op_number,
            "vsr.commit_le_op_after_apply",
            "commit_number must not exceed op_number after applying commits"
        );

        (self, all_effects)
    }

    // ========================================================================
    // Crash Injection (simulation only)
    // ========================================================================

    /// Simulates a replica crash by discarding all transient in-memory state
    /// and transitioning to `Recovering` status.
    ///
    /// After this call the replica is in the same state as a freshly restarted
    /// process: it knows what it committed (durable log up to `commit_number`)
    /// but has lost all in-flight prepares and view-change votes.  The caller
    /// should then fire `TimeoutKind::Recovery` to trigger `start_recovery()`,
    /// which broadcasts a `RecoveryRequest` and drives the full quorum path.
    ///
    /// # Safety
    ///
    /// Only available under `cfg(any(test, feature = "sim"))`.  Must never be
    /// called in production code — crashes should be modelled by process
    /// termination, not by mutating live state.
    #[cfg(any(test, feature = "sim"))]
    fn handle_crash(mut self) -> Self {
        // Increment generation so recovery responses from this attempt are
        // distinguishable from any lingering responses to a prior generation.
        self.generation = self.generation.next();

        // Discard all uncommitted log entries — only committed entries are
        // durable (in a real system these would survive on disk, but the
        // sim uses in-memory storage so we truncate to commit_number).
        let committed_len = self.commit_number.as_u64() as usize;
        self.log.truncate(committed_len);
        self.op_number = self.commit_number.as_op_number();

        // Clear all transient in-flight state.
        self.prepare_ok_tracker.clear();
        self.pending_requests.clear();
        self.start_view_change_votes.clear();
        self.do_view_change_msgs.clear();
        self.recovery_state = None;
        self.repair_state = None;
        self.state_transfer_state = None;
        self.reorder_buffer.clear();
        self.reorder_deadlines.clear();
        self.prepare_send_times.clear();
        self.message_dedup_tracker = MessageDedupTracker::new();

        // Transition to Recovering so start_recovery() will run on the
        // next TimeoutKind::Recovery event.
        self.status = ReplicaStatus::Recovering;

        debug_assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "handle_crash: commit_number={} > op_number={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_types::{DataClass, Placement};

    fn test_config_3() -> ClusterConfig {
        ClusterConfig::new(vec![
            ReplicaId::new(0),
            ReplicaId::new(1),
            ReplicaId::new(2),
        ])
    }

    fn test_command() -> Command {
        Command::create_stream_with_auto_id("test".into(), DataClass::Public, Placement::Global)
    }

    #[test]
    fn new_replica_state() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        assert_eq!(state.replica_id(), ReplicaId::new(0));
        assert_eq!(state.view(), ViewNumber::ZERO);
        assert_eq!(state.status(), ReplicaStatus::Normal);
        assert_eq!(state.op_number(), OpNumber::ZERO);
        assert_eq!(state.commit_number(), CommitNumber::ZERO);
        assert!(state.is_leader()); // Replica 0 is leader for view 0
    }

    #[test]
    fn leader_determination() {
        let config = test_config_3();

        let r0 = ReplicaState::new(ReplicaId::new(0), config.clone());
        let r1 = ReplicaState::new(ReplicaId::new(1), config.clone());
        let r2 = ReplicaState::new(ReplicaId::new(2), config);

        // In view 0, replica 0 is leader
        assert!(r0.is_leader());
        assert!(!r1.is_leader());
        assert!(!r2.is_leader());

        // Transition to view 1
        let r0 = r0.transition_to_view(ViewNumber::new(1));
        let r1 = r1.transition_to_view(ViewNumber::new(1));

        // In view 1, replica 1 is leader
        assert!(!r0.is_leader());
        assert!(r1.is_leader());
    }

    #[test]
    fn is_acting_leader_false_during_view_change() {
        // `is_leader()` is a pure view-table lookup, so during a view
        // change the incoming primary already answers `true` even though
        // its status is `ViewChange`. `is_acting_leader()` is the strict
        // predicate observability + submit-side gating should use: it
        // requires `Normal` status, so it stays `false` until the new
        // primary lands `StartView`. This pins the contract the
        // `kimberlite_is_leader` gauge depends on.
        let config = test_config_3();
        let r1 = ReplicaState::new(ReplicaId::new(1), config);
        // View 0: replica 1 is a follower. Neither predicate fires.
        assert!(!r1.is_leader());
        assert!(!r1.is_acting_leader());

        // View 1: replica 1 owns the view but status is ViewChange.
        let r1 = r1.transition_to_view(ViewNumber::new(1));
        assert_eq!(r1.status(), ReplicaStatus::ViewChange);
        assert!(r1.is_leader(), "view-table says yes");
        assert!(
            !r1.is_acting_leader(),
            "but is_acting_leader must reject ViewChange"
        );
        assert!(
            !r1.can_accept_requests(),
            "and can_accept_requests must agree"
        );
    }

    #[test]
    fn is_acting_leader_true_after_view_settles() {
        // Sanity counterpart to `is_acting_leader_false_during_view_change`:
        // once we restore Normal status (e.g. after `StartView` lands),
        // the strict predicate flips true on the view-table leader.
        let config = test_config_3();
        let mut r1 =
            ReplicaState::new(ReplicaId::new(1), config).transition_to_view(ViewNumber::new(1));
        // Hand-restore Normal — the real protocol path runs through
        // start_view machinery, but the predicate only reads `status`.
        r1.status = ReplicaStatus::Normal;

        assert!(r1.is_leader());
        assert!(r1.is_acting_leader());
        assert!(r1.can_accept_requests());
    }

    #[test]
    fn prepare_new_operation() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        let (state, output) = state.prepare_new_operation(test_command(), None, None, None);

        assert_eq!(state.op_number(), OpNumber::new(1));
        assert_eq!(state.log_len(), 1);
        assert!(!output.messages.is_empty()); // Should have Prepare broadcast
    }

    #[test]
    fn log_entry_retrieval() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        let (state, _) = state.prepare_new_operation(test_command(), None, None, None);

        let entry = state.log_entry(OpNumber::new(1));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().op_number, OpNumber::new(1));

        // Op 0 should return None
        assert!(state.log_entry(OpNumber::ZERO).is_none());

        // Op 2 doesn't exist yet
        assert!(state.log_entry(OpNumber::new(2)).is_none());
    }

    #[test]
    fn view_transition() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        assert_eq!(state.status(), ReplicaStatus::Normal);

        let state = state.transition_to_view(ViewNumber::new(1));

        assert_eq!(state.view(), ViewNumber::new(1));
        assert_eq!(state.status(), ReplicaStatus::ViewChange);
        assert_eq!(state.last_normal_view, ViewNumber::ZERO);
    }

    #[test]
    fn enter_normal_status() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        let state = state.transition_to_view(ViewNumber::new(1));
        assert_eq!(state.status(), ReplicaStatus::ViewChange);

        let state = state.enter_normal_status();
        assert_eq!(state.status(), ReplicaStatus::Normal);
        assert_eq!(state.last_normal_view, ViewNumber::new(1));
    }

    // ========================================================================
    // Message Replay Protection Tests (AUDIT-2026-03 M-6)
    // ========================================================================

    #[test]
    fn message_dedup_tracker_accepts_first_message() {
        let mut tracker = MessageDedupTracker::new();
        let msg_id = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));

        // First message should be accepted
        assert!(tracker.check_and_record(msg_id).is_ok());
        assert_eq!(tracker.tracked_count(), 1);
        assert_eq!(tracker.replay_attempts(), 0);
    }

    #[test]
    fn message_dedup_tracker_rejects_duplicate() {
        let mut tracker = MessageDedupTracker::new();
        let msg_id = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));

        // First message should be accepted
        assert!(tracker.check_and_record(msg_id).is_ok());

        // Duplicate should be rejected
        assert!(tracker.check_and_record(msg_id).is_err());
        assert_eq!(tracker.tracked_count(), 1); // Still only one tracked
        assert_eq!(tracker.replay_attempts(), 1); // Replay detected
    }

    #[test]
    fn message_dedup_tracker_tracks_different_messages() {
        let mut tracker = MessageDedupTracker::new();

        let msg1 = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let msg2 = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(2));
        let msg3 = MessageId::prepare(ReplicaId::new(2), ViewNumber::ZERO, OpNumber::new(1));

        // All different messages should be accepted
        assert!(tracker.check_and_record(msg1).is_ok());
        assert!(tracker.check_and_record(msg2).is_ok());
        assert!(tracker.check_and_record(msg3).is_ok());

        assert_eq!(tracker.tracked_count(), 3);
        assert_eq!(tracker.replay_attempts(), 0);
    }

    #[test]
    fn message_dedup_tracker_prunes_old_views() {
        let mut tracker = MessageDedupTracker::new();

        // Add messages from views 0, 1, 2
        let msg_v0 = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let msg_v1 = MessageId::prepare(ReplicaId::new(1), ViewNumber::new(1), OpNumber::new(1));
        let msg_v2 = MessageId::prepare(ReplicaId::new(1), ViewNumber::new(2), OpNumber::new(1));

        tracker.check_and_record(msg_v0).unwrap();
        tracker.check_and_record(msg_v1).unwrap();
        tracker.check_and_record(msg_v2).unwrap();

        assert_eq!(tracker.tracked_count(), 3);

        // Prune views < 2 (keeps only view 2)
        tracker.prune_old_views(ViewNumber::new(2));
        assert_eq!(tracker.tracked_count(), 1);

        // msg_v2 should still be tracked (rejected as duplicate)
        assert!(tracker.check_and_record(msg_v2).is_err());

        // msg_v0 and msg_v1 should be pruned (accepted as new)
        assert!(tracker.check_and_record(msg_v0).is_ok());
        assert!(tracker.check_and_record(msg_v1).is_ok());
    }

    #[test]
    fn message_dedup_tracker_handles_multiple_message_types() {
        let mut tracker = MessageDedupTracker::new();

        let prepare = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let prepare_ok =
            MessageId::prepare_ok(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let commit = MessageId::commit(ReplicaId::new(1), ViewNumber::ZERO, CommitNumber::ZERO);
        let heartbeat =
            MessageId::heartbeat(ReplicaId::new(1), ViewNumber::ZERO, CommitNumber::ZERO);

        // All different message types should be tracked independently
        assert!(tracker.check_and_record(prepare).is_ok());
        assert!(tracker.check_and_record(prepare_ok).is_ok());
        assert!(tracker.check_and_record(commit).is_ok());
        assert!(tracker.check_and_record(heartbeat).is_ok());

        assert_eq!(tracker.tracked_count(), 4);

        // Duplicates should be rejected
        assert!(tracker.check_and_record(prepare).is_err());
        assert!(tracker.check_and_record(prepare_ok).is_err());
        assert!(tracker.check_and_record(commit).is_err());
        assert!(tracker.check_and_record(heartbeat).is_err());

        assert_eq!(tracker.replay_attempts(), 4);
    }

    #[test]
    fn message_id_equality_by_type() {
        // Same sender, view, op_number, but different types
        let prepare = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let prepare_ok =
            MessageId::prepare_ok(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));

        // Should be different message IDs
        assert_ne!(prepare, prepare_ok);
        assert_ne!(prepare.msg_type, prepare_ok.msg_type);
    }

    #[test]
    fn replica_state_initializes_dedup_tracker() {
        let config = test_config_3();
        let state = ReplicaState::new(ReplicaId::new(0), config);

        // Dedup tracker should be initialized
        assert_eq!(state.message_dedup_tracker.tracked_count(), 0);
        assert_eq!(state.message_dedup_tracker.replay_attempts(), 0);
    }

    #[test]
    fn transition_to_view_prunes_dedup_tracker() {
        let config = test_config_3();
        let mut state = ReplicaState::new(ReplicaId::new(0), config);

        // Manually add messages from different views to the dedup tracker.
        // The pruning policy keeps 2 views of history (current_view - 2) to
        // prevent replay of recently-pruned messages during view transitions.
        let msg_v0 = MessageId::prepare(ReplicaId::new(1), ViewNumber::ZERO, OpNumber::new(1));
        let msg_v1 = MessageId::prepare(ReplicaId::new(1), ViewNumber::new(1), OpNumber::new(1));
        let msg_v2 = MessageId::prepare(ReplicaId::new(1), ViewNumber::new(2), OpNumber::new(1));

        state
            .message_dedup_tracker
            .check_and_record(msg_v0)
            .unwrap();
        assert_eq!(state.message_dedup_tracker.tracked_count(), 1);

        // Transition to view 1: min_view = max(0, 1-2) = 0 → all messages retained
        state = state.transition_to_view(ViewNumber::new(1));
        assert_eq!(
            state.message_dedup_tracker.tracked_count(),
            1,
            "view 0 msg retained after transition to view 1"
        );

        // Add message from view 1
        state
            .message_dedup_tracker
            .check_and_record(msg_v1)
            .unwrap();
        assert_eq!(state.message_dedup_tracker.tracked_count(), 2);

        // Transition to view 2: min_view = 2-2 = 0 → both view 0 and view 1 retained
        state = state.transition_to_view(ViewNumber::new(2));
        assert_eq!(
            state.message_dedup_tracker.tracked_count(),
            2,
            "both view 0 and view 1 msgs retained after transition to view 2"
        );

        // Add message from view 2
        state
            .message_dedup_tracker
            .check_and_record(msg_v2)
            .unwrap();
        assert_eq!(state.message_dedup_tracker.tracked_count(), 3);

        // Transition to view 3: min_view = 3-2 = 1 → view 0 pruned, views 1 and 2 retained
        state = state.transition_to_view(ViewNumber::new(3));
        assert_eq!(
            state.message_dedup_tracker.tracked_count(),
            2,
            "view 0 pruned after transition to view 3; views 1 and 2 retained"
        );
    }
}
