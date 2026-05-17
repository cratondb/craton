//! Event loop driver for VSR multi-node replication.
//!
//! This module provides a mio-based event loop that drives the `ReplicaState`
//! state machine with network events and timeouts.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         EventLoop                                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  1. Poll transport for messages                                  │
//! │  2. Check timeouts (heartbeat, prepare, view change)            │
//! │  3. Process pending client requests                              │
//! │  4. Drive ReplicaState::process() for each event                │
//! │  5. Send outgoing messages via transport                        │
//! │  6. Update superblock on state changes                          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Threading Model
//!
//! The event loop runs in a dedicated thread, separate from client I/O.
//! Communication with the main server thread is via channels:
//! - `command_tx`: Send commands to the replicator
//! - `result_rx`: Receive results from committed commands

use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;

use kimberlite_kernel::{Command, Effect, State};
use kimberlite_types::IdempotencyId;
use tracing::{debug, info, trace, warn};

use crate::VsrError;
use crate::config::{ClusterConfig, TimeoutConfig};
use crate::message::{Message, MessagePayload};
use crate::replica::{ReplicaEvent, ReplicaOutput, ReplicaState, TimeoutKind};
use crate::superblock::Superblock;
use crate::tcp_transport::TcpTransport;
use crate::transport::Transport;
use crate::types::{CommitNumber, OpNumber, ReplicaId, ReplicaStatus, ViewNumber};

// ============================================================================
// Event Loop Configuration
// ============================================================================

/// Configuration for the event loop.
#[derive(Debug, Clone)]
pub struct EventLoopConfig {
    /// Timeout configuration.
    pub timeouts: TimeoutConfig,
    /// How often to poll the transport (microseconds).
    pub poll_interval: Duration,
    /// Maximum commands to process per iteration.
    pub max_commands_per_tick: usize,
}

impl Default for EventLoopConfig {
    fn default() -> Self {
        Self {
            timeouts: TimeoutConfig::development(),
            poll_interval: Duration::from_millis(1),
            max_commands_per_tick: 100,
        }
    }
}

impl EventLoopConfig {
    /// Creates a configuration for production use.
    pub fn production() -> Self {
        Self {
            timeouts: TimeoutConfig::production(),
            poll_interval: Duration::from_millis(1),
            max_commands_per_tick: 1000,
        }
    }

    /// Creates a configuration for development/testing.
    pub fn development() -> Self {
        Self::default()
    }
}

// ============================================================================
// Commands and Results
// ============================================================================

/// Commands that can be sent to the event loop.
#[derive(Debug)]
pub enum EventLoopCommand {
    /// Submit a client request.
    Submit {
        command: Command,
        idempotency_id: Option<IdempotencyId>,
        result_tx: SyncSender<Result<SubmitResponse, VsrError>>,
    },
    /// Request a snapshot clone of the current kernel state. Cheap for small
    /// state (chaos probes use one stream); O(stream_count) otherwise.
    SnapshotKernelState { result_tx: SyncSender<State> },
    /// Shutdown the event loop.
    Shutdown,
}

/// Response from a successful command submission.
#[derive(Debug)]
pub struct SubmitResponse {
    /// The operation number assigned.
    pub op_number: OpNumber,
    /// Effects produced by the kernel.
    pub effects: Vec<Effect>,
    /// Whether this was a duplicate (idempotency hit).
    pub was_duplicate: bool,
}

/// A committed operation — broadcast to any subscriber registered via
/// [`EventLoopHandle::subscribe_applied_commits`]. Fires on every replica
/// (leader AND follower) whenever `commit_number` advances, enabling
/// observers like the chaos probe log to stay consistent across the
/// cluster without depending on the `Kimberlite` projection.
#[derive(Debug, Clone)]
pub struct AppliedCommit {
    pub op: OpNumber,
    pub effects: Vec<Effect>,
}

/// A committed command — broadcast to any subscriber registered via
/// [`EventLoopHandle::subscribe_applied_commands`]. Separate from
/// [`AppliedCommit`] because the projection-applier (which drives
/// `Kimberlite::submit` on non-leader replicas) needs the original
/// command, not its effects. Keeping the channels independent avoids
/// forcing chaos observers to pay the cost of a per-commit `Command`
/// clone they never look at.
#[derive(Debug, Clone)]
pub struct AppliedCommand {
    pub op: OpNumber,
    pub command: Command,
}

// ============================================================================
// Shared State
// ============================================================================

/// State shared between the event loop and external callers.
#[derive(Debug, Clone)]
pub struct SharedState {
    /// Current view number.
    pub view: ViewNumber,
    /// Current commit number.
    pub commit_number: CommitNumber,
    /// Current replica status.
    pub status: ReplicaStatus,
    /// Whether this replica is the leader.
    pub is_leader: bool,
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Current leader's replica ID (if known).
    pub leader_id: Option<ReplicaId>,
    /// Bootstrap phase completed.
    pub bootstrap_complete: bool,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            view: ViewNumber::ZERO,
            commit_number: CommitNumber::ZERO,
            status: ReplicaStatus::Normal,
            is_leader: false,
            connected_peers: 0,
            leader_id: None,
            bootstrap_complete: false,
        }
    }
}

// ============================================================================
// Timeout Tracker
// ============================================================================

/// Tracks and manages protocol timeouts.
struct TimeoutTracker {
    config: TimeoutConfig,
    /// Last time we received a heartbeat from the leader.
    last_heartbeat: Instant,
    /// Pending prepare timeouts: `op_number` -> deadline.
    prepare_deadlines: HashMap<OpNumber, Instant>,
    /// View change deadline (if in view change).
    view_change_deadline: Option<Instant>,
    /// Recovery deadline (if recovering).
    recovery_deadline: Option<Instant>,
}

impl TimeoutTracker {
    fn new(config: TimeoutConfig) -> Self {
        Self {
            config,
            last_heartbeat: Instant::now(),
            prepare_deadlines: HashMap::new(),
            view_change_deadline: None,
            recovery_deadline: None,
        }
    }

    /// Resets the heartbeat timer.
    fn reset_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Starts tracking a prepare timeout.
    fn start_prepare(&mut self, op: OpNumber) {
        let deadline = Instant::now() + self.config.prepare_timeout;
        self.prepare_deadlines.insert(op, deadline);
    }

    /// Cancels a prepare timeout.
    fn cancel_prepare(&mut self, op: OpNumber) {
        self.prepare_deadlines.remove(&op);
    }

    /// Starts view change timeout.
    #[allow(dead_code)]
    fn start_view_change(&mut self) {
        self.view_change_deadline = Some(Instant::now() + self.config.view_change_timeout);
    }

    /// Cancels view change timeout.
    #[allow(dead_code)]
    fn cancel_view_change(&mut self) {
        self.view_change_deadline = None;
    }

    /// Starts recovery timeout.
    #[allow(dead_code)]
    fn start_recovery(&mut self) {
        self.recovery_deadline = Some(Instant::now() + self.config.recovery_retry);
    }

    /// Cancels recovery timeout.
    #[allow(dead_code)]
    fn cancel_recovery(&mut self) {
        self.recovery_deadline = None;
    }

    /// Returns fired timeouts.
    fn check_timeouts(&mut self, is_leader: bool) -> Vec<TimeoutKind> {
        let now = Instant::now();
        let mut fired = Vec::new();

        // Heartbeat timeout (only for non-leaders)
        // Use view_change_timeout as the threshold for missing heartbeats
        if !is_leader && now.duration_since(self.last_heartbeat) > self.config.view_change_timeout {
            fired.push(TimeoutKind::Heartbeat);
            self.reset_heartbeat(); // Prevent repeated firing
        }

        // Prepare timeouts
        let expired_prepares: Vec<_> = self
            .prepare_deadlines
            .iter()
            .filter(|(_, deadline)| now > **deadline)
            .map(|(op, _)| *op)
            .collect();

        for op in expired_prepares {
            self.prepare_deadlines.remove(&op);
            fired.push(TimeoutKind::Prepare(op));
        }

        // View change timeout
        if let Some(deadline) = self.view_change_deadline {
            if now > deadline {
                self.view_change_deadline = None;
                fired.push(TimeoutKind::ViewChange);
            }
        }

        // Recovery timeout
        if let Some(deadline) = self.recovery_deadline {
            if now > deadline {
                self.recovery_deadline = None;
                fired.push(TimeoutKind::Recovery);
            }
        }

        fired
    }
}

// ============================================================================
// Event Loop Handle
// ============================================================================

/// Handle for interacting with the event loop from outside.
#[derive(Clone)]
pub struct EventLoopHandle {
    /// Bounded queue for sending commands (backpressure when full).
    command_queue: Arc<ArrayQueue<EventLoopCommand>>,
    /// Shared state (for status queries).
    shared_state: Arc<RwLock<SharedState>>,
    /// Single slot for an optional applied-commits subscriber. The event
    /// loop fans out each commit's `(op, effects)` through this sender on
    /// every replica — leaders and followers alike — so observers stay
    /// consistent with VSR's authoritative commit order.
    applied_commits_tx: Arc<RwLock<Option<SyncSender<AppliedCommit>>>>,
    /// Single slot for an optional applied-commands subscriber. Fed
    /// alongside (and independently of) `applied_commits_tx` so the
    /// chaos observer and the projection applier don't interfere.
    applied_commands_tx: Arc<RwLock<Option<SyncSender<AppliedCommand>>>>,
}

impl EventLoopHandle {
    /// Submits a command and waits for the result.
    ///
    /// Returns `VsrError::Backpressure` if the event loop command queue is full,
    /// indicating the caller should retry or propagate a `ServerBusy` response.
    pub fn submit(
        &self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
    ) -> Result<SubmitResponse, VsrError> {
        let (result_tx, result_rx) = mpsc::sync_channel(1);

        self.command_queue
            .push(EventLoopCommand::Submit {
                command,
                idempotency_id,
                result_tx,
            })
            .map_err(|_| VsrError::Backpressure)?;

        result_rx.recv().map_err(|_| VsrError::InvalidState {
            status: ReplicaStatus::Normal,
            expected: "event loop response",
        })?
    }

    /// Submits a command with a bounded wait. On timeout returns
    /// `VsrError::CommitTimeout` — callers translate this to a user-visible
    /// `no_quorum` error instead of hanging forever.
    pub fn submit_with_timeout(
        &self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
        timeout: Duration,
    ) -> Result<SubmitResponse, VsrError> {
        let (result_tx, result_rx) = mpsc::sync_channel(1);

        self.command_queue
            .push(EventLoopCommand::Submit {
                command,
                idempotency_id,
                result_tx,
            })
            .map_err(|_| VsrError::Backpressure)?;

        match result_rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(VsrError::CommitTimeout { timeout }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(VsrError::InvalidState {
                status: ReplicaStatus::Normal,
                expected: "event loop response",
            }),
        }
    }

    /// Registers a subscriber for applied commits. Replaces any existing
    /// subscriber (single-slot by design — the server process has exactly
    /// one chaos worker and one other consumer would indicate a logic
    /// bug). Returns a receiver that emits every commit observed on this
    /// replica, in commit order.
    pub fn subscribe_applied_commits(&self, capacity: usize) -> mpsc::Receiver<AppliedCommit> {
        let (tx, rx) = mpsc::sync_channel(capacity);
        if let Ok(mut guard) = self.applied_commits_tx.write() {
            *guard = Some(tx);
        }
        rx
    }

    /// Registers a subscriber for applied commands. Separate channel from
    /// `subscribe_applied_commits` so the projection applier — which
    /// needs the command but not the effects — doesn't compete with
    /// the chaos observer for a single-slot broadcast. One subscriber
    /// allowed (replaces any prior).
    pub fn subscribe_applied_commands(&self, capacity: usize) -> mpsc::Receiver<AppliedCommand> {
        let (tx, rx) = mpsc::sync_channel(capacity);
        if let Ok(mut guard) = self.applied_commands_tx.write() {
            *guard = Some(tx);
        }
        rx
    }

    /// Returns an owned snapshot of the current kernel state. Cost is
    /// `Clone` over the `State` value — cheap for small state but O(n) in
    /// stream count. Returns `VsrError::CommitTimeout` if the event loop
    /// doesn't respond within `timeout`.
    pub fn snapshot_kernel_state(&self, timeout: Duration) -> Result<State, VsrError> {
        let (result_tx, result_rx) = mpsc::sync_channel(1);

        self.command_queue
            .push(EventLoopCommand::SnapshotKernelState { result_tx })
            .map_err(|_| VsrError::Backpressure)?;

        match result_rx.recv_timeout(timeout) {
            Ok(state) => Ok(state),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(VsrError::CommitTimeout { timeout }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(VsrError::InvalidState {
                status: ReplicaStatus::Normal,
                expected: "event loop response",
            }),
        }
    }

    /// Returns the current shared state.
    pub fn state(&self) -> SharedState {
        self.shared_state
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Returns the current leader's replica ID (if known).
    pub fn leader_id(&self) -> Option<ReplicaId> {
        self.shared_state.read().ok().and_then(|s| s.leader_id)
    }

    /// Returns true if bootstrap has completed.
    pub fn is_bootstrap_complete(&self) -> bool {
        self.shared_state
            .read()
            .map(|s| s.bootstrap_complete)
            .unwrap_or(false)
    }

    /// Requests shutdown of the event loop.
    pub fn shutdown(&self) {
        let _ = self.command_queue.push(EventLoopCommand::Shutdown);
    }

    /// Returns true if this replica is the leader.
    pub fn is_leader(&self) -> bool {
        self.shared_state
            .read()
            .map(|s| s.is_leader)
            .unwrap_or(false)
    }

    /// Returns the current view.
    pub fn view(&self) -> ViewNumber {
        self.shared_state
            .read()
            .map(|s| s.view)
            .unwrap_or(ViewNumber::ZERO)
    }

    /// Returns the current commit number.
    pub fn commit_number(&self) -> CommitNumber {
        self.shared_state
            .read()
            .map(|s| s.commit_number)
            .unwrap_or(CommitNumber::ZERO)
    }
}

impl std::fmt::Debug for EventLoopHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLoopHandle")
            .field("state", &self.state())
            .finish()
    }
}

// ============================================================================
// Event Loop
// ============================================================================

/// The main event loop driver for VSR replication.
///
/// This struct contains the state needed to run the event loop. It should be
/// run in a dedicated thread via `EventLoop::run()`.
pub struct EventLoop<S> {
    /// Configuration.
    config: EventLoopConfig,
    /// Cluster configuration.
    cluster_config: ClusterConfig,
    /// The replica state machine.
    replica_state: ReplicaState,
    /// Transport for network communication.
    transport: TcpTransport,
    /// Superblock for persistent state.
    superblock: Superblock<S>,
    /// Timeout tracker.
    timeouts: TimeoutTracker,
    /// Bounded queue for receiving commands (shared with `EventLoopHandle`).
    command_queue: Arc<ArrayQueue<EventLoopCommand>>,
    /// Shared state.
    shared_state: Arc<RwLock<SharedState>>,
    /// Shared slot for the single applied-commits subscriber; see the
    /// matching field on [`EventLoopHandle`].
    applied_commits_tx: Arc<RwLock<Option<SyncSender<AppliedCommit>>>>,
    /// Shared slot for the single applied-commands subscriber.
    applied_commands_tx: Arc<RwLock<Option<SyncSender<AppliedCommand>>>>,
    /// Pending client requests waiting for commit.
    pending_commits: HashMap<OpNumber, SyncSender<Result<SubmitResponse, VsrError>>>,
    /// Time of last tick.
    last_tick: Instant,
    /// Heartbeat interval.
    heartbeat_interval: Duration,
    /// Time of last heartbeat sent (for leader).
    last_heartbeat_sent: Instant,
    /// Time of the last post-bootstrap reconnect-tick. Throttles peer
    /// reconnection attempts so we don't dial-storm a flapping peer.
    last_reconnect_tick: Instant,
    /// Running flag.
    running: bool,
}

impl<S: Read + Write + Seek> EventLoop<S> {
    /// Creates a new event loop.
    pub fn new(
        config: EventLoopConfig,
        cluster_config: ClusterConfig,
        replica_id: ReplicaId,
        transport: TcpTransport,
        superblock: Superblock<S>,
    ) -> (Self, EventLoopHandle) {
        // Size the command queue as a multiple of per-tick capacity for
        // adequate headroom under burst load.
        let queue_capacity = config.max_commands_per_tick * 10;
        let command_queue = Arc::new(ArrayQueue::new(queue_capacity));
        let shared_state = Arc::new(RwLock::new(SharedState::default()));
        let applied_commits_tx = Arc::new(RwLock::new(None));
        let applied_commands_tx = Arc::new(RwLock::new(None));

        let replica_state = ReplicaState::new(replica_id, cluster_config.clone());
        let timeouts = TimeoutTracker::new(config.timeouts);

        let event_loop = Self {
            heartbeat_interval: config.timeouts.heartbeat_interval / 2,
            config,
            cluster_config,
            replica_state,
            transport,
            superblock,
            timeouts,
            command_queue: Arc::clone(&command_queue),
            shared_state: Arc::clone(&shared_state),
            applied_commits_tx: Arc::clone(&applied_commits_tx),
            applied_commands_tx: Arc::clone(&applied_commands_tx),
            pending_commits: HashMap::new(),
            last_tick: Instant::now(),
            last_heartbeat_sent: Instant::now(),
            last_reconnect_tick: Instant::now(),
            running: true,
        };

        let handle = EventLoopHandle {
            command_queue,
            shared_state,
            applied_commits_tx,
            applied_commands_tx,
        };

        (event_loop, handle)
    }

    /// Runs the event loop until shutdown.
    ///
    /// This method blocks and should be run in a dedicated thread.
    pub fn run(&mut self) -> Result<(), VsrError> {
        info!(
            replica = %self.replica_state.replica_id(),
            "event loop starting"
        );

        // Initial state update
        self.update_shared_state();

        // Bootstrap phase: establish peer connectivity
        self.run_bootstrap_phase()?;

        while self.running {
            // 1. Poll transport for messages
            let messages = self
                .transport
                .poll(Some(self.config.poll_interval))
                .map_err(VsrError::Storage)?;

            // 2. Process received messages
            for msg in messages {
                self.process_event(ReplicaEvent::Message(Box::new(msg)))?;
            }

            // 3. Check and process timeouts
            let fired_timeouts = self.timeouts.check_timeouts(self.replica_state.is_leader());
            for timeout in fired_timeouts {
                self.process_event(ReplicaEvent::Timeout(timeout))?;
            }

            // 4. Process pending commands
            self.process_commands()?;

            // 5. Leader: send periodic heartbeats
            if self.replica_state.is_leader()
                && self.replica_state.status() == ReplicaStatus::Normal
            {
                let now = Instant::now();
                if now.duration_since(self.last_heartbeat_sent) > self.heartbeat_interval {
                    self.process_event(ReplicaEvent::Tick)?;
                    self.last_heartbeat_sent = now;
                }
            }

            // 6. Periodic peer-reconnect tick. A peer that came up after
            // bootstrap (or dropped its connection mid-run) would
            // otherwise stay `Disconnected` forever — `connect_all` is
            // only called once during bootstrap. Throttled to one
            // attempt per `heartbeat_interval` so a flapping peer can't
            // cause a dial-storm. The connect attempt itself is
            // non-blocking (mio non-blocking TcpStream); a peer that
            // doesn't accept just stays in `Disconnected` until the
            // next tick.
            let now = Instant::now();
            if now.duration_since(self.last_reconnect_tick) > self.heartbeat_interval {
                self.last_reconnect_tick = now;
                let disconnected = self.transport.disconnected_peer_ids();
                if !disconnected.is_empty() {
                    debug!(
                        replica = %self.replica_state.replica_id(),
                        ?disconnected,
                        "reconnecting to disconnected peers"
                    );
                    if let Err(e) = self.transport.reconnect_disconnected() {
                        warn!(error = %e, "reconnect tick failed");
                    }
                }
            }

            // 7. Periodic tick for housekeeping
            if now.duration_since(self.last_tick) > Duration::from_millis(100) {
                self.last_tick = now;
                // Could add additional periodic tasks here
            }
        }

        info!(
            replica = %self.replica_state.replica_id(),
            "event loop stopped"
        );

        Ok(())
    }

    /// Processes a single event.
    fn process_event(&mut self, event: ReplicaEvent) -> Result<(), VsrError> {
        trace!(event = ?event, "processing event");

        // Reset the heartbeat-deadline whenever the leader contacts us at
        // the current view. Without this, a follower's view-change deadline
        // expires every `view_change_timeout` regardless of how reliably the
        // leader is heartbeating — the cluster ends up in a view-change
        // storm with view climbing once per timeout period. Mirrors Raft's
        // "reset election timer on any AppendEntries from current leader"
        // rule. Inspecting the event here is the single hook that catches
        // every leader-originated message type without threading state
        // through the per-handler return shapes.
        if let ReplicaEvent::Message(msg) = &event {
            if self.is_from_current_leader(msg) {
                self.timeouts.reset_heartbeat();
            }
        }

        // Take ownership for pure state transition
        let state = std::mem::replace(
            &mut self.replica_state,
            ReplicaState::new(ReplicaId::new(0), self.cluster_config.clone()),
        );

        let (new_state, output) = state.process(event);
        self.replica_state = new_state;

        // Handle output
        self.handle_output(output)?;

        // Update shared state
        self.update_shared_state();

        Ok(())
    }

    /// Returns true when `msg` is a leader-originated, current-view
    /// message from the live leader (i.e. evidence that the leader is
    /// still alive). Stale-view leader messages are NOT counted — they
    /// would otherwise pin the follower to a deposed leader and prevent
    /// it from ever advancing its view.
    fn is_from_current_leader(&self, msg: &crate::message::Message) -> bool {
        let local_id = self.replica_state.replica_id();
        if msg.from == local_id {
            return false;
        }
        if msg.from != self.replica_state.leader() {
            return false;
        }
        let payload_view = match msg.payload.view() {
            Some(v) => v,
            None => return false,
        };
        if payload_view != self.replica_state.view() {
            return false;
        }
        matches!(
            msg.payload,
            MessagePayload::Heartbeat(_)
                | MessagePayload::Prepare(_)
                | MessagePayload::Commit(_)
                | MessagePayload::StartView(_)
        )
    }

    /// Handles output from the replica state machine.
    ///
    /// **Durability (AUDIT-2026-03 4.1):** PrepareOk must not be sent until the
    /// op_number is durably persisted. We partition messages into non-PrepareOk
    /// (sent immediately) and PrepareOk (sent only after superblock fsync).
    fn handle_output(&mut self, output: ReplicaOutput) -> Result<(), VsrError> {
        // Partition: PrepareOk must not be sent before op_number is durable.
        let (prepare_oks, immediate): (Vec<_>, Vec<_>) = output
            .messages
            .into_iter()
            .partition(|m| matches!(m.payload, MessagePayload::PrepareOk(_)));

        let local_id = self.replica_state.replica_id();
        // Self-addressed messages collected here for replay below.
        // `TcpTransport::send(local_id, _)` is a silent no-op (the
        // peers map excludes self), so without re-injection a directed
        // message to ourselves vanishes. The motivating case is the
        // new leader's own `DoViewChange`: after a heartbeat timeout
        // a 3-node cluster only reaches view-change quorum if the
        // new leader's own DVC is in its `do_view_change_msgs`
        // tracker. Drop-on-self left the new leader stuck at
        // quorum-1 forever and the cluster wedged in `ViewChange`.
        let mut self_routed: Vec<Message> = Vec::new();

        // Send all non-PrepareOk messages immediately (heartbeats, commits, etc.)
        for msg in immediate {
            if msg.is_broadcast() {
                let others: Vec<_> = self.cluster_config.others(local_id).collect();
                for peer in others {
                    self.transport.send(peer, msg.clone());
                }
            } else if let Some(to) = msg.to {
                if to == local_id {
                    self_routed.push(msg);
                } else {
                    self.transport.send(to, msg);
                }
            }
        }

        // Fsync op_number before acknowledging Prepare to the leader.
        // This guarantees the backup has durably recorded the operation before
        // the leader can count it toward quorum for commit.
        if !prepare_oks.is_empty() {
            self.superblock.update(
                self.replica_state.view(),
                self.replica_state.op_number(),
                self.replica_state.commit_number(),
            )?;

            for msg in prepare_oks {
                if let Some(to) = msg.to {
                    if to == local_id {
                        self_routed.push(msg);
                    } else {
                        self.transport.send(to, msg);
                    }
                }
            }
        }

        // Fan out applied effects to subscriber (chaos worker, etc.)
        // whenever a commit produced effects. Fires on every replica —
        // leader paths set `committed_op=Some(op)` for one op at a time,
        // but follower paths (`on_commit`/`on_heartbeat`/view-change
        // catch-up) collapse multiple commits into a single output with
        // `committed_op=None` and a batch of effects. Gating on `effects`
        // instead of `committed_op` keeps follower observers in sync with
        // the leader.
        if !output.effects.is_empty() {
            let op = output
                .committed_op
                .unwrap_or_else(|| self.replica_state.commit_number().as_op_number());
            if let Ok(guard) = self.applied_commits_tx.read() {
                if let Some(ref tx) = *guard {
                    let _ = tx.try_send(AppliedCommit {
                        op,
                        effects: output.effects.clone(),
                    });
                }
            }
            // Fanout to the command subscriber (projection applier).
            // Look up the command from the replica's log at `op` —
            // cheap Vec index — and clone. Independent from the effects
            // channel so chaos observers don't pay the `Command` clone.
            if let Ok(guard) = self.applied_commands_tx.read() {
                if let Some(ref tx) = *guard {
                    if let Some(entry) = self.replica_state.log_entry(op) {
                        let _ = tx.try_send(AppliedCommand {
                            op,
                            command: entry.command.clone(),
                        });
                    }
                }
            }
        }

        // Handle committed operation
        if let Some(op) = output.committed_op {
            debug!(op = %op, "operation committed");

            // Notify pending client if any
            if let Some(result_tx) = self.pending_commits.remove(&op) {
                let response = SubmitResponse {
                    op_number: op,
                    effects: output.effects, // Take ownership
                    was_duplicate: false,
                };
                let _ = result_tx.send(Ok(response));
            }

            // Update superblock to advance commit_number durably
            self.superblock.update(
                self.replica_state.view(),
                self.replica_state.op_number(),
                self.replica_state.commit_number(),
            )?;

            // Cancel prepare timeout
            self.timeouts.cancel_prepare(op);
        }

        // Replay any messages addressed back at ourselves through the
        // normal `process_event` path. The state machine handles them
        // exactly as it would an inbound message from the wire — which
        // is the only way the new leader's own `DoViewChange` can land
        // in its `do_view_change_msgs` tracker and complete the view
        // change. Each replay can produce further output (e.g. the
        // `StartView` broadcast after quorum), which goes through the
        // same `handle_output` (now via the recursive call). Terminates
        // because each replay strictly advances `replica_state` toward
        // a steady state — there is no cycle of self-routing messages
        // in the protocol.
        for msg in self_routed {
            self.process_event(ReplicaEvent::Message(Box::new(msg)))?;
        }

        Ok(())
    }

    /// Processes pending commands from the channel.
    ///
    /// Drains up to `max_commands_per_tick` commands, then processes them
    /// in a batch. This amortizes channel receive overhead and improves
    /// CPU cache locality when multiple commands arrive within a tick.
    fn process_commands(&mut self) -> Result<(), VsrError> {
        type PendingCommand = (
            Command,
            Option<IdempotencyId>,
            SyncSender<Result<SubmitResponse, VsrError>>,
        );

        // Phase 1: Drain commands from bounded queue into a local batch.
        // This minimizes time spent on queue synchronization.
        let mut batch: Vec<PendingCommand> = Vec::new();

        for _ in 0..self.config.max_commands_per_tick {
            match self.command_queue.pop() {
                Some(EventLoopCommand::Submit {
                    command,
                    idempotency_id,
                    result_tx,
                }) => {
                    batch.push((command, idempotency_id, result_tx));
                }
                Some(EventLoopCommand::SnapshotKernelState { result_tx }) => {
                    // Serve snapshots inline — they don't interact with the
                    // replica state machine and are cheap for small state.
                    let _ = result_tx.send(self.replica_state.kernel_state().clone());
                }
                Some(EventLoopCommand::Shutdown) => {
                    info!("shutdown requested");
                    self.running = false;
                    return Ok(());
                }
                None => break,
            }
        }

        // Phase 2: Process the batch.
        // Each command still gets its own Prepare (preserving VSR protocol safety),
        // but the batch drain above means we process them back-to-back with
        // minimal channel overhead.
        for (command, idempotency_id, result_tx) in batch {
            // Check if we can accept requests
            if !self.replica_state.can_accept_requests() {
                let _ = result_tx.send(Err(VsrError::NotLeader {
                    view: self.replica_state.view(),
                }));
                continue;
            }

            let event = ReplicaEvent::ClientRequest {
                command,
                idempotency_id,
                client_id: None,
                request_number: None,
            };

            let expected_op = self.replica_state.op_number().next();

            self.process_event(event)?;

            // Track pending commit
            self.pending_commits.insert(expected_op, result_tx);

            // Start prepare timeout
            self.timeouts.start_prepare(expected_op);
        }

        Ok(())
    }

    /// Runs the bootstrap phase to establish peer connectivity.
    ///
    /// This phase:
    /// 1. Proactively connects to all peers
    /// 2. Waits for quorum connectivity (with timeout)
    /// 3. Marks bootstrap as complete
    ///
    /// Single-node clusters skip this phase immediately.
    fn run_bootstrap_phase(&mut self) -> Result<(), VsrError> {
        // Single-node clusters don't need bootstrap
        if self.cluster_config.is_single_node() {
            info!(
                replica = %self.replica_state.replica_id(),
                "single-node cluster, skipping bootstrap"
            );
            self.mark_bootstrap_complete();
            return Ok(());
        }

        info!(
            replica = %self.replica_state.replica_id(),
            cluster_size = self.cluster_config.cluster_size(),
            quorum = self.cluster_config.quorum_size(),
            "starting bootstrap phase"
        );

        // Proactively connect to all peers
        if let Err(e) = self.transport.connect_all() {
            warn!(error = %e, "failed to initiate peer connections");
        }

        let bootstrap_timeout = Duration::from_secs(5);
        let bootstrap_start = Instant::now();
        let cluster_size = self.cluster_config.cluster_size();
        let quorum_needed = self.cluster_config.quorum_size();
        let mut last_reconnect_attempt = Instant::now();

        // Wait for full-mesh connectivity (or timeout). Returning early at
        // quorum was a real bug: a follower would exit bootstrap as soon
        // as it shook hands with the leader, before its sibling-follower
        // link came up. With no post-bootstrap reconnect (added below),
        // R1↔R2 stayed disconnected forever and replicated commits never
        // reached the late peer's projection. Waiting for full mesh —
        // with the same 5 s timeout fallback as before — costs at most a
        // few hundred extra milliseconds in the happy path and prevents
        // the partial-mesh failure mode entirely.
        loop {
            // Poll for connection events
            let messages = self
                .transport
                .poll(Some(Duration::from_millis(100)))
                .map_err(VsrError::Storage)?;

            // Process any messages received during bootstrap
            for msg in messages {
                self.process_event(ReplicaEvent::Message(Box::new(msg)))?;
            }

            // Check connectivity (connected peers + self = total connected)
            let connected = self.transport.connected_count() + 1;
            self.update_shared_state();

            if connected >= cluster_size {
                info!(
                    replica = %self.replica_state.replica_id(),
                    connected = connected,
                    cluster_size = cluster_size,
                    "bootstrap complete: full mesh established"
                );
                self.mark_bootstrap_complete();
                return Ok(());
            }

            // Re-attempt connections every ~250 ms during bootstrap so a
            // peer that came up after our initial dial gets picked up
            // before the bootstrap timeout fires.
            let now = Instant::now();
            if now.duration_since(last_reconnect_attempt) > Duration::from_millis(250) {
                last_reconnect_attempt = now;
                if let Err(e) = self.transport.reconnect_disconnected() {
                    warn!(error = %e, "bootstrap reconnect attempt failed");
                }
            }

            // Check timeout: proceed with whatever connectivity we have
            // as long as we cleared quorum. Below quorum we still
            // proceed (the existing behaviour) but log loudly — the
            // cluster won't be writable until the missing peers come up.
            if bootstrap_start.elapsed() > bootstrap_timeout {
                let missing = self.transport.disconnected_peer_ids();
                if connected >= quorum_needed {
                    warn!(
                        replica = %self.replica_state.replica_id(),
                        connected = connected,
                        cluster_size = cluster_size,
                        ?missing,
                        "bootstrap timeout: proceeding with quorum, missing peers will reconnect in background"
                    );
                } else {
                    warn!(
                        replica = %self.replica_state.replica_id(),
                        connected = connected,
                        quorum = quorum_needed,
                        ?missing,
                        "bootstrap timeout: BELOW QUORUM; cluster will not be writable until peers reconnect"
                    );
                }
                self.mark_bootstrap_complete();
                return Ok(());
            }
        }
    }

    /// Updates the shared state from the replica state.
    ///
    /// `is_leader` here uses the strict [`ReplicaState::is_acting_leader`]
    /// predicate — `Normal && view-leader`. This is what every external
    /// observer ("am I primary right now?") wants: a transient view-change
    /// must not surface as `is_leader=1` on more than one replica, which
    /// is what the pure view-table check would let happen for a few hundred
    /// milliseconds between `StartViewChange` and `StartView`.
    fn update_shared_state(&self) {
        if let Ok(mut state) = self.shared_state.write() {
            state.view = self.replica_state.view();
            state.commit_number = self.replica_state.commit_number();
            state.status = self.replica_state.status();
            state.is_leader = self.replica_state.is_acting_leader();
            state.connected_peers = self.transport.connected_count();
            // Track the leader ID for the current view
            state.leader_id = Some(self.replica_state.leader());
        }
    }

    /// Marks bootstrap as complete.
    fn mark_bootstrap_complete(&self) {
        if let Ok(mut state) = self.shared_state.write() {
            state.bootstrap_complete = true;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_loop_config_defaults() {
        let config = EventLoopConfig::default();
        assert_eq!(config.poll_interval, Duration::from_millis(1));
        assert_eq!(config.max_commands_per_tick, 100);
    }

    #[test]
    fn shared_state_default() {
        let state = SharedState::default();
        assert_eq!(state.view, ViewNumber::ZERO);
        assert_eq!(state.commit_number, CommitNumber::ZERO);
        assert_eq!(state.status, ReplicaStatus::Normal);
        assert!(!state.is_leader);
    }

    #[test]
    fn timeout_tracker_heartbeat() {
        let config = TimeoutConfig::development();
        let mut tracker = TimeoutTracker::new(config);

        // No timeout initially
        assert!(tracker.check_timeouts(false).is_empty());

        // Simulate time passing
        tracker.last_heartbeat = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();

        // Should fire heartbeat timeout (not leader)
        let timeouts = tracker.check_timeouts(false);
        assert!(timeouts.contains(&TimeoutKind::Heartbeat));

        // Should not fire for leader
        tracker.last_heartbeat = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        let timeouts = tracker.check_timeouts(true);
        assert!(!timeouts.contains(&TimeoutKind::Heartbeat));
    }

    #[test]
    fn timeout_tracker_prepare() {
        let config = TimeoutConfig {
            prepare_timeout: Duration::from_millis(10),
            ..TimeoutConfig::development()
        };
        let mut tracker = TimeoutTracker::new(config);

        tracker.start_prepare(OpNumber::new(1));

        // Not expired yet
        assert!(tracker.check_timeouts(true).is_empty());

        // Simulate expiry
        tracker.prepare_deadlines.insert(
            OpNumber::new(1),
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );

        let timeouts = tracker.check_timeouts(true);
        assert!(timeouts.contains(&TimeoutKind::Prepare(OpNumber::new(1))));
    }
}
