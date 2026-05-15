//! VSR replication integration for the server.
//!
//! This module provides a unified interface for command submission through
//! VSR replication. It supports both single-node and cluster modes.
//!
//! # Replication Modes
//!
//! - **Direct**: Direct kernel apply without VSR (no durability guarantees)
//! - **`SingleNode`**: Single-node VSR with file-based superblock (durable, for development)
//! - **Cluster**: Multi-node VSR with full consensus (production-grade)

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread;
use std::time::Duration;

use kimberlite::{CommandRouter, Kimberlite};
use kimberlite_kernel::{Command, State as KernelState};
use kimberlite_types::IdempotencyId;
use kimberlite_vsr::{
    AppliedCommand, AppliedCommit, ClusterAddresses, ClusterConfig, MultiNodeConfig,
    MultiNodeReplicator, Replicator, SingleNodeReplicator, VsrError,
};
use tracing::{debug, info, warn};

use crate::config::ReplicationMode;
use crate::error::{ServerError, ServerResult};

/// A command submitter that routes commands through the appropriate replication layer.
///
/// This abstraction allows the server to use either direct kernel apply
/// or VSR replication (single-node or cluster mode) transparently.
pub enum CommandSubmitter {
    /// Direct mode - applies commands directly to Kimberlite without VSR.
    Direct { db: Kimberlite },

    /// Single-node VSR mode - uses `SingleNodeReplicator` with file-based superblock.
    SingleNode {
        replicator: Arc<RwLock<SingleNodeReplicator<File>>>,
        db: Kimberlite,
    },

    /// Cluster mode - uses `MultiNodeReplicator` with full VSR consensus.
    Cluster {
        replicator: Arc<RwLock<MultiNodeReplicator>>,
        db: Kimberlite,
        /// Highest op number already applied to `db`'s projection on
        /// this replica. Shared between the leader's inline
        /// submit-path (applies immediately after VSR commit for
        /// strong read-your-writes) and the background projection
        /// applier thread (which drives follower projections via the
        /// `AppliedCommit` fanout). The mutex serializes so `db.submit`
        /// never fires twice for the same op — Kimberlite's command
        /// application is NOT idempotent (duplicate CreateStream
        /// errors, duplicate AppendBatch fails on expected_offset).
        last_applied_op: Arc<Mutex<u64>>,
    },
}

impl CommandSubmitter {
    /// Creates a new command submitter based on the replication mode.
    pub fn new(mode: &ReplicationMode, db: Kimberlite, data_dir: &Path) -> ServerResult<Self> {
        match mode {
            ReplicationMode::Direct => {
                info!("starting in direct mode (no VSR replication)");
                Ok(Self::Direct { db })
            }

            ReplicationMode::SingleNode { replica_id } => {
                info!(
                    replica_id = replica_id.as_u8(),
                    "starting single-node VSR replication"
                );

                let config = ClusterConfig::single_node(*replica_id);

                // Use file-based superblock for durability
                let superblock_path =
                    data_dir.join(format!("superblock-single-{}.vsr", replica_id.as_u8()));

                // Check if superblock exists BEFORE opening/creating
                let exists = superblock_path.exists();

                let replicator = if exists {
                    // Open existing replicator with persisted state
                    debug!(path = %superblock_path.display(), "opening existing single-node replicator");
                    let superblock = Self::open_superblock(&superblock_path)?;
                    SingleNodeReplicator::open(config, superblock)
                        .map_err(|e| ServerError::Replication(e.to_string()))?
                } else {
                    // Create new replicator with fresh superblock
                    debug!(path = %superblock_path.display(), "creating new single-node replicator");
                    let superblock = Self::create_superblock(&superblock_path, *replica_id)?;
                    SingleNodeReplicator::create(config, superblock)
                        .map_err(|e| ServerError::Replication(e.to_string()))?
                };

                Ok(Self::SingleNode {
                    replicator: Arc::new(RwLock::new(replicator)),
                    db,
                })
            }

            ReplicationMode::Cluster { replica_id, peers } => {
                info!(
                    replica_id = replica_id.as_u8(),
                    peer_count = peers.len(),
                    "starting cluster VSR replication"
                );

                // Build cluster addresses
                let addresses = ClusterAddresses::from_pairs(peers.iter().copied());

                // Create superblock path
                let superblock_path =
                    data_dir.join(format!("superblock-{}.vsr", replica_id.as_u8()));

                // Create multi-node config
                let config = MultiNodeConfig::new(*replica_id, addresses, superblock_path);

                // Start the multi-node replicator
                let replicator = MultiNodeReplicator::start(config)
                    .map_err(|e| ServerError::Replication(e.to_string()))?;

                // Subscribe to VSR applied-commits and spawn the
                // projection applier. This thread drives `db.submit` on
                // every replica (including followers, which wouldn't
                // otherwise update their Kimberlite projection — VSR's
                // kernel_state updates don't propagate to the projection
                // layer on their own). Leader inline submits also flow
                // through the same dedup gate, so each op applies at
                // most once no matter which path wins the race.
                //
                // Gated by env var so the chaos tier can keep running
                // without the applier while we iterate on it. Default
                // OFF until we've validated it doesn't regress anything.
                let enable_applier = std::env::var("KMB_ENABLE_FOLLOWER_PROJECTION")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let last_applied_op = Arc::new(Mutex::new(0u64));

                if enable_applier {
                    let applied_rx = replicator.subscribe_applied_commands(1024);
                    let db = db.clone();
                    let last_applied = Arc::clone(&last_applied_op);
                    thread::Builder::new()
                        .name("kimberlite-projection-applier".into())
                        .spawn(move || {
                            Self::run_projection_applier_inner(applied_rx, db, last_applied);
                        })
                        .map_err(|e| {
                            ServerError::Replication(format!(
                                "failed to spawn projection applier: {e}"
                            ))
                        })?;
                    info!("follower projection applier enabled");
                }

                Ok(Self::Cluster {
                    replicator: Arc::new(RwLock::new(replicator)),
                    db,
                    last_applied_op,
                })
            }
        }
    }

    /// Applies `command` to `db`'s projection iff no larger op has been
    /// applied already. Returns `true` if this call performed the apply,
    /// `false` if the op was already covered. The mutex serialises the
    /// compare-and-submit so concurrent leader-inline + fanout-applier
    /// paths don't double-apply.
    fn apply_once_to_projection(
        last_applied: &Mutex<u64>,
        db: &Kimberlite,
        op: u64,
        command: &Command,
    ) -> ServerResult<bool> {
        let mut guard = last_applied
            .lock()
            .map_err(|_| ServerError::Replication("last_applied_op mutex poisoned".into()))?;
        if op > *guard {
            // `apply_local`, not `submit` — applying through `submit`
            // would re-enter the installed `CommandRouter` and recurse
            // back into VSR. Followers must apply the already-committed
            // command directly to their projection.
            db.apply_local(command.clone())?;
            *guard = op;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Opens an existing superblock file for reading and writing.
    fn open_superblock(path: &Path) -> ServerResult<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| ServerError::Replication(format!("failed to open superblock: {e}")))
    }

    /// Creates a new superblock file and ensures parent directories exist.
    fn create_superblock(
        path: &Path,
        _replica_id: kimberlite_vsr::ReplicaId,
    ) -> ServerResult<File> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ServerError::Replication(format!("failed to create data directory: {e}"))
            })?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| ServerError::Replication(format!("failed to create superblock: {e}")))
    }

    /// Submits a command for processing.
    ///
    /// In direct mode, this applies the command directly to the kernel.
    /// In VSR mode, this routes through the replicator for durable processing.
    pub fn submit(&self, command: Command) -> ServerResult<SubmissionResult> {
        self.submit_with_idempotency(command, None)
    }

    /// Submits a command with an optional idempotency ID.
    ///
    /// The idempotency ID enables duplicate detection for retried requests.
    pub fn submit_with_idempotency(
        &self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
    ) -> ServerResult<SubmissionResult> {
        match self {
            Self::Direct { db } => {
                // Direct mode: apply to Kimberlite. `apply_local` skips
                // any installed router; in Direct mode there shouldn't
                // be one, but using `apply_local` keeps the contract
                // explicit and guards against future misconfiguration.
                db.apply_local(command.clone())?;

                // Direct mode doesn't track operation numbers
                Ok(SubmissionResult {
                    was_duplicate: false,
                    effects_applied: true,
                })
            }

            Self::SingleNode { replicator, db } => {
                let mut repl = replicator
                    .write()
                    .map_err(|_| ServerError::Replication("lock poisoned".to_string()))?;

                // Submit to replicator
                let result = repl
                    .submit(command.clone(), idempotency_id)
                    .map_err(|e| ServerError::Replication(e.to_string()))?;

                // If not a duplicate, apply to Kimberlite for projection
                // updates. `apply_local` (not `submit`) so we don't
                // re-enter the installed `CommandRouter`.
                if !result.was_duplicate {
                    db.apply_local(command)?;
                }

                Ok(SubmissionResult {
                    was_duplicate: result.was_duplicate,
                    effects_applied: true,
                })
            }

            Self::Cluster {
                replicator,
                db,
                last_applied_op,
            } => {
                let mut repl = replicator
                    .write()
                    .map_err(|_| ServerError::Replication("lock poisoned".to_string()))?;

                // Check if we're the leader before submitting
                if !repl.is_leader() {
                    // Get the current view for the error response
                    let view = repl.view().as_u64();

                    // Get the leader's address for client redirection
                    let leader_hint = repl.leader_address();

                    return Err(ServerError::NotLeader { view, leader_hint });
                }

                // Submit to replicator (blocks until committed or error)
                let result = repl.submit(command.clone(), idempotency_id).map_err(|e| {
                    // Check if the error is a backpressure signal from the event loop
                    let msg = e.to_string();
                    if msg.contains("backpressure") {
                        ServerError::ServerBusy
                    } else if msg.contains("not the leader")
                        || msg.contains("not leader")
                        || msg.contains("NotLeader")
                    {
                        ServerError::NotLeader {
                            view: repl.view().as_u64(),
                            leader_hint: repl.leader_address(),
                        }
                    } else {
                        ServerError::Replication(msg)
                    }
                })?;

                // Apply to Kimberlite via the same dedup-gated helper
                // the projection applier uses. Both paths hold the
                // mutex across check + apply + update, so there's no
                // window for the applier (which fires the leader's own
                // AppliedCommand fanout entry) to double-apply between
                // the inline submit and the guard update. Using
                // `apply_local` underneath also breaks recursion back
                // into the installed `CommandRouter`.
                if !result.was_duplicate {
                    let op = result.op_number.as_u64();
                    Self::apply_once_to_projection(last_applied_op, db, op, &command)?;
                }

                Ok(SubmissionResult {
                    was_duplicate: result.was_duplicate,
                    effects_applied: true,
                })
            }
        }
    }

    /// Background-thread body for the projection applier. Drains commits
    /// from `rx` and applies each to `db` via the shared dedup gate.
    ///
    /// Runs on every replica in cluster mode. On the leader it usually
    /// no-ops (the inline submit path applied first), on followers it's
    /// the ONLY path that updates `Kimberlite`'s projection. Exits when
    /// the sender is dropped (server shutdown).
    fn run_projection_applier_inner(
        rx: std::sync::mpsc::Receiver<AppliedCommand>,
        db: Kimberlite,
        last_applied: Arc<Mutex<u64>>,
    ) {
        while let Ok(commit) = rx.recv() {
            let op = commit.op.as_u64();
            let result = Self::apply_once_to_projection(&last_applied, &db, op, &commit.command);
            if let Err(e) = result {
                // Projection apply failing is usually a genuine data
                // error (e.g. duplicate StreamId) we've already
                // accounted for via the dedup gate, OR a Kimberlite
                // consistency error that deserves a loud warning.
                warn!(op, error = %e, "projection applier: db.submit failed");
            }
        }
        info!("projection applier thread exiting");
    }

    /// Returns a reference to the underlying Kimberlite instance.
    pub fn kimberlite(&self) -> &Kimberlite {
        match self {
            Self::Direct { db } | Self::SingleNode { db, .. } | Self::Cluster { db, .. } => db,
        }
    }

    /// Submits a command with a bounded wait for commit.
    ///
    /// Cluster mode routes through `MultiNodeReplicator::submit_with_timeout`;
    /// other modes delegate to the unbounded path since they don't cross a
    /// network and cannot hang on quorum.
    pub fn submit_with_timeout(
        &self,
        command: Command,
        timeout: Duration,
    ) -> ServerResult<SubmissionResult> {
        match self {
            Self::Direct { .. } | Self::SingleNode { .. } => self.submit(command),

            Self::Cluster {
                replicator,
                db,
                last_applied_op,
            } => {
                let mut repl = replicator
                    .write()
                    .map_err(|_| ServerError::Replication("lock poisoned".to_string()))?;

                if !repl.is_leader() {
                    return Err(ServerError::NotLeader {
                        view: repl.view().as_u64(),
                        leader_hint: repl.leader_address(),
                    });
                }

                let result = repl
                    .submit_with_timeout(command.clone(), None, timeout)
                    .map_err(|e| match e {
                        VsrError::CommitTimeout { timeout } => ServerError::CommitTimeout {
                            timeout_ms: timeout.as_millis(),
                        },
                        VsrError::NotLeader { view } => ServerError::NotLeader {
                            view: view.as_u64(),
                            leader_hint: repl.leader_address(),
                        },
                        VsrError::Backpressure => ServerError::ServerBusy,
                        other => ServerError::Replication(other.to_string()),
                    })?;

                if !result.was_duplicate {
                    let op = result.op_number.as_u64();
                    // Same dedup-gated apply as `submit_with_idempotency`
                    // — see that comment for the full rationale.
                    Self::apply_once_to_projection(last_applied_op, db, op, &command)?;
                }

                Ok(SubmissionResult {
                    was_duplicate: result.was_duplicate,
                    effects_applied: true,
                })
            }
        }
    }

    /// Returns an owned snapshot of the current kernel state.
    ///
    /// Works on every replica, including followers that have applied commits
    /// into VSR's `kernel_state` but (today) do NOT propagate to the
    /// `Kimberlite` projection. Chaos probes must use this path rather
    /// than reading through `kimberlite()` — otherwise follower reads would
    /// return an empty projection and break divergence checks.
    pub fn kernel_state_snapshot(&self, timeout: Duration) -> ServerResult<KernelState> {
        match self {
            Self::Direct { .. } => Err(ServerError::Replication(
                "kernel_state_snapshot unavailable in direct mode (no VSR)".into(),
            )),

            Self::SingleNode { replicator, .. } => {
                let repl = replicator
                    .read()
                    .map_err(|_| ServerError::Replication("lock poisoned".to_string()))?;
                Ok(repl.state())
            }

            Self::Cluster { replicator, .. } => {
                let repl = replicator
                    .read()
                    .map_err(|_| ServerError::Replication("lock poisoned".to_string()))?;
                repl.snapshot_kernel_state(timeout).map_err(|e| match e {
                    VsrError::CommitTimeout { timeout } => ServerError::CommitTimeout {
                        timeout_ms: timeout.as_millis(),
                    },
                    other => ServerError::Replication(other.to_string()),
                })
            }
        }
    }

    /// Returns true if VSR replication is enabled.
    pub fn is_replicated(&self) -> bool {
        !matches!(self, Self::Direct { .. })
    }

    /// Returns the current replication status (for health checks).
    pub fn status(&self) -> ReplicationStatus {
        match self {
            Self::Direct { .. } => ReplicationStatus {
                mode: "direct",
                is_leader: true,
                replica_id: None,
                commit_number: None,
                view: None,
                leader_id: None,
                connected_peers: None,
                bootstrap_complete: None,
                replica_status: None,
            },
            Self::SingleNode { replicator, .. } => {
                let repl = replicator.read().ok();
                ReplicationStatus {
                    mode: "single-node",
                    is_leader: true, // Single-node is always leader
                    replica_id: repl
                        .as_ref()
                        .and_then(|r| r.config().replicas().next().map(|id| id.as_u8())),
                    commit_number: repl.as_ref().map(|r| r.commit_number().as_u64()),
                    view: Some(0), // Single-node is always view 0
                    leader_id: repl
                        .as_ref()
                        .and_then(|r| r.config().replicas().next().map(|id| id.as_u8())),
                    connected_peers: Some(0), // No peers in single-node
                    bootstrap_complete: Some(true), // Always complete
                    replica_status: Some("normal"),
                }
            }
            Self::Cluster { replicator, .. } => {
                let repl = replicator.read().ok();
                ReplicationStatus {
                    mode: "cluster",
                    is_leader: repl.as_ref().is_some_and(|r| r.is_leader()),
                    replica_id: repl
                        .as_ref()
                        .and_then(|r| r.config().replicas().next().map(|id| id.as_u8())),
                    commit_number: repl.as_ref().map(|r| r.commit_number().as_u64()),
                    view: repl.as_ref().map(|r| r.view().as_u64()),
                    leader_id: repl
                        .as_ref()
                        .and_then(|r| r.leader_id().map(|id| id.as_u8())),
                    connected_peers: repl.as_ref().map(|r| {
                        // Get connected peers from the shared state
                        let state = r.cluster_config();
                        state.cluster_size().saturating_sub(1) // Approximate: cluster_size - 1
                    }),
                    bootstrap_complete: repl.as_ref().map(|r| r.is_bootstrap_complete()),
                    replica_status: repl.as_ref().map(|r| match r.replica_status() {
                        kimberlite_vsr::ReplicaStatus::Normal => "normal",
                        kimberlite_vsr::ReplicaStatus::ViewChange => "view_change",
                        kimberlite_vsr::ReplicaStatus::Recovering => "recovering",
                        kimberlite_vsr::ReplicaStatus::Standby => "standby",
                    }),
                }
            }
        }
    }

    /// Returns true if this node is the leader (for cluster mode).
    pub fn is_leader(&self) -> bool {
        match self {
            Self::Direct { .. } | Self::SingleNode { .. } => true, // Single-node is always leader
            Self::Cluster { replicator, .. } => replicator.read().is_ok_and(|r| r.is_leader()),
        }
    }

    /// Subscribes to applied-commit events on this replica. Cluster mode
    /// only — single-node and direct don't need observers because they
    /// already run `db.submit` synchronously on every commit. Returns
    /// `None` for those modes.
    pub fn subscribe_applied_commits(
        &self,
        capacity: usize,
    ) -> Option<std::sync::mpsc::Receiver<AppliedCommit>> {
        match self {
            Self::Direct { .. } | Self::SingleNode { .. } => None,
            Self::Cluster { replicator, .. } => {
                let repl = replicator.read().ok()?;
                Some(repl.subscribe_applied_commits(capacity))
            }
        }
    }
}

/// `CommandRouter` adapter that lets `Kimberlite::submit` forward
/// wire-level writes through VSR.
///
/// Holds a [`Weak`] reference to the [`CommandSubmitter`] to avoid the
/// cycle that would otherwise form (`Kimberlite` holds the router via
/// `Arc<dyn CommandRouter>`; the submitter holds the `Kimberlite`).
/// If the submitter has been dropped (server shutdown), the router
/// surfaces a clear error rather than silently no-oping.
pub struct ClusterCommandRouter {
    submitter: Weak<CommandSubmitter>,
}

impl ClusterCommandRouter {
    /// Constructs a router pointing at the supplied submitter. The
    /// router holds a `Weak<...>` so the install-on-Kimberlite step
    /// doesn't create an `Arc` cycle.
    pub fn new(submitter: &Arc<CommandSubmitter>) -> Self {
        Self {
            submitter: Arc::downgrade(submitter),
        }
    }
}

impl CommandRouter for ClusterCommandRouter {
    fn submit(&self, command: Command) -> kimberlite::Result<()> {
        let submitter = self.submitter.upgrade().ok_or_else(|| {
            kimberlite::KimberliteError::internal(
                "ClusterCommandRouter: CommandSubmitter has been dropped",
            )
        })?;
        // `CommandSubmitter::submit` runs the VSR commit + the
        // local `apply_local`. The latter is the destination of the
        // route — without `apply_local`'s recursion-break this would
        // re-enter the router and loop forever.
        submitter.submit(command).map_err(|e| {
            kimberlite::KimberliteError::internal(format!("cluster submit failed: {e}"))
        })?;
        Ok(())
    }
}

/// Result of command submission.
#[derive(Debug, Clone)]
pub struct SubmissionResult {
    /// Whether this was a duplicate request (idempotency hit).
    pub was_duplicate: bool,
    /// Whether effects were successfully applied.
    pub effects_applied: bool,
}

/// Replication status for health/metrics.
#[derive(Debug, Clone)]
pub struct ReplicationStatus {
    /// Replication mode name.
    pub mode: &'static str,
    /// Whether this node is the leader.
    pub is_leader: bool,
    /// Replica ID (if replicated).
    pub replica_id: Option<u8>,
    /// Commit number (if replicated).
    pub commit_number: Option<u64>,
    /// Current view number (cluster mode only).
    pub view: Option<u64>,
    /// Current leader's replica ID (cluster mode only).
    pub leader_id: Option<u8>,
    /// Number of connected peers (cluster mode only).
    pub connected_peers: Option<usize>,
    /// Whether bootstrap phase is complete (cluster mode only).
    pub bootstrap_complete: Option<bool>,
    /// VSR replica status ("normal" / "view_change" / "recovering") —
    /// cluster mode only. Chaos probes gate commit-hash compares on this
    /// to avoid racing a view change.
    pub replica_status: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_types::{DataClass, Placement, StreamId, StreamName};
    use tempfile::TempDir;

    #[test]
    fn test_direct_mode_submit() {
        let temp_dir = TempDir::new().unwrap();
        let db = Kimberlite::open(temp_dir.path()).unwrap();
        let submitter =
            CommandSubmitter::new(&ReplicationMode::Direct, db, temp_dir.path()).unwrap();

        assert!(!submitter.is_replicated());

        let cmd = Command::create_stream(
            StreamId::new(1),
            StreamName::new("test"),
            DataClass::Public,
            Placement::Global,
        );

        let result = submitter.submit(cmd).unwrap();
        assert!(!result.was_duplicate);
        assert!(result.effects_applied);
    }

    #[test]
    fn test_single_node_mode_submit() {
        let temp_dir = TempDir::new().unwrap();
        let db = Kimberlite::open(temp_dir.path()).unwrap();
        let submitter =
            CommandSubmitter::new(&ReplicationMode::single_node(), db, temp_dir.path()).unwrap();

        assert!(submitter.is_replicated());

        let cmd = Command::create_stream(
            StreamId::new(1),
            StreamName::new("test"),
            DataClass::Public,
            Placement::Global,
        );

        let result = submitter.submit(cmd).unwrap();
        assert!(!result.was_duplicate);
        assert!(result.effects_applied);

        // Check status
        let status = submitter.status();
        assert_eq!(status.mode, "single-node");
        assert!(status.is_leader);
        assert!(status.replica_id.is_some());
    }

    #[test]
    fn test_idempotency_detection() {
        let temp_dir = TempDir::new().unwrap();
        let db = Kimberlite::open(temp_dir.path()).unwrap();
        let submitter =
            CommandSubmitter::new(&ReplicationMode::single_node(), db, temp_dir.path()).unwrap();

        // Create idempotency ID
        let idem_id = IdempotencyId::generate();

        // First submission
        let cmd = Command::create_stream(
            StreamId::new(1),
            StreamName::new("test"),
            DataClass::Public,
            Placement::Global,
        );
        let result = submitter
            .submit_with_idempotency(cmd.clone(), Some(idem_id))
            .unwrap();
        assert!(!result.was_duplicate);

        // Second submission with same ID should be detected as duplicate
        // Note: The replicator should detect this, but we need different commands
        // for the same idempotency_id to trigger duplicate detection.
        // For now, this test verifies the plumbing works.
    }
}
