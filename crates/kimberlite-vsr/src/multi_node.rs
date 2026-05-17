//! Multi-node VSR replicator.
//!
//! This module implements a multi-node VSR replicator that drives the pure
//! `ReplicaState` state machine with real network transport.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     MultiNodeReplicator                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  • Spawns dedicated event loop thread                          │
//! │  • Uses channels for command submission                        │
//! │  • Implements Replicator trait for compatibility               │
//! │  • Thread-safe status queries via shared state                 │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         EventLoop                                │
//! │  (runs in dedicated thread, drives ReplicaState)                │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use kimberlite_vsr::{MultiNodeReplicator, MultiNodeConfig, ClusterAddresses, ReplicaId};
//! use std::collections::HashMap;
//!
//! // Configure addresses
//! let mut addrs = HashMap::new();
//! addrs.insert(ReplicaId::new(0), "127.0.0.1:5000".parse().unwrap());
//! addrs.insert(ReplicaId::new(1), "127.0.0.1:5001".parse().unwrap());
//! addrs.insert(ReplicaId::new(2), "127.0.0.1:5002".parse().unwrap());
//!
//! let config = MultiNodeConfig::new(
//!     ReplicaId::new(0),
//!     ClusterAddresses::new(addrs),
//!     "/path/to/superblock",
//! );
//!
//! let mut replicator = MultiNodeReplicator::start(config)?;
//!
//! // Submit commands (blocks until committed or error)
//! let result = replicator.submit(command, None)?;
//! ```

use std::fs::{File, OpenOptions};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use kimberlite_kernel::{Command, State};
use kimberlite_types::IdempotencyId;
use tracing::{debug, info, warn};

use crate::VsrError;
use crate::config::ClusterConfig;
use crate::event_loop::{EventLoop, EventLoopConfig, EventLoopHandle};
use crate::single_node::{Replicator, SubmitResult};
use crate::superblock::Superblock;
use crate::tcp_transport::{ClusterAddresses, TcpTransport};
use crate::types::{CommitNumber, ReplicaId, ReplicaStatus, ViewNumber};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for a multi-node replicator.
#[derive(Debug, Clone)]
pub struct MultiNodeConfig {
    /// This replica's ID.
    pub replica_id: ReplicaId,
    /// Network addresses for all replicas.
    pub addresses: ClusterAddresses,
    /// Path to the superblock file.
    pub superblock_path: PathBuf,
    /// Event loop configuration.
    pub event_loop: EventLoopConfig,
}

impl MultiNodeConfig {
    /// Creates a new configuration.
    pub fn new(
        replica_id: ReplicaId,
        addresses: ClusterAddresses,
        superblock_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            replica_id,
            addresses,
            superblock_path: superblock_path.into(),
            event_loop: EventLoopConfig::default(),
        }
    }

    /// Creates a configuration for a 3-node cluster on localhost.
    ///
    /// Useful for testing and development.
    pub fn three_node_localhost(
        replica_id: ReplicaId,
        base_port: u16,
        superblock_path: impl Into<PathBuf>,
    ) -> Self {
        let mut addresses = std::collections::HashMap::new();
        addresses.insert(
            ReplicaId::new(0),
            SocketAddr::from(([127, 0, 0, 1], base_port)),
        );
        addresses.insert(
            ReplicaId::new(1),
            SocketAddr::from(([127, 0, 0, 1], base_port + 1)),
        );
        addresses.insert(
            ReplicaId::new(2),
            SocketAddr::from(([127, 0, 0, 1], base_port + 2)),
        );

        Self {
            replica_id,
            addresses: ClusterAddresses::new(addresses),
            superblock_path: superblock_path.into(),
            event_loop: EventLoopConfig::development(),
        }
    }

    /// Sets the event loop configuration.
    pub fn with_event_loop(mut self, config: EventLoopConfig) -> Self {
        self.event_loop = config;
        self
    }

    /// Builds a `ClusterConfig` from the addresses.
    fn cluster_config(&self) -> ClusterConfig {
        let replicas: Vec<_> = self.addresses.replicas().collect();
        ClusterConfig::new(replicas)
    }
}

// ============================================================================
// Multi-Node Replicator
// ============================================================================

/// A multi-node VSR replicator.
///
/// This replicator runs a VSR cluster node with TCP transport. It spawns
/// a dedicated thread for the event loop and provides a synchronous
/// interface for command submission.
///
/// # Thread Safety
///
/// The replicator is thread-safe and can be shared across threads via
/// `Arc`. All methods use internal locking for synchronization.
///
/// # Shutdown
///
/// Call `shutdown()` to gracefully stop the event loop thread. The
/// replicator can also be dropped, which will attempt graceful shutdown.
pub struct MultiNodeReplicator {
    /// Handle to the event loop.
    handle: EventLoopHandle,
    /// Event loop thread handle.
    thread: Option<JoinHandle<()>>,
    /// Cluster configuration.
    config: ClusterConfig,
    /// Cluster addresses for leader lookup.
    addresses: ClusterAddresses,
    /// Cached kernel state (updated on each commit).
    /// Reserved for future use (state inspection, metrics).
    #[allow(dead_code)]
    state: Arc<RwLock<State>>,
}

impl MultiNodeReplicator {
    /// Starts a new multi-node replicator.
    ///
    /// This creates the transport, superblock, and event loop, then
    /// starts the event loop thread.
    ///
    /// # Arguments
    ///
    /// * `config` - Replicator configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Transport creation fails (e.g., address already in use)
    /// - Superblock creation/opening fails
    #[allow(clippy::needless_pass_by_value)] // config is moved into thread
    pub fn start(config: MultiNodeConfig) -> Result<Self, VsrError> {
        info!(
            replica = %config.replica_id,
            "starting multi-node replicator"
        );

        // Create cluster config
        let cluster_config = config.cluster_config();

        // Store addresses for leader lookup (before transport takes ownership)
        let addresses = config.addresses.clone();

        // Create transport
        let transport = TcpTransport::new(config.replica_id, config.addresses.clone())
            .map_err(VsrError::Storage)?;

        // Create or open superblock
        let superblock =
            Self::open_or_create_superblock(&config.superblock_path, config.replica_id)?;

        // Create event loop
        let (mut event_loop, handle) = EventLoop::new(
            config.event_loop.clone(),
            cluster_config.clone(),
            config.replica_id,
            transport,
            superblock,
        );

        // Shared state for kernel
        let state = Arc::new(RwLock::new(State::new()));
        let state_clone = Arc::clone(&state);

        // Spawn event loop thread
        let thread = thread::Builder::new()
            .name(format!("vsr-replica-{}", config.replica_id.as_u8()))
            .spawn(move || {
                if let Err(e) = event_loop.run() {
                    warn!(error = %e, "event loop exited with error");
                }
            })
            .map_err(|e| VsrError::Storage(io::Error::other(e)))?;

        Ok(Self {
            handle,
            thread: Some(thread),
            config: cluster_config,
            addresses,
            state: state_clone,
        })
    }

    /// Opens an existing superblock or creates a new one.
    ///
    /// Self-heals from a partially-written file left behind when a prior
    /// process died between `OpenOptions::create(truncate)` and
    /// `Superblock::create`'s fsync. In that case `path.exists()` is true
    /// but `Superblock::open` fails with `no valid superblock copy found`.
    /// Treat that as "doesn't exist" and recreate — the file has no
    /// committed VSR state to preserve anyway.
    fn open_or_create_superblock(
        path: &Path,
        replica_id: ReplicaId,
    ) -> Result<Superblock<File>, VsrError> {
        if path.exists() {
            debug!(path = %path.display(), "opening existing superblock");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(VsrError::Storage)?;
            match Superblock::open(file) {
                Ok(sb) => return Ok(sb),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "existing superblock file is invalid; recreating",
                    );
                    // Fall through to create path.
                }
            }
        } else {
            debug!(path = %path.display(), "creating new superblock");
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(VsrError::Storage)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(VsrError::Storage)?;
        Superblock::create(file, replica_id).map_err(VsrError::Storage)
    }

    /// Shuts down the replicator gracefully.
    ///
    /// This signals the event loop to stop and waits for the thread to exit.
    pub fn shutdown(&mut self) {
        info!("shutting down multi-node replicator");
        self.handle.shutdown();

        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Returns true if this replica is the leader.
    pub fn is_leader(&self) -> bool {
        self.handle.is_leader()
    }

    /// Returns the current leader's replica ID (if known).
    pub fn leader_id(&self) -> Option<ReplicaId> {
        self.handle.leader_id()
    }

    /// Returns the current leader's network address (if known).
    pub fn leader_address(&self) -> Option<SocketAddr> {
        self.handle
            .leader_id()
            .and_then(|id| self.addresses.get(id))
    }

    /// Returns the cluster configuration.
    pub fn cluster_config(&self) -> &ClusterConfig {
        &self.config
    }

    /// Returns true if bootstrap has completed.
    pub fn is_bootstrap_complete(&self) -> bool {
        self.handle.is_bootstrap_complete()
    }

    /// Returns the current replica status (Normal / ViewChange / Recovering).
    ///
    /// Readers that need to know whether the replica is mid-view-change
    /// should gate on this — only `Normal` means it's safe to read a
    /// consistent commit snapshot or fingerprint. The same info is available
    /// through the `Replicator::status()` trait method; this inherent
    /// accessor avoids forcing callers to import the trait.
    pub fn replica_status(&self) -> ReplicaStatus {
        self.handle.state().status
    }

    /// Returns a single atomic snapshot of the shared state (view,
    /// commit, status, is_leader, leader_id, bootstrap flag, connected
    /// peers). Use this when reporting / metrics need a self-consistent
    /// tuple — calling `is_leader()` + `view()` separately walks two
    /// distinct lock acquisitions and can observe partially-updated
    /// state across a `update_shared_state` boundary, which led to
    /// `is_leader=1 / view=0` mismatches on followers during boot.
    pub fn shared_state(&self) -> crate::event_loop::SharedState {
        self.handle.state()
    }

    /// Returns the cluster addresses.
    pub fn addresses(&self) -> &ClusterAddresses {
        &self.addresses
    }

    /// Submits a command with a bounded wait for commit.
    ///
    /// On timeout returns `VsrError::CommitTimeout` — callers should translate
    /// that into a user-visible `no_quorum` error rather than hanging. This
    /// is the safe variant for any call path that must not block forever
    /// (chaos probes, liveness-sensitive clients).
    pub fn submit_with_timeout(
        &mut self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
        timeout: std::time::Duration,
    ) -> Result<SubmitResult, VsrError> {
        if !self.handle.is_leader() {
            return Err(VsrError::NotLeader {
                view: self.handle.view(),
            });
        }

        let response = self
            .handle
            .submit_with_timeout(command, idempotency_id, timeout)?;

        Ok(SubmitResult {
            op_number: response.op_number,
            effects: response.effects,
            was_duplicate: response.was_duplicate,
        })
    }

    /// Returns an owned snapshot of the current kernel state via the event
    /// loop. Works on any replica (including followers). Use this for
    /// observability or chaos probes — the `Replicator::state()` trait
    /// method is a convenience wrapper with a fixed default timeout; this
    /// method lets callers pass their own budget.
    pub fn snapshot_kernel_state(&self, timeout: std::time::Duration) -> Result<State, VsrError> {
        self.handle.snapshot_kernel_state(timeout)
    }

    /// Registers a subscriber for applied commits on this replica.
    ///
    /// Fires on every committed op — leader and follower alike — so
    /// observers (chaos probe log, projections) stay consistent with VSR's
    /// authoritative commit order. The receiver is bounded; if the
    /// consumer falls behind, `try_send` drops on the producer side.
    pub fn subscribe_applied_commits(
        &self,
        capacity: usize,
    ) -> std::sync::mpsc::Receiver<crate::AppliedCommit> {
        self.handle.subscribe_applied_commits(capacity)
    }

    /// Registers a subscriber for applied commands on this replica.
    /// Independent channel from [`Self::subscribe_applied_commits`] — the
    /// projection applier (server-side, drives `Kimberlite::submit` on
    /// followers) consumes this; chaos observers consume the other.
    pub fn subscribe_applied_commands(
        &self,
        capacity: usize,
    ) -> std::sync::mpsc::Receiver<crate::AppliedCommand> {
        self.handle.subscribe_applied_commands(capacity)
    }
}

impl Replicator for MultiNodeReplicator {
    fn submit(
        &mut self,
        command: Command,
        idempotency_id: Option<IdempotencyId>,
    ) -> Result<SubmitResult, VsrError> {
        // Check if we're the leader
        if !self.handle.is_leader() {
            return Err(VsrError::NotLeader {
                view: self.handle.view(),
            });
        }

        // Submit to event loop
        let response = self.handle.submit(command, idempotency_id)?;

        // Update cached state (best effort)
        // Note: In a full implementation, we'd have a way to sync state
        // For now, we rely on the event loop having the authoritative state

        Ok(SubmitResult {
            op_number: response.op_number,
            effects: response.effects,
            was_duplicate: response.was_duplicate,
        })
    }

    fn state(&self) -> State {
        // Snapshot the kernel state through the event loop. Returns an
        // empty `State` on timeout so callers have a safe fallback — the
        // only callers today are chaos probes and tests, neither of which
        // benefit from blocking forever when the event loop is unhealthy.
        self.handle
            .snapshot_kernel_state(std::time::Duration::from_secs(2))
            .unwrap_or_else(|e| {
                warn!(error = %e, "snapshot_kernel_state failed; returning empty state");
                State::new()
            })
    }

    fn view(&self) -> ViewNumber {
        self.handle.view()
    }

    fn commit_number(&self) -> CommitNumber {
        self.handle.commit_number()
    }

    fn status(&self) -> ReplicaStatus {
        self.handle.state().status
    }

    fn config(&self) -> &ClusterConfig {
        &self.config
    }
}

impl Drop for MultiNodeReplicator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for MultiNodeReplicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiNodeReplicator")
            .field("is_leader", &self.is_leader())
            .field("view", &self.view())
            .field("commit_number", &self.commit_number())
            .field("status", &self.status())
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_node_config_creation() {
        let mut addrs = std::collections::HashMap::new();
        addrs.insert(ReplicaId::new(0), "127.0.0.1:5000".parse().unwrap());
        addrs.insert(ReplicaId::new(1), "127.0.0.1:5001".parse().unwrap());
        addrs.insert(ReplicaId::new(2), "127.0.0.1:5002".parse().unwrap());

        let config = MultiNodeConfig::new(
            ReplicaId::new(0),
            ClusterAddresses::new(addrs),
            "/tmp/test-superblock",
        );

        assert_eq!(config.replica_id, ReplicaId::new(0));
        assert_eq!(config.addresses.len(), 3);
    }

    #[test]
    fn three_node_localhost_config() {
        let config =
            MultiNodeConfig::three_node_localhost(ReplicaId::new(1), 9000, "/tmp/test-superblock");

        assert_eq!(config.replica_id, ReplicaId::new(1));
        assert_eq!(config.addresses.len(), 3);

        // Verify ports
        assert_eq!(
            config.addresses.get(ReplicaId::new(0)),
            Some("127.0.0.1:9000".parse().unwrap())
        );
        assert_eq!(
            config.addresses.get(ReplicaId::new(1)),
            Some("127.0.0.1:9001".parse().unwrap())
        );
        assert_eq!(
            config.addresses.get(ReplicaId::new(2)),
            Some("127.0.0.1:9002".parse().unwrap())
        );
    }

    #[test]
    fn cluster_config_from_multi_node_config() {
        let config =
            MultiNodeConfig::three_node_localhost(ReplicaId::new(0), 9000, "/tmp/test-superblock");

        let cluster = config.cluster_config();

        assert_eq!(cluster.cluster_size(), 3);
        assert_eq!(cluster.quorum_size(), 2);
        assert!(!cluster.is_single_node());
    }
}
