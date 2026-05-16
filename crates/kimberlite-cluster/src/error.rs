//! Error types for cluster management.

use std::path::PathBuf;
use thiserror::Error;

/// Cluster management errors.
#[derive(Error, Debug)]
pub enum Error {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Cluster not initialized.
    #[error("Cluster not initialized at {0}")]
    NotInitialized(PathBuf),

    /// Node already running.
    #[error("Node {0} is already running")]
    NodeAlreadyRunning(usize),

    /// Node not found.
    #[error("Node {0} not found")]
    NodeNotFound(usize),

    /// Node failed to start.
    #[error("Node {0} failed to start: {1}")]
    NodeStartFailed(usize, String),

    /// Node crashed.
    #[error("Node {0} crashed with exit code {1:?}")]
    NodeCrashed(usize, Option<i32>),

    /// Process spawn error.
    #[error("Failed to spawn process: {0}")]
    SpawnError(String),

    /// Invalid node count.
    #[error("Invalid node count: {0} (must be >= 1)")]
    InvalidNodeCount(usize),

    /// Invalid port range.
    #[error("Invalid port range: base={0}, nodes={1}")]
    InvalidPortRange(u16, usize),

    /// Empty host list passed to a multi-host constructor.
    #[error("Hosts list must be non-empty")]
    EmptyHosts,

    /// Two nodes claim the same `(host, port)` tuple — VSR's transport
    /// will fight for the same bind socket and the cluster never reaches
    /// quorum. Caught at config-build time rather than at child spawn so
    /// the operator sees the collision in `cluster.toml` validation.
    #[error("Duplicate (host, port) tuple {host}:{port} on nodes {first} and {second}")]
    DuplicateEndpoint {
        /// Host that collides.
        host: String,
        /// Port that collides (data, VSR, or HTTP-sidecar).
        port: u16,
        /// Lower-indexed node holding the tuple.
        first: usize,
        /// Higher-indexed node colliding with `first`.
        second: usize,
    },

    /// `--node-id` selected an entry that doesn't exist in `cluster.toml`.
    #[error("Node id {requested} out of range (cluster has {node_count} nodes)")]
    NodeIdOutOfRange {
        /// Index the operator asked for.
        requested: usize,
        /// Total nodes declared in `cluster.toml`.
        node_count: usize,
    },

    /// TOML deserialization error.
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TOML serialization error.
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

/// Result type for cluster operations.
pub type Result<T> = std::result::Result<T, Error>;
