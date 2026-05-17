//! Server configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use kimberlite_vsr::ReplicaId;

use crate::auth::AuthMode;
use crate::tls::TlsConfig;

/// Replication mode for the server.
#[derive(Debug, Clone)]
pub enum ReplicationMode {
    /// Direct kernel apply without VSR replication.
    /// This mode bypasses the replicator and applies commands directly.
    Direct,

    /// Single-node VSR replication.
    /// Uses `SingleNodeReplicator` for durable command processing with
    /// idempotency tracking and superblock persistence.
    SingleNode {
        /// Replica ID for this node (typically 0 for single-node).
        replica_id: ReplicaId,
    },

    /// Cluster mode with multiple replicas.
    /// Uses `MultiNodeReplicator` with full VSR consensus.
    Cluster {
        /// This node's replica ID.
        replica_id: ReplicaId,
        /// VSR transport peer addresses for all replicas (including
        /// self). These are the addresses the consensus layer dials
        /// for `Prepare` / `Commit` / `DoViewChange`. On the
        /// supervisor-spawned topology they sit at
        /// `data_port + VSR_PORT_OFFSET`.
        peers: Vec<(ReplicaId, SocketAddr)>,
        /// Client-facing data peer addresses for all replicas
        /// (including self). Used to populate the `leader_hint`
        /// returned with `NotLeader` so SDK retry-on-hint redirects
        /// land on the leader's data port, not its VSR port. Defaults
        /// to a clone of `peers` for constructors that don't know the
        /// distinction (single-host dev / tests where data and VSR
        /// ports happen to coincide).
        client_peers: Vec<(ReplicaId, SocketAddr)>,
    },
}

impl Default for ReplicationMode {
    fn default() -> Self {
        Self::Direct
    }
}

impl ReplicationMode {
    /// Creates a single-node replication mode.
    pub fn single_node() -> Self {
        Self::SingleNode {
            replica_id: ReplicaId::new(0),
        }
    }

    /// Creates a single-node replication mode with a specific replica ID.
    pub fn single_node_with_id(id: u8) -> Self {
        Self::SingleNode {
            replica_id: ReplicaId::new(id),
        }
    }

    /// Returns true if VSR replication is enabled.
    pub fn is_replicated(&self) -> bool {
        !matches!(self, Self::Direct)
    }

    /// Returns true if this is cluster mode.
    pub fn is_cluster(&self) -> bool {
        matches!(self, Self::Cluster { .. })
    }

    /// Creates a 3-node cluster configuration for localhost testing.
    ///
    /// # Arguments
    ///
    /// * `replica_id` - This node's replica ID (0, 1, or 2)
    /// * `base_port` - Base port number (nodes will use `base_port`, `base_port+1`, `base_port+2`)
    pub fn cluster_localhost(replica_id: u8, base_port: u16) -> Self {
        assert!(
            replica_id < 3,
            "replica_id must be 0, 1, or 2 for 3-node cluster"
        );

        let peers = vec![
            (
                ReplicaId::new(0),
                SocketAddr::from(([127, 0, 0, 1], base_port)),
            ),
            (
                ReplicaId::new(1),
                SocketAddr::from(([127, 0, 0, 1], base_port + 1)),
            ),
            (
                ReplicaId::new(2),
                SocketAddr::from(([127, 0, 0, 1], base_port + 2)),
            ),
        ];

        Self::Cluster {
            replica_id: ReplicaId::new(replica_id),
            client_peers: peers.clone(),
            peers,
        }
    }

    /// Creates a cluster configuration from a list of peer addresses.
    ///
    /// `peers` doubles as both the VSR transport list and the
    /// client-facing peer list, which is only valid when the two
    /// happen to coincide (single-binding dev clusters, tests). For
    /// the supervisor-spawned production topology, prefer
    /// [`Self::cluster_with_client_peers`].
    ///
    /// # Arguments
    ///
    /// * `replica_id` - This node's replica ID
    /// * `peers` - List of (`ReplicaId`, `SocketAddr`) for all cluster members
    pub fn cluster(replica_id: ReplicaId, peers: Vec<(ReplicaId, SocketAddr)>) -> Self {
        Self::Cluster {
            replica_id,
            client_peers: peers.clone(),
            peers,
        }
    }

    /// Creates a cluster configuration with distinct VSR and
    /// client-facing peer maps.
    ///
    /// The supervisor spawns each node with VSR bound at
    /// `data_port + VSR_PORT_OFFSET`; `peers` covers the VSR
    /// transport while `client_peers` covers the client data ports.
    /// The two maps MUST agree on replica ids — callers that mismatch
    /// here will surface a wrong `leader_hint` on `NotLeader`, which
    /// is exactly the bug this constructor exists to avoid.
    pub fn cluster_with_client_peers(
        replica_id: ReplicaId,
        peers: Vec<(ReplicaId, SocketAddr)>,
        client_peers: Vec<(ReplicaId, SocketAddr)>,
    ) -> Self {
        Self::Cluster {
            replica_id,
            peers,
            client_peers,
        }
    }

    /// Creates a cluster configuration from a comma-separated peer string.
    ///
    /// This is useful for parsing cluster configuration from environment variables.
    ///
    /// # Format
    ///
    /// The peer string should be in the format: `id1=addr1,id2=addr2,id3=addr3`
    ///
    /// For example: `0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002`
    ///
    /// # Arguments
    ///
    /// * `replica_id` - This node's replica ID
    /// * `peers_str` - Comma-separated peer addresses
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// use kimberlite_server::ReplicationMode;
    ///
    /// // Parse from environment variable format
    /// let mode = ReplicationMode::cluster_from_str(
    ///     0,
    ///     "0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002"
    /// ).unwrap();
    /// ```
    pub fn cluster_from_str(replica_id: u8, peers_str: &str) -> Result<Self, ClusterConfigError> {
        let peers = Self::parse_peers(peers_str)?;

        // Validate cluster configuration
        if peers.len() < 3 {
            return Err(ClusterConfigError::TooFewNodes {
                count: peers.len(),
                minimum: 3,
            });
        }

        if peers.len() % 2 == 0 {
            return Err(ClusterConfigError::EvenNodeCount { count: peers.len() });
        }

        // Check if this replica is in the cluster
        let replica = ReplicaId::new(replica_id);
        if !peers.iter().any(|(id, _)| *id == replica) {
            return Err(ClusterConfigError::ReplicaNotInCluster { replica_id });
        }

        Ok(Self::Cluster {
            replica_id: replica,
            client_peers: peers.clone(),
            peers,
        })
    }

    /// Parses a peer string into a list of (`ReplicaId`, `SocketAddr`) pairs.
    fn parse_peers(peers_str: &str) -> Result<Vec<(ReplicaId, SocketAddr)>, ClusterConfigError> {
        let mut peers = Vec::new();

        for peer in peers_str.split(',') {
            let peer = peer.trim();
            if peer.is_empty() {
                continue;
            }

            let (id_str, addr_str) =
                peer.split_once('=')
                    .ok_or_else(|| ClusterConfigError::InvalidPeerFormat {
                        peer: peer.to_string(),
                        reason: "expected format 'id=addr'".to_string(),
                    })?;

            let id: u8 =
                id_str
                    .trim()
                    .parse()
                    .map_err(|_| ClusterConfigError::InvalidPeerFormat {
                        peer: peer.to_string(),
                        reason: "replica ID must be a number 0-255".to_string(),
                    })?;

            let addr: SocketAddr =
                addr_str
                    .trim()
                    .parse()
                    .map_err(|e| ClusterConfigError::InvalidPeerFormat {
                        peer: peer.to_string(),
                        reason: format!("invalid address: {e}"),
                    })?;

            peers.push((ReplicaId::new(id), addr));
        }

        // Sort by replica ID for consistency
        peers.sort_by_key(|(id, _)| id.as_u8());

        // Check for duplicate replica IDs
        for window in peers.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(ClusterConfigError::DuplicateReplicaId {
                    replica_id: window[0].0.as_u8(),
                });
            }
        }

        Ok(peers)
    }

    /// Creates a cluster configuration from environment variables.
    ///
    /// Reads the following environment variables:
    /// - `KMB_REPLICA_ID`: This node's replica ID (required for cluster mode)
    /// - `KMB_CLUSTER_PEERS`: Comma-separated VSR transport peer addresses
    /// - `KMB_CLUSTER_CLIENT_PEERS`: Optional, comma-separated
    ///   client-facing data peer addresses. When unset, falls back to
    ///   `KMB_CLUSTER_PEERS` — which yields the wrong `leader_hint`
    ///   port for SDK retry redirects in supervisor-spawned topologies
    ///   (data port + `VSR_PORT_OFFSET`); the supervisor sets this
    ///   variable to keep the hints client-addressable.
    ///
    /// # Example
    ///
    /// ```bash
    /// export KMB_REPLICA_ID=0
    /// export KMB_CLUSTER_PEERS="0=127.0.0.1:5100,1=127.0.0.1:5101,2=127.0.0.1:5102"
    /// export KMB_CLUSTER_CLIENT_PEERS="0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002"
    /// ```
    pub fn from_env() -> Result<Self, ClusterConfigError> {
        // Check for single-node mode
        if std::env::var("KMB_SINGLE_NODE").is_ok() {
            let replica_id = std::env::var("KMB_REPLICA_ID")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap_or(0);
            return Ok(Self::single_node_with_id(replica_id));
        }

        // Check for cluster mode
        let peers_str =
            std::env::var("KMB_CLUSTER_PEERS").map_err(|_| ClusterConfigError::MissingEnvVar {
                var: "KMB_CLUSTER_PEERS".to_string(),
            })?;

        let replica_id: u8 = std::env::var("KMB_REPLICA_ID")
            .map_err(|_| ClusterConfigError::MissingEnvVar {
                var: "KMB_REPLICA_ID".to_string(),
            })?
            .parse()
            .map_err(|_| ClusterConfigError::InvalidEnvVar {
                var: "KMB_REPLICA_ID".to_string(),
                reason: "must be a number 0-255".to_string(),
            })?;

        let mut mode = Self::cluster_from_str(replica_id, &peers_str)?;

        // Optional override for the client-facing peer map. When the
        // supervisor sets `KMB_CLUSTER_CLIENT_PEERS`, the parsed map
        // wholesale replaces the `client_peers` cluster_from_str
        // defaulted from `peers`. Validated against the same shape
        // contract as `peers` (≥3 nodes, odd, replica_id present, no
        // duplicates) so a malformed env var fails-fast at boot rather
        // than at the first `NotLeader` response.
        if let Ok(client_str) = std::env::var("KMB_CLUSTER_CLIENT_PEERS") {
            let parsed = Self::parse_peers(&client_str)?;
            if parsed.len() < 3 {
                return Err(ClusterConfigError::TooFewNodes {
                    count: parsed.len(),
                    minimum: 3,
                });
            }
            if parsed.len() % 2 == 0 {
                return Err(ClusterConfigError::EvenNodeCount {
                    count: parsed.len(),
                });
            }
            let replica = ReplicaId::new(replica_id);
            if !parsed.iter().any(|(id, _)| *id == replica) {
                return Err(ClusterConfigError::ReplicaNotInCluster { replica_id });
            }
            if let Self::Cluster { client_peers, .. } = &mut mode {
                *client_peers = parsed;
            }
        }

        Ok(mode)
    }

    /// Returns the replica ID if replication is enabled.
    pub fn replica_id(&self) -> Option<ReplicaId> {
        match self {
            Self::Direct => None,
            Self::SingleNode { replica_id } | Self::Cluster { replica_id, .. } => Some(*replica_id),
        }
    }

    /// Returns the VSR-transport peer addresses if in cluster mode.
    pub fn peers(&self) -> Option<&[(ReplicaId, SocketAddr)]> {
        match self {
            Self::Cluster { peers, .. } => Some(peers),
            _ => None,
        }
    }

    /// Returns the client-facing peer addresses if in cluster mode.
    ///
    /// These drive the `leader_hint` field of `NotLeader` responses
    /// so SDK retry-on-hint redirects land on the leader's data port
    /// rather than its VSR transport port.
    pub fn client_peers(&self) -> Option<&[(ReplicaId, SocketAddr)]> {
        match self {
            Self::Cluster { client_peers, .. } => Some(client_peers),
            _ => None,
        }
    }
}

/// Errors that can occur when configuring a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterConfigError {
    /// Too few nodes for a cluster.
    TooFewNodes { count: usize, minimum: usize },
    /// Even number of nodes (must be odd for quorum).
    EvenNodeCount { count: usize },
    /// This replica is not part of the cluster.
    ReplicaNotInCluster { replica_id: u8 },
    /// Invalid peer format in configuration string.
    InvalidPeerFormat { peer: String, reason: String },
    /// Duplicate replica ID in configuration.
    DuplicateReplicaId { replica_id: u8 },
    /// Missing required environment variable.
    MissingEnvVar { var: String },
    /// Invalid environment variable value.
    InvalidEnvVar { var: String, reason: String },
}

impl std::fmt::Display for ClusterConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewNodes { count, minimum } => {
                write!(f, "cluster requires at least {minimum} nodes, got {count}")
            }
            Self::EvenNodeCount { count } => {
                write!(
                    f,
                    "cluster must have odd number of nodes for quorum, got {count}"
                )
            }
            Self::ReplicaNotInCluster { replica_id } => {
                write!(f, "replica {replica_id} is not in the cluster peer list")
            }
            Self::InvalidPeerFormat { peer, reason } => {
                write!(f, "invalid peer format '{peer}': {reason}")
            }
            Self::DuplicateReplicaId { replica_id } => {
                write!(
                    f,
                    "duplicate replica ID {replica_id} in cluster configuration"
                )
            }
            Self::MissingEnvVar { var } => {
                write!(f, "missing required environment variable: {var}")
            }
            Self::InvalidEnvVar { var, reason } => {
                write!(f, "invalid value for {var}: {reason}")
            }
        }
    }
}

impl std::error::Error for ClusterConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_from_str_valid() {
        let mode = ReplicationMode::cluster_from_str(
            0,
            "0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002",
        )
        .unwrap();

        assert!(mode.is_cluster());
        assert_eq!(mode.replica_id(), Some(ReplicaId::new(0)));

        let peers = mode.peers().unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].0, ReplicaId::new(0));
        assert_eq!(peers[1].0, ReplicaId::new(1));
        assert_eq!(peers[2].0, ReplicaId::new(2));
    }

    #[test]
    fn test_cluster_from_str_with_spaces() {
        let mode = ReplicationMode::cluster_from_str(
            1,
            " 0 = 127.0.0.1:5000 , 1 = 127.0.0.1:5001 , 2 = 127.0.0.1:5002 ",
        )
        .unwrap();

        assert!(mode.is_cluster());
        assert_eq!(mode.replica_id(), Some(ReplicaId::new(1)));
    }

    #[test]
    fn test_cluster_from_str_five_nodes() {
        let mode = ReplicationMode::cluster_from_str(
            2,
            "0=10.0.0.1:5000,1=10.0.0.2:5000,2=10.0.0.3:5000,3=10.0.0.4:5000,4=10.0.0.5:5000",
        )
        .unwrap();

        let peers = mode.peers().unwrap();
        assert_eq!(peers.len(), 5);
    }

    #[test]
    fn test_cluster_from_str_too_few_nodes() {
        let err = ReplicationMode::cluster_from_str(0, "0=127.0.0.1:5000").unwrap_err();
        assert!(matches!(
            err,
            ClusterConfigError::TooFewNodes {
                count: 1,
                minimum: 3
            }
        ));
    }

    #[test]
    fn test_cluster_from_str_even_nodes() {
        let err = ReplicationMode::cluster_from_str(
            0,
            "0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002,3=127.0.0.1:5003",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClusterConfigError::EvenNodeCount { count: 4 }
        ));
    }

    #[test]
    fn test_cluster_from_str_replica_not_in_cluster() {
        let err = ReplicationMode::cluster_from_str(
            5, // Not in the cluster
            "0=127.0.0.1:5000,1=127.0.0.1:5001,2=127.0.0.1:5002",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClusterConfigError::ReplicaNotInCluster { replica_id: 5 }
        ));
    }

    #[test]
    fn test_cluster_from_str_invalid_format() {
        let err = ReplicationMode::cluster_from_str(0, "invalid").unwrap_err();
        assert!(matches!(err, ClusterConfigError::InvalidPeerFormat { .. }));
    }

    #[test]
    fn test_cluster_from_str_duplicate_replica() {
        let err = ReplicationMode::cluster_from_str(
            0,
            "0=127.0.0.1:5000,0=127.0.0.1:5001,2=127.0.0.1:5002",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClusterConfigError::DuplicateReplicaId { replica_id: 0 }
        ));
    }

    #[test]
    fn cluster_from_str_defaults_client_peers_to_peers() {
        // Without `cluster_with_client_peers` (or the env-var path
        // in `from_env`), client_peers should mirror peers — that's
        // the pre-graduation behaviour and the safe default for
        // tests / single-host dev clusters.
        let mode = ReplicationMode::cluster_from_str(
            0,
            "0=127.0.0.1:5100,1=127.0.0.1:5101,2=127.0.0.1:5102",
        )
        .unwrap();

        let peers = mode.peers().unwrap();
        let client_peers = mode.client_peers().unwrap();
        assert_eq!(peers, client_peers);
    }

    #[test]
    fn cluster_with_client_peers_keeps_distinct_maps() {
        // The supervisor-spawned topology binds VSR at
        // data_port + VSR_PORT_OFFSET. Verify the constructor
        // preserves both addresses independently.
        let vsr: Vec<(ReplicaId, SocketAddr)> = (0..3)
            .map(|i| {
                (
                    ReplicaId::new(i),
                    format!("127.0.0.1:{}", 5100 + u16::from(i))
                        .parse()
                        .unwrap(),
                )
            })
            .collect();
        let data: Vec<(ReplicaId, SocketAddr)> = (0..3)
            .map(|i| {
                (
                    ReplicaId::new(i),
                    format!("127.0.0.1:{}", 5000 + u16::from(i))
                        .parse()
                        .unwrap(),
                )
            })
            .collect();

        let mode = ReplicationMode::cluster_with_client_peers(
            ReplicaId::new(1),
            vsr.clone(),
            data.clone(),
        );

        assert_eq!(mode.peers().unwrap(), vsr.as_slice());
        assert_eq!(mode.client_peers().unwrap(), data.as_slice());
    }

    #[test]
    fn test_cluster_localhost_helper() {
        let mode = ReplicationMode::cluster_localhost(1, 5000);
        assert!(mode.is_cluster());
        assert_eq!(mode.replica_id(), Some(ReplicaId::new(1)));

        let peers = mode.peers().unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].1, "127.0.0.1:5000".parse::<SocketAddr>().unwrap());
        assert_eq!(peers[1].1, "127.0.0.1:5001".parse::<SocketAddr>().unwrap());
        assert_eq!(peers[2].1, "127.0.0.1:5002".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_single_node_mode() {
        let mode = ReplicationMode::single_node();
        assert!(!mode.is_cluster());
        assert!(mode.is_replicated());
        assert_eq!(mode.replica_id(), Some(ReplicaId::new(0)));
        assert!(mode.peers().is_none());
    }

    #[test]
    fn test_direct_mode() {
        let mode = ReplicationMode::Direct;
        assert!(!mode.is_cluster());
        assert!(!mode.is_replicated());
        assert!(mode.replica_id().is_none());
        assert!(mode.peers().is_none());
    }

    #[test]
    fn test_tenant_tag_config_default_priority() {
        let config = TenantTagConfig::new(
            RateLimitConfig::per_second(100),
            RateLimitConfig::per_second(10),
        );

        // Unknown tenants get Default priority
        assert_eq!(config.priority_for(42), TenantPriority::Default);
    }

    #[test]
    fn test_tenant_tag_config_custom_priority() {
        let config = TenantTagConfig::new(
            RateLimitConfig::per_second(100),
            RateLimitConfig::per_second(10),
        )
        .with_tenant_priority(1, TenantPriority::System)
        .with_tenant_priority(99, TenantPriority::Batch);

        assert_eq!(config.priority_for(1), TenantPriority::System);
        assert_eq!(config.priority_for(99), TenantPriority::Batch);
        assert_eq!(config.priority_for(42), TenantPriority::Default);
    }

    #[test]
    fn test_tenant_tag_rate_limits() {
        let config = TenantTagConfig::new(
            RateLimitConfig::per_second(100),
            RateLimitConfig::per_second(10),
        )
        .with_tenant_priority(1, TenantPriority::System);

        // System tenants are never rate limited
        assert!(config.rate_limit_for(1).is_none());

        // Default tenants get 100 req/s
        let default_limit = config.rate_limit_for(42).unwrap();
        assert_eq!(default_limit.max_requests, 100);

        // Batch tenants get 10 req/s
        let config = config.with_tenant_priority(99, TenantPriority::Batch);
        let batch_limit = config.rate_limit_for(99).unwrap();
        assert_eq!(batch_limit.max_requests, 10);
    }

    #[test]
    fn test_priority_rate_limit_config() {
        let prl = PriorityRateLimitConfig {
            system: None,
            default: RateLimitConfig::per_minute(1000),
            batch: RateLimitConfig::per_minute(100),
        };

        assert!(prl.for_priority(TenantPriority::System).is_none());
        assert_eq!(
            prl.for_priority(TenantPriority::Default)
                .unwrap()
                .max_requests,
            1000
        );
        assert_eq!(
            prl.for_priority(TenantPriority::Batch)
                .unwrap()
                .max_requests,
            100
        );
    }
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Path to the data directory.
    pub data_dir: PathBuf,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// Read buffer size per connection.
    pub read_buffer_size: usize,
    /// Write buffer size per connection.
    pub write_buffer_size: usize,
    /// Idle connection timeout. Connections with no activity for this
    /// duration will be closed. Set to None to disable.
    pub idle_timeout: Option<Duration>,
    /// Maximum requests per connection per minute for rate limiting.
    /// Set to None to disable rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
    /// TLS configuration. Set to None to disable TLS.
    pub tls: Option<TlsConfig>,
    /// Authentication mode.
    pub auth: AuthMode,
    /// Enable metrics endpoint.
    pub metrics_enabled: bool,
    /// Enable health check endpoints.
    pub health_enabled: bool,
    /// Bind address for the HTTP metrics/health sidecar.
    /// Set to `Some(addr)` to enable the HTTP sidecar on that address.
    /// Defaults to `Some("127.0.0.1:9090")`.
    pub metrics_bind_addr: Option<SocketAddr>,
    /// Replication mode (`Direct`, `SingleNode`, or `Cluster`).
    pub replication: ReplicationMode,
    /// OpenTelemetry OTLP endpoint (e.g., `http://localhost:4317`).
    /// Only used when the `otel` feature is enabled.
    pub otel_endpoint: Option<String>,
    /// Tag-based per-tenant rate limiting (FoundationDB pattern).
    /// When set, overrides `rate_limit` with per-tenant QoS tiers.
    pub tenant_tags: Option<TenantTagConfig>,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
}

/// QoS priority tag for tenant-based rate limiting (FoundationDB pattern).
///
/// Higher-priority tenants get more capacity. When the system is under load,
/// lower-priority requests are shed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TenantPriority {
    /// System-level operations (replication, health checks).
    /// Never rate limited.
    System,
    /// Default priority for most tenants.
    Default,
    /// Batch/background workloads (analytics, exports).
    /// First to be throttled under load.
    Batch,
}

/// Per-priority rate limit configuration.
#[derive(Debug, Clone, Copy)]
pub struct PriorityRateLimitConfig {
    /// Rate limit for system-priority tenants (None = unlimited).
    pub system: Option<RateLimitConfig>,
    /// Rate limit for default-priority tenants.
    pub default: RateLimitConfig,
    /// Rate limit for batch-priority tenants.
    pub batch: RateLimitConfig,
}

impl PriorityRateLimitConfig {
    /// Returns the rate limit config for the given priority.
    pub fn for_priority(&self, priority: TenantPriority) -> Option<RateLimitConfig> {
        match priority {
            TenantPriority::System => self.system,
            TenantPriority::Default => Some(self.default),
            TenantPriority::Batch => Some(self.batch),
        }
    }
}

/// Tenant tag configuration for per-tenant QoS.
#[derive(Debug, Clone)]
pub struct TenantTagConfig {
    /// Per-priority rate limits.
    pub rate_limits: PriorityRateLimitConfig,
    /// Mapping from tenant ID to priority. Tenants not in this map get `Default`.
    pub tenant_priorities: std::collections::HashMap<u64, TenantPriority>,
}

impl TenantTagConfig {
    /// Creates a new tenant tag config with default rate limits.
    pub fn new(default_limit: RateLimitConfig, batch_limit: RateLimitConfig) -> Self {
        Self {
            rate_limits: PriorityRateLimitConfig {
                system: None,
                default: default_limit,
                batch: batch_limit,
            },
            tenant_priorities: std::collections::HashMap::new(),
        }
    }

    /// Sets the priority for a specific tenant.
    pub fn with_tenant_priority(mut self, tenant_id: u64, priority: TenantPriority) -> Self {
        self.tenant_priorities.insert(tenant_id, priority);
        self
    }

    /// Returns the priority for a tenant (defaults to `Default`).
    pub fn priority_for(&self, tenant_id: u64) -> TenantPriority {
        self.tenant_priorities
            .get(&tenant_id)
            .copied()
            .unwrap_or(TenantPriority::Default)
    }

    /// Returns the rate limit config for a tenant.
    pub fn rate_limit_for(&self, tenant_id: u64) -> Option<RateLimitConfig> {
        let priority = self.priority_for(tenant_id);
        self.rate_limits.for_priority(priority)
    }
}

impl ServerConfig {
    /// Creates a new server configuration.
    pub fn new(bind_addr: impl Into<SocketAddr>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            data_dir: data_dir.into(),
            max_connections: 1024,
            read_buffer_size: 64 * 1024,                  // 64 KiB
            write_buffer_size: 64 * 1024,                 // 64 KiB
            idle_timeout: Some(Duration::from_secs(300)), // 5 minutes default
            rate_limit: None,
            tls: None,
            auth: AuthMode::None,
            metrics_enabled: true,
            health_enabled: true,
            metrics_bind_addr: Some("127.0.0.1:9090".parse().expect("valid address")),
            replication: ReplicationMode::Direct,
            otel_endpoint: None,
            tenant_tags: None,
        }
    }

    /// Sets the maximum number of concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the read buffer size.
    pub fn with_read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = size;
        self
    }

    /// Sets the write buffer size.
    pub fn with_write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = size;
        self
    }

    /// Sets the idle connection timeout.
    ///
    /// Connections with no activity for this duration will be closed.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Disables idle timeout (connections never timeout).
    pub fn without_idle_timeout(mut self) -> Self {
        self.idle_timeout = None;
        self
    }

    /// Enables rate limiting.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests per window
    /// * `window` - Time window for rate limiting
    pub fn with_rate_limit(mut self, max_requests: u32, window: Duration) -> Self {
        self.rate_limit = Some(RateLimitConfig {
            max_requests,
            window,
        });
        self
    }

    /// Enables TLS with the given configuration.
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Sets the authentication mode.
    pub fn with_auth(mut self, auth: AuthMode) -> Self {
        self.auth = auth;
        self
    }

    /// Disables the metrics endpoint.
    pub fn without_metrics(mut self) -> Self {
        self.metrics_enabled = false;
        self
    }

    /// Disables the health check endpoints.
    pub fn without_health_checks(mut self) -> Self {
        self.health_enabled = false;
        self
    }

    /// Enables single-node VSR replication.
    ///
    /// This provides durable command processing with idempotency tracking
    /// and superblock persistence.
    pub fn with_replication(mut self, mode: ReplicationMode) -> Self {
        self.replication = mode;
        self
    }

    /// Enables single-node VSR replication (convenience method).
    pub fn with_single_node_replication(self) -> Self {
        self.with_replication(ReplicationMode::single_node())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:5432".parse().expect("valid address"),
            data_dir: PathBuf::from("./data"),
            max_connections: 1024,
            read_buffer_size: 64 * 1024,
            write_buffer_size: 64 * 1024,
            idle_timeout: Some(Duration::from_secs(300)),
            rate_limit: None,
            tls: None,
            auth: AuthMode::None,
            metrics_enabled: true,
            health_enabled: true,
            metrics_bind_addr: Some("127.0.0.1:9090".parse().expect("valid address")),
            replication: ReplicationMode::Direct,
            otel_endpoint: None,
            tenant_tags: None,
        }
    }
}

impl ServerConfig {
    /// Enables tag-based per-tenant rate limiting (FoundationDB pattern).
    ///
    /// When set, per-tenant QoS tiers override the global `rate_limit` config.
    /// System-priority tenants are never throttled. Batch tenants are throttled
    /// first under load.
    pub fn with_tenant_tags(mut self, tags: TenantTagConfig) -> Self {
        self.tenant_tags = Some(tags);
        self
    }
}

impl RateLimitConfig {
    /// Creates a new rate limit configuration.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
        }
    }

    /// Creates a rate limit of N requests per minute.
    pub fn per_minute(max_requests: u32) -> Self {
        Self::new(max_requests, Duration::from_secs(60))
    }

    /// Creates a rate limit of N requests per second.
    pub fn per_second(max_requests: u32) -> Self {
        Self::new(max_requests, Duration::from_secs(1))
    }
}
