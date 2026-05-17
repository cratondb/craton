//! Cluster configuration management.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// VSR transport port offset from the data port (`vsr_port = data_port + 100`).
///
/// Mirrors the value used by [`crate::node`] when rendering
/// `KMB_CLUSTER_PEERS`. Kept here so [`ClusterConfig::validate`] can check
/// the derived ports without a circular dep on the `node` module.
pub const VSR_PORT_OFFSET: u16 = 100;

/// HTTP-probe port offset from the data port (`http_port = data_port + 1000`).
///
/// Drives `/healthz`, `/readyz`, `/metrics`. The 1000-gap keeps the three
/// per-node ports legible to operators (a node on data port `15432` exposes
/// VSR on `15532` and HTTP on `16432`).
pub const HTTP_PORT_OFFSET: u16 = 1000;

/// Configuration for a Kimberlite cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Number of nodes in the cluster.
    pub node_count: usize,

    /// Base port number (node N uses `base_port` + N).
    pub base_port: u16,

    /// Root data directory for cluster.
    pub data_dir: PathBuf,

    /// Cluster topology (peers, leaders, etc.).
    pub topology: ClusterTopology,
}

/// Cluster topology configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTopology {
    /// Node configurations.
    pub nodes: Vec<NodeConfig>,
}

/// Configuration for a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node ID (0-indexed).
    pub id: usize,

    /// Port number.
    pub port: u16,

    /// Address to bind to.
    pub bind_address: String,

    /// Data directory for this node.
    pub data_dir: PathBuf,

    /// Peer addresses (for replication).
    pub peers: Vec<String>,
}

impl ClusterConfig {
    /// Creates a new cluster configuration.
    ///
    /// Prefer [`ClusterConfig::try_new`] in new code — it returns a
    /// [`Result`] rather than panicking on invalid input. This infallible
    /// form is kept for ergonomics in tests and happy-path code where the
    /// inputs are known-good.
    ///
    /// # Panics
    ///
    /// Panics if `node_count == 0`. For a fallible alternative, see
    /// [`ClusterConfig::try_new`].
    #[track_caller]
    pub fn new(data_dir: impl Into<PathBuf>, node_count: usize, base_port: u16) -> Self {
        Self::try_new(data_dir, node_count, base_port).expect(
            "ClusterConfig::new: invalid parameters — use try_new for fallible construction",
        )
    }

    /// Creates a new cluster configuration, validating parameters.
    ///
    /// All nodes are colocated on `127.0.0.1`. For a multi-host topology,
    /// use [`ClusterConfig::try_new_with_hosts`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNodeCount`] if `node_count == 0`.
    /// Returns [`Error::InvalidPortRange`] if `base_port + node_count` overflows.
    pub fn try_new(
        data_dir: impl Into<PathBuf>,
        node_count: usize,
        base_port: u16,
    ) -> Result<Self> {
        if node_count == 0 {
            return Err(Error::InvalidNodeCount(node_count));
        }
        let hosts: Vec<&str> = (0..node_count).map(|_| "127.0.0.1").collect();
        Self::try_new_with_hosts(data_dir, &hosts, base_port)
    }

    /// Creates a new cluster configuration with one host per node.
    ///
    /// `hosts[i]` is the routable address other nodes use to reach node `i`
    /// AND the address node `i` binds its data port to. For localhost dev,
    /// pass `["127.0.0.1"; N]`; for a multi-box hospital deployment, pass
    /// each box's routable IP or DNS name.
    ///
    /// Node ports follow the same convention as [`Self::try_new`]: data port
    /// `base_port + i`, VSR port `data_port + 100`, HTTP probe port
    /// `data_port + 1000`. The resulting config is run through
    /// [`Self::validate`] before return so callers cannot construct one that
    /// would deadlock at first spawn.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyHosts`] if `hosts` is empty.
    /// Returns [`Error::InvalidPortRange`] if any derived port (data, VSR,
    /// HTTP) overflows `u16`.
    /// Returns [`Error::DuplicateEndpoint`] if two nodes claim the same
    /// `(host, port)` tuple on any of the three ports.
    pub fn try_new_with_hosts(
        data_dir: impl Into<PathBuf>,
        hosts: &[impl AsRef<str>],
        base_port: u16,
    ) -> Result<Self> {
        if hosts.is_empty() {
            return Err(Error::EmptyHosts);
        }
        let node_count = hosts.len();
        // Each node needs ports at `base_port + i + DERIVED_OFFSET`. Validate
        // the highest derived port (HTTP) fits in `u16` first; everything
        // else is strictly smaller.
        let max_offset: u32 = (node_count - 1) as u32 + u32::from(HTTP_PORT_OFFSET);
        if u32::from(base_port) + max_offset > u32::from(u16::MAX) {
            return Err(Error::InvalidPortRange(base_port, node_count));
        }
        let data_dir = data_dir.into();

        // Generate node configs. Peer list excludes self, ordered by id
        // ascending — `render_cluster_peers_env` reinserts self at its
        // own index, so peers must be in that exact order.
        let mut nodes = Vec::with_capacity(node_count);
        for id in 0..node_count {
            let port = base_port + id as u16;
            let node_data_dir = data_dir.join("cluster").join(format!("node-{id}"));

            let peers: Vec<String> = (0..node_count)
                .filter(|&peer_id| peer_id != id)
                .map(|peer_id| {
                    let peer_port = base_port + peer_id as u16;
                    let peer_host = hosts[peer_id].as_ref();
                    format!("{peer_host}:{peer_port}")
                })
                .collect();

            nodes.push(NodeConfig {
                id,
                port,
                bind_address: hosts[id].as_ref().to_string(),
                data_dir: node_data_dir,
                peers,
            });
        }

        let config = Self {
            node_count,
            base_port,
            data_dir: data_dir.clone(),
            topology: ClusterTopology { nodes },
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates the topology: every `(host, port)` tuple — across the
    /// data, VSR, and HTTP-sidecar ports — must be unique.
    ///
    /// This is the gate the multi-host deployment story leans on: the
    /// supervisor on each box trusts that `cluster.toml` is collision-free
    /// before it spawns a child process that would otherwise fight a
    /// neighbour for a TCP listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateEndpoint`] with the colliding tuple and
    /// the two node ids involved.
    pub fn validate(&self) -> Result<()> {
        let mut seen: Vec<(String, u16, usize)> = Vec::with_capacity(self.node_count * 3);
        for node in &self.topology.nodes {
            for (label_port, _label) in [
                (node.port, "data"),
                (node.port.saturating_add(VSR_PORT_OFFSET), "vsr"),
                (node.port.saturating_add(HTTP_PORT_OFFSET), "http"),
            ] {
                if let Some((_, _, first)) = seen
                    .iter()
                    .find(|(h, p, _)| h == &node.bind_address && *p == label_port)
                {
                    return Err(Error::DuplicateEndpoint {
                        host: node.bind_address.clone(),
                        port: label_port,
                        first: *first,
                        second: node.id,
                    });
                }
                seen.push((node.bind_address.clone(), label_port, node.id));
            }
        }
        Ok(())
    }

    /// Loads cluster configuration from disk.
    ///
    /// Hand-edited `cluster.toml` is the multi-host onboarding path, so the
    /// loaded config is run through [`Self::validate`] before return — the
    /// alternative is an opaque "VSR transport failed to bind" error in the
    /// child process minutes later.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let config_path = data_dir.join("cluster").join("cluster.toml");

        if !config_path.exists() {
            return Err(Error::NotInitialized(data_dir.to_path_buf()));
        }

        let content = fs::read_to_string(&config_path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;

        Ok(config)
    }

    /// Saves cluster configuration to disk.
    pub fn save(&self) -> Result<()> {
        let cluster_dir = self.data_dir.join("cluster");
        fs::create_dir_all(&cluster_dir)?;

        let config_path = cluster_dir.join("cluster.toml");
        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;

        Ok(())
    }

    /// Creates directory structure for all nodes.
    pub fn create_directories(&self) -> Result<()> {
        for node in &self.topology.nodes {
            fs::create_dir_all(&node.data_dir)?;
        }
        Ok(())
    }

    /// Returns the configuration for a specific node.
    pub fn get_node(&self, id: usize) -> Option<&NodeConfig> {
        self.topology.nodes.get(id)
    }

    /// Returns the cluster directory path.
    pub fn cluster_dir(&self) -> PathBuf {
        self.data_dir.join("cluster")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cluster_config_creation() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);

        assert_eq!(config.node_count, 3);
        assert_eq!(config.base_port, 5432);
        assert_eq!(config.topology.nodes.len(), 3);

        // Check node 0
        let node0 = &config.topology.nodes[0];
        assert_eq!(node0.id, 0);
        assert_eq!(node0.port, 5432);
        assert_eq!(node0.peers.len(), 2); // 2 other nodes

        // Check node 1
        let node1 = &config.topology.nodes[1];
        assert_eq!(node1.id, 1);
        assert_eq!(node1.port, 5433);
    }

    #[test]
    fn test_save_and_load() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);

        config.save().unwrap();

        let loaded = ClusterConfig::load(temp.path()).unwrap();
        assert_eq!(loaded.node_count, 3);
        assert_eq!(loaded.base_port, 5432);
        assert_eq!(loaded.topology.nodes.len(), 3);
    }

    #[test]
    fn test_create_directories() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);

        config.create_directories().unwrap();

        for i in 0..3 {
            let node_dir = temp.path().join("cluster").join(format!("node-{i}"));
            assert!(node_dir.exists());
        }
    }

    #[test]
    fn test_get_node() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);

        let node = config.get_node(1).unwrap();
        assert_eq!(node.id, 1);
        assert_eq!(node.port, 5433);

        assert!(config.get_node(10).is_none());
    }

    #[test]
    fn test_peer_list_excludes_self() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);

        let node0 = &config.topology.nodes[0];
        assert_eq!(node0.peers.len(), 2);
        assert!(!node0.peers.iter().any(|p| p.contains("5432")));
        assert!(node0.peers.iter().any(|p| p.contains("5433")));
        assert!(node0.peers.iter().any(|p| p.contains("5434")));
    }

    #[test]
    fn try_new_with_hosts_assigns_per_node_bind_address() {
        let temp = TempDir::new().unwrap();
        let hosts = ["10.0.1.5", "10.0.1.6", "10.0.1.7"];
        let config =
            ClusterConfig::try_new_with_hosts(temp.path().to_path_buf(), &hosts, 5432).unwrap();

        assert_eq!(config.topology.nodes.len(), 3);
        for (i, node) in config.topology.nodes.iter().enumerate() {
            assert_eq!(node.bind_address, hosts[i]);
            assert_eq!(node.port, 5432 + i as u16);
        }

        // Node 0's peer list contains node 1 and node 2's IPs, not its own.
        let node0 = &config.topology.nodes[0];
        assert_eq!(node0.peers.len(), 2);
        assert!(node0.peers.contains(&"10.0.1.6:5433".to_string()));
        assert!(node0.peers.contains(&"10.0.1.7:5434".to_string()));
        assert!(!node0.peers.iter().any(|p| p.contains("10.0.1.5")));
    }

    #[test]
    fn try_new_with_hosts_rejects_empty_list() {
        let temp = TempDir::new().unwrap();
        let hosts: [&str; 0] = [];
        let err =
            ClusterConfig::try_new_with_hosts(temp.path().to_path_buf(), &hosts, 5432).unwrap_err();
        assert!(matches!(err, Error::EmptyHosts), "got {err:?}");
    }

    #[test]
    fn try_new_with_hosts_allows_colocated_nodes() {
        // Same host, distinct data ports → no collision, validate passes.
        // (Localhost dev is the existing case; `try_new` collapses to this.)
        let temp = TempDir::new().unwrap();
        let hosts = ["10.0.1.5", "10.0.1.5", "10.0.1.5"];
        let config =
            ClusterConfig::try_new_with_hosts(temp.path().to_path_buf(), &hosts, 5432).unwrap();
        config.validate().unwrap();
        for node in &config.topology.nodes {
            assert_eq!(node.bind_address, "10.0.1.5");
        }
    }

    #[test]
    fn validate_rejects_duplicate_data_port() {
        let temp = TempDir::new().unwrap();
        let mut config = ClusterConfig::try_new_with_hosts(
            temp.path().to_path_buf(),
            &["10.0.1.5", "10.0.1.6"],
            5432,
        )
        .unwrap();
        // Hand-edit: pin node 1 onto the same host & port as node 0.
        config.topology.nodes[1].bind_address = "10.0.1.5".to_string();
        config.topology.nodes[1].port = 5432;
        match config.validate().unwrap_err() {
            Error::DuplicateEndpoint {
                host,
                port,
                first,
                second,
            } => {
                assert_eq!(host, "10.0.1.5");
                assert_eq!(port, 5432);
                assert_eq!(first, 0);
                assert_eq!(second, 1);
            }
            other => panic!("expected DuplicateEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn validate_catches_data_vs_vsr_port_collision() {
        // Same host on both nodes; node 1's data port collides with node 0's
        // VSR port (data + VSR_PORT_OFFSET).
        let temp = TempDir::new().unwrap();
        let mut config = ClusterConfig::try_new_with_hosts(
            temp.path().to_path_buf(),
            &["10.0.1.5", "10.0.1.5"],
            5432,
        )
        .unwrap();
        config
            .validate()
            .expect("baseline config is collision-free");

        config.topology.nodes[1].port = config.topology.nodes[0].port + VSR_PORT_OFFSET;
        match config.validate().unwrap_err() {
            Error::DuplicateEndpoint { host, port, .. } => {
                assert_eq!(host, "10.0.1.5");
                assert_eq!(port, 5532);
            }
            other => panic!("expected DuplicateEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn try_new_with_hosts_rejects_port_overflow() {
        let temp = TempDir::new().unwrap();
        // HTTP port for node 0 = base + HTTP_PORT_OFFSET. Pick a base that
        // overflows even the smallest derived port.
        let hosts = ["10.0.1.5"];
        let err =
            ClusterConfig::try_new_with_hosts(temp.path().to_path_buf(), &hosts, u16::MAX - 100)
                .unwrap_err();
        assert!(matches!(err, Error::InvalidPortRange(_, _)), "got {err:?}");
    }
}
