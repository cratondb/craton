//! Multi-node cluster management for Kimberlite.
//!
//! Provides local cluster orchestration for testing and development:
//! - Process supervision for multiple Kimberlite nodes
//! - Cluster initialization and topology configuration
//! - Health monitoring and failover testing
//! - Single supervisor process managing N nodes

pub mod backup;
pub mod config;
pub mod error;
pub mod node;
pub mod supervisor;

pub use backup::{
    BackupEntry, BackupSummary, RestoreSummary, backup_cluster, restore_cluster,
};
pub use config::{ClusterConfig, ClusterTopology, HTTP_PORT_OFFSET, NodeConfig, VSR_PORT_OFFSET};
pub use error::{Error, Result};
pub use node::{NodeProcess, NodeStatus};
pub use supervisor::ClusterSupervisor;

use std::path::PathBuf;

/// Creates a new localhost cluster with the specified number of nodes.
///
/// All nodes are colocated on `127.0.0.1`. For a multi-host topology
/// (one node per box behind a load balancer), use
/// [`init_cluster_with_hosts`].
pub fn init_cluster(data_dir: PathBuf, node_count: usize, base_port: u16) -> Result<ClusterConfig> {
    let config = ClusterConfig::try_new(data_dir, node_count, base_port)?;
    config.save()?;
    config.create_directories()?;
    Ok(config)
}

/// Creates a new cluster spanning the given hosts.
///
/// `hosts[i]` is the routable address other nodes use to reach node `i`
/// AND the address node `i` binds its data port to — pass each box's
/// public IP or DNS name. The number of nodes is `hosts.len()`; each node
/// claims `base_port + i` (data), `+ VSR_PORT_OFFSET` (VSR transport),
/// `+ HTTP_PORT_OFFSET` (probes).
///
/// The resulting config is validated for `(host, port)` uniqueness across
/// all three ports — collisions surface as
/// [`Error::DuplicateEndpoint`] rather than as opaque "address in use"
/// errors at child-spawn time.
pub fn init_cluster_with_hosts(
    data_dir: PathBuf,
    hosts: &[impl AsRef<str>],
    base_port: u16,
) -> Result<ClusterConfig> {
    let config = ClusterConfig::try_new_with_hosts(data_dir, hosts, base_port)?;
    config.save()?;
    config.create_directories()?;
    Ok(config)
}

/// Starts an existing cluster, spawning every node locally.
///
/// Suitable for `localhost` development and integration tests where one
/// supervisor process owns all N children. For a hospital deployment
/// where each node runs on a separate box, every box invokes
/// [`start_cluster_node`] with its own `node_id` instead — that
/// supervisor only owns the local entry and treats the rest as remote
/// peers.
pub async fn start_cluster(data_dir: PathBuf) -> Result<ClusterSupervisor> {
    let config = ClusterConfig::load(&data_dir)?;
    let mut supervisor = ClusterSupervisor::new(config);
    supervisor.start_all().await?;
    Ok(supervisor)
}

/// Starts a single node of an existing multi-host cluster.
///
/// The supervisor keeps the full topology in `cluster.toml` (so the spawned
/// child can render `KMB_CLUSTER_PEERS` for all peers) but only spawns and
/// monitors the entry whose id matches `node_id` — the remaining entries
/// are owned by supervisors on the other hosts.
///
/// # Errors
///
/// Returns [`Error::NotInitialized`] if `cluster.toml` is missing,
/// [`Error::DuplicateEndpoint`] if validation rejects the loaded config,
/// or [`Error::NodeIdOutOfRange`] if `node_id` is not in `cluster.toml`.
pub async fn start_cluster_node(
    data_dir: PathBuf,
    node_id: usize,
) -> Result<ClusterSupervisor> {
    let config = ClusterConfig::load(&data_dir)?;
    let mut supervisor = ClusterSupervisor::for_node(config, node_id)?;
    supervisor.start_all().await?;
    Ok(supervisor)
}

/// Stops a running cluster gracefully.
pub async fn stop_cluster(supervisor: &mut ClusterSupervisor) -> Result<()> {
    supervisor.stop_all().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_init_cluster() {
        let temp = TempDir::new().unwrap();
        let config = init_cluster(temp.path().to_path_buf(), 3, 5432).unwrap();

        assert_eq!(config.node_count, 3);
        assert_eq!(config.base_port, 5432);
        assert!(temp.path().join("cluster").exists());
    }

    #[test]
    fn test_cluster_config_save_load() {
        let temp = TempDir::new().unwrap();
        let config = ClusterConfig::new(temp.path().to_path_buf(), 3, 5432);
        config.save().unwrap();

        let loaded = ClusterConfig::load(temp.path()).unwrap();
        assert_eq!(loaded.node_count, config.node_count);
        assert_eq!(loaded.base_port, config.base_port);
    }
}
