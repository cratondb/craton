//! Node process management.

use crate::{Error, NodeConfig, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::sleep;

/// Status of a cluster node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is stopped.
    Stopped,

    /// Node is starting up.
    Starting,

    /// Node is running normally.
    Running,

    /// Node has crashed.
    Crashed,
}

/// A managed Kimberlite node process.
pub struct NodeProcess {
    /// Node configuration.
    pub config: NodeConfig,

    /// Child process handle.
    pub process: Option<Child>,

    /// Current status.
    pub status: NodeStatus,

    /// Number of restart attempts.
    pub restart_count: usize,
}

impl NodeProcess {
    /// Creates a new node process (not started).
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            process: None,
            status: NodeStatus::Stopped,
            restart_count: 0,
        }
    }

    /// Starts the node process by spawning a real `kimberlite start` invocation.
    ///
    /// Single-node configurations (`peers.is_empty()`) boot in the default
    /// single-node-VSR mode; multi-node configurations boot with `--cluster`
    /// and the `KMB_REPLICA_ID` / `KMB_CLUSTER_PEERS` env vars VSR expects.
    /// `KMB_ENABLE_FOLLOWER_PROJECTION=1` is set so follower reads see leader
    /// writes (otherwise the projection layer is leader-only).
    ///
    /// The data directory is created if missing — VSR's superblock + log
    /// allocate on first boot, and a missing dir would fail with a confusing
    /// `Failed to open database` error before the supervisor saw anything.
    pub async fn start(&mut self) -> Result<()> {
        if self.status != NodeStatus::Stopped && self.status != NodeStatus::Crashed {
            return Err(Error::NodeAlreadyRunning(self.config.id));
        }

        self.status = NodeStatus::Starting;

        let bin = match locate_kimberlite_binary() {
            Ok(p) => p,
            Err(e) => {
                self.status = NodeStatus::Crashed;
                return Err(e);
            }
        };

        let address = format!("{}:{}", self.config.bind_address, self.config.port);

        if let Err(e) = std::fs::create_dir_all(&self.config.data_dir) {
            self.status = NodeStatus::Crashed;
            return Err(Error::Io(e));
        }

        let mut command = Command::new(&bin);
        command
            .arg("start")
            .arg(self.config.data_dir.as_os_str())
            .arg("--address")
            .arg(&address)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if !self.config.peers.is_empty() {
            command.arg("--cluster");
            let peers_env = render_cluster_peers_env(
                self.config.id,
                &self.config.bind_address,
                self.config.port,
                &self.config.peers,
            );
            command.env("KMB_REPLICA_ID", self.config.id.to_string());
            command.env("KMB_CLUSTER_PEERS", peers_env);
            // Bind the HTTP sidecar at data_port + 1000 so probes are
            // reachable per node without colliding with peer data ports.
            let http_port = self.config.port.saturating_add(1000);
            command.env("KMB_HTTP_PORT", http_port.to_string());
            // Drive follower projections so cross-node reads see leader
            // writes — without this the projection layer is leader-only.
            command.env("KMB_ENABLE_FOLLOWER_PROJECTION", "1");
        }

        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.status = NodeStatus::Crashed;
                return Err(Error::SpawnError(format!(
                    "failed to spawn `{}`: {e}",
                    bin.display()
                )));
            }
        };

        self.process = Some(child);

        // Give the child a moment to fail fast on obvious errors (bad args,
        // port conflict). Real readiness is the caller's responsibility —
        // an integration test should poll the data port until it accepts.
        sleep(Duration::from_millis(200)).await;

        if self.is_alive() {
            self.status = NodeStatus::Running;
            Ok(())
        } else {
            self.status = NodeStatus::Crashed;
            Err(Error::NodeStartFailed(
                self.config.id,
                "process exited immediately after spawn".to_string(),
            ))
        }
    }

    /// Stops the node process gracefully.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.process.take() {
            // Use tokio's built-in kill (sends SIGKILL on Unix, TerminateProcess on Windows)
            child.kill().await.ok();

            // Wait for it to exit (with timeout)
            let exit_status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;

            match exit_status {
                Ok(Ok(_status)) => {
                    self.status = NodeStatus::Stopped;
                    Ok(())
                }
                Ok(Err(e)) => {
                    self.status = NodeStatus::Stopped;
                    Err(Error::Io(e))
                }
                Err(_) => {
                    // Timeout, but we already killed it
                    self.status = NodeStatus::Stopped;
                    Ok(())
                }
            }
        } else {
            Ok(()) // Already stopped
        }
    }

    /// Checks if the node process is alive.
    pub fn is_alive(&mut self) -> bool {
        if let Some(child) = &mut self.process {
            // Try to check if process has exited
            match child.try_wait() {
                Ok(Some(_exit_status)) => false, // Process has exited
                Ok(None) => true,                // Still running
                Err(_) => false,                 // Error checking, assume dead
            }
        } else {
            false
        }
    }

    /// Returns the node ID.
    pub fn id(&self) -> usize {
        self.config.id
    }

    /// Returns the port.
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Returns the OS process ID of the running child, if any.
    ///
    /// Used by integration tests that need to send signals out-of-band
    /// (e.g. SIGKILL for a forced-crash scenario). Returns `None` once the
    /// child has exited, since the OS may recycle the PID.
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().and_then(Child::id)
    }

    /// Sends SIGKILL to the running child without taking ownership of it.
    ///
    /// Unlike [`Self::stop`], this leaves [`Self::status`] untouched so the
    /// next supervisor poll observes the death and treats it as a crash —
    /// the path the supervisor's restart-with-backoff logic exercises.
    /// Returns `Ok(())` when no child is attached (idempotent).
    pub fn force_kill(&mut self) -> Result<()> {
        if let Some(child) = self.process.as_mut() {
            child.start_kill().map_err(Error::Io)?;
        }
        Ok(())
    }

    /// Attempts to restart a crashed node.
    pub async fn restart(&mut self) -> Result<()> {
        if self.status != NodeStatus::Crashed {
            return Ok(());
        }

        self.restart_count += 1;

        // Exponential backoff
        let backoff = Duration::from_secs(2u64.pow(self.restart_count.min(5) as u32));
        sleep(backoff).await;

        self.start().await
    }
}

/// Locates the `kimberlite` binary the supervisor should spawn.
///
/// Search order:
/// 1. `KIMBERLITE_BIN` environment variable (must point to an existing file).
/// 2. `kimberlite` (or `kimberlite.exe` on Windows) on `$PATH`.
/// 3. Sibling of the current executable, then its parent — covers the cargo
///    layout where test binaries live in `target/<profile>/deps/` while the
///    `kimberlite` binary lives one directory up in `target/<profile>/`.
///
/// Returns [`Error::SpawnError`] with a remediation hint if no candidate is
/// found, so operator output points at the correct lever (env var, PATH,
/// rebuild) rather than a bare ENOENT.
pub fn locate_kimberlite_binary() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("KIMBERLITE_BIN") {
        let p = PathBuf::from(&override_path);
        if p.is_file() {
            return Ok(p);
        }
        return Err(Error::SpawnError(format!(
            "KIMBERLITE_BIN={override_path} does not point to an existing file"
        )));
    }

    let exe_name = if cfg!(windows) {
        "kimberlite.exe"
    } else {
        "kimberlite"
    };

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
            if let Some(parent) = dir.parent() {
                let candidate = parent.join(exe_name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(Error::SpawnError(format!(
        "could not locate `{exe_name}`: set KIMBERLITE_BIN, add it to PATH, \
         or build the workspace so it sits next to the cluster binary"
    )))
}

/// VSR uses its own TCP listener per replica, distinct from the
/// client-facing data port. The supervisor uses this fixed offset to
/// derive the VSR port from each node's configured data port — same
/// convention as the docker-compose / chaos-VM topologies, just on
/// localhost where ports must not collide between nodes.
///
/// Concretely: data port `15432` → VSR port `15532`, HTTP probe port
/// `16432`. Three nodes on consecutive bases occupy 9 distinct ports.
pub const VSR_PORT_OFFSET: u16 = 100;

/// Renders the `KMB_CLUSTER_PEERS` env value (`0=host:port,1=host:port,...`)
/// using VSR ports rather than data ports.
///
/// `peers` is the existing `NodeConfig::peers` list, which is generated in
/// replica-id order with self omitted; reinserting self at position
/// `self_id` recovers the full membership ordered by replica id. The
/// per-entry `host:data_port` is rewritten to `host:vsr_port` via
/// [`VSR_PORT_OFFSET`] so the VSR transport's listener doesn't collide
/// with the server's client-facing bind.
fn render_cluster_peers_env(
    self_id: usize,
    self_addr: &str,
    self_port: u16,
    peers: &[String],
) -> String {
    let total = peers.len() + 1;
    let mut entries: Vec<String> = Vec::with_capacity(total);
    let mut peer_iter = peers.iter();
    for id in 0..total {
        let entry = if id == self_id {
            format!(
                "{id}={self_addr}:{}",
                self_port.saturating_add(VSR_PORT_OFFSET)
            )
        } else {
            let raw = peer_iter
                .next()
                .expect("peer list inconsistent with self_id: peers should equal node_count - 1");
            let shifted = shift_peer_port(raw, VSR_PORT_OFFSET);
            format!("{id}={shifted}")
        };
        entries.push(entry);
    }
    entries.join(",")
}

/// Adds `offset` to the port suffix of a `host:port` peer string. Falls
/// back to the original string if the port doesn't parse — the spawned
/// child will surface a clearer error than this helper would.
fn shift_peer_port(addr: &str, offset: u16) -> String {
    let Some(colon) = addr.rfind(':') else {
        return addr.to_string();
    };
    let (host, port_str) = addr.split_at(colon);
    let port_str = &port_str[1..];
    let Ok(port) = port_str.parse::<u16>() else {
        return addr.to_string();
    };
    format!("{host}:{}", port.saturating_add(offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_node_config() -> NodeConfig {
        NodeConfig {
            id: 0,
            port: 5432,
            bind_address: "127.0.0.1".to_string(),
            data_dir: PathBuf::from("/tmp/node-0"),
            peers: vec!["127.0.0.1:5433".to_string()],
        }
    }

    #[test]
    fn test_node_process_creation() {
        let config = test_node_config();
        let node = NodeProcess::new(config);

        assert_eq!(node.status, NodeStatus::Stopped);
        assert_eq!(node.id(), 0);
        assert_eq!(node.port(), 5432);
    }

    #[tokio::test]
    async fn test_node_start_stop() {
        let config = test_node_config();
        let mut node = NodeProcess::new(config);

        // Without a built `kimberlite` binary on PATH/KIMBERLITE_BIN this
        // surfaces SpawnError; with one, the cluster boot may either come
        // up or die immediately — either outcome is fine for the unit test.
        let start_result = node.start().await;

        if start_result.is_ok() {
            assert_eq!(node.status, NodeStatus::Running);
            assert!(node.is_alive());
            node.stop().await.unwrap();
            assert_eq!(node.status, NodeStatus::Stopped);
            assert!(!node.is_alive());
        } else {
            assert_eq!(node.status, NodeStatus::Crashed);
        }
    }

    #[tokio::test]
    async fn test_node_double_start_error() {
        let config = test_node_config();
        let mut node = NodeProcess::new(config);

        if node.start().await.is_ok() {
            let result = node.start().await;
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), Error::NodeAlreadyRunning(0)));
            node.stop().await.ok();
        }
    }

    #[test]
    fn render_cluster_peers_env_inserts_self_in_id_order_with_vsr_offset() {
        let env = render_cluster_peers_env(
            1,
            "127.0.0.1",
            5433,
            &[
                "127.0.0.1:5432".to_string(),
                "127.0.0.1:5434".to_string(),
            ],
        );
        // VSR ports = data ports + VSR_PORT_OFFSET (100).
        assert_eq!(
            env,
            "0=127.0.0.1:5532,1=127.0.0.1:5533,2=127.0.0.1:5534"
        );
    }

    #[test]
    fn render_cluster_peers_env_handles_node_zero() {
        let env =
            render_cluster_peers_env(0, "127.0.0.1", 5432, &["127.0.0.1:5433".to_string()]);
        assert_eq!(env, "0=127.0.0.1:5532,1=127.0.0.1:5533");
    }

    #[test]
    fn shift_peer_port_advances_only_the_port() {
        assert_eq!(shift_peer_port("127.0.0.1:5432", 100), "127.0.0.1:5532");
        assert_eq!(shift_peer_port("[::1]:5432", 100), "[::1]:5532");
    }

    #[test]
    fn shift_peer_port_returns_input_when_unparseable() {
        // No colon → unchanged.
        assert_eq!(shift_peer_port("not-an-addr", 100), "not-an-addr");
        // Non-numeric port → unchanged.
        assert_eq!(shift_peer_port("host:abc", 100), "host:abc");
    }

    #[test]
    fn locate_kimberlite_binary_returns_a_path_or_helpful_error() {
        // The discovery helper is fully exercised by the integration
        // smoke test (which spawns a real binary). At unit-test time we
        // only sanity-check the contract: either it found something on
        // PATH / next to the test binary, or it returned a SpawnError
        // with operator-actionable wording. Modifying env vars in 2024-
        // edition is `unsafe` (workspace-denied), so we can't exercise
        // the override branch here without violating the lint.
        match locate_kimberlite_binary() {
            Ok(path) => assert!(path.is_file(), "discovered path must exist"),
            Err(Error::SpawnError(msg)) => {
                assert!(
                    msg.contains("KIMBERLITE_BIN") || msg.contains("PATH"),
                    "error should hint at remediation: {msg}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
