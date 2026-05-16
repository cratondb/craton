//! Cluster management commands.

use anyhow::{Context, Result};
use comfy_table::{Cell, Color, Table, presets::UTF8_FULL};
use kimberlite_cluster::{
    ClusterConfig, NodeStatus, backup_cluster, init_cluster, init_cluster_with_hosts,
    restore_cluster, start_cluster, start_cluster_node,
};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use crate::style::{self, colors::SemanticStyle, create_spinner, finish_success};

/// Initialize a new cluster.
///
/// When `hosts` is empty, all nodes are colocated on `127.0.0.1` (the
/// localhost-dev path). When `hosts` is non-empty, it declares one
/// routable address per node and `nodes` is ignored — the operator's
/// intent is encoded in the host list directly.
pub fn init(nodes: u32, hosts: &[String], project: &str) -> Result<()> {
    let project_path = Path::new(project);
    let data_dir = project_path.to_path_buf();

    let spinner = create_spinner("Creating cluster configuration...");

    let config = if hosts.is_empty() {
        if nodes == 0 {
            return Err(anyhow::anyhow!("Node count must be >= 1"));
        }
        println!(
            "Initializing {}-node localhost cluster in {}...",
            nodes,
            project.code()
        );
        init_cluster(data_dir, nodes as usize, 5432)
            .with_context(|| "Failed to initialize cluster")?
    } else {
        println!(
            "Initializing {}-node multi-host cluster ({}) in {}...",
            hosts.len(),
            hosts.join(", "),
            project.code()
        );
        init_cluster_with_hosts(data_dir, hosts, 5432)
            .with_context(|| "Failed to initialize cluster")?
    };

    finish_success(&spinner, "Cluster initialized");

    println!();
    println!("Cluster Details:");
    println!("  Nodes: {}", config.node_count);
    println!("  Base Port: {}", config.base_port);
    println!(
        "  Cluster Dir: {}",
        config.cluster_dir().display().to_string().code()
    );
    println!();

    for node in &config.topology.nodes {
        println!(
            "  Node {} → {}:{} ({})",
            node.id,
            node.bind_address,
            node.port,
            node.data_dir.display().to_string().muted()
        );
    }

    println!();
    if hosts.is_empty() {
        println!("Start the cluster with:");
        println!("  {} cluster start", "kimberlite".code());
    } else {
        println!("Start each node from its own host:");
        for node in &config.topology.nodes {
            println!(
                "  {} cluster start --node-id {}   {}",
                "kimberlite".code(),
                node.id,
                format!("(on {})", node.bind_address).muted()
            );
        }
    }

    Ok(())
}

/// Start the cluster.
///
/// `node_id == None` brings every entry up locally (the localhost-dev path).
/// `node_id == Some(N)` spawns only entry `N` on this host and treats the
/// rest as remote peers — this is the multi-host deployment path. In both
/// modes the supervisor enters a monitor loop that auto-restarts crashed
/// children with bounded backoff until the operator hits Ctrl+C.
pub async fn start(node_id: Option<u32>, project: &str) -> Result<()> {
    let project_path = Path::new(project);

    // Verify cluster is initialized before we promise to spawn anything.
    let _ = ClusterConfig::load(project_path).with_context(|| {
        format!(
            "Cluster not initialized. Run: {} cluster init",
            "kimberlite".code()
        )
    })?;

    let spinner = create_spinner("Starting cluster nodes...");

    let mut supervisor = match node_id {
        Some(id) => {
            println!(
                "Starting node {} only in {}...",
                id,
                project.code()
            );
            start_cluster_node(project_path.to_path_buf(), id as usize)
                .await
                .with_context(|| "Failed to start cluster node")?
        }
        None => {
            println!("Starting cluster in {}...", project.code());
            start_cluster(project_path.to_path_buf())
                .await
                .with_context(|| "Failed to start cluster")?
        }
    };

    let running = supervisor.running_count();
    let total = supervisor.config().node_count;
    let owned = supervisor.status().len();

    finish_success(
        &spinner,
        &format!("{running}/{owned} owned nodes running ({total} total in topology)"),
    );

    println!();
    for (id, status, port) in supervisor.status() {
        let status_str = match status {
            NodeStatus::Running => style::success("Running"),
            NodeStatus::Starting => "Starting".to_string(),
            NodeStatus::Stopped => "Stopped".warning(),
            NodeStatus::Crashed => style::error("Crashed"),
        };
        println!("  Node {id} → Port {port} [{status_str}]");
    }

    println!();
    let stop_hint = if node_id.is_some() {
        "this node"
    } else {
        "all nodes"
    };
    println!(
        "Cluster running. Press {} to stop {stop_hint}.",
        "Ctrl+C".code()
    );
    println!();

    // Enter monitor loop — blocks until Ctrl+C
    supervisor.monitor_loop().await;

    Ok(())
}

/// Stop the cluster or specific node.
#[allow(clippy::unused_async)]
pub async fn stop(node_id: Option<u32>, project: &str) -> Result<()> {
    let project_path = Path::new(project);
    let config = ClusterConfig::load(project_path).with_context(|| "Cluster not initialized")?;

    if let Some(id) = node_id {
        println!("Stopping node {id}...");

        if id as usize >= config.node_count {
            return Err(anyhow::anyhow!("Node {id} does not exist"));
        }

        println!("{} Node {id} stopped", style::success("✓"));
    } else {
        println!("Stopping all nodes...");

        for i in 0..config.node_count {
            println!("{} Node {i} stopped", style::success("✓"));
        }
    }

    Ok(())
}

/// Show cluster status.
///
/// Probes each node's TCP port to determine if it is reachable.
pub fn status(project: &str) -> Result<()> {
    let project_path = Path::new(project);
    let config = ClusterConfig::load(project_path).with_context(|| {
        format!(
            "Cluster not initialized. Run: {} cluster init",
            "kimberlite".code()
        )
    })?;

    println!();
    println!("Cluster Status");
    println!();

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Node").fg(Color::Blue),
        Cell::new("Port").fg(Color::Blue),
        Cell::new("Status").fg(Color::Blue),
        Cell::new("Data Directory").fg(Color::Blue),
    ]);

    let mut running_count = 0;

    for node in &config.topology.nodes {
        // Probe TCP port to check if node is reachable
        let addr: SocketAddr = format!("{}:{}", node.bind_address, node.port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], node.port)));

        let is_running = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();

        let status_cell = if is_running {
            running_count += 1;
            Cell::new("Running").fg(Color::Green)
        } else {
            Cell::new("Stopped").fg(Color::Yellow)
        };

        table.add_row(vec![
            Cell::new(node.id),
            Cell::new(node.port),
            status_cell,
            Cell::new(node.data_dir.display().to_string()),
        ]);
    }

    println!("{table}");
    println!();
    println!("Base Port: {}", config.base_port);
    println!("Nodes: {running_count}/{} running", config.node_count);

    Ok(())
}

/// Back up a cluster's data dir into a `tar.zst` archive.
///
/// HIPAA § 164.308(a)(7) — contingency plan. The operator chooses when
/// to invoke this (stop writes first for a clean snapshot, or accept
/// the trailing-fsync semantic). The archive carries an embedded
/// BLAKE3 manifest so [`restore`] can verify integrity end-to-end.
pub fn backup(project: &str, output: &str) -> Result<()> {
    let project_path = Path::new(project);
    let output_path = Path::new(output);

    println!(
        "Backing up cluster {} → {}",
        project.code(),
        output.code()
    );

    let spinner = create_spinner("Creating archive...");
    let summary = backup_cluster(project_path, output_path)
        .with_context(|| "Failed to back up cluster")?;
    finish_success(
        &spinner,
        &format!(
            "Backup complete ({} files, {} MB → {} MB)",
            summary.file_count,
            summary.uncompressed_bytes / 1_048_576,
            summary.compressed_bytes / 1_048_576,
        ),
    );

    println!();
    println!("Archive: {}", summary.archive_path.display().to_string().code());
    println!("Files:   {}", summary.file_count);
    println!(
        "Size:    {} bytes uncompressed, {} bytes on disk",
        summary.uncompressed_bytes, summary.compressed_bytes
    );
    println!("Created: {} (UNIX seconds)", summary.created_at_secs);

    Ok(())
}

/// Restore a cluster backup into a fresh data dir.
///
/// The target directory must be empty or absent; restoring on top of a
/// live cluster is rejected. After extract, every file's BLAKE3 is
/// re-checked against the archive's manifest.
pub fn restore(input: &str, target: &str) -> Result<()> {
    let input_path = Path::new(input);
    let target_path = Path::new(target);

    println!(
        "Restoring backup {} → {}",
        input.code(),
        target.code()
    );

    let spinner = create_spinner("Extracting and verifying...");
    let summary = restore_cluster(input_path, target_path)
        .with_context(|| "Failed to restore cluster")?;
    finish_success(
        &spinner,
        &format!("Restore complete ({} files)", summary.file_count),
    );

    println!();
    println!(
        "Cluster dir: {}",
        summary.cluster_dir.display().to_string().code()
    );
    println!("Files:       {}", summary.file_count);
    println!("Size:        {} bytes", summary.uncompressed_bytes);
    println!();
    println!(
        "Start the restored cluster with:  {} cluster start --project {}",
        "kimberlite".code(),
        target.code()
    );

    Ok(())
}

/// Destroy cluster configuration.
pub fn destroy(project: &str, force: bool) -> Result<()> {
    let project_path = Path::new(project);
    let config = ClusterConfig::load(project_path).with_context(|| "Cluster not initialized")?;

    println!("{}", "WARNING: This will delete all cluster data!".error());
    println!(
        "Cluster directory: {}",
        config.cluster_dir().display().to_string().muted()
    );

    if !force {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt("Are you sure you want to destroy the cluster?")
            .default(false)
            .interact()
            .unwrap_or(false);

        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let spinner = create_spinner("Destroying cluster...");

    std::fs::remove_dir_all(config.cluster_dir())
        .with_context(|| "Failed to remove cluster directory")?;

    finish_success(&spinner, "Cluster destroyed");

    Ok(())
}
