//! Multi-host topology integration tests.
//!
//! On a real hospital deployment each node runs on its own box, with one
//! supervisor per box owning the local entry and treating the rest as
//! remote peers (T2.1 from the v0.9.x cluster graduation plan). We can't
//! simulate distinct IPs in a unit test, but we can exercise the same
//! code path on a single host:
//!
//!   - author a `cluster.toml` with the multi-host builder
//!     (`init_cluster_with_hosts`) so the constructor's host-propagation
//!     and uniqueness-validation paths run,
//!   - spawn each node via `start_cluster_node(node_id)` so each
//!     supervisor only owns its one local entry,
//!   - drive a leader-write / follower-read round-trip end-to-end.
//!
//! The cluster looks identical to VSR on the wire — the only difference
//! versus `three_node_smoke.rs` is which code path the supervisor
//! reaches. If this test green, the multi-host deployment story is
//! gated only on operator-supplied routable IPs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kimberlite_client::{Client, ClientConfig};
use kimberlite_cluster::{ClusterConfig, ClusterSupervisor, init_cluster_with_hosts};
use kimberlite_types::{DataClass, Offset, TenantId};
use tempfile::TempDir;

mod common;

const SMOKE_TENANT: u64 = 1;

/// Best-effort cluster shutdown — same pattern as `three_node_smoke.rs`.
async fn teardown(mut supervisors: Vec<ClusterSupervisor>) {
    for s in &mut supervisors {
        let _ = s.stop_all().await;
    }
}

#[tokio::test]
#[ignore = "spawns real kimberlite processes; run with --ignored or in nightly"]
async fn multi_host_init_and_per_node_start_end_to_end() {
    let Some(_bin) = common::locate_built_kimberlite() else {
        eprintln!(
            "skipping: no built `kimberlite` binary found; run `cargo build` \
             or set KIMBERLITE_BIN before re-running with --ignored"
        );
        return;
    };

    let temp = TempDir::new().expect("temp dir");
    let base_port = common::pick_base_port();

    // Author a cluster.toml as if there were 3 distinct hosts. The
    // localhost integration test elides the IP differences (they all
    // resolve to the same NIC) but the bind_address propagation is
    // identical to the production path.
    let hosts = [
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
    ];
    let config = init_cluster_with_hosts(temp.path().to_path_buf(), &hosts, base_port)
        .expect("init_cluster_with_hosts");

    assert_eq!(config.node_count, 3);
    for (i, node) in config.topology.nodes.iter().enumerate() {
        assert_eq!(
            node.bind_address, "127.0.0.1",
            "host did not propagate for node {i}",
        );
    }

    // Spawn each node from its own "supervisor" — the real multi-host
    // shape, just collapsed onto one box. Each call to
    // `start_cluster_node(N)` owns only entry N and renders
    // KMB_CLUSTER_PEERS with all three IPs/ports.
    let mut supervisors: Vec<ClusterSupervisor> = Vec::with_capacity(3);
    for node_id in 0..3 {
        let supervisor = kimberlite_cluster::start_cluster_node(temp.path().to_path_buf(), node_id)
            .await
            .unwrap_or_else(|e| panic!("start_cluster_node({node_id}) failed: {e}"));

        // Sanity: this supervisor only owns one local entry, but the
        // full topology is preserved for peer addressing.
        let status = supervisor.config().topology.nodes.len();
        assert_eq!(status, 3, "supervisor lost peer entries for node {node_id}");

        supervisors.push(supervisor);
    }

    common::wait_for_tcp_ready(base_port, 3, Duration::from_secs(20));

    // Round-trip: write through node 0 (assumed boot-time leader),
    // read on node 1.
    let leader_addr = format!("127.0.0.1:{base_port}");
    let mut leader = match Client::connect(
        &leader_addr,
        TenantId::new(SMOKE_TENANT),
        ClientConfig::default(),
    ) {
        Ok(c) => c,
        Err(e) => {
            teardown(supervisors).await;
            panic!("leader connect failed: {e}");
        }
    };
    let stream_id = match leader.create_stream("multi-host-smoke", DataClass::Public) {
        Ok(s) => s,
        Err(e) => {
            drop(leader);
            teardown(supervisors).await;
            panic!("create_stream failed: {e}");
        }
    };
    let payload = b"multi-host-smoke-event".to_vec();
    if let Err(e) = leader.append(stream_id, vec![payload.clone()], Offset::ZERO) {
        drop(leader);
        teardown(supervisors).await;
        panic!("append failed: {e}");
    }
    drop(leader);

    let follower_addr = format!("127.0.0.1:{}", base_port + 1);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut observed: Option<Vec<u8>> = None;
    while Instant::now() < deadline {
        if let Ok(mut follower) = Client::connect(
            &follower_addr,
            TenantId::new(SMOKE_TENANT),
            ClientConfig::default(),
        ) {
            if let Ok(resp) = follower.read_events(stream_id, Offset::new(0), 65_536) {
                if let Some(first) = resp.events.into_iter().next() {
                    observed = Some(first);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    teardown(supervisors).await;

    let observed = observed.expect(
        "follower never replicated the write under multi-host spawn path; \
         a regression here means start_cluster_node is dropping the peer \
         topology or KMB_CLUSTER_PEERS rendering is missing entries",
    );
    assert_eq!(observed, payload);

    // The temp dir's data dir was also kept for inspection during failures;
    // dropping `temp` here lets the OS reclaim it on success.
    let _ = temp;
    // Keep PathBuf in scope so tooling can list contents if a future
    // tracing-only debug session needs it.
    let _ = PathBuf::from(temp.path());
}

#[tokio::test]
async fn init_with_hosts_rejects_duplicate_endpoints() {
    let temp = TempDir::new().expect("temp dir");
    // Two nodes claiming the same data port — this is the cluster.toml
    // hand-edit failure mode. Validation must reject *before* spawn.
    let mut config =
        init_cluster_with_hosts(temp.path().to_path_buf(), &["127.0.0.1", "127.0.0.1"], 5432)
            .expect("baseline init");

    // Force the collision and re-save so `ClusterConfig::load` re-validates.
    config.topology.nodes[1].port = 5432;
    config.save().expect("re-save bad config");

    match ClusterConfig::load(temp.path()) {
        Ok(_) => panic!("expected load() to reject duplicate endpoints"),
        Err(kimberlite_cluster::Error::DuplicateEndpoint { port, .. }) => {
            assert_eq!(port, 5432);
        }
        Err(other) => panic!("expected DuplicateEndpoint, got {other:?}"),
    }
}
