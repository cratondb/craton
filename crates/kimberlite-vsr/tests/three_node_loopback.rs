//! End-to-end VSR integration test: 3 `MultiNodeReplicator`s on real
//! TCP loopback, no `kimberlite-server` / wire-protocol layers in the
//! picture. This is the regression guard for the v0.9.x cluster
//! graduation work — failures here are unambiguous VSR bugs.
//!
//! Two scenarios, both `#[ignore]`'d by default because they bind real
//! ports and run for several seconds:
//!
//! - `three_node_loopback_stable_leader` — boots 3 replicas, asserts that
//!   exactly one becomes leader and the cluster's view stops climbing
//!   (proves no view-change storm).
//! - `three_node_loopback_replicates_writes` — leader submits a
//!   `CreateStream` command; both followers' `KernelState` reflects it
//!   within a generous deadline.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::time::{Duration, Instant};

use kimberlite_kernel::Command;
use kimberlite_types::{DataClass, Placement, StreamId, StreamName, TenantId};
use kimberlite_vsr::{
    ClusterAddresses, MultiNodeConfig, MultiNodeReplicator, ReplicaId, Replicator,
};
use tempfile::TempDir;

/// Reserves three consecutive free TCP ports on `127.0.0.1` and returns
/// the base. Probes by binding all three at once — releasing only after
/// confirming the trio is contiguous and free.
fn pick_base_port() -> u16 {
    for _attempt in 0..32 {
        let probe = TcpListener::bind("127.0.0.1:0")
            .expect("bind probe socket")
            .local_addr()
            .expect("probe local_addr")
            .port();
        let candidate = probe.saturating_sub(probe % 10);
        if candidate < 10_000 || candidate.checked_add(2).is_none() {
            continue;
        }
        let bind_a = TcpListener::bind(("127.0.0.1", candidate));
        let bind_b = TcpListener::bind(("127.0.0.1", candidate + 1));
        let bind_c = TcpListener::bind(("127.0.0.1", candidate + 2));
        if let (Ok(a), Ok(b), Ok(c)) = (bind_a, bind_b, bind_c) {
            drop((a, b, c));
            return candidate;
        }
    }
    panic!("could not find three consecutive free ports after 32 attempts");
}

/// Builds a 3-node localhost membership map keyed by `ReplicaId`.
fn membership(base_port: u16) -> ClusterAddresses {
    let mut addrs = HashMap::new();
    for id in 0_u8..3 {
        let addr: SocketAddr = format!("127.0.0.1:{}", base_port + u16::from(id))
            .parse()
            .expect("loopback addr parses");
        addrs.insert(ReplicaId::new(id), addr);
    }
    ClusterAddresses::new(addrs)
}

/// Spawns one replica with its own superblock under `dir`.
fn spawn_replica(replica_id: u8, addresses: &ClusterAddresses, dir: &Path) -> MultiNodeReplicator {
    let config = MultiNodeConfig::new(
        ReplicaId::new(replica_id),
        addresses.clone(),
        dir.join(format!("superblock-{replica_id}.vsr")),
    );
    MultiNodeReplicator::start(config).expect("start replicator")
}

/// Polls `predicate` every 50ms until it returns true or the deadline elapses.
fn wait_until<F: FnMut() -> bool>(deadline: Duration, mut predicate: F) -> bool {
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    predicate()
}

#[test]
#[ignore = "binds real TCP ports + spawns 3 VSR replicas; run with --ignored"]
fn three_node_loopback_stable_leader() {
    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();
    let addresses = membership(base_port);
    let dir = temp.path().to_path_buf();

    let r0 = spawn_replica(0, &addresses, &dir);
    let r1 = spawn_replica(1, &addresses, &dir);
    let r2 = spawn_replica(2, &addresses, &dir);

    // Bootstrap should complete on every replica within a few seconds.
    let bootstrapped = wait_until(Duration::from_secs(8), || {
        r0.is_bootstrap_complete() && r1.is_bootstrap_complete() && r2.is_bootstrap_complete()
    });
    assert!(
        bootstrapped,
        "bootstrap never completed on every replica within 8s"
    );

    // Wait for exactly one leader to emerge.
    let leader_elected = wait_until(Duration::from_secs(5), || {
        let leaders = [r0.is_leader(), r1.is_leader(), r2.is_leader()]
            .into_iter()
            .filter(|x| *x)
            .count();
        leaders == 1
    });
    assert!(
        leader_elected,
        "no single leader emerged within 5s (leaders: r0={} r1={} r2={})",
        r0.is_leader(),
        r1.is_leader(),
        r2.is_leader(),
    );

    // Stability window: capture the current view, sleep 2s, assert it
    // hasn't moved. Climbing view = view-change storm.
    let view_before = r0.view();
    std::thread::sleep(Duration::from_secs(2));
    let view_after = r0.view();
    assert_eq!(
        view_before, view_after,
        "view climbed from {view_before} to {view_after} during 2s stability window — view-change storm"
    );

    drop((r0, r1, r2));
}

#[test]
#[ignore = "binds real TCP ports + spawns 3 VSR replicas; run with --ignored"]
fn three_node_loopback_replicates_writes() {
    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();
    let addresses = membership(base_port);
    let dir = temp.path().to_path_buf();

    let mut r0 = spawn_replica(0, &addresses, &dir);
    let mut r1 = spawn_replica(1, &addresses, &dir);
    let mut r2 = spawn_replica(2, &addresses, &dir);

    // Wait for stable leadership before submitting.
    let bootstrapped = wait_until(Duration::from_secs(8), || {
        r0.is_bootstrap_complete() && r1.is_bootstrap_complete() && r2.is_bootstrap_complete()
    });
    assert!(bootstrapped, "bootstrap never completed within 8s");
    let leader_elected = wait_until(Duration::from_secs(5), || {
        r0.is_leader() || r1.is_leader() || r2.is_leader()
    });
    assert!(leader_elected, "no leader within 5s");

    // Find the leader; submit a CreateStream through it.
    let stream_id = StreamId::from_tenant_and_local(TenantId::from(1), 1);
    let cmd = Command::create_stream(
        stream_id,
        StreamName::new("loopback-smoke"),
        DataClass::Public,
        Placement::Global,
    );

    let submit_result = if r0.is_leader() {
        r0.submit_with_timeout(cmd, None, Duration::from_secs(5))
    } else if r1.is_leader() {
        r1.submit_with_timeout(cmd, None, Duration::from_secs(5))
    } else {
        r2.submit_with_timeout(cmd, None, Duration::from_secs(5))
    };

    let result = submit_result.expect("leader submit succeeded");
    assert!(
        !result.was_duplicate,
        "fresh submit should not be flagged as duplicate"
    );

    // Each replica's KernelState should observe the new stream within a
    // generous deadline. The follower projection isn't an in-process
    // detail here — we read directly from the VSR snapshot, which is
    // updated by `apply_commits_up_to` on every replica.
    let observed = wait_until(Duration::from_secs(10), || {
        let s0 = r0
            .snapshot_kernel_state(Duration::from_millis(500))
            .map(|s| s.stream_exists(&stream_id))
            .unwrap_or(false);
        let s1 = r1
            .snapshot_kernel_state(Duration::from_millis(500))
            .map(|s| s.stream_exists(&stream_id))
            .unwrap_or(false);
        let s2 = r2
            .snapshot_kernel_state(Duration::from_millis(500))
            .map(|s| s.stream_exists(&stream_id))
            .unwrap_or(false);
        s0 && s1 && s2
    });

    if !observed {
        eprintln!(
            "stream visibility — r0: {:?} r1: {:?} r2: {:?}",
            r0.snapshot_kernel_state(Duration::from_millis(500))
                .map(|s| s.stream_exists(&stream_id)),
            r1.snapshot_kernel_state(Duration::from_millis(500))
                .map(|s| s.stream_exists(&stream_id)),
            r2.snapshot_kernel_state(Duration::from_millis(500))
                .map(|s| s.stream_exists(&stream_id)),
        );
    }
    assert!(
        observed,
        "stream did not propagate to all 3 replicas within 10s"
    );

    r0.shutdown();
    r1.shutdown();
    r2.shutdown();
}
