//! End-to-end smoke tests for `kimberlite-cluster`.
//!
//! These tests spawn real `kimberlite start` subprocesses, so they require
//! a built binary on PATH (or pointed at by `KIMBERLITE_BIN`) and they
//! consume real ports + disk. They're `#[ignore]`d by default so the
//! standard `cargo test` matrix stays fast and isolated; the nightly
//! integration job exercises them with `--ignored`.
//!
//! Acceptance contract from the v0.9.x cluster graduation plan:
//!   - 3-node cluster comes up; one write on the leader is readable on a
//!     follower (eventually consistent).
//!   - SIGKILL'ing a follower triggers supervisor restart with bounded
//!     backoff, observable via `NodeStatus`.

use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kimberlite_client::{Client, ClientConfig};
use kimberlite_cluster::{ClusterSupervisor, NodeStatus};
use kimberlite_types::{DataClass, Offset, TenantId};
use tempfile::TempDir;

/// Default tenant the smoke test writes through. Server-side defaults
/// give tenant 1 a healthcare profile out of the box, matching the
/// pivot's quickstart story.
const SMOKE_TENANT: u64 = 1;

/// Locates a built `kimberlite` binary by walking up from this crate's
/// manifest dir to `target/{debug,release}/kimberlite`. Returns `None`
/// if no binary exists yet — in which case the test should skip rather
/// than fail, since the binary is built on demand by the dev workflow.
fn locate_built_kimberlite() -> Option<PathBuf> {
    if let Ok(env_override) = std::env::var("KIMBERLITE_BIN") {
        let p = PathBuf::from(env_override);
        if p.is_file() {
            return Some(p);
        }
    }

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cursor: &std::path::Path = crate_dir.as_path();
    loop {
        for profile in ["debug", "release"] {
            let candidate = cursor.join("target").join(profile).join("kimberlite");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => return None,
        }
    }
}

/// Reserves a base port such that the data-port trio (base..=base+2),
/// the VSR-port trio (base+100..=base+102), and the HTTP-probe trio
/// (base+1000..=base+1002) are all simultaneously bindable on
/// 127.0.0.1. Each spawned node uses one port from each band; the
/// supervisor's port-offset convention is documented on
/// [`kimberlite_cluster::node::VSR_PORT_OFFSET`].
fn pick_base_port() -> u16 {
    for _attempt in 0..32 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind probe socket")
            .local_addr()
            .expect("probe local_addr")
            .port();
        // Round down to a base that leaves headroom for +100 / +1000
        // offsets without overflowing u16. Skip ephemeral-range probes
        // that would put the HTTP band above 65k.
        let candidate = probe.saturating_sub(probe % 10);
        if candidate < 10_000 || u32::from(candidate) + 1_002 > u32::from(u16::MAX) {
            continue;
        }
        let mut bound = Vec::with_capacity(9);
        let mut ok = true;
        for offset in [0_u16, 1, 2, 100, 101, 102, 1_000, 1_001, 1_002] {
            match std::net::TcpListener::bind(("127.0.0.1", candidate + offset)) {
                Ok(listener) => bound.push(listener),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        drop(bound);
        if ok {
            return candidate;
        }
    }
    panic!("could not find a free port band after 32 attempts");
}

/// Polls the data port of every node until it accepts a TCP connection,
/// or the deadline elapses. Real readiness (handshake success, leader
/// election quorum) is the test body's concern.
async fn wait_for_tcp_ready(base_port: u16, node_count: u16, deadline: Duration) {
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        let mut all_up = true;
        for offset in 0..node_count {
            let addr = format!("127.0.0.1:{}", base_port + offset);
            if TcpStream::connect_timeout(
                &addr.parse().expect("addr parses"),
                Duration::from_millis(200),
            )
            .is_err()
            {
                all_up = false;
                break;
            }
        }
        if all_up {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("nodes never accepted TCP connections within {deadline:?}");
}

/// Best-effort cluster shutdown for use in test teardown — swallows
/// errors so an assertion failure inside the test body still surfaces
/// as the panic message rather than getting masked by a stop failure.
async fn teardown(mut supervisor: ClusterSupervisor) {
    let _ = supervisor.stop_all().await;
}

#[tokio::test]
#[ignore = "spawns real kimberlite processes; run with --ignored or in nightly"]
async fn three_node_cluster_smoke() {
    let Some(bin) = locate_built_kimberlite() else {
        eprintln!(
            "skipping: no built `kimberlite` binary found; run `cargo build` \
             or set KIMBERLITE_BIN before re-running with --ignored"
        );
        return;
    };
    // SAFETY-equivalent: this test uses `unsafe`-free env propagation —
    // child processes inherit env from the parent test process at spawn
    // time. We can't mutate env in 2024 edition without `unsafe`, so we
    // launch each node with KIMBERLITE_BIN already pointing at our found
    // path via the supervisor's discovery (which checks the env first).
    // Tests in this file run sequentially because they share the env.
    if std::env::var("KIMBERLITE_BIN").as_deref() != Ok(bin.to_str().expect("utf-8 path")) {
        eprintln!(
            "note: KIMBERLITE_BIN not set to {}; relying on PATH / sibling discovery",
            bin.display()
        );
    }

    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();

    let _config = kimberlite_cluster::init_cluster(temp.path().to_path_buf(), 3, base_port)
        .expect("init_cluster");
    let supervisor = kimberlite_cluster::start_cluster(temp.path().to_path_buf())
        .await
        .expect("start_cluster");

    wait_for_tcp_ready(base_port, 3, Duration::from_secs(15)).await;

    // Drive the smoke through the assumed leader (replica 0). VSR may
    // re-elect, but for a fresh boot replica 0 starts as the primary.
    let leader_addr = format!("127.0.0.1:{base_port}");
    let mut leader = match Client::connect(
        &leader_addr,
        TenantId::new(SMOKE_TENANT),
        ClientConfig::default(),
    ) {
        Ok(c) => c,
        Err(e) => {
            teardown(supervisor).await;
            panic!("leader connect failed: {e}");
        }
    };

    let stream_id = match leader.create_stream("smoke", DataClass::Public) {
        Ok(s) => s,
        Err(e) => {
            drop(leader);
            teardown(supervisor).await;
            panic!("create_stream failed on leader: {e}");
        }
    };

    let payload = b"three-node-smoke-event".to_vec();
    if let Err(e) = leader.append(stream_id, vec![payload.clone()], Offset::ZERO) {
        drop(leader);
        teardown(supervisor).await;
        panic!("append failed on leader: {e}");
    }

    // Sanity: re-read on the leader, confirming the write committed on
    // the local projection. If this fails, the failure is in the write
    // path, not in cross-node replication.
    let leader_echo = leader.read_events(stream_id, Offset::new(0), 65_536);
    drop(leader);
    let leader_events = match leader_echo {
        Ok(resp) => resp.events,
        Err(e) => {
            teardown(supervisor).await;
            panic!("leader read-back failed: {e}");
        }
    };
    assert_eq!(
        leader_events.first().map(Vec::as_slice),
        Some(payload.as_slice()),
        "leader did not return its own write"
    );

    // Cross-node read: poll a follower until the replicated write
    // surfaces in its projection. Replication is eventually consistent
    // (VSR commit + background projection applier), so a generous
    // window matters more than a tight loop.
    let follower_addr = format!("127.0.0.1:{}", base_port + 1);
    let read_deadline = Instant::now() + Duration::from_secs(20);
    let mut received: Option<Vec<u8>> = None;
    while Instant::now() < read_deadline {
        if let Ok(mut follower) = Client::connect(
            &follower_addr,
            TenantId::new(SMOKE_TENANT),
            ClientConfig::default(),
        ) {
            if let Ok(resp) = follower.read_events(stream_id, Offset::new(0), 65_536) {
                if let Some(first) = resp.events.into_iter().next() {
                    received = Some(first);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    teardown(supervisor).await;

    let observed = received.expect(
        "follower never replicated the event within the deadline; \
         leader-side write succeeded, so this points at VSR \
         apply-fanout or the projection applier on the follower",
    );
    assert_eq!(observed, payload, "follower returned mismatched event data");
}

#[tokio::test]
#[ignore = "spawns real kimberlite processes; run with --ignored or in nightly"]
async fn supervisor_restarts_killed_follower() {
    let Some(_bin) = locate_built_kimberlite() else {
        eprintln!(
            "skipping: no built `kimberlite` binary found; run `cargo build` \
             or set KIMBERLITE_BIN before re-running with --ignored"
        );
        return;
    };

    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();

    let _config = kimberlite_cluster::init_cluster(temp.path().to_path_buf(), 3, base_port)
        .expect("init_cluster");
    let mut supervisor = kimberlite_cluster::start_cluster(temp.path().to_path_buf())
        .await
        .expect("start_cluster");

    wait_for_tcp_ready(base_port, 3, Duration::from_secs(15)).await;

    // Capture follower 1's PID, then SIGKILL it via tokio's cross-platform
    // start_kill (which sends SIGKILL on Unix). We don't take ownership
    // of the Child handle so the supervisor's next supervise_once pass
    // still observes the death and treats it as a crash.
    let pid_before = supervisor
        .node(1)
        .and_then(kimberlite_cluster::NodeProcess::pid)
        .expect("follower 1 should have a live pid before kill");

    {
        let follower = supervisor
            .node_mut(1)
            .expect("follower 1 should be present");
        follower.force_kill().expect("force_kill follower 1");
    }

    // Give the kernel a moment to deliver SIGKILL and reap the process,
    // then drive a supervision pass. NodeProcess::restart applies an
    // exponential backoff (2^n seconds), so the first restart waits
    // roughly 2 seconds before re-spawning.
    tokio::time::sleep(Duration::from_millis(500)).await;
    supervisor.supervise_once().await;

    // Verify the supervisor incremented restart_count and brought the
    // node back to Running. Allow a small grace window for the new child
    // to come up on the same port (which the killed predecessor freed).
    let recovery_deadline = Instant::now() + Duration::from_secs(20);
    let mut recovered = false;
    let mut last_status = NodeStatus::Stopped;
    let mut last_restart_count = 0;
    while Instant::now() < recovery_deadline {
        if let Some(node) = supervisor.node(1) {
            last_status = node.status;
            last_restart_count = node.restart_count;
            if node.status == NodeStatus::Running && node.restart_count >= 1 {
                recovered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let pid_after = supervisor.node(1).and_then(kimberlite_cluster::NodeProcess::pid);

    teardown(supervisor).await;

    assert!(
        recovered,
        "follower 1 never recovered: status={last_status:?} restart_count={last_restart_count}"
    );
    assert!(
        pid_after.is_some_and(|p| p != pid_before),
        "expected a fresh PID after restart (was {pid_before:?}, now {pid_after:?})"
    );
}
