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

mod common;

use std::time::{Duration, Instant};

use common::{locate_built_kimberlite, pick_base_port, wait_for_tcp_ready};
use kimberlite_client::{Client, ClientConfig};
use kimberlite_cluster::{ClusterSupervisor, NodeStatus};
use kimberlite_types::{DataClass, Offset, TenantId};
use tempfile::TempDir;

/// Default tenant the smoke test writes through. Server-side defaults
/// give tenant 1 a healthcare profile out of the box, matching the
/// pivot's quickstart story.
const SMOKE_TENANT: u64 = 1;

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

    wait_for_tcp_ready(base_port, 3, Duration::from_secs(15));

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

    wait_for_tcp_ready(base_port, 3, Duration::from_secs(15));

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
