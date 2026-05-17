//! T3.2 — Cluster performance baseline: measured RTO, RPO, and
//! sustained-write throughput.
//!
//! These tests boot a real 3-node localhost cluster (built `kimberlite`
//! binary required) and emit measurement distributions to stdout. They
//! are the data source for `docs/operating/performance/cluster.md` and
//! the back-referenced RTO/RPO numbers in
//! `docs/operating/runbooks/cluster.md`.
//!
//! All tests are `#[ignore]`-tagged; run them via:
//!
//! ```text
//! cargo test --release -p kimberlite-cluster --test perf_baseline \
//!     -- --ignored --nocapture perf
//! ```
//!
//! Each test runs N iterations (default 5; override via
//! `KIMBERLITE_PERF_ITERATIONS=20`). The 5-iteration default keeps a
//! local dev run under ~5 minutes while still producing enough
//! samples to surface a p50/p99 split; the larger value is intended
//! for the run that produces published numbers.
//!
//! **What this harness measures vs. doesn't:**
//! - User-observable RTO: wall-clock from `SIGKILL`-of-leader to first
//!   successful write through a surviving replica. This includes view-
//!   change time, leader-election propagation, and the client retry +
//!   round-robin loop — i.e. exactly what a real application sees.
//! - User-observable RPO: gap between the highest sequence the client
//!   received an ack for (pre-kill) and the highest sequence readable
//!   on the new leader (post-kill). With VSR + fsync + quorum
//!   replication this should be 0 for every acked write; we measure
//!   to prove it.
//! - Sustained throughput: a single writer's events/sec against one
//!   stream on the leader, no concurrency. This is the baseline floor
//!   — fan-out, batching, and pipelining are explicit follow-ons.
//! - **NOT** measured here: multi-host network RTT (loopback only),
//!   fsync mode sweeps (run at server default), or CI-gated regression
//!   thresholds (first-pass baseline is reproducibility).

mod common;

use std::time::{Duration, Instant};

use common::{find_leader_replica, locate_built_kimberlite, pick_base_port, wait_for_tcp_ready};
use kimberlite_client::{Client, ClientConfig};
use kimberlite_cluster::ClusterSupervisor;
use kimberlite_types::{DataClass, Offset, StreamId, TenantId};
use tempfile::TempDir;

const TENANT: u64 = 1;
const NODES: u16 = 3;

/// Default iteration count for the per-test distributions. Override
/// with `KIMBERLITE_PERF_ITERATIONS=N` when generating published numbers.
fn iterations() -> usize {
    std::env::var("KIMBERLITE_PERF_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

async fn teardown(mut supervisor: ClusterSupervisor) {
    let _ = supervisor.stop_all().await;
}

async fn boot() -> Option<(ClusterSupervisor, u16, TempDir)> {
    locate_built_kimberlite()?;
    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();
    kimberlite_cluster::init_cluster(temp.path().to_path_buf(), NODES as usize, base_port)
        .expect("init_cluster");
    let supervisor = kimberlite_cluster::start_cluster(temp.path().to_path_buf())
        .await
        .expect("start_cluster");
    wait_for_tcp_ready(base_port, NODES, Duration::from_secs(15));
    Some((supervisor, base_port, temp))
}

fn connect(addr: &str) -> Result<Client, String> {
    Client::connect(addr, TenantId::new(TENANT), ClientConfig::default()).map_err(|e| format!("{e}"))
}

/// Round-robins all `NODES` replicas, returning the first client that
/// successfully creates a stream named `name`. Mirrors the pattern in
/// `three_node_integration::create_stream_via_leader` — the metric-
/// based leader gauge is transiently wrong during view changes, but
/// the wire protocol's `NotLeader` error is authoritative.
fn create_stream_anywhere(
    base_port: u16,
    name: &str,
    deadline: Duration,
) -> Result<(u16, StreamId), String> {
    let stop = Instant::now() + deadline;
    let mut last_err = String::from("no replica accepted create_stream");
    while Instant::now() < stop {
        for replica in 0..NODES {
            let addr = format!("127.0.0.1:{}", base_port + replica);
            match connect(&addr) {
                Ok(mut c) => match c.create_stream(name, DataClass::Public) {
                    Ok(stream_id) => return Ok((replica, stream_id)),
                    Err(e) => last_err = format!("create_stream on r{replica}: {e}"),
                },
                Err(e) => last_err = format!("connect r{replica}: {e}"),
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last_err)
}

/// Appends `payload` to `stream_id` on whichever replica currently
/// accepts the write. Used for the post-kill probe in
/// `measure_rto_leader_kill`. Skipped replicas are excluded from the
/// round-robin so the killed leader doesn't waste connect timeouts.
fn append_anywhere_except(
    base_port: u16,
    stream_id: StreamId,
    expected_offset: Offset,
    payload: Vec<u8>,
    skip: u16,
    deadline: Duration,
) -> Result<(u16, Offset), String> {
    let stop = Instant::now() + deadline;
    let mut last_err = String::from("no replica accepted append");
    while Instant::now() < stop {
        for replica in 0..NODES {
            if replica == skip {
                continue;
            }
            let addr = format!("127.0.0.1:{}", base_port + replica);
            match connect(&addr) {
                Ok(mut c) => match c.append(stream_id, vec![payload.clone()], expected_offset) {
                    Ok(off) => return Ok((replica, off)),
                    Err(e) => last_err = format!("append on r{replica}: {e}"),
                },
                Err(e) => last_err = format!("connect r{replica}: {e}"),
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(last_err)
}

/// Sorted distribution stats from a series of `Duration` samples.
struct Stats {
    n: usize,
    p50: Duration,
    p99: Duration,
    max: Duration,
    min: Duration,
    mean: Duration,
}

impl Stats {
    fn compute(samples: &mut [Duration]) -> Self {
        assert!(!samples.is_empty(), "Stats::compute requires ≥1 sample");
        samples.sort();
        let n = samples.len();
        let p50 = samples[n / 2];
        // p99 index via nearest-rank; for small N this collapses to max.
        let p99 = samples[((n as f64 * 0.99).ceil() as usize).saturating_sub(1).min(n - 1)];
        let max = *samples.last().expect("non-empty");
        let min = *samples.first().expect("non-empty");
        let sum_nanos: u128 = samples.iter().map(Duration::as_nanos).sum();
        let mean = Duration::from_nanos((sum_nanos / n as u128) as u64);
        Self {
            n,
            p50,
            p99,
            max,
            min,
            mean,
        }
    }

    fn print(&self, label: &str) {
        eprintln!(
            "{label}: n={} min={:.3}ms p50={:.3}ms mean={:.3}ms p99={:.3}ms max={:.3}ms",
            self.n,
            self.min.as_secs_f64() * 1000.0,
            self.p50.as_secs_f64() * 1000.0,
            self.mean.as_secs_f64() * 1000.0,
            self.p99.as_secs_f64() * 1000.0,
            self.max.as_secs_f64() * 1000.0,
        );
    }
}

// ===========================================================================
// RTO — recovery from leader kill, user-observable
// ===========================================================================

#[tokio::test]
#[ignore = "perf baseline; spawns real kimberlite processes; run with --ignored --nocapture perf"]
async fn perf_rto_leader_kill() {
    let Some(_bin) = locate_built_kimberlite() else {
        eprintln!("skipping: no built kimberlite binary; set KIMBERLITE_BIN or `cargo build --release`");
        return;
    };
    let iters = iterations();
    let mut samples: Vec<Duration> = Vec::with_capacity(iters);

    for i in 0..iters {
        let Some((mut supervisor, base_port, _temp)) = boot().await else {
            panic!("boot failed on iter {i}");
        };

        // Wait for a stable leader; the metric-based discovery is
        // authoritative once boot has settled.
        let leader = match find_leader_replica(base_port, NODES, Duration::from_secs(15)) {
            Some(l) => l,
            None => {
                teardown(supervisor).await;
                panic!("iter {i}: no leader emerged within 15s of boot");
            }
        };

        // Pre-kill warmup: create a stream so we have a known
        // committed VSR op and a stable stream_id for the post-kill
        // probe.
        let stream_name = format!("rto-iter-{i}");
        let (_, stream_id) = match create_stream_anywhere(
            base_port,
            &stream_name,
            Duration::from_secs(15),
        ) {
            Ok(s) => s,
            Err(e) => {
                teardown(supervisor).await;
                panic!("iter {i}: pre-kill create_stream failed: {e}");
            }
        };

        // SIGKILL the leader and clock the recovery window. Don't
        // call supervise_once — the surviving replicas must elect on
        // their own, which is what we're measuring.
        let kill_at = match supervisor.node_mut(leader as usize) {
            Some(n) => {
                n.force_kill().expect("force_kill leader");
                Instant::now()
            }
            None => {
                teardown(supervisor).await;
                panic!("iter {i}: leader process missing");
            }
        };

        // Tight-loop append against the surviving replicas. The first
        // success marks user-observable RTO: the new leader has been
        // elected and accepts writes from a client perspective.
        let probe_payload = format!("rto-probe-{i}").into_bytes();
        let recovery = match append_anywhere_except(
            base_port,
            stream_id,
            Offset::ZERO,
            probe_payload,
            leader,
            Duration::from_secs(20),
        ) {
            Ok((replica, off)) => {
                let elapsed = kill_at.elapsed();
                eprintln!(
                    "iter {i}: recovered via r{replica} at offset {off:?} in {:.3}s",
                    elapsed.as_secs_f64()
                );
                elapsed
            }
            Err(e) => {
                teardown(supervisor).await;
                panic!("iter {i}: no replica accepted writes within 20s after kill: {e}");
            }
        };
        samples.push(recovery);

        teardown(supervisor).await;
    }

    let stats = Stats::compute(&mut samples);
    eprintln!();
    eprintln!("=== RTO (user-observable, leader SIGKILL → first successful write) ===");
    stats.print("RTO");
    eprintln!();

    // Sanity envelope: every recovery should fit inside 15s on local
    // dev hardware. If this trips on a known-good build, investigate
    // before adjusting the bound — the runbook claim is 5s p99.
    assert!(
        stats.max <= Duration::from_secs(15),
        "RTO max {:?} exceeded 15s envelope — investigate before relaxing",
        stats.max
    );
}

// ===========================================================================
// RPO — data-loss window for acked writes
// ===========================================================================

#[tokio::test]
#[ignore = "perf baseline; spawns real kimberlite processes; run with --ignored --nocapture perf"]
async fn perf_rpo_leader_kill() {
    // Writes per iteration before the kill. Enough to exercise the
    // log + replication but small enough each iteration stays bounded.
    const WRITES_PER_ITER: usize = 100;

    let Some(_bin) = locate_built_kimberlite() else {
        eprintln!("skipping: no built kimberlite binary; set KIMBERLITE_BIN or `cargo build --release`");
        return;
    };
    let iters = iterations();

    // Total acked-but-lost events across iterations that fully
    // completed (kill → new leader elected → read-back succeeded).
    // VSR safety means this must be 0; anything nonzero is a real
    // bug, not a perf datum.
    let mut acked_lost: u64 = 0;
    let mut per_iter_acked: Vec<usize> = Vec::with_capacity(iters);
    let mut per_iter_readable: Vec<usize> = Vec::with_capacity(iters);
    // Iterations where view-change failed to converge within the
    // budget after `force_kill`. Reported separately so they don't
    // get conflated with the RPO=0 datum — these are stability
    // events, not data-loss events. Under sustained-write load this
    // is currently a known intermittent on macOS dev hardware; see
    // the v0.10.x rolling-restart stability tracker in
    // `docs-internal/design-docs/active/cluster-graduation-v0.9.x.md`.
    let mut stalled_iters: Vec<usize> = Vec::new();

    for i in 0..iters {
        let Some((mut supervisor, base_port, _temp)) = boot().await else {
            panic!("boot failed on iter {i}");
        };

        let leader = match find_leader_replica(base_port, NODES, Duration::from_secs(15)) {
            Some(l) => l,
            None => {
                teardown(supervisor).await;
                panic!("iter {i}: no leader emerged within 15s of boot");
            }
        };

        let stream_name = format!("rpo-iter-{i}");
        let (_, stream_id) = match create_stream_anywhere(
            base_port,
            &stream_name,
            Duration::from_secs(15),
        ) {
            Ok(s) => s,
            Err(e) => {
                teardown(supervisor).await;
                panic!("iter {i}: pre-kill create_stream failed: {e}");
            }
        };

        // Write WRITES_PER_ITER sequenced payloads through the leader.
        // Each ack means VSR committed → durable on a quorum.
        let leader_addr = format!("127.0.0.1:{}", base_port + leader);
        let mut leader_client = match connect(&leader_addr) {
            Ok(c) => c,
            Err(e) => {
                teardown(supervisor).await;
                panic!("iter {i}: connect leader for pre-kill writes: {e}");
            }
        };
        let mut last_acked: Option<u64> = None;
        let mut next_expected = Offset::ZERO;
        for seq in 0..WRITES_PER_ITER as u64 {
            let payload = seq.to_be_bytes().to_vec();
            match leader_client.append(stream_id, vec![payload], next_expected) {
                Ok(first_off) => {
                    last_acked = Some(seq);
                    // Single-payload append; advance expected_offset
                    // by 1 for the next call.
                    next_expected = Offset::new(u64::from(first_off) + 1);
                }
                Err(e) => {
                    eprintln!(
                        "iter {i}: write seq={seq} failed pre-kill (last_acked={last_acked:?}): {e}"
                    );
                    break;
                }
            }
        }
        drop(leader_client);
        let acked_count = last_acked.map_or(0, |s| (s + 1) as usize);

        // SIGKILL leader, wait for a new one, then read everything
        // back from any surviving replica that accepts read_events.
        if let Some(n) = supervisor.node_mut(leader as usize) {
            n.force_kill().expect("force_kill leader");
        }
        std::thread::sleep(Duration::from_millis(300));

        // Wait out the view change; we don't measure RTO here, just
        // need a stable replica we can read from.
        let new_leader = match find_leader_replica(base_port, NODES, Duration::from_secs(20)) {
            Some(l) if l != leader => l,
            other => {
                eprintln!(
                    "iter {i}: view-change stalled after kill (found leader: {other:?}); \
                     recording as STALL, not RPO violation"
                );
                stalled_iters.push(i);
                teardown(supervisor).await;
                continue;
            }
        };

        // Read from the new leader. read_events is a follower-OK
        // operation (projection reads), but reading from the leader
        // simplifies the "is the post-kill state visible" question.
        let new_leader_addr = format!("127.0.0.1:{}", base_port + new_leader);
        let mut reader = match connect(&new_leader_addr) {
            Ok(c) => c,
            Err(e) => {
                teardown(supervisor).await;
                panic!("iter {i}: connect new leader r{new_leader} for read: {e}");
            }
        };
        // Allow some convergence time — projection applier on the
        // new leader needs to catch up from the VSR log.
        let read_deadline = Instant::now() + Duration::from_secs(15);
        let mut readable_count = 0_usize;
        while Instant::now() < read_deadline {
            match reader.read_events(stream_id, Offset::new(0), 65_536) {
                Ok(resp) => {
                    readable_count = resp.events.len();
                    if readable_count >= acked_count {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("iter {i}: post-kill read attempt: {e}");
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        drop(reader);

        let lost = acked_count.saturating_sub(readable_count) as u64;
        acked_lost += lost;
        per_iter_acked.push(acked_count);
        per_iter_readable.push(readable_count);
        eprintln!(
            "iter {i}: acked={acked_count} readable_post_kill={readable_count} lost={lost} \
             new_leader=r{new_leader}"
        );

        teardown(supervisor).await;
    }

    let completed = iters - stalled_iters.len();
    eprintln!();
    eprintln!("=== RPO (acked writes lost after leader SIGKILL) ===");
    eprintln!("iterations:        {iters}");
    eprintln!("completed:         {completed}");
    eprintln!("view-change stalls: {} (iters: {stalled_iters:?})", stalled_iters.len());
    eprintln!("writes per iter (target): {WRITES_PER_ITER}");
    eprintln!("acked per completed iter:    {per_iter_acked:?}");
    eprintln!("readable per completed iter: {per_iter_readable:?}");
    eprintln!("total acked-but-lost events: {acked_lost}");
    eprintln!();

    // Correctness gate: VSR guarantees acked writes are committed on
    // a quorum. ANY loss here is a real bug; the test fails so it
    // can't be silently quoted as "RPO = N events" in the doc. We
    // tolerate view-change stalls (logged as STALL above) — those
    // are availability events, not safety violations.
    assert_eq!(
        acked_lost, 0,
        "VSR safety violation: {acked_lost} acked writes vanished after leader kill"
    );
    // Sanity: most iterations should actually complete. If view-
    // change stalls run away (>50%) that's its own bug and we should
    // not silently report RPO=0 from a tiny sample.
    assert!(
        completed * 2 >= iters,
        "{} of {iters} iterations stalled in view-change — too few completed iters to report RPO",
        stalled_iters.len()
    );
}

// ===========================================================================
// Sustained-write throughput baseline
// ===========================================================================

#[tokio::test]
#[ignore = "perf baseline; spawns real kimberlite processes; run with --ignored --nocapture perf"]
async fn perf_sustained_write_throughput() {
    let Some(_bin) = locate_built_kimberlite() else {
        eprintln!("skipping: no built kimberlite binary; set KIMBERLITE_BIN or `cargo build --release`");
        return;
    };

    // Configurable via env so the published-numbers run can use a
    // longer window. Default 10s keeps the test bounded.
    let duration_secs: u64 = std::env::var("KIMBERLITE_PERF_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let payload_bytes: usize = std::env::var("KIMBERLITE_PERF_PAYLOAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);

    let Some((supervisor, base_port, _temp)) = boot().await else {
        panic!("boot failed");
    };
    let leader = match find_leader_replica(base_port, NODES, Duration::from_secs(15)) {
        Some(l) => l,
        None => {
            teardown(supervisor).await;
            panic!("no leader emerged within 15s of boot");
        }
    };

    let (_, stream_id) =
        match create_stream_anywhere(base_port, "throughput", Duration::from_secs(15)) {
            Ok(s) => s,
            Err(e) => {
                teardown(supervisor).await;
                panic!("create_stream failed: {e}");
            }
        };

    let leader_addr = format!("127.0.0.1:{}", base_port + leader);
    let mut client = match connect(&leader_addr) {
        Ok(c) => c,
        Err(e) => {
            teardown(supervisor).await;
            panic!("connect leader r{leader}: {e}");
        }
    };

    let payload = vec![0u8; payload_bytes];
    let mut next_expected = Offset::ZERO;
    let mut written: u64 = 0;
    let mut latencies: Vec<Duration> = Vec::with_capacity(8_192);
    let stop_at = Instant::now() + Duration::from_secs(duration_secs);
    let run_start = Instant::now();
    while Instant::now() < stop_at {
        let t0 = Instant::now();
        match client.append(stream_id, vec![payload.clone()], next_expected) {
            Ok(first_off) => {
                latencies.push(t0.elapsed());
                next_expected = Offset::new(u64::from(first_off) + 1);
                written += 1;
            }
            Err(e) => {
                eprintln!("write failed at written={written}: {e}");
                break;
            }
        }
    }
    let elapsed = run_start.elapsed();
    drop(client);
    teardown(supervisor).await;

    let throughput = written as f64 / elapsed.as_secs_f64();
    let stats = Stats::compute(&mut latencies);
    eprintln!();
    eprintln!("=== Sustained write throughput (single writer, 3-node localhost) ===");
    eprintln!(
        "duration={:.2}s payload={}B writes={} throughput={:.0} events/s",
        elapsed.as_secs_f64(),
        payload_bytes,
        written,
        throughput
    );
    stats.print("latency");
    eprintln!();
}
