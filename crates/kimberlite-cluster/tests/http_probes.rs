//! End-to-end HTTP probe tests for `kimberlite-cluster` (T1.2).
//!
//! Spins up a real 3-node cluster, then `curl`s `/healthz`, `/readyz`,
//! and `/metrics` on each node's HTTP sidecar (data_port + 1000 per
//! `crates/kimberlite-cluster/src/node.rs`). Acceptance, per
//! `docs-internal/design-docs/active/cluster-graduation-v0.9.x.md`:
//!
//! - Each spawned node exposes `/healthz` / `/readyz` / `/metrics`.
//! - `curl -s :PORT/metrics | grep kimberlite_` returns at least
//!   4 cluster gauges (`kimberlite_committed_offset`,
//!   `kimberlite_view_number`, `kimberlite_is_leader`,
//!   `kimberlite_replication_lag_seconds`).
//!
//! `#[ignore]`'d by default because it spawns real binaries; run via
//! `cargo test -p kimberlite-cluster --test http_probes -- --ignored`
//! against a built `KIMBERLITE_BIN`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kimberlite_cluster::ClusterSupervisor;
use tempfile::TempDir;

/// HTTP sidecar offset relative to the data port — must mirror the
/// supervisor's `node.rs::VSR_PORT_OFFSET`-adjacent convention.
const HTTP_PORT_OFFSET: u16 = 1_000;

/// Locates a built `kimberlite` binary by walking up from this crate's
/// manifest dir to `target/{debug,release}/kimberlite`. Returns `None`
/// if no binary exists yet.
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

/// Reserves a base port whose data-port trio (base..=base+2),
/// VSR-port trio (base+100..=base+102), and HTTP-probe trio
/// (base+1000..=base+1002) are simultaneously bindable on 127.0.0.1.
///
/// Probes successive bases starting from a random ephemeral port,
/// then walks downward in 10-port strides — this is more robust than
/// picking random ephemeral candidates because adjacent ports tend to
/// have correlated availability (whole bands being in TIME_WAIT
/// from prior test runs).
fn pick_base_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0")
        .expect("bind probe socket")
        .local_addr()
        .expect("probe local_addr")
        .port();
    // Walk from just below the probe's value down toward 10_000,
    // staying clear of the +1002 ceiling.
    let start: u16 = probe.clamp(15_000, 64_000);
    let start = start - (start % 10);
    let mut candidate = start;
    for _ in 0..1_000 {
        if candidate < 10_000 {
            break;
        }
        let mut bound = Vec::with_capacity(9);
        let mut ok = true;
        for offset in [0_u16, 1, 2, 100, 101, 102, 1_000, 1_001, 1_002] {
            match TcpListener::bind(("127.0.0.1", candidate + offset)) {
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
        candidate = candidate.saturating_sub(10);
    }
    panic!("could not find a free port band after sweeping from {start}");
}

/// Polls every node's data port until each accepts a TCP connection
/// or the deadline elapses. Same pattern as the smoke test.
fn wait_for_tcp_ready(base_port: u16, node_count: u16, deadline: Duration) {
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        let mut all_up = true;
        for offset in 0..node_count {
            let addr = format!("127.0.0.1:{}", base_port + offset);
            if TcpStream::connect_timeout(
                &addr.parse::<SocketAddr>().expect("addr parses"),
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
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("nodes never accepted TCP connections within {deadline:?}");
}

/// Holds an HTTP/1.1 response decomposed into status code and body.
/// We don't need headers for the probe tests, so they're discarded.
struct HttpResponse {
    status: u16,
    body: String,
}

/// Sends a minimal HTTP/1.1 GET on a fresh TCP connection and returns
/// the parsed response. Bypasses pulling in a full HTTP client crate
/// — the sidecar's parser is plain HTTP/1.1, so this is sufficient.
fn http_get(addr: &str, path: &str) -> Result<HttpResponse, String> {
    let socket: SocketAddr = addr.parse().map_err(|e| format!("addr parse: {e}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(2))
        .map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set timeout: {e}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nUser-Agent: kimberlite-test/1\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("malformed response: {raw}"))?;
    let status_line = head.lines().next().ok_or("empty response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("no status code")?
        .parse()
        .map_err(|e| format!("status parse: {e}"))?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}

/// Polls `path` on `addr` until the response status equals `expected`
/// or the deadline elapses. Returns the final response either way.
fn poll_http(
    addr: &str,
    path: &str,
    expected: u16,
    deadline: Duration,
) -> Result<HttpResponse, HttpResponse> {
    let stop = Instant::now() + deadline;
    let mut last: Option<HttpResponse> = None;
    while Instant::now() < stop {
        match http_get(addr, path) {
            Ok(resp) if resp.status == expected => return Ok(resp),
            Ok(resp) => last = Some(resp),
            Err(_) => {} // Connection refused / timeout — try again.
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    match last {
        Some(r) => Err(r),
        None => Err(HttpResponse {
            status: 0,
            body: "no response received".into(),
        }),
    }
}

async fn teardown(mut supervisor: ClusterSupervisor) {
    let _ = supervisor.stop_all().await;
}

#[tokio::test]
#[ignore = "spawns real kimberlite processes; run with --ignored or in nightly"]
async fn three_node_http_probes_serve_healthz_readyz_metrics() {
    if locate_built_kimberlite().is_none() {
        eprintln!(
            "skipping: no built `kimberlite` binary found; run `cargo build` \
             or set KIMBERLITE_BIN before re-running with --ignored"
        );
        return;
    }

    let temp = TempDir::new().expect("temp dir");
    let base_port = pick_base_port();

    let _config = kimberlite_cluster::init_cluster(temp.path().to_path_buf(), 3, base_port)
        .expect("init_cluster");
    let supervisor = kimberlite_cluster::start_cluster(temp.path().to_path_buf())
        .await
        .expect("start_cluster");

    wait_for_tcp_ready(base_port, 3, Duration::from_secs(15));

    // Allow the cluster's HTTP sidecars a moment to bind. Each
    // sidecar listens at data_port + HTTP_PORT_OFFSET; the supervisor
    // wires this via KMB_HTTP_PORT in `node.rs`.
    for replica in 0..3_u16 {
        let http_addr = format!("127.0.0.1:{}", base_port + HTTP_PORT_OFFSET + replica);

        // /healthz is unconditionally 200 once the process is up.
        let healthz = match poll_http(&http_addr, "/healthz", 200, Duration::from_secs(10)) {
            Ok(r) => r,
            Err(r) => {
                teardown(supervisor).await;
                panic!(
                    "replica {replica} /healthz never returned 200 (got {}: {})",
                    r.status, r.body
                );
            }
        };
        assert!(
            healthz.body.contains("\"status\":\"ok\""),
            "replica {replica} /healthz body missing status:ok — got: {}",
            healthz.body
        );

        // /readyz needs VSR bootstrap + Normal status + lag < threshold.
        // 10s budget is comfortable: bootstrap typically settles in <1s
        // post-fix; the threshold itself is 5s of lag.
        let readyz = match poll_http(&http_addr, "/readyz", 200, Duration::from_secs(15)) {
            Ok(r) => r,
            Err(r) => {
                teardown(supervisor).await;
                panic!(
                    "replica {replica} /readyz never returned 200 (got {}: {})",
                    r.status, r.body
                );
            }
        };
        assert!(
            readyz.body.contains("\"status\":\"ok\"")
                || readyz.body.contains("\"status\":\"degraded\""),
            "replica {replica} /readyz body should report ok/degraded — got: {}",
            readyz.body
        );

        // /metrics must return Prometheus exposition with at least the
        // four T1.2 cluster gauges plus the existing request /
        // connection metrics. Use the polling helper so an occasional
        // transient failure (the sidecar's mio loop sometimes resets
        // a connection under cluster boot churn) doesn't flake the
        // test — by the time we get here, the cluster has already
        // been confirmed ready.
        let metrics = match poll_http(&http_addr, "/metrics", 200, Duration::from_secs(10)) {
            Ok(r) => r,
            Err(r) => {
                teardown(supervisor).await;
                panic!(
                    "replica {replica} /metrics never returned 200 (got {}: body excerpt {})",
                    r.status,
                    first_chars(&r.body, 256)
                );
            }
        };
        assert_eq!(metrics.status, 200, "replica {replica} /metrics status");

        let required_gauges = [
            "kimberlite_committed_offset",
            "kimberlite_view_number",
            "kimberlite_is_leader",
            "kimberlite_replication_lag_seconds",
        ];
        for gauge in required_gauges {
            assert!(
                metrics.body.contains(gauge),
                "replica {replica} /metrics missing {gauge}; body excerpt: \n{}",
                first_chars(&metrics.body, 1024)
            );
        }
    }

    teardown(supervisor).await;
}

fn first_chars(s: &str, n: usize) -> &str {
    if let Some((i, _)) = s.char_indices().nth(n) {
        &s[..i]
    } else {
        s
    }
}
