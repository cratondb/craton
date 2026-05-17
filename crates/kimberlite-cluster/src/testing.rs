//! Test-only helpers for spawned-binary cluster tests and benches.
//!
//! Marked `#[doc(hidden)]` and exposed via `kimberlite_cluster::testing`
//! so the crate's own integration tests, the cluster bench harness in
//! `kimberlite-bench`, and the perf-baseline harness all share one
//! source of truth for port reservation, binary discovery, HTTP/1.1
//! polling, and Prometheus gauge parsing. Not for end-user consumption.
//!
//! All helpers are sync (`std::thread::sleep`) so they work in both
//! blocking test contexts and inside `#[tokio::test]` bodies — the
//! brief 100–250 ms polls block one worker thread, which is fine for
//! `#[ignore]`-tagged integration tests but would be wrong in
//! production async code.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// HTTP sidecar offset relative to the data port, mirroring the
/// supervisor's convention in `kimberlite-cluster::config`.
pub const HTTP_PORT_OFFSET: u16 = 1_000;

/// Locates a built `kimberlite` binary by walking up from this crate's
/// manifest dir to `target/{debug,release}/kimberlite`. Honors
/// `KIMBERLITE_BIN` env override. Returns `None` if no binary exists
/// — tests typically skip-with-message in that case.
pub fn locate_built_kimberlite() -> Option<PathBuf> {
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
/// Sweeps downward from a random ephemeral probe in 10-port strides.
/// More robust than picking independent random ports because adjacent
/// bands tend to have correlated availability (whole ranges in
/// TIME_WAIT after a previous test run).
pub fn pick_base_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0")
        .expect("bind probe socket")
        .local_addr()
        .expect("probe local_addr")
        .port();
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
/// or the deadline elapses; panics on timeout. Same pattern across
/// every spawned-binary test in this crate.
pub fn wait_for_tcp_ready(base_port: u16, node_count: u16, deadline: Duration) {
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

/// Polls a single TCP port until it accepts a connection or the
/// deadline elapses. Useful for waiting on a single restarted node.
pub fn wait_for_port(addr: &str, deadline: Duration) -> bool {
    let stop = Instant::now() + deadline;
    let socket: SocketAddr = addr.parse().expect("addr parses");
    while Instant::now() < stop {
        if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Decomposed HTTP/1.1 response: status code + body. Headers are
/// discarded — the integration tests only assert on these two.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Minimal HTTP/1.1 GET on a fresh TCP connection. Avoids a heavy
/// HTTP client crate; the sidecar's parser is plain HTTP/1.1.
pub fn http_get(addr: &str, path: &str) -> Result<HttpResponse, String> {
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

/// Polls `path` on `addr` until the response status matches `expected`
/// or the deadline elapses. Returns the final response either way so
/// callers can include the body in assertion failure messages.
pub fn poll_http(
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
            Err(_) => {}
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

/// Returns the replica id (0..node_count) whose `kimberlite_is_leader`
/// gauge reads `1` in its `/metrics` endpoint, or `None` if no replica
/// reports leadership within the deadline.
///
/// During a view change zero or two replicas may temporarily report
/// leadership; the helper requires exactly one to settle on a result,
/// retrying until the cluster stabilises.
pub fn find_leader_replica(base_port: u16, node_count: u16, deadline: Duration) -> Option<u16> {
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        let mut leaders: Vec<u16> = Vec::new();
        for replica in 0..node_count {
            let addr = format!("127.0.0.1:{}", base_port + HTTP_PORT_OFFSET + replica);
            if let Ok(resp) = http_get(&addr, "/metrics") {
                if resp.status == 200
                    && parse_gauge(&resp.body, "kimberlite_is_leader") == Some(1.0)
                {
                    leaders.push(replica);
                }
            }
        }
        if leaders.len() == 1 {
            return Some(leaders[0]);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// Extracts the numeric value of a Prometheus gauge from a `/metrics`
/// text exposition.
///
/// Looks for the FIRST data line of the form `<gauge> <value>` — i.e.
/// not starting with `#` (which would be a `# HELP` / `# TYPE`
/// comment) — and parses the trailing whitespace-separated token as
/// `f64`.
///
/// Returns `None` if the gauge is absent or unparseable. Substring
/// matches against the raw body are unsafe here: Prometheus's `HELP`
/// comment embeds the gauge description verbatim, so
/// `body.contains("kimberlite_is_leader 1")` happily matches the
/// `# HELP kimberlite_is_leader 1 if this replica…` line on every
/// replica regardless of the gauge value. That false-positive sent
/// `find_leader_replica` chasing the wrong replica during boot and
/// drove the v0.9.x integration-test flake.
pub fn parse_gauge(body: &str, name: &str) -> Option<f64> {
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let first = parts.next()?;
        if first != name {
            continue;
        }
        return parts.next().and_then(|v| v.parse().ok());
    }
    None
}
