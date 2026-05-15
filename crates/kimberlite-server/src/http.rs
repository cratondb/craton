//! Lightweight HTTP sidecar for metrics, health, readiness, and chaos probes.
//!
//! Runs on a separate port (default 9090; chaos VMs use 9000) alongside
//! the main binary-protocol server. Parses a minimal HTTP/1.1 subset:
//!
//! - `GET /metrics`                — Prometheus text format.
//! - `GET /health`                 — Liveness: always 200 if the process is up.
//! - `GET /ready`                  — Readiness: 503 while unhealthy.
//! - `GET /state/commit_watermark` — Chaos probe: committed offset.
//! - `GET /state/write_log`        — Chaos probe: ordered write IDs.
//! - `GET /state/commit_hash`      — Chaos probe: set-fingerprint hash.
//! - `GET /state/vsr_status`       — Chaos probe: VSR replica status snapshot.
//! - `POST /kv/chaos-probe`        — Chaos probe: submit a write.
//!
//! Chaos endpoints activate only when a [`ChaosHandle`] is plumbed in by
//! the server — controlled at boot via the `KMB_ENABLE_CHAOS_ENDPOINTS=1`
//! env var. Without it these routes return 404.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use mio::net::TcpListener;
use mio::{Interest, Poll, Token};
use tracing::{debug, error, warn};

use crate::chaos::{ChaosHandle, ChaosSnapshot, ProbeResult};
use crate::health::HealthChecker;
use crate::metrics::Metrics;

/// Token offset for the HTTP listener in the mio event loop.
/// Must not conflict with LISTENER_TOKEN (0) or SIGNAL_TOKEN (1).
pub const HTTP_LISTENER_TOKEN: Token = Token(1_000_000);

/// Hard cap on POST body size. Chaos probes carry tiny JSON objects
/// (~60 bytes typical). 4 KiB tolerates any reasonable padding.
const MAX_POST_BODY_BYTES: usize = 4 * 1024;

/// Request-read deadline. Long enough for a client on a lossy link,
/// short enough that a stalled peer can't park the sidecar thread.
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// HTTP sidecar that serves observability + chaos-probe endpoints.
pub struct HttpSidecar {
    listener: TcpListener,
    chaos: Option<ChaosHandle>,
}

impl HttpSidecar {
    /// Binds the HTTP sidecar listener and registers it with the poll.
    pub fn bind(addr: SocketAddr, poll: &Poll) -> std::io::Result<Self> {
        Self::bind_with_chaos(addr, poll, None)
    }

    /// Binds with an optional chaos handle. When `Some`, enables the
    /// `POST /kv/chaos-probe` and `GET /state/*` endpoints.
    pub fn bind_with_chaos(
        addr: SocketAddr,
        poll: &Poll,
        chaos: Option<ChaosHandle>,
    ) -> std::io::Result<Self> {
        let mut listener = TcpListener::bind(addr)?;
        poll.registry()
            .register(&mut listener, HTTP_LISTENER_TOKEN, Interest::READABLE)?;
        if chaos.is_some() {
            tracing::info!("HTTP sidecar listening on {addr} (chaos endpoints enabled)");
        } else {
            tracing::info!("HTTP sidecar listening on {addr}");
        }
        Ok(Self { listener, chaos })
    }

    /// Handles incoming HTTP connections (non-blocking, call from event loop).
    ///
    /// Reads the request, dispatches, writes the response. Connections are
    /// not kept alive. Chaos POSTs hand off to a worker thread via the
    /// `ChaosHandle` so the mio loop isn't stalled waiting on VSR commit.
    pub fn handle_accept(&self, health_checker: &HealthChecker) {
        loop {
            match self.listener.accept() {
                Ok((mut stream, addr)) => {
                    debug!("HTTP connection from {addr}");

                    // Convert to a blocking std socket so we can use
                    // read-timeout semantics for body reads without
                    // wrestling the mio event loop. On Unix this is a
                    // plain FD hand-off; on other platforms we fall back
                    // to best-effort inline parse.
                    let mut request_buf = [0u8; 4096];
                    let n = match stream.read(&mut request_buf) {
                        Ok(0) => continue,
                        Ok(n) => n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            warn!("HTTP read error from {addr}: {e}");
                            continue;
                        }
                    };

                    let raw = &request_buf[..n];
                    let Some(parsed) = parse_request(raw) else {
                        let _ = stream
                            .write_all(http_response(400, "text/plain", "Bad Request").as_bytes());
                        continue;
                    };

                    // Best-effort: if the client's POST body hasn't fully
                    // arrived in the first read, poll for a few more
                    // milliseconds before giving up. Chaos bodies are
                    // typically <100 bytes so this is rarely needed.
                    let full_body = if parsed.method == Method::Post
                        && parsed.body.len() < parsed.content_length.min(MAX_POST_BODY_BYTES)
                    {
                        drain_post_body(&mut stream, &parsed)
                    } else {
                        parsed.body.clone()
                    };

                    let response = dispatch(
                        parsed.method,
                        parsed.path,
                        &full_body,
                        health_checker,
                        self.chaos.as_ref(),
                    );

                    if let Err(e) = write_full_response(&mut stream, response.as_bytes()) {
                        debug!("HTTP write error to {addr}: {e}");
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("HTTP accept error: {e}");
                    break;
                }
            }
        }
    }
}

/// HTTP method we care about. Everything else → 405.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

struct ParsedRequest<'a> {
    method: Method,
    path: &'a str,
    content_length: usize,
    body: Vec<u8>,
}

/// Parses the request line + headers, extracts `Content-Length`, and
/// captures however much of the body landed in the first read.
fn parse_request(raw: &[u8]) -> Option<ParsedRequest<'_>> {
    // Find end of headers (CRLF CRLF).
    let hdr_end = find_subseq(raw, b"\r\n\r\n")?;
    let header_bytes = &raw[..hdr_end];
    let body_bytes = &raw[hdr_end + 4..];

    let headers = std::str::from_utf8(header_bytes).ok()?;
    let mut lines = headers.lines();
    let first = lines.next()?;

    let mut parts = first.split_whitespace();
    let method = match parts.next()? {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => return None,
    };
    let path = parts.next()?;

    let mut content_length = 0usize;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    Some(ParsedRequest {
        method,
        path,
        content_length,
        body: body_bytes.to_vec(),
    })
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Writes the full response to a non-blocking mio TcpStream,
/// looping on `WouldBlock` so kernel send-buffer pressure doesn't
/// silently truncate the body. `mio::net::TcpStream` is non-blocking
/// by default — `std::io::Write::write_all` returns an error on the
/// first `WouldBlock`, then dropping the stream sends a RST that
/// surfaces to the client as "Connection reset by peer". This loop
/// retries with brief sleeps until the data is fully sent or the
/// deadline elapses (the latter rare for sub-MB responses).
///
/// Pre-existing latent bug: small responses (under one TCP packet)
/// always succeeded so health/ready endpoints worked, but `/metrics`
/// with its multi-KB Prometheus output reliably tripped the RST.
fn write_full_response(
    stream: &mut mio::net::TcpStream,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut written = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while written < bytes.len() {
        if std::time::Instant::now() > deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP response write deadline elapsed",
            ));
        }
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "stream write returned 0",
                ));
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads remaining POST body bytes from the mio stream in non-blocking
/// mode, polling briefly until the client's `Content-Length` worth of
/// data has arrived or the deadline fires. Safe — no raw-fd gymnastics.
fn drain_post_body(stream: &mut mio::net::TcpStream, parsed: &ParsedRequest) -> Vec<u8> {
    let target = parsed.content_length.min(MAX_POST_BODY_BYTES);
    let mut body = parsed.body.clone();
    let deadline = std::time::Instant::now() + HTTP_READ_TIMEOUT;

    while body.len() < target && std::time::Instant::now() < deadline {
        let mut buf = [0u8; 512];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    body
}

/// Dispatch a request to the appropriate handler.
fn dispatch(
    method: Method,
    path: &str,
    body: &[u8],
    health_checker: &HealthChecker,
    chaos: Option<&ChaosHandle>,
) -> String {
    match (method, path) {
        (Method::Get, "/metrics") => {
            // Refresh cluster gauges from a fresh ReplicationStatus
            // snapshot so the scrape sees current values without
            // paying for a periodic background tick.
            let status = health_checker.submitter().map(|s| s.status());
            Metrics::global().sync_replication_status(status.as_ref());
            let body = Metrics::global().render();
            http_response(200, "text/plain; version=0.0.4; charset=utf-8", &body)
        }
        // `/healthz` / `/readyz` are the Kubernetes-convention paths
        // (originating from Google's internal `/healthz`). `/health`
        // and `/ready` are kept as back-compat aliases for existing
        // probes; both routes return identical responses.
        (Method::Get, "/healthz" | "/health") => {
            let response = health_checker.liveness_check();
            http_response(200, "application/json", &response.to_json())
        }
        (Method::Get, "/readyz" | "/ready") => {
            let response = health_checker.readiness_check();
            let status_code = if response.status.is_healthy() {
                200
            } else {
                503
            };
            http_response(status_code, "application/json", &response.to_json())
        }
        (Method::Get, "/state/commit_watermark") => chaos_get_watermark(chaos),
        (Method::Get, "/state/write_log") => chaos_get_write_log(chaos),
        (Method::Get, "/state/commit_hash") => chaos_get_commit_hash(chaos),
        (Method::Get, "/state/vsr_status") => chaos_get_vsr_status(chaos),
        (Method::Post, "/kv/chaos-probe") => chaos_post_probe(body, chaos),
        _ => http_response(404, "text/plain", "Not Found"),
    }
}

fn chaos_get_watermark(chaos: Option<&ChaosHandle>) -> String {
    let Some(h) = chaos else {
        return http_response(404, "text/plain", "chaos endpoints disabled");
    };
    let snap = h.snapshot();
    http_response(
        200,
        "application/json",
        &format!("{{\"watermark\":{}}}", snap.watermark),
    )
}

fn chaos_get_write_log(chaos: Option<&ChaosHandle>) -> String {
    let Some(h) = chaos else {
        return http_response(404, "text/plain", "chaos endpoints disabled");
    };
    let snap = h.snapshot();
    let body = render_write_log_json(&snap);
    http_response(200, "application/json", &body)
}

fn chaos_get_commit_hash(chaos: Option<&ChaosHandle>) -> String {
    let Some(h) = chaos else {
        return http_response(404, "text/plain", "chaos endpoints disabled");
    };
    let snap = h.snapshot();
    http_response(
        200,
        "application/json",
        &format!("{{\"commit_hash\":\"{}\"}}", snap.commit_hash),
    )
}

fn chaos_get_vsr_status(chaos: Option<&ChaosHandle>) -> String {
    let Some(h) = chaos else {
        return http_response(404, "text/plain", "chaos endpoints disabled");
    };
    let status = h.replication_status();
    // Render as JSON. Missing fields (Direct/SingleNode modes, poisoned lock)
    // serialize as `null` so chaos probes can distinguish "no cluster VSR"
    // from "replica in view_change".
    let replica_status = status
        .replica_status
        .map_or_else(|| "null".to_string(), |s| format!("\"{s}\""));
    let bootstrap_complete = status
        .bootstrap_complete
        .map_or_else(|| "null".to_string(), |b| b.to_string());
    let commit_number = status
        .commit_number
        .map_or_else(|| "null".to_string(), |n| n.to_string());
    let body = format!(
        "{{\"replica_status\":{replica_status},\"bootstrap_complete\":{bootstrap_complete},\"commit_number\":{commit_number}}}"
    );
    http_response(200, "application/json", &body)
}

fn chaos_post_probe(body: &[u8], chaos: Option<&ChaosHandle>) -> String {
    let Some(h) = chaos else {
        return http_response(404, "text/plain", "chaos endpoints disabled");
    };

    let write_id = extract_write_id(std::str::from_utf8(body).unwrap_or("")).map(str::to_string);
    let rx = match h.submit_probe(write_id) {
        Ok(rx) => rx,
        Err(_) => {
            return http_response(
                503,
                "text/plain",
                "no_quorum: chaos worker queue full (backpressure)",
            );
        }
    };

    match rx.recv_timeout(Duration::from_secs(6)) {
        Ok(ProbeResult::Ok) => http_response(200, "text/plain", "ok"),
        Ok(ProbeResult::NoQuorum(reason)) => {
            http_response(503, "text/plain", &format!("no_quorum: {reason}"))
        }
        Ok(ProbeResult::NotLeader { view, leader_hint }) => {
            let hint = leader_hint.unwrap_or_else(|| "unknown".into());
            http_response(
                421,
                "text/plain",
                &format!("not_leader: view={view} leader={hint}"),
            )
        }
        Ok(ProbeResult::InternalError(msg)) => {
            http_response(500, "text/plain", &format!("error: {msg}"))
        }
        Err(_) => http_response(
            503,
            "text/plain",
            "no_quorum: chaos worker did not respond in time",
        ),
    }
}

/// Extracts `"write_id":"<s>"` from a JSON body without pulling in serde.
/// Returns `None` for missing or empty value.
fn extract_write_id(body: &str) -> Option<&str> {
    const KEY: &str = "\"write_id\":\"";
    let start = body.find(KEY)? + KEY.len();
    let end = body[start..].find('"')? + start;
    let v = &body[start..end];
    if v.is_empty() { None } else { Some(v) }
}

/// Renders the ordered write_ids as `{"write_ids":["..."],"total":N}`.
fn render_write_log_json(snap: &ChaosSnapshot) -> String {
    let ids: String = snap
        .write_ids
        .iter()
        .map(|id| format!("\"{}\"", id.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"write_ids\":[{}],\"total\":{}}}",
        ids,
        snap.write_ids.len()
    )
}

/// Build a minimal HTTP/1.1 response.
fn http_response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };

    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get() {
        let raw = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let p = parse_request(raw).unwrap();
        assert_eq!(p.method, Method::Get);
        assert_eq!(p.path, "/metrics");
        assert_eq!(p.content_length, 0);
        assert!(p.body.is_empty());
    }

    #[test]
    fn parse_post_with_body() {
        let raw =
            b"POST /kv/chaos-probe HTTP/1.1\r\nContent-Length: 26\r\n\r\n{\"write_id\":\"42\"}";
        let p = parse_request(raw).unwrap();
        assert_eq!(p.method, Method::Post);
        assert_eq!(p.path, "/kv/chaos-probe");
        assert_eq!(p.content_length, 26);
        assert_eq!(p.body, b"{\"write_id\":\"42\"}");
    }

    #[test]
    fn parse_rejects_unsupported_method() {
        assert!(parse_request(b"DELETE / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn extract_write_id_basic() {
        assert_eq!(
            extract_write_id(r#"{"op":"workload","write_id":"42"}"#),
            Some("42")
        );
    }

    #[test]
    fn extract_write_id_missing() {
        assert_eq!(extract_write_id(r#"{"op":"chaos-probe"}"#), None);
    }

    #[test]
    fn extract_write_id_empty_value() {
        assert_eq!(extract_write_id(r#"{"write_id":""}"#), None);
    }

    #[test]
    fn render_write_log_empty() {
        let snap = ChaosSnapshot::default();
        assert_eq!(
            render_write_log_json(&snap),
            "{\"write_ids\":[],\"total\":0}"
        );
    }

    #[test]
    fn render_write_log_multiple() {
        let snap = ChaosSnapshot {
            write_ids: vec!["w1".into(), "w2".into(), "w3".into()],
            ..Default::default()
        };
        let json = render_write_log_json(&snap);
        assert!(json.contains("\"w1\""));
        assert!(json.contains("\"w2\""));
        assert!(json.contains("\"w3\""));
        assert!(json.contains("\"total\":3"));
    }

    #[test]
    fn render_write_log_escapes_quotes_and_backslashes() {
        let snap = ChaosSnapshot {
            write_ids: vec!["a\"b\\c".into()],
            ..Default::default()
        };
        let json = render_write_log_json(&snap);
        assert!(json.contains("\"a\\\"b\\\\c\""), "got {json}");
    }

    #[test]
    fn http_response_format() {
        let resp = http_response(200, "text/plain", "OK");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Length: 2\r\n"));
        assert!(resp.ends_with("OK"));
    }
}
