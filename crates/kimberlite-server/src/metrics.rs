//! Prometheus metrics for the `Kimberlite` server.
//!
//! Exposes metrics for monitoring request rates, latencies, connections, and errors.

use std::sync::OnceLock;
use std::time::Instant;

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};

/// Global metrics registry.
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Server metrics collection.
pub struct Metrics {
    /// Registry for all metrics.
    registry: Registry,

    // Request metrics
    /// Total requests by method and status.
    pub requests_total: CounterVec,
    /// Request duration histogram by method.
    pub request_duration_seconds: HistogramVec,
    /// Currently in-flight requests.
    pub requests_in_flight: Gauge,

    // Connection metrics
    /// Total connections accepted.
    pub connections_total: Counter,
    /// Currently active connections.
    pub connections_active: Gauge,
    /// Connections by state (handshaking, authenticated, closing).
    pub connections_by_state: GaugeVec,

    // Error metrics
    /// Errors by type.
    pub errors_total: CounterVec,

    // Rate limiting metrics
    /// Requests rejected due to rate limiting.
    pub rate_limited_total: Counter,

    // Storage metrics
    /// Bytes written to storage.
    pub storage_bytes_written: Counter,
    /// Records written to storage.
    pub storage_records_written: Counter,
    /// Checkpoints created.
    pub storage_checkpoints: Counter,

    // Authentication metrics
    /// Authentication attempts by method and result.
    pub auth_attempts: CounterVec,

    // Cluster / VSR replication metrics (T1.2)
    //
    // Sampled into these gauges by `Metrics::sync_replication_status`,
    // typically called from the HTTP sidecar's `/metrics` handler so the
    // values reflect the latest [`ReplicationStatus`] at scrape time.
    /// Local committed offset (VSR `commit_number`). 0 in direct mode.
    pub committed_offset: Gauge,
    /// Current view number. 0 in direct / single-node modes.
    pub view_number: Gauge,
    /// 1 if this replica is the leader, 0 otherwise.
    pub is_leader: Gauge,
    /// Seconds since this replica's `commit_number` last advanced.
    /// 0 on the leader (writes commit immediately on this node);
    /// followers report wall-clock time since their last apply, which
    /// approximates "how far behind the leader are we" in a low-write
    /// cluster. Operators paging on this should also watch
    /// `kimberlite_committed_offset` per replica.
    pub replication_lag_seconds: Gauge,
}

impl Metrics {
    /// Creates a new metrics collection.
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let registry = Registry::new();

        // Request metrics
        let requests_total = CounterVec::new(
            Opts::new("kimberlite_requests_total", "Total number of requests"),
            &["method", "status"],
        )
        .expect("valid metric");

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "kimberlite_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                10.0,
            ]),
            &["method"],
        )
        .expect("valid metric");

        let requests_in_flight = Gauge::new(
            "kimberlite_requests_in_flight",
            "Number of requests currently being processed",
        )
        .expect("valid metric");

        // Connection metrics
        let connections_total = Counter::new(
            "kimberlite_connections_total",
            "Total number of connections accepted",
        )
        .expect("valid metric");

        let connections_active = Gauge::new(
            "kimberlite_connections_active",
            "Number of active connections",
        )
        .expect("valid metric");

        let connections_by_state = GaugeVec::new(
            Opts::new("kimberlite_connections_by_state", "Connections by state"),
            &["state"],
        )
        .expect("valid metric");

        // Error metrics
        let errors_total = CounterVec::new(
            Opts::new("kimberlite_errors_total", "Total number of errors"),
            &["type"],
        )
        .expect("valid metric");

        // Rate limiting metrics
        let rate_limited_total = Counter::new(
            "kimberlite_rate_limited_total",
            "Total requests rejected due to rate limiting",
        )
        .expect("valid metric");

        // Storage metrics
        let storage_bytes_written = Counter::new(
            "kimberlite_storage_bytes_written_total",
            "Total bytes written to storage",
        )
        .expect("valid metric");

        let storage_records_written = Counter::new(
            "kimberlite_storage_records_total",
            "Total records written to storage",
        )
        .expect("valid metric");

        let storage_checkpoints = Counter::new(
            "kimberlite_storage_checkpoints_total",
            "Total checkpoints created",
        )
        .expect("valid metric");

        // Authentication metrics
        let auth_attempts = CounterVec::new(
            Opts::new("kimberlite_auth_attempts_total", "Authentication attempts"),
            &["method", "result"],
        )
        .expect("valid metric");

        // Cluster / VSR replication metrics
        let committed_offset = Gauge::new(
            "kimberlite_committed_offset",
            "Local VSR commit_number — highest op_number durably committed on this replica",
        )
        .expect("valid metric");

        let view_number = Gauge::new(
            "kimberlite_view_number",
            "Current VSR view number on this replica",
        )
        .expect("valid metric");

        let is_leader = Gauge::new(
            "kimberlite_is_leader",
            "1 if this replica is the leader for the current view, 0 otherwise",
        )
        .expect("valid metric");

        let replication_lag_seconds = Gauge::new(
            "kimberlite_replication_lag_seconds",
            "Seconds since this replica's commit_number last advanced (0 on leader)",
        )
        .expect("valid metric");

        // Register all metrics
        registry
            .register(Box::new(requests_total.clone()))
            .expect("register metric");
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .expect("register metric");
        registry
            .register(Box::new(requests_in_flight.clone()))
            .expect("register metric");
        registry
            .register(Box::new(connections_total.clone()))
            .expect("register metric");
        registry
            .register(Box::new(connections_active.clone()))
            .expect("register metric");
        registry
            .register(Box::new(connections_by_state.clone()))
            .expect("register metric");
        registry
            .register(Box::new(errors_total.clone()))
            .expect("register metric");
        registry
            .register(Box::new(rate_limited_total.clone()))
            .expect("register metric");
        registry
            .register(Box::new(storage_bytes_written.clone()))
            .expect("register metric");
        registry
            .register(Box::new(storage_records_written.clone()))
            .expect("register metric");
        registry
            .register(Box::new(storage_checkpoints.clone()))
            .expect("register metric");
        registry
            .register(Box::new(auth_attempts.clone()))
            .expect("register metric");
        registry
            .register(Box::new(committed_offset.clone()))
            .expect("register metric");
        registry
            .register(Box::new(view_number.clone()))
            .expect("register metric");
        registry
            .register(Box::new(is_leader.clone()))
            .expect("register metric");
        registry
            .register(Box::new(replication_lag_seconds.clone()))
            .expect("register metric");

        Self {
            registry,
            requests_total,
            request_duration_seconds,
            requests_in_flight,
            connections_total,
            connections_active,
            connections_by_state,
            errors_total,
            rate_limited_total,
            storage_bytes_written,
            storage_records_written,
            storage_checkpoints,
            auth_attempts,
            committed_offset,
            view_number,
            is_leader,
            replication_lag_seconds,
        }
    }

    /// Refreshes the cluster gauges (`kimberlite_committed_offset`,
    /// `kimberlite_view_number`, `kimberlite_is_leader`,
    /// `kimberlite_replication_lag_seconds`) from a freshly-sampled
    /// [`crate::ReplicationStatus`]. Call from the `/metrics` HTTP
    /// handler so each scrape sees current values without paying for a
    /// background tick. Direct mode passes `None` and the gauges stay
    /// at their initial zeros — Prometheus treats that as "no
    /// replication" rather than "broken".
    pub fn sync_replication_status(&self, status: Option<&crate::ReplicationStatus>) {
        let Some(status) = status else {
            return;
        };
        if let Some(commit) = status.commit_number {
            self.committed_offset.set(commit as f64);
        }
        if let Some(view) = status.view {
            self.view_number.set(view as f64);
        }
        self.is_leader.set(if status.is_leader { 1.0 } else { 0.0 });
        if let Some(lag) = status.commit_lag_seconds {
            self.replication_lag_seconds.set(lag);
        }
    }

    /// Returns the global metrics instance.
    pub fn global() -> &'static Metrics {
        METRICS.get_or_init(Metrics::new)
    }

    /// Renders metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode_to_string(&metric_families)
            .unwrap_or_else(|e| format!("# Error encoding metrics: {e}\n"))
    }
}

/// A guard that measures request duration when dropped.
pub struct RequestTimer {
    method: &'static str,
    start: Instant,
}

impl RequestTimer {
    /// Creates a new request timer.
    pub fn new(method: &'static str) -> Self {
        Metrics::global().requests_in_flight.inc();
        Self {
            method,
            start: Instant::now(),
        }
    }
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        let metrics = Metrics::global();
        metrics.requests_in_flight.dec();
        metrics
            .request_duration_seconds
            .with_label_values(&[self.method])
            .observe(duration);
    }
}

/// Records a successful request.
pub fn record_request_success(method: &str) {
    Metrics::global()
        .requests_total
        .with_label_values(&[method, "success"])
        .inc();
}

/// Records a failed request.
pub fn record_request_error(method: &str, error_type: &str) {
    let metrics = Metrics::global();
    metrics
        .requests_total
        .with_label_values(&[method, "error"])
        .inc();
    metrics.errors_total.with_label_values(&[error_type]).inc();
}

/// Records a new connection.
pub fn record_connection_accepted() {
    let metrics = Metrics::global();
    metrics.connections_total.inc();
    metrics.connections_active.inc();
}

/// Records a closed connection.
pub fn record_connection_closed() {
    Metrics::global().connections_active.dec();
}

/// Records a rate-limited request.
pub fn record_rate_limited() {
    Metrics::global().rate_limited_total.inc();
}

/// Records an authentication attempt.
pub fn record_auth_attempt(method: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    Metrics::global()
        .auth_attempts
        .with_label_values(&[method, result])
        .inc();
}

/// Records storage operations.
#[allow(clippy::cast_precision_loss)]
pub fn record_storage_write(bytes: u64, records: u64) {
    let metrics = Metrics::global();
    metrics.storage_bytes_written.inc_by(bytes as f64);
    metrics.storage_records_written.inc_by(records as f64);
}

/// Records a checkpoint creation.
pub fn record_checkpoint() {
    Metrics::global().storage_checkpoints.inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::global();
        // Record a metric first so it appears in the output
        record_request_success("test");
        assert!(metrics.render().contains("kimberlite_requests_total"));
    }

    #[test]
    fn test_request_timer() {
        let _timer = RequestTimer::new("test");
        let metrics = Metrics::global();
        assert!(metrics.requests_in_flight.get() >= 1.0);
        // Timer will be dropped and decrement when it goes out of scope
    }

    #[test]
    fn test_record_request_success() {
        record_request_success("Query");
        let output = Metrics::global().render();
        assert!(output.contains("kimberlite_requests_total"));
    }

    #[test]
    fn test_record_connection() {
        let initial = Metrics::global().connections_active.get();
        record_connection_accepted();
        assert!(
            (Metrics::global().connections_active.get() - (initial + 1.0)).abs() < f64::EPSILON
        );
        record_connection_closed();
        assert!((Metrics::global().connections_active.get() - initial).abs() < f64::EPSILON);
    }
}
