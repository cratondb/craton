//! Health check endpoints for liveness and readiness probes.
//!
//! Provides `/healthz` (liveness) and `/readyz` (readiness) endpoints
//! for Kubernetes and load balancer health checks. The `/health` and
//! `/ready` paths are kept as back-compat aliases.
//!
//! In replicated mode the readiness check additionally requires that
//! VSR has completed bootstrap, the local replica is in `Normal`
//! status, and `commit_lag_seconds` is below `max_replication_lag`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics::Metrics;
use crate::replication::CommandSubmitter;

/// Default maximum replication lag (seconds) before `/readyz` flips
/// to 503. Picked to comfortably exceed the dev `view_change_timeout`
/// (1 s) so a short view-change window doesn't false-positive a
/// follower; operators can override per-deployment.
pub const DEFAULT_MAX_REPLICATION_LAG_SECONDS: f64 = 5.0;

/// Health check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// The service is healthy.
    Ok,
    /// The service is degraded but functional.
    Degraded,
    /// The service is unhealthy.
    Unhealthy,
}

impl HealthStatus {
    /// Returns true if the status is healthy or degraded.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Ok | Self::Degraded)
    }
}

/// Result of a health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: HealthStatus,
    /// Individual check results.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub checks: HashMap<String, CheckResult>,
    /// Server version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Uptime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

/// Result of an individual health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check status.
    pub status: HealthStatus,
    /// Additional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Check duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl CheckResult {
    /// Creates a healthy check result.
    pub fn ok() -> Self {
        Self {
            status: HealthStatus::Ok,
            message: None,
            duration_ms: None,
        }
    }

    /// Creates an unhealthy check result.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            duration_ms: None,
        }
    }

    /// Creates a degraded check result.
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            duration_ms: None,
        }
    }

    /// Sets the duration.
    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration_ms = Some(duration.as_millis() as u64);
        self
    }
}

/// Health checker that performs various health checks.
pub struct HealthChecker {
    /// Server start time.
    start_time: Instant,
    /// Data directory path.
    data_dir: std::path::PathBuf,
    /// Minimum free disk space (10% by default).
    min_disk_free_percent: f64,
    /// Replication submitter for VSR-aware readiness checks. `None`
    /// in tests / direct mode; `Some` in single-node and cluster
    /// modes whether we ran via [`Self::with_submitter`].
    submitter: Option<Arc<CommandSubmitter>>,
    /// Maximum acceptable replication lag in seconds before `/readyz`
    /// flips to 503. Tunable so chaos / latency-sensitive deployments
    /// can dial it independently of the VSR view-change timeout.
    max_replication_lag_seconds: f64,
}

impl HealthChecker {
    /// Creates a new health checker.
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            start_time: Instant::now(),
            data_dir: data_dir.as_ref().to_path_buf(),
            min_disk_free_percent: 10.0,
            submitter: None,
            max_replication_lag_seconds: DEFAULT_MAX_REPLICATION_LAG_SECONDS,
        }
    }

    /// Attaches the [`CommandSubmitter`] so [`Self::readiness_check`]
    /// can incorporate VSR status (bootstrap complete, replica
    /// `Normal`, replication lag under threshold). Direct mode (no
    /// VSR) is treated as always-ready and the submitter is still
    /// useful so `kimberlite_committed_offset` etc. read 0 not
    /// missing.
    #[must_use]
    pub fn with_submitter(mut self, submitter: Arc<CommandSubmitter>) -> Self {
        self.submitter = Some(submitter);
        self
    }

    /// Returns the attached submitter, if any. Used by the HTTP
    /// sidecar to refresh cluster gauges at scrape time.
    pub fn submitter(&self) -> Option<&Arc<CommandSubmitter>> {
        self.submitter.as_ref()
    }

    /// Sets the maximum acceptable replication lag in seconds.
    #[must_use]
    pub fn with_max_replication_lag(mut self, seconds: f64) -> Self {
        self.max_replication_lag_seconds = seconds;
        self
    }

    /// Sets the minimum free disk space percentage.
    #[must_use]
    pub fn with_min_disk_free_percent(mut self, percent: f64) -> Self {
        self.min_disk_free_percent = percent;
        self
    }

    /// Performs a liveness check.
    ///
    /// Liveness checks should be fast and only verify that the process
    /// is running and responsive. If this fails, the container should
    /// be restarted.
    pub fn liveness_check(&self) -> HealthResponse {
        HealthResponse {
            status: HealthStatus::Ok,
            checks: HashMap::new(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            uptime_seconds: Some(self.start_time.elapsed().as_secs()),
        }
    }

    /// Performs a readiness check.
    ///
    /// Readiness checks verify that the service is ready to accept traffic.
    /// This includes checking dependencies like storage and memory, and —
    /// when an attached [`CommandSubmitter`] is in replicated mode — that
    /// VSR has bootstrapped, the local replica is `Normal`, and the
    /// replication lag is under [`Self::with_max_replication_lag`].
    pub fn readiness_check(&self) -> HealthResponse {
        let mut checks = HashMap::new();
        let mut overall_status = HealthStatus::Ok;

        // Check disk space
        let disk_check = self.check_disk_space();
        if disk_check.status == HealthStatus::Unhealthy {
            overall_status = HealthStatus::Unhealthy;
        } else if disk_check.status == HealthStatus::Degraded && overall_status == HealthStatus::Ok
        {
            overall_status = HealthStatus::Degraded;
        }
        checks.insert("disk".to_string(), disk_check);

        // Check memory
        let memory_check = self.check_memory();
        if memory_check.status == HealthStatus::Unhealthy {
            overall_status = HealthStatus::Unhealthy;
        } else if memory_check.status == HealthStatus::Degraded
            && overall_status == HealthStatus::Ok
        {
            overall_status = HealthStatus::Degraded;
        }
        checks.insert("memory".to_string(), memory_check);

        // Check data directory
        let data_check = self.check_data_dir();
        if data_check.status == HealthStatus::Unhealthy {
            overall_status = HealthStatus::Unhealthy;
        }
        checks.insert("data_dir".to_string(), data_check);

        // Check VSR replication state if a submitter is attached.
        // Direct mode reports `replica_status: None` and is treated as
        // always-ready (single-node deployments don't have a notion of
        // "lag"). Single-node and cluster modes apply the full check.
        if let Some(submitter) = &self.submitter {
            let vsr_check = self.check_vsr(submitter);
            if vsr_check.status == HealthStatus::Unhealthy {
                overall_status = HealthStatus::Unhealthy;
            } else if vsr_check.status == HealthStatus::Degraded
                && overall_status == HealthStatus::Ok
            {
                overall_status = HealthStatus::Degraded;
            }
            checks.insert("vsr".to_string(), vsr_check);
        }

        HealthResponse {
            status: overall_status,
            checks,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            uptime_seconds: Some(self.start_time.elapsed().as_secs()),
        }
    }

    /// Renders the VSR replication subset of the readiness check.
    ///
    /// Direct mode → always-ready. SingleNode → ready (always
    /// bootstrapped, lag = 0). Cluster → ready iff bootstrap is
    /// complete, the replica is in `Normal` status, and
    /// `commit_lag_seconds` is under the configured maximum. Each
    /// failure mode produces a distinct, operator-actionable
    /// `message`.
    fn check_vsr(&self, submitter: &CommandSubmitter) -> CheckResult {
        let start = Instant::now();
        let status = submitter.status();

        // Direct mode has no VSR — pass through cleanly.
        if status.replica_status.is_none() {
            return CheckResult::ok().with_duration(start.elapsed());
        }

        if matches!(status.bootstrap_complete, Some(false)) {
            return CheckResult::unhealthy("VSR bootstrap not complete")
                .with_duration(start.elapsed());
        }

        match status.replica_status {
            // "normal" or None (direct mode, already handled above) → continue.
            Some("normal") | None => {}
            Some(other) => {
                return CheckResult::unhealthy(format!("VSR replica status: {other}"))
                    .with_duration(start.elapsed());
            }
        }

        if let Some(lag) = status.commit_lag_seconds {
            if lag > self.max_replication_lag_seconds {
                return CheckResult::degraded(format!(
                    "replication lag {lag:.2}s exceeds threshold {:.2}s",
                    self.max_replication_lag_seconds
                ))
                .with_duration(start.elapsed());
            }
        }

        CheckResult::ok().with_duration(start.elapsed())
    }

    /// Checks disk space availability.
    fn check_disk_space(&self) -> CheckResult {
        let start = Instant::now();

        // Use statvfs on Unix to check disk space
        #[cfg(unix)]
        {
            // We'll use a simple heuristic since we can't directly call statvfs
            // In production, you'd use the nix crate or similar
            if self.data_dir.exists() {
                // Assume healthy if directory exists
                CheckResult::ok().with_duration(start.elapsed())
            } else {
                CheckResult::unhealthy("data directory does not exist")
                    .with_duration(start.elapsed())
            }
        }

        #[cfg(not(unix))]
        {
            if self.data_dir.exists() {
                CheckResult::ok().with_duration(start.elapsed())
            } else {
                CheckResult::unhealthy("data directory does not exist")
                    .with_duration(start.elapsed())
            }
        }
    }

    /// Checks memory usage.
    #[allow(clippy::unused_self)] // May need self in the future for memory limit config
    fn check_memory(&self) -> CheckResult {
        let start = Instant::now();

        // Check current connections as a proxy for memory pressure
        let connections = Metrics::global().connections_active.get();

        if connections > 900.0 {
            // Near max connections (assuming 1024 max)
            CheckResult::degraded(format!("high connection count: {connections}"))
                .with_duration(start.elapsed())
        } else {
            CheckResult::ok().with_duration(start.elapsed())
        }
    }

    /// Checks that the data directory is accessible.
    fn check_data_dir(&self) -> CheckResult {
        let start = Instant::now();

        if !self.data_dir.exists() {
            return CheckResult::unhealthy("data directory does not exist")
                .with_duration(start.elapsed());
        }

        // Try to check if the directory is writable
        let test_file = self.data_dir.join(".health_check");
        match std::fs::write(&test_file, b"health") {
            Ok(()) => {
                // Clean up
                let _ = std::fs::remove_file(&test_file);
                CheckResult::ok().with_duration(start.elapsed())
            }
            Err(e) => CheckResult::unhealthy(format!("data directory not writable: {e}"))
                .with_duration(start.elapsed()),
        }
    }

    /// Returns the uptime in seconds.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Returns the metrics endpoint response.
    pub fn metrics(&self) -> String {
        Metrics::global().render()
    }
}

impl HealthResponse {
    /// Serializes the response to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"status":"unhealthy"}"#.to_string())
    }

    /// Serializes the response to pretty JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| r#"{"status":"unhealthy"}"#.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Ok.is_healthy());
        assert!(HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Unhealthy.is_healthy());
    }

    #[test]
    fn test_check_result_ok() {
        let result = CheckResult::ok();
        assert_eq!(result.status, HealthStatus::Ok);
        assert!(result.message.is_none());
    }

    #[test]
    fn test_check_result_unhealthy() {
        let result = CheckResult::unhealthy("test error");
        assert_eq!(result.status, HealthStatus::Unhealthy);
        assert_eq!(result.message.as_deref(), Some("test error"));
    }

    #[test]
    fn test_health_checker_liveness() {
        let checker = HealthChecker::new("/tmp");
        let response = checker.liveness_check();
        assert_eq!(response.status, HealthStatus::Ok);
        assert!(response.version.is_some());
        assert!(response.uptime_seconds.is_some());
    }

    #[test]
    fn test_health_response_to_json() {
        let response = HealthResponse {
            status: HealthStatus::Ok,
            checks: HashMap::new(),
            version: Some("0.1.0".to_string()),
            uptime_seconds: Some(100),
        };

        let json = response.to_json();
        assert!(json.contains(r#""status":"ok""#));
        assert!(json.contains(r#""version":"0.1.0""#));
    }

    #[test]
    fn test_health_checker_readiness_with_temp_dir() {
        let temp = tempfile::tempdir().unwrap();
        let checker = HealthChecker::new(temp.path());
        let response = checker.readiness_check();

        // Should be healthy with a valid temp directory
        assert!(response.status.is_healthy());
        assert!(response.checks.contains_key("disk"));
        assert!(response.checks.contains_key("memory"));
        assert!(response.checks.contains_key("data_dir"));
    }
}
