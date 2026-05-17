---
title: "Monitoring"
section: "operating"
slug: "monitoring"
order: 4
---

# Monitoring

Monitor Kimberlite clusters in production.

> **Running a 3-node cluster?** Pair this metrics guide with [`runbooks/cluster.md`](runbooks/cluster.md) — the runbook maps the cluster gauges below (`kimberlite_is_leader`, `kimberlite_committed_offset`, `kimberlite_replication_lag_seconds`, `kimberlite_view_number`) to specific failure modes and triage steps.

## Overview

Kimberlite provides comprehensive observability through:
1. **Prometheus metrics** - Performance and health metrics
2. **Structured logging** - JSON logs with request tracing
3. **OpenTelemetry tracing** - Distributed request traces
4. **Health checks** - HTTP endpoints for load balancers

## Prometheus Metrics

Kimberlite exposes Prometheus-compatible metrics on the configured metrics endpoint (default: `:9090`).

### Accessing Metrics

```bash
# Scrape metrics
curl http://localhost:9090/metrics

# Example output
# TYPE kmb_log_entries_total counter
kmb_log_entries_total{node_id="1"} 12345
# TYPE kmb_log_bytes_total counter
kmb_log_bytes_total{node_id="1"} 524288000
```

### Core Metrics

**Log Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `kmb_log_entries_total` | Counter | Total log entries written |
| `kmb_log_bytes_total` | Counter | Total log bytes written |
| `kmb_log_size_bytes` | Gauge | Current log size |

**Consensus Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `kmb_consensus_commits_total` | Counter | Total committed entries |
| `kmb_consensus_view` | Gauge | Current consensus view number |
| `kmb_consensus_leader` | Gauge | Current leader node ID |
| `kmb_consensus_view_changes_total` | Counter | Total view changes |

**Projection Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `kmb_projection_applied_position` | Gauge | Last applied log position |
| `kmb_projection_lag` | Gauge | Log position lag (head - applied) |

**Query Performance:**

| Metric | Type | Description |
|--------|------|-------------|
| `kmb_query_duration_seconds` | Histogram | Query latency distribution |
| `kmb_write_duration_seconds` | Histogram | Write latency distribution |
| `kmb_requests_total` | Counter | Total requests by method and status |
| `kmb_requests_in_flight` | Gauge | Currently processing requests |

**Tenant Metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `kmb_active_tenants` | Gauge | Number of active tenants |
| `kmb_tenant_log_entries_total` | Counter | Entries per tenant (labeled by tenant_id) |

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'kimberlite'
    static_configs:
      - targets:
        - 'kimberlite-node1:9090'
        - 'kimberlite-node2:9090'
        - 'kimberlite-node3:9090'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
```

### Example Queries

**Throughput:**

```promql
# Write throughput (ops/sec)
rate(kmb_log_entries_total[1m])

# Write bandwidth (MB/sec)
rate(kmb_log_bytes_total[1m]) / 1024 / 1024
```

**Latency:**

```promql
# P95 write latency
histogram_quantile(0.95, rate(kmb_write_duration_seconds_bucket[5m]))

# P99 query latency
histogram_quantile(0.99, rate(kmb_query_duration_seconds_bucket[5m]))
```

**Health:**

```promql
# Projection lag (should be near 0)
kmb_projection_lag

# View changes (spikes indicate instability)
rate(kmb_consensus_view_changes_total[5m])

# Leader stability (should be constant)
kmb_consensus_leader
```

## Structured Logging

Kimberlite emits structured JSON logs for machine parsing:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "target": "kmb_consensus",
  "message": "Became leader",
  "fields": {
    "node_id": 1,
    "view": 5,
    "commit_index": 12345
  }
}
```

### Log Levels

| Level | Usage | Typical Volume |
|-------|-------|----------------|
| `ERROR` | Errors requiring attention | <1/min |
| `WARN` | Unexpected but recoverable | <10/min |
| `INFO` | Normal operational events | 10-100/min |
| `DEBUG` | Detailed debug information | 100-1000/min |
| `TRACE` | Very verbose (development only) | >1000/min |

### Configuration

```bash
# Set log level via environment variable
export RUST_LOG=kimberlite=info

# Per-module logging
export RUST_LOG=kimberlite_vsr=debug,kimberlite_storage=info

# JSON output (default)
export RUST_LOG_FORMAT=json
```

### Log Aggregation

**With Promtail + Loki:**

```yaml
# promtail-config.yml
clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: kimberlite
    static_configs:
      - targets:
          - localhost
        labels:
          job: kimberlite
          __path__: /var/log/kimberlite/*.log
```

**With Fluent Bit:**

```ini
[INPUT]
    Name tail
    Path /var/log/kimberlite/*.log
    Parser json

[OUTPUT]
    Name es
    Host elasticsearch
    Port 9200
    Index kimberlite
```

## Distributed Tracing

Enable OpenTelemetry tracing for request-level observability:

```toml
# config.toml
[telemetry]
tracing_enabled = true
tracing_endpoint = "http://jaeger:14268/api/traces"
```

### Trace Spans

Kimberlite automatically creates spans for:
- `kmb.write` - Client write path (Prepare → Commit → Apply)
- `kmb.query` - Query execution
- `kmb.consensus.prepare` - Consensus prepare phase
- `kmb.consensus.commit` - Consensus commit phase
- `kmb.repair` - Log repair operations
- `kmb.view_change` - View change protocol

### Jaeger Configuration

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # UI
      - "14268:14268"  # HTTP collector
    environment:
      - COLLECTOR_OTLP_ENABLED=true
```

Access Jaeger UI at `http://localhost:16686`

## Health Checks

Kimberlite provides HTTP health check endpoints for load balancers:

### Liveness Check

```bash
curl http://localhost:9090/health/live
# 200 OK: Process is running
# 503 Service Unavailable: Process is shutting down
```

**Use for:** Kubernetes liveness probes, restart decisions

### Readiness Check

```bash
curl http://localhost:9090/health/ready
# 200 OK: Replica is ready to serve traffic
# 503 Service Unavailable: Replica is not ready (recovering, view change)
```

**Use for:** Kubernetes readiness probes, load balancer targets

### Status Endpoint

```bash
curl http://localhost:9090/status
```

```json
{
  "node_id": 1,
  "status": "normal",
  "view": 5,
  "commit_number": 12345,
  "op_number": 12400,
  "is_leader": true,
  "cluster_size": 3,
  "healthy_replicas": 3
}
```

## Alerting

### Recommended Alerts

**Critical Alerts** (page immediately):

```yaml
# Cluster lost quorum
- alert: ClusterNoQuorum
  expr: sum(kmb_consensus_leader) == 0
  for: 30s
  annotations:
    summary: "Cluster has no leader"

# High error rate
- alert: HighErrorRate
  expr: rate(kmb_requests_total{status="error"}[5m]) > 10
  for: 5m
  annotations:
    summary: "Error rate > 10/sec"

# Projection lag growing
- alert: ProjectionLagHigh
  expr: kmb_projection_lag > 1000
  for: 5m
  annotations:
    summary: "Projection lagging by >1000 entries"
```

**Warning Alerts** (investigate):

```yaml
# Frequent view changes
- alert: FrequentViewChanges
  expr: rate(kmb_consensus_view_changes_total[15m]) > 0.1
  for: 15m
  annotations:
    summary: "View changes > 1 per 10 minutes"

# High write latency
- alert: HighWriteLatency
  expr: histogram_quantile(0.99, rate(kmb_write_duration_seconds_bucket[5m])) > 0.1
  for: 10m
  annotations:
    summary: "P99 write latency > 100ms"
```

## Dashboards

### Grafana Dashboard

Import the official Kimberlite dashboard:

```bash
curl -o kimberlite-dashboard.json \
  https://grafana.com/api/dashboards/XXXXX/revisions/1/download
```

**Key Panels:**
- Write throughput (ops/sec)
- P50/P95/P99 latency
- Active tenants
- Projection lag
- View change history
- Error rates

### CLI Dashboard

Use the `vopr dashboard` command for live metrics during testing:

```bash
# Web dashboard
vopr dashboard --port 8080

# Terminal dashboard
vopr tui
```

## Performance Profiling

### CPU Profiling

```bash
# Install pprof
cargo install pprof

# Profile for 30 seconds
pprof --seconds 30 http://localhost:9090/debug/pprof/profile

# Generate flamegraph
pprof -flame http://localhost:9090/debug/pprof/profile
```

### Memory Profiling

```bash
# Heap snapshot
curl http://localhost:9090/debug/pprof/heap > heap.prof
pprof -svg heap.prof
```

## Compliance Auditing

For HIPAA/SOC 2 compliance, enable audit log export:

```bash
# Export audit log for date range
kimberlite-admin audit export \
  --start 2024-01-01 \
  --end 2024-12-31 \
  --format json \
  --output audit-2024.json
```

See [Audit Trails](/docs/coding/recipes/audit-trails) for audit log queries.

## Monitoring Best Practices

### 1. Set Up Alerts

```yaml
# Alert on fundamentals, not symptoms
- alert: HighErrorRate     # ✅ Good
- alert: CPUHigh           # ❌ Bad (symptom, not root cause)
```

### 2. Monitor Projection Lag

```promql
# Should stay near 0 in steady state
kmb_projection_lag < 100
```

### 3. Track View Change Rate

```promql
# Frequent view changes indicate network issues or crashes
rate(kmb_consensus_view_changes_total[1h]) < 0.01
```

### 4. Watch Write Latency

```promql
# P99 latency should stay under SLA
histogram_quantile(0.99, rate(kmb_write_duration_seconds_bucket[5m])) < 0.1
```

### 5. Log Everything

```bash
# Ship logs to centralized aggregation
export RUST_LOG=kimberlite=info
```

## Troubleshooting Metrics

| Symptom | Metric to Check | Likely Cause |
|---------|-----------------|--------------|
| Slow writes | `kmb_write_duration_seconds` P99 | Disk I/O, network latency |
| Frequent view changes | `kmb_consensus_view_changes_total` | Network partition, node crashes |
| Growing projection lag | `kmb_projection_lag` | CPU bottleneck, slow queries |
| No leader | `kmb_consensus_leader == 0` | Cluster lost quorum |

See [Troubleshooting Guide](troubleshooting.md) for detailed debugging.

## Related Documentation

- **[Configuration Guide](configuration.md)** - Configure telemetry endpoints
- **[Deployment Guide](deployment.md)** - Deploy monitoring stack
- **[Troubleshooting Guide](troubleshooting.md)** - Debug production issues
- **[Instrumentation Design](/docs/internals/design/instrumentation)** - Technical details

---

**Key Takeaway:** Monitor write latency, projection lag, and view change rate. Alert on loss of quorum and high error rates. Export logs for compliance auditing.
