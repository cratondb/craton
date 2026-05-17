---
title: "Configuration"
section: "operating"
slug: "configuration"
order: 3
---

# Configuration

Configure Kimberlite for your deployment environment.

## Configuration File

Kimberlite uses TOML for configuration:

```toml
# /etc/kimberlite/config.toml

[server]
# Network binding
bind_address = "0.0.0.0:7000"
cluster_address = "0.0.0.0:7001"

# Node identity
node_id = 1
cluster_name = "production"

[storage]
# Data directory (absolute path required)
data_dir = "/var/lib/kimberlite"

# Segment size (default 64MB)
segment_size = "64MB"

# Sync mode: "fsync" (durable) or "async" (faster, less safe)
sync_mode = "fsync"

[consensus]
# Heartbeat interval
heartbeat_interval = "100ms"

# Election timeout (min, max)
election_timeout_min = "150ms"
election_timeout_max = "300ms"

# Maximum entries per AppendEntries RPC
max_entries_per_rpc = 100

[projections]
# Maximum memory for projection cache
cache_size = "1GB"

# Checkpoint interval (by log entries)
checkpoint_interval = 10000

[security]
# TLS configuration
tls_cert = "/etc/kimberlite/server.crt"
tls_key = "/etc/kimberlite/server.key"
tls_ca = "/etc/kimberlite/ca.crt"

# Require client certificates (mutual TLS)
require_client_cert = true

[encryption]
# Enable at-rest encryption
enabled = true

# KMS provider: "local" or "aws-kms" or "gcp-kms" or "azure-keyvault"
kms_provider = "aws-kms"
kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc123"

[limits]
# Per-tenant limits
max_tenants = 1000
max_streams_per_tenant = 100
max_record_size = "1MB"
max_batch_size = "10MB"

[rate_limiting]
# Tag-based per-tenant rate limiting (FoundationDB pattern)
# Tenants are assigned priority tiers that control QoS
enabled = true

# Rate limits per priority tier (requests per second)
system_rps = 0          # 0 = unlimited (system tenants bypass limits)
default_rps = 1000      # Standard tenant rate
batch_rps = 100         # Throttled first under load

# Assign tenants to priority tiers
# [rate_limiting.tenant_priorities]
# 1 = "system"          # Internal monitoring tenant
# 42 = "batch"          # Background analytics tenant

[retention]
# Stream retention policy enforcement
# Applies compliance-framework-based retention periods automatically
enabled = true

# Override default retention periods (days)
# phi_min_retention = 2190             # 6 years (HIPAA Privacy Rule §164.530(j)(2))
# pediatric_min_retention_years = 25   # Until age of majority + 7 years (worst-case state)
# audit_min_retention = 2190           # 6 years (HIPAA audit log retention)
# pci_min_retention = 365              # 1 year (PCI DSS, for billing card-on-file)

# Scan interval for expired streams
scan_interval = "1h"

[telemetry]
# Metrics endpoint
metrics_address = "0.0.0.0:9090"

# Tracing
tracing_enabled = true
tracing_endpoint = "http://jaeger:14268/api/traces"
```

## Configuration Sections

### Server

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | String | `127.0.0.1:7000` | Address for client connections |
| `cluster_address` | String | `127.0.0.1:7001` | Address for cluster communication |
| `node_id` | Integer | Required | Unique node identifier (1-255) |
| `cluster_name` | String | `default` | Cluster name for isolation |

### Storage

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `data_dir` | Path | Required | Directory for data files |
| `segment_size` | Size | `64MB` | Log segment size |
| `sync_mode` | Enum | `fsync` | Durability mode: `fsync`, `async` |

**Sync Modes:**
- `fsync` - Guaranteed durability, slower (~1ms per write)
- `async` - OS manages flush, faster but may lose data on crash

### Consensus

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `heartbeat_interval` | Duration | `100ms` | Leader heartbeat frequency |
| `election_timeout_min` | Duration | `150ms` | Minimum election timeout |
| `election_timeout_max` | Duration | `300ms` | Maximum election timeout |
| `max_entries_per_rpc` | Integer | `100` | Batch size for replication |

**Tuning:**
- Lower heartbeat → faster failure detection, higher network overhead
- Higher election timeout → fewer unnecessary elections, slower recovery
- Larger batch size → higher throughput, increased latency

### Projections

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cache_size` | Size | `1GB` | Projection cache memory limit |
| `checkpoint_interval` | Integer | `10000` | Entries between checkpoints |

### Security

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tls_cert` | Path | None | Server TLS certificate |
| `tls_key` | Path | None | Server TLS private key |
| `tls_ca` | Path | None | CA certificate for client validation |
| `require_client_cert` | Boolean | `false` | Require mutual TLS |

See [Security Guide](security.md) for TLS setup.

### Encryption

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | Boolean | `true` | Enable at-rest encryption |
| `kms_provider` | Enum | `local` | Key management: `local`, `aws-kms`, `gcp-kms`, `azure-keyvault` |
| `kms_key_id` | String | None | KMS key identifier |

**KMS Providers:**
- `local` - Encrypt with local key (development only)
- `aws-kms` - AWS Key Management Service
- `gcp-kms` - Google Cloud Key Management
- `azure-keyvault` - Azure Key Vault

### Limits

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_tenants` | Integer | `1000` | Maximum tenants per node |
| `max_streams_per_tenant` | Integer | `100` | Maximum streams per tenant |
| `max_record_size` | Size | `1MB` | Maximum single record size |
| `max_batch_size` | Size | `10MB` | Maximum batch write size |

### Rate Limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | Boolean | `true` | Enable tag-based rate limiting |
| `system_rps` | Integer | `0` | System-priority rate limit (0 = unlimited) |
| `default_rps` | Integer | `1000` | Default-priority rate limit |
| `batch_rps` | Integer | `100` | Batch-priority rate limit |

**Priority Tiers (FoundationDB pattern):**
- `system` — Never rate limited (monitoring, internal services)
- `default` — Standard rate limits (most tenants)
- `batch` — Throttled first under load (background analytics, ETL)

Assign tenants to tiers via the `tenant_priorities` map in the rate limiting config section.

### Retention

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | Boolean | `true` | Enable retention policy enforcement |
| `scan_interval` | Duration | `1h` | How often to scan for expired streams |
| `phi_min_retention` | Integer | `2190` | PHI minimum retention in days (6 years, HIPAA §164.530(j)(2)) |
| `pediatric_min_retention_years` | Integer | `25` | Pediatric records retention to age of majority + 7 years (worst-case state) |
| `audit_min_retention` | Integer | `2190` | Audit-log minimum retention in days (6 years, HIPAA audit-log policy) |
| `pci_min_retention` | Integer | `365` | PCI minimum retention in days (1 year, PCI DSS — for billing card-on-file) |

**Legal Holds:** Streams under a legal hold (subpoena, malpractice litigation, OCR investigation) are exempt from automatic deletion regardless of retention policy. Use the compliance API to manage legal holds.

### Telemetry

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `metrics_address` | String | `127.0.0.1:9090` | Prometheus metrics endpoint |
| `tracing_enabled` | Boolean | `false` | Enable distributed tracing |
| `tracing_endpoint` | String | None | OpenTelemetry collector URL |

See [Monitoring Guide](monitoring.md) for observability setup.

## Environment Variables

Override configuration via environment variables:

```bash
# Server
export KMB_NODE_ID=1
export KMB_BIND_ADDRESS=0.0.0.0:7000
export KMB_CLUSTER_ADDRESS=0.0.0.0:7001

# Storage
export KMB_DATA_DIR=/var/lib/kimberlite
export KMB_SYNC_MODE=fsync

# Logging
export KMB_LOG_LEVEL=info
export RUST_LOG=kimberlite=debug
```

**Priority:** CLI flags > Environment variables > Config file

## CLI Flags

```bash
kimberlite-server --help

Usage: kimberlite-server [OPTIONS]

Options:
    --config <PATH>          Configuration file path
    --node-id <ID>           Node identifier (overrides config)
    --bind <ADDR>            Bind address (overrides config)
    --data-dir <PATH>        Data directory (overrides config)
    --cluster-peers <PEERS>  Comma-separated peer addresses
    --log-level <LEVEL>      Log level: trace, debug, info, warn, error
    -h, --help               Print help
    -V, --version            Print version
```

## Configuration Validation

Validate configuration before deployment:

```bash
# Check configuration syntax
kimberlite-server --config /etc/kimberlite/config.toml --validate

# Show effective configuration (after merging file + env + flags)
kimberlite-server --config /etc/kimberlite/config.toml --show-config
```

## Production Configuration Examples

### High-Throughput Workload

```toml
[storage]
segment_size = "128MB"      # Larger segments
sync_mode = "async"         # Higher throughput (acceptable for some workloads)

[consensus]
max_entries_per_rpc = 500   # Larger batches

[projections]
cache_size = "4GB"          # More cache
```

**Use when:** High write volume, can tolerate rare data loss on crash

### High-Durability Workload

```toml
[storage]
segment_size = "64MB"
sync_mode = "fsync"         # Guaranteed durability

[consensus]
heartbeat_interval = "50ms" # Faster failure detection
election_timeout_min = "100ms"
election_timeout_max = "200ms"

[limits]
max_record_size = "512KB"   # Smaller records for faster sync
```

**Use when:** PHI, audit logs, or any healthcare data requiring guaranteed durability under HIPAA / state breach laws

### Multi-Tenant SaaS

```toml
[limits]
max_tenants = 10000
max_streams_per_tenant = 1000
max_record_size = "1MB"

[projections]
cache_size = "8GB"          # Cache for many tenants

[security]
require_client_cert = true  # Enforce mutual TLS
```

**Use when:** Multi-tenant SaaS with strict isolation requirements

## Configuration Best Practices

### 1. Use Absolute Paths

```toml
# Good
data_dir = "/var/lib/kimberlite"

# Bad (relative paths can break)
data_dir = "./data"
```

### 2. Set Resource Limits

```toml
[limits]
max_tenants = 1000          # Prevent unbounded growth
max_record_size = "1MB"     # Prevent OOM from huge records
```

### 3. Enable TLS in Production

```toml
[security]
tls_cert = "/etc/kimberlite/server.crt"
tls_key = "/etc/kimberlite/server.key"
require_client_cert = true  # Mutual TLS
```

### 4. Use KMS for Encryption Keys

```toml
[encryption]
enabled = true
kms_provider = "aws-kms"    # Never use "local" in production
kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc123"
```

### 5. Enable Monitoring

```toml
[telemetry]
metrics_address = "0.0.0.0:9090"
tracing_enabled = true
tracing_endpoint = "http://jaeger:14268/api/traces"
```

## Related Documentation

- **[Deployment Guide](deployment.md)** - How to deploy Kimberlite
- **[Security Guide](security.md)** - TLS and authentication setup
- **[Monitoring Guide](monitoring.md)** - Observability configuration
- **[Performance Guide](performance.md)** - Performance tuning

---

**Key Takeaway:** Start with default configuration for development, tune for your workload in production. Always use `fsync` mode and KMS encryption for critical data.
