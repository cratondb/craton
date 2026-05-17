---
title: "Production Deployment Guide"
section: "operating"
slug: "production-deployment"
order: 2
---

# Production Deployment Guide

**Target Audience:** DevOps Engineers, SREs, Platform Teams
**Use Case:** Production deployment for healthcare SaaS (EHR/EMR, payer/RCM, clinical research, digital health)
**Compliance Focus:** HIPAA (Privacy + Security + Breach Notification), with GDPR / SOC 2 / ISO 27001 overlays

---

## Table of Contents

- [Overview](#overview)
- [Hardware Requirements](#hardware-requirements)
- [Cluster Sizing](#cluster-sizing)
- [Configuration Checklist](#configuration-checklist)
- [Deployment Architecture](#deployment-architecture)
- [Monitoring Setup](#monitoring-setup)
- [Backup and Disaster Recovery](#backup-and-disaster-recovery)
- [Security Hardening](#security-hardening)
- [Compliance Validation](#compliance-validation)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)

---

## Overview

**Kimberlite** is a verifiable database for healthcare, with a multi-layer verification stack. This guide covers production-grade deployment with emphasis on:

1. **Verification:** ~91 Kani proofs (PR-gated), ~25 TLA+ core theorems (TLC PR-gated; TLAPS nightly), Coq crypto proofs, 74 VOPR scenario variants (~50 substantive)
2. **Compliance substrate:** HIPAA-aligned (audit trail, encryption, access control, retention), SOC 2-aligned (monitoring, change management, logical access), GDPR-aligned (Art. 17 erasure, Art. 20 portability, Art. 6/7 consent), PCI DSS-aligned (encryption, key management). **Kimberlite ships the primitives that enable these compliance regimes; no third-party audits or attestations have been completed as of v0.8** — SOC 2 Type II, HIPAA attestation, and FedRAMP authorization are ROADMAP.md v1.0 gates.
3. **Zero-downtime operations:** Rolling upgrades, cluster reconfiguration, standby replicas
4. **Operational maturity:** Monitoring, backup/DR, incident response

> ⚠️ **v0.8.0 is Developer Preview.** Single-node deployments are stable; multi-node VSR is implemented and PR-gated against TLA+ specs but the cluster crate is marked "not ready for public use" — see [ROADMAP.md](../../ROADMAP.md) for the v1.0 production-readiness gates. Phase 6 compliance endpoints (breach notification, audit query, subject export, masking policy CRUD, `audit.verifyChain` server-walked) are end-to-end on Rust + TypeScript; Python parity for `audit.verifyChain` / `audit.subscribe` lands in v0.9.0. See the [SDK parity matrix](../reference/sdk/parity.md) for the per-SDK status.

### Key Design Principles

- **Correctness over performance:** Multi-layer verification (specs + bounded proofs + simulation) tightens the bug surface
- **Immutable audit logs:** Hash-chained, tamper-evident
- **Multi-tenant isolation:** Cryptographic separation (AES-256-GCM per tenant)
- **Geographic redundancy:** Standby replicas for DR without quorum overhead

---

## Hardware Requirements

### Minimum Production Specifications

**Active Replicas (3-5 nodes):**

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| **CPU** | 8 cores | 16 cores | Intel Xeon/AMD EPYC, AVX2 for crypto |
| **RAM** | 32 GB | 64 GB | Kernel state, log cache, crypto buffers |
| **Disk** | 500 GB NVMe SSD | 1 TB NVMe SSD | Sustained 50K IOPS, <1ms latency |
| **Network** | 10 Gbps | 25 Gbps | Low latency <1ms RTT between replicas |
| **Redundancy** | RAID 1 | RAID 10 | Disk failure tolerance |

**Standby Replicas (DR/Read Scaling):**

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| **CPU** | 4 cores | 8 cores | Read-only workload |
| **RAM** | 16 GB | 32 GB | Reduced requirements (no quorum) |
| **Disk** | 500 GB NVMe SSD | 1 TB NVMe SSD | Same as active replicas |
| **Network** | 1 Gbps | 10 Gbps | Geographic DR tolerates higher latency |

### Capacity Planning

**Log Growth Estimation:**

```
Daily Log Size = Avg Event Size × Events/Second × 86400 seconds

Example (Healthcare Application):
- Avg Event Size: 2 KB (patient record update)
- Events/Second: 500 writes/sec
- Daily Growth: 2 KB × 500 × 86400 = 86 GB/day
- Monthly Growth: 86 GB × 30 = 2.6 TB/month
- Annual Growth: 2.6 TB × 12 = 31 TB/year

Recommendation: Provision 50 TB per replica (18 months retention)
```

**RAM Requirements:**

```
Kernel State = Stream Count × Avg Stream State Size
             + Crypto Buffers (2 GB)
             + Log Cache (10% of disk)

Example:
- 100K active streams
- 128 bytes per stream state
- Log cache: 100 GB (10% of 1 TB disk)

Total RAM: (100K × 128 bytes) + 2 GB + 100 GB = 115 GB
Recommendation: 128 GB RAM with overhead
```

### Storage Selection

**Recommended NVMe SSDs:**

| Vendor | Model | IOPS | Latency | Endurance |
|--------|-------|------|---------|-----------|
| Samsung | PM9A3 | 1M IOPS | 100μs | 1 DWPD |
| Intel | P5800X (Optane) | 1.5M IOPS | 10μs | 100 DWPD |
| Micron | 7450 Pro | 1.4M IOPS | 80μs | 3 DWPD |

**CRITICAL:** Do NOT use QLC NAND (poor write endurance). Use TLC or better.

---

## Cluster Sizing

### 3-Replica vs 5-Replica Clusters

| Aspect | 3-Replica | 5-Replica |
|--------|-----------|-----------|
| **Quorum Size** | 2 nodes | 3 nodes |
| **Fault Tolerance** | 1 node failure | 2 node failures |
| **Latency** | Lower (smaller quorum) | Higher (+15-20%) |
| **Throughput** | Higher | Lower (more coordination) |
| **Compliance** | HIPAA/GDPR sufficient | FedRAMP/High Security |
| **Cost** | Lower (3 nodes) | Higher (5 nodes) |
| **When to Use** | Standard production | Mission-critical, regulatory |

**Recommendation:** Start with 3-replica, upgrade to 5-replica if:
- Regulatory requirement (FedRAMP, DoD)
- Mission-critical (financial trading, emergency services)
- Multi-region deployment (2 failures tolerated)

### Geographic Distribution

**Single-Region (3 Availability Zones):**

```text
Region: US-East-1
┌─────────────────────────────────────────────────────────────┐
│  AZ-1           AZ-2           AZ-3                          │
│  ┌───────┐      ┌───────┐      ┌───────┐                    │
│  │  R0   │      │  R1   │      │  R2   │                    │
│  │Primary│◄────►│Backup │◄────►│Backup │                    │
│  └───────┘      └───────┘      └───────┘                    │
│                                                               │
│  Latency: <1ms intra-AZ, 1-2ms cross-AZ                     │
└─────────────────────────────────────────────────────────────┘
```

**Multi-Region (Active + Standby DR):**

```text
Primary Region: US-East-1           DR Region: US-West-2
┌──────────────────────────┐        ┌──────────────────────────┐
│  Active Cluster (3x)     │        │  Standby Replicas (2x)   │
│  ┌───────┐ ┌───────┐    │        │  ┌───────┐ ┌───────┐    │
│  │  R0   │ │  R1   │    │  Async │  │  S0   │ │  S1   │    │
│  │Primary│ │Backup │    │────────►  │  DR   │ │  DR   │    │
│  └───────┘ └───────┘    │        │  └───────┘ └───────┘    │
│  Quorum: 2/3             │        │  NOT in quorum           │
└──────────────────────────┘        └──────────────────────────┘

Latency: 50-100ms cross-region
Failover: Promote standby to active (manual or automatic)
RPO: <1 second (standby lag)
RTO: <60 seconds (promotion time)
```

---

## Configuration Checklist

### Pre-Deployment Validation

- [ ] **Hardware verified:** NVMe SSDs, 10+ Gbps network, 64+ GB RAM
- [ ] **OS hardened:** SELinux/AppArmor enabled, firewall configured
- [ ] **Time sync configured:** NTP/Chrony with <10ms offset
- [ ] **DNS resolution:** All replica hostnames resolvable
- [ ] **TLS certificates:** Valid certs for all replicas (Let's Encrypt or internal CA)
- [ ] **Monitoring agents:** Prometheus exporters installed
- [ ] **Backup storage:** S3/GCS bucket configured for snapshots
- [ ] **Compliance reviewed:** HIPAA/GDPR checklist completed

### Configuration File (`kimberlite.toml`)

```toml
# kimberlite.toml - Production Configuration

[cluster]
# Active replicas (participate in quorum)
replicas = [
    { id = 0, address = "replica-0.kimberlite.prod:7000" },
    { id = 1, address = "replica-1.kimberlite.prod:7000" },
    { id = 2, address = "replica-2.kimberlite.prod:7000" },
]

# Cluster-wide settings
heartbeat_interval_ms = 100
election_timeout_ms = 1000
max_batch_size = 1000
log_compaction_interval_hours = 24

[storage]
# Log storage path
data_dir = "/var/lib/kimberlite/data"
wal_dir = "/var/lib/kimberlite/wal"  # Separate disk for WAL (optional)
max_log_size_gb = 1000
sync_on_write = true  # fsync after every write (compliance requirement)

[crypto]
# Master encryption key (load from HSM or KMS in production)
master_key_source = "aws-kms"  # or "vault", "pkcs11"
master_key_id = "arn:aws:kms:us-east-1:123456789:key/abcd-1234"

# Encryption settings
algorithm = "AES-256-GCM"
key_rotation_days = 90
enforce_encryption_at_rest = true

[compliance]
# Data classification levels
data_classification = ["PHI", "PII", "Confidential", "Public"]

# Audit settings
audit_log_enabled = true
audit_log_path = "/var/lib/kimberlite/audit.log"
audit_log_immutable = true  # Tamper-evident hash chain

# Retention policies (regulatory requirements)
min_retention_days = 2555  # 7 years (HIPAA)
max_retention_days = 3650  # 10 years

[standby]
# Standby replicas for DR and read scaling (optional)
replicas = [
    { id = 100, address = "standby-0.kimberlite.dr:7000" },
    { id = 101, address = "standby-1.kimberlite.dr:7000" },
]

# Auto-promotion settings
auto_promote_on_failure = false  # Manual promotion for safety
max_lag_ms = 100  # Mark ineligible if lag exceeds threshold

[monitoring]
# Prometheus metrics endpoint
metrics_address = "0.0.0.0:9090"

# Health check endpoint
health_check_address = "0.0.0.0:8080"

# Logging
log_level = "info"
log_format = "json"  # Structured logging for SIEM integration
log_output = "/var/log/kimberlite/server.log"

[security]
# TLS configuration
tls_enabled = true
tls_cert_path = "/etc/kimberlite/certs/server.crt"
tls_key_path = "/etc/kimberlite/certs/server.key"
tls_ca_path = "/etc/kimberlite/certs/ca.crt"
tls_client_auth = "require"  # Mutual TLS

# Network security
bind_address = "0.0.0.0:7000"  # Cluster replication
client_address = "0.0.0.0:7001"  # Client connections

# Rate limiting
max_connections = 10000
max_requests_per_second = 50000
```

### Environment Variables

```bash
# Production environment variables
export KIMBERLITE_ENV=production
export KIMBERLITE_CONFIG=/etc/kimberlite/kimberlite.toml
export KIMBERLITE_DATA_DIR=/var/lib/kimberlite/data
export KIMBERLITE_LOG_LEVEL=info

# AWS KMS (for master key)
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Monitoring
export PROMETHEUS_PUSHGATEWAY=http://pushgateway.monitoring.svc:9091
```

---

## Deployment Architecture

### Kubernetes Deployment (Recommended)

**StatefulSet for Active Replicas:**

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kimberlite
  namespace: production
spec:
  serviceName: kimberlite
  replicas: 3
  selector:
    matchLabels:
      app: kimberlite
      role: active
  template:
    metadata:
      labels:
        app: kimberlite
        role: active
    spec:
      # Anti-affinity: Spread replicas across nodes/AZs
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - kimberlite
              topologyKey: topology.kubernetes.io/zone

      containers:
        - name: kimberlite
          image: kimberlite/server:v0.8.0
          ports:
            - containerPort: 7000  # Cluster replication
              name: cluster
            - containerPort: 7001  # Client connections
              name: client
            - containerPort: 9090  # Prometheus metrics
              name: metrics
          env:
            - name: KIMBERLITE_REPLICA_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: KIMBERLITE_CONFIG
              value: /etc/kimberlite/kimberlite.toml
          volumeMounts:
            - name: data
              mountPath: /var/lib/kimberlite/data
            - name: config
              mountPath: /etc/kimberlite
          resources:
            requests:
              memory: "64Gi"
              cpu: "16"
            limits:
              memory: "64Gi"
              cpu: "16"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5

  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: fast-nvme
        resources:
          requests:
            storage: 1Ti
```

**Service for Client Connections:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kimberlite-client
  namespace: production
spec:
  selector:
    app: kimberlite
    role: active
  ports:
    - port: 7001
      targetPort: client
      name: client
  type: LoadBalancer
  sessionAffinity: ClientIP  # Sticky sessions
```

### Docker Compose (Development/Testing)

```yaml
version: '3.9'

services:
  replica-0:
    image: kimberlite/server:v0.8.0
    container_name: kimberlite-replica-0
    environment:
      - KIMBERLITE_REPLICA_ID=0
      - KIMBERLITE_CONFIG=/etc/kimberlite/kimberlite.toml
    volumes:
      - ./data/replica-0:/var/lib/kimberlite/data
      - ./config:/etc/kimberlite
    ports:
      - "7000:7000"  # Cluster
      - "7001:7001"  # Client
      - "9090:9090"  # Metrics
    networks:
      - kimberlite

  replica-1:
    image: kimberlite/server:v0.8.0
    container_name: kimberlite-replica-1
    environment:
      - KIMBERLITE_REPLICA_ID=1
      - KIMBERLITE_CONFIG=/etc/kimberlite/kimberlite.toml
    volumes:
      - ./data/replica-1:/var/lib/kimberlite/data
      - ./config:/etc/kimberlite
    ports:
      - "7010:7000"
      - "7011:7001"
      - "9091:9090"
    networks:
      - kimberlite

  replica-2:
    image: kimberlite/server:v0.8.0
    container_name: kimberlite-replica-2
    environment:
      - KIMBERLITE_REPLICA_ID=2
      - KIMBERLITE_CONFIG=/etc/kimberlite/kimberlite.toml
    volumes:
      - ./data/replica-2:/var/lib/kimberlite/data
      - ./config:/etc/kimberlite
    ports:
      - "7020:7000"
      - "7021:7001"
      - "9092:9090"
    networks:
      - kimberlite

networks:
  kimberlite:
    driver: bridge
```

---

## Monitoring Setup

### Prometheus Metrics

**Key Metrics to Monitor:**

```
# Cluster Health
kimberlite_cluster_replicas_total{status="healthy"}  # Expect: 3 (or 5)
kimberlite_cluster_leader_id                          # Current primary

# Consensus Performance
kimberlite_consensus_commits_total                    # Throughput
kimberlite_consensus_commit_latency_seconds{quantile="0.99"}  # p99 latency
kimberlite_consensus_view_changes_total               # View change frequency

# Replication Lag
kimberlite_replication_lag_ops{replica_id="1"}       # Operations behind leader
kimberlite_replication_lag_ms{replica_id="1"}        # Time behind leader

# Storage
kimberlite_storage_log_size_bytes                     # Log file size
kimberlite_storage_disk_usage_percent                 # Disk utilization
kimberlite_storage_fsync_latency_seconds{quantile="0.99"}  # Disk performance

# Standby Replicas (if deployed)
kimberlite_standby_lag_ms{replica_id="100"}          # Standby replication lag
kimberlite_standby_promotion_eligible{replica_id="100"}  # 1 = eligible

# Formal Verification (Runtime Assertions)
kimberlite_assertion_failures_total                   # Expect: 0 always
kimberlite_kani_proof_coverage_percent                # Expect: 100%

# Compliance
kimberlite_audit_log_entries_total                    # Audit trail completeness
kimberlite_encryption_operations_total{operation="encrypt"}
kimberlite_hash_chain_verifications_total{result="success"}
```

**Prometheus Configuration:**

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'kimberlite'
    static_configs:
      - targets:
          - 'replica-0:9090'
          - 'replica-1:9090'
          - 'replica-2:9090'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

# Alerting rules
rule_files:
  - /etc/prometheus/alerts/kimberlite.yml
```

### Grafana Dashboards

**Dashboard 1: Cluster Overview**
- Cluster health (replicas up/down)
- Leader election history
- Commit throughput and latency
- Replication lag per replica

**Dashboard 2: Storage and Performance**
- Disk IOPS and throughput
- fsync latency (p50, p99, p999)
- Log file growth rate
- Compaction status

**Dashboard 3: Compliance and Audit**
- Audit log entries per hour
- Encryption operations rate
- Hash chain verification status
- Data classification distribution

**Dashboard 4: Formal Verification**
- Kani proof coverage
- Runtime assertion failures (CRITICAL: must be 0)
- VOPR scenario pass rate (from nightly runs)

---

## Backup and Disaster Recovery

### Backup Strategy

**1. Continuous Replication (Primary):**
- Active replicas maintain 3 copies (quorum = 2/3)
- Standby replicas in DR region (geographic redundancy)
- RPO: <1 second (standby lag)

**2. Snapshot Backups (Secondary):**

```bash
# Daily snapshots to S3
#!/bin/bash
set -euo pipefail

REPLICA_ID=0
BACKUP_DIR="/var/lib/kimberlite/backup"
S3_BUCKET="s3://kimberlite-backups-prod"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# 1. Quiesce writes (optional, reduces snapshot inconsistency)
kimberlite-cli replica pause --replica-id $REPLICA_ID

# 2. Create snapshot
tar -czf "$BACKUP_DIR/snapshot-$TIMESTAMP.tar.gz" \
    /var/lib/kimberlite/data

# 3. Resume writes
kimberlite-cli replica resume --replica-id $REPLICA_ID

# 4. Upload to S3 with encryption
aws s3 cp "$BACKUP_DIR/snapshot-$TIMESTAMP.tar.gz" \
    "$S3_BUCKET/snapshots/" \
    --server-side-encryption AES256

# 5. Verify backup integrity
aws s3api head-object \
    --bucket kimberlite-backups-prod \
    --key "snapshots/snapshot-$TIMESTAMP.tar.gz" \
    --checksum-mode ENABLED

# 6. Cleanup old local snapshots (keep last 7 days)
find "$BACKUP_DIR" -name "snapshot-*.tar.gz" -mtime +7 -delete

echo "Backup completed: snapshot-$TIMESTAMP.tar.gz"
```

**Backup Schedule:**
- **Hourly:** Incremental backups (last 24 hours retained locally)
- **Daily:** Full snapshots to S3 (30 days retained)
- **Weekly:** Long-term retention (7 years for HIPAA compliance)

### Disaster Recovery Procedures

**Scenario 1: Single Replica Failure**

```bash
# Automatic recovery (no action needed)
# - Cluster continues with 2/3 quorum
# - Monitor: kimberlite_cluster_replicas_total

# If replica doesn't auto-recover:
# 1. Check replica health
kimberlite-cli replica status --replica-id 2

# 2. Restart replica (Kubernetes auto-restarts)
kubectl delete pod kimberlite-2 -n production

# 3. Verify replica rejoins cluster
kimberlite-cli cluster status
```

**Scenario 2: Entire Region Failure (Multi-Region Setup)**

```bash
# CRITICAL: Requires human approval (risk of data loss if standby lagged)

# 1. Verify primary region is DOWN
ping replica-0.us-east-1.prod  # No response

# 2. Check standby replica status in DR region
kimberlite-cli standby status --replica-id 100
# Expected: promotion_eligible=true, lag_ms < 100

# 3. Promote standby to active (manual approval required)
kimberlite-cli cluster reconfig promote-standby \
    --replica-id 100 \
    --new-primary \
    --approve-data-loss-risk

# 4. Verify new cluster operational
kimberlite-cli cluster status
# Expected: leader_id=100, replicas=[100,101], status=healthy

# 5. Update DNS to point to DR region
aws route53 change-resource-record-sets \
    --hosted-zone-id Z1234567890ABC \
    --change-batch file://failover-to-dr.json

# 6. Monitor for stability
# RTO: <60 seconds (promotion + DNS propagation)
# RPO: <1 second (standby lag at time of failure)
```

**Scenario 3: Data Corruption Detection**

```bash
# Runtime assertion failure detected (CRITICAL ALERT)

# 1. Immediately isolate affected replica
kimberlite-cli replica isolate --replica-id 1 --reason "corruption-detected"

# 2. Run storage verification
kimberlite-cli storage verify --replica-id 1 --full-scan

# 3. If corruption confirmed, restore from backup
kimberlite-cli storage restore \
    --replica-id 1 \
    --backup-source "s3://kimberlite-backups-prod/snapshots/snapshot-20260206-120000.tar.gz" \
    --verify-hash-chain

# 4. Rejoin cluster after verification
kimberlite-cli replica rejoin --replica-id 1

# 5. Post-incident analysis
# - Check disk SMART status
# - Review scrubbing logs
# - Update RCA document
```

---

## Security Hardening

### TLS Configuration

**Mutual TLS (mTLS) for Cluster Communication:**

```bash
# Generate CA certificate
openssl req -x509 -newkey rsa:4096 -days 3650 \
    -keyout ca-key.pem -out ca-cert.pem \
    -subj "/CN=Kimberlite CA" -nodes

# Generate replica certificates
for i in 0 1 2; do
    openssl req -newkey rsa:4096 -nodes \
        -keyout replica-$i-key.pem \
        -out replica-$i-csr.pem \
        -subj "/CN=replica-$i.kimberlite.prod"

    openssl x509 -req -in replica-$i-csr.pem \
        -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -days 365 \
        -out replica-$i-cert.pem
done
```

### Firewall Rules

```bash
# iptables configuration (run on each replica)

# Allow cluster communication (port 7000)
iptables -A INPUT -p tcp --dport 7000 -s 10.0.1.0/24 -j ACCEPT

# Allow client connections (port 7001) from application subnet only
iptables -A INPUT -p tcp --dport 7001 -s 10.0.2.0/24 -j ACCEPT

# Allow monitoring (port 9090) from Prometheus only
iptables -A INPUT -p tcp --dport 9090 -s 10.0.3.10 -j ACCEPT

# Drop all other inbound traffic
iptables -A INPUT -j DROP
```

### Secrets Management

**AWS Secrets Manager Integration:**

```bash
# Store master encryption key in AWS Secrets Manager
aws secretsmanager create-secret \
    --name kimberlite/prod/master-key \
    --secret-string "$(openssl rand -base64 32)" \
    --kms-key-id alias/aws/secretsmanager \
    --region us-east-1

# Fetch at runtime (in kimberlite startup script)
export KIMBERLITE_MASTER_KEY=$(aws secretsmanager get-secret-value \
    --secret-id kimberlite/prod/master-key \
    --region us-east-1 \
    --query SecretString \
    --output text)
```

---

## Compliance Validation

### Pre-Production Compliance Checklist

**HIPAA §164.312 (Technical Safeguards):**
- [x] §312(a)(1): Access control (JWT auth + RBAC)
- [x] §312(a)(2)(iv): Encryption at rest (AES-256-GCM)
- [x] §312(b): Audit controls (immutable hash-chained logs)
- [x] §312(c)(1): Integrity controls (CRC32 checksums + hash chains)
- [x] §312(d): Transmission security (TLS 1.3)

**GDPR Articles:**
- [x] Article 25: Data protection by design (multi-tenant isolation)
- [x] Article 30: Records of processing activities (audit logs)
- [x] Article 32: Security of processing (encryption + formal verification)
- [x] Article 33: Breach notification (monitoring + alerting)

**SOC 2 Trust Services Criteria:**
- [x] CC6.1: Logical access controls (RBAC)
- [x] CC6.6: Encryption (AES-256-GCM, TLS 1.3)
- [x] CC7.1: System monitoring (Prometheus + Grafana)
- [x] CC7.2: Change management (rolling upgrades, version control)

### Generating Compliance Reports

```bash
# Generate compliance report for HIPAA audit
kimberlite-cli compliance report \
    --framework HIPAA \
    --start-date 2025-01-01 \
    --end-date 2025-12-31 \
    --output /var/lib/kimberlite/reports/hipaa-2025.pdf

# Verify proof certificates (formal verification traceability)
kimberlite-cli compliance verify-certificates \
    --spec-dir /opt/kimberlite/specs \
    --output /var/lib/kimberlite/reports/certificates-verification.json

# Export audit logs for external SIEM
kimberlite-cli audit export \
    --start-date 2025-12-01 \
    --end-date 2025-12-31 \
    --format json \
    --output /var/lib/kimberlite/exports/audit-december-2025.json
```

---

## Performance Tuning

### Kernel Parameters (Linux)

```bash
# /etc/sysctl.d/99-kimberlite.conf

# Network tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_slow_start_after_idle = 0

# Disk I/O
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.swappiness = 10

# File descriptors
fs.file-max = 2097152
```

### NVMe Tuning

```bash
# Optimal I/O scheduler for NVMe
echo none > /sys/block/nvme0n1/queue/scheduler

# Increase queue depth
echo 1024 > /sys/block/nvme0n1/queue/nr_requests
```

---

## Troubleshooting

See: [Operational Runbook](runbook.md) for detailed troubleshooting procedures.

**Common Issues:**

1. **High Replication Lag:** Check network latency, disk IOPS
2. **View Change Storms:** Verify clock sync (<10ms offset)
3. **Assertion Failures:** CRITICAL - isolate replica, restore from backup
4. **Disk Full:** Trigger log compaction, expand storage

---

## References

- **Configuration Reference:** [Configuration Guide](configuration.md)
- **Monitoring Guide:** [Monitoring and Alerting](monitoring.md)
- **Security Guide:** [Security Best Practices](security.md)
- **Runbook:** [Operational Runbook](runbook.md)
- **Compliance:** [Compliance Certification Package](../compliance/certification-package.md)
- **Formal Verification:** [Traceability Matrix](../traceability_matrix.md)

---

**Last Updated:** 2026-02-06
**Version:** 0.4.0
**Validated For:** HIPAA, GDPR, SOC 2, PCI DSS production deployments
