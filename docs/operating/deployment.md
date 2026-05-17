---
title: "Deployment Guide"
section: "operating"
slug: "deployment"
order: 1
---

# Deployment Guide

This guide covers deploying Kimberlite and the cloud platform in production environments.

> **Operating a 3-node cluster?** Procedures for failover, quorum loss, rolling upgrades, and backup/restore live in [`runbooks/cluster.md`](runbooks/cluster.md). Measured RTO/RPO and throughput baselines for the same topology are in [`performance/cluster.md`](performance/cluster.md).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Variables](#environment-variables)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [NATS Configuration](#nats-configuration)
6. [TLS Configuration](#tls-configuration)
7. [Health Checks](#health-checks)
8. [Monitoring](#monitoring)

---

## Prerequisites

### Required Software

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| Rust | 1.85 | Building from source |
| Docker | 24.0 | Container runtime |
| Kubernetes | 1.28 | Orchestration (optional) |
| NATS | 2.10 | Platform messaging |
| SQLite | 3.40 | Platform projections |

### Hardware Requirements

**Single Node (Development)**:
- 2 CPU cores
- 4 GB RAM
- 20 GB SSD

**Production Cluster (3-node VSR)**:
- 4+ CPU cores per node
- 8+ GB RAM per node
- 100+ GB NVMe SSD per node
- 10 Gbps network between nodes

---

## Environment Variables

### Core Kimberlite Server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMB_BIND_ADDR` | No | `0.0.0.0:5432` | Server bind address |
| `KMB_DATA_DIR` | Yes | - | Path to data directory |
| `KMB_MAX_CONNECTIONS` | No | `1024` | Maximum concurrent connections |
| `KMB_IDLE_TIMEOUT_SECS` | No | `300` | Connection idle timeout |
| `KMB_RATE_LIMIT_RPS` | No | - | Requests per second limit |
| `KMB_TLS_CERT` | No | - | Path to TLS certificate |
| `KMB_TLS_KEY` | No | - | Path to TLS private key |
| `KMB_AUTH_MODE` | No | `none` | Auth mode: `none`, `jwt`, `apikey`, `both` |
| `KMB_JWT_SECRET` | Cond | - | JWT signing secret (required if `jwt` auth) |
| `KMB_JWT_ISSUER` | No | `kimberlite` | JWT issuer claim |
| `KMB_JWT_AUDIENCE` | No | `kimberlite` | JWT audience claim |
| `KMB_JWT_EXPIRATION_SECS` | No | `3600` | JWT token expiration (seconds) |
| `KMB_REPLICATION_MODE` | No | `none` | Replication: `none`, `single-node`, `cluster` |
| `KMB_REPLICA_ID` | Cond | `0` | Replica ID (required for `single-node` or `cluster`) |
| `KMB_LOG_LEVEL` | No | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

### Platform Services

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PLATFORM_HTTP_ADDR` | No | `0.0.0.0:8080` | HTTP server address |
| `PLATFORM_NATS_URL` | Yes | - | NATS server URL |
| `PLATFORM_SQLITE_PATH` | Yes | - | SQLite database path |
| `PLATFORM_SESSION_TTL_SECS` | No | `3600` | Session TTL |
| `PLATFORM_OAUTH_GITHUB_CLIENT_ID` | Cond | - | GitHub OAuth client ID |
| `PLATFORM_OAUTH_GITHUB_CLIENT_SECRET` | Cond | - | GitHub OAuth client secret |
| `PLATFORM_WEBAUTHN_RP_ID` | Cond | - | WebAuthn relying party ID |
| `PLATFORM_WEBAUTHN_RP_ORIGIN` | Cond | - | WebAuthn origin URL |

---

## Docker Deployment

### Building Images

```dockerfile
# Dockerfile.kimberlite-server
FROM rust:1.88-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --package kimberlite-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/kimberlite-server /usr/local/bin/

EXPOSE 5432
VOLUME /data

ENV KMB_DATA_DIR=/data
ENV KMB_BIND_ADDR=0.0.0.0:5432

CMD ["kimberlite-server"]
```

```dockerfile
# Dockerfile.platform-app
FROM rust:1.88-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --package platform-app

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/platform-app /usr/local/bin/

EXPOSE 8080
VOLUME /data

ENV PLATFORM_SQLITE_PATH=/data/platform.db

CMD ["platform-app"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  kimberlite-server:
    build:
      context: .
      dockerfile: Dockerfile.kimberlite-server
    ports:
      - "5432:5432"
    volumes:
      - kimberlite-data:/data
    environment:
      KMB_DATA_DIR: /data
      KMB_BIND_ADDR: 0.0.0.0:5432
      KMB_AUTH_MODE: jwt
      KMB_JWT_SECRET: ${KMB_JWT_SECRET}
      KMB_TLS_CERT: /certs/server.crt
      KMB_TLS_KEY: /certs/server.key
      KMB_REPLICATION_MODE: single-node
      KMB_REPLICA_ID: 0
    secrets:
      - tls-cert
      - tls-key
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5432/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  nats:
    image: nats:2.10-alpine
    ports:
      - "4222:4222"
      - "8222:8222"
    command: ["--jetstream", "--store_dir", "/data"]
    volumes:
      - nats-data:/data
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8222/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3

  platform-app:
    build:
      context: .
      dockerfile: Dockerfile.platform-app
    ports:
      - "8080:8080"
    depends_on:
      - nats
      - kimberlite-server
    environment:
      PLATFORM_HTTP_ADDR: 0.0.0.0:8080
      PLATFORM_NATS_URL: nats://nats:4222
      PLATFORM_SQLITE_PATH: /data/platform.db
      PLATFORM_OAUTH_GITHUB_CLIENT_ID: ${GITHUB_CLIENT_ID}
      PLATFORM_OAUTH_GITHUB_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET}
    volumes:
      - platform-data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  kimberlite-data:
  nats-data:
  platform-data:

secrets:
  tls-cert:
    file: ./certs/server.crt
  tls-key:
    file: ./certs/server.key
```

### Running with Docker Compose

```bash
# Create secrets
mkdir -p certs
# Generate TLS certificates (see TLS Configuration section)

# Set environment variables
export KMB_JWT_SECRET=$(openssl rand -hex 32)
export GITHUB_CLIENT_ID=your_client_id
export GITHUB_CLIENT_SECRET=your_client_secret

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kimberlite
---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kimberlite-config
  namespace: kimberlite
data:
  KMB_BIND_ADDR: "0.0.0.0:5432"
  KMB_MAX_CONNECTIONS: "1024"
  KMB_IDLE_TIMEOUT_SECS: "300"
  KMB_LOG_LEVEL: "info"
  KMB_REPLICATION_MODE: "single-node"
```

### Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: kimberlite-secrets
  namespace: kimberlite
type: Opaque
stringData:
  jwt-secret: "your-jwt-secret-here"
---
apiVersion: v1
kind: Secret
metadata:
  name: tls-certs
  namespace: kimberlite
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

### StatefulSet for Kimberlite

```yaml
# kimberlite-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kimberlite-server
  namespace: kimberlite
spec:
  serviceName: kimberlite-server
  replicas: 3
  selector:
    matchLabels:
      app: kimberlite-server
  template:
    metadata:
      labels:
        app: kimberlite-server
    spec:
      containers:
        - name: kimberlite-server
          image: kimberlite/kimberlite-server:latest
          ports:
            - containerPort: 5432
              name: kimberlite
            - containerPort: 9090
              name: metrics
          envFrom:
            - configMapRef:
                name: kimberlite-config
          env:
            - name: KMB_DATA_DIR
              value: /data
            - name: KMB_AUTH_MODE
              value: jwt
            - name: KMB_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: kimberlite-secrets
                  key: jwt-secret
            - name: KMB_TLS_CERT
              value: /certs/tls.crt
            - name: KMB_TLS_KEY
              value: /certs/tls.key
          volumeMounts:
            - name: data
              mountPath: /data
            - name: certs
              mountPath: /certs
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: 5432
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 5432
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              memory: "2Gi"
              cpu: "1"
            limits:
              memory: "8Gi"
              cpu: "4"
      volumes:
        - name: certs
          secret:
            secretName: tls-certs
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: fast-ssd
        resources:
          requests:
            storage: 100Gi
```

### Service and Ingress

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: kimberlite-server
  namespace: kimberlite
spec:
  selector:
    app: kimberlite-server
  ports:
    - port: 5432
      targetPort: 5432
      name: kimberlite
    - port: 9090
      targetPort: 9090
      name: metrics
  clusterIP: None  # Headless for StatefulSet
---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: platform-ingress
  namespace: kimberlite
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - api.kimberlite.example.com
      secretName: tls-certs
  rules:
    - host: api.kimberlite.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: platform-app
                port:
                  number: 8080
```

---

## NATS Configuration

### Single Node

```conf
# nats.conf
port: 4222
http_port: 8222

jetstream {
  store_dir: /data/jetstream
  max_memory_store: 1GB
  max_file_store: 10GB
}

# TLS for clients
tls {
  cert_file: /certs/nats-server.crt
  key_file: /certs/nats-server.key
  ca_file: /certs/ca.crt
  verify: true
}
```

### Cluster Mode

```conf
# nats-cluster.conf
port: 4222
http_port: 8222

jetstream {
  store_dir: /data/jetstream
  max_memory_store: 1GB
  max_file_store: 10GB
}

cluster {
  name: kimberlite-nats
  port: 6222
  routes: [
    nats-route://nats-1.kimberlite.local:6222
    nats-route://nats-2.kimberlite.local:6222
    nats-route://nats-3.kimberlite.local:6222
  ]
}
```

---

## TLS Configuration

### Generating Certificates

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=Kimberlite CA"

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=kimberlite-server.kimberlite.local"

# Sign server certificate
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt \
  -extfile <(printf "subjectAltName=DNS:kimberlite-server.kimberlite.local,DNS:localhost,IP:127.0.0.1")

# Create client certificate (for mTLS)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=kimberlite-client"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt
```

### Using Let's Encrypt

For production, use cert-manager with Let's Encrypt:

```yaml
# cert-manager issuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
---
# Certificate
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kimberlite-cert
  namespace: kimberlite
spec:
  secretName: tls-certs
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - api.kimberlite.example.com
```

---

## Health Checks

### Endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `/health` | Liveness check | `{"status": "ok", "version": "...", "uptime_seconds": ...}` |
| `/ready` | Readiness check | `{"status": "ok", "checks": {...}, "version": "...", "uptime_seconds": ...}` |
| `/metrics` | Prometheus metrics | Prometheus text format |

### Health Status Values

| Status | Description |
|--------|-------------|
| `ok` | Service is healthy |
| `degraded` | Service is functional but with warnings (e.g., high connection count) |
| `unhealthy` | Service cannot handle requests |

### Readiness Check Details

The `/ready` endpoint performs:
1. Disk space check (verifies data directory exists)
2. Memory check (monitors connection count as proxy)
3. Data directory writability check

```json
{
  "status": "ok",
  "checks": {
    "disk": {"status": "ok", "duration_ms": 1},
    "memory": {"status": "ok", "duration_ms": 0},
    "data_dir": {"status": "ok", "duration_ms": 2}
  },
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

---

## Monitoring

### Prometheus Metrics

Key metrics exported:

```
# Request metrics
kimberlite_requests_total{method="Query",status="success"}
kimberlite_request_duration_seconds{method="Query",quantile="0.99"}

# Connection metrics
kimberlite_connections_active
kimberlite_connections_total

# Storage metrics
kimberlite_storage_bytes_written_total
kimberlite_storage_records_total
kimberlite_storage_checkpoints_total

# Replication metrics (VSR mode)
kimberlite_replication_lag_records
kimberlite_replication_view_number
```

### Grafana Dashboard

Import the Kimberlite dashboard from `deploy/grafana/kimberlite-dashboard.json`:

```json
{
  "dashboard": {
    "title": "Kimberlite",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {"expr": "rate(kimberlite_requests_total[5m])"}
        ]
      },
      {
        "title": "P99 Latency",
        "type": "graph",
        "targets": [
          {"expr": "histogram_quantile(0.99, rate(kimberlite_request_duration_seconds_bucket[5m]))"}
        ]
      }
    ]
  }
}
```

### Alerting Rules

```yaml
# prometheus-rules.yaml
groups:
  - name: kimberlite
    rules:
      - alert: KimberliteHighLatency
        expr: histogram_quantile(0.99, rate(kimberlite_request_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High request latency"

      - alert: KimberliteReplicationLag
        expr: kimberlite_replication_lag_records > 1000
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Replication lag exceeds threshold"
```

---

## Related Documentation

- [CLOUD_ARCHITECTURE.md](../../docs-internal/internal/cloud-architecture.md) - Platform architecture
- [Security Guide](security.md) - Security configuration
- [Configuration Guide](configuration.md) - Configuration reference
