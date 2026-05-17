# systemd reference deployment

Production-shaped systemd units for a 3-node `kimberlite-cluster`
deployment — one node per host behind a load balancer, the
healthcare-deployment pattern from the T2.1 multi-host topology work.

For a *single-host* development cluster, see
[`../docker-compose/`](../docker-compose/) — it is faster to bring up
and tear down.

## Files

| File | Role |
|---|---|
| `kimberlite-cluster@.service` | Templated unit, one instance per node id (`@0`, `@1`, `@2`) |
| `kimberlite-cluster-readyz@.service` | Oneshot post-start verifier; polls `/readyz` until the node is in VSR Normal mode |

## Prerequisites

- `kimberlite` binary at `/usr/local/bin/kimberlite`
- `kimberlite` system user + group
- Project directory at `/var/lib/kimberlite/cluster` owned by that user
- A `cluster.toml` already produced by `kimberlite cluster init` with
  the multi-host `--host` form

## One-time setup (per host)

```bash
# 1. Create the system user.
sudo useradd --system --create-home \
             --home-dir /var/lib/kimberlite \
             --shell /usr/sbin/nologin kimberlite

# 2. Install the binary.
sudo install -m 0755 ./kimberlite /usr/local/bin/kimberlite

# 3. Generate the cluster config (run ONCE on any host, then copy
#    /var/lib/kimberlite/cluster/cluster/cluster.toml to the other
#    boxes byte-for-byte).
sudo -u kimberlite kimberlite cluster init \
    --project /var/lib/kimberlite/cluster \
    --host 10.0.1.10 --host 10.0.1.11 --host 10.0.1.12

# 4. Install the units.
sudo install -m 0644 kimberlite-cluster@.service        /etc/systemd/system/
sudo install -m 0644 kimberlite-cluster-readyz@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Enable + start (per host, with matching node-id)

```bash
# Host 10.0.1.10 — node 0.
sudo systemctl enable --now kimberlite-cluster@0.service \
                            kimberlite-cluster-readyz@0.service

# Host 10.0.1.11 — node 1.
sudo systemctl enable --now kimberlite-cluster@1.service \
                            kimberlite-cluster-readyz@1.service

# Host 10.0.1.12 — node 2.
sudo systemctl enable --now kimberlite-cluster@2.service \
                            kimberlite-cluster-readyz@2.service
```

The readyz unit exits 0 once the node is replicating from the leader.
If it exits non-zero, the cluster failed to converge — start triage with
`journalctl -u kimberlite-cluster@<N>.service`.

## Verify

```bash
# Process alive + supervisor in monitor loop.
systemctl status kimberlite-cluster@0.service

# Node is in VSR Normal mode and within replication-lag bound.
curl -fsS http://127.0.0.1:6432/readyz

# Prometheus gauges (data port + 1000 == HTTP probe port).
curl -fsS http://127.0.0.1:6432/metrics | grep kimberlite_

# Cluster-wide status.
sudo -u kimberlite kimberlite cluster status \
    --project /var/lib/kimberlite/cluster
```

## Port layout

For `base_port = 5432` and 3 nodes on three hosts, each box exposes:

| Node | Host | Data port | VSR port | HTTP probe |
|---|---|---|---|---|
| 0 | `10.0.1.10` | 5432 | 5532 | 6432 |
| 1 | `10.0.1.11` | 5433 | 5533 | 6433 |
| 2 | `10.0.1.12` | 5434 | 5534 | 6434 |

The data port (clients) and the HTTP probe port (load balancer health
check) should be reachable from outside the host. The VSR port only
needs to be reachable from the other nodes; firewall it off the public
internet.

## Tuning

The shipped unit is conservative. Common overrides via
`/etc/systemd/system/kimberlite-cluster@.service.d/override.conf`:

```ini
[Service]
# Different project directory.
Environment=KIMBERLITE_PROJECT=/srv/kimberlite

# Pin a specific binary path (also honoured by the supervisor for
# spawning the per-node VSR child process).
Environment=KIMBERLITE_BIN=/opt/kimberlite/bin/kimberlite

# Longer drain window for clusters carrying large in-flight batches.
TimeoutStopSec=300s
```

After editing:

```bash
sudo systemctl daemon-reload
sudo systemctl restart kimberlite-cluster@0.service
```

## Operating

See [`docs/operating/runbooks/cluster.md`](../../../docs/operating/runbooks/cluster.md)
for failover, quorum loss, replacing a permanently-failed node, and
rolling-upgrade procedures.
