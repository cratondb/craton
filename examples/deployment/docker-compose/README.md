# docker-compose reference deployment

3-node `kimberlite-cluster` on a single host, mirroring the production
multi-host shape from T2.1: each node has its own hostname, its own
data + VSR + HTTP ports, and the same `cluster.toml` view of the
topology.

For a *production* multi-host deployment, see
[`../systemd/`](../systemd/) — that pattern is what a hospital actually
ships, one box per node behind a load balancer.

## Bring up

```bash
docker compose up -d
```

The `init` service runs `kimberlite cluster init` against the shared
volume on first start, then exits. The three `kimberlite-N` services
wait for that one-shot to complete before launching their supervisors.

## Verify

```bash
# Each node's HTTP probe (data port + 1000):
curl http://127.0.0.1:6432/readyz   # node 0
curl http://127.0.0.1:6433/readyz   # node 1
curl http://127.0.0.1:6434/readyz   # node 2

# Prometheus gauges from any node — kimberlite_is_leader = 1 marks
# the current leader, the other two are followers:
curl http://127.0.0.1:6432/metrics | grep -E 'kimberlite_(is_leader|view_number|committed_offset|replication_lag)'

# Process / container view:
docker compose ps
```

The cluster is fully usable once all three `/readyz` endpoints return
`200 OK`. If one returns `503` indefinitely, start with
`docker compose logs kimberlite-<id>` — the supervisor's restart-loop
output mirrors what systemd would surface on `journalctl`.

## Port layout

| Node | Container | Data port | VSR port | HTTP probe |
|---|---|---|---|---|
| 0 | `kimberlite-0` | 5432 | 5532 | 6432 |
| 1 | `kimberlite-1` | 5433 | 5533 | 6433 |
| 2 | `kimberlite-2` | 5434 | 5534 | 6434 |

The VSR port is internal to the docker network — not published to the
host — which mirrors a hospital deployment where the consensus port
should be firewalled off the public internet anyway.

## Exercising failover

The T1.3 leader-kill scenario reproduces directly:

```bash
# 1. Identify the current leader.
for port in 6432 6433 6434; do
  echo "port=$port "; curl -s http://127.0.0.1:$port/metrics | grep '^kimberlite_is_leader '
done

# 2. Kill it (replace 0 with whichever node above had is_leader = 1).
docker compose kill kimberlite-0

# 3. Watch the others elect a new leader within ~1 second (measured RTO
#    p99 ≈ 1.05 s — see docs/operating/performance/cluster.md).
sleep 3
for port in 6433 6434; do
  echo "port=$port "; curl -s http://127.0.0.1:$port/metrics | grep '^kimberlite_is_leader '
done

# 4. Restart the killed node — it rejoins as a follower.
docker compose start kimberlite-0
```

## Tear down

```bash
docker compose down       # stops containers, keeps volumes
docker compose down -v    # stops containers AND wipes the cluster's data
```

## Caveats

This is a *reference* deployment, not a hardened one:

- All three nodes share one host. A real high-availability deployment
  puts each node on a separate host with independent disks and power.
  The `systemd` example is the production shape.
- The shared `kimberlite-shared` volume holds every node's data dir.
  In production, give each node its own volume so a corrupt
  filesystem cannot take down the quorum. See
  [`docs/operating/runbooks/cluster.md`](../../../docs/operating/runbooks/cluster.md)
  for the replacement-of-a-failed-node procedure.
- TLS termination is not configured. Front the cluster with a reverse
  proxy (Caddy, Envoy, NGINX) for client connections and metrics
  scraping.

See the runbook above for the full operational surface — failover,
quorum-loss recovery, rolling upgrade, audit-log integrity verification.
