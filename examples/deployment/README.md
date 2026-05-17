# Deployment reference configurations

Production-shaped reference configurations for running
`kimberlite-cluster` outside a developer laptop. Both patterns target
the same 3-node multi-host topology built in T2.1 of the cluster
graduation plan; they differ in where the boundary between nodes lives.

| Pattern | When to use |
|---|---|
| [`systemd/`](systemd/) | One node per host behind a load balancer — the production shape for a hospital deployment. |
| [`docker-compose/`](docker-compose/) | All three nodes on one host for staging, local rehearsal of operational procedures, or CI integration tests. |

For a *user-facing* single-node Docker setup ("show me Kimberlite
running in five minutes"), see [`../docker/`](../docker/). The configs
here assume you've decided to operate a cluster.

## What both patterns share

- Use the multi-host CLI surface from T2.1:
  `kimberlite cluster init --host h0 --host h1 --host h2` →
  `kimberlite cluster start --node-id N` per host.
- Wire process-supervision health checks (systemd `Restart=on-failure`
  / docker `restart: unless-stopped`) underneath the in-tree
  supervisor's bounded-backoff loop — two layers of restart, so a
  process panic recovers within seconds and a supervisor crash
  recovers within tens of seconds.
- Expose `/healthz`, `/readyz`, and `/metrics` on each node's admin
  port (data port + 1000), which lets a load balancer pull a degraded
  node out of rotation within ~5 s of leader change (see
  `docs/operating/performance/cluster.md` for measured numbers).

## Operating

After standing up the cluster with either pattern, follow
[`docs/operating/runbooks/cluster.md`](../../docs/operating/runbooks/cluster.md):

- Failover (manual leader transfer, RTO expectations)
- Quorum loss recovery
- Replacing a permanently-failed node
- Rolling upgrade
- Audit-log integrity verification

The runbook's RTO/RPO numbers were measured against the same
3-node topology these examples deploy.
