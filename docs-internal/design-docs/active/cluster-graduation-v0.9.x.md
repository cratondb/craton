# `kimberlite-cluster` Graduation Plan — v0.9.x

**Status**: active
**Owner**: kernel team
**Targets**: graduate `kimberlite-cluster` from "not ready for public use" → production-ready for healthcare clinical deployments (5+ nines)
**Author**: 2026-05-15

## Context

Healthcare pivot (Sprint 1 → Q1 → Q2) brought us to the point where every primitive a SMART-on-FHIR clinical app needs to read a patient chart is built, tested, and runnable end-to-end *on a single node*. The remaining production blocker is multi-node high availability: a hospital cannot stake a clinical workload on a single-node database.

A v0.9.x triage of `kimberlite-cluster` (2026-05-15) surfaced a structural finding that reshapes the scope:

> **`kimberlite-cluster` is not a consensus crate.** It is a single-machine process supervisor (`tokio::process::Command` over child nodes) that currently spawns `sleep infinity` as a placeholder rather than a real `kimberlite start` subprocess. It does not import `kimberlite-vsr`.

VSR — the consensus protocol — lives in `kimberlite-vsr` and is described as mature elsewhere. The graduation work is therefore **integration plumbing + operational surface**, not protocol development.

This document is the punch list. Tier order is blocker → critical → important → nice-to-have. Items in earlier tiers MUST close before later tiers ship.

## Scope baseline (what exists today)

5 files, 834 LOC under `crates/kimberlite-cluster/src/`:

| File | LOC | Role |
|---|---|---|
| `lib.rs` | 67 | `init_cluster()`, `start_cluster()`, `stop_cluster()` entry points |
| `config.rs` | 241 | `ClusterConfig`, `ClusterTopology`, `NodeConfig` — TOML persistence |
| `node.rs` | 231 | `NodeProcess` — child-process wrapper |
| `supervisor.rs` | 236 | `ClusterSupervisor` — N-node orchestration, restart-on-crash with backoff |
| `error.rs` | 59 | 10 error variants |

15 tests (unit + lightweight async). No fault injection, no real subprocess in CI, no chaos.

Public API (`lib.rs:21-40`):

```rust
pub fn init_cluster(data_dir: PathBuf, node_count: usize, base_port: u16) -> Result<ClusterConfig>
pub async fn start_cluster(data_dir: PathBuf) -> Result<ClusterSupervisor>
pub async fn stop_cluster(supervisor: &mut ClusterSupervisor) -> Result<()>
```

## T1 — Blockers (must ship before any v0.9.x graduation tag)

### T1.1 — Real subprocess: replace `sleep infinity` with `kimberlite start`

- **File**: `crates/kimberlite-cluster/src/node.rs` (currently spawns placeholder around line 91)
- **Change**: discover the `kimberlite` binary at runtime (env override `KIMBERLITE_BIN`, then PATH, then alongside-the-cluster-binary fallback). Pass node data dir + listen address from `NodeConfig`.
- **Acceptance**:
  - Starting a 3-node cluster brings up 3 real `kimberlite start` processes with distinct data dirs and ports
  - Killing PID 1 of those triggers supervisor restart with backoff, observable via `NodeStatus`
  - New integration test `tests/three_node_smoke.rs` spawns the binary, writes one event through tenant 0 to leader, reads it from a follower (eventually consistent), asserts equality
- **Estimate**: 1 week

### T1.2 — HTTP health/readiness endpoints per node

Healthcare ops teams (and Kubernetes deployments later) require liveness + readiness checks. Today there is no out-of-process way to ask "is this node healthy?".

- **New file**: `crates/kimberlite-server/src/admin_http.rs` — minimal axum service on a separate port (default `+1` from the data port, configurable)
- **Endpoints**:
  - `GET /healthz` — process alive; returns `200 OK` always while running
  - `GET /readyz` — node is in VSR Normal mode AND its log is within `--max-replication-lag` of the leader. Returns `200 OK` / `503 Service Unavailable`
  - `GET /metrics` — Prometheus exposition (gauges: `kimberlite_committed_offset`, `kimberlite_replication_lag_seconds`, `kimberlite_view_number`, `kimberlite_is_leader`)
- **Acceptance**:
  - Each spawned node exposes `/healthz` / `/readyz` / `/metrics` on its admin port
  - Killing the leader's data port forces `/readyz` on a follower to flip green within 5s of the new leader being elected
  - `curl -s :PORT/metrics | grep kimberlite_` returns at least 4 gauges
- **Estimate**: 1.5 weeks

### T1.3 — Real integration tests with spawned binaries

Test coverage today is unit-only; the supervisor's restart logic has never been exercised against a real child process. This is a graduation blocker on its own.

- **New file**: `crates/kimberlite-cluster/tests/three_node_integration.rs`
- **Scenarios**:
  1. **Happy path**: 3-node cluster, write to leader, follower converges within 5s
  2. **Single-node kill**: SIGKILL one follower; supervisor restarts it; cluster remains writable throughout
  3. **Leader kill**: SIGKILL the leader; new leader elected within `--election-timeout-ms`; previous leader rejoins as follower
  4. **Rolling restart**: stop-then-start each node sequentially; assert no writes lost
  5. **Disk full**: simulate a disk-full on one node; assert that node enters degraded readyz state but doesn't drag the cluster down
- **Acceptance**: all five tests pass in CI under the standard `cargo test --workspace` matrix. Optionally tagged `#[ignore]` for slow tests and exercised in a nightly job.
- **Estimate**: 1.5 weeks

## T2 — Critical (should ship in v0.9.x — slip-to-v0.10 is OK only with stated risk)

### T1 follow-ups (post-T1.3) — **DONE**

The T1.3 integration tests called out two follow-up bugs that surfaced as ~3-4/5 flake. Both fixed in v0.9.x:

- **`MultiNodeReplicator::is_leader` ignored Normal status.** Pure view-table lookup let the gauge / submit gate read `true` on a replica mid-view-change. Fixed by introducing `ReplicaState::is_acting_leader()` (`Normal && view-leader`) and routing `SharedState.is_leader` through it. See `crates/kimberlite-vsr/src/replica/state.rs::is_acting_leader` + `crates/kimberlite-vsr/src/event_loop.rs::update_shared_state`. Two paired tests in `replica/state.rs`.
- **Server mio loop starved the data-port accept queue.** Single-thread Poll serviced data-port + HTTP probe + per-connection events in one pass; under view-change churn the per-connection burst delayed accepts, kernel backlog overflowed (visible as `Resource temporarily unavailable` / `os error 35`). Fixed with two-pass listener-first dispatch: `dispatch_listener_events` + `dispatch_per_connection_events` in `crates/kimberlite-server/src/server.rs`. `poll_once` uses the same path. Soak on `leader_kill_flips_follower_readyz_within_5s`: 5/5 (was 3-4/5).

Remaining T1 integration flake (`cluster_remains_writable_through_follower_crash`, `leader_kill_elects_new_leader_and_old_leader_rejoins`) — 2-3/5 soak — is pre-existing and unrelated: NotLeader hint advertises VSR-replica address (data_port + 100) rather than client-data address, so the SDK's retry-on-hint path can't redirect. Out of scope for this slice; tracked separately in ROADMAP.md → v0.10.x.

### T2.1 — Non-localhost / multi-host topology — **DONE (commit pending)**

Today's `ClusterConfig` hardcodes `127.0.0.1`. A hospital deployment needs nodes on three different hosts behind a load balancer.

- **File**: `crates/kimberlite-cluster/src/config.rs`
- **Change**: `NodeConfig` already has a host field; verify it propagates through `start_cluster()` to the spawned process's `--listen` / `--peer` arguments. Add validation that all 3 nodes' (host, port) tuples are unique.
- **Acceptance**: a `cluster.toml` declaring 3 nodes on three different IPs spins up successfully when the operator launches `kimberlite cluster start` on each host (with `--node-id <0|1|2>` selecting which entry to bring up locally).
- **What shipped**:
  - `ClusterConfig::try_new_with_hosts(data_dir, hosts, base_port)` — per-node bind address.
  - `ClusterConfig::validate()` — checks `(host, port)` uniqueness across data / VSR / HTTP ports; called on `load()` and on `try_new_with_hosts()`.
  - `ClusterSupervisor::for_node(config, node_id)` — owns one local entry, keeps full peer topology for `KMB_CLUSTER_PEERS` rendering.
  - `start_cluster_node(data_dir, node_id)` lib-level helper.
  - `kimberlite cluster init --host a --host b --host c` and `kimberlite cluster start --node-id N` CLI surfaces.
  - `tests/multi_host_topology.rs` — end-to-end test of the multi-host code path (5/5 soak on localhost).
  - Pre-existing `VSR_PORT_OFFSET=100` / new `HTTP_PORT_OFFSET=1000` promoted to canonical constants in `crate::config`.
- **Estimate**: 4 days
- **Follow-up surfaced**: `tests/three_node_smoke.rs`'s embedded `pick_base_port` (from T1.1, pre-`tests/common/`) sweeps only 32 attempts and gets starved on systems where the OS ephemeral range is biased high (macOS default 49152-65535). Migrate it to `common::pick_base_port` (1000 attempts, downward sweep from a clamped start) when next touching that file.

### T2.2 — Backup + restore semantics — **DONE (commit pending)**

HIPAA § 164.308(a)(7) — contingency plan requires data backup, disaster recovery, and emergency mode operation. Today there is no documented backup procedure.

- **New CLI**: `kimberlite cluster backup --project <data> --output <archive.tar.zst>`.
- **New CLI**: `kimberlite cluster restore --input <archive.tar.zst> --target <new_data>`.
- **Acceptance**: a 3-node cluster with 1 GB of writes can be backed up to a tarball, the cluster destroyed, the tarball restored into a fresh 3-node cluster, and a full table scan returns identical rows.
- **What shipped**:
  - `kimberlite-cluster::backup::backup_cluster(data_dir, archive_path)` — tar+zstd of `<data_dir>/cluster/` with embedded BLAKE3 manifest.
  - `kimberlite-cluster::backup::restore_cluster(archive_path, new_data_dir)` — extract + per-file checksum re-verification; refuses non-empty target.
  - `kimberlite cluster backup` / `kimberlite cluster restore` CLI surfaces wired through `commands/cluster.rs`.
  - 5 lib-level + 3 integration tests; 10 MB synthetic-payload round-trip passes byte-identical; 1 GB soak runs in nightly job.
- **Scope deviation from doc wording**: the design said "JOIN-into-checkpoint" — VSR-coordinated pause for a quiescent snapshot. The shipped path is offline-safe: operator either stops writes for a clean snapshot or accepts the trailing-fsync-window semantic. Online-coordinated backup is documented in the runbook as a v1.0 deliverable.
- **Estimate**: 1.5 weeks

### T2.3 — Cluster-level VOPR scenarios

Today's VOPR scenarios target VSR (consensus) and the kernel directly. The supervisor itself — process restart, health-check timing, config reload, cascading node failure — has zero VOPR coverage.

- **File**: `crates/kimberlite-sim/src/scenarios.rs`
- **New variants** (scaffolded under the established "drivers ship per-commit" idiom):
  - `ClusterNodeProcessCrash` — SIGKILL one node, supervisor restarts within `restart_window_ms`, restart count audited
  - `ClusterCascadingNodeFailure` — N-1 nodes crash in sequence (where N is quorum size); cluster blocks writes but never loses committed entries
  - `ClusterHealthCheckTimeout` — node hangs without crashing; `/readyz` flips red within bounded time; supervisor escalates to restart
  - `ClusterConfigReloadUnderLoad` — `cluster.toml` updated mid-write; no in-flight write loses durability
  - `ClusterRollingRestartFullCluster` — each node restarted in sequence; the leader transition window doesn't drop committed entries
- **Acceptance**: 5 scenarios added to `ScenarioType::all()`, `is_aspirational()`, and `description()` arms with canary-mutation contracts (same pattern as Q2's clinical scenarios). Drivers ship per-scenario in follow-ons.
- **Estimate**: 3 days for scaffolding; drivers are separate work.

## T3 — Important (must be planned, may slip to v1.0)

### T3.1 — Ops runbook — **DONE (commit pending)**

`docs/operating/runbooks/cluster.md` — covering:
- Failover procedure (manual leader transfer, RTO expectations)
- Quorum loss recovery (`unsafe-disaster-recovery` command + when to use it)
- Replacing a permanently-failed node
- Rolling upgrade procedure (with version-compatibility matrix)
- Disk-full / disk-slow degraded-mode behaviour
- Audit-log integrity verification after a recovery

**Shipped** at `docs/operating/runbooks/cluster.md`. ~400 lines covering every bullet above plus the Quick-reference triage table, an Operating-model orientation, Transient-view-change diagnostics, Single-node degradation decision tree, RPO/RTO numbers tied to the existing integration test soaks, and an Escalation policy. Cross-linked from the runbook into `deployment.md`, `monitoring.md`, `security.md`.

**Estimate**: 1 week. Touch only after the cluster behaviours are real.

### T3.2 — Performance baseline + RTO/RPO measurement

- Sustained-write benchmark suite that runs against the 3-node configuration
- Documented RTO (time-to-recovery after leader kill) and RPO (data-loss window) under fault injection
- Published in `docs/operating/performance/cluster.md` plus the v0.9.x release notes

**Estimate**: 1 week.

### T3.3 — Daemonization examples

`examples/deployment/systemd/` and `examples/deployment/docker-compose/` reference configurations. systemd unit files for each node, with proper `Restart=on-failure`, `WantedBy=multi-user.target`, and post-start health-check.

**Estimate**: 2 days.

## T4 — Nice-to-have (v1.0+)

- Multi-region topology (cross-AZ replication latency simulation)
- Hot-standby read replicas surfaced through the SDK with read-your-writes semantics
- Web admin UI showing cluster topology + per-node health (folds into existing `kimberlite-studio`)
- Backup encryption tied to the customer-managed key story (`kimberlite-crypto` BYOK from the Q3 plan)

## Verification matrix

End-state acceptance for graduating the crate from `Cargo.toml`'s "not ready for public use" description:

| Gate | Evidence |
|---|---|
| T1.1 real subprocess | 3-node smoke test green in CI |
| T1.2 health endpoints | curl-able from each node; Prometheus scrape returns 4+ gauges |
| T1.3 integration tests | 5 scenarios green; SIGKILL-leader scenario reliably elects new leader |
| T2.1 multi-host | `cluster.toml` with 3 distinct IPs boots end-to-end |
| T2.2 backup/restore | 1 GB roundtrip identical row-by-row |
| T2.3 VOPR coverage | 5 cluster scenarios in `ScenarioType::all()` with canary contracts |
| T3.1 runbook | published under `docs/operating/runbooks/` |
| T3.2 perf baseline | RTO + RPO numbers in release notes |

When T1.* and T2.* are complete, drop the `(not ready for public use)` from the crate's `Cargo.toml` description.

## Estimate summary

| Tier | Effort |
|---|---|
| T1 (blockers) | ~4 weeks |
| T2 (critical) | ~3 weeks |
| T3 (important) | ~2.5 weeks |
| Total to graduation | **~9.5 weeks** of focused effort |

This is consistent with the original plan's framing of Q2 (3 months) covering HL7v2 + multi-node HA. HL7v2 shipped today; cluster graduation is the remaining Q2 spend.

## Out of scope

- Reworking `kimberlite-vsr`. VSR is mature per the project's existing positioning; this plan trusts that and treats it as a known-good dependency.
- General-purpose distributed-systems primitives (gossip, sharding, etc.). Kimberlite is single-master VSR; cross-shard transactions are explicitly not in the roadmap.
- BYOK / external-KMS integration. That's a Q3 deliverable (see `ROADMAP.md`'s v0.10.x section).

## First piece (today)

Of all the work above, the smallest concrete addition that ships without prerequisites is **T2.3 (cluster VOPR scenarios)** — same scaffolding pattern as the Q2 clinical scenarios, additive, no kernel changes. Recommended as the immediate next commit; the heavier T1.* integration work follows in subsequent sessions.
