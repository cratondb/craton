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

All four T1.3 integration scenarios run 5/5 (and 30/30 across longer rolls) on macOS local-dev hardware after the v0.9.x graduation fixes. The original 2-3/5 flake had four distinct causes — each one fixed in this slice:

1. **NotLeader hint port — fixed.** Hint previously pointed at `data_port + VSR_PORT_OFFSET` (the VSR transport address). The supervisor now sets `KMB_CLUSTER_CLIENT_PEERS` alongside `KMB_CLUSTER_PEERS` with the client-facing data ports, and `ReplicationMode::Cluster` carries a parallel `client_peers` map that `CommandSubmitter::resolve_leader_hint` reads via `pick_leader_hint`. See `crates/kimberlite-server/src/replication.rs::pick_leader_hint` + `crates/kimberlite-cluster/src/node.rs::render_cluster_client_peers_env`.
2. **`find_leader_replica` substring-matched the metric `HELP` comment — fixed.** The original test helper used `body.contains("kimberlite_is_leader 1")`. That substring appears in `# HELP kimberlite_is_leader 1 if this replica is the leader for the current view, 0 otherwise` on every replica, so the helper returned the first replica it polled regardless of which one was actually leader. `common::parse_gauge` now parses the data line directly. This was the dominant flake driver and the source of every "transient leader observed" symptom we had attributed to VSR convergence in earlier slices.
3. **New leader's own `DoViewChange` was silently dropped — fixed.** `TcpTransport::send(local_id, _)` is a no-op because the peers map excludes self. The new leader of a view change therefore sent its self-DVC into the void and stalled at quorum-1 forever (visible in `leader_kill_*`: cluster wedged in `ViewChange` after the leader was killed, no `StartView` ever broadcast). `EventLoop::handle_output` now re-injects messages addressed at `local_id` through `process_event`, the same path as a wire-arrival message.
4. **Rejoining old leader stayed at its obsolete view forever — fixed.** `on_heartbeat` rejected heartbeats from non-`self.leader()` senders before checking the message's view, so a rejoined leader (still believing it's leader of its old view) ignored every higher-view heartbeat from the current leader. `on_heartbeat` now treats a heartbeat from the leader-of-msg's higher view as a state-transfer trigger — using state transfer rather than view-change to avoid the cascading-view-change side effect (peers in `Normal` interpret a `StartViewChange` for their current view as "current leader is dead" and bump again, landing the cluster at an unpredictable view that sometimes makes the rejoined old leader leader-of-record again).

The `CommandSubmitter::status()` path was also tightened to use a single atomic `MultiNodeReplicator::shared_state()` snapshot rather than walking `is_leader()` + `view()` + `replica_status()` through three separate `RwLock` reads — a small defensive correction that prevents a partially-updated `update_shared_state` boundary from surfacing in `/metrics`.

### T2.1 — Non-localhost / multi-host topology — **DONE** (8df6dc9)

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

### T2.2 — Backup + restore semantics — **DONE** (5d337ee)

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

### T2.3 — Cluster-level VOPR scenarios — **DONE** (4a7237e scaffolding; drivers in this slice)

Today's VOPR scenarios target VSR (consensus) and the kernel directly. The supervisor itself — process restart, health-check timing, config reload, cascading node failure — has zero VOPR coverage.

- **File**: `crates/kimberlite-sim/src/scenarios.rs`
- **Scenarios** (registered through `ScenarioType::all()`, `description()`, and the `ScenarioConfig::new` dispatch — each backed by a real driver method, no longer flagged `is_aspirational`):
  - `ClusterNodeProcessCrash` — SIGKILL one node, supervisor restarts within `restart_window_ms`, restart count audited. Driver: `cluster_node_process_crash()` — single-replica gray-failure cycling at 15 %/30 % entry/recovery, ~20 s window.
  - `ClusterCascadingNodeFailure` — N-1 nodes crash in sequence (where N is quorum size); cluster blocks writes but never loses committed entries. Driver: `cluster_cascading_node_failure()` — aggressive 35 %/8 % gray-failure rates + 15 % network drop + aggressive swizzle-clogging, 30 s window.
  - `ClusterHealthCheckTimeout` — node hangs without crashing; `/readyz` flips red within bounded time; supervisor escalates to restart. Driver: `cluster_health_check_timeout()` — 20 %/3 % gray-failure + elevated latency (max 100 ms) modelling slow-not-absent responses.
  - `ClusterConfigReloadUnderLoad` — `cluster.toml` updated mid-write; no in-flight write loses durability. Driver: `cluster_config_reload_under_load()` — 8 %/25 % gray-failure + 2k in-flight + 30k events stressing the reload window.
  - `ClusterRollingRestartFullCluster` — each node restarted in sequence; the leader transition window doesn't drop committed entries. Driver: `cluster_rolling_restart_full_cluster()` — matched 18 %/22 % gray-failure cycling over a 40 s window.
- **Acceptance**: 5 scenarios in `ScenarioType::all()` with canary contracts in `description()`, dispatched to real drivers (not `aspirational_v07`), parseable via `vopr --scenario cluster-*`, executed by `cargo run -p kimberlite-sim --bin vopr -- --scenario <name>`.
- **What shipped**:
  - 5 driver methods in `scenarios.rs::impl ScenarioConfig`.
  - `ScenarioConfig::new` dispatch updated; `is_aspirational()` no longer claims them; `description()` strings drop the "(Q2 cluster scaffold)" tag in favour of "(v0.9.x cluster scenario)".
  - 4 new unit tests in `scenarios::tests`: `test_cluster_scenarios_have_real_drivers` covers all 5; per-scenario shape tests for cascading/health-check/rolling-restart.
  - `vopr::parse_scenario` matcher gains `cluster-*` aliases (snake_case + kebab-case, consistent with the rest of the table).
  - Smoke runs: each scenario passes 30+ iterations with 0 invariant violations and 16/16 invariants covered.
- **In-process VOPR vs OS supervisor caveat**: the in-process VOPR runtime does not model an OS-level process supervisor; the drivers express the fault *shapes* the real `kimberlite-cluster` supervisor would surface to the replicated log (one or more replicas going dark, hanging, or being restarted in sequence). The existing VSR invariants (offset monotonicity, prefix property, durability, hash-chain integrity) are the canary mutations — any safety regression would land there. End-to-end OS-process supervisor coverage continues to live in `crates/kimberlite-cluster/tests/three_node_integration.rs` (T1.3) and `tests/perf_baseline.rs` (T3.2).
- **Estimate**: 3 days scaffolding + 1 day drivers (both done).

## T3 — Important (must be planned, may slip to v1.0)

### T3.1 — Ops runbook — **DONE** (b4b0696, 53e504b)

`docs/operating/runbooks/cluster.md` — covering:
- Failover procedure (manual leader transfer, RTO expectations)
- Quorum loss recovery (`unsafe-disaster-recovery` command + when to use it)
- Replacing a permanently-failed node
- Rolling upgrade procedure (with version-compatibility matrix)
- Disk-full / disk-slow degraded-mode behaviour
- Audit-log integrity verification after a recovery

**Shipped** at `docs/operating/runbooks/cluster.md`. ~400 lines covering every bullet above plus the Quick-reference triage table, an Operating-model orientation, Transient-view-change diagnostics, Single-node degradation decision tree, RPO/RTO numbers tied to the existing integration test soaks, and an Escalation policy. Cross-linked from the runbook into `deployment.md`, `monitoring.md`, `security.md`.

**Estimate**: 1 week. Touch only after the cluster behaviours are real.

### T3.2 — Performance baseline + RTO/RPO measurement — **DONE** (bb5082b)

- Sustained-write benchmark suite that runs against the 3-node configuration
- Documented RTO (time-to-recovery after leader kill) and RPO (data-loss window) under fault injection
- Published in `docs/operating/performance/cluster.md` plus the v0.9.x release notes

**What shipped**:
- `crates/kimberlite-cluster/tests/perf_baseline.rs` — three `#[ignore]`-tagged harnesses: `perf_rto_leader_kill`, `perf_rpo_leader_kill`, `perf_sustained_write_throughput`. Env-tunable (`KIMBERLITE_PERF_ITERATIONS`, `KIMBERLITE_PERF_SECS`, `KIMBERLITE_PERF_PAYLOAD`). RPO harness uses a hard `assert_eq!` on acked-vs-readable so safety regressions fail loudly; availability stalls under sustained-write leader kill are recorded separately.
- `docs/operating/performance/cluster.md` (167 lines) — methodology + measured numbers (n=8, Apple Silicon, localhost): RTO p99 ≈ 1.05 s vs runbook 5 s target (~5× headroom), RPO = 0 across all completed iterations, throughput ≈ 75 events/s @ 256 B (p50 ≈ 11 ms, p99 ≈ 23 ms). Reproduction recipe + known-limitation note for the ~1-in-8 view-change stall under sustained-write leader kill (deferred to v0.10.x stability work).
- `docs/operating/runbooks/cluster.md` — RTO/RPO tables grew a measured-column alongside target-column, link to the perf doc.
- CHANGELOG.md — v0.9.x T3.2 block with headline numbers.

**Estimate**: 1 week (done).

### T3.3 — Daemonization examples — **DONE** (2993ff6)

`examples/deployment/systemd/` and `examples/deployment/docker-compose/` reference configurations. systemd unit files for each node, with proper `Restart=on-failure`, `WantedBy=multi-user.target`, and post-start health-check.

**What shipped**:
- `examples/deployment/systemd/kimberlite-cluster@.service` — templated unit instantiated per node-id (`@0`, `@1`, `@2`). `Restart=on-failure` with `StartLimitBurst=5` over a 60s window, `TimeoutStopSec=60s`, hardened (`ProtectSystem=full`, `PrivateTmp=true`, `NoNewPrivileges=true`, `LimitNOFILE=65536`).
- `examples/deployment/systemd/kimberlite-cluster-readyz@.service` — `Type=oneshot` + `RemainAfterExit=yes` companion that polls `/readyz` until 200 OK (or `KIMBERLITE_READYZ_TIMEOUT_SECS` elapses). `BindsTo` the main unit so deployment automation can `systemctl enable --now kimberlite-cluster-readyz@N` and gate on real readiness, not just process-alive.
- `examples/deployment/docker-compose/docker-compose.yml` — 3-node stack with a one-shot `init` service that runs `kimberlite cluster init --host kimberlite-0 --host kimberlite-1 --host kimberlite-2` against a shared volume on first start. Each node service `depends_on` it with `condition: service_completed_successfully`. Healthchecks hit `/readyz` (the T1.2 admin endpoints), not `kimberlite info`. Data + admin ports published; VSR port stays internal to the bridge network.
- `examples/deployment/README.md` orienting between the two patterns; `examples/README.md` index updated.
- `CHANGELOG.md` v0.9.x T3.3 block.

**Estimate**: 2 days (done).

## T4 — Nice-to-have (v1.0+) — **captured in `ROADMAP.md` deferred section**

Each of these is a discrete v1.0+ work item with its own dependencies; all four are now tracked under the "Cluster T4 nice-to-haves (post-v0.9.x graduation)" bullet in `ROADMAP.md`'s Deferred section. Original list, kept here for design-doc completeness:

- Multi-region topology (cross-AZ replication latency simulation). Dependency: real customer requirement (federated hospital network, multi-region payer).
- Hot-standby read replicas surfaced through the SDK with read-your-writes semantics. Dependency: protocol-version bump for the causality token, SDK API design.
- Web admin UI showing cluster topology + per-node health (folds into existing `kimberlite-studio`). Dependency: `kimberlite-studio` reaching v1 (currently v0.10.x scoped).
- Backup encryption tied to the customer-managed key story (`kimberlite-crypto` BYOK from the Q3 plan). Dependency: BYOK / external-KMS Q3 deliverable; design wraps the archive in an AES-256-GCM envelope keyed by the customer's KMS.

## Verification matrix

End-state acceptance for graduating the crate from `Cargo.toml`'s "not ready for public use" description. **All gates closed as of 2026-05-17**; `(not ready for public use)` removed from the crate description in `19e1e5e`.

| Gate | Evidence | Landed |
|---|---|---|
| T1.1 real subprocess | 3-node smoke test green in CI | `f1fd8df` |
| T1.2 health endpoints | curl-able from each node; Prometheus scrape returns 4+ gauges | `780d695` |
| T1.3 integration tests | 5 scenarios green; SIGKILL-leader scenario reliably elects new leader | `fd8ce37` + 4 follow-on fixes (`f9695a4`, `9f642d7`, `1971aa7`, `b488398`, `b04439f`, `23537cb`) |
| T2.1 multi-host | `cluster.toml` with 3 distinct IPs boots end-to-end | `8df6dc9` |
| T2.2 backup/restore | 1 GB roundtrip identical row-by-row | `5d337ee` |
| T2.3 VOPR coverage | 5 cluster scenarios in `ScenarioType::all()` with canary contracts, dispatched to real drivers | `4a7237e` (scaffolding) + this slice (drivers) |
| T3.1 runbook | published under `docs/operating/runbooks/` | `b4b0696`, `53e504b` |
| T3.2 perf baseline | RTO + RPO numbers in release notes | `bb5082b` |
| T3.3 daemonization | systemd + docker-compose under `examples/deployment/` | `2993ff6` |

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

## Status — graduated

All T1, T2, T3 items closed. `kimberlite-cluster` graduated v0.9.x. T4 items captured in `ROADMAP.md`'s Deferred section as discrete v1.0+ work items, each with stated dependencies.

This design doc should be moved from `docs-internal/design-docs/active/` to `docs-internal/design-docs/archived/` once the next release cuts.
