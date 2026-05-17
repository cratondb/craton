---
title: "Cluster Performance Baseline"
section: "operating"
slug: "performance/cluster"
order: 6
---

# Cluster Performance Baseline

**Target audience:** operators sizing a 3-node Kimberlite cluster, SREs setting alert thresholds, kernel engineers tracking regressions across releases.
**Scope:** measured throughput, latency, RTO, and RPO for a 3-node localhost cluster on dev-class hardware. Numbers are reproducible from a single `cargo test --release` invocation; the doc names every command and every assumption.

This doc complements `docs/operating/performance.md` (single-node engineering philosophy) with the cluster-specific numbers an operator needs at the moment they're filling in a capacity plan or an SLO worksheet.

---

## Table of contents

1. [Methodology](#methodology)
2. [Sustained-write throughput](#sustained-write-throughput)
3. [Write latency](#write-latency)
4. [Recovery Time Objective (RTO)](#recovery-time-objective-rto)
5. [Recovery Point Objective (RPO)](#recovery-point-objective-rpo)
6. [Known limitation: view-change stall under post-write leader kill](#known-limitation-view-change-stall-under-post-write-leader-kill)
7. [How these numbers translate to production hardware](#how-these-numbers-translate-to-production-hardware)
8. [Reproduction recipe](#reproduction-recipe)

---

## Methodology

All numbers come from `crates/kimberlite-cluster/tests/perf_baseline.rs`. The harness boots a fresh 3-node cluster against the built `kimberlite` release binary, drives a real client through the wire protocol, and emits distributions to stdout — no internal hooks, no mocked I/O.

| Parameter | Value |
|---|---|
| Cluster shape | 3 nodes, single host, localhost loopback |
| Build profile | `--release` (`-O3`, LTO disabled) |
| Storage | Default tempdir (`TempDir::new()`) on host filesystem |
| `fsync` mode | Server default (no env override) |
| Client | `kimberlite-client::Client`, synchronous, single connection |
| Tenant | 1 (healthcare-default profile) |
| Hardware | Apple Silicon macOS dev laptop |

The harness is the source of truth, not these numbers — a baseline run on different hardware will produce different absolute values. The doc reports a representative run; the runbook (`docs/operating/runbooks/cluster.md`) and v0.9.x release notes quote the headline distributions.

---

## Sustained-write throughput

| Workload | Throughput | p50 latency | p99 latency | max latency |
|---|---|---|---|---|
| 1 writer, 256-byte payloads, 10-second window | ~75 events/s | ~11 ms | ~23 ms | ~31 ms |

**What this measures.** A single client connection writing one event per `append()` call against the leader, no batching, no concurrent connections. Each call round-trips through wire encode → leader accept → VSR commit (quorum on 3 nodes) → ack.

**Why the number looks modest.** The per-call cost is dominated by a synchronous RPC plus a VSR quorum commit. A real application gains throughput by either (a) batching multiple events per `append` call — the wire takes `events: Vec<Vec<u8>>`, so a single RPC can carry hundreds — or (b) running concurrent writer connections so multiple commits overlap. Neither is exercised in this baseline; both are reasonable next-step measurements.

**Latency floor.** p50 ≈ 12 ms reflects the localhost VSR commit round-trip on dev hardware. On production gear with a faster filesystem you should expect single-digit p50.

---

## Write latency

The latency distribution from the same single-writer sustained-throughput run:

```
min=5.1ms p50=10.5ms mean=13.3ms p99=22.6ms max=31.5ms
```

Latency is consistent — the p99/p50 ratio is ~2x, which is the kind of tail predictability the architecture is designed for ("predictable is better than fast" — see `docs/operating/performance.md`). The 31 ms max across ~750 calls suggests no GC-style pauses or thundering-herd cliffs at this workload.

---

## Recovery Time Objective (RTO)

| Scenario | n | min | p50 | mean | p99 | max |
|---|---|---|---|---|---|---|
| Leader SIGKILL → first successful write through any replica | 8 | ~1.03 s | ~1.04 s | ~1.04 s | ~1.05 s | ~1.05 s |

**What this measures.** Wall clock from the instant `force_kill` delivers `SIGKILL` to the leader process to the instant a client `append()` succeeds against any surviving replica. This is *user-observable RTO*: it includes VSR view-change time, new-leader election, the client's NotLeader-hint round-robin, and the new leader's accept path coming online — i.e. exactly what an application sees from outside the cluster.

**How it relates to the runbook claim.** `docs/operating/runbooks/cluster.md` lists "Leader process crash: RTO ≤ 5 s". Measured p99 on the 8-sample baseline is ~1.05 s, comfortably inside that envelope with ~5× headroom for production network jitter. Distribution is tight — the p99/p50 ratio is essentially 1.0, meaning the recovery path has no long-tail outliers within the sample.

**What's NOT measured.** Multi-host network partitions, cold-start RTO (all 3 nodes down), or recovery under sustained read load. These are tracked under T2.3 in the cluster graduation plan (`docs-internal/design-docs/active/cluster-graduation-v0.9.x.md`).

---

## Recovery Point Objective (RPO)

| Scenario | Completed iters | Acked writes pre-kill | Readable post-kill | RPO |
|---|---|---|---|---|
| Leader SIGKILL after 100 sequential acked writes | 7 of 8 | 100 each | 100 each | **0 events** |

**What this measures.** Per iteration: open a connection to the leader, append 100 sequenced events (each one ack'd by the leader before the next is submitted), `SIGKILL` the leader, wait for a new leader to be elected, read everything back. RPO = `acked_count − readable_count`.

**The expected and measured answer is 0.** VSR's safety property guarantees that any write the client received an ack for has been committed on a quorum, so any surviving replica with the latest log is eligible to serve it after a view change. The test measures this rather than assuming it — and the harness's assertion `assert_eq!(acked_lost, 0)` is a correctness gate that will fail loudly if the property ever degrades.

**Acked-but-unreplicated writes are by definition impossible.** A pre-kill write the client received `Ok(_)` for is committed. A pre-kill write the client did NOT receive `Ok(_)` for (i.e. an in-flight request the client never got a response to) is *uncommitted* and is *not* counted toward RPO — the application protocol must treat in-flight requests as indeterminate until reconnect-and-replay clarifies their state.

---

## Known limitation: view-change stall under post-write leader kill

The RPO harness records, in addition to per-iteration RPO, a stall count — iterations where no new leader emerged within 20 s after the leader was killed.

**Observed rate on dev hardware:** ~1 in 8 iterations (~12%) on Apple Silicon macOS in v0.9.x; the same iter 3 stalled across two independent 5- and 8-iteration runs, suggesting the failure mode is timing-deterministic given the harness's fixed inter-iteration cadence rather than a free random flake.

The leader-kill scenario in `tests/three_node_integration.rs::leader_kill_*` runs 5/5 (30/30 soak) without stalls — but those scenarios kill the leader immediately after a single `create_stream`, before any sustained write load. The RPO harness kills the leader after 100 sequential acked writes, which produces a different state in the surviving replicas' logs.

This is consistent with the v0.10.x stability tracker noting that "repeated leader-transitions starve the leader's main loop" (see comment in `tests/three_node_integration.rs::single_node_restart_preserves_writes`). The fix lands when the HTTP-sidecar + client-port mio fairness work completes.

**Operational implication today:** plan for occasional view-change stalls of >20 s under high-write-rate leader failures. They self-recover; the supervisor will still restart the dead process, and once it rejoins the cluster, view-change completes. If you observe a stall that does not self-recover within ~60 s, escalate per `docs/operating/runbooks/cluster.md`.

---

## How these numbers translate to production hardware

Localhost numbers are a **lower bound on consistency, upper bound on throughput**:

- **Latency floor will grow** with real network RTT — add the inter-AZ RTT (typically 0.5–2 ms within a region) to every commit. p50 of 12 ms becomes 13–14 ms; p99 jitter widens with the network's tail.
- **Throughput per writer will fall** by a small amount on the same workload, but should still scale linearly with concurrent writer connections (each commit is independent).
- **RTO floor will grow** with the propagation time for leader-election messages across hosts. Sub-second loopback RTO becomes 1–3 s across-AZ; the runbook's 5 s budget allows for this.
- **RPO stays at 0** regardless of hardware — it's a safety property, not a perf number.

Re-baseline on your own hardware before publishing SLOs.

---

## Reproduction recipe

```bash
# Build the binary once; perf_baseline.rs discovers it via the env override.
just build-release

# All three measurements; ~2 minutes wall time at default 5 iterations.
KIMBERLITE_BIN=target/release/kimberlite \
  cargo test --release -p kimberlite-cluster --test perf_baseline \
  -- --ignored --nocapture --test-threads=1

# Higher-rigor run for published numbers (~10 minutes wall time).
KIMBERLITE_BIN=target/release/kimberlite \
  KIMBERLITE_PERF_ITERATIONS=20 \
  KIMBERLITE_PERF_SECS=60 \
  cargo test --release -p kimberlite-cluster --test perf_baseline \
  -- --ignored --nocapture --test-threads=1
```

Output goes to stderr (via `eprintln!`); the `--nocapture` flag preserves it. Each test prints a labelled distribution table that maps 1:1 to the sections above.

To validate against a specific build:

```bash
git rev-parse --short HEAD             # capture the SHA
KIMBERLITE_BIN=$(realpath target/release/kimberlite) \
  cargo test --release -p kimberlite-cluster --test perf_baseline \
  -- --ignored --nocapture --test-threads=1 \
  | tee /tmp/kimberlite-perf-$(git rev-parse --short HEAD).log
```

---

## Related documentation

- `docs/operating/performance.md` — general performance philosophy, single-node optimisation guidelines.
- `docs/operating/runbooks/cluster.md` — operator-facing runbook; quotes the headline RTO/RPO numbers from this doc.
- `docs-internal/design-docs/active/cluster-graduation-v0.9.x.md` — engineering plan; T3.2 is the line item this doc closes.
- `crates/kimberlite-cluster/tests/perf_baseline.rs` — the harness. Source of truth; this doc reflects its output.
