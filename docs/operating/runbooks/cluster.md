---
title: "Cluster Operations Runbook"
section: "operating"
slug: "runbooks/cluster"
order: 9
---

# Cluster Operations Runbook

**Target audience:** on-call engineers, SREs running a 3-node Kimberlite cluster.
**Scope:** procedures for graduating a v0.9.x cluster and operating it through the failure modes its design admits.
**Severity levels:** P0 (data loss / write outage) → P3 (cosmetic).

---

## Quick reference

| Symptom | Procedure |
|---|---|
| Writes return `no quorum` | [Leader failover](#leader-failover) |
| Two replicas report `is_leader=1` | [Transient view-change](#transient-view-change) — usually self-heals |
| `/readyz` red on one node, others green | [Single-node degradation](#single-node-degradation) |
| `/readyz` red on a majority | [Quorum loss recovery](#quorum-loss-recovery) — **risk: data loss** |
| A node is permanently dead (hardware fault) | [Replacing a permanently-failed node](#replacing-a-permanently-failed-node) |
| Disk full on one replica | [Disk-full degraded mode](#disk-full--disk-slow-degraded-mode) |
| Need to upgrade Kimberlite version | [Rolling upgrade](#rolling-upgrade) |
| Just restored from backup; need to verify | [Audit-log integrity verification](#audit-log-integrity-verification) |
| Need to back up | [Backup + restore](#backup--restore) |

Every procedure assumes the cluster was provisioned per `docs/operating/deployment.md` and exposes the standard probe ports: `data_port + 1000` for `/healthz` `/readyz` `/metrics`.

---

## Operating model

Kimberlite's cluster is single-leader VSR with N=3 (one leader, two followers, quorum=2). Writes go to the leader; reads can target any replica. The leader and one follower must be reachable for the cluster to accept writes.

Three constants you will need:

- **`kimberlite_is_leader`** — gauge per replica. Exactly one replica should report `1` in steady state.
- **`kimberlite_view_number`** — gauge per replica. Strictly monotonic. A view-number bump means VSR ran a view change (failover).
- **`kimberlite_committed_offset`** — gauge per replica. Leader advances first; followers catch up within seconds.

The single oracle of "is this cluster healthy?" is **all three replicas returning HTTP 200 from `/readyz`** AND **all three reporting the same `kimberlite_view_number`** AND **the leader's `kimberlite_committed_offset` advancing**.

---

## Leader failover

**Trigger:** writes fail with `NotLeader` / `no quorum`; client logs show retried submits; `/readyz` red on the previous leader.

**Severity:** P0 if it doesn't auto-recover within ~5 seconds; P2 if it does.

### Auto-recovery (expected path)

1. The leader dies (process crash, host loss, OS pause).
2. Within `--election-timeout-ms` (default ~3s), the remaining replicas notice the missing heartbeat.
3. VSR runs a view change: `view_number` ticks on each replica; one new leader is elected from the remaining N-1.
4. Within 5 seconds total, a new leader has `is_leader=1` and `/readyz=200`.
5. The client SDK retries the failed write against the new leader (transparently).

**Verification (paste into a shell):**

```bash
for port in 16432 16433 16434; do
  printf "node @%d: " "$port"
  curl -sf "http://127.0.0.1:${port}/metrics" \
    | grep -E "^kimberlite_(is_leader|view_number|committed_offset) "
done
```

Expect one `is_leader 1` and identical `view_number` across all three. If those don't agree within 30 s, escalate to the [transient view-change](#transient-view-change) procedure below.

### Manual leader transfer

There is **no operator-initiated leader transfer command in v0.9.x.** The protocol-level support exists in `kimberlite-vsr` but isn't exposed at the CLI. Workaround: stop the current leader with `kimberlite cluster stop --node <id>`; VSR will elect a new one. The old leader rejoins as a follower when restarted.

### RTO expectations

| Event | RTO |
|---|---|
| Leader process crash | ≤ 5 s (election timeout + new-leader settle) |
| Leader host kernel panic | ≤ 5 s (same) |
| Leader network partition | ≤ 5 s (same; the leader self-abdicates when partitioned) |
| Cluster cold-start (all 3 nodes down) | ≤ 15 s (leader recovers superblock + waits for quorum) |

These numbers come from `tests/three_node_integration.rs::leader_kill_*` and `tests/http_probes.rs::leader_kill_flips_follower_readyz_within_5s`. Re-run those in your environment to baseline.

---

## Transient view-change

**Symptom:** `kimberlite_is_leader` reads `1` on two replicas simultaneously, for under a second.

**Severity:** P3. This is **expected** during view-change windows in v0.9.x. The `is_leader` gauge reflects "this replica owns the current view AND is in Normal status" — but during the brief window between `StartViewChange` and `StartView`, the outgoing primary and the incoming primary can both transiently report `1` if their statuses straddle the change.

**v0.9.x fix:** the metric was tightened in `kimberlite-vsr/src/replica/state.rs::is_acting_leader` to require Normal status. If you observe this in v0.9.x or later, the bug is back; capture `/metrics` snapshots from every replica with their timestamps and file an issue.

If the condition persists for **more than ~5 seconds**, it is no longer transient — escalate to [Quorum loss recovery](#quorum-loss-recovery) because it likely means two replicas have diverging views of who the leader is, which indicates a partition.

---

## Single-node degradation

**Trigger:** one replica's `/readyz` returns 503; the other two report 200.

**Severity:** P2. The cluster is still writable (2-of-3 quorum), but a second failure now becomes a write outage.

### Decision tree

1. Read the degraded node's `/healthz`. If 200, the process is alive; if 503 or no answer, the process is dead — go to step 5.
2. Read the degraded node's `/metrics`. Compare `kimberlite_committed_offset` to the leader's. Lag indicates replication is catching up.
3. Read `kimberlite_replication_lag_seconds`. > 30s sustained means follower is wedged.
4. Check the host: disk space (`df -h`), file descriptors (`lsof | wc -l`), CPU pressure, swap. The supervisor's restart loop won't fix host-level resource exhaustion.
5. If the process is dead, the supervisor should be restarting it with exponential backoff. Tail its stderr for the panic / error:
   ```bash
   journalctl -u kimberlite@<node-id> --since "5 min ago" -e
   ```

### Don't panic

A single node degraded is **not** a P0. Do not restart the cluster, do not run disaster-recovery commands. The cluster is operating within its design envelope.

---

## Quorum loss recovery

**Trigger:** majority of replicas (≥ 2 of 3) unreachable. `/readyz` red on at least two nodes. Writes have been failing for > 30 s.

**Severity:** P0. **This is the data-loss-risk procedure. Read the entire section before running any command.**

### Step 1: stop the bleed

1. Pause any write workload pointed at the cluster (load balancer drain, app circuit-breaker open, etc.).
2. Do **NOT** kill the surviving replica(s). Do **NOT** delete data directories. Treat them as evidence.

### Step 2: diagnose

- **Network partition** between datacentres? Restoring connectivity may auto-recover; VSR is partition-tolerant within its quorum constraint.
- **Two host failures simultaneously?** Recover the hosts; nodes will rejoin once VSR sees them and the surviving log has the missing entries.
- **Two replicas corrupted (disk error)?** This is genuine quorum loss. There may be committed entries that exist only on the failed nodes.

### Step 3: the unsafe path

If hosts can't be recovered and you must restore service, the surviving replica's log is the new source of truth. **Any entry committed on the failed pair but not on the survivor is lost.** This is the HIPAA § 164.308(a)(7) emergency-mode operation — invoking it requires:

1. Document the decision in your incident log (who authorized, what data window is at risk).
2. Trigger an audit-log integrity verification on the survivor (see [Audit-log integrity verification](#audit-log-integrity-verification)) before you re-form the cluster.
3. **Disaster-recovery command:** not yet exposed in v0.9.x CLI. The intended invocation is `kimberlite unsafe-disaster-recovery --force-single-node <data_dir>` which marks the survivor as a single-node cluster. Until that ships, the workaround is:
   ```bash
   # On the surviving box. WARNING: rewrites cluster topology.
   kimberlite cluster init --nodes 1 --project /var/lib/kimberlite-restored
   # Copy the survivor's per-stream segment dirs + projections.db
   # into /var/lib/kimberlite-restored/cluster/node-0/.
   # Manually craft a new superblock — see ROADMAP.md "unsafe disaster recovery"
   # for the schema. Then:
   kimberlite cluster start --project /var/lib/kimberlite-restored
   ```
   This last step is a v1.0 deliverable. For v0.9.x, contact the kernel team for a one-off recovery plan if it triggers.
4. Once running single-node, take a **full backup** before doing anything else.
5. Provision two new replicas and let them sync from the restored survivor.

### RPO expectations

- Quorum maintained throughout: **RPO = 0** (no committed entry can be lost — VSR safety property, formally verified).
- Quorum lost, surviving replica's log is the latest: **RPO = trailing-write-window of failed replicas** (typically sub-second).
- Quorum lost, no recoverable surviving log: **RPO = age of the most recent backup**.

---

## Replacing a permanently-failed node

**Trigger:** one node's host is dead (motherboard, drive, datacentre incident) and won't come back. Cluster is operating in N-1 mode.

**Severity:** P2 until replacement is in place; P3 once the new replica is caught up.

### Procedure

1. Provision the replacement box. Same Kimberlite version, same network reachability as the dead one.
2. Ensure the replacement's data dir is **empty** — Kimberlite refuses to bootstrap into a partially-populated dir.
3. On the operator's workstation, update `cluster.toml` to point the dead node's slot at the replacement's IP:
   ```bash
   # If you initialised with `--host`:
   $EDITOR /var/lib/kimberlite/cluster/cluster.toml
   # Change `bind_address` for the failed node's entry to the
   # replacement's IP. Then re-run uniqueness validation:
   kimberlite cluster status --project /var/lib/kimberlite \
     || echo "validation failed — fix cluster.toml"
   ```
4. Copy the updated `cluster.toml` to every replica (including the new one).
5. On the replacement box, start the node:
   ```bash
   kimberlite cluster start --node-id <dead-id> --project /var/lib/kimberlite
   ```
6. The new replica bootstraps an empty log and runs VSR's state-transfer / catchup against the existing leader. Watch `kimberlite_committed_offset` rise; it converges with the leader's value once caught up.

### Catchup time

Roughly `total_log_bytes / network_throughput_bytes_per_second`. A 10 GB log on a 1 Gbit link is ≈ 80 s on the wire plus disk-write time.

### Verification

- All three `kimberlite_view_number` gauges agree.
- All three `kimberlite_committed_offset` gauges agree (within the leader's heartbeat window).
- All three `/readyz` return 200.

---

## Disk-full / disk-slow degraded mode

**Trigger:** one replica's host hits 95 %+ disk; writes on that replica error out.

**Severity:** P2 if isolated to one replica; P0 if the leader.

### Single-replica disk-full

Kimberlite is append-only — no truncate, no compaction in v0.9.x. The remediation is to add capacity, not to delete files.

1. The affected node's `/readyz` flips red on its own. The cluster keeps writes going against the 2-of-3 quorum.
2. **Do not** delete `segment_*.log` files from a stream directory — the hash chain will break and the node won't recover. Treat the data dir as immutable to the operator.
3. Grow the underlying volume (cloud: resize the EBS / persistent disk; bare-metal: extend the LVM volume and resize2fs).
4. After capacity is restored, `kimberlite cluster start --node-id <id>` restarts the affected replica; it resumes appending where it left off.

### Leader disk-full

Same procedure, but the leader's `/readyz` going red triggers a view change. The new leader takes over; the original leader rejoins as a follower once its disk is restored.

### Disk-slow (latency spike, not exhaustion)

The leader will fail its own heartbeat liveness check if write fsyncs exceed ~1 s sustained, then abdicate. This is intentional — a slow disk on the leader stalls every write. The cluster picks a new leader on a healthier disk.

---

## Rolling upgrade

**Trigger:** new Kimberlite release available; want to upgrade with zero write downtime.

**Severity:** N/A — this is a planned operation, not an incident.

### Pre-flight

1. **Read the release notes**. Cross-version compatibility is documented in `CHANGELOG.md` per release; only consecutive minor versions are guaranteed to interoperate.
2. **Take a backup**: `kimberlite cluster backup --project /var/lib/kimberlite --output /backups/pre-$NEW_VERSION.tar.zst`.
3. **Confirm cluster is healthy**: all three `/readyz` green, all three views agree, no replication lag > 1s.

### Procedure (followers first, leader last)

For each follower replica (in order: lowest id that isn't the leader, then next):

1. Stop the node: `kimberlite cluster stop --node-id <id>`.
2. Wait for the other two to acknowledge: `/readyz` on each remaining node should still be green within 5s.
3. Replace the binary on disk (package upgrade, container restart with new image, etc.).
4. Start the node: `kimberlite cluster start --node-id <id>`.
5. Wait for `kimberlite_committed_offset` on the upgraded node to match the leader's.
6. **Don't proceed to the next replica until step 5 completes.** The window between "follower restarted" and "follower caught up" is when the cluster is one failure away from a write outage.

For the leader (last):

1. Trigger a view change by stopping the leader. The cluster elects a new leader from the already-upgraded followers.
2. Wait for the new leader's `/readyz` to flip green.
3. Replace the binary on the old-leader host.
4. Start the old-leader node; it rejoins as a follower.

### Verification

Once all three are on the new version:

- All three `/metrics` report the new version string in `kimberlite_build_info` (if exposed).
- `kimberlite_view_number` has bumped by at least 1 (since the leader rolled).
- A write through the new leader and a read on each follower round-trips correctly.

### Rollback

If something is wrong post-upgrade:

1. Stop the cluster: `kimberlite cluster stop --project /var/lib/kimberlite`.
2. Restore from the pre-upgrade backup: `kimberlite cluster restore --input /backups/pre-$NEW_VERSION.tar.zst --target /var/lib/kimberlite-rollback`.
3. Start the rollback cluster: `kimberlite cluster start --project /var/lib/kimberlite-rollback`.
4. Repoint clients at the rollback path.

Any writes that landed after the backup but before the rollback are lost — that's why step "take a backup" comes first.

### Version-compatibility matrix

Kimberlite supports rolling upgrade across **one minor version at a time**. From `0.X.Y` you may roll to `0.X.Y+k` or `0.(X+1).0`, but not directly to `0.(X+2).0`. Major-version bumps require a stop-the-world upgrade until the dual-version VSR work in ROADMAP v1.0 ships.

---

## Backup + restore

**Trigger:** routine backup cadence (recommended: hourly + daily), pre-upgrade safety, pre-major-change snapshot.

**Severity:** N/A — planned operation.

### Backup

```bash
kimberlite cluster backup \
  --project /var/lib/kimberlite \
  --output  /backups/cluster-$(date -u +%Y%m%dT%H%M%SZ).tar.zst
```

Output is a single self-checksummed `tar.zst` containing the entire `<project>/cluster/` subtree (every node's data dir + `cluster.toml`). The archive embeds a `MANIFEST` with BLAKE3 of every file; `kimberlite cluster restore` re-verifies on extract.

**Backup is taken from the data dir, not the running cluster.** For a clean snapshot, either:

- Stop writes (load-balancer drain) for the duration of the backup, **or**
- Accept the trailing-fsync-window semantic: any write whose VSR commit landed in the last `commit_interval` may or may not be in the archive.

The HIPAA § 164.308(a)(7) acceptance gate ("1 GB roundtrip, identical row-by-row") runs offline. Online-coordinated backup with a no-op-reconfig pause is a v1.0 deliverable.

### Restore

```bash
kimberlite cluster restore \
  --input  /backups/cluster-20260516T143000Z.tar.zst \
  --target /var/lib/kimberlite-restored
```

The target dir must be empty or absent — restore **refuses** to overwrite. This is intentional; restoring on top of a running cluster would silently corrupt it.

After restore:

1. Verify integrity (the restore step already did this, but to be paranoid): `tar -tf /backups/cluster-*.tar.zst | head` and confirm `cluster/cluster.toml` is at the front.
2. Start the cluster: `kimberlite cluster start --project /var/lib/kimberlite-restored`.
3. Run [audit-log integrity verification](#audit-log-integrity-verification).
4. Replay any application-side writes that landed after the backup timestamp.

### Cadence recommendation

- **Hourly backup**, retain 24h on local disk.
- **Daily backup**, retain 30d on off-host storage (S3 / Glacier / equivalent).
- **Pre-upgrade backup** — every time, no exceptions.

---

## Audit-log integrity verification

**Trigger:** any recovery / restore / disaster operation. Mandatory before declaring a recovered cluster operational for HIPAA workloads.

**Severity:** verification is mandatory; the procedure is read-only and safe.

### Procedure

1. Run the existing audit-log integrity check (single-node, repeats across replicas):
   ```bash
   kimberlite audit verify --project /var/lib/kimberlite
   ```
2. Expected output: `chain hash OK on N events` and no `chain break at offset X` messages.
3. If there's a break, **stop**. Do not put the cluster into production. Capture:
   - The exact offset of the break.
   - The replica's `kimberlite_committed_offset` value at boot.
   - The most recent backup's age.

   Then either:
   - Restore from a backup that pre-dates the break, replay forward, re-verify.
   - Escalate to the kernel team — a hash-chain break in production is always a P0 invariant violation and we want to see the bytes.

4. Cross-replica sanity (cluster-wide): the `chain_hash` for the same offset should be identical on every replica. Hash a known-stable offset on each:
   ```bash
   for port in 5432 5433 5434; do
     kimberlite query --server "127.0.0.1:${port}" --sql "SELECT chain_hash FROM __audit__ WHERE offset=1000"
   done
   ```
   All three must return the same hex string.

---

## Escalation

If a procedure here says "escalate," that means:

1. Stop changing the cluster's state.
2. Capture (`/healthz` `/readyz` `/metrics` from every replica) + the last 1000 lines of each node's stderr.
3. Open an issue with the captured data; include the incident timeline.
4. Wait for the kernel team to advise before running any disaster-recovery command. Running them blind risks turning a P1 into permanent data loss.

---

## Related docs

- `docs/operating/deployment.md` — provisioning a fresh cluster.
- `docs/operating/monitoring.md` — Prometheus scrape config, alert thresholds.
- `docs/operating/security.md` — auth, TLS, audit-log retention.
- `docs/operating/runbook.md` — the general (non-cluster-specific) operations runbook.
- `docs-internal/design-docs/active/cluster-graduation-v0.9.x.md` — the engineering punch list this runbook covers the operator-facing surface of.
