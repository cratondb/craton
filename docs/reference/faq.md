---
title: "Frequently Asked Questions"
section: "reference"
slug: "faq"
order: 3
---

# Frequently Asked Questions

## General

### What is Kimberlite?

Kimberlite is a compliance-first database built on a single principle: **All data is an immutable, ordered log. All state is a derived view.**

It combines:
- **Append-only storage** (like event sourcing)
- **SQL interface** (like PostgreSQL)
- **MVCC time-travel queries** (like Datomic)
- **Deterministic consensus** (VSR protocol)
- **Hash-chained tamper-evidence** (like blockchain, without the blockchain)

Target users: Healthcare systems requiring HIPAA-grade audit trails — EHR/EMR, payer/RCM, clinical research, digital health.

### Who should use Kimberlite?

**Ideal for:**
- 🏥 EHR / EMR systems needing HIPAA compliance, FHIR R4, and tamper-evident audit
- 💊 Payer / RCM platforms handling X12 837 claims and 835 remittance with audit-by-default
- 🔬 Clinical research with IRB-aware retention, consent-bound queries, and Safe Harbor de-identification
- 📱 Digital health / telehealth SaaS needing per-tenant encryption and BAA-ready audit chain
- 💻 Database researchers and systems programmers exploring immutable log architectures

**Not ideal for:**
- High-frequency trading (latency-sensitive)
- Social media feeds (append-only is overkill)
- Ephemeral data (caches, sessions)
- Workloads requiring in-place updates

### Is Kimberlite production-ready?

**Current status (v0.4.0):** Developer preview focused on learning and exploration.

- ✅ **Core is solid:** 1,300+ tests, deterministic simulation testing, production-grade crypto
- ✅ **Architecture is stable:** No major breaking changes planned
- ⚠️ **APIs are evolving:** v0.x means breaking changes possible (follow SemVer)
- ⚠️ **Limited deployment experience:** Not yet battle-tested at scale

**Recommendation:** Use for:
- Internal tools and prototypes
- Learning database internals
- Compliance research and evaluation

**Wait for v1.0 if you need:**
- Guaranteed API stability
- Large-scale production deployments
- 24/7 commercial support

### Is Kimberlite a blockchain?

**No.** Kimberlite uses hash chains (like blockchain) but is fundamentally different:

| Feature | Blockchain | Kimberlite |
|---------|-----------|-----------|
| **Consensus** | Proof-of-Work / PoS | VSR (Viewstamped Replication) |
| **Trust model** | Trustless (anyone can join) | Trusted replicas (permissioned) |
| **Performance** | Slow (global consensus) | Fast (cluster consensus) |
| **Purpose** | Decentralized ledger | Centralized audit-first database |
| **Energy use** | High (mining) | Low (standard servers) |

**TL;DR:** Kimberlite borrows hash chains for tamper-evidence, but runs on standard servers with trusted replicas. No mining, no tokens, no decentralization.

## Architecture

### Why append-only? Isn't that wasteful?

**Benefits outweigh costs for compliance workloads:**

✅ **Audit trail is free** - History is built-in, no separate audit table
✅ **Time-travel queries** - View state at any past timestamp
✅ **Simpler concurrency** - No locks, no in-place updates
✅ **Tamper-evident** - Hash chain detects modification
✅ **Deterministic replay** - Reproduce exact state from log

**Storage trade-off:**
- 1M patient records ≈ 500 MB (with 5 updates each)
- Use retention policies to prune old versions
- Compression reduces storage by 60-70%

**Real-world comparison:**
- PostgreSQL with audit triggers: Similar storage, worse query performance
- Event sourcing: Same append-only model, but no SQL interface

### How does MVCC work?

Each row version has two timestamps:

```sql
CREATE TABLE patients (
    id INTEGER,
    name TEXT,
    _created_at TIMESTAMP,  -- implicit
    _deleted_at TIMESTAMP   -- implicit, NULL if current
);
```

**Query at time T:**
```sql
SELECT * FROM patients AS OF TIMESTAMP '2026-02-03 10:00:00';
```

Returns rows where:
```
_created_at <= '2026-02-03 10:00:00'
AND (_deleted_at > '2026-02-03 10:00:00' OR _deleted_at IS NULL)
```

**Under the hood:**
1. Log contains all versions: `[v1, v2, v3, ...]`
2. Query specifies point-in-time
3. Kernel filters versions by timestamp
4. Returns consistent snapshot

No read locks needed - queries never block writes.

### How fast is it compared to PostgreSQL?

**Current benchmarks (v0.4.0, M1 Mac):**

| Operation | PostgreSQL | Kimberlite | Notes |
|-----------|-----------|-----------|-------|
| **Single insert** | 150 μs | 200 μs | 33% slower (hash chain overhead) |
| **Batch insert (1K)** | 80 ms | 90 ms | 12% slower (CRC32 + hashing) |
| **Point query** | 50 μs | 60 μs | 20% slower (MVCC filtering) |
| **Time-travel query** | N/A | 80 μs | Free (no audit table) |
| **Full table scan (1M rows)** | 300 ms | 450 ms | 50% slower (version filtering) |

**Key insight:** Kimberlite trades 10-50% performance for audit trail + time-travel queries.

**When Kimberlite is faster:**
- Audit queries (no separate audit table)
- Historical analysis (MVCC built-in)
- Compliance reports (tamper-evidence free)

**When PostgreSQL is faster:**
- Pure transactional workloads (OLTP)
- Workloads not needing history
- In-place updates (Kimberlite always appends)

### What's the "Functional Core / Imperative Shell" pattern?

The kernel is a **pure function**:

```rust
fn apply_committed(
    state: State,
    cmd: Command
) -> Result<(State, Vec<Effect>)>
```

**No IO inside the kernel:**
- No file operations
- No network calls
- No system clock (`Instant::now()`)
- No randomness (except via explicit RNG parameter)

**Why?**
- ✅ **Deterministic** - Same inputs → same outputs (enables simulation testing)
- ✅ **Testable** - No mocks needed, pure unit tests
- ✅ **Replayable** - Rebuild state from log perfectly
- ✅ **Simple** - Easy to reason about, no hidden state

**The shell executes effects:**

```rust
for effect in effects {
    match effect {
        Effect::WriteLog(entry) => storage.append(entry),
        Effect::SendMessage(msg) => network.send(msg),
    }
}
```

See the [architecture internals](../internals/architecture/crate-structure.md) for details.

## Compliance

### Does Kimberlite meet HIPAA requirements?

Kimberlite provides **technical controls** for HIPAA compliance:

✅ **Audit trails** (§164.312(b)) - Immutable log records all data access
✅ **Integrity controls** (§164.312(c)(1)) - Hash chains detect tampering
✅ **Access controls** (§164.312(a)(1)) - Multi-tenant isolation
✅ **Encryption** (§164.312(a)(2)(iv)) - AES-256-GCM for data at rest

⚠️ **You still need:**
- Business Associate Agreement (BAA)
- Administrative safeguards (policies, training)
- Physical security (server room access)
- Breach notification procedures

**Kimberlite ≠ automatic HIPAA compliance.** It's a compliance-friendly tool, not a compliance solution.

See the [compliance certification package](../compliance/certification-package.md) for detailed guidance.

### What about GDPR "right to be forgotten"?

GDPR Article 17 (right to erasure) seems incompatible with immutable logs. Here's how Kimberlite handles it:

**1. Logical deletion (preferred):**
```sql
UPDATE patients SET name = '[REDACTED]', email = '[REDACTED]' WHERE id = 123;
```

Creates new version with redacted data. Old versions stay in log, but:
- Marked as "superseded by redaction"
- Not returned in queries
- Can be physically purged after retention period

**2. Tombstone marker:**
```sql
DELETE FROM patients WHERE id = 123;
```

Inserts tombstone: `{id: 123, _deleted_at: now(), reason: 'GDPR erasure'}`

**3. Physical purging (advanced):**

Kimberlite can rewrite the log, removing specific entries:
```bash
kimberlite purge --entity-id 123 --reason "GDPR Art. 17 request" ./data
```

Creates **new hash chain** starting from purge point. Old chain archived for audit.

**Legal note:** Consult a lawyer. GDPR has exceptions for legal obligations and public interest.

### Can I use it for SOC 2 compliance?

Yes! Kimberlite helps with SOC 2 Trust Service Criteria:

| Criterion | How Kimberlite Helps |
|-----------|---------------------|
| **CC6.1** (Logical access controls) | Multi-tenant isolation, role-based access |
| **CC7.1** (Detect threats) | Integrity monitoring via hash chains |
| **CC7.2** (Monitor system) | Event log records all operations |
| **CC8.1** (Change management) | Schema migrations tracked in log |

See the [compliance certification package](../compliance/certification-package.md) for SOC 2 evidence templates.

## Operations

### How do I back up a Kimberlite database?

**Simple approach (development):**

```bash
# Stop the server
kimberlite stop ./data

# Copy the entire data directory
tar -czf backup-$(date +%Y%m%d).tar.gz ./data

# Restart server
kimberlite start --address 127.0.0.1:3000 ./data
```

**Production approach:**

1. **Streaming replication** - Run 3+ replicas, one is always a backup
2. **Point-in-time recovery** - Export log segments to S3/GCS:
   ```bash
   kimberlite export --since '2026-02-01' --output backup.kmb ./data
   ```
3. **Checkpoint + incremental** - Export checkpoint + log delta

See the [operations runbook](../operating/runbook.md) for detailed backup procedures.

### How do I monitor Kimberlite in production?

Kimberlite exposes Prometheus metrics at `/metrics`:

```
# Key metrics
kimberlite_log_offset         # Current log position
kimberlite_hash_chain_valid   # Hash chain integrity (0/1)
kimberlite_crc_errors_total   # Corruption detections
kimberlite_vsr_view           # Current consensus view
kimberlite_query_duration_seconds  # Query latency (histogram)
```

**Alerting rules:**
```yaml
- alert: HashChainBroken
  expr: kimberlite_hash_chain_valid == 0
  severity: critical

- alert: HighCRCErrors
  expr: rate(kimberlite_crc_errors_total[5m]) > 0
  severity: critical
```

See the [monitoring guide](../operating/monitoring.md) for Grafana dashboards.

### What's the disaster recovery strategy?

**RPO (Recovery Point Objective):** Zero data loss if you have 3+ replicas

**RTO (Recovery Time Objective):** Depends on data size
- 1 GB: ~30 seconds (hash chain verification)
- 100 GB: ~5 minutes
- 1 TB: ~30 minutes

**Recovery scenarios:**

1. **Single node failure** → Automatic failover to replica (30s)
2. **Data corruption** → Restore from last valid checkpoint (5 min)
3. **Complete cluster loss** → Restore from offsite backup (30 min - 2 hours)
4. **Logical error** (bad DELETE) → Time-travel query to recover data (instant)

See the [operations runbook](../operating/runbook.md) for disaster-recovery procedures.

## Development

### How do I contribute?

1. **Read the docs:**
   - [PRESSURECRAFT](../concepts/pressurecraft.md) — code quality standards
   - [CONTRIBUTING](../../CONTRIBUTING.md) — contribution guidelines
   - [CODE_OF_CONDUCT](../../CODE_OF_CONDUCT.md) — community standards

2. **Pick an issue:**
   - Good first issues: https://github.com/kimberlitedb/kimberlite/labels/good-first-issue
   - Join Discord to discuss before starting

3. **Follow the checklist:**
   - No `unsafe` code (workspace lint enforces)
   - No recursion (use bounded loops)
   - 2+ assertions per function
   - Tests pass (`just test`)
   - Clippy clean (`just clippy`)

4. **Submit PR** using the template (includes PRESSURECRAFT checklist)

### When will APIs be stable?

**Current state:**
- **v0.6.0** (shipped) — feature-complete compliance surface: masking
  policies, ON CONFLICT, correlated subqueries, AS OF TIMESTAMP,
  erasure auto-discovery, audit log query, ConsentBasis wire v4.
- **v0.7.0** (next) — DX + SQL follow-ups. No breaking wire changes
  expected.
- **v1.0.0** — API stability guarantee when the gates in
  [`ROADMAP.md`](../../ROADMAP.md) close. No fixed date.

**What changes between v0.x versions:**
- SQL syntax (new keywords, functions)
- Storage format (will provide migration tools)
- Client protocol (breaking changes documented)

**What WON'T change:**
- Core invariants (immutable log, hash chains, FCIS)
- VOPR testing framework
- Compliance guarantees

Subscribe to releases: https://github.com/kimberlitedb/kimberlite/releases

### Where's the roadmap?

See [ROADMAP.md](../../ROADMAP.md) for planned features:

**v0.7.0** (in flight):
- DX + SQL follow-ups (additional scalar functions, `DROP TABLE IF EXISTS`, etc.)
- Python SDK typing refresh
- VOPR workload generators for v0.6.0 command families

**v0.8.0**:
- Streaming replication and CDC
- Multi-region clustering
- Broader SDK coverage

**v1.0.0**:
- API stability guarantee
- Commercial support options
- Certified compliance templates

## Comparisons

### Kimberlite vs PostgreSQL?

| Feature | PostgreSQL | Kimberlite |
|---------|-----------|-----------|
| **Model** | Relational (mutable) | Relational (immutable) |
| **History** | Audit triggers (manual) | Built-in (MVCC) |
| **Time-travel** | Via extensions | Native SQL |
| **Integrity** | Checksums | Hash chains + CRC32 |
| **Consensus** | Streaming replication | VSR (deterministic) |
| **Best for** | General OLTP | Compliance-heavy workloads |

**When to use PostgreSQL:** General purpose, mature ecosystem, need 100+ extensions

**When to use Kimberlite:** Audit trails, compliance, tamper-evidence, time-travel queries

### Kimberlite vs EventStoreDB?

| Feature | EventStoreDB | Kimberlite |
|---------|-------------|-----------|
| **Model** | Event sourcing | Event sourcing + SQL views |
| **Query** | Stream reads, projections | SQL (familiar) |
| **Schema** | Schemaless (JSON events) | Typed (SQL DDL) |
| **Time-travel** | Replay events | SQL queries |
| **Best for** | Event-driven architectures | Compliance + traditional apps |

**Key difference:** EventStoreDB is event streams with projections. Kimberlite is SQL database backed by event log.

### Kimberlite vs Datomic?

| Feature | Datomic | Kimberlite |
|---------|---------|-----------|
| **Model** | Datalog (facts) | SQL (tables) |
| **Time-travel** | As-of queries (native) | AS OF TIMESTAMP (SQL) |
| **Storage** | Pluggable (DynamoDB, etc.) | Append-only log (native) |
| **License** | Proprietary | Apache 2.0 (open source) |
| **Best for** | Clojure apps, graph queries | Compliance, SQL familiarity |

**Key difference:** Datomic is Datalog-native. Kimberlite targets SQL users needing immutability.

---

**Didn't find your question?** Ask on Discord: https://discord.gg/QPChWYjD
