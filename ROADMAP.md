# Kimberlite Roadmap

Kimberlite is an OSS-first, verifiable database for healthcare —
clinical/EHR-adjacent systems, digital health, payer/RCM, and clinical
research. All data is an immutable ordered log; all state is a derived
view.

This file lists what's shipped, what's next, and the gates v1.0 must
clear. Detail for each completed release lives in [`CHANGELOG.md`].
Detail for each planned feature lives in GitHub issues.

[`CHANGELOG.md`]: ./CHANGELOG.md

## Status

**Current release:** `v0.8.0` (2026-05-06) — notebar v0.7.0-migration
wishlist + SDK error/audit ratchet. Six items surfaced when notebar
drove a real workload on top of v0.7.0; each shipped behind its own
PR (#125 → #131). Highlights: typed unique-constraint error
(`QueryError::DuplicatePrimaryKey` end-to-end across Rust / TS /
Python), `requestId` on the `eraseSubject` per-stream callback,
`Effect::ProjectionRowsPurge` for DROP TABLE row purge,
`streamLength(streamId)` O(1) primitive (TS + Rust),
TS bindings for the v0.7.0 typed primitives (`Interval`,
`SubstringRange`, `DateField`, `AggregateMemoryBudget`),
server-walked `audit.verifyChain()` (replaces the v0.5.0 / v0.6.0
hardcoded `{ ok: true }` stub) on TS + Rust, and `audit.subscribe()`
polling iterator on TS. Python parity for these items is the
v0.9.0 ratchet — see "v0.9.0 — in-flight" below. See
[`CHANGELOG.md`] for the full list.

**Next release:** v0.9.0 — see "v0.9.0 — in-flight" below.

**Target v1.0:** when the gates below close. No fixed date — we ship
when the third-party audits, SDK coverage, and production readiness
criteria are all green.

[`v0.6.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.6.0
[`v0.7.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.7.0
[`v0.8.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.8.0

---

## v0.9.0 — in-flight

The v0.9.0 cycle finishes the items v0.8.0 deferred (Go SDK Phase 1,
plan-time time-fold production wiring, VOPR scenario drivers for the
v0.7.0 scaffolds, pool-metrics client-side parity) plus Python parity
for the SDK primitives that landed TS-first / Rust-first in v0.8.0.
Stretch goal: published performance baselines on reference hardware
so the `compare/postgresql` page and the README's trade-off table
quote real numbers instead of qualitative language.

- [ ] **Go SDK — Phase 1.** `Connect`/`Query`/`Append`/`Read`/
      `Subscribe`/`Pool` over the existing FFI bridge. Scaffolding
      lives at `sdks/go/`; v0.7.0 + v0.8.0 deferred this so TS /
      Python / Rust stayed at parity for the data plane and
      compliance surface. Phase 2 (compliance) and Phase 3
      (typed primitives + framework integrations) follow inside
      the v0.9.x → v1.0 window.
- [ ] **Plan-time time-fold production wiring.** v0.7.0 shipped
      the `ScalarExpr::Now` / `CurrentTimestamp` / `CurrentDate`
      sentinel variants and the evaluator panics if reached
      unfolded (paired `#[should_panic]` tests at
      `crates/kimberlite-query/src/expression.rs:1336-1354`
      verify). The planner-side `fold_time_constants` pass needs
      to be implemented and wired into `tenant.rs::execute` so
      production queries actually use these scalars without
      panicking. Carried over from v0.8.0 in-flight.
- [ ] **VOPR scenario drivers for the 16 v0.7.0 scaffolds.** Each
      `Masking*` / `Upsert*` / `AsOfTimestamp*` /
      `EraseAutoDiscovery*` variant has a documented canary
      mutation; the driver step that injects + asserts ships per
      family. Currently each variant runs the baseline workload
      via `ScenarioConfig::aspirational_v07`. Carried over.
- [ ] **Pool metrics — client-side Prometheus parity.** Server-side
      metrics already exist at
      `crates/kimberlite-server/src/metrics.rs`; v0.7.0 + v0.8.0
      deferred the TS / Python / Rust client-side surface because
      it touches the napi-rs binding layer. AWS ECS-friendly
      design: text-format `pool.metrics()` consumed by CloudWatch
      Prometheus source.
- [ ] **Python parity for v0.8.0 deliveries.** Catch-up cycle for
      the items that landed TS-first / Rust-first:
      `streamLength` (O(1) row count), typed primitive bindings
      (`Interval`, `SubstringRange`, `DateField`,
      `AggregateMemoryBudget`), and `audit.verifyChain` /
      `audit.subscribe`. Re-uses the same wire frames; Python
      napi-equivalent shapes via the existing FFI bridge.
- [ ] **Rust `audit.subscribe` polling iterator.** TS shipped in
      v0.8.0; Rust client + Python parity follow here. Mirror the
      shape of `erasure.subscribe()`. Cross-stream subscription-
      filter server hook (push-based instead of polling) stays
      deferred — the polling iterator is sufficient for the
      dashboard use-case notebar surfaced.
- [ ] **Performance baselines on reference hardware.** Quoted in
      the README trade-off table and the `compare/postgresql`
      website page. Bench harness already exists; v0.9.0 publishes
      numbers (single-node read/write throughput, consensus
      latency on a 3-node VSR cluster, audit-chain verification
      cost). Closes the qualitative-only gap for founders
      evaluating Kimberlite for production workloads.

(Plus the items below carried forward from the v0.7.0 deferred
section — re-evaluate at v0.9.0 cycle planning.)

---

## Released

### v0.8.0 (2026-05-06)

- ✅ Typed unique-constraint error end-to-end —
  `QueryError::DuplicatePrimaryKey { table, key }` plumbed through
  `ErrorCode::UniqueConstraintViolation` on the wire, FFI, and
  per-SDK error class (Rust / TS / Python)
- ✅ `requestId` exposed to the per-stream callback on
  `eraseSubject` (TS additive 2nd arg; Python arity-detected;
  Rust closure type bumped — pre-1.0 SDK breaking change
  documented in CHANGELOG)
- ✅ `Effect::ProjectionRowsPurge { tenant_id, table_id }` —
  DROP TABLE now actually purges projection rows (un-`#[ignore]`d
  the `tests/catalog_staleness.rs::drop_table_purges_projection_rows`
  regression net)
- ✅ `streamLength(streamId)` / `stream_length(stream_id)` —
  O(1) row count via new `StreamInfoRequest` /
  `StreamInfoResponse` wire frames (TS + Rust; Python parity in
  v0.9.0)
- ✅ TS bindings for v0.7.0 typed primitives —
  `sdks/typescript/src/typed-primitives.ts` exposes type
  definitions, constructors that enforce Rust-side invariants,
  and SQL fragment builders for `Interval`,
  `AggregateMemoryBudget`, `SubstringRange`, `DateField`
- ✅ `audit.verifyChain()` server-walked attestation — replaces
  the v0.5.0 / v0.6.0 hardcoded `{ ok: true }` stub with a real
  SHA-256 hash-chain walk; new
  `VerifyAuditChainRequest` / `Response` wire frames; populated
  `eventCount` / `chainHeadHex` / `firstBrokenAt` (TS + Rust;
  Python parity in v0.9.0)
- ✅ `audit.subscribe()` polling iterator (TS) — replaces the
  no-op stub; polls `audit.query()` at `intervalMs` cadence with
  high-water timestamp tracking and `AbortSignal` cancellation
  (Rust + Python in v0.9.0)
- ✅ `tla2tools.jar` SHA pin re-bumped (#132); Dependabot
  rust-minor group of 27 crate bumps (#133); GitHub Actions
  group bump (#124)

### v0.7.0 (2026-05-04)

- ✅ Catalog staleness on DROP+CREATE same name — fixed via
  symmetric `Effect::TableMetadataDrop` rebuild
- ✅ Inverted-range planner output — fixed at the lowering source
  via `RangeBoundsResult::is_empty`; `kimberlite-store::btree::scan`
  debug_assert restored unconditionally (no `cfg(fuzzing)` escape)
- ✅ `DELETE FROM t` (no WHERE) `rowsAffected` postcondition
  `assert_eq!` + integration test
- ✅ `MOD`, `POWER`, `SQRT`, `SUBSTRING`, `EXTRACT`, `DATE_TRUNC`
  scalar functions (production-grade evaluator + parser)
- ✅ `NOW()` / `CURRENT_TIMESTAMP` / `CURRENT_DATE` sentinel
  variants + plan-time-fold contract (production wiring lands
  v0.8.0)
- ✅ `Interval { months, days, nanos }` typed primitive with
  Kani-friendly arithmetic + companion proofs
- ✅ `AggregateMemoryBudget(u64)` typed primitive replacing
  `MAX_GROUP_COUNT` const; structured `AggregateMemoryExceeded`
  error
- ✅ `DateField` closed enum + `SubstringRange` typed primitive
- ✅ Auto-generated traceability matrix from `AUDIT-YYYY-NN`
  markers (`audit-matrix` tool + `audit-matrix-check` CI gate)
- ✅ `validate-publish-order` topological checker
  (`tools/publish-order-check/`) — found and fixed real
  ordering bug (test-harness vs client/server)
- ✅ 16 scaffolded VOPR scenarios across `Masking*` / `Upsert*` /
  `AsOfTimestamp*` / `EraseAutoDiscovery*` families
- ✅ `ScalarPurity.tla` formal-verification spec + companion
  property tests (Determinism / NoIO / NullPropagation /
  CastLossless meta-theorems)
- ✅ Cookbook examples for subscriptions, secondary-index, and
  consent-decline flows (TS + Python)
- ✅ Python SDK floor bumped 3.9 → 3.10 (PEP 604 + Self via
  typing_extensions unblocked)
- ✅ MIRI annotation for heavy AES-GCM roundtrip test (closes
  nightly-lite timeout regression)
- ✅ `release-tag-sign` justfile recipe (GPG-signed tags)

---

## v0.7.0 — released

Scheduled for the first minor after v0.6.0. All items below were
deliberately deferred from v0.6.0 to keep that release focused on the
feature-complete compliance surface.

### SQL

- [ ] Additional scalar functions: `MOD`, `POWER`, `SQRT`, `SUBSTRING`,
      `EXTRACT`, `DATE_TRUNC`, `NOW()`, `CURRENT_TIMESTAMP`,
      `CURRENT_DATE`, plus interval arithmetic. Requires a clock
      threading decision for VOPR-sim-vs-wall-clock (separate design
      conversation).
- [ ] `DELETE FROM t` (no WHERE) `rowsAffected` fix.
      Test-infrastructure impact only. (`DROP TABLE IF EXISTS`
      shipped in v0.6.2 alongside the integration-test cleanup.)
- [ ] **Catalog staleness on DROP+CREATE same name.** Recreating a
      table by the same name within a single connection leaves
      stale planner state — parameter-bound INSERT into the
      recreated table fails with `QueryParseError: SQL syntax
      error`. v0.6.2 sidestepped it in the integration suites with
      unique-per-test table names; the proper fix is to invalidate
      whatever cache (planner / catalog snapshot / table-id resolver)
      retains the dropped table's binding. Reproducer:
      `DROP TABLE t; CREATE TABLE t (...); INSERT INTO t (...)
      VALUES ($1, ...)` — the second INSERT's parameter binding
      hits the stale catalog. Found by: notebar integration test
      cleanup loop.
- [ ] Auto-generated traceability matrix from in-source `AUDIT-YYYY-NN`
      markers (currently manual).
- [ ] SQL planner — prevent inverted range output. `fuzz_sql_norec`
      currently triggers an `if range.start > range.end` path in
      `kimberlite-store::btree::scan` that the debug assert surfaces as
      a planner correctness warning. Release builds clamp to empty, so
      results are still correct; the v0.6.1 patch disables the assert
      under `cfg(fuzzing)` to unblock CI. Track down which predicate
      lowerings emit the inverted range and fix upstream.
- [ ] **GROUP BY scale ceiling.** `MAX_GROUP_COUNT = 100_000` in
      `crates/kimberlite-query/src/executor.rs:54` is a hard error
      rather than a degradation, and aggregation is fully in-memory
      (`HashMap<Vec<Value>, AggregateState>`). Replace the const with
      a configurable `aggregate_memory_budget_bytes` (default 256 MiB,
      ≈ 1M groups), and replace the panic-style error with a
      structured `AggregateMemoryExceeded { budget, observed }` whose
      message names the knob. Pushes the ceiling out ~10× without a
      planner overhaul. Proper spill-to-disk hash aggregate is
      tracked under Deferred (v0.8.0). Found by: notebar GST report
      drill-down on `ar_ledger`.
- [ ] **Expression-index note (no v0.7.0 work).** `CreateIndex.columns`
      in `crates/kimberlite-kernel/src/command.rs` carries bare
      column names (`Vec<String>`); expressions like
      `DATE_TRUNC('month', created_at)` cannot be indexed today.
      Surfacing this requires an index-definition AST plus an
      evaluator on the write path — too large for v0.7.0. Tracked
      under Deferred for v0.8.0 so consumers know not to rely on
      it. (Equality / range indexes on plain columns already work end
      to end via `find_usable_indexes` → `IndexScan` in
      `crates/kimberlite-query/src/planner.rs:1373-1383`.)

### SDK & DX

- [ ] Go SDK — deferred post-v0.4 in README; brings Kimberlite to
      parity with the TS / Python / Rust trio.
- [ ] SDK connection-pool metrics + Prometheus exporter parity.
- [ ] Python SDK typing refresh (PEP 604, Self types, Protocol-based
      plugins).
- [ ] **Cookbook examples for already-shipped primitives that
      downstream consumers keep missing.** Notebar filed gap reports
      for two features that are already implemented end-to-end —
      because nothing in `examples/` or the SDK README pointed at
      them. Ship one runnable TS example per primitive, linked from
      the SDK README:
      - **Real-time subscriptions.** `client.subscribe(streamId, {
        startOffset })` from `sdks/typescript/src/subscription.ts` is
        an `AsyncIterable<SubscriptionEvent>` with credit-based flow
        control; wire frame + server handler shipped in earlier v0.x.
        Notebar still believes the client is pull-only.
      - **Secondary-index lookup by non-PK column.**
        `CREATE INDEX ON projection(provider, providerMessageId)`
        followed by a `SELECT … WHERE provider = ? AND
        providerMessageId = ?` — the planner already emits
        `IndexScan` via `find_usable_indexes` /
        `select_best_index` (`crates/kimberlite-query/src/planner.rs`).
      - **`recordConsent` round-trip.** Once the v0.6.2 fields
        (`termsVersion`, `accepted`) land, ensure an example
        demonstrates the full grant + audit-query flow.
      Goal: the next consumer integrating Kimberlite finds the
      answer in `examples/` instead of filing a gap report.

### Testing & verification

- [ ] VOPR workload generators for the v0.6.0 command families —
      `Masking*`, `Upsert`, `AS OF TIMESTAMP` resolution,
      `eraseSubject` auto-discovery. Kernel-level correctness is
      covered by unit + integration tests; this closes the
      storage-realism + protocol-attack coverage gap documented at
      `docs-internal/audit/2026-Q2-release-readiness.md`.
- [ ] Formal-verification specs for scalar-expression purity.
- [ ] VOPR scenarios for SQL-surface semantics (beyond the Tier 1 / 2
      scenarios already landed in v0.6.0).
- [ ] Investigate fuzz-target slow inputs. `fuzz_kernel_command` and
      `fuzz_abac_evaluator` have corpus entries that take 20+ minutes
      per iteration on the 2-vCPU GitHub runner. v0.6.1 raised the
      libFuzzer per-input timeout above the per-target wall-clock
      budget so these don't false-positive as crashes, but the
      underlying perf signal is real and worth chasing — either the
      corpus has accumulated pathological inputs that should be
      pruned, or there's an O(n^k) blowup in the kernel command
      apply-path on certain shapes.

### Infrastructure

- [ ] Topological-order validation for `PUBLISH_CRATES` in `justfile`
      (compare against `cargo metadata`).
- [ ] Performance re-baseline against current hardware — I/O
      throughput, consensus latency, SQL query throughput.
- [ ] GPG-signed release tags by default.
- [ ] MIRI nightly-lite runtime exceeds the service's
      `TimeoutStartSec=5400` (90 min). Root cause is MIRI's
      interpretation overhead on crypto-roundtrip tests (e.g.
      `encryption::tests::large_plaintext_encryption`) — not a
      proptest/isolation issue. Consider annotating the heaviest
      tests with `#[cfg_attr(miri, ignore)]` or narrowing MIRI scope
      (MIRI's main value is UB via pointer/lifetime interpretation,
      not arithmetic correctness on AES-GCM). As a stopgap, bump
      `TimeoutStartSec` to 10800 and accept that the FV/fuzz overlap
      window will trip `Conflicts=kimberlite-fuzz-nightly.service` —
      or shift the FV timer earlier so both finish before fuzz fires
      at 02:00 UTC.

---

## Deferred

Items we're not working on now. Revisit at v0.8+ or v1.0 planning.

- **Transactions** (`BEGIN` / `COMMIT` / `ROLLBACK`, including
  multi-stream atomic appends) — single statements are atomic;
  event-sourcing + optimistic concurrency covers current consumers.
  Notebar's Phase 4 POS flow (issue invoice + decrement stock across
  two streams) is the first concrete v1.0 motivator; outbox pattern
  remains the documented workaround for v0.7.0. The single-writer-
  per-tenant VSR model makes cross-stream atomicity a non-trivial
  design tension — `AppendBatch` in
  `crates/kimberlite-kernel/src/command.rs:89-94` is single-stream
  by construction. If notebar Phase 8 claim reconciliation hits a
  half-success the outbox can't tolerate, escalate to a v1.0 design
  doc before v1.0 freeze. Re-evaluate against v1.0 if scope is
  manageable.
- **Window functions beyond what shipped** — ROWS BETWEEN clauses,
  EXCLUDE, window-aggregate frame defaults. Current `ROW_NUMBER` /
  `RANK` / `LAG` / `LEAD` / `FIRST_VALUE` / `LAST_VALUE` with
  `PARTITION BY` / `ORDER BY` covers the common cases.
- **Linearizability chaos testing** — currently labelled a liveness
  proxy in code. Full linearizability testing deferred pending a
  design conversation about what "linearizable" means in the
  single-writer-per-tenant model.
- **Physical stream deletion** — soft-delete + retention only for
  now. Physical deletion conflicts with the "all data is an
  immutable ordered log" principle; needs a careful design for how
  retention horizons interact with `AS OF TIMESTAMP` and audit
  witnesses.
- **Unbounded audit-log query surface** — current queries are
  paginated + bounded. Unbounded retrieval deferred until we decide
  how it interacts with retention + compliance export formats.
- **Antithesis integration** — paid service. Worth evaluating
  post-v1.0 once revenue supports it; current VOPR + fuzz nightly
  on EPYC covers the cost-effective window.
- **Snapshots** — gated on real-usage benchmarks from the first
  v0.7.0 consumer (notebar). We need aggregate size distribution,
  replay cost per 1k events, read-vs-write frequency, and
  worst-case long-lived-aggregate profiles before designing the
  snapshot primitive. Re-evaluate after the consumer runs on
  v0.7.0 for 2–4 weeks and produces those benchmarks.
  Correctness primitive (bounded recovery, deterministic
  reconstruction under formal verification), not just a
  perf optimisation — the design needs those numbers to land
  correctly the first time.
- **User-defined materialised projections** — notebar wants
  `practitioner_hours_by_day` (currently compute-on-read in their
  `repos/practitioner-hours.ts`) and a typed `communications`
  projection registered as kernel-managed views. Today
  `ProjectionStore` in `crates/kimberlite-store/src/lib.rs` is
  system-internal; surfacing a `Cmd::CreateProjection` plus a SQL
  `CREATE MATERIALIZED VIEW` plus a refresh scheduler is ~1000+ LOC
  across kernel, query, and store, and needs a design doc that
  reconciles refresh semantics with the immutable-log model.
  Re-evaluate at v0.8 — this is a kernel primitive, not a patch.
- **Spill-to-disk hash aggregate** — proper fix for the GROUP BY
  ceiling that v0.7.0 only widens with a memory-budget knob (see
  v0.7.0 SQL section). When notebar's GST drill-down or any future
  consumer's aggregate workload approaches the budget, this becomes
  the real fix. Re-evaluate at v0.8.0.
- **Expression indexes** — `CreateIndex.columns` carries bare
  identifier strings today, so `DATE_TRUNC('month', created_at)`
  cannot be indexed. Needs an index-definition AST that survives
  parse → kernel → executor, plus an evaluator on the write path so
  index entries reflect the expression result. Re-evaluate at v0.8.0
  alongside the materialised-projection work — they share planner
  infrastructure.
- **Blob storage adapter abstraction** — Kimberlite's storage layer
  is the event log by design; `docs/reference/sql/ddl.md` already
  directs consumers to keep blobs out of the log. Notebar's
  `document-store.ts` hardcoding S3 is the intended pattern, not a
  workaround. Defer to v1.0+; revisit only if a compliance use case
  (signed-blob retention with audit witnesses, GDPR-erasure
  integration spanning blob lifecycle) requires kernel-level blob
  primitives. A backend-adapter trait alone (S3 / GCS / Azure /
  MinIO) is a community-extension shape, not a core primitive.
- **Document content search / full-text index** — `LIKE` / `ILIKE`
  in `crates/kimberlite-query/src/plan.rs::matches_like_pattern`
  cover pattern matching; there is no tokenizer, inverted index,
  `MATCH` operator, or ranking. From-scratch subsystem
  (tokenization + stemming pipeline, inverted-index storage,
  `MATCH` syntax, real-time index maintenance on append). Notebar's
  Phase 9 explicitly cuts content search. Defer to v1.0+ pending
  consumer demand and a clear story for how FT interacts with
  retention + erasure.

---

## v1.0 — checklist-gated

v1.0 ships when **every** item below is green. No date. If an item
proves unnecessary, it's removed from this checklist via a pull
request with justification, not quietly dropped.

### Third-party attestations

- [ ] SOC 2 Type II audit completed with a clean report.
- [ ] HIPAA attestation + a BAA partner willing to use Kimberlite
      as a healthcare database of record.
- [ ] GDPR readiness review by an independent privacy counsel.
- [ ] At least one healthcare production deployment (clinical IT,
      payer / RCM, or clinical research) running Kimberlite as the
      system of record, not a secondary store.

### SDK coverage

- [ ] Rust, TypeScript, Python — all three at SDK parity with
      Kimberlite's server surface. Verified by the SDK parity matrix
      at `docs/reference/sdk/parity.md`.
- [ ] Go SDK at parity.
- [ ] Java SDK — at least Phase 1 (core client + auth + queries).
- [ ] C++ SDK — via the existing FFI header + thin idiomatic
      wrapper.

### Formal verification

- [ ] Coq → Rust extraction pipeline producing verified cryptographic
      primitives, not just hand-written impls with Coq specs.
- [ ] Ivy → Apalache migration complete — Ivy's UX is blocking and
      Apalache gives us a clearer path to bounded model-checking.
- [ ] All TLA+ theorems PR-gated (currently: core subset PR-gated,
      92 compliance meta-theorems nightly). Target: 100% PR-gated.
- [ ] Kani proof count sustained ≥90 with coverage growing
      per-release.

### Performance

- [ ] Throughput baseline published for standard workloads on the
      reference hardware tier (EPYC 7xx3 series, 64 GB RAM,
      NVMe SSD).
- [ ] Latency baseline for consensus commit, SQL point-read, SQL
      point-write, and audit-log append.
- [ ] Benchmark reproduction kit in `benches/` that third parties
      can run against their own hardware.

### Operational maturity

- [ ] Documented disaster-recovery procedure with tested runbooks.
- [ ] Documented upgrade path for every v0.x → v0.(x+1) migration
      (not just breaking ones) with end-to-end validated smoke test.
- [ ] On-call rotation playbook (for self-hosters, not a managed
      service).
- [ ] Observability dashboards — Prometheus + Grafana templates for
      VSR consensus health, storage I/O, SQL query latency,
      compliance-event rates.

### Documentation

- [ ] A published book or long-form tutorial covering "design a
      compliance-backed app on Kimberlite" end-to-end.
- [ ] Reference architectures for HIPAA, PCI DSS, and GDPR
      deployments.
- [ ] Every API in the SDK parity matrix has runnable, tested
      examples in Rust, TypeScript, and Python.

---

## Post-v1.0

### Managed cloud

Kimberlite Cloud — managed database service — is planned for after
v1.0. The OSS core stays OSS. Cloud adds ops, scaling, billing, UI,
and a compliance-ready shared-responsibility model. Similar model to
CockroachDB Serverless / MongoDB Atlas / Supabase Platform layered on
Postgres.

Exact pricing + infrastructure vendor + geographic availability are
not yet settled. This roadmap is the commitment that the OSS core
will remain independently usable with the same feature set as the
cloud service.

### Continuous improvement

These items ship opportunistically once v1.0 lands — not gated on
specific versions.

- Performance improvements as real workloads expose bottlenecks.
- Additional compliance-framework formal specs as regulation
  evolves (EU AI Act, DORA deepening, APRA CPS 230/234
  refreshes).
- Deeper VOPR scenario coverage as production incidents surface
  new bug classes.
- Protocol evolution — wire v5 when a new feature needs it.
- Additional language SDKs driven by demand.

---

## How to propose a roadmap change

- **Adding an item to v0.7.0:** open a GitHub issue with the label
  `target:v0.7.0`, link a design doc if the change is non-trivial,
  then submit a PR against this file.
- **Adding an item to the v1.0 checklist:** the bar is high.
  v1.0 gates should represent the minimum for a healthcare
  production deployment. Open an issue with the label
  `v1.0-gate-proposal` and expect pushback.
- **Removing a v1.0 gate:** requires a design discussion. Open an
  issue with the label `v1.0-gate-remove` and a written
  justification.
- **Deferring a v0.7.0 item:** move it to the Deferred section with a
  one-line reason. Don't quietly drop.

## Related documents

- [`CHANGELOG.md`](./CHANGELOG.md) — what shipped in each release.
- [`VERSIONING.md`](./VERSIONING.md) — SemVer policy, breaking-change
  rules, deprecation windows.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to submit changes.
- [`SECURITY.md`](./SECURITY.md) — vulnerability reporting.
- `docs-internal/audit/` — internal audit trail (compliance,
  release-readiness).
- `docs-internal/design-docs/active/` — active design discussions.
