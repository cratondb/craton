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

**Current release:** `v0.9.0` (2026-05-18) — healthcare-pivot
release. Kimberlite is now positioned exclusively as a verifiable
database for healthcare (EHR / payer-RCM / clinical research /
digital health), with GDPR / SOC 2 / ISO 27001 / FedRAMP as overlay
frameworks. Q1 (FHIR R4 + SMART-on-FHIR), Q2 (HL7 v2 + cluster HA),
and Q3 (Safe Harbor de-identification + KMS provider trait + X12
envelope + pediatric retention) all landed. Pivot-cleanup sweep
purged finance / legal / government framing from the website, docs,
and SDK descriptions; SOX / GLBA / FERPA / CMMC / NIS2 / DORA /
eIDAS / IRAP frameworks marked explicitly out of product scope.
PRESSURECRAFT Wave 3 complete (all 10 Bucket-C panicking
`pub fn new()` sites migrated to paired `try_new()`). Six
healthcare VOPR scenarios promoted out of `aspirational_v07` to
real fault drivers. Four healthcare fuzz targets added (FHIR, X12,
Safe Harbor de-id, audit signature round-trip). New
`specs/tla/Healthcare.tla` adds four healthcare-specific
invariants gated in PR CI. See [`CHANGELOG.md`] for the full list.

**Next release:** v0.10.0 — Firecracker / KVM multi-node DST on
Hetzner EPYC, KMS production backends (AWS / Azure / GCP),
geo-fencing enforcement layer, full X12 837 claim-loop schemas.

**Target v1.0:** when the gates below close. No fixed date — we ship
when the third-party audits, SDK coverage, and production readiness
criteria are all green.

[`v0.6.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.6.0
[`v0.7.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.7.0
[`v0.8.0`]: https://github.com/kimberlitedb/kimberlite/releases/tag/v0.8.0
[`docs-internal/design-docs/active/cluster-graduation-v0.9.x.md`]: docs-internal/design-docs/active/cluster-graduation-v0.9.x.md

---

## v0.10.0 — in-flight

The v0.10.0 cycle is the production-hardening release. v0.9.0
finished the healthcare positioning + the Q1/Q2/Q3 feature wedge;
v0.10.0 turns the design surfaces shipped in v0.9.0 into
production-ready substrate.

### Scoped for v0.10.0 (from v0.9.0 deferral decision)

- [ ] **Hypervisor-based multi-node DST on Hetzner EPYC.**
      Today's `kimberlite-sim` runs in-process; EPYC nightly uses
      EPYC for CPU-hour capacity, not VM-level instrumentation.
      Build a Firecracker / KVM harness that boots a real 3-node
      cluster in microVMs, kills a VM mid-write, and asserts
      recovery via VSR view-change against the existing log /
      audit / projection invariants. Pairs the in-process VOPR
      (deep, fast) with VM-isolated DST (high-fidelity, slower).
      Dependency: `kimberlite-chaos` + cluster supervisor must
      stay stable. Estimated ~4 weeks; design doc lands first.
- [ ] **KMS production backends (AWS / Azure / GCP).** v0.9.0
      shipped the `KmsProvider` trait + a file-backed dev
      provider in `kimberlite_crypto::kms`. v0.10.0 ships first-
      class implementations: AWS KMS via `aws-sdk-kms`, Azure
      Key Vault via `azure_security_keyvault`, GCP KMS via
      `google-cloud-kms`. Each behind an off-by-default cargo
      feature so the default binary stays dependency-light.
      Order: AWS KMS first (most common BYOK ask for federal-
      touching healthcare), then Azure (VA / DoD MTF tenants),
      then GCP. Includes a KEK-rotation property test against
      each backend's mock.
- [ ] **Geo-fencing / data-sovereignty enforcement layer.**
      v0.9.0 ships `PlacementPolicy` as an API surface;
      v0.10.0 ships the enforcement layer that rejects
      cross-region replication when a stream is region-pinned.
      Touches `kimberlite-directory` (placement routing) and
      `kimberlite-vsr` (replica selection). Use case: BAA
      jurisdictional gates (US-only data must not replicate
      to EU read replicas; AU patient data must stay in
      ap-southeast-2). New TLA+ property: `PlacementInvariant`
      in `Healthcare.tla` extension.
- [ ] **Full X12 837 claim-loop schemas.** v0.9.0 ships envelope
      + segment-iterator only (sufficient for ingest + audit-event
      emission). v0.10.0 adds typed loop schemas for the deep
      structure of 837P (professional), 837I (institutional), and
      837D (dental) — the 1000+ segment loop catalog with
      submitter / subscriber / patient / provider / claim-detail /
      service-line decomposition. Plus the first-pass 837 writer.
      Marker for full schemas was previously v0.11+; promoted to
      v0.10 to unblock first-class clearinghouse adapters.

### Carried over from v0.9.0 (did not ship in v0.9.0 cut)

These items were declared in-flight at the start of the v0.9.0
cycle but the healthcare pivot took priority; each lands in v0.10:

- [ ] **Go SDK — Phase 1.** `Connect`/`Query`/`Append`/`Read`/
      `Subscribe`/`Pool` over the existing FFI bridge.
      Scaffolding lives at `sdks/go/`. Phase 2 (compliance) and
      Phase 3 (typed primitives + framework integrations)
      follow inside v0.10.x → v1.0.
- [ ] **Plan-time time-fold production wiring.** v0.7.0 shipped
      the `ScalarExpr::Now` / `CurrentTimestamp` / `CurrentDate`
      sentinel variants with `#[should_panic]` tests verifying
      the evaluator panics if reached unfolded. The planner-side
      `fold_time_constants` pass needs to be implemented and
      wired into `tenant.rs::execute`.
- [ ] **VOPR scenario drivers for the remaining 11 v0.7.0
      scaffolds.** v0.9.0 promoted the 6 healthcare clinical
      scenarios + the 5 cluster scenarios; 11 of the original 16
      `Masking*` / `Upsert*` / `AsOfTimestamp*` /
      `EraseAutoDiscovery*` scaffolds still delegate to
      `aspirational_v07`. Land one driver per family.
- [ ] **Pool metrics — client-side Prometheus parity.** Server-
      side metrics already exist at
      `crates/kimberlite-server/src/metrics.rs`; the TS /
      Python / Rust client-side surface is still pending.
      AWS-ECS-friendly: text-format `pool.metrics()` consumed
      by CloudWatch Prometheus source.
- [ ] **Python parity for v0.8.0 deliveries.** `streamLength`
      (O(1) row count), typed primitive bindings (`Interval`,
      `SubstringRange`, `DateField`, `AggregateMemoryBudget`),
      and `audit.verifyChain` / `audit.subscribe`.
- [ ] **Rust `audit.subscribe` polling iterator.** TS shipped
      in v0.8.0; Rust client + Python parity follow here.
- [ ] **Performance baselines on reference hardware.** Quoted
      in the README trade-off table and the `compare/postgresql`
      website page. Bench harness already exists; v0.10.0
      publishes numbers (single-node read/write throughput,
      consensus latency on a 3-node VSR cluster, audit-chain
      verification cost).

---

## Released

### v0.9.0 (2026-05-18)

The healthcare-only release. Kimberlite is no longer positioned as a
generic compliance database — every primitive is now sized to HIPAA,
with GDPR / SOC 2 / ISO 27001 / FedRAMP as overlay frameworks.
SOX / GLBA / FERPA / CMMC / NIS2 / DORA / eIDAS / IRAP marked
explicitly out of product scope (specs retained for historical
reference). Full detail in [`CHANGELOG.md`].

- ✅ **Sprint 1 — strip.** Finance / legal examples deleted; README,
  ROADMAP, docs, examples README, blog posts, and website templates
  rewritten around the clinical/EHR-adjacent wedge. Studio
  playground collapsed to a single healthcare tenant. Residual
  `tenant-{finance,legal,government,retail,insurance}` CSS selectors
  pruned. (`eb5a57f`, plus pivot-sweep cleanup)
- ✅ **Sprint 2 — healthcare-first defaults.** New streams default
  to `DataClass::PHI`, audit-on, retention=6y, encryption-required.
  Purpose-of-use enum extended with HIPAA TPO + `Research`,
  `PublicHealth`, `Emergency`. `BreakGlassActivated` /
  `BreakGlassClosed` audit events with mandatory justification.
  Audit-log retention promoted to a distinct policy class
  (HIPAA §164.530(j)(2)). (`4b8590e`)
- ✅ **Q1 — FHIR + SMART on FHIR.** `kimberlite-fhir` crate (R4
  typed resources, canonical JSON, FHIRPath subset),
  `kimberlite-fhir-store` (FHIR ↔ Kimberlite event + projection
  adapter), `kimberlite-rbac` SMART scope parsing + `authorize()`
  + JWT validation. `examples/ehr_mini` + `examples/smart_on_fhir_app`
  shipped, plus the "FHIR-native, verifiable" blog post.
  (`fa782d0`, `08bc9ab`, `dc828c2`, `1379af2`)
- ✅ **Q2 — HL7v2 + cluster HA graduation.** `kimberlite-hl7v2`
  crate (parser, encoder, MLLP framing, typed ADT^A01) +
  `examples/hl7v2_feed`. Clinical + cluster VOPR scenarios
  promoted out of aspirational. `kimberlite-cluster` graduated
  from "not ready for public use" through the T1 → T3 punch list.
  (`e45ebe6`, `4a7237e`, `6c878a8`, `f1fd8df` … `19e1e5e`,
  `2993ff6`, `53e504b`)
- ✅ **Q3 — moat layer.** HIPAA Safe Harbor de-identification
  (`kimberlite_compliance::deidentification` + `DeidentificationApplied`
  audit event), `kimberlite_crypto::kms` (`KmsProvider` trait +
  AWS/GCP/Azure integration docs + in-memory mock + KEK rotation),
  `kimberlite-x12` crate (837P/I/D + 835 envelope + typed wrappers),
  pediatric birthdate-anchored retention (`PediatricRetention` +
  per-state age-of-majority override), `claims_mini` +
  `research_mini` examples. (`5d5d8bd`)
- ✅ **Release sweep.** PRESSURECRAFT Wave 3 (10/10 Bucket-C
  panicking `pub fn new()` migrated to paired `try_new()` per
  `docs-internal/contributing/constructor-audit-2026-04.md`); 6
  healthcare VOPR scenarios promoted from `aspirational_v07` to
  real fault drivers; 4 new fuzz targets (FHIR R4, X12 envelope,
  Safe Harbor de-id, audit signature round-trip);
  `specs/tla/Healthcare.tla` with 4 healthcare-specific invariants
  (SafeHarborCoverage, BreakGlassAuditOrder, ConsentRevocationCausality,
  NoPhiReadAfterRevocation) gated in PR CI. (`62385c1`)

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
- **Cluster T4 nice-to-haves (post-v0.9.x graduation).** Captured
  here so the v0.9.x cluster-graduation design doc can be archived
  cleanly once T1–T3 close. Each is a discrete v1.0+ work item with
  its own dependencies:
  - **Multi-region topology** — cross-AZ replication latency
    simulation in VOPR + transport-layer accommodations for
    higher-latency links. Today's `MultiNodeReplicator` assumes
    same-AZ latencies; cross-AZ pushes view-change timeouts and
    quorum-write tail-latency budgets in ways that need a design
    pass before code. Dependency: real customer requirement
    (federated hospital network, multi-region payer).
  - **Hot-standby read replicas surfaced through the SDK with
    read-your-writes semantics** — extends the existing standby
    work (`StandbyFollowsLog` / `StandbyPromotion` / `StandbyReadScaling`
    VOPR scenarios) to a first-class SDK surface: client opts into
    read-from-replica, the SDK injects causality tokens so a
    follow-up read sees its own write. Dependency: protocol-version
    bump for the causality token, SDK API design for opt-in.
  - **Web admin UI for cluster topology + per-node health.** Folds
    into the existing `kimberlite-studio` surface — adds a topology
    view that consumes the T1.2 `/healthz` + `/readyz` + `/metrics`
    endpoints + a per-node panel. Dependency: `kimberlite-studio`
    reaching v1 itself (currently scoped for v0.10.x).
  - **Backup encryption tied to the customer-managed key story
    (BYOK).** Today's T2.2 backup archives are zstd-compressed but
    not encrypted at rest. Production deployments either accept
    encryption-at-the-storage-layer (S3 SSE) or want a customer-
    managed key directly bound to the archive. Dependency: the
    BYOK / external-KMS Q3 deliverable (`ROADMAP.md` v0.10.x
    section); design wraps the archive in an AES-256-GCM envelope
    keyed by the customer's KMS.
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
