# Changelog

All notable changes to Kimberlite are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Kimberlite uses [Semantic Versioning](https://semver.org/). Breaking
changes are called out in a `### Breaking changes` section at the top
of each release block — see [`VERSIONING.md`](./VERSIONING.md) for the
SemVer policy and deprecation windows.

Internal audit trails and design campaigns live under
[`docs-internal/`](./docs-internal/) and are not duplicated here. The
git log is the authoritative per-commit record; this file is the
user-facing narrative.

## [Unreleased]

_Accretion slot for v0.10.0 work. See [`ROADMAP.md`](./ROADMAP.md)
for planned scope (Firecracker/KVM multi-node DST, KMS production
backends, geo-fencing enforcement, full X12 837 loop schemas)._

## [0.9.1] — 2026-05-20

Patch release for two upstream bugs notebar surfaced while upgrading
from v0.8.0 → v0.9.0. Both are silent data-corruption / silent-write
failure modes promoted to typed, actionable errors at the wire and
SDK layer.

### Fixed

- **`StreamId` u32 truncation contract.** `StreamId::from_tenant_and_local`
  packs `tenant_id` into the upper 32 bits of a `u64` and silently
  truncated values above `u32::MAX`. Two tenants whose ids collided in
  the lower 32 bits collapsed onto the same `StreamId`, producing a
  misleading `StreamAlreadyExists` later in the flow (or — worse —
  cross-tenant data leak through any per-tenant filter that consumed
  `StreamId.tenant_id()`). Notebar tripped it on macOS PIDs > 2^15
  where the `pid << 16 + counter` tenant-id scheme overflowed u32.
  - New `kimberlite_types::StreamIdEncodingError` + `pub const
    MAX_TENANT_ID_FOR_STREAM_ID` documenting the encoding ceiling.
  - New `StreamId::try_from_tenant_and_local() -> Result<_, _>`
    fallible constructor for any caller that receives `tenant_id`
    from outside (SDK boundary, wire deserialisation, fuzz harness).
  - Existing `StreamId::from_tenant_and_local` kept as a
    `#[track_caller]` shim that panics on overflow (debug builds
    catch it loudly; production gets a clear panic message instead
    of silent truncation).
  - `tenant.create_stream` rejects overflow up-front with the new
    typed `KimberliteError::TenantIdTooLarge { tenant_id, max }`.
  - New wire `ErrorCode::TenantIdTooLarge = 30` mapped through the
    server handler.
  - TS SDK exposes `TenantIdTooLargeError` typed class.
  - Tests: `test_create_stream_rejects_tenant_id_above_u32_max` +
    `test_create_stream_accepts_tenant_id_at_u32_max` boundary pair.
- **B+tree single-entry overflow → typed error.** When the same
  primary key is upserted many times the row's MVCC version chain
  grows unbounded. A hot row updated dozens of times accumulates a
  `LeafEntry` whose `serialized_size` exceeds the page byte budget
  (4096 − header − CRC = 4048). `bcba460` added byte-budget splitting
  for the *many-rows* case but couldn't help the *one-fat-row* case
  — both halves of any split still hold the same fat entry. v0.9.0
  surfaced it as the generic `StoreError::PageOverflow` ("page
  overflow: need 4195 bytes, have 4048") which gave SDK callers no
  actionable signal; notebar's seed loop was silently dropping
  writes.
  - New typed `StoreError::EntryTooLarge { key, entry_size,
    page_budget }` variant carrying the offending key + sizes.
  - `LeafNode::to_page` detects the case up-front (before any
    partial write) and emits a `tracing::error!` so operators see
    it even if a caller swallows the error.
  - New wire `ErrorCode::RowVersionChainTooLarge = 31`.
  - TS SDK exposes `RowVersionChainTooLargeError` typed class with
    mitigation guidance (rate-limit hot keys, rotate keys, use the
    event stream as source of truth) — proper version-chain
    compaction driven by a retention horizon is v0.10.0 work.
  - Test: `test_same_key_many_versions_does_not_silently_drop`.

### Maintenance

- `tla2tools.jar` SHA-256 bump in `.github/workflows/formal-verification.yml`
  to track upstream's v1.8.0 asset rebuild (was `e47073579d0f…`,
  now `25780ac9578e…`). The TLA+ Toolbox CI republishes the jar
  every few weeks; pin updated to match the API-reported digest.
  (`ef5cdb3`)
- ROADMAP.md restructured: v0.9.0 moved from "in-flight" to
  "Released" with completion markers; new "v0.10.0 — in-flight"
  section scopes the four healthcare-pivot-deferred items
  (Firecracker DST, KMS production backends, geo-fencing
  enforcement, full X12 837 claim-loop schemas) plus the seven
  carried-over items (Go SDK Phase 1, plan-time time-fold,
  remaining v0.7.0 scaffolds, pool metrics parity, Python parity,
  Rust audit.subscribe, reference-hardware perf baselines); the
  stale duplicate v0.7.0 planning block was deleted. (`7576d0b`)
- Python SDK `pyproject.toml` version bumped to 0.9.0 (was missed
  in the initial v0.9.0 sweep because the Python SDK has its own
  pin, not workspace-tied). (`dd2f703`)

## [0.9.0] — 2026-05-18

The healthcare-only release. Kimberlite is no longer positioned as a
generic compliance database — every primitive is now sized to HIPAA,
with GDPR / SOC 2 / ISO 27001 / FedRAMP as overlay frameworks for
healthcare SaaS that need them.

### Healthcare pivot — release sweep (v0.9.0 cut)

The Q1 (FHIR R4 + SMART-on-FHIR), Q2 (HL7 v2 + cluster HA), and Q3
(Safe Harbor de-id + KMS + X12 + pediatric retention) chapters of the
healthcare pivot all land in v0.9.0. Plus the release-sweep additions
listed below.

- **Pivot cleanup (L1–L10).** Purged finance/legal/government framing
  from the live website (deleted `/finance` route, handler, and
  template; rewrote the TigerBeetle and PostgreSQL comparison pages
  to healthcare-only positioning); README "Use Cases" section now
  lists EHR / payer-RCM / clinical research / digital health;
  `quick-start.md` and `cli.md` template list now offers `ehr` /
  `claims` / `research` / `multi-tenant` instead of finance/legal;
  `docs/concepts/data-classification.md`,
  `docs/concepts/compliance-implementation.md`, `docs/start.md`,
  `docs/reference/faq.md`,
  `docs/compliance/certification-package.md`,
  `docs/operating/production-deployment.md`,
  `docs/operating/configuration.md`, `docs/operating/security.md`,
  `docs/internals/compliance-implementation.md`,
  `docs/reference/sql/json.md`,
  `docs/internals/compliance/traceability-matrix.md`, and the SDK
  package description all moved to HIPAA-native framing with explicit
  out-of-scope flags on SOX/GLBA/FERPA/CMMC/NIS2/DORA/eIDAS/IRAP/PCI
  DSS frameworks (specs retained for historical reference).
- **PRESSURECRAFT Wave 3 (`try_new`) migration complete.** All 10
  Bucket-C panicking `pub fn new()` sites identified in
  `docs-internal/contributing/constructor-audit-2026-04.md` now ship
  paired `try_new() -> Result<_, Error>` constructors with explicit
  error variants and `#[track_caller]` shim `new()` methods. Affected
  sites: `ClusterConfig` (cluster), `RecordSignature` (compliance),
  `FieldMask` (rbac), `CoreRouter` / `CoreRuntime` / `BufferPool` /
  `BoundedQueue` (server), `Clock` / `VsrConfig` / `RepairState`
  (vsr). Each rejection path now has dedicated tests
  (`try_new_rejects_*` + `#[should_panic]` `new_panics_on_*`).
- **Healthcare VOPR scenarios promoted.** 6 clinical scenarios that
  previously delegated to the v0.7.0 `aspirational_v07` scaffold now
  have real fault-shape drivers in `crates/kimberlite-sim/src/scenarios.rs`:
  `ehr_admissions_surge`, `lab_result_delayed_delivery`,
  `claims_batch_reconciliation`, `break_glass_under_load`,
  `consent_revocation_cascade`, `as_of_before_retention_horizon`.
  Each tunes its NetworkConfig / StorageConfig / SwizzleClogger /
  GrayFailureInjector to the canary contract documented on the
  scenario's `ScenarioType` variant. New
  `test_healthcare_scenarios_have_real_drivers` integration check
  enforces graduation.
- **4 new fuzz targets** added under `fuzz/fuzz_targets/`:
  `fuzz_fhir_r4_resource` (FHIR R4 Patient/Bundle JSON parser +
  canonical round-trip), `fuzz_x12_envelope` (X12 EDI parser
  no-panic-on-input), `fuzz_deid_safe_harbor` (HIPAA Safe Harbor
  de-id + attestation round-trip), `fuzz_audit_export_roundtrip`
  (RecordSignature canonical postcard round-trip). Wired into
  `.github/workflows/fuzz.yml` for the nightly campaign.
- **`Healthcare.tla` spec** — new formal-verification module with 4
  healthcare-specific invariants: `SafeHarborCoverage`
  (§164.514(b)(2)), `BreakGlassAuditOrder` (§164.510(b)(3)),
  `ConsentRevocationCausality`, `NoPhiReadAfterRevocation`. Layered
  on top of the existing `Compliance.tla` and gated in
  `.github/workflows/formal-verification.yml`.
- **Notebar upstream-blocker regression tests** — three in-process
  tenant.rs tests guard against regressions on the four issues
  notebar previously had `describe.skip`'d (N1 tenant-scoped table
  catalog already fixed in `kimberlite@89d3bd6`; N2 DELETE-without-WHERE,
  N3 DROP-leaves-rows, N4 DROP-IF-EXISTS confirmed already fixed and
  guarded with `test_delete_all_rows_no_where_clause`,
  `test_drop_then_recreate_table_starts_empty`,
  `test_drop_table_if_exists_on_missing_table_is_noop`).

### Changed

- TypeScript SDK package description updated from "compliance-first
  database for regulated industries" to "verifiable database for
  healthcare".
- Workspace version bumped to 0.9.0; TS SDK at
  `@kimberlitedb/client@0.9.0`.

### Out of scope (tracked for v0.10.0)

- Firecracker / KVM-based multi-node DST harness on Hetzner EPYC
  (current in-process VOPR + `kimberlite-cluster` integration tests
  remain the v0.9 correctness foundation).
- Geo-fencing / data-sovereignty enforcement (`PlacementPolicy` API
  surface exists; the enforcement layer is v0.10).
- KMS production backends (AWS KMS, Azure Key Vault, GCP KMS). The
  trait exists; file-backed dev provider is the v0.9 default.
- Full X12 837 claim-loop schemas (837P/837I/837D with 1000+ segment
  loops). v0.9 ships envelope-and-segment-iterator only — sufficient
  for ingest + audit-event emission. Deep loop modelling is v0.11.

### Added — Healthcare pivot Q3 (de-id, KMS, X12, pediatric retention)

Closes the Q3 chapter of the healthcare-only pivot plan
(`~/.claude/plans/i-have-decided-to-eventual-fiddle.md`). Q1 (FHIR +
SMART) and Q2 (HL7v2 + cluster HA) already landed; Q3 adds the
moat-and-coverage layer that distinguishes Kimberlite from a generic
verifiable database for clinical / payer / RCM buyers.

- **HIPAA Safe Harbor de-identification** —
  new `kimberlite_compliance::deidentification` module. Removes
  the 18 § 164.514(b)(2) identifier classes from a JSON record
  with a configurable rule table (date → year-only, ZIP → first-3,
  age → 90+, others → redacted). Returns a
  `DeidentificationAttestation` carrying SHA-256 pre-/post-image
  hashes, the set of identifier classes touched, and a stable
  `transform_version`. New audit-event variant
  `ComplianceAuditAction::DeidentificationApplied` chains the
  attestation into the existing audit log so any downstream
  consumer can prove the dataset they hold is the declared
  transform of the declared input. 10 unit tests, including all-18
  enumeration and stable canonical-JSON hashing.

- **External KMS providers (BYOK)** —
  new `kimberlite_crypto::kms` module. `KmsProvider` trait
  abstracts AWS KMS / GCP Cloud KMS / Azure Key Vault; opaque
  `KmsKeyRef` + variable-length `SealedKey` blobs accommodate
  every cloud's ciphertext shape. `KmsMasterKey` adapter provides
  `seal_raw` / `open_raw` / `generate_sealed_kek` /
  `restore_sealed_kek` / `rotate_kek` for the BYOK flow. Ships
  with a production-quality `InMemoryKms` mock for CI and
  single-node deployments, plus three doc modules
  (`aws_kms_integration`, `gcp_kms_integration`,
  `azure_key_vault_integration`) showing exactly how operators
  wire each cloud's SDK to the trait. 7 KMS tests covering
  seal/open round-trip, error paths, and KEK rotation. New
  `KeyEncryptionKey::from_bytes` / `KeyEncryptionKey::generate` /
  `KeyEncryptionKey::to_bytes` constructors mirror
  `EncryptionKey` for the BYOK path.

- **`kimberlite-x12` crate** —
  ASC X12 EDI parser for HIPAA-mandated healthcare transactions.
  Envelope-level support for 837 (Professional / Institutional /
  Dental claims) and 835 (remittance advice) with per-interchange
  delimiter discovery from the fixed-position ISA header. Typed
  wrappers `tx837::Claim` and `tx835::Remittance` recognise
  transactions by implementation-convention reference and expose
  the call-site primitives ingestion code needs (`claim_headers`,
  `submitter_batch_id`, `total_paid_amount`, `payment_method`,
  `claim_payments`). 11 unit tests covering envelope round-trip,
  segment-count consistency, and rejection of malformed input.
  Full claim/remittance segment-loop modelling is a v0.11 scope
  item; v1 ships the ingest-and-audit surface that RCM and payer
  integrations need.

- **Pediatric extended retention** —
  `kimberlite_compliance::retention` extends with
  `PediatricRetention` (birthdate-anchored age-of-majority +
  extension years), `age_of_majority_years_for_state` lookup
  (AL/NE=19, MS=21, default 18),
  `DEFAULT_PEDIATRIC_EXTENSION_YEARS=6`, and
  `RetentionEnforcer::register_pediatric_stream`. Pediatric rule
  evaluation runs *before* the data-class minimum so the
  birthdate-anchored horizon dominates when binding (e.g., a
  newborn's record retains for ~24y, far longer than the standard
  6y HIPAA PHI minimum). 6 new retention tests including state
  override and AL=19 boundary.

- **`examples/rust/src/claims_mini.rs`** —
  X12 837 → audit-log → 835 reconciliation walkthrough. Parses an
  inbound claim batch, emits a `DataExported` audit event per
  claim, parses the matching remittance, and flags claim IDs in
  the remittance that have no matching intake event. Runs
  offline — `cargo run --example claims_mini`.

- **`examples/rust/src/research_mini.rs`** —
  21 CFR Part 11 e-signature + audit-of-audits walkthrough.
  Investigator signs a clinical case-report form with Ed25519,
  `RecordSigned` event chains into the trial audit log, a
  regulator review of the trial audit chain is itself captured
  as a `DataExported` event in a separate regulator audit
  stream. Both chains independently `verify_chain`-clean. Runs
  offline — `cargo run --example research_mini`.

- **Residual strip** — pruned 14 dead
  `::view-transition-*(tenant-{finance,legal,government,retail,insurance})`
  selectors from `website/public/css/blocks/tenant-vault.css`,
  closing the loose end from the Sprint-1 strip.

### Added — v0.9.x cluster graduation T2.3 (drivers)

- **5 cluster-supervisor VOPR scenarios promoted out of the aspirational
  set** with real drivers in `crates/kimberlite-sim/src/scenarios.rs`:
  - `cluster_node_process_crash` — single-replica gray-failure cycling
    (15 %/30 % entry/recovery), ~20 s window — models SIGKILL + supervisor
    restart of one follower while N-1 nodes stay writable.
  - `cluster_cascading_node_failure` — aggressive 35 %/8 % gray-failure
    rates + 15 % packet drop + aggressive swizzle-clogging, 30 s window —
    models N-1 nodes failing in rapid sequence.
  - `cluster_health_check_timeout` — 20 %/3 % gray-failure + elevated
    network latency (max 100 ms) — models a hung process that responds
    slowly rather than crashing outright.
  - `cluster_config_reload_under_load` — 8 %/25 % gray-failure + 2k
    in-flight + 30k events — stresses the supervisor's reload window
    against sustained write load.
  - `cluster_rolling_restart_full_cluster` — matched 18 %/22 % gray-failure
    cycling over a 40 s window — models sequential node-by-node restart
    with leadership transferring along the way.
- **`ScenarioConfig::new` dispatch** wired to the five new drivers; the
  `aspirational_v07` shortcut for these scenarios is gone.
- **`vopr --scenario cluster-*` aliases** added to `parse_scenario` so
  each driver is selectable from the CLI (snake_case + kebab-case,
  matching the rest of the matcher).
- **Unit tests**: `test_cluster_scenarios_have_real_drivers` covers all
  five; per-scenario shape tests (`*_cascading_*`, `*_health_check_*`,
  `*_rolling_restart_*`) assert the fault parameters match the canary
  contract in each scenario's `description()` string.
- **Smoke runs** (release build, 30 iterations each): all five drivers
  pass with 0 invariant violations and 16/16 invariants covered.

The in-process VOPR runtime does not model an OS process supervisor;
the drivers express the fault *shapes* the supervisor would surface to
the replicated log. The existing VSR invariants (offset monotonicity,
prefix property, durability, hash-chain integrity) are the canary
mutations. End-to-end OS-process coverage continues to live in
`crates/kimberlite-cluster/tests/three_node_integration.rs` (T1.3) and
`tests/perf_baseline.rs` (T3.2).

### Added — v0.9.x cluster graduation T3.3

- **`examples/deployment/systemd/`** — production-shaped templated
  systemd units (`kimberlite-cluster@.service`,
  `kimberlite-cluster-readyz@.service`) for the canonical
  one-node-per-host hospital deployment. Wires `Restart=on-failure`
  + `StartLimitBurst` underneath the in-tree supervisor's bounded-backoff
  loop, hardens the process (`ProtectSystem`, `PrivateTmp`,
  `NoNewPrivileges`), and ships an oneshot readyz-poller for deployment
  automation that needs to gate "rollout complete" on real `/readyz=200`
  rather than process-alive.
- **`examples/deployment/docker-compose/`** — single-host 3-node stack
  built around an `init` one-shot (`kimberlite cluster init --host
  kimberlite-0 --host kimberlite-1 --host kimberlite-2`) that the three
  node services depend on. Healthchecks poll `/readyz` (not
  `kimberlite info`), exposing the T1.2 admin endpoints to the docker
  daemon. README reproduces the T1.3 leader-kill scenario as a hands-on
  failover walkthrough.
- **`examples/deployment/README.md`** — orientation between the two
  patterns; cross-linked from `examples/README.md` and the cluster
  runbook.

### Added — v0.9.x cluster graduation T3.2

- **Measured RTO + RPO baseline** for the 3-node cluster, published
  in `docs/operating/performance/cluster.md`. Headline numbers from
  the dev-hardware loopback run (n=8 iterations): user-observable
  RTO p99 ≈ **1.05 s** (target 5 s, ~5× headroom), RPO **= 0 events**
  across all completed iterations — confirming the VSR safety
  property holds end-to-end. Single-writer sustained throughput
  baseline: ~75 events/s, p50 latency ~11 ms, p99 ~23 ms (256-byte
  payloads, no batching, no concurrency).
- **`crates/kimberlite-cluster/tests/perf_baseline.rs`** — the
  reproducible harness behind the doc. Three `#[ignore]`-tagged
  tests (`perf_rto_leader_kill`, `perf_rpo_leader_kill`,
  `perf_sustained_write_throughput`) that boot a real 3-node cluster
  against the built `kimberlite` binary, drive a real client, and
  emit labelled distributions. Iteration count and run length are
  env-tunable (`KIMBERLITE_PERF_ITERATIONS`, `KIMBERLITE_PERF_SECS`).
- **Shared testing helpers promoted to `kimberlite_cluster::testing`**
  (`#[doc(hidden)]` public module). `crates/kimberlite-cluster/src/testing.rs`
  is now the source of truth for port-band reservation, binary
  discovery, HTTP/1.1 polling, and Prometheus gauge parsing;
  `tests/common/mod.rs` is a thin re-export shim. `tests/three_node_smoke.rs`
  migrated off its embedded `pick_base_port` / `wait_for_tcp_ready`
  duplicates — closes the T2.1 follow-up flake risk noted in the
  cluster graduation plan.
- **`docs/operating/runbooks/cluster.md`** RTO and RPO sections
  back-linked to the new perf doc; runbook's "≤ 5 s" targets now
  appear alongside the measured "p99 ≈ 1.05 s" baseline.

### Known limitation (v0.9.x)

- Under sustained-write leader kill (100 acked writes then
  SIGKILL'ing the leader), ~1 in 8 iterations on Apple Silicon dev
  hardware shows a view-change stall (> 20 s without a new leader
  elected). Self-recovers; not a data-loss event. Same root cause
  family as the deferred "rolling restart of all 3 nodes" scenario
  in `tests/three_node_integration.rs::single_node_restart_preserves_writes`
  — tracked for v0.10.x alongside the HTTP-sidecar / mio fairness
  work.

### Added — v0.9.x cluster graduation T1.3

- **4 new failure-mode integration scenarios** in
  `crates/kimberlite-cluster/tests/three_node_integration.rs`,
  `#[ignore]`d by default and run via
  `cargo test -p kimberlite-cluster --test three_node_integration -- --ignored`
  against a built `KIMBERLITE_BIN`:
  - `cluster_remains_writable_through_follower_crash` — write
    pre-kill, kill follower, write during, supervise+restart, write
    post-restart. Verifies leader keeps accepting writes through a
    follower's crash and that supervisor restart-with-backoff brings
    the follower back with a fresh PID.
  - `leader_kill_elects_new_leader_and_old_leader_rejoins` — SIGKILL
    the leader; assert a new leader emerges; write through the new
    leader; restart the old leader and assert it rejoins as a
    follower (not leader).
  - `leader_kill_flips_follower_readyz_within_5s` — closes the T1.2
    acceptance bullet (`/readyz` on a follower is 200 within 5 s of
    the new leader being elected).
  - `single_node_restart_preserves_writes` — a strict subset of the
    plan's "rolling restart of all 3 nodes" scenario. Stop+start one
    follower; assert the baseline write is still visible on every
    replica including the restarted one. The 3-of-3 rolling-restart
    extension is deferred — see the scenario's TODO comment for the
    underlying mio-loop fairness limitation it surfaces.
- **Shared test helpers** in
  `crates/kimberlite-cluster/tests/common/mod.rs` — port-band picker,
  binary discovery, minimal HTTP/1.1 GET, `/metrics`-based leader
  finder. Imported via `mod common;` in each integration test.

### Fixed — busy-loop reconnect storm starved leader's main loop

The post-bootstrap reconnect tick added in the v0.9.x VSR fixes
re-dialed every disconnected peer on every `heartbeat_interval`
(~125 ms in dev). On a peer that was permanently dead (e.g. a
SIGKILL'd replica during an integration test), this produced 8
connect attempts per second per peer, and the resulting `WARN` log
spam plus mio event traffic starved the leader's main loop enough to
drop client TCP accepts (`EAGAIN`) and HTTP-sidecar scrapes for
several seconds. Fix: per-peer exponential reconnect backoff
(50 ms → 30 s, doubled on failure, reset on a successful Connected
transition). The 50 ms minimum keeps initial cluster boot fast (peers
that come up within the bootstrap window are still discovered
quickly); the 30 s cap puts a permanently-dead peer at ~2 attempts
per minute. Failed-connect logs demoted from `warn` to `debug`.
(`crates/kimberlite-vsr/src/tcp_transport.rs`)

### Added — v0.9.x cluster graduation T1.2

- **`/healthz` and `/readyz` Kubernetes-convention HTTP probes.** New
  routes on the existing `kimberlite-server` HTTP sidecar (cluster
  mode default port `data_port + 1000`); the legacy `/health` and
  `/ready` paths remain as back-compat aliases. `/healthz` is
  unconditionally 200 once the process is up; `/readyz` is 200 only
  when the existing disk + memory checks pass AND (in replicated
  mode) VSR has completed bootstrap, the local replica is in `Normal`
  status, and `commit_lag_seconds` is below `--max-replication-lag`
  (default 5 s). Returns `503 Service Unavailable` otherwise.
- **Four new Prometheus gauges in `/metrics`** (per the cluster
  graduation plan's T1.2 acceptance bullet):
  `kimberlite_committed_offset`, `kimberlite_view_number`,
  `kimberlite_is_leader`, `kimberlite_replication_lag_seconds`. All
  refreshed at scrape time from a fresh `ReplicationStatus` snapshot
  via the new `Metrics::sync_replication_status` helper, so each
  scrape sees current values without a periodic background tick.
- **`CommandSubmitter::Cluster` tracks `last_commit_advance`.**
  Updated inside the dedup-gated `apply_once_to_projection` helper,
  which both the leader's inline submit and the follower projection
  applier already use; `kimberlite_replication_lag_seconds` reads
  `now - last_commit_advance` for followers (0 on the leader).
- **`HealthChecker::with_submitter` and `with_max_replication_lag`
  builder methods.** `Server::new` constructs the submitter first
  (reordered) and passes it via `Arc::clone` so the readiness check
  can incorporate VSR status; existing `HealthChecker::new(data_dir)`
  call sites stay source-compatible.
- **New integration test `crates/kimberlite-cluster/tests/http_probes.rs`.**
  `#[ignore]`d by default; run with
  `cargo test -p kimberlite-cluster --test http_probes -- --ignored`.
  Boots a 3-node cluster, asserts each replica's `/healthz`,
  `/readyz`, `/metrics` return 200, and that the four T1.2 gauges
  appear in the Prometheus output. 5/5 soak.

### Fixed — `/metrics` (and any large HTTP sidecar response) silently RST'd

The HTTP sidecar accepts on a `mio::net::TcpListener`, so accepted
streams are non-blocking. `std::io::Write::write_all` errors on the
first `WouldBlock`; dropping the stream then sends a TCP RST that
surfaces to clients as `Connection reset by peer`. Small responses
(under one TCP packet — `/health`, `/ready`) always fit, so the bug
never tripped them; `/metrics`, with its multi-KB Prometheus output,
reliably broke. Pre-existing latent bug surfaced while building T1.2's
integration test. Fix: new `write_full_response` helper that retries
on `WouldBlock` with brief sleeps until a 5 s deadline.
(`crates/kimberlite-server/src/http.rs`)

### Added — v0.9.x cluster graduation T1.1

- **`kimberlite-cluster` supervisor spawns real `kimberlite start`
  subprocesses.** Replaced the placeholder spawn in `node.rs:91` (the
  CLI's own test binary, which exited immediately) with a real
  `kimberlite start [--cluster] <data_dir> --address <addr>`
  invocation. New three-tier binary discovery
  (`locate_kimberlite_binary`): `KIMBERLITE_BIN` env override → `$PATH`
  lookup → sibling-of-current-exe fallback (handles the cargo
  `target/<profile>/deps/` test-binary layout).
- **VSR port offset (`VSR_PORT_OFFSET = 100`).** VSR's `TcpTransport`
  binds its own listener distinct from the client data port; the
  supervisor rewrites peer addresses through `shift_peer_port` when
  rendering `KMB_CLUSTER_PEERS` so data + VSR don't collide on
  localhost. Real boot-time bug — manual probe surfaced "Address
  already in use" until fixed.
- **Multi-node configs boot with `--cluster` automatically.** When
  `NodeConfig.peers` is non-empty the supervisor passes `--cluster`
  plus the `KMB_REPLICA_ID`, `KMB_CLUSTER_PEERS`, `KMB_HTTP_PORT`,
  and `KMB_ENABLE_FOLLOWER_PROJECTION=1` env that VSR + the projection
  applier expect. Single-node configs (`peers.is_empty()`) keep the
  default single-node-VSR boot.
- **Supervisor accessors for integration tests.** New
  `ClusterSupervisor::node`, `node_mut`, `supervise_once`, and
  `NodeProcess::pid` / `force_kill`. Lets tests SIGKILL a child
  out-of-band and step the supervisor's restart-with-backoff
  deterministically without racing the 1-second monitor tick.
- **`tests/three_node_smoke.rs` integration test.** Two `#[ignore]`d
  scenarios that boot 3 real nodes on a free port band:
  `three_node_cluster_smoke` (write through leader, read back from a
  follower) and `supervisor_restarts_killed_follower` (SIGKILL one,
  assert recovery with fresh PID + bumped `restart_count`). Both
  green — see the cluster graduation plan for the acceptance contract.

### Fixed — VSR multi-node localhost was unrecoverable

A 3-node cluster on `127.0.0.1` previously entered a view-change
storm within ~3 seconds of bootstrap (view number climbing once per
second, never settling). Four distinct bugs compounded; all four
fixed, and a new VSR-only loopback regression test
(`crates/kimberlite-vsr/tests/three_node_loopback.rs`) covers the
post-fix invariant (stable leader + cross-replica replication via
the in-VSR API). See `docs-internal/design-docs/active/cluster-
graduation-v0.9.x.md` for the full punch list.

- **Heartbeat reset is no longer dead code.** `EventLoop::process_event`
  now calls `timeouts.reset_heartbeat()` whenever an incoming message
  is from the current leader at the current view (Heartbeat / Prepare /
  Commit / StartView). Without this the follower's `last_heartbeat`
  deadline only got reset when the timeout itself fired, so every
  follower fired a view change every `view_change_timeout` (1 s in
  development), pushing view by 1 each time even when the leader was
  healthily heartbeating. Mirrors Raft's "reset election timer on any
  AppendEntries from current leader" rule. Removed the dead
  `on_leader_message()` helper.
- **Bootstrap waits for full mesh + reconnect tick.**
  `run_bootstrap_phase` previously exited when `connected_count + 1 >=
  quorum_size`, so a follower returned the moment it shook hands with
  the leader — its sibling-follower link stayed unconnected and there
  was no post-bootstrap reconnect path. Now: cluster mode waits for
  full membership (5 s timeout fallback with quorum / below-quorum
  diagnostic warnings); the main loop fires a reconnect tick every
  `heartbeat_interval` so a peer that comes up late or drops mid-run
  gets re-dialed. New `TcpTransport::reconnect_disconnected` and
  `disconnected_peer_ids` accessors back the tick.
- **`Hello` handshake binds inbound TCP socket → `ReplicaId`.** New
  `MessagePayload::Hello { sender_id, cluster_hash }` sent as the
  first frame on every freshly-opened outbound connection. Inbound
  state machine in `tcp_transport::route_inbound_frame` rejects
  connections whose first frame isn't a valid Hello, validates
  `cluster_hash` against `ClusterAddresses::membership_hash` (BLAKE3
  via `kimberlite-crypto`), binds the inbound mio `Token` to the
  declared `ReplicaId`, and on every subsequent frame enforces
  `msg.from == bound_id`. Spoofed-from messages are dropped with a
  Byzantine-rejection metric. Closes a real reliability gap: the
  transport previously trusted the spoofable `from` field on every
  frame and never identified inbound peers.
- **`DoViewChange` dedup no longer shadows the "use better message"
  replacement logic.** `MessageId` gained an `Option<u64>
  content_hash`; `MessageId::do_view_change(...)` now requires a hash
  derived from `(last_normal_view, op_number, log_tail_hash)`.
  Byte-identical replays still hash the same and are rejected (the
  audit-2026-03 M-6 contract); legitimate retransmissions with newer
  state get through, and the "replace if higher
  `(last_normal_view, op_number)`" replacement at
  `view_change.rs:287-318` finally runs.
- **Wire-protocol writes route through VSR.** The wire handler called
  `tenant.create_stream` → `Kimberlite::submit`, which was purely
  local — replicated cluster mode never replicated wire writes. New
  `kimberlite::CommandRouter` trait + `Kimberlite::set_command_router`
  + `Kimberlite::apply_local` (the recursion-break for routers that
  apply through the local projection). `kimberlite-server` ships a
  `ClusterCommandRouter` that the server installs on the underlying
  `Kimberlite` whenever replication is enabled. The leader's inline
  apply now uses the same dedup-gated `apply_once_to_projection` the
  follower applier uses — closes a race that surfaced as
  `"stream with id X already exists"` once routing was wired.
- **`MultiNodeReplicator` API additions.** `subscribe_applied_commands`
  and the `AppliedCommand` fanout were already wired; this work makes
  them actually flow on the leader's wire-write path. No public API
  removal; the `Hello` payload variant is wire-incompatible with
  pre-fix `kimberlite-vsr` builds, but the crate is internal
  (`description = "Viewstamped Replication consensus for Kimberlite"`,
  not yet on a stable surface) and pre-graduation per the cluster
  plan, so this is acceptable.

### Added — OSS launch readiness

- **Plan-time time-fold production wiring.** `plan_query` now folds
  `ScalarExpr::Now` / `CurrentTimestamp` / `CurrentDate` sentinels
  into `Literal(Timestamp(ns))` / `Literal(Date(days))` before
  returning, using a single statement-stable timestamp sampled at
  the planner boundary. Closes the v0.8.0 ROADMAP item that left
  these scalars panicking if reached unfolded. New public API:
  `planner::fold_time_constants(expr, ts_ns)`,
  `planner::fold_time_constants_in_plan(plan, ts_ns)`,
  `planner::current_statement_timestamp_ns()`,
  `planner::plan_query_with_clock(schema, parsed, params, ts_ns)`
  for VOPR / replay paths that need a deterministic clock. The
  `#[should_panic]` evaluator tests stay in place — they're now
  the contract that the fold pass MUST run before evaluation.
  AUDIT-2026-05 S3.7. (planner.rs:282–415, lib.rs:405)
- **Healthcare and finance vertical pages on the website.** New
  `/healthcare` and `/finance` landing pages with HIPAA / SEC
  17a-4 / SOX / GLBA mapping tables; new `/faq` page surfacing
  production-readiness, compliance posture (formally modelled, not
  yet certified), and known limitations of v0.8.0. New
  `docs/coding/quickstarts/{healthcare,finance}.md` walking
  through `examples/healthcare/` and `examples/finance/` end to end.
- **Finance ledger example.** New `examples/finance/00-setup.sh`,
  `03-time-travel.sql`, and `ledger.py` mirroring the structure of
  the healthcare clinic example. Demonstrates SEC 17a-4 audit
  trails, point-in-time portfolio reconstruction, GDPR Article 6
  consent under `Contract` lawful basis, and erasure orchestration
  with SEC-retention caveats.
- **Cookbook recipes for already-shipped primitives.** New
  `examples/cookbook/{time-travel,audit-verify-chain,multi-tenant}/`
  with runnable TypeScript scripts. Each ends with the
  `KMB_COOKBOOK_OK` success marker that CI gates on.
- **README "Known Limitations" + "Compliance posture" sections.**
  Up-front honesty: single-node only for production, no
  multi-statement transactions, no published benchmarks yet, no
  third-party SOC 2 / HIPAA / FedRAMP attestations. `Kimberlite
  *enables* your compliance posture; certification remains your
  team's responsibility.`

### Fixed — docs accuracy sweep

- ROADMAP Status header: `v0.7.0` → `v0.8.0`; v0.8.0 in-flight
  section moved to Released; new v0.9.0 in-flight populated from
  the items v0.8.0 deferred (Go SDK Phase 1, plan-time time-fold
  wiring, VOPR scenario drivers, pool metrics) plus Python parity
  for the items TS / Rust shipped in v0.8.0.
- SDK parity matrix: every `🚧 v0.8` row reconciled against what
  actually shipped in v0.8.0 — `audit.subscribe` (Rust 🚧 v0.9,
  Python 🚧 v0.9), `audit.verifyChain` Python 🚧 v0.9, typed
  primitive bindings Python 🚧 v0.9, `streamLength` Python 🚧 v0.9.
- Quick-start banner version: `v0.4.0` → `v0.8.0`. Installation
  docs `--version` example: `v0.4.2` → `v0.8.0`. Production
  deployment doc: image tags + the v0.4 disclaimer brought to
  v0.8.0. Runbook example image tags: `v0.3.0` / `v0.4.0` →
  `v0.7.0` / `v0.8.0`. Website download / home templates: `v0.4.2`
  example → `v0.8.0`; obsolete v0.5.0 ROADMAP comment removed.
- Compliance certification package: `as of v0.4` → `as of v0.8`.
- SQL DML reference: transactions language reconciled —
  `BEGIN`/`COMMIT`/`ROLLBACK` are planned **post-v1.0**, not
  "v1.0", to match the README and ROADMAP.
- Coding quickstart "(coming soon)" links replaced with concrete
  pointers to `examples/` per language.
- Go SDK status: `Deferred post-v0.4 launch` → `Phase 1 planned
  for v0.9.0`, with explicit Phase 2 / Phase 3 scope.

## [0.8.0] — 2026-05-06

**Theme:** notebar v0.7.0-migration wishlist + SDK error/audit
ratchet. Six items surfaced when notebar drove a real workload on top
of v0.7.0; each shipped behind its own PR and merged in sequence
(#125 → #131). The CI floor was repaired in the same window —
`tla2tools.jar` SHA pin re-bumped (#132), Dependabot rust-minor group
of 27 crate bumps (#133) and the GitHub Actions group bump (#124)
landed alongside the feature work.

### Breaking changes (pre-1.0)

- **Rust SDK: `Client::erase_subject` / `erase_subject_with_streams`
  closure type bumps from `FnMut(StreamId) -> ClientResult<u64>` to
  `FnMut(StreamId, &str) -> ClientResult<u64>`** — the second argument
  is the erasure request id, so callers can tag the shred event with
  a stable correlation id without fabricating a placeholder. TS / Python
  callbacks stay backwards-compatible (TS allows fewer-arg function
  assignment; Python uses `inspect`-based arity detection). Migration:
  add a `request_id` parameter to the closure or accept it via `_`.

### Added — SDK error surface

- **Typed unique-constraint error end-to-end.** New
  `QueryError::DuplicatePrimaryKey { table: String, key: Vec<Value> }`
  variant emitted at the duplicate-PK INSERT path
  (`crates/kimberlite/src/tenant.rs:1628`); plumbed through
  `ErrorCode::UniqueConstraintViolation = 29` on the wire,
  `KmbErrUniqueConstraintViolation = 16` over the FFI, and surfaced
  as typed error classes per SDK:
  - Rust: `ClientError::is_unique_constraint_violation()` predicate;
    `DomainError::Conflict` mapping (existing shape).
  - TypeScript: `UniqueConstraintViolationError` class wired into
    `wrapNativeError`.
  - Python: `UniqueConstraintViolationError` class +
    `KimberliteError.is_unique_constraint_violation()` predicate.
  Notebar's `webhook-dedup.ts` try-INSERT-then-SELECT recovery loop
  collapses to a single typed catch.

### Added — eraseSubject orchestrator

- **`requestId` exposed to the per-stream callback.** TS callback
  signature gains a 2nd arg `(streamId: StreamId, requestId: string)
  => Promise<bigint>`; old 1-arg callbacks still type-check (TS
  fewer-arg assignment). Python orchestrator uses `inspect` to detect
  callback arity and dispatches to the new shape only when the
  callable accepts it; legacy `on_stream` keeps working without
  modification. Rust closure type bumps to `FnMut(StreamId, &str) ->
  ClientResult<u64>` (pre-1.0 SDK breaking change documented in the
  rustdoc and Breaking changes section above). Closes notebar's
  empty-string placeholder in `erasure.ts:139`.

### Added — DROP TABLE row purge

- **`Effect::ProjectionRowsPurge { tenant_id, table_id }`.** New
  effect emitted alongside `Effect::TableMetadataDrop` in the
  `Command::DropTable` handler. Production runtime calls
  `ProjectionStore::purge_table(table_id)` (new trait method); the
  `BTreeStore` impl drops the per-table `BTreeMeta` from the
  superblock so subsequent reads return empty. v0.7.0's metadata-only
  DROP semantics are gone; recreating a table by the same name (=
  same `TableId`, since `TableId = hash(tenant, name)`) starts on an
  empty B-tree. The previously-`#[ignore]`d regression net at
  `tests/catalog_staleness.rs::drop_does_not_yet_purge_projection_rows`
  is renamed `drop_table_purges_projection_rows` and now passes.

### Added — stream-length primitive

- **`streamLength(streamId)` / `stream_length(stream_id)` on the SDK.**
  O(1) read of `StreamMetadata.current_offset`; new wire frames
  `StreamInfoRequest` + `StreamInfoResponse { length: u64 }` carry the
  count without paging events. Replaces the full-stream `readAll(...)`
  walk that notebar's Group-1 telemetry sites were using purely to
  count rows. Ships in TypeScript and Rust this cycle; Python parity
  is a focused follow-up against the same wire frame.

### Added — typed primitive bindings (TypeScript)

- **TS bindings for `Interval`, `AggregateMemoryBudget`,
  `SubstringRange`, and `DateField`.** New module
  `sdks/typescript/src/typed-primitives.ts` exposes type definitions
  (mirroring the v0.7.0 Rust shapes — `DateField` as a string-literal
  union per SDK shape decision), constructors that enforce the
  Rust-side invariants (`intervalFromComponents` normalises sub-day
  nanos overflow into days; `substringWithLength` rejects negative
  length; `aggregateMemoryBudget` enforces the 64 KiB floor), and
  SQL fragment builders (`extractFromSql`, `dateTruncSql`,
  `intervalLiteral`, `substringSql`) so callers don't string-
  concatenate. Wire-level `QueryParam` / `QueryValue` round-trip
  for these types is a deliberate follow-up.

### Added — audit subsystem wiring

- **`audit.verifyChain()` server-walked attestation.** Replaces the
  v0.5.0 / v0.6.0 stubs that returned a hardcoded `{ ok: true }`.
  New wire frames `VerifyAuditChainRequest` / `VerifyAuditChainResponse
  { ok, event_count, chain_head_hex, mismatch_at_index, error_message }`;
  server handler delegates to `ComplianceAuditLog::verify_chain` (the
  SHA-256 hash chain walk in the kernel since AUDIT-2026-04 H-2). On
  chain breaks, the earliest mismatched event index is surfaced via
  `mismatch_at_index` so regulator-visible reports can pinpoint the
  tampering location. New `TenantHandle::audit_log_verify_chain` and
  `audit_log_chain_head_hex` helpers; Rust `Client::verify_audit_chain`;
  napi-rs `JsClient::verify_audit_chain`; TS
  `compliance.audit.verifyChain()` returns the populated
  `ChainVerification` shape with the real `eventCount` /
  `chainHeadHex` / `firstBrokenAt` fields. Python parity is a
  follow-up.
- **`audit.subscribe()` polling iterator (TS).** Replaces the no-op
  stub. Implementation polls the existing `audit.query()` at
  `intervalMs` cadence (default 1s), yields entries newer than the
  high-water timestamp, supports `AbortSignal` cancellation, and
  matches the shape of `erasure.subscribe()`. Cross-stream
  subscription-filter server hook (push-based instead of polling)
  is deferred; the polling iterator is sufficient for the dashboard
  use-case notebar surfaced.

### Documentation

- **`docs/reference/sdk/parity.md`** updated: `audit.subscribe`
  marked TS ✅ (polling iterator), Rust/Python 🚧 v0.8; new
  `audit.verifyChain` row TS ✅ / Rust ✅ / Python 🚧 v0.8.
- **`ROADMAP.md`** v0.8.0 in-flight section consolidated to
  10 items (4 carried-over + 6 notebar-wishlist), each with file:line
  references for the implementation surface.

### Carried over from v0.7.0 deferred (still in flight)

- Go SDK Phase 1 (`Connect`/`Query`/`Append`/`Read`/`Subscribe`/
  `Pool` over the existing FFI bridge)
- Plan-time time-fold production wiring (substitutes
  `ScalarExpr::Now` / `CurrentTimestamp` / `CurrentDate` sentinels
  with literal values at plan time)
- VOPR scenario drivers for the 16 v0.7.0 scaffolds (`Masking*` /
  `Upsert*` / `AsOfTimestamp*` / `EraseAutoDiscovery*` families)
- Pool metrics — client-side Prometheus parity (TS / Python / Rust
  `pool.metrics()` text format, AWS ECS-friendly)

---

## [0.7.0] — 2026-05-04

**Theme:** production-validation release. Closes every v0.7.0
ROADMAP gap that notebar's healthcare reporting flow needed,
ratchets the verification surface (PRESSURECRAFT typed primitives +
TLA+ purity spec + 16 VOPR scenario scaffolds + audit-matrix tool +
topological publish validator), and bumps the Python SDK floor in
lockstep with the typing refresh that PEP 604 unlocks.

### Breaking changes

- **Python SDK minimum version bumped 3.9 → 3.10.** Python 3.9
  reached EOL 2025-10. The bump unlocks PEP 604 union syntax (`X |
  None`) at runtime — the typing-refresh roadmap item leans on it.
  Notebar uses Python 3.12 in production tooling so the bump is
  invisible to them; downstream consumers pinned to 3.9 should hold
  at `kimberlite==0.6.2` until they upgrade their interpreter.
  `pyproject.toml`, `[tool.mypy]`, `[tool.black]`, `[tool.ruff]`
  all updated; the `Programming Language :: Python :: 3.9`
  classifier is removed.

### Added — SQL surface

- **6 new scalar functions in production**: `MOD(a, b)` (NULL on
  divide-by-zero per Postgres), `POWER(base, exp)` (returns Real),
  `SQRT(x)` (DomainError on negative input), `SUBSTRING(s FROM
  start [FOR length])` (Unicode char-correct, supports negative
  start per SQL semantics), `EXTRACT(field FROM ts)` (closed
  `DateField` enum), `DATE_TRUNC(field, ts)` (truncatable subset
  of fields, returns Date or Timestamp matching input shape). Each
  has 2+ assertions, paired `#[should_panic]` tests, and property
  tests for null-propagation + determinism.
- **3 sentinel scalar variants** for time-now functions: `NOW()`,
  `CURRENT_TIMESTAMP`, `CURRENT_DATE`. The evaluator stays pure —
  these variants panic loudly if reached unfolded, with paired
  `#[should_panic]` tests pinning the contract. The plan-time
  `fold_time_constants` pass that substitutes them with literal
  values is scaffolded for v0.8.0 production wiring; the v0.7.0
  spec, parser, evaluator, and AST-walking infrastructure all
  ship.
- **Interval arithmetic primitives.** `Interval { months: i32,
  days: i32, nanos: i64 }` typed primitive with PostgreSQL-
  compatible three-component semantics (months calendar-relative,
  days wall-clock, nanos sub-day). Construction normalises nanos
  overflow into days. Component-wise `checked_add` /
  `checked_sub` / `checked_neg` with Kani-friendly arithmetic;
  Kani harnesses for associativity (no-month subset) and zero-
  identity ship behind `#[cfg(kani)]`.
- **`AggregateMemoryBudget(u64)`.** Replaces the `MAX_GROUP_COUNT
  = 100_000` panic-style cap with a configurable budget. Default
  256 MiB ≈ 1M groups (≈ 10× lift). New `QueryError::AggregateMemoryExceeded
  { budget, observed }` error variant. Construction via
  `try_new` or `TryFrom<u64>` rejects budgets below the 64 KiB
  floor with a structured error.
- **`DateField`** closed enum (`Year`/`Month`/`Day`/`Hour`/
  `Minute`/`Second`/`Millisecond`/`Microsecond`/`DayOfWeek`/
  `DayOfYear`/`Quarter`/`Week`/`Epoch`) drives both `EXTRACT`
  and `DATE_TRUNC`. `is_truncatable()` projects to the
  `DATE_TRUNC` subset.
- **`SubstringRange { start: i64, length: Option<i64> }`** typed
  primitive — negative `length` rejected at construction.

### Added — verification & tooling

- **`specs/tla/ScalarPurity.tla`** formal-verification spec.
  Four meta-theorems (`DeterminismTheorem`, `NoIOTheorem`,
  `NullPropagationTheorem`, `CastLosslessTheorem`) plus a
  meta-theorem (`FoldThenEvaluateIsPure`) covering the
  plan-time-fold contract for time-now sentinels.
- **`audit-matrix` tool** (`crates/kimberlite-compliance/src/bin/audit-matrix.rs`).
  Pure-stdlib workspace scanner that emits a Markdown
  traceability matrix from `AUDIT-YYYY-NN <code>` source markers.
  342 markers indexed in this release. Marker taxonomy extended
  with new `T` (Traceability hook) variant. New `just audit-matrix`
  generates the matrix; `just audit-matrix-check` is the CI
  drift-detector gate (same pattern as `cargo fmt --check`).
- **16 scaffolded VOPR scenarios** in
  `crates/kimberlite-sim/src/scenarios.rs` covering the v0.6.0
  command families: `MaskingClassMonotonicity`,
  `MaskingDuplicateClassDefinition`,
  `MaskingCrashAfterDdlBeforeReplay`,
  `MaskingClassReadDuringRotation`, `UpsertConcurrentInsertSamePk`,
  `UpsertCrashMidConflict`, `UpsertWithComputedReturning`,
  `UpsertOnNonUniqueIndex`, `AsOfBeforeRetentionHorizon`,
  `AsOfDuringWrite`, `AsOfMonotonicityUnderClockSkew`,
  `AsOfRoundTripDeterminism`,
  `EraseAutoDiscoveryAcrossSchemaVersions`,
  `EraseAutoDiscoveryWithDroppedColumn`,
  `EraseAutoDiscoveryDeterminism`,
  `EraseAutoDiscoveryWithCrashMidScan`. Each variant carries the
  canary mutation it surfaces; full drivers ship per-family in
  v0.8.0 commits.
- **`tools/publish-order-check`** standalone Rust binary +
  `just validate-publish-order` recipe. Pairwise topological
  validator (NOT a single-toposort comparison — that would
  false-positive on alternative valid orders) for
  `PUBLISH_CRATES`. Surfaced and fixed a real ordering bug
  (`kimberlite-test-harness` was published before its production
  deps `kimberlite-client` and `kimberlite-server`).

### Added — SDK & DX

- **`examples/cookbook/`** with three runnable recipes per the
  v0.7.0 ROADMAP "Cookbook examples for already-shipped primitives
  that downstream consumers keep missing":
  - `subscriptions/` — `client.subscribe(streamId, { startOffset })`
    AsyncIterable with credit-based flow control. Closes the
    "Notebar still believes the client is pull-only" gap.
  - `secondary-index/` — `CREATE INDEX ON projection(provider,
    providerMessageId)` + `EXPLAIN`-asserts-IndexScan.
  - `consent-decline/` — `recordConsent({ termsVersion,
    accepted: false })` with audit-trail verification.
  Each recipe ships TypeScript + Python with shared
  `KMB_COOKBOOK_OK` stdout marker for CI gate.

### Fixed

- **Catalog staleness on `DROP TABLE` + `CREATE TABLE` (same
  name).** Root cause: `Effect::TableMetadataDrop` did not call
  `rebuild_query_engine_schema()` while `Effect::TableMetadataWrite`
  did — the asymmetry left the per-tenant `QueryEngine` cache
  holding the dropped table's `TableDef`. Reproducer test
  pinned at `crates/kimberlite/tests/catalog_staleness.rs`.
  Closes the v0.6.2-deferred bug; notebar's DDL test loop now
  runs without the unique-table-name workaround.
- **Inverted-range planner output.** Fixed at the lowering
  source: `compute_range_bounds` now detects unsatisfiable
  predicate combinations (`x > 5 AND x < 3`, etc.) and returns
  `RangeBoundsResult::is_empty = true`; the caller short-
  circuits to `AccessPath::TableScan` with an `AlwaysFalse`
  predicate. The `kimberlite-store::btree::scan` debug_assert
  is now unconditional — the v0.6.1 `cfg(not(fuzzing))` escape
  hatch is removed because the planner no longer emits inverted
  ranges in any code path. Property tests in
  `tests/property_tests.rs` pin the invariant.
- **`DELETE FROM t` (no WHERE) `rows_affected` postcondition.**
  Added `assert_eq!(rows_affected as usize, expected_rows)`
  postcondition + reproducer integration test. The kernel-side
  count was always correct; the missing piece was the executable
  contract.
- **MIRI nightly-lite timeout regression.** Annotated the heavy
  AES-GCM roundtrip test (`encryption::tests::large_plaintext_encryption`)
  with `#[cfg_attr(miri, ignore = ...)]`. PRESSURECRAFT §4
  routes correctness checks for crypto internals to property
  tests + fuzz under standard `cargo test`; MIRI's value is
  UB detection on the unsafe / FFI surface. Closes the
  90-min `TimeoutStartSec` overrun.

### Safety — new production assertions

Per the `docs/internals/testing/assertions-inventory.md` policy:

- `crates/kimberlite/src/tenant.rs::execute_delete` —
  postcondition asserting `rows_affected` matches the planner's
  matched-row count (AUDIT-2026-05 S3.5).
- `crates/kimberlite-types/src/domain.rs::AggregateMemoryBudget` —
  precondition rejecting budgets below the 64 KiB floor +
  postcondition round-trip on the accessor (AUDIT-2026-05 H-4).
- `crates/kimberlite-types/src/domain.rs::Interval::try_from_components` —
  postcondition `|nanos| < NANOS_PER_DAY` invariant
  (AUDIT-2026-05 S3.9).
- `crates/kimberlite-store/src/btree.rs::scan` — restored
  unconditional debug_assert on range orientation (AUDIT-2026-05
  H-3).
- 9 paired `#[should_panic]` tests for the 9 new scalar
  variants' precondition asserts.

### Found by

`notebar` healthcare-reporting integration (catalog staleness on
the per-test DDL loop, GROUP BY scale ceiling on the
`ar_ledger` GST drill-down) + the April 2026 fuzz-to-types
campaign continuation (inverted-range planner regression seeds
fed into v0.7.0 property tests).

### Known issue (deferred to v0.8.0)

- **DROP TABLE is metadata-only** — projection-store rows survive
  a `DROP TABLE`. Recreating a table with the same name observes
  the old data on first read. Tracked at
  `crates/kimberlite/tests/catalog_staleness.rs::drop_does_not_yet_purge_projection_rows`
  with `#[ignore]` so the regression net trips when the data-purge
  effect lands. Workaround for v0.7.0 consumers: use a fresh
  primary key after recreation, or use unique table names per
  test invocation (notebar pattern).

---

## [0.6.2] — 2026-05-04

**Theme:** notebar-driven patch. Closes the four TS-SDK trips and the
consent-grant gap that the first downstream consumer (notebar) reported
during integration. Wire bump v4 → v5 (consent-grant payload growth).

### Breaking changes

- **Wire protocol v4 → v5.** `ConsentGrantRequest` and `ConsentRecord`
  gained two tail fields (`terms_version: Option<String>`, `accepted:
  bool`). Postcard is positional and errors on missing tail bytes, so
  v0.6.1 ↔ v0.6.2 cross-version connections are rejected at the frame
  validator with `UnsupportedVersion(...)`. Source-level consumers
  (Rust callers of `ConsentTracker`, TS `consent.grant`, Python
  `consent.grant`) keep their existing call shapes — back-compat is
  preserved at the API surface, only the on-the-wire format moved.

### Added — TS SDK pagination + buffer hygiene

- **`Client.readAll(streamId, { fromOffset, batchSize })`.** Async
  generator that walks offsets internally until end-of-stream,
  driven by the server's `nextOffset` signal. Removes the
  silent-truncation footgun where bare `read()` returned only the
  first batch and the caller forgot to paginate. Throws loudly if a
  single event exceeds `batchSize` (instead of spinning).
- **`bufferSizeBytes` default 64 KiB → 4 MiB.** Pre-v0.6.2 the SDK
  tripped its own framing limit on its own defaults: the 1 MiB
  `read({ maxBytes })` default exceeded the 128 KiB framing cap
  (`buffer_size * 2`). New default gives an 8 MiB cap — comfortably
  above the read budget, with regression-pinned defaults across all
  4 sites (sync `Client`, `AsyncClient`, napi sync + pool variants).
- **`ResponseTooLargeError`** subclass of `ConnectionError`. The
  oversized-response error now carries observed/limit byte counts
  and points at the three remediations (`bufferSizeBytes` ↑,
  `maxBytes` ↓, `readAll`). Routed via `wrapNativeError` for both
  the `[KMB_ERR_]` prefix and legacy paths.

### Added — channel recovery

- **Poison-and-reconnect on oversized responses.** When the framing
  cap trips, the Rust client clears `read_buf` + `push_buffer` and
  marks itself `poisoned`. Subsequent `send_request` calls return a
  sticky `Connection("connection poisoned … reconnect required")`
  error that drives `invoke_with_reconnect` (Rust) or
  `autoReconnect` (TS). `reconnect()` clears the flag once the new
  stream + handshake succeed. Closes the `ResponseMismatch`
  follow-on that fired on the next request after the first oversize.

### Added — consent-grant terms-acceptance fields

- **`terms_version: Option<String>` + `accepted: bool` (default
  `true`)** on `ConsentRecord` and `ConsentGrantRequest`. Captures
  which terms-of-service version a subject responded to and whether
  they accepted (default) or explicitly declined (`false`). A
  decline is itself a compliance event — the audit trail captures
  the decline against `terms_version`.
- **`GrantOptions` struct** + `ConsentTracker::grant_consent_with_options`,
  `TenantHandle::grant_consent_with_options`,
  `Client::consent_grant_with_terms`. Pre-v0.6.2 entry points
  (`grant_consent`, `grant_consent_with_scope`,
  `grant_consent_with_basis`) keep their signatures and delegate —
  zero source-level breakage.
- **TS SDK overload:** `consent.grant(s, p, options)` accepts
  `{ basis?, termsVersion?, accepted? }` as the 3rd argument.
  Pre-v0.6.2 callers passing a bare `ConsentBasis` keep working via
  a runtime type-guard on `'article' in arg3`.
- **Python SDK kwargs:** `consent.grant(subject, purpose, basis, *,
  terms_version=None, accepted=None)`. Default `accepted=True`.
- **Audit event:** `ComplianceAuditAction::ConsentGranted` extended
  with the same two fields. Variant name retained — `accepted: false`
  is still a "consent recorded" event.
- **C ABI:** `kmb_compliance_consent_grant` adds an `options_json`
  parameter (UTF-8 JSON envelope). Existing C consumers must update
  their bindings; the call shape is intentionally extension-friendly
  for v0.7+ option growth.

### Added — `DROP TABLE IF EXISTS`

- **Idempotent DDL.** `DROP TABLE IF EXISTS <name>` now returns
  `Ok(rows_affected = 0)` when the table doesn't exist, instead of
  `TableNotFound`. Cleared a v0.7.0 ROADMAP item along the way.
  Test fixtures stop needing try/catch wrappers around setup
  cleanup.

### Fixed — integration-test infrastructure

- **Per-invocation unique table / stream names** in TS and Python
  integration suites. Hardcoded names (`test_users`, `append_test`,
  …) collided with leftover state from prior runs, surfacing as
  duplicate-PK errors and `Internal server error`. The new fixture
  yields `(client, table_name)` with a fresh `uuid` suffix per
  test invocation.
- **Python `Client.execute` return-type assertions.**
  `client.execute(...)` returns `ExecuteResult(rows_affected,
  log_offset)` — a dataclass, not a bare int. Tests that compared
  the return value against `int` (e.g. `result == 0`) crashed with
  `TypeError`; now compare `result.rows_affected`.
- **Python `Client.read` docstring + `test_stream_not_found`.**
  Reading a non-existent stream returns `[]` — the server doesn't
  distinguish unknown-stream from empty-stream. The docstring's
  "Raises StreamNotFoundError" was inaccurate; both contract and
  test now match observed behaviour.

### Found by

`notebar` Phase 1 consent-capture flow + `repo-kit.ts::replayFromStream`
against `appointment_events` / `invoice_events`. The first downstream
consumer should not be the project's QA pass for trivially fixable
defaults; v0.6.2 closes both gaps before the next integration.

### Known issue (deferred to v0.7.0)

- **Catalog staleness on `DROP TABLE` + `CREATE TABLE` (same name).**
  Within a single connection, recreating a table by the same name
  leaves stale planner state that causes parameter-bound INSERT to
  fail with `QueryParseError`. Workaround: use unique table names
  (the v0.6.2 integration-test fixtures already do this). Tracked
  in `ROADMAP.md` under v0.7.0.

---

## [0.6.1] — 2026-04-24

**Theme:** clean-slate release. Turns every red CI badge green
without changing a single public API or wire surface. Ship this
before any v0.7.0 feature work lands.

### Fixed

- **Fuzz Nightly** — 3 of 20 targets were crashing or failing to
  build; all 20 now pass.
  - `fuzz_kernel_command`: `StreamId::Add` panicked on `u64`
    overflow under debug assertions when the fuzzer fed
    `stream_id == u64::MAX`. Switched the impl to
    `saturating_add` and added a regression unit test
    (`stream_id_add_saturates_on_overflow`) in
    `crates/kimberlite-types/src/tests.rs`.
  - `fuzz_sql_norec`: a planner quirk produced inverted
    `range.start > range.end` scans that the `debug_assert!` in
    `BTreeStore::scan` escalated to a libFuzzer deadly signal.
    Release builds already return empty for inverted ranges
    (intended defence), so the assertion is now gated
    `#[cfg(not(fuzzing))]`. The underlying planner issue is
    tracked in `ROADMAP.md` for a follow-up proper fix.
  - `fuzz_sql_parser`: non-exhaustive `match` on `ParsedStatement`
    broke the build after v0.6.0 added the masking-policy DDL
    variants (`CreateMaskingPolicy`, `DropMaskingPolicy`,
    `AttachMaskingPolicy`, `DetachMaskingPolicy`). Arms added.
  - Workspace: added `cfg(fuzzing)` to the `check-cfg` list so the
    `cfg(not(fuzzing))` guard doesn't warn.

- **CI (`ci.yml`)** — every required job green again.
  - Coverage upload no longer gates CI: dropped
    `fail_ci_if_error: true` on `codecov/codecov-action` and added
    `continue-on-error: true`. Codecov retired tokenless uploads,
    so this stays best-effort without a `CODECOV_TOKEN` secret.
  - `Test (ubuntu-latest)` no longer SIGTERMs. Two zstd proptests
    (`zstd_roundtrip_under_limit`, `zstd_rejects_oversized_payloads`)
    allocated up to 1 GiB payloads per case across the default 256
    cases — enough to blow past the 17-minute workflow watchdog on
    GitHub runners. Capped both tests at 8 proptest cases; the
    invariants still exercise end-to-end.
  - `vopr-features` job renamed from stale
    "VOPR v0.4.0 features" to "VOPR feature matrix".

- **Rustdoc / FFI** — `cargo doc -D rustdoc::private_intra_doc_links`
  failed on a `[parse_masking_strategy]` link in
  `kmb_admin_masking_policy_create`'s public docstring (target was
  a private helper). Rewrote the doc to describe the JSON shape
  inline and point to `MaskingStrategyWire`. `kimberlite-ffi.h`
  regenerates automatically via cbindgen.

- **Build FFI workflow** — removed the duplicate
  `test-typescript-sdk` job. The TS SDK moved from `ffi-napi` to
  napi-rs prebuilt `.node` addons; this job only downloaded the
  raw FFI library and had no way to load the napi addon, so every
  run was red. The real TS SDK CI lives in `sdk-typescript.yml`
  and already passes.

- **Python SDK mypy** — 30 strict-mode errors across
  `admin.py`, `compliance.py`, `client.py`, `pool.py`,
  `testing.py`, `aio.py` fixed. No behaviour changes:
  - Parameterised every bare `dict` / `Popen` generic.
  - Imported the missing `KmbAdminJson` in `compliance.py` and
    `Subscription` (via `TYPE_CHECKING`) in `client.py`.
  - Added `assert self._handle is not None` after
    `_check_connected()` to narrow the `Optional[c_void_p]`
    handle for `ComplianceNamespace`, `AdminNamespace`, and
    `Subscription` construction (soundness fix — callers of
    these namespaces must hold a connected client).
  - Dropped unused `# type: ignore` comments in `pool.py`,
    `client.py`.
  - Removed the broken `AsyncClient.sync()` shim that dispatched
    to a non-existent `Client.sync` attribute.
  - Added proper `__aexit__` type annotations.

- **Docs workflow (`docs.yml`)** — lychee link-check passes again.
  - Added `--base .` so root-relative `/docs/...` links resolve
    from the repo root.
  - Extended `.lycheeignore` for kimberlite.dev placeholders,
    illustrative `incidents`/`status` subdomains, and the
    PagerDuty runbook URL that was always illustrative.
  - Fixed the actually-broken relative links in
    `docs/reference/faq.md` (stale `docs/ARCHITECTURE.md`,
    `docs/COMPLIANCE.md`, `docs/BACKUP.md`, `docs/MONITORING.md`,
    `docs/DISASTER_RECOVERY.md`, `docs/PRESSURECRAFT.md`,
    `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `ROADMAP.md` paths
    all pointed outside the actual doc tree).
  - Fixed the stale API-stability timeline in `faq.md` (referenced
    v0.5/v0.8/v1.0 targets that predate the v0.6.0 release).
  - Fixed `docs/reference/README.md` pointing at a non-existent
    `cli/vopr.md`; now links to `../internals/vopr.md`.
  - Fixed `docs/reference/cli.md` root-relative `/docs/...` links.

### Changed

- SDK version bump: `kimberlite` (Python) and
  `@kimberlitedb/client` (TypeScript) to `0.6.1`. No API changes;
  patch release to match the Rust workspace version.

---

## [0.6.0] — 2026-04-21

**Theme:** feature-complete SQL + SDK + compliance surface. Every
primitive a healthcare-grade clinic app, finance ledger, or legal
case-management app needs is live and kernel-side — no in-memory
fakes, no parallel audit streams, no regex SQL parsers, no
hand-rolled erasure orchestrators.

### Breaking changes

- **Wire protocol v3 → v4.** `PROTOCOL_VERSION` bumped so
  `ConsentGrantRequest` and `ConsentRecord` can carry
  `basis: Option<ConsentBasis>` (GDPR Art 6 justification). v3
  clients against a v4 server are rejected at frame-header decode
  with a clean "unsupported protocol version" error; v4 servers
  do not speak v3. Upgrade both sides together. 4-cell compat
  matrix tested in `crates/kimberlite-wire/src/tests.rs::v3_v4_compat`.
  Migration details: [`docs/coding/migration-v0.6.md`](./docs/coding/migration-v0.6.md).
- **ABAC rule-name uniqueness.** `AbacPolicy::with_rule` now returns
  `Result<Self, AbacError>` and rejects rules whose name duplicates
  an existing rule. Previously duplicates were silently tolerated.
  Rule names are the audit-log identifier — HIPAA/SOX/FedRAMP
  reviews need this to be stable. Callers with duplicate-named
  rules must rename or deduplicate.

### Added

**SQL surface**

- **`ON CONFLICT` / UPSERT.** `INSERT INTO t (…) VALUES (…) ON
  CONFLICT (pk) DO UPDATE SET col = EXCLUDED.col` and
  `ON CONFLICT (pk) DO NOTHING`. Kernel-level `Command::Upsert` with
  a single atomic `UpsertApplied` event carrying a `resolution:
  Inserted | Updated | NoOp` discriminator — no dual-write window.
  Composes with `RETURNING`.
- **Correlated subqueries.** `EXISTS`, `NOT EXISTS`, `IN (SELECT)`,
  `NOT IN (SELECT)` with outer column references. Decorrelation to
  semi-join when provable; correlated-loop fallback otherwise.
  Configurable cardinality guard (`max_correlated_row_evaluations`,
  default 10M) rejects pathological shapes with
  `CorrelatedCardinalityExceeded`.
- **`AS OF TIMESTAMP` runtime resolver.** v0.5.0 shipped the parser +
  `QueryEngine::query_at_timestamp` with a caller-supplied resolver.
  v0.6.0 ships the default audit-log-backed timestamp→offset resolver
  so inline SQL works without the caller plumbing one. SDK
  `queryAt()` now accepts ISO-8601 / `Date` / nanos-bigint in
  addition to the existing event-offset form across TS + Python +
  Rust. Error surface: `AsOfBeforeRetentionHorizon` when asked older
  than the retained window.

**Compliance**

- **End-to-end `ConsentBasis`.** Wire v4 plus SDK surface for GDPR
  Art 6 basis (Consent, Contract, LegalObligation, VitalInterests,
  PublicTask, LegitimateInterests). `client.compliance.consent.grant({
  subjectId, purpose, basis })` across all three SDKs. Basis
  round-trips through the audit log and compliance exports.
- **`client.compliance.eraseSubject(subjectId)` auto-discovery.** The
  kernel now walks streams tagged `PHI` / `PII` with a `subject_id`
  column automatically. Override still available via
  `eraseSubject(subjectId, { streams: [...] })`. Idempotent — second
  call returns the existing signed receipt + emits a "second-call-noop"
  audit record. New VOPR scenario `EraseSubjectWithCrash` verifies
  crash-in-progress + recovery produces a valid hash-chain + signed
  proof.
- **Audit-log SDK query surface.** `client.compliance.audit.query({
  subjectId?, actor?, action?, fromTs?, toTs?, limit? })` across
  TS + Python + Rust. Returns structured rows with
  `changedFieldNames` only — never `before`/`after` values —
  enforced at the `kimberlite-wire` serialisation boundary.
  Server-side filtering with an index on
  `(tenant_id, subject_id, occurred_at)`. Streaming form over the
  existing Subscribe primitive.
- **Column-level masking policy CRUD.** DDL: `CREATE MASKING POLICY`,
  `ALTER TABLE t ALTER COLUMN c SET MASKING POLICY`, `DROP MASKING
  POLICY`. Reuses the `FieldMask` substrate (5 strategies shipped in
  v0.4.x: Redact, Hash, Tokenize, Truncate, Null). Planner
  composition: RBAC filter → mask → break-glass override. New
  kernel commands `CreateMaskingPolicy` / `AttachMaskingPolicy` /
  `DetachMaskingPolicy` / `DropMaskingPolicy` — all audit-logged.
  SDK: `client.admin.maskingPolicy.{create,alter,drop,list}()`
  across TS + Python + Rust. VOPR scenario `MaskingRoleTransition`
  proves no unredacted leakage across role transitions.

**Testing**

- **`StorageBackend` trait + `MemoryStorage` impl.** Extracted
  `trait StorageBackend` from the concrete `Storage` struct.
  `MemoryStorage` — no disk IO, hash-chain in-memory, deterministic
  replay. `Kimberlite::in_memory()` constructor alongside
  `Kimberlite::open(path)`; no breaking change. Test harness grows
  `Backend::InMemory` variant; TS + Python test modules accept
  `{ backend: 'memory' }`. 17.7× TempDir baseline speedup on
  Apple M-series in release.
- **ALTER TABLE VOPR crash scenario.** `AlterTableCrashRecovery` —
  add column + concurrent INSERTs + storage-crash mid-ALTER;
  recovery preserves `schema_version` monotonicity + event ordering.
  Additional doc-tests for `ADD COLUMN + SELECT *` round-trip.

### Safety

- Four new production `assert!` postconditions promoted in
  `crates/kimberlite-kernel/src/kernel.rs` covering the
  `Create/Attach/Detach/Drop MaskingPolicy` state-machine
  transitions (lines 1154, 1223, 1269, 1310). Each is paired with
  a `#[should_panic]` mirror test per
  [`docs/internals/testing/assertions-inventory.md`](./docs/internals/testing/assertions-inventory.md).

### Dependencies

- `sqlparser` 0.54 → 0.61. Prerequisite for ON CONFLICT syntax.
  16 breaking-change categories migrated. 470 `kimberlite-query`
  tests pass.
- `printpdf` 0.7 → 0.9. Full rewrite of
  `crates/kimberlite-compliance/src/report.rs` (427 lines) against
  the new layout-tree / Op-based model. Compliance-report output
  identical.
- `aws-lc-rs` 1.15 → 1.16 (pulls `aws-lc-sys` 0.37 → 0.40). Closes
  RUSTSEC-2026-0044..0048.
- `rustls-webpki` 0.103.9 → 0.103.13. Closes RUSTSEC-2026-0049,
  2026-0098, 2026-0099.
- `tar` 0.4.44 → 0.4.45. Closes RUSTSEC-2026-0067, 2026-0068.

### Infrastructure

- **EPYC nightly campaigns.** Three systemd timer pairs on the
  Hetzner EPYC box (`caterwaul`): VOPR nightly (daily 19:00 UTC,
  50k iterations ~2-4h), FV nightly-lite (daily 01:00 UTC, MIRI +
  Kani-smoke, ~35m), FV weekly (Sat 04:00 UTC, Alloy + Ivy + Coq +
  Kani full depth). 12 new `just` recipes.
- **Release-pipeline justfile.** 25-crate dep-ordered publish, 10-gate
  `release-dry-run` (version consistency, CHANGELOG section present,
  workspace build, clippy `-D warnings`, lib tests, doc-tests,
  publish dry-run, fuzz smoke, VOPR smoke, `cargo deny check
  advisories`), SDK-inclusive `bump-version` including
  sub-workspace Cargo.locks.

### Fixed

- `fix(query): reject deeply-nested SQL to prevent DoS via parser
  backtracking` (PR #87). New `depth_check` module with
  `MAX_SQL_NESTING_DEPTH=50` and `MAX_SQL_NOT_TOKENS=100` pre-parse
  guards. Rejection happens in microseconds.
- `fix(fuzz,chaos): eliminate false positives in nightly campaigns`
  (PR #86). Four surgical fixes silencing ~35 spurious crashes/run.
- `fix(upsert): clippy items-after-statements in convergence test`,
  `fix(client): collapse identical Query/QueryAt match arms`,
  `fix(parser): replace wildcard-for-single-variant in upsert
  tests` — drive-by lint fixes surfaced by the pre-publish audit.

### Documentation

- New `docs/coding/migration-v0.6.md` — v0.5.1 → v0.6.0 upgrade
  checklist + new-surface quick-reference.
- New `docs/reference/sql/correlated-subqueries.md` — design doc
  covering semi-join decorrelation, correlated-loop fallback,
  cardinality guard.
- New `docs/reference/sql/masking-policies.md` — DDL surface +
  composition with RBAC + break-glass.
- `docs/reference/sql/queries.md` — `AS OF TIMESTAMP` /
  `FOR SYSTEM_TIME AS OF` documented end-to-end.
- `docs/reference/sdk/parity.md` — `ConsentBasis`, audit query
  surface, and masking policy rows all flipped to ✅.
- `ROADMAP.md` rewritten for clarity — current / v0.7.0 / v1.0
  checklist / deferred / post-v1.0 cloud.
- `CHANGELOG.md` restructured — one `[Unreleased]` block, SemVer
  descending order, user-facing narrative only. Internal audit
  content moved to `docs-internal/audit/2026-Q2-release-readiness.md`
  and `docs-internal/design-docs/active/fuzz-to-types-hardening-apr-2026.md`.

---

## [0.5.1] — 2026-04-21

**Theme:** DX point release closing papercuts surfaced post-v0.5.0.
No architectural surface expands — storage-trait refactor,
wire-protocol bump, and new kernel commands stay in v0.6.0.

### Added

**SQL**

- **Scalar functions in `SELECT` projection.** `UPPER`, `LOWER`,
  `LENGTH`, `TRIM`, `CONCAT` / `||`, `ABS`, `ROUND(x)`,
  `ROUND(x, scale)`, `CEIL` / `CEILING`, `FLOOR`, `COALESCE`,
  `NULLIF`, `CAST`. New `parse_scalar_columns_from_select_items`
  pass parallels the existing aggregate / CASE / window passes.
  Un-aliased projections synthesise PostgreSQL-style default names.
- **Scalar predicates in `WHERE`.** `UPPER(name) = 'ALICE'`,
  `COALESCE(x, 0) > 10`, `CAST(s AS INTEGER) = $1` all route
  through a new `Predicate::ScalarCmp` variant. `!=` / `<>` route
  through ScalarCmp too (previously rejected).
- **`CAST(x AS <type>)`.** Integer widening is lossless; narrowing
  checks for overflow. `Text → Integer` uses `str::parse` and
  errors rather than silently coercing bad input to 0. `Real →
  Integer` truncates toward zero with explicit NaN/±∞ rejection.
  `Text → Boolean` accepts case-insensitive literals.
- **`NOT IN (list)` / `NOT BETWEEN low AND high`.** Both correctly
  surface `false` for `NULL` cells (SQL three-valued logic).
- **ILIKE / NOT LIKE / NOT ILIKE.** Three-valued NULL semantics
  preserved; Unicode simple lowercase for case-insensitive match.

**Testing**

- **`kimberlite-test-harness` crate (phase 1).** Wraps
  `Kimberlite::open(tempdir)` + in-process server behind a
  `TestKimberlite::builder()` API. Real parser, real kernel, real
  storage. Deterministic `Drop` that joins the polling thread with
  a 3s grace. Back-ported four e2e test files.
- **`@kimberlitedb/client/testing` + `kimberlite.testing`.** TS
  subpath export and Python module exposing
  `createTestKimberlite` / `create_test_kimberlite`. Both shell out
  to the shared `kimberlite-test-harness-cli` binary — one Rust
  codebase serves both SDKs.
- **`fuzz_scalar_expr` target** isolating the evaluator from
  planner/executor noise. Byte input → `arbitrary`-derived Shape →
  `ScalarExpr` tree (bounded depth) → twice-evaluated against a
  fixed row. Asserts determinism.

### Changed

- **SDK package rename.** `@kimberlite/client` → `@kimberlitedb/client`
  (npm org alignment). Auto-reconnect and retry built in; new
  `mapKimberliteError` error taxonomy.

### Fixed

- Regression test for SELECT alias preservation — the bare-column
  path was already correct as of v0.5.0, but a pinned test prevents
  silent regression.

---

## [0.5.0] — 2026-04-21

**Theme:** SQL coverage uplift + Phase 6 compliance endpoints +
test harness + nightly testing discipline.

Bundles three concurrent streams: the nine-phase SQL coverage
uplift (below), the April 2026 release-readiness audit deferred
items (see `docs-internal/audit/2026-Q2-release-readiness.md`), and
the AUDIT-2026-04 remediation wave.

### Added

**SQL — nine-phase coverage uplift**

- **Parameterised `LIMIT` / `OFFSET`** (`$N` placeholders). OFFSET
  is now actually applied — pre-fix `query.offset` was never read
  from the parsed AST, so `SELECT … OFFSET 50` silently returned
  rows from the start. Negative/non-integer bounds rejected with a
  clear error rather than panicking.
- **Simple `CASE` form** (`CASE x WHEN v1 THEN r1 … END`) — desugars
  to searched `CASE`.
- **Uncorrelated subqueries** — `IN (SELECT …)`, `EXISTS (…)`,
  `NOT EXISTS (…)`. Pre-execute pass walks the predicate tree, runs
  each subquery once before planning the outer query.
- **`INTERSECT` / `EXCEPT`** (plus existing `UNION`). `ALL` variants
  preserve multiset semantics; bare form deduplicates.
- **`RIGHT JOIN` / `FULL OUTER JOIN` / `CROSS JOIN` / `USING`.**
  CROSS JOIN has a cardinality guard (`MAX_JOIN_OUTPUT_ROWS = 1M`).
- **Aggregate `FILTER (WHERE …)`** on `COUNT(*)`, `COUNT(col)`,
  `SUM`, `AVG`, `MIN`, `MAX`.
- **JSON operators** `->`, `->>`, `@>` via new `Predicate::JsonExtractEq`
  and `Predicate::JsonContains`. Containment is recursive for
  objects, multiset-subset for arrays.
- **`WITH RECURSIVE`** with `MAX_RECURSIVE_DEPTH = 1000` iteration
  cap (honours the workspace "no recursion" lint).
- **`ALTER TABLE ADD / DROP COLUMN` end-to-end.** Kernel commands
  + paired `#[should_panic]` coverage on `schema_version`
  monotonicity assertions. Parser-only support shipped in v0.4.x;
  v0.5.0 lands the kernel path.

**Compliance (AUDIT-2026-04 remediation)**

- **Phase 6 server handlers** — `audit_query`, `export_subject`,
  `verify_export`, `breach_*`. Previously stub; now wired end-to-end
  with SDK wrappers.
- **`ErasureExecutor` trait + signed `ErasureCompleted` witness**
  emitted as a single kernel effect (AUDIT-2026-04 C-1).
  `client.compliance.eraseSubject()` surface in all three SDKs.
  (Auto-discovery of affected streams: v0.6.0.)
- **Tamper-evident `ComplianceAuditLog`** backed by `trait AuditStore`
  + durable storage (AUDIT-2026-04 H-2 / C-4).
- **Tenant isolation checker wired into VOPR** via new
  `EventKind::CatalogOperationApplied` / `EventKind::DmlRowObserved`
  event kinds. `sim-canary-catalog-cross-tenant` feature proves the
  wire fires (AUDIT-2026-04 C-2).
- **`RbacFilter::rewrite_query` recursive descent** into CTEs,
  UNION/INTERSECT/EXCEPT branches, derived-table subqueries in
  FROM, and subqueries in WHERE predicates (AUDIT-2026-04 M-7).
- **Seal / unseal tenant lifecycle** — single audit effect per
  command; tenant-scoped mutation rejection when sealed
  (AUDIT-2026-04 H-5).

**Testing & verification**

- **Nightly fuzzing** (`fuzz.yml`) — 20 targets with hard-fail
  crash + minimised repro archival.
- **VOPR nightly hard-fail** (`vopr-nightly.yml`) — removed
  `continue-on-error`; `.kmb` reproduction bundles archived on
  failure.
- **TLAPS PR-gating** (`formal-verification.yml::tla-tlaps-pr`) —
  5 core theorems PR-gated; the 92 compliance meta-theorems run
  nightly-full.
- **Fuzz-to-Types hardening campaign.** See
  `docs-internal/design-docs/active/fuzz-to-types-hardening-apr-2026.md`
  for the full narrative. Five bug classes made unrepresentable via
  new `kimberlite-types::domain` primitives (`NonEmptyVec`,
  `SqlIdentifier`, `BoundedSize<MAX>`, `ClearanceLevel`).
  Structure-aware fuzz targets (`fuzz_wire_typed`, `fuzz_vsr_typed`,
  `fuzz_sql_grammar`, `fuzz_sql_norec`, `fuzz_sql_pqs`). Persistent-
  mode fuzz infrastructure behind the `fuzz-reset` cargo feature
  (test-only).
- **UBSan nightly campaign** — 4h offset from ASan nightly on EPYC.
  Corpora shared so coverage benefits both.

### Changed

- **`AS OF TIMESTAMP` parser shipped** — `FOR SYSTEM_TIME AS OF '<iso>'`
  / `AS OF '<iso>'`. `QueryEngine::query_at_timestamp` accepts a
  caller-supplied resolver. (Default audit-log resolver: v0.6.0.)

### Fixed

- `pre_execute_subqueries` handles the `OFFSET`-never-read bug
  surfaced in the phase-1 regression tests.

### Migration

See [`docs/coding/migration-v0.5.md`](./docs/coding/migration-v0.5.md).
Short version: bump the SDK dep, update any `execute()` call sites
to read `.rowsAffected` / `.rows_affected` instead of treating the
return value as a number.

---

## [0.4.2] — 2026-04-20

**Theme:** release-readiness — truth-in-advertising patch + SDK
production launch. Corrects user-facing claims to match code; no
behaviour changes or feature deferrals.

### Breaking changes

- **Wire protocol v1 → v2.** `PROTOCOL_VERSION` bumped from 1 to 2.
  v0.4.0 clients cannot talk to v0.4.2 servers and vice versa — the
  handshake rejects. Payload is now a `Message` enum
  (Request | Response | Push) instead of a flat Request / Response
  pair, which cleanly supports the new Subscribe push primitive.
  No protocol shim; upgrade both sides in lockstep.

### Added

**SDK production launch (9 phases)**

- **Production-grade SDKs for Rust, TypeScript, and Python.** Every
  server-side primitive is reachable from all three SDKs with
  idiomatic ergonomics, structured errors, typed rows, connection
  pooling, real-time subscriptions, admin operations, and GDPR
  compliance flows.
- **Structured errors** replace the prior `number` return from
  `execute()` — all three SDKs now return `ExecuteResult` with
  `.rowsAffected` / `.rows_affected` / `.returning`.
- **Real-time subscriptions** over the new Push message kind.
- **Admin operations** — tenant CRUD, stream CRUD, API-key
  lifecycle.
- **GDPR compliance flows** — consent grant/revoke, breach
  notification, subject export, audit query.
- **Platform binaries** — Linux x86_64/aarch64, macOS x86_64/aarch64,
  Windows x64. `.sha256` sidecars; `install.sh` verifies against
  `SHA256SUMS` manifest.

### Changed

- **Truth-in-advertising scrub across `docs/`, `crates/`,
  `README.md`, `CLAUDE.md`, `SECURITY.md`** — "compliant" /
  "certified" language → "-ready" + framework-specific qualifiers.
  Formal-verification claims (`"world's first/only"`, "136+ proofs")
  replaced with honest decomposition. Assertion-count claims
  removed; replaced with pointer to
  `docs/internals/testing/assertions-inventory.md`. VOPR scenario
  count corrected (74 enum variants, ~50 substantive, ~24
  scaffolded). "90-95% Antithesis-grade" replaced with
  "Antithesis-inspired deterministic simulation". Framework
  readiness percentages → "designed for / ready / no audit
  completed" framing. See
  `docs-internal/audit/2026-Q2-release-readiness.md` for the full
  18-item rubric.

### Fixed

- `install.sh` POSIX-sh local-variable collision inside
  `verify_checksum()` that caused `unzip` to look for the wrong
  filename. Helper-function locals renamed throughout. Mirror
  re-synced to `website/public/install.sh`.
- **Release publish workflow** — `cargo publish | tee` masking
  cargo failures fixed with `set -euo pipefail` + `PIPESTATUS[0]`;
  publish order expanded from 6 crates to full 24-crate topological
  order in 6 tiers with 30s settle delays; `kimberlite-doc-tests`
  marked `publish = false`.

---

## [0.4.1] — 2026-02-04

**Theme:** VOPR infrastructure hardening + formal verification
additions.

### Added

- **FCIS pattern adapters** in `crates/kimberlite-sim/src/adapters/`
  for Clock, RNG, Network, Storage, Crash. Trait-based abstraction
  for swapping sim ↔ production implementations.
- **19 specialised invariant checkers** — offset monotonicity,
  event-count bounds, consensus safety. O(1) checkers replace the
  O(n!) linearizability checker (which was a naive implementation
  that couldn't scale).
- **5 canary mutations** with 100% detection rate — proves VOPR
  catches real bugs.
- **17 fault-injection test scenarios.**
- **Docker release hotfix** — v0.4.1 bumps the Docker image tag
  without a workspace version bump.

### Performance

- Maintained >70k sims/sec throughput with the new invariant
  checkers (vs the prior O(n!) checker that was the bottleneck).

---

## [0.4.0] — 2026-02-03

**Theme:** VOPR advanced debugging — production-grade DST platform.

### Added

- **Timeline visualisation** — ASCII Gantt chart renderer for
  understanding simulation execution flow. 11 event kinds
  (client ops, storage, network, protocol, crashes, invariants).
  `vopr timeline failure.kmb --width 120`.
- **Bisect to first bad event.** `BisectEngine` performs O(log n)
  binary search through the event sequence.
  `SimulationCheckpoint` + `CheckpointManager` with deterministic
  RNG fast-forward to any event. 10-100× faster than full replay;
  typical convergence <10 iterations for 100k events. Generates
  minimal reproduction bundles.
- **Delta debugging** — Zeller's ddmin algorithm for automatic
  test-case minimisation. Dependency-aware (network, storage,
  causality). 80-95% test-case reduction achieved.
- **Real kernel state hash** — BLAKE3 hashing of actual kernel
  state replaces the prior placeholder. Enables true determinism
  validation and checkpoint integrity.
- **Coverage dashboard** (`vopr dashboard`). Axum + Askama +
  Datastar web UI. 4 coverage dimensions (state points, message
  sequences, fault combinations, event sequences). Real-time SSE
  updates; top seeds table; progress bars.
- **Interactive TUI** (`vopr tui`). Ratatui-based terminal UI with
  3 tabs (Overview, Logs, Configuration), real-time progress
  gauge, scrollable logs.

### Changed

- CLI gains 5 new commands: `timeline`, `bisect`, `minimize`,
  `dashboard`, `tui`.
- Feature flags: `dashboard` (axum + askama + tokio-stream), `tui`
  (ratatui + crossterm).

---

## [0.3.1] — 2026-02-03

**Theme:** VOPR VSR mode — protocol-level Byzantine testing.

### Added

- Complete VSR protocol integration into VOPR. Fundamental
  architecture shift from state-based simulation to testing actual
  VSR replicas processing real protocol messages with Byzantine
  mutation.
- **10 protocol-level attack patterns** in `protocol_attacks.rs`
  (SplitBrain, MaliciousLeader, PrepareEquivocation, ForgedMessage,
  ReplayOldPrepare, …) with 3 pre-configured suites (Standard,
  Aggressive, Subtle). 100% attack detection rate.
- **Event logging** with compact binary format (~100 bytes/event).
  `.kmb` reproduction bundles (bincode + zstd). Perfect
  reproduction from seed + event log.

---

## [0.3.0] — 2026-02-03

**Theme:** VSR hardening and Byzantine resistance.

### Added

- **Storage realism** — 4 I/O scheduler policies (FIFO, Random,
  Elevator, Deadline); concurrent out-of-order I/O (up to 32
  operations/device); 5 crash scenarios (DuringWrite, DuringFsync,
  PowerLoss, etc.); block-level granularity (4KB); torn-write
  simulation.
- **Byzantine-resistant VSR consensus** with production-enforced
  assertions in cryptography, consensus, and state-machine paths.
- **Realistic workload generators** — 6 patterns (Uniform, Hotspot,
  Sequential, MultiTenant, Bursty, ReadModifyWrite).
- **Coverage-guided fuzzing** with multi-dimensional coverage
  tracking and 3 selection strategies.

### Performance

- 85k-167k sims/sec throughput with full fault injection.
- Storage realism overhead: <5%. Event logging overhead: <10%.

---

## [0.2.0] — 2026-02-02

**Theme:** advanced testing infrastructure + documentation.

### Added

- **VOPR framework** (Viewstamped Replication Operational Property
  testing) — deterministic simulation framework inspired by
  TigerBeetle + Antithesis.
- **Invariant checking** with production-ready documentation.
- **Comprehensive docs layout** — user-facing in `docs/`, internal
  in `docs-internal/`.

---

## [0.1.10] — 2026-01-31

**Theme:** protocol layer, SDK integration, secure data sharing.

### Added

- Complete **wire protocol** implementation (TCP + length-prefixed
  frames, JWT + API-key auth, TLS).
- **Multi-language SDKs** (Python, TypeScript, Rust, Go) with
  tests and CI.
- **SQL query engine** — SELECT, INSERT, UPDATE, DELETE, CREATE
  TABLE, aggregates, GROUP BY, HAVING, DISTINCT, INNER / LEFT
  JOIN, parameterised queries (`$1`, `$2`, ...).
- **Secure data-sharing layer** with consent ledger.
- **MCP server** for LLM integration (4 tools).

---

## [0.1.5] — 2026-01-25

**Theme:** RBAC, ABAC, masking, consent, erasure.

### Added

- **RBAC** with 4 roles, SQL rewriting, column filtering, row-level
  security.
- **ABAC** with 12 condition types, 3 pre-built compliance policies
  (HIPAA, FedRAMP, PCI DSS).
- **Field-level data masking** with 5 strategies (Redact, Hash,
  Tokenize, Truncate, Null).
- **Consent management** with 8 purposes, kernel-level enforcement.
- **Right to erasure** (GDPR Article 17) with 30-day deadlines and
  exemptions.
- **Breach detection** with 6 indicators and 72-hour notification
  deadlines.
- **Data portability export** (GDPR Article 20) with HMAC-SHA256
  signing.
- **Audit logging** with 13 action types across all compliance
  modules.

---

## [0.1.0] — 2025-12-20

**Theme:** core foundation — crypto, storage, consensus, projections.

### Added

- **Cryptographic primitives.** SHA-256 + BLAKE3 dual-hash
  (`HashPurpose` enum enforces compliance vs hot-path split).
  AES-256-GCM content encryption. Ed25519 signatures.
- **Append-only log storage** with CRC32 checksums, segment
  rotation (256MB), index WAL.
- **Pure functional kernel** (Functional Core / Imperative Shell).
  Commands → State + Effects; deterministic by construction.
- **VSR consensus** (Viewstamped Replication) adapted from
  TigerBeetle's architecture, extended with multi-tenant routing,
  clock synchronisation, and repair-budget policies.
- **B+tree projection store** with MVCC and SIEVE cache for
  derived-view queries.
- **Multi-tenant isolation** at placement and kernel level.

### Design principles

- **All data is an immutable ordered log; all state is a derived
  view.**
- **Functional Core / Imperative Shell** — kernel is pure, IO at
  the edges.
- **Make illegal states unrepresentable** — enums over booleans,
  newtypes over primitives.
- **Parse, don't validate** — validate at boundaries once, then
  use typed representations throughout.
