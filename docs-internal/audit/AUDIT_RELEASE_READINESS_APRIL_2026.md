# Kimberlite Release-Readiness Audit — April 2026

**Audit Date:** 2026-04-20
**Target Commit:** `4e817b1` (sdk: notebar feedback pass — audit wire v3 + cross-SDK parity (S4.\*))
**Workspace Version:** 0.4.0 (last tag `v0.4.1` was a Docker-only fix; 40+ feature commits since)
**Scope:** OSS release readiness across 7 user-defined dimensions
**Reviewers:** Jared Reyes + Claude Code (Opus 4.7, 1M context)
**Classification:** Internal — Pre-OSS-Release Gate

**Prior / adjacent audits:**
- `AUDIT-2026-01` (Jan 2026) — 21 findings
- `AUDIT-2026-02` (Feb 2026) — 4 findings
- `AUDIT-2026-03` (Feb 2026) — 16 findings (Byzantine coverage)
- `AUDIT-2026-04` (Apr 2026) — 25 findings (compliance-claim gaps); 7-PR remediation currently in `CHANGELOG.md [Unreleased]`
- *This audit* — release-readiness (distinct scope; does not duplicate the above)

---

## 1. Executive Summary

**Verdict: v0.4.2 PATCH RELEASE RECOMMENDED after truth-in-advertising fixes.**

Kimberlite's *core is production-quality and its release infrastructure is mature*: append-only log, VSR consensus, MVCC time-travel, SQL DML + window functions, RBAC/ABAC, consent/erasure, dual-hash crypto, Rust+TS SDKs (Python beta), 5-platform binary releases, 23 crates on crates.io, Docker multi-arch, Homebrew tap, nightly VOPR + formal-verification workflows.

However, a release-blocking class of issues pervades the **user-facing surface**: docs contradict themselves on version/readiness, the website displays a 3-minor-version-stale version string, the install script lies about what it does, and several marketing claims (absolute compliance certifications, "136+ proofs", "38 assertions", "46 scenarios", "90-95% Antithesis-grade") overstate reality. These are not functional bugs — the *code is honest* — but shipping OSS in this state invites regulatory / legal / trust erosion.

**This v0.4.2 patch corrects claims to match code. No behaviour changes; no feature deferrals; no reopened roadmap.** All heavy lift (Phase 6 server impl, TLAPS PR-gating, doc-test repair, fuzz CI, perf re-benchmark) is explicitly scheduled for v0.5.0, with acceptance criteria written into `ROADMAP.md`.

The `AUDIT-2026-04` remediation PR series (7 PRs in `[Unreleased]`) is complementary and lands before this patch.

---

## 2. Scope + Methodology

Three parallel Explore agents, each "very thorough" tier:

- **Agent A — Features vs claims, testing rigor, CI/CD state**: walked README, `/docs/concepts/`, `/docs/reference/`, mapped each headline claim to code, counted assertions / proptests / fuzz targets / VOPR variants, read all 18 GitHub workflows.
- **Agent B — Nightly testing, releases, crates.io**: read `.github/workflows/vopr-nightly.yml`, `formal-verification*.yml`, `release.yml`, `publish-crates.yml`; ran `gh release list` and `cargo search` checks; enumerated fuzz targets and formal-verification tools.
- **Agent C — Docs + website + install UX**: walked all 107 `.md` files in `/docs/`, `website/templates/*.html`, `website/public/install.sh`, checked for claim drift, contradictions, and stale version strings.

Synthesis reviewed against spot-reads of the highest-consequence files: `docs/concepts/overview.md:180-230`, `install.sh` (all 260 lines), `docs/start/installation.md:1-60`, `docs/reference/sdk/parity.md:1-100`, `docs/reference/sql/queries.md:1-60`, `Cargo.toml:45-46`, and `git log v0.4.0..HEAD`.

Methodology note: exploration agents produce a trustworthy first pass; every release-blocking finding below was re-verified by direct `Read` on the cited file:line.

---

## 3. Findings by Dimension

### 3.1 Feature Claims vs Implementation

#### Verified — shipped & tested

| Claim | Evidence |
|---|---|
| Append-only log, SHA-256 hash chains, CRC32 | `crates/kimberlite-crypto/src/chain.rs`, `kimberlite-storage/` |
| Viewstamped Replication (Normal, ViewChange, Recovery, Repair, StateTransfer, Reconfiguration) | `crates/kimberlite-vsr/src/` |
| MVCC time-travel via `AT OFFSET` | `crates/kimberlite-query/src/` — `query_at()` |
| DML: INSERT/UPDATE/DELETE/SELECT, DDL: CREATE/ALTER TABLE, aggregates, GROUP BY, HAVING, UNION, INNER/LEFT JOIN, CTEs, subqueries | `crates/kimberlite-query/src/parser.rs`, `executor.rs` — 85+ tests |
| Window functions: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, FIRST_VALUE, LAST_VALUE | `crates/kimberlite-query/src/window.rs` (S3.2, commit `fd7fce2`) |
| AsyncClient (Rust tokio + sans-I/O framing) | `crates/kimberlite-client/src/async_client.rs` (S2.1, commit `f4a8f8a`) |
| Multi-tenant isolation with cryptographic boundaries | `crates/kimberlite-directory/src/lib.rs` + `e2e_healthcare.rs` |
| RBAC (4 roles + row/column filter) | `crates/kimberlite-rbac/src/` |
| ABAC (12 condition types + HIPAA TPO + break-glass prebuilts) | `crates/kimberlite-abac/src/` |
| Field-level masking (5 strategies) | `crates/kimberlite-crypto/src/field.rs` |
| Consent management (8 purposes, kernel-enforced) | `crates/kimberlite-compliance/src/consent.rs` |
| Right to Erasure (GDPR Art. 17; 30-day deadlines, exemptions) | `crates/kimberlite-compliance/src/erasure.rs` |
| JWT + API-key auth with rotation | `crates/kimberlite-server/src/auth.rs` |
| Dual-hash crypto (SHA-256 + BLAKE3), compile-time `HashPurpose` boundary | `crates/kimberlite-crypto/src/hash.rs` |
| FCIS (pure kernel, IO at shell) | `crates/kimberlite-kernel/src/` — no IO/clock/random in `apply_committed()` |
| Healthcare E2E against in-process server | `crates/kimberlite-client/tests/e2e_healthcare.rs` (S3.7, commit `68d4ddf`; finance E2E removed in healthcare pivot) |
| Audit wire v3 + cross-SDK parity | commit `4e817b1` (S4.\*) |

#### Partial — scaffolded, not end-to-end

| Feature | Status |
|---|---|
| `audit_query` | SDK wrapper present; server handler returns 5xx stub. `docs/reference/sdk/parity.md:76`. |
| `export_subject`, `verify_export` | SDK present; server stub. `parity.md:77-78`. |
| `breach_report_indicator`, `breach_query_status`, `breach_confirm`, `breach_resolve` | SDK present; server stubs. `parity.md:79-82`. |
| Masking policy CRUD | Deferred v0.6. `parity.md:83`. |
| `erasure.mark_stream_erased` | ⚠️ Python SDK missing; scheduled v0.5.1. `parity.md:64`. |
| Go SDK | Deferred post-v0.4. README:217. |

#### Unsubstantiated / overstated claims

| Claim | Location | Reality |
|---|---|---|
| "136+ formal proofs guarantee correctness" | `README.md:15,42,123` | Mixes ~25 TLA+ theorems, 5 Ivy invariants, 15+ Coq lemmas, 91 Kani proofs, 92 compliance TLAPS aspirations → ~230 spec artifacts; only ~50 are mechanically verified in PR-gated CI. TLAPS proofs live in `formal-verification-aspirational.yml` (nightly only). |
| "World's first / only database with complete 6-layer formal verification" | `docs/compliance/certification-package.md:34`, `docs/concepts/formal-verification.md` | Competitive overstatement. TigerBeetle (Ivy), FoundationDB (record layer proofs), Isabelle/seL4, Amazon s2n-tls all have multi-layer verification. Kimberlite's stack is strong but not unique. |
| "90-95% Antithesis-grade testing" | `CLAUDE.md:168` | Antithesis is hypervisor-level. VOPR is deterministic simulation (excellent, but different category). |
| "46 test scenarios across 10 phases" | `CLAUDE.md:171`, `README.md`, `docs/concepts/overview.md:202` | 74 enum variants in `crates/kimberlite-sim/src/scenarios.rs`; ~50 substantive, ~24 TODO-scaffolded (ReconfigDuringPartition, Upgrade\*, Standby\*, some RBAC variants). |
| "38 production assertions promoted" | `CLAUDE.md:294`, `README.md:180` | Pinned to v0.2.0 (Feb 2026). Current count is 2,489 `assert!()` calls. `docs/internals/testing/assertions-inventory.md` now prudently declines to quote a number — README/CLAUDE should too. |
| "Full SQL support" | `docs/concepts/overview.md:213` | Missing RIGHT/FULL OUTER JOIN, transactions (`BEGIN`/`COMMIT`/`ROLLBACK`), `AS OF TIMESTAMP` (the quickstart in README:80 uses `AS OF TIMESTAMP` but `docs/reference/sql/queries.md:28` says it's v0.6). |
| "Kimberlite is production-ready" (§ Current Status v1.0.0) | `docs/concepts/overview.md:194-217` | **Direct contradiction of README §Status** which correctly says "v0.x — Developer Preview. Not yet battle-tested at scale." Release-blocker. |
| "Sacrifices 10-50% write performance for auditability" | `README.md:173` | Number comes from `docs/operating/performance.md:844` v0.2.0 baseline (Feb 2026); no current benchmarks for v0.4.x. |
| "HIPAA-compliant" | multiple | No HIPAA audit exists. Code substrate supports HIPAA workflows; framing should be "HIPAA-ready" / "designed for HIPAA". |
| "SOC 2-certified" | `docs/operating/production-deployment.md:37` (implicit 90% readiness rating) | No SOC 2 Type II audit. "SOC 2-ready" is honest. |
| "GDPR-compliant" | `docs/concepts/data-portability.md:10`, `compliance.md` | Art. 17 erasure + Art. 20 portability implemented; no GDPR audit. Framing: "GDPR-ready (Art. 17 + 20)". |
| "Same as TigerBeetle's battle-tested consensus" | `README.md:144` context | VSR adapted from TigerBeetle's architecture with Kimberlite-specific extensions (multi-tenant routing, clock sync, repair budgets). Battle-testing does not transfer by descent. |

---

### 3.2 CI/CD State

18 workflows in `.github/workflows/`. Key status:

| Workflow | State | Notes |
|---|---|---|
| `ci.yml` | ✅ Green on main for format/clippy/check/test | ⚠️ Doc-tests: 55/58 fail in `crates/kimberlite-doc-tests/` (ROADMAP-tracked as non-blocking; user trust risk) |
| `vopr-determinism.yml` | ✅ PR-blocking | |
| `vopr-nightly.yml` | ⚠️ Masks failures | `continue-on-error: true` on invariant jobs; references missing `tools/validate-coverage.py` |
| `release.yml` | ✅ Ready; tag-triggered; 5 platforms + Docker multi-arch | Verified no hardcoded version |
| `publish-crates.yml` | ✅ Ready; ordered publish with 30s delays; skip-if-exists | |
| `publish-docker.yml` | ✅ Ready | |
| `formal-verification.yml` | ✅ PR-blocking: TLC, Alloy-quick, Coq, Kani, MIRI | ⚠️ TLAPS + full Ivy are nightly-only (`formal-verification-aspirational.yml`) |
| `formal-verification-aspirational.yml` | ⚠️ Nightly only | TLAPS stretched to 3000/10000; not PR-gated |
| `build-ffi.yml` | ⚠️ Partial | Core FFI green; SDK test scaffolding incomplete |
| `deploy-site.yml` | ✅ Triggers on `website/**` push to main | Auto-redeploy confirmed |
| `docs.yml` | ✅ Partial | Pandoc + build OK; deploy gated on GitHub Pages config |
| `sdk-python.yml` | ⚠️ Partial | Type check + tests OK; wheel via FFI |
| `sdk-typescript.yml` | ✅ Partial | Napi-rs prebuilts |
| `sdk-go.yml.disabled` | ❌ Disabled | Go post-v0.4 |
| `security.yml` | ⚠️ Issues | cargo-audit OK; SBOM fragile; license checks partial |
| `claude-code-review.yml` / `claude.yml` | ✅ Ready | |
| `bench.yml` | ✅ 21 Criterion benchmarks | |

**CI gaps (deferred to v0.5.0 in ROADMAP):**
- 20 fuzz targets exist; only 3 run in CI smoke (`fuzz-smoke`). No nightly fuzz job.
- VOPR nightly masks invariant failures.
- TLAPS proofs not PR-gated.
- 55/58 doc-tests fail.

---

### 3.3 Nightly Fuzzing / DST / Formal Verification

Scheduled workflows:

| Cron | Workflow | Coverage |
|---|---|---|
| `0 2 * * *` | `vopr-nightly.yml` | VOPR 1M-iter baseline + swizzle + combined + multi-tenant; 10-seed determinism; 5-canary mutation detection; coverage enforcement (100k) |
| `0 3 * * *` | `formal-verification-aspirational.yml` | TLAPS 16 Cat-A theorems across 4 proof files (Compliance 10, Recovery 3, ViewChange 1, VSR 2), stretch 3000 nightly / 10000 EPYC |

**Formal verification stack (verified runnable):**

| Layer | PR-blocking | Nightly | Artifacts |
|---|---|---|---|
| TLA+ (TLC model-checker) | ✅ quick configs | — | `specs/tla/` (46 `.tla` files; 25 theorems documented) |
| TLAPS (proof engine) | ❌ | ✅ aspirational | `specs/tla/compliance/*_Proofs.tla` |
| Ivy (Byzantine consensus) | ✅ (Apr 2026) | — | `specs/ivy/VSR_Byzantine.ivy` — 5 safety invariants; pinned `v0.1-msv`, Python 2/3 workaround |
| Alloy (structural) | ✅ quick scopes | ✅ full scopes | `specs/alloy/` — HashChain, Quorum |
| Coq (crypto) | ✅ | — | `specs/coq/` — Common, SHA256, BLAKE3, AES_GCM, Ed25519, KeyHierarchy (6 core); extraction unfinished |
| Kani (bounded model check) | ✅ unwind 32 | ✅ unwind 128 (EPYC) | 91 proofs |
| MIRI (UB detection) | ✅ | — | storage, crypto, types |

**Fuzz targets (20 total, listed below):**

```
fuzz_sql_parser, fuzz_sql_grammar, fuzz_sql_norec, fuzz_sql_pqs,
fuzz_vsr_protocol, fuzz_vsr_typed,
fuzz_wire_typed, fuzz_wire_deserialize,
fuzz_auth_token,
fuzz_rbac_injection, fuzz_rbac_rewrite, fuzz_abac_evaluator,
fuzz_storage_decompress, fuzz_crypto_encrypt,
(+ 6 more per just fuzz-list)
```

CI smoke runs 3 × 30s. No continuous fuzzing job — **deferred to v0.5.0**.

---

### 3.4 GitHub Releases + Download Scripts

Latest tags (most recent first): `v0.4.1` (Mar 2, 2026 — Docker fix only), `v0.4.0` (Feb 22, 2026), `v0.1.1`, `v0.1.0`.

**Latest release assets (v0.4.1):**
- `kimberlite-linux-x86_64.zip`
- `kimberlite-linux-aarch64.zip`
- `kimberlite-macos-x86_64.zip`
- `kimberlite-macos-aarch64.zip`
- `kimberlite-windows-x86_64.zip`
- `SHA256SUMS`, `SHA512SUMS`, `checksums.txt`
- Cosign keyless signatures (`continue-on-error: true` — signature step non-fatal)
- Docker images `linux/amd64` + `linux/arm64`

**Install script (`install.sh`, 260 lines):**
- ✅ OS detection (Linux, Darwin, Windows→error with winget pointer)
- ✅ Arch detection (x86_64, aarch64)
- ✅ Version resolution via GitHub API or `--version` flag
- ✅ Download via `curl` or `wget`; unzip; chmod +x; PATH update
- ❌ **Does NOT verify checksums** — `docs/start/installation.md:20` says it does
- ❌ **Does NOT install `kmb` alias** — `docs/start/installation.md:20` says it does

**Homebrew:** tap auto-updated by `release.yml`.

---

### 3.5 Documentation Accuracy

107 `.md` files across `/docs/` + top-level (README, CLAUDE, ROADMAP, CHANGELOG, CONTRIBUTING). See §3.1 "Unsubstantiated claims" for release-blocker list.

**Additional findings:**
- `README.md:80` Quick Start example uses `SELECT * FROM patients AS OF TIMESTAMP '2026-02-03 10:30:00';` — but `docs/reference/sql/queries.md:28` says `AS OF TIMESTAMP` is v0.6.0. **Contradiction**.
- `README.md:198` cites "1,300+ tests" — not sourced to CI output; verify with `cargo nextest` counts before release.
- `README.md:48-53` uses "HIPAA-compliant EHR systems" / "SOC 2-ready applications" — mix of `-compliant` and `-ready`; standardise on `-ready` or `designed-for`.
- `docs/concepts/overview.md:194-217` — release-blocker (see §4.1).
- `docs/compliance/certification-package.md:34` "only database with 6-layer formal verification" — see §3.1.

---

### 3.6 Website

**Platform**: Custom Rust + Askama templates; SST v3 + AWS App Runner (Sydney, `ap-southeast-2`); ECR container deploy.
**Auto-redeploy**: `.github/workflows/deploy-site.yml` triggers on `website/**` push to main + manual dispatch. ✅
**Public URL**: `https://kimberlite.dev`.
**Version-string drift:**

| File | Line | Current | Correct |
|---|---|---|---|
| `website/templates/home.html` | 132 | `v0.1.0` | `v0.4.2` (or dynamic fetch) |
| `website/templates/download.html` | 28 | `--version v0.6.0` example | latest example, or `$(LATEST)` placeholder |
| `website/public/install.sh` | — | mirror of root `install.sh` | must re-sync after Wave 3 |

**Broken links / stale pricing:** none identified in template sweep.

---

### 3.7 crates.io

**23 publishable crates @ v0.4.0** (workspace version; all inherit from `[workspace.package]`):

```
kimberlite, kimberlite-types, kimberlite-crypto, kimberlite-storage,
kimberlite-kernel, kimberlite-client, kimberlite-query, kimberlite-rbac,
kimberlite-abac, kimberlite-compliance, kimberlite-mcp, kimberlite-migration,
kimberlite-agent-protocol, kimberlite-config, kimberlite-directory,
kimberlite-event-sourcing, kimberlite-io, kimberlite-oracle,
kimberlite-server, kimberlite-sharing, kimberlite-vsr, kimberlite-wire,
kimberlite-store
```

**13 internal-only (`publish = false`):**
```
kimberlite-admin, kimberlite-bench, kimberlite-chaos, kimberlite-chaos-shim,
kimberlite-cli, kimberlite-cluster, kimberlite-dev, kimberlite-ffi,
kimberlite-node, kimberlite-sim, kimberlite-sim-macros, kimberlite-studio,
kimberlite-doc-tests
```

**Metadata:** description, license, repository, keywords, categories, homepage, documentation — all inherited from workspace; complete for every publishable crate.

**Version drift:** workspace `Cargo.toml:46` = `0.4.0`. Git tag `v0.4.1` was a Docker-only fix (did not bump workspace version). All 23 crates on crates.io are at `0.4.0`.

---

## 4. Critical Fixes Before v0.4.2 Release

Numbered for tracking. Each fix includes file:line and a verification command.

### 4.1 `docs/concepts/overview.md` — Rewrite "Current Status" block

**Location:** `docs/concepts/overview.md:194-217`
**Current:** Claims `v1.0.0` + "production-ready" + "Full SQL support" + lists Go SDK as shipped.
**Correction:** Mirror `README.md §Status` (v0.x Developer Preview); split compliance into "shipped v0.4" vs "v0.5 targets"; replace "Full SQL support" with concrete feature list + planned gaps; SDK row = Rust (stable), TS (stable), Python (beta), Go (deferred post-v0.4).
**Verify:** `grep -n "v1\.0\.0\|production-ready\|Full SQL support" docs/concepts/overview.md` → zero hits.

### 4.2 Compliance certification language

**Locations:** grep surface-wide.
**Rewrite rules:**
- `HIPAA-compliant` → `HIPAA-ready` / `designed to support HIPAA compliance`
- `SOC 2-certified` / `SOC2-certified` / `SOC 2-compliant` → `SOC 2-ready` (footnote: "No SOC 2 Type II audit completed as of v0.4; third-party audit tracked in ROADMAP.md for v1.0.")
- `GDPR-compliant` → `GDPR-ready (Art. 17 erasure and Art. 20 portability implemented)`
**Verify:** `grep -rn "HIPAA-compliant\|SOC 2-certified\|SOC2-certified\|SOC 2-compliant\|GDPR-compliant" docs/ website/ README.md CLAUDE.md` → zero hits.

### 4.3 Formal-verification claims

**Locations:** `README.md:15,42,123,180` (badge + text); `docs/concepts/formal-verification.md:10,42`; `docs/compliance/certification-package.md:34`; `docs/internals/formal-verification/traceability-matrix.md` rows 24-27.
**Correction:**
- README badge text "verified — 136+ proofs" → "verified — formal spec + bounded proofs" (link unchanged).
- Body text: precise decomposition (TLA+ 25 theorems [TLC PR-CI; TLAPS nightly], Coq 6 core files, Alloy 4 scopes, Ivy 5 invariants, Kani 91 PR-blocking, MIRI PR-blocking). Drop "world's first" / "only" phrasing.
- Traceability matrix: HIPAA/GDPR/SOC2 meta-theorem rows labelled "formalized — TLAPS verification runs nightly, not PR-gated (v0.5.0 target)".
**Verify:** `grep -rn "136+" README.md docs/` should return only the updated context, no standalone claim.

### 4.4 Assertion count

**Locations:** `CLAUDE.md:290-297`; `README.md:180`.
**Correction:** Remove "38 critical assertions promoted" specific number. Replace with: "Production assertions guard cryptographic (25+), consensus (9+), and state-machine (4+) invariants. Inventory drifts as codebase evolves; see `docs/internals/testing/assertions-inventory.md` for current guidance and paired `#[should_panic]` test policy."
**Verify:** `grep -rn "38 production assertions\|38 critical assertions" README.md CLAUDE.md docs/` → zero hits.

### 4.5 VOPR scenario count

**Locations:** `README.md` (VOPR badge section or body), `CLAUDE.md:168-171`, `docs/concepts/overview.md:202`.
**Correction:** "74 scenario variants (~50 with full implementations, ~24 scaffolded for v0.5/v0.6/v0.8 completion); 19 invariant checkers; 5 canary mutations with 100% detection rate."
**Also:** `CLAUDE.md:168` "90-95% Antithesis-grade" → "Antithesis-inspired deterministic simulation with full determinism validated in CI; hypervisor-level instrumentation out of scope."

### 4.6 Phase 6 stub clarity on README + overview

**Locations:** `README.md` "Key Features" and "SDKs" sections; `docs/concepts/overview.md` compliance block.
**Correction:** Any reference to breach notification / audit query / subject export → prefix with "v0.5.0 target:" or move below a "Coming v0.5.0" sub-section. Cross-link to `docs/reference/sdk/parity.md`.
**Server handler message (optional polish):** `crates/kimberlite-server/src/handler.rs` stubs — ensure they return `ErrorCode::NotImplemented` with message "endpoint scheduled for v0.5.0; see ROADMAP.md" rather than a generic 5xx.

### 4.7 Performance claim

**Location:** `README.md:173`; `docs/reference/faq.md` (search); `docs/operating/performance.md:844-870`.
**Correction:** Remove "10-50% write performance" number. Replace with qualitative: "Kimberlite trades some throughput for built-in auditability and tamper-evidence; re-baselined benchmarks for v0.4.x scheduled for v0.5.0 (see `ROADMAP.md`)."

### 4.8 Time-travel consistency

**Locations:** `README.md:71-81` (Quick Start example uses `AS OF TIMESTAMP`); `docs/reference/sql/queries.md:28` (says v0.6); `docs/concepts/overview.md` (if applicable).
**Correction:** Use `AT OFFSET` in the README Quick Start (it works today); keep the v0.6 note for `AS OF TIMESTAMP`. Optionally add example comment: `-- AS OF TIMESTAMP '...' coming v0.6.0`.

### 4.9 TigerBeetle attribution

**Location:** Any implicit "same as TigerBeetle's battle-tested consensus" copy; verified phrasing appears in `README.md:144` neighbourhood.
**Correction:** "VSR adapted from TigerBeetle's architecture, extended with multi-tenant routing, clock synchronization, and repair-budget policies."

### 4.10 Install script — add checksum verification

**Location:** `install.sh` after download step.
**Implementation:** Fetch `SHA256SUMS` from same release; compute sha256 on downloaded zip; abort on mismatch. Fallback chain: `shasum -a 256` (macOS) → `sha256sum` (Linux) → error.
**Verify:** After install, tamper test — modify zip bytes, rerun, expect `checksum mismatch` error.

### 4.11 Install script — install `kmb` symlink

**Location:** `install.sh` after `cp "$binary" "$install_dir/kimberlite"`.
**Implementation:** `ln -sf "$install_dir/kimberlite" "$install_dir/kmb"`.
**Verify:** `kmb version` works after install.

### 4.12 Install docs — match script behaviour

**Location:** `docs/start/installation.md:20`.
**Correction:** Sentence now accurately describes checksum verification (after 4.10) and `kmb` alias (after 4.11). If either fix is rejected, remove the corresponding claim from this sentence.

### 4.13 Website — home.html version string

**Location:** `website/templates/home.html:132`.
**Correction:** `v0.1.0` → `v0.4.2`. Add comment: `<!-- AUDIT 2026-04: update on every release; TODO(v0.5): templateize from GitHub API -->`.

### 4.14 Website — download.html example

**Location:** `website/templates/download.html:28`.
**Correction:** Remove version from example (`curl … | sh` with no `--version` flag) or use v0.4.2.

### 4.15 Mirror install.sh to website

**Location:** `install.sh` → `website/public/install.sh`.
**Implementation:** copy verbatim after all Wave 3 changes. Comment at `install.sh:9-10` mandates the mirror.

### 4.16 Workspace version bump

**Location:** `Cargo.toml:46`.
**Correction:** `version = "0.4.0"` → `"0.4.2"`.

### 4.17 CHANGELOG entry

**Location:** `CHANGELOG.md`, below the current `[Unreleased]` AUDIT-2026-04 remediation section.
**Add:** `[0.4.2] - 2026-04-20 — Release-Readiness Truth-in-Advertising` with subsections: ### Documentation, ### Website, ### Install Script, ### Compliance Claims Recalibration. Do not collapse with `[Unreleased]`.

### 4.18 ROADMAP v0.5.0 / v0.6.0 targets

**Location:** `ROADMAP.md`.
**Add:** Acceptance-criteria entries for every deferred item (see §5).

---

## 5. Defer-to-v0.5.0+ (Roadmap Items, Out of v0.4.2 Scope)

### v0.5.0 (next minor)

1. **Phase 6 server handlers** — implement `audit_query`, `export_subject`, `verify_export`, `breach_report_indicator`, `breach_query_status`, `breach_confirm`, `breach_resolve`. Acceptance: stubs removed; SDK E2E tests pass; HIPAA §164.308(a)(6) breach workflow demonstrable end-to-end.
2. **TLAPS PR-gating** — migrate TLAPS proofs from `formal-verification-aspirational.yml` to `formal-verification.yml` with bounded configs (< 20 min). Nightly retains full-stretch runs.
3. **Doc-test repair** — fix or `#[ignore]` 55/58 failing tests in `crates/kimberlite-doc-tests/`. Add `just ci-doctests` target.
4. **Continuous fuzzing** — new `.github/workflows/fuzz.yml` running 20 targets × 15 min nightly; corpus cached via `actions/cache` or checked into `fuzz/corpus/`.
5. **VOPR nightly hard-fail** — remove `continue-on-error: true` from invariant jobs in `vopr-nightly.yml`; ship `tools/validate-coverage.py`.
6. **Benchmark re-baseline** — `docs/operating/performance.md` updated with v0.4.x Criterion numbers; settle or remove the "10-50% write-perf sacrifice" claim based on fresh data.
7. **Scaffolded VOPR scenarios** — implement or delete ~24 TODO-scaffolded variants (ReconfigDuringPartition, Upgrade\*, Standby\*, RBAC variants). `just vopr-scenarios` lists only runnable.
8. **Python SDK parity** — add `erasure.mark_stream_erased` (currently TS-only).

### v0.6.0

1. `AS OF TIMESTAMP` time-travel (already noted in queries.md:28).
2. Masking policy CRUD (deferred per parity.md:83).
3. RIGHT / FULL OUTER JOIN.
4. Transactions (`BEGIN`/`COMMIT`/`ROLLBACK`) — re-evaluate priority vs v1.0.
5. Go SDK.

### v1.0.0

1. Third-party SOC 2 Type II audit.
2. HIPAA attestation with BAA-capable deployment partner.
3. Java / C# / C++ SDKs.
4. Auto-generated traceability matrix from source markers.

---

## 6. Cross-Reference: Relationship to AUDIT-2026-04

`AUDIT-2026-04` is a directed compliance-claim review triggered by the `89d3bd6` tenant-isolation bug. Its 7-PR remediation is landing in `[Unreleased]` of CHANGELOG and addresses:
- C-1, C-4, H-4: Erasure redesign (actual deletion, not ledger)
- C-2: `verify_catalog_isolation` wire
- C-3: DDL/DML workload + SimCatalog
- H-1, M-3: Trace-alignment validator
- H-2: Audit log durability
- H-3, H-5: Liveness checker wiring
- M-\*, L-\*: Byzantine proof protocol binding, subquery RBAC, per-tenant index uniqueness

**This release-readiness audit does not overlap.** AUDIT-2026-04 fixes *code-to-verification gaps*; this one fixes *code-to-documentation gaps*. Where the same file is touched (e.g., `docs/internals/formal-verification/traceability-matrix.md` — AUDIT-2026-04 PR1 fixes line ranges; this audit updates HIPAA/GDPR/SOC2 row labels), rebase on the later state.

**Ordering constraint:** AUDIT-2026-04 PR series should land first; this v0.4.2 release can cut after those PRs are merged (they can land in the same `[Unreleased]` → `[0.4.2]` promotion, or — preferably — AUDIT-2026-04 lands as `[0.4.2-audit]` and this lands as `[0.4.2-truth]`, but that's cosmetic; a single `[0.4.2]` is fine if the CHANGELOG subsections are clear).

---

## 7. Sign-Off Matrix

| Dimension | Verdict | Risk | Action |
|---|---|---|---|
| 1. Features / claims parity | ⚠️ FIX | HIGH | Waves 1 + 6 of plan; §4.1-4.9 above |
| 2. CI / CD | ✅ READY (with flags) | MEDIUM | Doc-tests, fuzz CI, TLAPS gating → v0.5.0 |
| 3. Nightly fuzzing / DST / FV | ✅ READY | MEDIUM | Continue-on-error removal → v0.5.0; otherwise solid |
| 4. GitHub releases + install | ⚠️ FIX | HIGH | §4.10-4.15 (install.sh + website) |
| 5. Documentation accuracy | ⚠️ FIX | CRITICAL | §4.1-4.9 (must ship together) |
| 6. Website | ⚠️ FIX | MEDIUM | §4.13-4.15 (version strings) |
| 7. crates.io | ✅ READY | LOW | v0.4.2 bump + publish workflow will handle |

**Aggregate:** DO NOT PUBLIC-RELEASE until §4 fixes land. After they land, v0.4.2 is cut-ready.

**Sign-off owners (proposed):**
- Docs fixes (§4.1-4.9) — Jared, self-review
- Install script (§4.10-4.12) — Jared, ideally test on clean macOS + Linux VM before tag
- Website (§4.13-4.15) — Jared; auto-deploy will confirm
- Version + CHANGELOG (§4.16-4.17) — Jared (plus human review of final CHANGELOG text before tag push)
- ROADMAP (§4.18 / §5) — Jared

---

## 8. Appendix: Exact Grep Scrub (for CI / pre-tag verification)

Run against the release commit. Each line should return **zero hits** (or only historical ROADMAP/CHANGELOG mentions):

```bash
# Compliance certification absolutes
grep -rn "HIPAA-compliant\|SOC 2-certified\|SOC2-certified\|SOC 2-compliant\|GDPR-compliant" \
    docs/ website/ README.md CLAUDE.md

# Production-ready outside of status-qualifying context
grep -rn "production-ready" docs/concepts/overview.md README.md

# v1.0.0 outside of ROADMAP / v1.0 planning context
grep -rn "v1\.0\.0" docs/concepts/overview.md docs/concepts/compliance.md

# "Full SQL support" (should be replaced with concrete list)
grep -rn "Full SQL support" docs/ README.md

# 90-95% Antithesis overclaim
grep -rn "90-95% Antithesis\|Antithesis-grade" . --include='*.md' --include='CLAUDE.md'

# 136+ proofs standalone claim
grep -rn "136+ formal proofs\|136+ mathematical proofs" README.md docs/

# 38 assertions outdated
grep -rn "38 production assertions\|38 critical assertions" README.md CLAUDE.md docs/

# 46 scenarios outdated
grep -rn "46 test scenarios\|46 scenarios" README.md CLAUDE.md docs/

# "Only" / "world's first" for formal verification
grep -rin "only database.*formal\|world.?s first.*verif" docs/ README.md

# Website stale versions
grep -n "v0\.1\.0\|v0\.6\.0" website/templates/home.html website/templates/download.html
```

Pass criterion: all greps return 0 matches, OR matches are explicit "historical" / "roadmap" references.

---

*End of audit.*
