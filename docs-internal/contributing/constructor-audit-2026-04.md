# Constructor Audit — April 2026

Punch list produced during the fuzz-to-types hardening effort (`done-7-commits-happy-nebula` plan, Wave 0). Scans every `pub fn new(...)` in `crates/*/src/` whose body contains `assert!`, `assert_eq!`, `panic!`, `.unwrap()`, or `.expect()` within the first 60 lines of the function body. Excludes `tests.rs` and files under `/tests`.

## Scope

- **Files scanned**: 168 source files across 35 crates
- **Total `pub fn new()`**: 332
- **Panicking constructors found**: **16**

## Classification

Each site is assigned a bucket that drives the migration action:

| Bucket | Action | When |
|---|---|---|
| **A** | Saturate | Domain has an obvious clamp (e.g. max-value minus 1). Demote `assert!` → `debug_assert!` + saturate. |
| **B** | Enum-domain | Domain is a small finite set. Replace the primitive with an `enum`. |
| **C** | `try_new()` | Failure is a real error the caller should handle. Introduce fallible `try_new()`; drop the panicking `new()` (or keep a Default-based infallible alias). |
| **D** | Keep + document | `assert!` is documenting a cryptographic / consensus-protocol invariant OR `expect()` is on a provably infallible literal. No API change. |

## Audit table

| # | Site | Trigger | Bucket | Rationale / Migration |
|---|---|---|---|---|
| 1 | `kimberlite-compliance` `signature_binding.rs:68` `RecordSignature::new` | `assert!` non-empty hash, non-empty signer, `assert_eq!` sig len == 64 | **C** | Ed25519 signature length is caller-controlled input. Introduce `try_new()` returning `Result<_, SignatureError::{EmptyHash, EmptySigner, WrongSignatureLength}>`. |
| 2 | `kimberlite-crypto` `encryption.rs:383` `WrappedKey::new` | `assert!` key_to_wrap not all-zeros; `assert_eq!` ciphertext length | **D** | Cryptographic invariant (all-zero key = corrupted DEK). Per `docs/internals/testing/assertions.md` promoted-assertion policy (25 crypto assertions already in prod). Keep. |
| 3 | `kimberlite-crypto` `encryption.rs:967` `CachedCipher::new` | `.expect("KEY_LENGTH is always valid")` | **D** | `Aes256Gcm::new_from_slice` on a `&[u8; KEY_LENGTH]`. Infallible by type. Keep. |
| 4 | `kimberlite-server` `config.rs:671` `ServerConfig::new` | `.expect("valid address")` on const `"127.0.0.1:9090"` | **D** | Const address literal; infallible. Consider a `LocalAddr` newtype later, but no panic risk today. Keep. |
| 5 | `kimberlite-server` `core_runtime.rs:60` `CoreRouter::new` | `assert!(core_count > 0)` | **C** | Config comes from user TOML. `try_new() -> Result<_, CoreRuntimeError::ZeroCores>`. |
| 6 | `kimberlite-server` `core_runtime.rs:134` `CoreRuntime::new` | `assert!(core_count > 0)`, `assert!(queue_capacity > 0)` | **C** | Same path as #5. Fold into the same `CoreRuntimeError`. |
| 7 | `kimberlite-server` `buffer_pool.rs:42` `BufferPool::new` | `assert!(pool_size > 0)`, `assert!(default_capacity > 0)` | **C** | Config-driven. `try_new() -> Result<_, BufferPoolError>`. |
| 8 | `kimberlite-server` `bounded_queue.rs:39` `BoundedQueue::new` | `assert!(capacity > 0)` | **C** | Same config surface. `try_new()`. |
| 9 | `kimberlite-vsr` `message.rs:337` `Prepare::new` | `assert_eq!` entry.op_number == op_number; entry.view == view | **D** | Protocol-correctness invariant (internal, not caller-supplied). A mismatch is a logic bug in message construction, not a runtime error. Keep + `#[must_use]`. **Follow-up**: consider redesigning so `op_number` and `view` derive from the entry, making the invariant unrepresentable (tracked separately). |
| 10 | `kimberlite-vsr` `clock.rs:289` `Clock::new` | `assert!(cluster_size > 0)`, `assert!(replica.as_usize() < cluster_size)` | **C** | Cluster size from config. `try_new() -> Result<_, ClockError>`. |
| 11 | `kimberlite-vsr` `config.rs:57` `VsrConfig::new` | `assert!` non-empty replicas, odd count, ≤ MAX_REPLICAS, no duplicates | **C** | Config-driven. `try_new() -> Result<_, VsrConfigError::{Empty, EvenClusterSize, TooManyReplicas, DuplicateReplica}>`. The 4 distinct invariants map cleanly to 4 error variants. |
| 12 | `kimberlite-vsr` `replica/repair.rs:61` `RepairState::new` | `assert!(op_range_start < op_range_end)` | **C** | Range is caller-supplied. `try_new() -> Result<_, RepairError::EmptyRange>`. |
| 13 | `kimberlite-cluster` `config.rs:52` `ClusterConfig::new` | `assert!(node_count >= 1)` | **C** | Cluster-config surface. `try_new()`. |
| 14 | `kimberlite-bench` `lib.rs:50` `LatencyTracker::new` | `.expect("valid histogram config")` on `Histogram::new(3)` | **D** | Infallible literal. Bench-only crate; even if it panicked, blast radius is a benchmark run. Keep. |
| 15 | `kimberlite-rbac` `masking.rs:124` `FieldMask::new` | `assert!(!column.is_empty())` | **C** | Column comes from policy definitions (config / SQL DDL). `try_new() -> Result<_, MaskingError::EmptyColumn>`. |
| 16 | `kimberlite-sim` `real_state_driver.rs:217` `RealStateDriver::new` | `.expect("tempdir for real_state_driver Storage")` | **D** | Simulation-only test infrastructure. Panicking on tempdir failure is acceptable for the sim driver. Keep. |

## Summary by bucket

| Bucket | Count | Disposition |
|---|---|---|
| A (saturate) | 0 | None in this pass. `ReplicaId::new` (commit `5a64a36`) is the canonical Bucket-A pattern; added to the `docs/concepts/pressurecraft.md` appendix. |
| B (enum-domain) | 0 | Wave 2 `ClearanceLevel` is the audit's only Bucket-B site, but it's counted in the Wave 2 bug-site list, not this audit. |
| **C (`try_new()`)** | **10** | 4 crates: `kimberlite-server` (4), `kimberlite-vsr` (3), `kimberlite-compliance` (1), `kimberlite-rbac` (1), `kimberlite-cluster` (1). |
| D (keep) | 6 | Cryptographic invariants (2), infallible literals (3), protocol-correctness invariant (1). |

## Wave 3 PR plan

**Status: ✅ COMPLETE (v0.9.0 healthcare-pivot sweep)**

All 10 Bucket-C sites now have:
- Paired `try_new() -> Result<_, Error>` fallible constructor with explicit error variants
- Infallible `new()` shim marked `#[track_caller]` that delegates to `try_new().expect(...)` with a clear panic message pointing users at `try_new`
- Tests for each rejection path (`try_new(...).unwrap_err()` matchers) plus `#[should_panic]` coverage on the `new()` shim

Bucket-C migration batches:

1. **`kimberlite-cluster`** — 1 site (`ClusterConfig::new`) ✅ shim + try_new + tests in `src/config.rs:77-102`, error tests at `try_new_rejects_zero_nodes`, `new_panics_on_zero_nodes`
2. **`kimberlite-compliance`** — 1 site (`RecordSignature::new`) ✅ shim + try_new + tests in `src/signature_binding.rs:91-148`, error tests at `try_new_rejects_{empty_hash,empty_signer,wrong_signature_length}`, `new_panics_on_invalid_inputs`
3. **`kimberlite-rbac`** — 1 site (`FieldMask::new`) ✅ shim + try_new + tests in `src/masking.rs:137-160`
4. **`kimberlite-server`** — 4 sites (`CoreRouter`, `CoreRuntime`, `BufferPool`, `BoundedQueue`) ✅ all four migrated in `src/core_runtime.rs`, `buffer_pool.rs`, `bounded_queue.rs` with paired `try_new()` and `#[should_panic]` tests
5. **`kimberlite-vsr`** — 3 sites (`Clock`, `VsrConfig`, `RepairState`) ✅ migrated in `src/clock.rs:293-323`, `src/config.rs:61-89`, `src/replica/repair.rs:68-98`. Error tests: `try_new_rejects_zero_cluster_size`, `try_new_rejects_replica_out_of_range`, `new_panics_on_zero_cluster_size`, `repair_state_try_new_rejects_{empty,inverted}_range`, `repair_state_new_panics_on_empty_range`

## Non-goals

- **Struct literal constructors** (e.g. `ParsedCreateTable { columns: vec![], .. }`) are covered by Wave 2 type-system migration (`NonEmptyVec`), not by this audit.
- **Panicking `expect()` on `RwLock::read()` / `Mutex::lock()`** — poisoned-lock panics are idiomatic Rust; separate policy decision.
- **Internal helper functions** (non-`pub` or `pub(crate)`) — not audited. Internal invariants stay as `assert!`/`debug_assert!` per `docs/internals/testing/assertions.md`.

## Follow-ups (ROADMAP v0.5.0)

- **Prepare::new redesign** (site #9) — derive `view`/`op_number` from `LogEntry` to make the mismatch invariant unrepresentable. Touches every VSR constructor, large refactor.
- **Struct-literal construction ban** — once the `SqlIdentifier` migration completes, many `Vec<String>` columns flip to `Vec<SqlIdentifier>`; add a clippy lint preventing `Struct { field: vec![...] }` where `field: NonEmptyVec<_>` would be correct.
- **`expect()` → `unwrap_or_default()` sweep** — for Bucket-D sites where the default is harmless, swap the panic for the default to reduce worst-case failure modes (e.g. `LatencyTracker::new` returning an uninitialized `Histogram` on failure).
