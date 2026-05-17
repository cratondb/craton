<p align="center">
  <img src="website/public/images/kimberlite-icon-512.png" alt="Kimberlite Logo" width="200"/>
</p>

# Kimberlite

[![Crates.io](https://img.shields.io/crates/v/kimberlite.svg)](https://crates.io/crates/kimberlite)
[![Downloads](https://img.shields.io/crates/d/kimberlite.svg)](https://crates.io/crates/kimberlite)
[![Documentation](https://docs.rs/kimberlite/badge.svg)](https://docs.rs/kimberlite)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-blue.svg)](https://doc.rust-lang.org/edition-guide/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/kimberlitedb/kimberlite/workflows/CI/badge.svg)](https://github.com/kimberlitedb/kimberlite/actions/workflows/ci.yml)
[![VOPR](https://img.shields.io/badge/testing-VOPR-green.svg)](docs/internals/testing/overview.md)
[![Fuzz Nightly](https://github.com/kimberlitedb/kimberlite/actions/workflows/fuzz.yml/badge.svg)](https://github.com/kimberlitedb/kimberlite/actions/workflows/fuzz.yml)
[![Formal Verification](https://img.shields.io/badge/verified-formal%20spec%20%2B%20bounded%20proofs-success.svg)](docs/concepts/formal-verification.md)
[![Discord](https://img.shields.io/discord/1468161583787151493?label=discord&logo=discord&color=5865F2)](https://discord.gg/QPChWYjD)

**A verifiable database for healthcare.**

Built for clinical and digital-health systems where PHI integrity is non-negotiable.

🔬 **Developer Preview** - Explore deterministic database concepts through production-quality code

Kimberlite is a verifiable, durable database engine designed for environments where data integrity, auditability, and trust are non-negotiable. Built around a single principle:

> **All data is an immutable, ordered log. All state is a derived view.**

## Why Kimberlite?

**The compliance tax is real.** In healthcare, you're forced to build:
- Immutable audit trails for every change
- Cryptographic proof of data integrity
- Per-tenant encryption and isolation
- Point-in-time reconstruction

Most teams bolt these onto existing databases. **Kimberlite builds them in.**

**Key approach:**
- **Immutable audit trail** - Hash-chained append-only log means every action is recorded
- **Time-travel queries** - Reconstruct any point-in-time state via MVCC (`AT OFFSET n` and `AS OF TIMESTAMP '...'` both shipped)
- **Multi-tenant isolation** - Cryptographic boundaries prevent cross-tenant access
- **Multi-layer verification** - TLA+ protocol specs, Coq crypto proofs, Alloy structural models, Ivy Byzantine invariants, Kani bounded model checking, MIRI UB detection ([details](docs/concepts/formal-verification.md))

**Designed for healthcare:** EHR-adjacent systems, digital-health platforms, payer/RCM workloads, and clinical research — every primitive is sized to HIPAA, with GDPR (international health) and SOC 2 / FedRAMP (clinical SaaS / federal health) as load-bearing extensions.

## Who Should Explore This

- 🏥 **Clinical IT teams** - Build HIPAA-ready EHR-adjacent systems with built-in audit trails
- 🚀 **Digital-health founders** - Ship FHIR-aware apps without bolting on the compliance plumbing
- 💳 **Payer & RCM engineers** - Append-only claims ledgers with cryptographic chain-of-custody
- 🔬 **Clinical researchers & informaticists** - 21 CFR Part 11-friendly audit, de-identification, and time-travel queries

**Perfect for learning.** Not yet recommended for production deployments (see [Status](#status) below).

## Quick Start

**5-minute quickstart:** See [Getting Started](docs/start/quick-start.md) for a complete tutorial with explanations.

**TL;DR:**

```bash
# Install (see docs/start/installation.md for all options)
curl -fsSL https://kimberlite.dev/install.sh | sh

# Initialize (or: kimberlite init  for interactive wizard)
kimberlite init myproject
kimberlite dev
# Studio: http://localhost:5555, DB: 127.0.0.1:5432
```

Try time-travel queries:
```sql
CREATE TABLE patients (id INTEGER, name TEXT);
INSERT INTO patients VALUES (1, 'Alice'), (2, 'Bob');

-- View current state
SELECT * FROM patients;

-- View state as of a specific log offset (MVCC time-travel)
SELECT * FROM patients AT OFFSET 0;

-- Or as of a wall-clock timestamp (resolved via the audit-log index)
SELECT * FROM patients AS OF TIMESTAMP '2026-01-15T00:00:00Z';
```

## Documentation

- [Quick Start](https://kimberlite.dev/docs/quick-start) - Get running in 90 seconds
- [CLI Reference](https://kimberlite.dev/docs/reference/cli) - All commands
- [SQL Reference](https://kimberlite.dev/docs/reference/sql) - Supported SQL syntax
- [Architecture](https://kimberlite.dev/architecture) - How Kimberlite works
- [Roadmap](ROADMAP.md) - Future features and enhancements
- [Changelog](CHANGELOG.md) - Release history and completed work
- [Contributing](CONTRIBUTING.md) - How to contribute

## Building from Source

```bash
# Clone and build
git clone https://github.com/kimberlitedb/kimberlite.git
cd kimberlite
cargo build --release -p kimberlite-cli

# Binary is at ./target/release/kimberlite
```

### Development Commands

```bash
just build          # Debug build
just build-release  # Release build
just test           # Run all tests
just nextest        # Faster test runner
just clippy         # Linting
just pre-commit     # Run before committing
```

## Key Features

**What Makes Kimberlite Unique:**

- ✅ **Immutable audit trail** - Hash-chained append-only log (SHA-256 for compliance, BLAKE3 for performance)
- ✅ **Time-travel queries** - MVCC enables both `AT OFFSET n` and `AS OF TIMESTAMP '...'`
- ✅ **Deterministic core** - Functional Core / Imperative Shell pattern enables perfect replication
- ✅ **Multi-tenant isolation** - Per-tenant storage with cryptographic boundaries
- ✅ **Multi-layer verification** - TLA+ protocol specs (TLC in PR CI, TLAPS nightly), Coq crypto proofs, Alloy structural models, Ivy Byzantine invariants, Kani bounded model checking, MIRI undefined-behavior detection ([details](docs/concepts/formal-verification.md))
- ✅ **SQL interface** - SELECT with aggregates, GROUP BY/HAVING, UNION/INTERSECT/EXCEPT, all JOIN kinds, CTEs (incl. recursive), subqueries (incl. correlated), window functions, JSON operators, scalar expressions. `INSERT ... ON CONFLICT` upsert. `ALTER TABLE ADD/DROP COLUMN`. Multi-statement transactions planned post-v1.0.
- ✅ **Compliance surface** - `client.compliance.{eraseSubject, audit.query, export_subject, breach_*, consent.{grant,revoke}}` reachable from all SDKs with signed witnesses, hash-chain tamper-evidence, and GDPR Art 6 consent basis
- ✅ **Column-level masking policies** - `CREATE MASKING POLICY` DDL composes with RBAC + break-glass
- ✅ **Tamper-evidence** - CRC32 checksums + hash chains detect corruption
- ✅ **Viewstamped Replication (VSR)** - Full multi-node consensus (Normal, ViewChange, Recovery, Repair, StateTransfer, Reconfiguration)
- ✅ **RBAC/ABAC enforcement** - Per-role row/column filters; HIPAA TPO + break-glass policies built-in
- ✅ **Security hardened** - pre-launch audit completed; message signatures, replay protection, DoS limits, zero unallowed RustSec advisories

See [`CHANGELOG.md`](CHANGELOG.md) for per-release detail; [`ROADMAP.md`](ROADMAP.md) for what's next.

## Use Cases

Kimberlite is built for healthcare:
- **EHR / EMR systems** — patient records, clinical notes, encounters with FHIR R4 and HL7 v2 native types
- **Payer / RCM** — X12 837 claim ingestion, 835 remittance reconciliation, audit-by-default
- **Clinical research** — IRB-aware retention, consent-bound queries, Safe Harbor de-identification for secondary use
- **Digital health** — multi-tenant SaaS with per-tenant encryption and BAA-ready audit chain

## Examples

See the [examples/](examples/) directory for:
- [quickstart/](examples/quickstart/) - Getting started
- [rust/](examples/rust/) - Rust SDK examples
- [docker/](examples/docker/) - Docker deployments
- [healthcare/](examples/healthcare/) - HIPAA-ready schema

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Kernel (pure state machine: Cmd -> State + FX)  │
├──────────────────────────────────────────────────┤
│  Append-Only Log (hash-chained, CRC32)           │
├──────────────────────────────────────────────────┤
│  Crypto (SHA-256, BLAKE3, AES-256-GCM, Ed25519)  │
└──────────────────────────────────────────────────┘
```

See [docs/concepts/architecture.md](docs/concepts/architecture.md) for details.

## Why Kimberlite vs. Traditional Databases?

| Feature | PostgreSQL | Kimberlite |
|---------|-----------|-----------|
| **Data model** | Mutable tables | Immutable log + derived views |
| **Audit trail** | Manual triggers | Built-in (every write logged) |
| **Time-travel** | Extensions (complex) | Native SQL (`AS OF TIMESTAMP`) |
| **Integrity** | Checksums | Hash chains + CRC32 |
| **Consensus** | Streaming replication | VSR (deterministic, multi-node) |
| **Best for** | General OLTP | Compliance-heavy workloads |

**Trade-offs:** Kimberlite trades some write throughput for built-in auditability and tamper-evidence. Quantitative re-baseline against current hardware is a v0.9.0 target; see [FAQ](docs/reference/faq.md) for the qualitative comparison.

## Learning Resources

### Documentation Deep Dive

- [docs/concepts/architecture.md](docs/concepts/architecture.md) - FCIS pattern, kernel design, consensus
- [docs/internals/testing/assertions-inventory.md](docs/internals/testing/assertions-inventory.md) - Production assertion policy + paired `#[should_panic]` tests
- [docs/internals/testing/overview.md](docs/internals/testing/overview.md) - VOPR deterministic simulation testing
- [docs/concepts/pressurecraft.md](docs/concepts/pressurecraft.md) - Code quality standards
- [docs/concepts/compliance.md](docs/concepts/compliance.md) - HIPAA-ready, SOC 2-ready, GDPR-ready patterns

## Community

- 💬 [Discord](https://discord.gg/QPChWYjD) - Join for real-time support, design discussions, and community
- 📖 [Documentation](docs/) - Comprehensive architecture and usage guides
- 🐛 [Issues](https://github.com/kimberlitedb/kimberlite/issues) - Bug reports and feature requests
- 💡 [Discussions](https://github.com/kimberlitedb/kimberlite/discussions) - Questions, ideas, and design conversations
- ❓ [FAQ](docs/reference/faq.md) - Frequently asked questions

## Status

> **v0.x — Developer Preview.** Stable enough for prototypes, learning,
> internal tools, and compliance research. Not yet battle-tested at scale.
>
> - ✅ **Core is solid:** 3,000+ tests, deterministic simulation, production-grade crypto.
> - ✅ **Architecture is stable:** FCIS pattern, immutable log, full multi-node VSR consensus.
> - ✅ **Security hardened:** pre-launch audit closed, zero unallowed RustSec advisories, supply-chain pins.
> - ✅ **SDKs are production-grade:** Rust, TypeScript, and Python SDKs ship full data-plane + compliance + admin surface, with connection pooling and real-time subscriptions. See [SDK parity matrix](docs/reference/sdk/parity.md).
> - ⚠️ **Wire protocol may still evolve** between minor versions. See [`CHANGELOG.md`](CHANGELOG.md) for the current version and any breaking changes.
>
> **Use for:** internal tools, prototypes, learning database internals, compliance research.
>
> **Wait for v1.0 if you need:** API stability guarantees, large-scale production deployment, commercial support, or third-party SOC 2 / HIPAA / GDPR attestations. v1.0 is checklist-gated with no fixed date — see [`ROADMAP.md`](ROADMAP.md#v10--checklist-gated) for the gates.
>
> **Post-v1.0:** a managed cloud service (Kimberlite Cloud) is planned alongside the OSS core. The core stays OSS; the cloud adds ops, scaling, and compliance-ready shared-responsibility — similar to CockroachDB Serverless on top of CockroachDB OSS.

## Known Limitations (v0.8.0)

We surface these up front so you don't trip over them:

- **Single-node only for production.** Multi-node VSR consensus is implemented end-to-end and PR-gated against TLA+ specs, but the `kimberlite-cluster` crate is marked "not ready for public use" — production multi-node is a v1.0 gate. Single-node is stable.
- **No multi-statement transactions.** `BEGIN`/`COMMIT`/`ROLLBACK` are planned post-v1.0; the parser rejects them today. Single statements are atomic. For cross-table workflows, see the outbox-pattern recipe in [`examples/cookbook/`](examples/cookbook/).
- **`NOW()` / `CURRENT_TIMESTAMP` / `CURRENT_DATE` panic if reached unfolded.** v0.7.0 shipped the sentinel variants; the planner-side `fold_time_constants` pass is a v0.9.0 in-flight item. Until then, pass an explicit timestamp parameter from the application instead.
- **No published performance baselines yet.** Hardware re-baseline is a v0.9.0 target. Correctness is covered by 3,000+ tests + VOPR deterministic simulation; throughput / latency numbers are coming.
- **Wire protocol may evolve between minor versions.** Breaking changes are called out in [`CHANGELOG.md`](CHANGELOG.md). Pin server and SDK to compatible versions until v1.0.
- **Go SDK Phase 1 lands in v0.9.0.** Rust / TypeScript / Python are at full data-plane + compliance-surface parity today.

See [`ROADMAP.md`](ROADMAP.md) for the full list of in-flight and deferred items, and the v1.0 readiness gates.

## Compliance posture

**Kimberlite ships the cryptographic and architectural primitives that HIPAA demands, with GDPR / SOC 2 / ISO 27001 / FedRAMP as overlays:** hash-chained immutable audit log (server-walked attestation via `audit.verifyChain()`), AES-256-GCM at rest, Ed25519 signed exports, multi-tenant key isolation, GDPR Article 17 erasure orchestration with `requestId` correlation, GDPR Article 6 consent-basis tracking on the wire, column-level masking policies that compose with RBAC + break-glass, Safe Harbor de-identification of all 18 §164.514(b)(2) identifiers, and healthcare-relevant frameworks formally modelled (TLA+ + Coq + Kani + VOPR scenarios) — see [`docs/compliance/certification-package.md`](docs/compliance/certification-package.md).

**What we have NOT done:** third-party SOC 2 Type II audit, HIPAA attestation + BAA, FedRAMP authorization, GDPR readiness review. These are v1.0 gates. Until then, **Kimberlite *enables* your compliance posture; certification remains your team's responsibility** (BAA with your hosting provider, pen test, audit firm engagement, internal controls). If you're a regulated startup, you can build on Kimberlite today knowing the substrate is sound — but the audit letters and certifications are work you (or we, post-v1.0) still have to do.

## SDKs

Kimberlite provides idiomatic client libraries for multiple languages:

| Language   | Status                                      | Package                  | Install                          |
|------------|---------------------------------------------|--------------------------|----------------------------------|
| Rust       | ✅ Ready                                    | `kimberlite-client`      | `cargo add kimberlite-client`    |
| TypeScript | ✅ Ready (Node 18/20/22/24, prebuilt napi)  | `@kimberlitedb/client`   | `npm install @kimberlitedb/client` |
| Python     | ✅ Ready                                    | `kimberlite`             | `pip install kimberlite`         |
| Go         | 📋 Planned (v0.9.0 Phase 1)                 | —                        | See [ROADMAP](ROADMAP.md)        |
| Java       | 📋 Planned (v1.0 gate)                      | `com.kimberlite:kimberlite-client` | Maven / Gradle         |
| C++        | 📋 Planned (v1.0 gate, via FFI)             | `kimberlite-cpp`         | Coming soon                      |

See [docs/reference/sdk/overview.md](docs/reference/sdk/overview.md) for architecture and [docs/reference/protocol.md](docs/reference/protocol.md) for wire protocol specification.

## License

Apache 2.0

## Contributing

- Read [CLAUDE.md](CLAUDE.md) for development guidelines
- Review [docs/concepts/pressurecraft.md](docs/concepts/pressurecraft.md) for coding standards
- Open issues for design discussions
