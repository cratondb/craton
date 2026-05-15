---
title: "Kimberlite Documentation"
section: "root"
slug: "README"
order: 0
---

# Kimberlite Documentation

Welcome to Kimberlite, a **verifiable database for healthcare**. This documentation follows a progressive disclosure model to help you find what you need quickly.

## What is Kimberlite?

Kimberlite is built for clinical and digital-health systems where PHI integrity is non-negotiable. It's designed around a single principle:

> **All data is an immutable, ordered log. All state is a derived view.**

**Key features:**
- **Immutable audit trail** - Hash-chained append-only log means every action is recorded
- **Time-travel queries** - Reconstruct any point-in-time state without separate audit tables
- **Multi-tenant isolation** - Cryptographic boundaries prevent cross-tenant access
- **Multi-layer verification** - TLA+ protocol specs, Coq crypto proofs, Alloy structural models, Ivy Byzantine invariants, Kani bounded proofs, MIRI UB detection

**Designed for healthcare:** HIPAA-first, with GDPR (international health), SOC 2 (clinical SaaS), and FedRAMP (federal health) as supported overlays.

**→ [Learn more about Kimberlite's architecture](concepts/overview.md)**

## Documentation Sections

### [Start](start/) - Get Running in <10 Minutes
New to Kimberlite? Start here to get up and running quickly.

- [Quick Start](start/quick-start.md) - Fastest path to a working system
- [Installation](/docs/start) - Installation options for all platforms
- [First Application](start/first-app.md) - Build your first healthcare compliance app

### [Concepts](concepts/) - Understanding Kimberlite
Learn the strategic "why" behind Kimberlite's design and approach.

- [Overview](concepts/overview.md) - What is Kimberlite and why does it exist?
- [Architecture](concepts/architecture.md) - High-level system design
- [Data Model](concepts/data-model.md) - Append-only log and projections
- [Consensus](concepts/consensus.md) - Viewstamped Replication explained
- [Compliance](concepts/compliance.md) - Compliance-first approach
- [Formal Verification](concepts/formal-verification.md) - Multi-layer verification stack (TLA+, Coq, Alloy, Ivy, Kani, MIRI)
- [Multi-tenancy](concepts/multitenancy.md) - Tenant isolation and security
- [Pressurecraft](concepts/pressurecraft.md) - Our coding philosophy

### [Coding](coding/) - Building Applications
Practical guides for building applications with Kimberlite.

**Quickstarts** (language-specific getting started):
- [Python](coding/quickstarts/python.md)
- [TypeScript](coding/quickstarts/typescript.md)
- [Rust](coding/quickstarts/rust.md)
- [Go](coding/quickstarts/go.md)

**Guides** (how-to guides):
- [Connection Pooling](coding/guides/connection-pooling.md)
- [Schema Migrations](coding/guides/migrations.md)
- [Testing Applications](coding/guides/testing.md)
- [Shell Completions](coding/guides/shell-completions.md)

**Recipes** (code examples for common patterns):
- [Time-Travel Queries](coding/recipes/time-travel-queries.md)
- [Audit Trails](coding/recipes/audit-trails.md)
- [Encryption](coding/recipes/encryption.md)
- [Data Classification](coding/recipes/data-classification.md)
- [Multi-Tenant Queries](coding/recipes/multi-tenant-queries.md)

### [Operating](operating/) - Deployment & Operations
Running Kimberlite in production environments.

- [Deployment](operating/deployment.md) - Docker, Kubernetes, bare metal
- [Configuration](operating/configuration.md) - Configuration reference
- [Monitoring](operating/monitoring.md) - Observability and metrics
- [Security](operating/security.md) - TLS, authentication, hardening
- [Performance](operating/performance.md) - Tuning and optimization
- [Troubleshooting](operating/troubleshooting.md) - Common issues and solutions

**Cloud Platforms:**
- [AWS](operating/cloud/aws.md)
- [GCP](operating/cloud/gcp.md)
- [Azure](operating/cloud/azure.md)

### [Reference](reference/) - API Documentation
Exhaustive reference documentation for all APIs and protocols.

**CLI Tools:**
- [CLI Reference](reference/cli.md) - Command reference

**SQL:**
- [Overview](reference/sql/overview.md) - SQL support overview
- [DDL](reference/sql/ddl.md) - CREATE/DROP TABLE/INDEX
- [DML](reference/sql/dml.md) - INSERT/UPDATE/DELETE
- [Queries](reference/sql/queries.md) - SELECT and query syntax

**SDKs:**
- [Python API](reference/sdk/python-api.md)
- [TypeScript API](reference/sdk/typescript-api.md)
- [Rust API](reference/sdk/rust-api.md)
- [Go API](reference/sdk/go-api.md)

**Protocols:**
- [Wire Protocol](reference/protocol.md) - Network protocol specification
- [Agent Protocol](reference/agent-protocol.md) - LLM agent integration

### [Internals](internals/) - Deep Technical Details
For contributors and those who want to understand how Kimberlite works internally.

**Architecture:**
- [Crate Structure](internals/architecture/crate-structure.md)
- [Kernel](internals/architecture/kernel.md)
- [Storage](internals/architecture/storage.md)
- [Cryptography](internals/architecture/crypto.md)

**Testing:**
- [Testing Overview](internals/testing/overview.md)
- [Assertions](internals/testing/assertions.md)
- [Property Testing](internals/testing/property-testing.md)

**Design Documents:**
- [Instrumentation](internals/design/instrumentation.md)
- [Reconfiguration](internals/design/reconfiguration.md)
- [LLM Integration](internals/design/llm-integration.md)
- [Data Sharing](internals/design/data-sharing.md)
- [SDK Design](internals/design/sdk.md)
- [SQL Engine Design](internals/design/sql-engine.md)

**Implementation Details:**
- [Compliance Implementation](internals/compliance-implementation.md)
- [VSR Implementation](internals/vsr.md)

---

## For Contributors

If you're contributing to Kimberlite, see [/docs-internal](../docs-internal/) for internal documentation including:
- VOPR testing infrastructure (scenario catalogue, deployment, debugging)
- Contributor guides (getting started, code review, release process)
- Internal design discussions and team processes

---

## Additional Resources

- [Roadmap](../ROADMAP.md) - Future plans and version targets
- [Changelog](../CHANGELOG.md) - Release history
- [GitHub Repository](https://github.com/kimberlitedb/kimberlite)
- [Website](https://kimberlite.dev)
