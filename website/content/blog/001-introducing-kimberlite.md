---
title: "Introducing Kimberlite"
slug: "introducing-kimberlite"
date: 2026-01-23
excerpt: "A verifiable database for healthcare. Built on a single principle: all data is an immutable, ordered log."
author_name: "Jared Reyes"
author_avatar: "/public/images/jared-avatar.jpg"
---

# Introducing Kimberlite

We're building something different. Not another database that bolts compliance features onto an existing architecture, but a database designed from first principles for healthcare.

## The Problem

Healthcare faces a fundamental tension: clinical and digital-health systems need databases that are both performant *and* auditable. Traditional databases treat audit logs as an afterthought—append-only tables that capture *some* changes, with gaps that become fault lines during HIPAA audits, OCR investigations, or breach response.

When regulators ask "prove this data hasn't been tampered with," most systems can only offer trust. "Trust that our logs are complete. Trust that nobody with admin access made unauthorized changes. Trust that our backups haven't been modified."

Trust isn't compliance.

## Our Approach

Kimberlite is built on a single architectural principle:

> **All data is an immutable, ordered log. All state is a derived view.**

Every write appends to a hash-chained log. Every record links cryptographically to its predecessor, forming an unbroken chain back to genesis. Modify any record, and the chain breaks. The math doesn't lie.

This isn't new computer science—it's just rarely applied at the database layer. Blockchains use hash chains for consensus. Git uses them for version control. We use them for *compliance*.

## What This Enables

**Verifiable Reads**: Every query returns data with a cryptographic proof. Clients can independently verify that what they received matches what was stored.

**Complete Audit Trail**: Not just "what changed," but cryptographic proof of the entire history. Export a Merkle proof for any record at any point in time.

**Tamper Detection**: Any modification—even by administrators—is detectable. The hash chain is the invariant.

**Multi-Tenant Isolation**: Tenants are cryptographically separated, not just logically. Cross-tenant data access is provably impossible.

## The Stack

We're building this in Rust with a functional core / imperative shell architecture:

- **Pure kernel**: A deterministic state machine that processes commands and emits effects. No IO, no clocks, no randomness in the core—like a kimberlite, it refuses to change in response to external events.
- **Imperative shell**: Executes effects, handles IO, provides randomness to the edge.

This architecture makes the system testable by construction. Property-based tests can explore the state space without mocking IO.

Cryptography is dual-hash:
- **SHA-256** for compliance-critical paths (hash chains, checkpoints, exports)
- **BLAKE3** for high-performance internal operations (content addressing, Merkle trees)

## Current Status

Kimberlite is under active development. We've completed:

- Core type system with entity IDs and data classification
- Cryptographic primitives (hash chains, signatures, encryption)
- Binary append-only log with CRC32 checksums
- Hash chain integration for tamper detection
- Verified reads with proof generation

We're currently working on the pure functional kernel that will process commands and manage state transitions.

## Follow Along

The project is open source under Apache 2.0. We believe compliance infrastructure should be auditable by the people who depend on it.

Star the repo on [GitHub](https://github.com/kimberlitedb/kimberlite) to follow our progress. We'll be posting regular updates here as we hit milestones.

---

*Kimberlite is not yet production-ready. We're building in public, and we'd love your feedback.*
