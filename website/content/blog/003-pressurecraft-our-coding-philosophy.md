---
title: "Pressurecraft: Our Coding Philosophy"
slug: "pressurecraft-our-coding-philosophy"
date: 2026-01-21
excerpt: "Diamonds form under immense pressure over geological time. This is about writing code with the same property—forged under pressure, built to endure."
author_name: "Jared Reyes"
author_avatar: "/public/images/jared-avatar.jpg"
---

# Pressurecraft: Our Coding Philosophy

> *"Diamonds form 150 kilometers below the surface, at pressures exceeding 50 kilobars and temperatures above 1000°C. They remain there for billions of years—unchanged, stable, enduring. Only rare volcanic eruptions through kimberlite pipes bring them to the surface."*

Diamonds don't become valuable by accident. They're forged under immense pressure over geological time. The pressure doesn't break them—it creates their structure. Their hardness, their clarity, their brilliance—all products of conditions that would destroy lesser materials.

This is about writing code with the same property.

Kimberlite is a verifiable database for healthcare. Our users—clinical IT teams, digital-health platforms, payers, and clinical researchers—stake their patients and their businesses on our correctness. An invalid state is not a bug to fix in the next sprint; it is a fault line waiting to rupture during a HIPAA audit, an OCR investigation, or a breach response.

Our architecture mirrors the geology:
- **The append-only log** is the stable core—immutable, pressure-forged, enduring
- **Kimberlite** is the system that extracts value from that core
- **Projections** are the diamonds—valuable, structured artifacts derived from the unchanging log

We optimize for three things, in this order:

1. **Correctness** — Code that cannot be wrong is better than code that is tested to be right.
2. **Auditability** — Every state change must be traceable. If it's not in the log, it didn't happen.
3. **Simplicity** — Every abstraction is a potential crack, invisible until stress reveals it.

We do not optimize for writing speed. We optimize for *reading over decades*. The code you write today will be read by auditors, regulators, and engineers who haven't been hired yet.

There is no "quick fix" in Kimberlite. There is only *correct* or *fractured*.

---

## The Five Principles

> *"Simplicity is prerequisite for reliability."* — Edsger W. Dijkstra

### 1. Functional Core, Imperative Shell

**This is a mandatory pattern for all Kimberlite code.**

Diamonds do not change in the depths. Earthquakes, volcanic eruptions, tectonic shifts—these happen at the surface, not in the crystalline core. The core remains inert, unchanged, *pure*.

Our kernel follows the same principle. It is a pure, deterministic state machine. All side effects—I/O, clocks, randomness—live at the edges, in the imperative shell.

**The Core (Pure)**:
- Takes commands and current state
- Returns new state and effects to execute
- No I/O, no clocks, no randomness
- Trivially testable with unit tests

**The Shell (Impure)**:
- Handles RPC, authentication, network I/O
- Manages storage, file handles, sockets
- Provides clocks, random numbers when needed
- Executes effects produced by the core

**Why This Matters**:
- *Deterministic replay*: Given the same log, we get the same state. Always.
- *Testing*: The core can be tested exhaustively without mocks.
- *Simulation*: We can run thousands of simulated nodes in a single process.
- *Debugging*: Reproduce any bug by replaying the log.

---

### 2. Make Illegal States Unrepresentable

> *"I call it my billion-dollar mistake. It was the invention of the null reference in 1965."* — Tony Hoare

A flaw in a diamond is a place where invalid structures can exist. The goal is to eliminate flaws entirely—to build structures that *cannot* fracture because the fracture planes don't exist.

Use Rust's type system to prevent bugs at compile time, not runtime. If the compiler accepts it, it should be correct.

Consider a simple example. Many codebases track state with booleans:

```rust
struct Request {
    is_authenticated: bool,
    is_admin: bool,
}
```

What happens when `is_admin` is true but `is_authenticated` is false? The code "works," but it represents a state that should never exist. Somewhere, there's probably an `if` statement that checks both flags. Maybe.

I make this impossible to represent:

```rust
enum RequestAuth {
    Anonymous,
    Authenticated(UserId),
    Admin(AdminId),
}
```

Now the compiler enforces the invariant. An admin is always a specific user. Anonymous requests have no user ID. The impossible state is *unrepresentable*.

This pattern scales up. I use newtypes instead of primitives, so you can't accidentally pass a `TenantId` where a `StreamId` is expected. I encode state machines in types, so you can't call `.commit()` on a transaction that hasn't been prepared.

The goal is to make the code path from "valid state" to "valid state" the only path the compiler allows.

---

### 3. Parse, Don't Validate

> *"Data dominates. If you've chosen the right data structures and organized things well, the algorithms will almost always be self-evident."* — Rob Pike

Carbon becomes diamond through pressure and time. Once crystallized, it doesn't need to be re-validated as diamond. The transformation is permanent.

Validation is checking that data meets constraints. Parsing is *transforming* data into a representation that *cannot violate* those constraints. Validate once, at the boundary. Parse into types that carry the proof of validity with them.

```rust
// This is a TenantId - guaranteed valid by construction
struct TenantId(u64);

impl TenantId {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let id: u64 = s.parse()?;
        if id == 0 {
            return Err(ParseError::ZeroId);
        }
        Ok(TenantId(id))
    }
}

// Internal functions receive TenantId, not &str
// They cannot receive invalid input
fn load_tenant(id: TenantId) -> Tenant { ... }
```

Once data crosses the trust boundary and becomes a typed value, it's never validated again. The type *is* the proof of validity.

## Assertion Density

Geologists don't wait for earthquakes to discover fault lines. They deploy seismic sensors.

Every function in the codebase has at least two assertions: one precondition and one postcondition.

Assertions serve two purposes:

**Living documentation.** The assertions tell you what the function expects and guarantees. They're comments that the runtime verifies.

**Early failure.** When invariants are violated, I want to fail immediately and loudly, not subtly corrupt data and fail hours later.

I write assertions in pairs—one at the write site, one at the read site:

```rust
// When writing
fn write_record(storage: &mut Storage, record: &Record) {
    let checksum = crc32(&record.data);
    storage.write_u32(checksum);
    storage.write(&record.data);
}

// When reading
fn read_record(storage: &Storage, offset: Offset) -> Record {
    let stored_checksum = storage.read_u32(offset);
    let data = storage.read_bytes(offset + 4);
    let computed_checksum = crc32(&data);

    // Paired assertion: verify what write_record wrote
    assert_eq!(
        stored_checksum, computed_checksum,
        "record corruption at offset {:?}", offset
    );

    Record { data }
}
```

## Explicit Control Flow

Subduction zones are where hidden processes build pressure invisibly until the earthquake arrives. Hidden control flow is the software equivalent.

The codebase has no recursion. Every loop has explicit bounds. Control flow is visible.

Why no recursion? Stack overflow risks. Unbounded resource consumption. Difficulty reasoning about worst-case behavior.

Instead, I use explicit iteration with bounds:

```rust
fn traverse(root: &Node, max_depth: usize) {
    let mut stack = vec![(root, 0)];

    while let Some((node, depth)) = stack.pop() {
        assert!(depth <= max_depth, "max depth exceeded");
        process(node);

        for child in &node.children {
            stack.push((child, depth + 1));
        }
    }
}
```

The depth limit is explicit. The stack is visible. Resource usage is bounded.

## Minimal Dependencies

Every dependency is trust extended. Every crate pulled in becomes part of the trusted computing base.

I evaluate dependencies carefully:

- **Can I implement this in under 200 lines?** If so, I probably should.
- **Is it well-maintained?** Active development, responsive maintainers, semver discipline.
- **Has it been audited?** Security-critical code should have third-party review.
- **What does it pull in?** Transitive dependencies count.

I prefer the standard library. I vendor when it makes sense. I question every `cargo add`.

## The Philosophy Serves the Mission

These aren't arbitrary rules. Each principle exists because Kimberlite is compliance infrastructure.

When a hospital stores patient records in Kimberlite, they're trusting the system with data that could affect care decisions. When a financial institution stores transaction records, they're trusting it with data that regulators will audit.

That trust demands code that is:
- **Correct** — Bugs in compliance infrastructure become legal liability
- **Auditable** — Regulators and security teams need to verify claims
- **Predictable** — Surprise behavior in a database is never acceptable

I write code that I would trust with my own medical records.

---

A kimberlite survives because it has no fault lines to exploit. Write code with the same property. Be the kimberlite.

*The full Kimberliteics coding philosophy is documented in the [repository](https://github.com/kimberlitedb/kimberlite). Scrutiny is welcome.*
