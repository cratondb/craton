# Kimberlite Examples

Runnable examples grouped by audience. If you're just trying it for the
first time, start with `quickstart/`. Healthcare is the reference vertical —
`healthcare/` is the canonical end-to-end walkthrough.

## Index

| Directory | Description |
|---|---|
| [`quickstart/`](quickstart/) | Minimal "hello, database" script |
| [`rust/`](rust/) | Rust SDK examples: basic, streaming, time-travel, clinic, axum + actix, **ehr-mini** (FHIR R4 pipeline), **smart-on-fhir-app** (SMART standalone launch + scope enforcement) |
| [`typescript/`](typescript/) | TypeScript SDK examples: `express-app/`, `nextjs-app/` |
| [`python/`](python/) | Python SDK examples: `fastapi-app/`, `django-app/` |
| [`docker/`](docker/) | Docker and Docker Compose configurations |
| [`healthcare/`](healthcare/) | **End-to-end clinic-management walkthrough** — compliance, consent, erasure, subscribe, typed rows, time-travel. The reference healthcare example. |
| [`cookbook/`](cookbook/) | Domain-agnostic recipes — time-travel, audit-verify-chain, multi-tenant |

## Running examples

Each directory has its own README with language- or domain-specific
instructions. Common prerequisites:

- `kimberlite` CLI on PATH (`curl -fsSL https://kimberlite.dev/install.sh | sh`)
- Rust 1.88+ for `rust/`
- Node.js 18 / 20 / 22 / 24 for `typescript/`
- Python 3.8+ for `python/`
- Docker + Docker Compose for `docker/`

Kick off a dev server once, then point every example at it:

```bash
# In one terminal:
kimberlite init ./clinic-data
kimberlite start ./clinic-data/.kimberlite/data --address 127.0.0.1:5432 --development

# In another terminal:
cd examples/rust && cargo run --example basic
# or:
python examples/healthcare/clinic.py
```

Most examples honour `KIMBERLITE_ADDR=host:port` to target a non-default
server.

### Offline examples

A handful of Rust examples run **without** a server — they showcase
library APIs end-to-end and are the quickest way to see Kimberlite's
FHIR pipeline:

```bash
cd examples/rust
cargo run --example ehr_mini             # parse Bundle → events → projections → FHIRPath
cargo run --example smart_on_fhir_app    # SMART standalone-launch + PKCE + scope-enforced FHIR read
```
