---
title: "TypeScript Client"
section: "coding"
slug: "typescript"
order: 2
---

# TypeScript Client

Build Kimberlite applications in TypeScript or Node.js with the
`@kimberlitedb/client` package.

## What you get

- Promise-based async API, idiomatic TypeScript
- First-class `bigint` support for stream/tenant/offset IDs
- Typed `Value` system for SQL parameters and results
- Point-in-time (`queryAt`) queries for compliance audits
- Time-travel via `AS OF TIMESTAMP` or log-offset queries
- Backed by a Rust N-API native addon (via
  [napi-rs](https://napi.rs)) — no `node-gyp`, no Rust toolchain, no
  compile step for end-users

## Prerequisites

- **Node.js 18, 20, 22, or 24** — the addon targets N-API v8, which is
  ABI-stable across this range.
- A running Kimberlite server. See [Start](/docs/start).

## Install

```bash
npm install @kimberlitedb/client
```

No build step. The package ships prebuilt native binaries for:
- macOS arm64 + x64
- Linux x64 + arm64 (glibc)
- Windows x64 (MSVC)

On `npm install`, the loader in `native/index.js` picks the binary matching
your platform. If you hit an unsupported platform, file an issue and use the
Rust SDK from your server process in the meantime.

## Quick start

```ts
import { Client, DataClass, ValueBuilder, valueToString } from '@kimberlitedb/client';

async function main() {
  const client = await Client.connect({
    addresses: ['127.0.0.1:5432'],
    tenantId: 1n,
  });

  try {
    await client.execute(
      'CREATE TABLE IF NOT EXISTS patients (id BIGINT PRIMARY KEY, name TEXT)',
    );

    await client.execute(
      'INSERT INTO patients (id, name) VALUES ($1, $2)',
      [ValueBuilder.bigint(1), ValueBuilder.text('Jane Doe')],
    );

    const result = await client.query('SELECT id, name FROM patients');
    for (const row of result.rows) {
      console.log(row.map(valueToString).join(' | '));
    }
  } finally {
    await client.disconnect();
  }
}

main().catch(console.error);
```

## Connecting

```ts
const client = await Client.connect({
  addresses: ['127.0.0.1:5432'],   // first address is used
  tenantId: 1n,                    // bigint; required
  authToken: 'bearer-token',       // optional
  readTimeoutMs: 30_000,           // optional, default 30s
  writeTimeoutMs: 30_000,          // optional, default 30s
  bufferSizeBytes: 64 * 1024,      // optional, default 64 KiB
});
```

`Client.connect` is an async static factory — there is no `new Client(...)`.
Call `client.disconnect()` when done. Disconnect is idempotent.

## Query values

Parameters and result cells are typed `Value` objects, not raw JavaScript
primitives. Build parameters with `ValueBuilder`, read cells with the
`isBigInt`/`isText`/... type guards or `valueToString`.

| SQL type | ValueBuilder | ValueType |
|----------|--------------|-----------|
| NULL | `ValueBuilder.null()` | `Null` |
| BIGINT | `ValueBuilder.bigint(42)` | `BigInt` |
| TEXT | `ValueBuilder.text('hi')` | `Text` |
| BOOLEAN | `ValueBuilder.boolean(true)` | `Boolean` |
| TIMESTAMP | `ValueBuilder.timestamp(1_609_459_200_000_000_000n)` or `ValueBuilder.fromDate(new Date())` | `Timestamp` |

Placeholders are `$1, $2, ...` (PostgreSQL-style), not `?`.

```ts
import { ValueBuilder, isBigInt, isText, valueToDate } from '@kimberlitedb/client';

const result = await client.query(
  'SELECT id, name, dob FROM patients WHERE id = $1',
  [ValueBuilder.bigint(1)],
);

for (const row of result.rows) {
  if (isBigInt(row[0]) && isText(row[1])) {
    const dob = valueToDate(row[2]);          // Date | null
    console.log(`#${row[0].value} ${row[1].value} dob=${dob?.toISOString()}`);
  }
}
```

## Data classification

Every stream has a `DataClass`. Values match the Rust enum 1:1:

```ts
import { DataClass } from '@kimberlitedb/client';

await client.createStream('patient_events', DataClass.PHI);
await client.createStream('audit_log', DataClass.Public);
```

| Value | Meaning |
|---|---|
| `DataClass.PHI` | Protected Health Information (HIPAA) |
| `DataClass.Deidentified` | HIPAA Safe Harbor de-identified |
| `DataClass.PII` | GDPR Art. 4 personal data |
| `DataClass.Sensitive` | GDPR Art. 9 special-category data |
| `DataClass.PCI` | Payment card data (e.g. patient billing card-on-file) |
| `DataClass.Financial` | Financial records (e.g. claims payments, invoices) |
| `DataClass.Confidential` | Internal / trade secret |
| `DataClass.Public` | No restrictions |

## Event streams

```ts
const streamId = await client.createStream('orders', DataClass.Confidential);

const firstOffset = await client.append(streamId, [
  Buffer.from(JSON.stringify({ type: 'created', id: 1 })),
  Buffer.from(JSON.stringify({ type: 'shipped', id: 1 })),
]);

const events = await client.read(streamId, { fromOffset: 0n, maxBytes: 1024 });
for (const ev of events) {
  console.log(`offset=${ev.offset}`, JSON.parse(ev.data.toString()));
}
```

## Point-in-time queries (compliance)

`queryAt` runs a SQL query against historical state at a specific log
offset — useful for "what did this chart look like last Tuesday?" audits.

```ts
// Current state
const now = await client.query('SELECT * FROM patients WHERE id = $1', [
  ValueBuilder.bigint(1),
]);

// Historical state at offset 100
const before = await client.queryAt(
  'SELECT * FROM patients WHERE id = $1',
  [ValueBuilder.bigint(1)],
  100n,
);
```

The SQL dialect also supports `AS OF TIMESTAMP '2024-01-15 10:30:00'` and
`AT OFFSET N` inline. See
[SQL Reference](/docs/reference/sql/overview).

## Errors

All errors inherit from `KimberliteError`.

```ts
import {
  KimberliteError,
  ConnectionError,
  StreamNotFoundError,
  PermissionDeniedError,
  AuthenticationError,
  TimeoutError,
  InternalError,
} from '@kimberlitedb/client';

try {
  await client.query('SELECT * FROM nope');
} catch (err) {
  if (err instanceof StreamNotFoundError) {
    // handle missing stream/table
  } else if (err instanceof PermissionDeniedError) {
    // handle auth failure
  } else if (err instanceof KimberliteError) {
    console.error(err.message);
  }
}
```

## Examples

Runnable examples live at
[`sdks/typescript/examples/`](https://github.com/kimberlitedb/kimberlite/tree/main/sdks/typescript/examples):

- `quickstart.ts` — Connect, create stream, append/read events
- `query-example.ts` — Full SQL walkthrough: DDL, DML, parameterized queries,
  time-travel, NULL handling, timestamps

Run them against a local dev server:

```bash
kimberlite dev                      # starts on 127.0.0.1:5432
cd sdks/typescript && npm install
npx ts-node examples/quickstart.ts
```

## Build from source

If you want to hack on the SDK:

```bash
git clone https://github.com/kimberlitedb/kimberlite
cd kimberlite/sdks/typescript
npm install
npm run build:native       # compiles crates/kimberlite-node for host platform
npm run build              # tsc
npm test
```

The native addon is produced by the `kimberlite-node` crate (Rust, napi-rs)
at the repo root.

## Next steps

- [Python Client](/docs/coding/python)
- [Rust Client](/docs/coding/rust)
- [CLI Reference](/docs/reference/cli)
- [SQL Reference](/docs/reference/sql/overview)

## Further reading

- [SDK Architecture](/docs/reference/sdk/overview)
- [Protocol Specification](/docs/reference/protocol)
- [Compliance Guide](/docs/concepts/compliance)
