---
title: "FHIR-Native, Verifiable: storing clinical data so the audit log can prove it"
date: "2026-05-15"
author: "Jared Reyes"
summary: "Kimberlite v0.9.x lands FHIR R4 as a first-class storage model. Typed Patient/Encounter/Observation resources, a canonical-JSON layer the audit log can hash-chain over, projection rows for SQL search, a FHIRPath subset for queries, and SMART on FHIR scope enforcement. Six healthcare-shaped primitives that together turn the database into the EHR-adjacent system of record we've been positioning toward."
tags: ["fhir", "healthcare", "smart-on-fhir", "compliance", "audit"]
---

Healthcare data is FHIR-shaped. Every modern EHR speaks it; every
clinical app reads it; every payer integration carries it. But almost
no database is FHIR-aware. You hand FHIR JSON to Postgres as `JSONB`,
to Mongo as a document, to S3 as a blob — and the schema, the
provenance, and the audit story stay your problem.

Kimberlite is built on a single principle: *all data is an immutable,
ordered log; all state is a derived view*. v0.9.x is the release
where that principle meets FHIR.

This post walks the six primitives that landed in main this week and
the property each one is solving for.

## 1. Typed resources you can hold in your hand

[`kimberlite-fhir`](https://github.com/kimberlitedb/kimberlite/tree/main/crates/kimberlite-fhir)
is the new crate. It carries hand-written FHIR R4 representations of
the wedge resource set:

- `Patient`, `Practitioner`, `Organization`
- `Encounter`, `Observation`
- `Bundle`

Each one is a faithful `serde`-derived Rust struct that round-trips
to and from canonical FHIR JSON. No code generation, no `fhirbolt`
dependency, no R5-specific assumptions creeping in. The struct is
small enough to read in one sitting and the test suite proves every
field round-trips:

```rust
let patient = Patient {
    id: Some("alice-001".into()),
    name: vec![HumanName {
        family: Some("Smith".into()),
        given: vec!["Alice".into(), "M.".into()],
        ..Default::default()
    }],
    gender: Some(PatientGender::Female),
    birth_date: Some("1980-05-12".into()),
    ..Default::default()
};
let bytes = patient.to_json()?;
assert_eq!(Patient::from_json(&bytes)?, patient);
```

Why hand-write the types instead of generating them? Two reasons.

First, **PRESSURECRAFT**. Our internal coding standard is paranoid
about complexity creeping in via codegen. Every struct in
`kimberlite-fhir` is reviewable, modifiable, and bounded. Adding a
profile-specific extension doesn't require regenerating a 50k-line
pile.

Second, **failure forensics**. If a Patient JSON is fed into a
deserializer expecting an Observation, we want to know — not silently
get a half-populated value. Every resource carries a unit-variant
tag type that *only* deserialises from the matching `resourceType`:

```rust
let raw = br#"{"resourceType":"Observation","id":"o1"}"#;
let err = Patient::from_json(raw).unwrap_err();
assert!(matches!(
    err,
    ResourceError::WrongResourceType { actual, .. } if actual == "Observation"
));
```

Same posture as our consensus invariants: an invalid state is a
forensic event, not a benign mismatch.

## 2. Canonical JSON for the audit log

Healthcare audit logs aren't "nice to have." HIPAA § 164.312(b)
mandates them. § 164.530(j)(2) says they live for six years after
the data is gone. And — the part most database vendors hand-wave —
the auditor needs to verify that what's on disk today is what was
written then.

Kimberlite's audit log is hash-chained: every event commits over its
bytes plus the previous event's hash. The chain breaks if anything
changes. But hashing requires bytes that are *deterministic*. Two
serialisations of the same Patient must produce the same bytes —
otherwise the chain validates differently on each rebuild.

`serde_json` doesn't promise that. Object key order in Rust depends
on `HashMap` iteration order. Two encodes can disagree byte-for-byte.

So we wrote `kimberlite_fhir::canonical::to_canonical_bytes`:

- Object keys sorted lexicographically at every nesting level
- Arrays preserve order (semantically meaningful in FHIR — the first
  `HumanName.given` is the primary)
- No insignificant whitespace
- Standard JSON-escape for strings, numbers via serde's f64 formatter

The property the test suite proves:

```rust
let a = br#"{"id":"p1","resourceType":"Patient","active":true}"#;
let b = br#"{"active":true,"resourceType":"Patient","id":"p1"}"#;
let pa = Patient::from_json(a)?;
let pb = Patient::from_json(b)?;
assert_eq!(to_canonical_bytes(&pa)?, to_canonical_bytes(&pb)?);
```

That's the property the audit log depends on. Field-order shouldn't
matter; semantic identity should.

## 3. Storage shape: typed events + canonical fidelity

`kimberlite-fhir-store::FhirEvent` is what each per-resource stream
carries:

```rust
pub struct FhirEvent {
    pub version: u8,             // = 1
    pub action: FhirAction,      // Create | Update | Delete
    pub resource_type: String,   // "Patient", "Observation", ...
    pub resource_id: String,
    pub version_id: Option<String>,
    pub canonical_json: Vec<u8>, // byte-stable, audit-grade
}
```

Postcard-encoded on disk. The `canonical_json` field is the fidelity
half of the *typed-plus-JSON* model: an Epic-emitted Patient with
seventeen Epic-specific extensions arrives, deserialises to our
typed shape, and the extensions survive on the way out because
they're in the canonical bytes. We don't drop what we don't model.

Streams are named by `(tenant, resource_type)`:

```
tenant 42, Patient resources       → "fhir.Patient.42"
tenant 42, Observation resources   → "fhir.Observation.42"
tenant 42, Bundle ingestion log    → "fhir.Bundle.42"
```

Every stream defaults to `DataClass::PHI` — the healthcare-first
default that Sprint 2 introduced. Retention defaults to
`HIPAA § 164.530` minimum: 2,190 days, six years. You don't opt in;
you opt out (with an explicit `DataClass::Public` if you genuinely
have a de-identified extract).

## 4. Projection rows: search without leaking the canonical bytes

Storing the canonical JSON is enough for fidelity but useless for
search. The query layer needs columns it can index, predicates it
can plan, and rows it can return in milliseconds.

So every resource projects to a typed row:

```rust
pub struct PatientProjection {
    pub id: String,
    pub family_name: Option<String>,
    pub given_names: Option<String>,
    pub birth_date: Option<String>,
    pub gender: Option<String>,
    pub primary_identifier: Option<String>,
    pub primary_identifier_system: Option<String>,
}
```

`PatientProjection::table_name()` → `"fhir_patient"`.
`PractitionerProjection` specifically pulls the NPI off the
`http://hl7.org/fhir/sid/us-npi` identifier. `ObservationProjection`
routes `valueQuantity` to `value_numeric` + `value_unit`,
`valueString` to `value_string`, `valueCodeableConcept` to a
`value_string` rendering — the projection knows the FHIR
value-x indirection so the SQL layer doesn't have to.

A clinical app doing an MRN lookup becomes:

```sql
SELECT id, family_name, birth_date
FROM   fhir_patient
WHERE  primary_identifier = 'MRN-12345'
  AND  primary_identifier_system = 'http://hospital.example.org/mrn';
```

The full canonical JSON sits next to it in the event log for export
and audit. The fast path doesn't pay for the fidelity path.

## 5. FHIRPath: the query language SMART apps already speak

FHIRPath is the expression language every SMART on FHIR client uses
to navigate resources. We landed a focused subset:

| Feature | Example |
|---|---|
| Path navigation | `Patient.name.family` |
| Indexing | `Patient.name[0].family` |
| Filter | `Patient.name.where(use = 'official').given` |
| Collection predicates | `Patient.identifier.exists()`, `count()`, `first()`, `last()`, `empty()` |
| Comparison | `Observation.valueQuantity.value > 70` |
| Logical | `Patient.active = true and Patient.gender = 'female'` |

The evaluator runs against `serde_json::Value` — i.e. against the
canonical JSON the audit log committed to. That means a FHIRPath
expression evaluated today returns the same answer it would have
returned yesterday, against the same bytes. Reproducible queries
over reproducible data.

Skipped in v0.9.x (deferred to v0.10+): `as`/`is`/`ofType`,
`resolve()`, date arithmetic, quantity arithmetic, `iif`, `select`,
`repeat`, context variables. These layer on as workloads demand
them — we don't ship the full spec for the sake of completeness.

## 6. SMART on FHIR scope enforcement

The point of all of the above is to let a SMART-launched clinical
app read a patient's chart with end-to-end provable authorization.

`kimberlite_rbac::smart_on_fhir` parses v1 scopes into a typed
form:

```rust
"patient/Observation.read" → SmartScope::Resource {
    context: ScopeContext::Patient,
    resource_type: ResourceFilter::Specific("Observation".into()),
    actions: ScopeActions::read_only(),
}
```

`authorize(scope_set, launch_context, resource_type, action)` is the
decision point. It returns one of four outcomes:

- `Allow` — `user/*.read` matched, no further constraint
- `AllowWithPatientContext { patient_id }` — `patient/*.read`
  matched; the query layer MUST AND in
  `subject.reference = "Patient/<id>"`
- `MissingPatientContext` — a `patient/...` scope matched but no
  `patient_id` was on the token. The server returns OAuth
  `invalid_token`, not `insufficient_scope`. The distinction
  matters: misconfigured launch ≠ missing permission.
- `Deny` — nothing matched

When both `user/Observation.read` and `patient/Observation.read` are
present, the broader user-scope wins. SMART semantics; mechanical to
enforce.

`TokenValidator` supports RS256 / ES256 against an issuer's PEM
(production), and HS256 against a shared secret (test/dev only,
documented as such).

## Putting it together: a clinical visit, end-to-end

The `ehr_mini` example takes a transaction Bundle — Patient +
ambulatory Encounter + body-weight Observation — and walks the
pipeline offline:

```text
[1] Parse the transaction Bundle
    ✓ Bundle `visit-2026-03-15` parsed: type=Transaction, 3 entries

[2] BundleIngester → per-stream events
    · Patient → fhir.Patient.42  (retention: 2190 days, class: PHI)
    · Encounter → fhir.Encounter.42  (retention: 2190 days, class: PHI)
    · Observation → fhir.Observation.42  (retention: 2190 days, class: PHI)

[3] Audit-grade byte-stability
    ✓ canonical JSON deterministic across two encodes (410 bytes)

[4] Projection rows for SQL search
    fhir_patient row:  family_name=Smith, primary_identifier=MRN-12345
    fhir_observation row:  code=29463-7, value_numeric=72.5 kg

[5] FHIRPath queries against canonical JSON
    `Patient.identifier.where(system='…/mrn').value` → ["MRN-12345"]
    `Observation.valueQuantity.value > 70` → [true]
```

`smart_on_fhir_app` layers SMART on top: discovery →
`/authorize` (PKCE S256) → `/token` (HS256 demo) → bearer-protected
`/fhir/Observation/obs-weight-001` → patient-context-enforced read.
Both run with `cargo run --example` and exit cleanly — no server,
no port, no infrastructure. Pure library demos.

## What we haven't shipped

Honesty is part of the audit trail too.

- **FHIRPath SQL integration.** The evaluator runs against canonical
  JSON. Wiring it into `kimberlite-query` as a `FHIRPATH '…'` clause
  inside SQL is v0.10.
- **REST API surface.** `GET /fhir/Patient/123` and the SMART app
  example are illustrative but not yet a shipped server route.
  Q1.6 + Q1.8 give every primitive the route needs; gluing them
  to the server is a discrete next step.
- **Beyond the wedge.** DiagnosticReport, MedicationRequest,
  ServiceRequest, Condition — not yet modelled. The `FhirExtras`
  catch-all means they survive Bundle round-trip as untyped JSON;
  typed support comes as the workload demands.
- **De-identification.** Safe Harbor's 18-identifier transform is
  v0.10.x — the canonical-bytes layer is the substrate that will
  make verifiable de-identification proofs possible later.
- **Multi-node HA.** Clinical systems need 5+ nines. Multi-node
  VSR is pulled forward as a v0.9.x deliverable; pages on its
  status will follow.

## Test inventory

What landed:

- `kimberlite-fhir`: 65 unit + 1 doctest
- `kimberlite-fhir-store`: 32
- `kimberlite-rbac` SMART module: 27
- 2 runnable end-to-end examples (`ehr_mini`, `smart_on_fhir_app`)

**125 new tests. Zero regressions across the existing 1,200+ test
suite.** That number matters more than the line count: every claim
in this post is paired with a passing assertion in the tree.

## Why this is the right shape

A FHIR server that doesn't audit its own bytes is asking the
hospital's legal team to trust it. A FHIR server that hash-chains
over the canonical bytes hands the legal team a cryptographic
artefact instead. The difference between those two stances is the
difference between a six-week breach investigation and a
two-minute integrity proof.

We're not the only FHIR-aware Rust crate. We are, as far as I can
tell, the only one whose primitives map cleanly onto a hash-chained
audit log designed to be re-verified six years later. That's the
moat. v0.9.x is the foundation; v1.0 is when third-party assessors
sign off on the BAA-ready packaging.

The code is on `main` today.
[crates/kimberlite-fhir](https://github.com/kimberlitedb/kimberlite/tree/main/crates/kimberlite-fhir),
[crates/kimberlite-fhir-store](https://github.com/kimberlitedb/kimberlite/tree/main/crates/kimberlite-fhir-store),
[crates/kimberlite-rbac/src/smart_on_fhir](https://github.com/kimberlitedb/kimberlite/tree/main/crates/kimberlite-rbac/src/smart_on_fhir).
Try `cargo run --example ehr_mini` from `examples/rust/` to see it
move.

— Jared
