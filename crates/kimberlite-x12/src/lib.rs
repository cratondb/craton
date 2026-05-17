//! # `kimberlite-x12`: X12 EDI parser for HIPAA-mandated healthcare transactions
//!
//! ASC X12 is the wire format CMS mandates for HIPAA-covered
//! transactions: claims submission (837), remittance advice (835),
//! eligibility (270/271), claim status (276/277), and authorisations
//! (278). Every U.S. clearinghouse, payer, and RCM vendor speaks it.
//!
//! ## Scope (v1 / Q3)
//!
//! - [`envelope`] — ISA / GS / ST / SE / GE / IEA hierarchy. The
//!   transmission envelope independent of transaction-set semantics.
//! - [`segment`] — segment-level model (segment-id + elements +
//!   composites). Faithful to the wire bytes; no normalisation.
//! - [`parser`] — `parse(bytes) -> Interchange`. Handles
//!   per-interchange delimiter declaration from the fixed-position
//!   ISA header.
//! - [`tx837`] — typed wrapper recognising 837 claims (Professional
//!   `837P`, Institutional `837I`, Dental `837D`) at the envelope
//!   level. Does not yet model the 1000+ data-segment loops — that's
//!   a v0.11+ scope item. The current surface is enough to ingest
//!   claims into a Kimberlite stream and emit a `ClaimReceived`
//!   audit event with the issuer / submission ID / claim count.
//! - [`tx835`] — typed wrapper recognising 835 remittance advice;
//!   same scope contract as `tx837`.
//!
//! ## Why ship the envelope first
//!
//! 837 claims average ~3000 lines of EDI per claim with deep nested
//! loops. A full schema implementation is a year of work. But the
//! *ingestion* path — receive an 837 batch, persist it to an
//! immutable Kimberlite stream, emit an audit event, ack with a 999
//! — needs only the envelope plus segment-level access. That's what
//! ships in v1. Downstream consumers (RCM apps, payer adjudicators)
//! read the raw segments via the iterator and build their own
//! typed projections.
//!
//! ## Design
//!
//! - **Delimiters are declared per-interchange.** The ISA header is
//!   fixed-position (positions 105–106 give the component separator,
//!   position 105 the repetition separator). We read them once and
//!   thread them through the rest of the parse.
//! - **Bytes in, bytes out.** Round-trip preservation is a v0.11
//!   target; v1 is parse-only (encoders ship with the
//!   first-pass `tx837` writer).
//! - **Healthcare-first defaults.** A parsed interchange carries
//!   PHI by definition (837 = claim with patient identifiers; 835 =
//!   payment for a claim). Callers must store into
//!   `DataClass::PHI`-classified streams.

#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod envelope;
pub mod parser;
pub mod segment;
pub mod tx835;
pub mod tx837;

pub use envelope::{FunctionalGroup, Interchange, TransactionSet};
pub use parser::{ParseError, X12Delimiters, parse};
pub use segment::{Element, Segment};
pub use tx835::{Remittance, RemittanceError};
pub use tx837::{Claim, ClaimError, ClaimFormat};
