//! # `kimberlite-hl7v2`: HL7 v2.x parser + encoder + MLLP framing
//!
//! HL7 v2 is the wire protocol the existing fleet of hospital systems
//! speaks — ADT (admit/discharge/transfer), ORU (observation results),
//! ORM (orders), SIU (scheduling), MFN (master files), and dozens
//! more. While the modern world moves to FHIR R4, every clinical
//! integration project still terminates on the v2 plumbing. This
//! crate models v2 messages faithfully so Kimberlite can ingest
//! them.
//!
//! ## Scope
//!
//! - [`message`] — generic [`Message`], [`Segment`], [`Field`],
//!   [`Component`], [`Subcomponent`] model that holds any v2.x
//!   message without typed schemas.
//! - [`encoding`] — separator + escape-character handling.
//!   v2's separators are declared on every message by `MSH.1` /
//!   `MSH.2`; we honour them rather than assuming defaults.
//! - [`parser`] — `parse(bytes) -> Message`.
//! - [`encoder`] — `encode(&Message) -> Vec<u8>`. Round-trips.
//! - [`mllp`] — Minimum Lower Layer Protocol framing for TCP feeds
//!   (`<VT> payload <FS> <CR>`).
//! - [`adt`] — typed wrapper for `ADT^A01` (admit / visit
//!   notification). The pattern other typed message wrappers will
//!   follow.
//!
//! ## Design
//!
//! - **No allocations in the hot path beyond what segments require.**
//!   Parsing a 2 KB ADT message produces O(segment-count) `Vec`s.
//! - **Faithful, not opinionated.** Empty fields, repeating fields,
//!   and components survive round-trip. We don't normalise.
//! - **Healthcare-first defaults.** Every parsed HL7v2 message
//!   carries PHI; the caller is expected to write it into a stream
//!   classified as such (Sprint 2's `DataClass::PHI` default).

#![warn(
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::panic, clippy::todo, clippy::unimplemented)
)]

pub mod adt;
pub mod encoder;
pub mod encoding;
pub mod message;
pub mod mllp;
pub mod parser;

pub use adt::{AdtA01, AdtError};
pub use encoder::{encode, EncodeError};
pub use encoding::{Encoding, DEFAULT_COMPONENT_SEP, DEFAULT_FIELD_SEP, DEFAULT_REPETITION_SEP, DEFAULT_SUBCOMPONENT_SEP, DEFAULT_ESCAPE_CHAR};
pub use message::{Component, Field, Message, Segment, Subcomponent};
pub use mllp::{MllpError, MLLP_END_BLOCK, MLLP_LAST_BYTE, MLLP_START_BLOCK};
pub use parser::{parse, ParseError};

#[cfg(test)]
mod tests;
