#![no_main]

//! Healthcare-pivot Q3 fuzz target — X12 EDI envelope parser.
//!
//! Drives arbitrary bytes through `kimberlite_x12::parse()`. The X12
//! parser is the entry point for HIPAA-mandated transactions:
//! 837 claims, 835 remittance advice, 270/271 eligibility, etc. It
//! receives clearinghouse-supplied bytes that we don't control, so
//! its first invariant is: **never panic, return an `Err` instead.**
//!
//! Per-interchange delimiters are declared in fixed positions in the
//! ISA header (positions 105-106 give the component separator,
//! position 105 the repetition separator). Mis-shaped envelopes,
//! truncated headers, conflicting delimiters, and malformed segment
//! terminators are all expected fault modes — the fuzzer's job is to
//! find inputs that crash the parser rather than returning a clean
//! error.
//!
//! The April 2026 EPYC fuzz campaign documented in
//! `docs/concepts/pressurecraft.md` §Fuzz-findings-as-type-pressure
//! found 5 real bugs in 77 minutes. This target keeps that pressure on
//! X12, the third-party-input surface that maps most directly to
//! clearinghouse-supplied bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse-only contract. Returns `Result<Interchange, ParseError>`.
    // No panic permitted on any input.
    let _ = kimberlite_x12::parser::parse(data);
});
