//! # hl7v2-feed — End-to-end HL7 v2 ingest walkthrough.
//!
//! Simulates what an MLLP TCP listener does for every inbound ADT
//! message arriving from a registration system:
//!
//! 1. Receive bytes (here: a baked-in fixture instead of a socket)
//! 2. Unframe the MLLP envelope
//! 3. Parse the HL7 v2 message
//! 4. Use the typed `AdtA01` wrapper to access PID + PV1 fields
//! 5. Build an `ACK^A01` and MLLP-frame it for the response
//!
//! Runs offline — no listener, no TCP. Equivalent to the
//! `ehr_mini` demo for the v2 side of the integration story.
//!
//! ## Running
//!
//! ```bash
//! cd examples/rust
//! cargo run --example hl7v2_feed
//! ```

use anyhow::Result;
use kimberlite_hl7v2::{
    adt::{build_ack, AdtA01},
    mllp, parse,
};

/// Realistic ADT^A01 from a registration system.
const INBOUND_ADT: &[u8] = b"MSH|^~\\&|ADT1|GOOD HEALTH HOSPITAL|GHH LAB, INC.|GOOD HEALTH HOSPITAL|20260315093015||ADT^A01^ADT_A01|MSG00001|P|2.5\rEVN|A01|20260315093015\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rPV1|1|I|2000^2012^01|||||||SUR||||ADM|A0\r";

fn main() -> Result<()> {
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  hl7v2-feed — MLLP → HL7 v2 → typed ADT^A01 → ACK            │");
    println!("└──────────────────────────────────────────────────────────────┘");

    // ── [1] Simulate the wire bytes — MLLP-framed ADT ────────────
    let wire = mllp::frame(INBOUND_ADT);
    println!("\n[1] Received {} bytes of MLLP-framed v2 data", wire.len());
    println!(
        "    First 4 bytes: {:02X?}  (expect 0x0B + 'M' + 'S' + 'H')",
        &wire[..4]
    );
    println!(
        "    Last 2 bytes:  {:02X?}  (expect 0x1C + 0x0D)",
        &wire[wire.len() - 2..]
    );

    // ── [2] Unframe MLLP ─────────────────────────────────────────
    println!("\n[2] Unframe MLLP envelope");
    let payload = mllp::unframe(&wire)?;
    println!("    ✓ payload: {} bytes of HL7 v2", payload.len());

    // ── [3] Parse the HL7 v2 message ─────────────────────────────
    println!("\n[3] Parse v2");
    let msg = parse(payload)?;
    let names: Vec<_> = msg.segments.iter().map(|s| s.name.as_str()).collect();
    println!("    ✓ segments: {}", names.join(", "));
    println!(
        "    message type = {}^{}",
        msg.message_type().unwrap_or("?"),
        msg.trigger_event().unwrap_or("?")
    );

    // ── [4] Typed ADT^A01 access ─────────────────────────────────
    println!("\n[4] Typed ADT^A01 accessors");
    let adt = AdtA01::from_message(&msg)?;
    println!("    event_code             = {}", adt.event_code().unwrap_or("∅"));
    println!(
        "    event_recorded_at      = {}",
        adt.event_recorded_at().unwrap_or("∅")
    );
    println!(
        "    patient_id (MRN)       = {} (type: {})",
        adt.patient_id().unwrap_or("∅"),
        adt.patient_id_type().unwrap_or("∅")
    );
    println!(
        "    name                   = {} {} {}",
        adt.given_name().unwrap_or(""),
        adt.middle_name().unwrap_or(""),
        adt.family_name().unwrap_or("")
    );
    println!(
        "    date_of_birth          = {}",
        adt.date_of_birth().unwrap_or("∅")
    );
    println!("    gender                 = {}", adt.gender().unwrap_or("∅"));
    println!(
        "    patient_class          = {}",
        adt.patient_class().unwrap_or("∅")
    );
    println!(
        "    assigned_ward / room   = {} / {}",
        adt.assigned_ward().unwrap_or("∅"),
        adt.assigned_room().unwrap_or("∅")
    );
    println!(
        "    message_control_id     = {}",
        adt.message_control_id().unwrap_or("∅")
    );

    // ── [5] Build and frame the ACK ──────────────────────────────
    println!("\n[5] Build ACK^A01 and MLLP-frame for the response");
    let ack_payload = build_ack(&adt)?;
    let ack_framed = mllp::frame(&ack_payload);
    println!("    ✓ ACK payload  = {} bytes", ack_payload.len());
    println!("    ✓ ACK framed   = {} bytes", ack_framed.len());
    println!(
        "    ACK content:\n      {}",
        std::str::from_utf8(&ack_payload)
            .unwrap_or("(non-utf8)")
            .replace('\r', "\n      ")
    );

    // ── [6] Verify ACK round-trips ───────────────────────────────
    let ack_msg = parse(&ack_payload)?;
    assert_eq!(ack_msg.message_type(), Some("ACK"));
    assert_eq!(ack_msg.trigger_event(), Some("A01"));
    println!("\n[6] ACK parses cleanly — message_type={}^{}",
        ack_msg.message_type().unwrap_or("?"),
        ack_msg.trigger_event().unwrap_or("?"),
    );

    println!("\n──────────────────────────────────────────────────────────────");
    println!("Pipeline OK: MLLP → parse → typed ADT → ACK → MLLP-framed.");
    println!("Real ingest workers run this once per incoming TCP frame,");
    println!("then hand the parsed PID/PV1 fields to a FHIR Patient/Encounter");
    println!("write against the per-tenant fhir.* streams.");
    println!();

    Ok(())
}
