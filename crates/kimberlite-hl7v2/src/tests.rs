//! Cross-cutting tests — parser ↔ encoder fidelity and MLLP
//! framing around realistic message shapes.

use crate::adt::{AdtA01, build_ack};
use crate::encoder::encode;
use crate::mllp;
use crate::parser::parse;

const SAMPLE_ADT_A01: &[u8] = b"MSH|^~\\&|ADT1|GOOD HEALTH HOSPITAL|GHH LAB, INC.|GOOD HEALTH HOSPITAL|20260315093015||ADT^A01^ADT_A01|MSG00001|P|2.5\rEVN|A01|20260315093015\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rPV1|1|I|2000^2012^01|||||||SUR||||ADM|A0\r";

const SAMPLE_ORU_R01: &[u8] = b"MSH|^~\\&|LAB|CITY HOSPITAL|EHR|CITY HOSPITAL|20260315101500||ORU^R01^ORU_R01|MSG44321|P|2.5\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rOBR|1|ORDER12345|LAB67890|CBC^Complete Blood Count|||20260315101500\rOBX|1|NM|6690-2^Leukocytes^LN||7.2|10*3/uL|3.4-9.6|N|||F\rOBX|2|NM|789-8^Erythrocytes^LN||4.8|10*6/uL|4.2-5.4|N|||F\r";

#[test]
fn adt_message_round_trips_byte_identical() {
    let msg = parse(SAMPLE_ADT_A01).unwrap();
    let encoded = encode(&msg).unwrap();
    assert_eq!(encoded, SAMPLE_ADT_A01);
}

#[test]
fn oru_with_multiple_obx_segments_parses_and_round_trips() {
    let msg = parse(SAMPLE_ORU_R01).unwrap();
    assert_eq!(msg.segments_named("OBX").count(), 2);
    assert_eq!(msg.message_type(), Some("ORU"));
    assert_eq!(msg.trigger_event(), Some("R01"));
    assert_eq!(encode(&msg).unwrap(), SAMPLE_ORU_R01);
}

#[test]
fn mllp_frame_then_unframe_preserves_adt_bytes() {
    let framed = mllp::frame(SAMPLE_ADT_A01);
    let payload = mllp::unframe(&framed).unwrap();
    assert_eq!(payload, SAMPLE_ADT_A01);
    let msg = parse(payload).unwrap();
    assert_eq!(msg.message_type(), Some("ADT"));
}

#[test]
fn streaming_mllp_extracts_consecutive_frames() {
    // Simulate two ADT messages arriving in one TCP read.
    let mut buf = mllp::frame(SAMPLE_ADT_A01);
    buf.extend_from_slice(&mllp::frame(SAMPLE_ORU_R01));

    let (first, consumed) = mllp::next_frame(&buf).unwrap();
    assert_eq!(first, SAMPLE_ADT_A01);

    let (second, _) = mllp::next_frame(&buf[consumed..]).unwrap();
    assert_eq!(second, SAMPLE_ORU_R01);
}

#[test]
fn end_to_end_ingest_pipeline() {
    // Wire (MLLP frame) → unframe → parse → typed accessor → ACK
    // — the exact pipeline an ingest worker runs per incoming
    // message.
    let wire = mllp::frame(SAMPLE_ADT_A01);
    let payload = mllp::unframe(&wire).unwrap();
    let msg = parse(payload).unwrap();
    let adt = AdtA01::from_message(&msg).unwrap();

    assert_eq!(adt.patient_id(), Some("PATID1234"));
    assert_eq!(adt.family_name(), Some("SMITH"));
    assert_eq!(adt.patient_class(), Some("I"));

    let ack_payload = build_ack(&adt).unwrap();
    let ack_framed = mllp::frame(&ack_payload);
    assert_eq!(ack_framed[0], mllp::MLLP_START_BLOCK);

    // The ACK itself parses cleanly.
    let ack_msg = parse(&ack_payload).unwrap();
    assert_eq!(ack_msg.message_type(), Some("ACK"));
    assert_eq!(ack_msg.trigger_event(), Some("A01"));
}
