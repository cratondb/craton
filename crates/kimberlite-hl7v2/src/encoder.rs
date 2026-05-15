//! HL7 v2 encoder.
//!
//! The dual of [`crate::parser::parse`]. Serialises a [`Message`]
//! back to bytes using the message's declared [`crate::Encoding`].
//! A parse → encode round-trip is byte-identical for well-formed
//! input (the parser doesn't normalise field counts).

use thiserror::Error;

use crate::encoding::SEGMENT_TERMINATOR;
use crate::message::{Component, Field, Message, Repetition, Segment};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("MSH segment missing or malformed")]
    BadMsh,
}

/// Encode a `Message` to bytes. Segments are terminated with `\r`.
pub fn encode(msg: &Message) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(256);
    for segment in &msg.segments {
        encode_segment(segment, msg, &mut out)?;
        out.push(SEGMENT_TERMINATOR);
    }
    Ok(out)
}

fn encode_segment(seg: &Segment, msg: &Message, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    out.extend_from_slice(seg.name.as_bytes());

    let is_msh = seg.name == "MSH";
    if is_msh {
        // MSH-1 (field separator) and MSH-2 (encoding chars) are
        // written positionally, not delimited.
        if seg.fields.len() < 2 {
            return Err(EncodeError::BadMsh);
        }
        // MSH-1: emit the field separator byte itself.
        out.push(msg.encoding.field);
        // MSH-2: emit the four encoding chars.
        out.push(msg.encoding.component);
        out.push(msg.encoding.repetition);
        out.push(msg.encoding.escape);
        out.push(msg.encoding.subcomponent);
        // Remaining fields (MSH-3..) delimited by field separator.
        for field in seg.fields.iter().skip(2) {
            out.push(msg.encoding.field);
            encode_field(field, msg, out);
        }
    } else {
        for field in &seg.fields {
            out.push(msg.encoding.field);
            encode_field(field, msg, out);
        }
    }
    Ok(())
}

fn encode_field(field: &Field, msg: &Message, out: &mut Vec<u8>) {
    for (i, rep) in field.repetitions.iter().enumerate() {
        if i > 0 {
            out.push(msg.encoding.repetition);
        }
        encode_repetition(rep, msg, out);
    }
}

fn encode_repetition(rep: &Repetition, msg: &Message, out: &mut Vec<u8>) {
    for (i, c) in rep.components.iter().enumerate() {
        if i > 0 {
            out.push(msg.encoding.component);
        }
        encode_component(c, msg, out);
    }
}

fn encode_component(comp: &Component, msg: &Message, out: &mut Vec<u8>) {
    for (i, sub) in comp.subcomponents.iter().enumerate() {
        if i > 0 {
            out.push(msg.encoding.subcomponent);
        }
        out.extend_from_slice(sub.value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    const SAMPLE_ADT_A01: &[u8] = b"MSH|^~\\&|ADT1|GOOD HEALTH HOSPITAL|GHH LAB, INC.|GOOD HEALTH HOSPITAL|20260315093015||ADT^A01^ADT_A01|MSG00001|P|2.5\rEVN|A01|20260315093015\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rPV1|1|I|2000^2012^01|||||||SUR||||ADM|A0\r";

    #[test]
    fn parse_then_encode_round_trips() {
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        let encoded = encode(&msg).unwrap();
        assert_eq!(
            encoded, SAMPLE_ADT_A01,
            "round-trip mismatch:\nwant: {:?}\n got: {:?}",
            String::from_utf8_lossy(SAMPLE_ADT_A01),
            String::from_utf8_lossy(&encoded)
        );
    }

    #[test]
    fn empty_field_round_trips_as_empty() {
        // MSH-8 (security) is empty in the sample.
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        let encoded = encode(&msg).unwrap();
        // Original has `||ADT^A01^ADT_A01` — two pipes signalling
        // an empty field. Re-encoded form must preserve.
        let raw = std::str::from_utf8(&encoded).unwrap();
        assert!(raw.contains("||ADT^A01^ADT_A01"));
    }
}
