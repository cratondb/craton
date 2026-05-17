//! HL7 v2 parser.
//!
//! The parser is structural — it builds a [`Message`] without
//! interpreting field semantics. Typed wrappers (see [`crate::adt`])
//! consume the [`Message`] after parsing.
//!
//! The trickiest part of v2 parsing is that the message's own
//! separators are declared by MSH-1 (the field separator) and MSH-2
//! (everything else). Both must be read positionally from the raw
//! bytes before the rest of the message can be tokenised.

use thiserror::Error;

use crate::encoding::{Encoding, SEGMENT_TERMINATOR};
use crate::message::{Component, Field, Message, Repetition, Segment, Subcomponent};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("message is empty")]
    Empty,

    #[error("message does not start with `MSH` segment header (found `{found}`)")]
    MissingMsh { found: String },

    #[error(
        "MSH segment too short to declare encoding: need at least 8 bytes after `MSH`, got {got}"
    )]
    MalformedMshHeader { got: usize },

    #[error("encoding declaration in MSH-2 is malformed: {0}")]
    BadEncoding(&'static str),

    #[error("segment name is not 3 ASCII letters: `{found}`")]
    InvalidSegmentName { found: String },
}

/// Parse an HL7 v2 message from raw bytes.
///
/// Accepts both `\r` and `\n` line endings as segment terminators —
/// real-world feeds vary. The canonical wire form uses `\r` only;
/// the encoder writes `\r` to match.
pub fn parse(bytes: &[u8]) -> Result<Message, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }

    // 1. Confirm MSH prefix and read separator declarations.
    if bytes.len() < 3 || &bytes[..3] != b"MSH" {
        let found = bytes.iter().take(3).map(|b| *b as char).collect::<String>();
        return Err(ParseError::MissingMsh { found });
    }
    let field_sep = bytes
        .get(3)
        .copied()
        .ok_or(ParseError::MalformedMshHeader {
            got: bytes.len() - 3,
        })?;
    // MSH-2 occupies the 4 bytes after the field separator.
    if bytes.len() < 8 {
        return Err(ParseError::MalformedMshHeader {
            got: bytes.len() - 3,
        });
    }
    let component_sep = bytes[4];
    let repetition_sep = bytes[5];
    let escape_char = bytes[6];
    let subcomponent_sep = bytes[7];

    // Separators must all differ from each other; otherwise the
    // tokeniser can't distinguish levels.
    let seps = [
        field_sep,
        component_sep,
        repetition_sep,
        escape_char,
        subcomponent_sep,
    ];
    for i in 0..seps.len() {
        for j in (i + 1)..seps.len() {
            if seps[i] == seps[j] {
                return Err(ParseError::BadEncoding(
                    "duplicate separator character in MSH-1/MSH-2",
                ));
            }
        }
    }

    let encoding = Encoding {
        field: field_sep,
        component: component_sep,
        repetition: repetition_sep,
        escape: escape_char,
        subcomponent: subcomponent_sep,
    };

    // 2. Split into segments. Segments terminate on `\r`; we also
    //    accept `\n` and `\r\n` defensively (real feeds do this).
    let mut segments = Vec::new();
    let mut segment_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == SEGMENT_TERMINATOR || b == b'\n' {
            let raw = &bytes[segment_start..i];
            if !raw.is_empty() {
                segments.push(parse_segment(raw, &encoding)?);
            }
            // Skip both bytes if `\r\n`.
            if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
            segment_start = i;
            continue;
        }
        i += 1;
    }
    // Trailing segment without terminator.
    if segment_start < bytes.len() {
        let raw = &bytes[segment_start..];
        if !raw.is_empty() {
            segments.push(parse_segment(raw, &encoding)?);
        }
    }

    Ok(Message { encoding, segments })
}

fn parse_segment(raw: &[u8], encoding: &Encoding) -> Result<Segment, ParseError> {
    // The first three bytes are the segment name (e.g. "MSH", "PID").
    if raw.len() < 3 {
        return Err(ParseError::InvalidSegmentName {
            found: String::from_utf8_lossy(raw).into_owned(),
        });
    }
    let name_bytes = &raw[..3];
    // Per HL7 v2, the first character must be a letter; the remaining
    // two can be letters or digits (PV1, OBX, OBR, NK1, etc.).
    if !name_bytes[0].is_ascii_alphabetic()
        || !name_bytes[1..].iter().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(ParseError::InvalidSegmentName {
            found: String::from_utf8_lossy(name_bytes).into_owned(),
        });
    }
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    let is_msh = name == "MSH";

    let mut fields: Vec<Field> = Vec::new();

    // MSH is special: MSH-1 *is* the field separator (a single byte),
    // and MSH-2 is the rest-of-encoding declaration. The remainder of
    // the segment is `<field_sep><MSH-3><field_sep><MSH-4>...`.
    let after_name = &raw[3..];
    if is_msh {
        // MSH-1 — the field separator character itself.
        if after_name.is_empty() {
            return Ok(Segment { name, fields });
        }
        fields.push(Field::from_text(&String::from_utf8_lossy(&[after_name[0]])));
        // MSH-2 — the next 4 bytes (component/repetition/escape/subcomp).
        if after_name.len() < 5 {
            return Err(ParseError::MalformedMshHeader {
                got: after_name.len(),
            });
        }
        let msh2 = String::from_utf8_lossy(&after_name[1..5]).into_owned();
        fields.push(Field::from_text(&msh2));
        // Remaining fields parse normally.
        let remaining = &after_name[5..];
        // The byte at index 0 of `remaining` is either a field
        // separator (if there are more fields) or the segment end.
        if !remaining.is_empty() {
            // Skip the leading field separator.
            let from = if remaining[0] == encoding.field { 1 } else { 0 };
            parse_field_list(&remaining[from..], encoding, &mut fields);
        }
    } else {
        // Non-MSH: bytes after the name are `<field_sep>field1<field_sep>field2...`.
        if !after_name.is_empty() {
            let from = if after_name[0] == encoding.field {
                1
            } else {
                0
            };
            parse_field_list(&after_name[from..], encoding, &mut fields);
        }
    }

    Ok(Segment { name, fields })
}

fn parse_field_list(bytes: &[u8], encoding: &Encoding, out: &mut Vec<Field>) {
    if bytes.is_empty() {
        return;
    }
    for raw_field in split_top(bytes, encoding.field) {
        out.push(parse_field(raw_field, encoding));
    }
}

fn parse_field(bytes: &[u8], encoding: &Encoding) -> Field {
    if bytes.is_empty() {
        return Field {
            repetitions: vec![Repetition::default()],
        };
    }
    let mut repetitions = Vec::new();
    for raw_rep in split_top(bytes, encoding.repetition) {
        repetitions.push(parse_repetition(raw_rep, encoding));
    }
    if repetitions.is_empty() {
        repetitions.push(Repetition::default());
    }
    Field { repetitions }
}

fn parse_repetition(bytes: &[u8], encoding: &Encoding) -> Repetition {
    if bytes.is_empty() {
        return Repetition::default();
    }
    let mut components = Vec::new();
    for raw_comp in split_top(bytes, encoding.component) {
        components.push(parse_component(raw_comp, encoding));
    }
    Repetition { components }
}

fn parse_component(bytes: &[u8], encoding: &Encoding) -> Component {
    let mut subcomponents = Vec::new();
    for raw_sub in split_top(bytes, encoding.subcomponent) {
        subcomponents.push(Subcomponent {
            value: String::from_utf8_lossy(raw_sub).into_owned(),
        });
    }
    if subcomponents.is_empty() {
        subcomponents.push(Subcomponent {
            value: String::new(),
        });
    }
    Component { subcomponents }
}

/// Split `bytes` on every occurrence of `sep`, returning the
/// in-between slices (including empty ones). Equivalent to
/// `bytes.split(sep)` but preserves the original sequence.
fn split_top(bytes: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == sep {
            out.push(&bytes[start..i]);
            start = i + 1;
        }
    }
    out.push(&bytes[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ADT_A01: &[u8] = b"MSH|^~\\&|ADT1|GOOD HEALTH HOSPITAL|GHH LAB, INC.|GOOD HEALTH HOSPITAL|20260315093015||ADT^A01^ADT_A01|MSG00001|P|2.5\rEVN|A01|20260315093015\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rPV1|1|I|2000^2012^01|||||||SUR||||ADM|A0\r";

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse(b""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_non_msh_prefix() {
        let r = parse(b"PID|1|").unwrap_err();
        assert!(matches!(r, ParseError::MissingMsh { .. }));
    }

    #[test]
    fn parses_adt_a01_segments() {
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        let names: Vec<_> = msg.segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["MSH", "EVN", "PID", "PV1"]);
    }

    #[test]
    fn msh_field_accessors() {
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        assert_eq!(msg.msh_field(3), Some("ADT1"));
        assert_eq!(msg.msh_field(7), Some("20260315093015"));
    }

    #[test]
    fn message_type_and_trigger_event_extracted() {
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        assert_eq!(msg.message_type(), Some("ADT"));
        assert_eq!(msg.trigger_event(), Some("A01"));
    }

    #[test]
    fn pid_5_split_into_components() {
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        let pid = msg.segment("PID").unwrap();
        let f = pid.field(5).unwrap();
        let rep = f.first_rep().unwrap();
        assert_eq!(rep.components.len(), 3);
        assert_eq!(rep.components[0].first_subcomp_text(), Some("SMITH"));
        assert_eq!(rep.components[1].first_subcomp_text(), Some("ALICE"));
        assert_eq!(rep.components[2].first_subcomp_text(), Some("M"));
    }

    #[test]
    fn pid_3_subcomponents_inside_component() {
        // PID-3 ≈ PATID1234^5^M11^ADT1^MR — components separated by ^.
        let msg = parse(SAMPLE_ADT_A01).unwrap();
        let pid = msg.segment("PID").unwrap();
        let f = pid.field(3).unwrap();
        let rep = f.first_rep().unwrap();
        assert_eq!(rep.components.len(), 5);
        assert_eq!(rep.components[0].first_subcomp_text(), Some("PATID1234"));
        assert_eq!(rep.components[4].first_subcomp_text(), Some("MR"));
    }

    #[test]
    fn lf_only_line_endings_accepted() {
        let raw = SAMPLE_ADT_A01
            .iter()
            .copied()
            .map(|b| if b == b'\r' { b'\n' } else { b })
            .collect::<Vec<u8>>();
        let msg = parse(&raw).unwrap();
        assert_eq!(msg.segments.len(), 4);
    }

    #[test]
    fn duplicate_separators_rejected() {
        // Field sep `|` and component sep also `|` — illegal.
        let bad = b"MSH||~\\&|XYZ";
        let err = parse(bad).unwrap_err();
        assert!(matches!(err, ParseError::BadEncoding(_)));
    }
}
