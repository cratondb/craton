//! X12 parser. Reads the fixed-position ISA header to discover the
//! per-interchange delimiters, then tokenises the remaining bytes
//! into segments / functional groups / transaction sets.
//!
//! # ISA fixed positions
//!
//! ASC X12 ISA is uniquely fixed-width — every element is a known
//! byte offset. The element separator is byte 3 (the first character
//! after `ISA`). The repetition separator is byte 82. The component
//! (composite) separator is byte 104. The segment terminator is the
//! byte immediately after the segment (byte 105+1 from the start of
//! ISA, accounting for the carriage of all elements).

use crate::envelope::{FunctionalGroup, Interchange, TransactionSet};
use crate::segment::{Element, Segment};
use thiserror::Error;

/// Default delimiter set per the ASC X12 standard.
pub const DEFAULT_ELEMENT_SEP: u8 = b'*';
pub const DEFAULT_COMPONENT_SEP: u8 = b':';
pub const DEFAULT_REPETITION_SEP: u8 = b'^';
pub const DEFAULT_SEGMENT_TERM: u8 = b'~';

/// The per-interchange delimiter set, read from the ISA fixed-position
/// header at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X12Delimiters {
    pub element: u8,
    pub component: u8,
    pub repetition: u8,
    pub segment: u8,
}

impl Default for X12Delimiters {
    fn default() -> Self {
        Self {
            element: DEFAULT_ELEMENT_SEP,
            component: DEFAULT_COMPONENT_SEP,
            repetition: DEFAULT_REPETITION_SEP,
            segment: DEFAULT_SEGMENT_TERM,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("transmission too short to contain an ISA header (need >= 106 bytes, got {0})")]
    TooShort(usize),

    #[error("expected segment id 'ISA' at byte 0, got '{0}'")]
    NotIsa(String),

    #[error("expected GS segment after ISA, got '{0}'")]
    MissingGs(String),

    #[error("expected GE/IEA trailers, hit end of input")]
    UnterminatedEnvelope,

    #[error("expected ST segment to open a transaction set, got '{0}'")]
    MissingSt(String),

    #[error("segment '{0}' is missing required element at position {1}")]
    MissingElement(String, usize),

    #[error("ISA segment is malformed: {0}")]
    MalformedIsa(&'static str),
}

/// Entry point: parse a full X12 interchange.
pub fn parse(bytes: &[u8]) -> Result<Interchange, ParseError> {
    if bytes.len() < 106 {
        return Err(ParseError::TooShort(bytes.len()));
    }
    if &bytes[..3] != b"ISA" {
        return Err(ParseError::NotIsa(
            String::from_utf8_lossy(&bytes[..3.min(bytes.len())]).to_string(),
        ));
    }
    let delims = read_isa_delimiters(bytes)?;
    let segments = tokenise_segments(bytes, delims)?;
    assemble(segments, delims)
}

fn read_isa_delimiters(bytes: &[u8]) -> Result<X12Delimiters, ParseError> {
    // ISA header is fixed-width: 106 chars + segment terminator.
    // Element separator is whatever's at byte 3 (immediately after "ISA").
    let element = bytes[3];
    if element == 0 {
        return Err(ParseError::MalformedIsa("element separator is NUL"));
    }
    // Repetition separator at byte 82, component at 104, segment term at 105.
    let repetition = bytes[82];
    let component = bytes[104];
    let segment = bytes[105];
    Ok(X12Delimiters {
        element,
        component,
        repetition,
        segment,
    })
}

fn tokenise_segments(bytes: &[u8], delims: X12Delimiters) -> Result<Vec<Segment>, ParseError> {
    let mut segments = Vec::new();
    for raw in bytes.split(|&b| b == delims.segment) {
        // Strip leading whitespace (CRLF padding is common between segments).
        let trimmed = trim_segment(raw);
        if trimmed.is_empty() {
            continue;
        }
        segments.push(parse_segment(trimmed, delims)?);
    }
    Ok(segments)
}

fn trim_segment(raw: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = raw.len();
    while start < end && matches!(raw[start], b'\r' | b'\n' | b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(raw[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    &raw[start..end]
}

fn parse_segment(raw: &[u8], delims: X12Delimiters) -> Result<Segment, ParseError> {
    let mut iter = raw.split(|&b| b == delims.element);
    let id_bytes = iter
        .next()
        .ok_or(ParseError::MalformedIsa("empty segment"))?;
    let id = String::from_utf8_lossy(id_bytes).to_string();
    let elements: Vec<Element> = iter
        .map(|raw_elem| parse_element(raw_elem, delims))
        .collect();
    Ok(Segment { id, elements })
}

fn parse_element(raw: &[u8], delims: X12Delimiters) -> Element {
    if raw.contains(&delims.component) {
        let parts: Vec<String> = raw
            .split(|&b| b == delims.component)
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect();
        Element::Composite(parts)
    } else {
        Element::Simple(String::from_utf8_lossy(raw).to_string())
    }
}

/// Assemble flat segments into the ISA/GS/ST envelope hierarchy.
#[allow(clippy::similar_names, clippy::while_let_on_iterator)]
fn assemble(segments: Vec<Segment>, _delims: X12Delimiters) -> Result<Interchange, ParseError> {
    let mut iter = segments.into_iter();
    let isa = iter.next().ok_or(ParseError::UnterminatedEnvelope)?;
    if isa.id != "ISA" {
        return Err(ParseError::NotIsa(isa.id));
    }

    let mut groups = Vec::new();
    let mut iea_segment: Option<Segment> = None;

    while let Some(seg) = iter.next() {
        match seg.id.as_str() {
            "GS" => {
                let group = assemble_group(seg, &mut iter)?;
                groups.push(group);
            }
            "IEA" => {
                iea_segment = Some(seg);
                break;
            }
            other => {
                return Err(ParseError::MissingGs(other.to_string()));
            }
        }
    }

    let iea = iea_segment.ok_or(ParseError::UnterminatedEnvelope)?;
    Ok(Interchange { isa, iea, groups })
}

#[allow(clippy::similar_names, clippy::while_let_on_iterator)]
fn assemble_group(
    gs: Segment,
    iter: &mut std::vec::IntoIter<Segment>,
) -> Result<FunctionalGroup, ParseError> {
    let mut transactions = Vec::new();
    let mut ge_segment: Option<Segment> = None;
    while let Some(seg) = iter.next() {
        match seg.id.as_str() {
            "ST" => {
                let tx = assemble_transaction(seg, iter)?;
                transactions.push(tx);
            }
            "GE" => {
                ge_segment = Some(seg);
                break;
            }
            other => return Err(ParseError::MissingSt(other.to_string())),
        }
    }
    let ge = ge_segment.ok_or(ParseError::UnterminatedEnvelope)?;
    Ok(FunctionalGroup {
        gs,
        ge,
        transactions,
    })
}

fn assemble_transaction(
    st: Segment,
    iter: &mut std::vec::IntoIter<Segment>,
) -> Result<TransactionSet, ParseError> {
    let mut data_segments = Vec::new();
    let mut se_segment: Option<Segment> = None;
    for seg in iter.by_ref() {
        if seg.id == "SE" {
            se_segment = Some(seg);
            break;
        }
        data_segments.push(seg);
    }
    let se = se_segment.ok_or(ParseError::UnterminatedEnvelope)?;
    Ok(TransactionSet {
        st,
        se,
        segments: data_segments,
    })
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    /// Minimal valid 837 envelope with one BHT segment as payload.
    /// Constructed with default delimiters and the fixed ISA layout.
    fn minimal_837() -> Vec<u8> {
        let isa = "ISA*00*          *00*          *ZZ*SENDERID       *ZZ*RECEIVERID     \
                   *240101*0900*^*00501*000000001*0*P*:~";
        let gs = "GS*HC*SENDERAPP*RECEIVERAPP*20240101*0900*1*X*005010X222A1~";
        let st = "ST*837*0001*005010X222A1~";
        let bht = "BHT*0019*00*REF-1234*20240101*0900*CH~";
        let se = "SE*3*0001~";
        let ge = "GE*1*1~";
        let iea = "IEA*1*000000001~";
        format!("{isa}{gs}{st}{bht}{se}{ge}{iea}").into_bytes()
    }

    fn minimal_835() -> Vec<u8> {
        let isa = "ISA*00*          *00*          *ZZ*PAYERID        *ZZ*PROVIDERID     \
                   *240102*1000*^*00501*000000002*0*P*:~";
        let gs = "GS*HP*PAYERAPP*PROVIDERAPP*20240102*1000*2*X*005010X221A1~";
        let st = "ST*835*0001~";
        let bpr = "BPR*I*1500.00*C*ACH*CTX*01*999999992*DA*123456789*1234567890**01*999999991*DA*987654321*20240102~";
        let se = "SE*3*0001~";
        let ge = "GE*1*2~";
        let iea = "IEA*1*000000002~";
        format!("{isa}{gs}{st}{bpr}{se}{ge}{iea}").into_bytes()
    }

    #[test]
    fn reads_isa_envelope() {
        let bytes = minimal_837();
        let interchange = parse(&bytes).unwrap();
        assert_eq!(interchange.sender_id().map(str::trim), Some("SENDERID"));
        assert_eq!(interchange.receiver_id().map(str::trim), Some("RECEIVERID"));
        assert_eq!(interchange.control_number(), Some("000000001"));
        assert!(interchange.is_production());
    }

    #[test]
    fn finds_functional_group_and_transaction() {
        let bytes = minimal_837();
        let interchange = parse(&bytes).unwrap();
        assert_eq!(interchange.groups.len(), 1);
        let group = &interchange.groups[0];
        assert_eq!(group.functional_id(), Some("HC"));
        assert_eq!(group.transactions.len(), 1);
        let tx = &group.transactions[0];
        assert_eq!(tx.transaction_type(), Some("837"));
        assert_eq!(tx.implementation_convention(), Some("005010X222A1"));
    }

    #[test]
    fn segment_count_consistency_holds() {
        let bytes = minimal_837();
        let interchange = parse(&bytes).unwrap();
        let tx = interchange.transactions().next().unwrap();
        assert!(
            tx.is_count_consistent(),
            "SE01 says {} segments, parsed {}",
            tx.declared_segment_count().unwrap_or(0),
            tx.actual_segment_count()
        );
    }

    #[test]
    fn recognises_835() {
        let bytes = minimal_835();
        let interchange = parse(&bytes).unwrap();
        let tx = interchange.transactions().next().unwrap();
        assert_eq!(tx.transaction_type(), Some("835"));
        assert_eq!(interchange.groups[0].functional_id(), Some("HP"));
    }

    #[test]
    fn rejects_short_input() {
        let err = parse(b"too short").unwrap_err();
        assert!(matches!(err, ParseError::TooShort(_)));
    }

    #[test]
    fn rejects_non_isa_header() {
        let mut bytes = minimal_837();
        bytes[0] = b'X';
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(err, ParseError::NotIsa(_)));
    }

    #[test]
    fn iterates_data_segments() {
        let bytes = minimal_837();
        let interchange = parse(&bytes).unwrap();
        let tx = interchange.transactions().next().unwrap();
        let bht = tx.first_segment("BHT").expect("BHT present");
        assert_eq!(bht.text(3), Some("REF-1234"));
    }
}
