//! X12 envelope: ISA → GS → ST → SE → GE → IEA hierarchy.
//!
//! Every X12 interchange has this onion structure: an `Interchange`
//! (ISA/IEA) contains one or more `FunctionalGroup`s (GS/GE), each of
//! which contains one or more `TransactionSet`s (ST/SE).

use crate::segment::Segment;
use serde::{Deserialize, Serialize};

/// The outermost envelope. Holds the ISA header for routing metadata
/// plus all the functional groups inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interchange {
    pub isa: Segment,
    pub iea: Segment,
    pub groups: Vec<FunctionalGroup>,
}

impl Interchange {
    /// Interchange Sender ID (ISA06).
    pub fn sender_id(&self) -> Option<&str> {
        self.isa.text(6)
    }

    /// Interchange Receiver ID (ISA08).
    pub fn receiver_id(&self) -> Option<&str> {
        self.isa.text(8)
    }

    /// Interchange Control Number (ISA13). Used for ack correlation
    /// (TA1 / 999 responses reference this exact number).
    pub fn control_number(&self) -> Option<&str> {
        self.isa.text(13)
    }

    /// Test indicator (ISA15). `"P"` = production, `"T"` = test.
    pub fn is_production(&self) -> bool {
        self.isa.text(15) == Some("P")
    }

    /// Walk every transaction set across every group.
    pub fn transactions(&self) -> impl Iterator<Item = &TransactionSet> {
        self.groups.iter().flat_map(|g| g.transactions.iter())
    }
}

/// Functional group: a batch of transactions of the same type
/// (`GS01` = `HC` for healthcare claims, `HP` for remittance, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionalGroup {
    pub gs: Segment,
    pub ge: Segment,
    pub transactions: Vec<TransactionSet>,
}

impl FunctionalGroup {
    /// Functional Identifier Code (GS01). `HC` = claim,
    /// `HP` = remittance, `HB` = eligibility response, `HS` =
    /// eligibility request, etc.
    pub fn functional_id(&self) -> Option<&str> {
        self.gs.text(1)
    }

    /// Application Sender Code (GS02).
    pub fn sender_code(&self) -> Option<&str> {
        self.gs.text(2)
    }

    /// Application Receiver Code (GS03).
    pub fn receiver_code(&self) -> Option<&str> {
        self.gs.text(3)
    }

    /// Group control number (GS06).
    pub fn group_control_number(&self) -> Option<&str> {
        self.gs.text(6)
    }
}

/// Transaction set: one logical message (a single 837 claim batch,
/// a single 835 remittance, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSet {
    pub st: Segment,
    pub se: Segment,
    pub segments: Vec<Segment>,
}

impl TransactionSet {
    /// Transaction set identifier code (ST01) — `"837"`, `"835"`,
    /// `"270"`, etc.
    pub fn transaction_type(&self) -> Option<&str> {
        self.st.text(1)
    }

    /// Transaction set control number (ST02). Within a functional
    /// group these must be unique.
    pub fn control_number(&self) -> Option<&str> {
        self.st.text(2)
    }

    /// Implementation Convention Reference (ST03) — when present,
    /// this names the specific implementation guide (e.g.
    /// `005010X222A1` for 837 Professional v5010).
    pub fn implementation_convention(&self) -> Option<&str> {
        self.st.text(3)
    }

    /// Find the first segment with the given id.
    pub fn first_segment(&self, id: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.id == id)
    }

    /// All segments with the given id, in document order.
    pub fn segments_by_id<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a Segment> + 'a {
        self.segments.iter().filter(move |s| s.id == id)
    }

    /// Declared segment count from SE01 (includes ST and SE).
    pub fn declared_segment_count(&self) -> Option<usize> {
        self.se.text(1).and_then(|s| s.parse().ok())
    }

    /// Actual segment count (ST + data segments + SE).
    pub fn actual_segment_count(&self) -> usize {
        // 1 (ST) + data segments + 1 (SE)
        self.segments.len() + 2
    }

    /// True iff the SE01 declared count matches what we actually parsed.
    pub fn is_count_consistent(&self) -> bool {
        self.declared_segment_count() == Some(self.actual_segment_count())
    }
}
