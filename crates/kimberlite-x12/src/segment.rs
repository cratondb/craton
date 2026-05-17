//! Segment-level model. An X12 segment is `<segment-id><element-sep><elem1>...<segment-term>`,
//! where elements can themselves carry composite sub-elements separated
//! by a composite separator.

use serde::{Deserialize, Serialize};

/// A single X12 element. Either a simple scalar or a composite of
/// sub-elements (separated by the composite-separator in the wire bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Element {
    Simple(String),
    Composite(Vec<String>),
}

impl Element {
    /// Returns the simple-element value, or the first sub-element of a
    /// composite. Convenience for code that only cares about the head.
    pub fn first(&self) -> &str {
        match self {
            Self::Simple(s) => s.as_str(),
            Self::Composite(parts) => parts.first().map_or("", String::as_str),
        }
    }

    pub fn as_simple(&self) -> Option<&str> {
        match self {
            Self::Simple(s) => Some(s.as_str()),
            Self::Composite(_) => None,
        }
    }

    pub fn as_composite(&self) -> Option<&[String]> {
        match self {
            Self::Simple(_) => None,
            Self::Composite(parts) => Some(parts.as_slice()),
        }
    }
}

/// An X12 segment: identifier (e.g. `ISA`, `CLM`, `SE`) plus its elements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub id: String,
    pub elements: Vec<Element>,
}

impl Segment {
    pub fn new(id: impl Into<String>, elements: Vec<Element>) -> Self {
        Self {
            id: id.into(),
            elements,
        }
    }

    /// 1-indexed element access matching how X12 specs reference
    /// segment positions (`ISA01`, `CLM02`, etc.). Position `0` is
    /// the segment id itself; `1..=n` are the elements.
    pub fn element(&self, position: usize) -> Option<&Element> {
        if position == 0 {
            return None;
        }
        self.elements.get(position - 1)
    }

    /// Same as `element`, returning the head string. Convenience for
    /// the common case `seg.text(2)` instead of
    /// `seg.element(2).and_then(|e| e.as_simple())`.
    pub fn text(&self, position: usize) -> Option<&str> {
        self.element(position).map(Element::first)
    }
}
