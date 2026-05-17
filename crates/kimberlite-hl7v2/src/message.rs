//! Generic HL7 v2 message model.
//!
//! ```text
//! Message
//!   └─ Segment ("MSH", "PID", "PV1", ...)
//!       └─ Field   (separated by `|`)
//!           └─ Repetition (separated by `~`)
//!               └─ Component (separated by `^`)
//!                   └─ Subcomponent (separated by `&`)
//! ```
//!
//! A `Field` is `Vec<Component>` *within a single repetition*.
//! Repeating fields are modelled at the `Field` level as a
//! `Vec<Vec<Component>>` of repetitions, but the common case
//! (cardinality 1) flattens to the trivial repetition.

use serde::{Deserialize, Serialize};

use crate::encoding::Encoding;

/// One complete HL7 v2 message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Separator set declared by this message's MSH segment.
    pub encoding: Encoding,
    /// Segments in declaration order.
    pub segments: Vec<Segment>,
}

impl Message {
    /// Look up the first segment with the given 3-character name
    /// (e.g. `"PID"`, `"PV1"`).
    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    /// Iterate all segments with a given name (e.g. several `OBX`
    /// segments in an ORU message).
    pub fn segments_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Segment> + 'a {
        self.segments.iter().filter(move |s| s.name == name)
    }

    /// Read the `MSH.<idx>` field as a text rendering of its first
    /// repetition / first component / first subcomponent. Returns
    /// `None` if MSH or the field doesn't exist.
    ///
    /// `idx` is 1-based per the HL7 v2 convention (`MSH.1` is the
    /// field separator itself, `MSH.9` is the message type).
    pub fn msh_field(&self, idx: usize) -> Option<&str> {
        let msh = self.segment("MSH")?;
        msh.field_text(idx)
    }

    /// `MSH.9.1` — the message type code (`"ADT"`, `"ORU"`, ...).
    pub fn message_type(&self) -> Option<&str> {
        let msh = self.segment("MSH")?;
        let f = msh.field(9)?;
        f.first_rep()?.components.first()?.first_subcomp_text()
    }

    /// `MSH.9.2` — the trigger event code (`"A01"`, `"R01"`, ...).
    pub fn trigger_event(&self) -> Option<&str> {
        let msh = self.segment("MSH")?;
        let f = msh.field(9)?;
        f.first_rep()?.components.get(1)?.first_subcomp_text()
    }
}

/// A single segment. `name` is always the 3-character segment ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub name: String,
    /// `fields[0]` is the segment name field for MSH (special),
    /// otherwise the first user-data field (1-based index).
    pub fields: Vec<Field>,
}

impl Segment {
    /// 1-based field accessor — `seg.field(3)` returns `PID-3` etc.
    /// Returns `None` if the field index is out of range.
    pub fn field(&self, idx: usize) -> Option<&Field> {
        if idx == 0 {
            return None;
        }
        self.fields.get(idx - 1)
    }

    /// Read a field's first repetition / first component / first
    /// subcomponent as text. Convenience for the common case where
    /// a field is a single scalar value.
    pub fn field_text(&self, idx: usize) -> Option<&str> {
        self.field(idx)?
            .first_rep()?
            .components
            .first()?
            .first_subcomp_text()
    }
}

/// One field (potentially with repetitions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// Each repetition is itself a list of components. The
    /// cardinality-1 case is `repetitions.len() == 1`.
    pub repetitions: Vec<Repetition>,
}

impl Field {
    /// True when the field is `""` on the wire (no components, no
    /// repetitions).
    pub fn is_empty(&self) -> bool {
        self.repetitions.is_empty()
            || (self.repetitions.len() == 1 && self.repetitions[0].components.is_empty())
    }

    pub fn first_rep(&self) -> Option<&Repetition> {
        self.repetitions.first()
    }

    /// Build a single-component, single-repetition field from text.
    pub fn from_text(text: &str) -> Self {
        Self {
            repetitions: vec![Repetition {
                components: vec![Component {
                    subcomponents: vec![Subcomponent {
                        value: text.to_string(),
                    }],
                }],
            }],
        }
    }

    /// Empty field.
    pub fn empty() -> Self {
        Self {
            repetitions: vec![Repetition::default()],
        }
    }
}

/// One repetition within a field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repetition {
    pub components: Vec<Component>,
}

/// One component (separated by `^`). Most fields are a single
/// component containing a single subcomponent — that's why the
/// accessors short-circuit on `[0]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub subcomponents: Vec<Subcomponent>,
}

impl Component {
    pub fn first_subcomp_text(&self) -> Option<&str> {
        self.subcomponents.first().map(|s| s.value.as_str())
    }
}

/// One subcomponent — leaf of the segment tree, always a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subcomponent {
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_msh() -> Segment {
        // The MSH-9 field below has structure `ADT^A01^ADT_A01`.
        Segment {
            name: "MSH".into(),
            fields: vec![
                Field::from_text("|"),
                Field::from_text("^~\\&"),
                Field::from_text("SENDER"),
                Field::from_text("FACILITY"),
                Field::from_text("RECEIVER"),
                Field::from_text("RFAC"),
                Field::from_text("20260315093015"),
                Field::empty(),
                Field {
                    repetitions: vec![Repetition {
                        components: vec![
                            Component {
                                subcomponents: vec![Subcomponent {
                                    value: "ADT".into(),
                                }],
                            },
                            Component {
                                subcomponents: vec![Subcomponent {
                                    value: "A01".into(),
                                }],
                            },
                            Component {
                                subcomponents: vec![Subcomponent {
                                    value: "ADT_A01".into(),
                                }],
                            },
                        ],
                    }],
                },
            ],
        }
    }

    #[test]
    fn segment_field_is_1_based() {
        let msh = dummy_msh();
        assert_eq!(msh.field_text(3).unwrap(), "SENDER");
        assert_eq!(msh.field_text(7).unwrap(), "20260315093015");
        assert!(msh.field(0).is_none());
    }

    #[test]
    fn message_type_and_trigger_event_extracted_from_msh_9() {
        let msg = Message {
            encoding: Encoding::standard(),
            segments: vec![dummy_msh()],
        };
        assert_eq!(msg.message_type(), Some("ADT"));
        assert_eq!(msg.trigger_event(), Some("A01"));
    }

    #[test]
    fn segments_named_returns_all_matches() {
        let header = dummy_msh();
        let obx_first = Segment {
            name: "OBX".into(),
            fields: vec![Field::from_text("1"), Field::from_text("NM")],
        };
        let obx_second = Segment {
            name: "OBX".into(),
            fields: vec![Field::from_text("2"), Field::from_text("ST")],
        };
        let msg = Message {
            encoding: Encoding::standard(),
            segments: vec![header, obx_first, obx_second],
        };
        assert_eq!(msg.segments_named("OBX").count(), 2);
    }

    #[test]
    fn empty_field_helpers() {
        assert!(Field::empty().is_empty());
        assert!(!Field::from_text("x").is_empty());
    }
}
