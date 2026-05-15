//! HL7 v2 encoding characters.
//!
//! A v2 message declares its separators on the first two fields of
//! MSH:
//!
//! ```text
//! MSH|^~\&|...
//!    |    ^^^^^ MSH.2 — component(^) repetition(~) escape(\) subcomp(&)
//!    └────────  MSH.1 — field separator
//! ```
//!
//! Almost every real-world deployment uses the defaults below, but
//! the spec allows others. We capture the declared separators on the
//! parsed [`crate::Message`] and use those for encoding so a
//! round-trip is byte-identical.

/// Default HL7 v2 field separator — `|`.
pub const DEFAULT_FIELD_SEP: u8 = b'|';
/// Default component separator — `^`.
pub const DEFAULT_COMPONENT_SEP: u8 = b'^';
/// Default repetition separator — `~`.
pub const DEFAULT_REPETITION_SEP: u8 = b'~';
/// Default escape character — `\`.
pub const DEFAULT_ESCAPE_CHAR: u8 = b'\\';
/// Default subcomponent separator — `&`.
pub const DEFAULT_SUBCOMPONENT_SEP: u8 = b'&';

/// Segment terminator — always `\r`, not configurable.
pub const SEGMENT_TERMINATOR: u8 = b'\r';

/// Separator set in effect for a single parsed/encoded message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Encoding {
    pub field: u8,
    pub component: u8,
    pub repetition: u8,
    pub escape: u8,
    pub subcomponent: u8,
}

impl Encoding {
    /// HL7 v2 default encoding — `MSH|^~\&|...`.
    pub const fn standard() -> Self {
        Self {
            field: DEFAULT_FIELD_SEP,
            component: DEFAULT_COMPONENT_SEP,
            repetition: DEFAULT_REPETITION_SEP,
            escape: DEFAULT_ESCAPE_CHAR,
            subcomponent: DEFAULT_SUBCOMPONENT_SEP,
        }
    }
}

impl Default for Encoding {
    fn default() -> Self {
        Self::standard()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_encoding_uses_canonical_separators() {
        let e = Encoding::standard();
        assert_eq!(e.field, b'|');
        assert_eq!(e.component, b'^');
        assert_eq!(e.repetition, b'~');
        assert_eq!(e.escape, b'\\');
        assert_eq!(e.subcomponent, b'&');
    }

    #[test]
    fn default_is_standard() {
        assert_eq!(Encoding::default(), Encoding::standard());
    }
}
