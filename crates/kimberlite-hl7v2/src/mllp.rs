//! Minimum Lower Layer Protocol (MLLP) framing.
//!
//! MLLP is how HL7 v2 messages are framed over TCP between sending
//! and receiving systems. Each frame is:
//!
//! ```text
//! <VT>  payload  <FS> <CR>
//!  0x0B           0x1C 0x0D
//! ```
//!
//! - `VT` (vertical tab, `0x0B`) — start block
//! - `FS` (file separator, `0x1C`) — end block (first byte)
//! - `CR` (carriage return, `0x0D`) — end block (second byte)
//!
//! The payload between VT and FS is the HL7 v2 message bytes,
//! exactly as [`crate::encoder::encode`] emits them.

use thiserror::Error;

/// MLLP start-of-block byte (`<VT>`, 0x0B).
pub const MLLP_START_BLOCK: u8 = 0x0B;

/// MLLP end-of-block byte (`<FS>`, 0x1C). Followed by `<CR>`.
pub const MLLP_END_BLOCK: u8 = 0x1C;

/// MLLP final byte after `<FS>` (`<CR>`, 0x0D).
pub const MLLP_LAST_BYTE: u8 = 0x0D;

/// Errors from framing/unframing MLLP.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MllpError {
    #[error("MLLP frame missing leading <VT> (0x0B)")]
    MissingStart,

    #[error("MLLP frame missing trailing <FS><CR> (0x1C 0x0D)")]
    MissingEnd,

    #[error("MLLP frame too short to contain start + end markers")]
    TruncatedFrame,
}

/// Wrap a payload in an MLLP frame.
///
/// Allocates a `Vec<u8>` of length `payload.len() + 3`.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 3);
    out.push(MLLP_START_BLOCK);
    out.extend_from_slice(payload);
    out.push(MLLP_END_BLOCK);
    out.push(MLLP_LAST_BYTE);
    out
}

/// Unwrap an MLLP frame to its payload bytes.
///
/// Returns [`MllpError::MissingStart`] / [`MllpError::MissingEnd`]
/// if the framing bytes aren't present.
pub fn unframe(bytes: &[u8]) -> Result<&[u8], MllpError> {
    if bytes.len() < 3 {
        return Err(MllpError::TruncatedFrame);
    }
    if bytes[0] != MLLP_START_BLOCK {
        return Err(MllpError::MissingStart);
    }
    let last = bytes.len() - 1;
    if bytes[last] != MLLP_LAST_BYTE || bytes[last - 1] != MLLP_END_BLOCK {
        return Err(MllpError::MissingEnd);
    }
    Ok(&bytes[1..last - 1])
}

/// Streaming MLLP frame extractor.
///
/// Given a buffer that may contain a partial frame, returns
/// `Some((payload, consumed_bytes))` for the first complete frame.
/// The caller advances their read cursor by `consumed_bytes` and
/// retains the unparsed tail for the next read.
///
/// Returns `None` when no complete frame has arrived yet.
pub fn next_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    let start = buf.iter().position(|b| *b == MLLP_START_BLOCK)?;
    // Look for FS+CR after the start.
    for i in (start + 1)..buf.len().saturating_sub(1) {
        if buf[i] == MLLP_END_BLOCK && buf[i + 1] == MLLP_LAST_BYTE {
            let payload = &buf[start + 1..i];
            let consumed = i + 2;
            return Some((payload, consumed));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_then_unframe_round_trips() {
        let payload = b"MSH|^~\\&|ADT1|H|...|2.5\rEVN|A01|20260315\r";
        let framed = frame(payload);
        assert_eq!(framed[0], MLLP_START_BLOCK);
        assert_eq!(framed[framed.len() - 2], MLLP_END_BLOCK);
        assert_eq!(framed[framed.len() - 1], MLLP_LAST_BYTE);

        let payload2 = unframe(&framed).unwrap();
        assert_eq!(payload2, payload);
    }

    #[test]
    fn missing_start_rejected() {
        let bad = b"MSH|payload\x1C\x0D";
        assert_eq!(unframe(bad), Err(MllpError::MissingStart));
    }

    #[test]
    fn missing_end_rejected() {
        let bad = b"\x0BMSH|payload";
        assert_eq!(unframe(bad), Err(MllpError::MissingEnd));
    }

    #[test]
    fn truncated_rejected() {
        assert_eq!(unframe(b"\x0B"), Err(MllpError::TruncatedFrame));
    }

    #[test]
    fn next_frame_returns_first_complete_frame_in_buffer() {
        let one = frame(b"first");
        let two = frame(b"second");
        let mut combined = one.clone();
        combined.extend_from_slice(&two);
        let (payload, consumed) = next_frame(&combined).unwrap();
        assert_eq!(payload, b"first");
        assert_eq!(consumed, one.len());
        // Subsequent read on the tail produces the second frame.
        let (payload2, _) = next_frame(&combined[consumed..]).unwrap();
        assert_eq!(payload2, b"second");
    }

    #[test]
    fn next_frame_returns_none_for_incomplete_buffer() {
        let partial = b"\x0Bpayload-still-coming";
        assert!(next_frame(partial).is_none());
    }
}
