//! Typed accessors for `ADT^A01` (admit / visit notification).
//!
//! `ADT^A01` is the canonical HL7 v2 message a registration system
//! sends when a patient is admitted. It carries identification
//! (PID), visit info (PV1), event details (EVN), and optionally
//! next-of-kin, additional demographics, etc.
//!
//! The wrapper here surfaces the fields a Kimberlite ingest pipeline
//! needs to land in our FHIR projections — MRN, name parts, DOB,
//! gender, encounter class, and ward/room. Anything else stays in
//! the underlying [`Message`] for fidelity.

use thiserror::Error;

use crate::encoder::EncodeError;
use crate::message::Message;

#[derive(Debug, Error)]
pub enum AdtError {
    #[error("message is not an ADT^A01 (found `{message_type}^{trigger}`)")]
    NotAdtA01 {
        message_type: String,
        trigger: String,
    },

    #[error("ADT message missing required PID segment")]
    MissingPid,

    #[error("ADT message missing required PV1 segment")]
    MissingPv1,

    #[error("ADT message missing required EVN segment")]
    MissingEvn,

    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),
}

/// Typed view over an `ADT^A01` message. Held by reference to the
/// underlying [`Message`] so accessors are cheap and the original
/// bytes remain available for re-emission.
#[derive(Debug)]
pub struct AdtA01<'a> {
    pub message: &'a Message,
}

impl<'a> AdtA01<'a> {
    /// Wrap a parsed [`Message`] as an `ADT^A01`. Errors if the
    /// MSH-9 doesn't say so or if a required segment is missing.
    pub fn from_message(message: &'a Message) -> Result<Self, AdtError> {
        let mt = message.message_type().unwrap_or("");
        let te = message.trigger_event().unwrap_or("");
        if mt != "ADT" || te != "A01" {
            return Err(AdtError::NotAdtA01 {
                message_type: mt.to_string(),
                trigger: te.to_string(),
            });
        }
        if message.segment("PID").is_none() {
            return Err(AdtError::MissingPid);
        }
        if message.segment("PV1").is_none() {
            return Err(AdtError::MissingPv1);
        }
        if message.segment("EVN").is_none() {
            return Err(AdtError::MissingEvn);
        }
        Ok(Self { message })
    }

    /// `EVN-1` — event type code (`"A01"` for an admit).
    pub fn event_code(&self) -> Option<&str> {
        self.message.segment("EVN")?.field_text(1)
    }

    /// `EVN-2` — event recorded date/time, as written
    /// (`"20260315093015"`).
    pub fn event_recorded_at(&self) -> Option<&str> {
        self.message.segment("EVN")?.field_text(2)
    }

    /// `PID-3.1` — first patient identifier value (the MRN).
    pub fn patient_id(&self) -> Option<&str> {
        let pid = self.message.segment("PID")?;
        let f = pid.field(3)?;
        f.first_rep()?.components.first()?.first_subcomp_text()
    }

    /// `PID-3.5` — identifier type code (e.g. `"MR"` for medical
    /// record number).
    pub fn patient_id_type(&self) -> Option<&str> {
        let pid = self.message.segment("PID")?;
        let f = pid.field(3)?;
        f.first_rep()?.components.get(4)?.first_subcomp_text()
    }

    /// `PID-5.1` — family name.
    pub fn family_name(&self) -> Option<&str> {
        let pid = self.message.segment("PID")?;
        let f = pid.field(5)?;
        f.first_rep()?.components.first()?.first_subcomp_text()
    }

    /// `PID-5.2` — given name.
    pub fn given_name(&self) -> Option<&str> {
        let pid = self.message.segment("PID")?;
        let f = pid.field(5)?;
        f.first_rep()?.components.get(1)?.first_subcomp_text()
    }

    /// `PID-5.3` — middle name / initial.
    pub fn middle_name(&self) -> Option<&str> {
        let pid = self.message.segment("PID")?;
        let f = pid.field(5)?;
        f.first_rep()?.components.get(2)?.first_subcomp_text()
    }

    /// `PID-7` — date of birth (YYYYMMDD format on the wire).
    pub fn date_of_birth(&self) -> Option<&str> {
        self.message.segment("PID")?.field_text(7)
    }

    /// `PID-8` — administrative gender (`"M"`, `"F"`, `"O"`, `"U"`).
    pub fn gender(&self) -> Option<&str> {
        self.message.segment("PID")?.field_text(8)
    }

    /// `PV1-2` — patient class (`"I"` inpatient, `"O"` outpatient,
    /// `"E"` emergency, `"P"` preadmit, …).
    pub fn patient_class(&self) -> Option<&str> {
        self.message.segment("PV1")?.field_text(2)
    }

    /// `PV1-3.1` — assigned point of care (ward / unit).
    pub fn assigned_ward(&self) -> Option<&str> {
        let pv1 = self.message.segment("PV1")?;
        let f = pv1.field(3)?;
        f.first_rep()?.components.first()?.first_subcomp_text()
    }

    /// `PV1-3.2` — assigned room.
    pub fn assigned_room(&self) -> Option<&str> {
        let pv1 = self.message.segment("PV1")?;
        let f = pv1.field(3)?;
        f.first_rep()?.components.get(1)?.first_subcomp_text()
    }

    /// `MSH-10` — message control id. Used to generate the
    /// corresponding `ACK` (see [`AdtA01::build_ack_payload`]).
    pub fn message_control_id(&self) -> Option<&str> {
        self.message.msh_field(10)
    }
}

/// Build a minimal `ACK^A01` payload acknowledging the supplied
/// ADT message. Mirrors MSH header fields, swaps sender/receiver,
/// emits a single MSA segment with `AA` (Application Accept).
///
/// Returns the bytes the caller MUST then MLLP-frame.
pub fn build_ack(adt: &AdtA01<'_>) -> Result<Vec<u8>, AdtError> {
    let m = adt.message;
    let sending_app = m.msh_field(3).unwrap_or("");
    let sending_facility = m.msh_field(4).unwrap_or("");
    let receiving_app = m.msh_field(5).unwrap_or("");
    let receiving_facility = m.msh_field(6).unwrap_or("");
    let timestamp = m.msh_field(7).unwrap_or("");
    let control_id = adt.message_control_id().unwrap_or("");
    let processing_id = m.msh_field(11).unwrap_or("P");
    let version_id = m.msh_field(12).unwrap_or("2.5");

    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(b"MSH|^~\\&|");
    // Swap sender/receiver — the ACK comes back the other way.
    out.extend_from_slice(receiving_app.as_bytes());
    out.push(b'|');
    out.extend_from_slice(receiving_facility.as_bytes());
    out.push(b'|');
    out.extend_from_slice(sending_app.as_bytes());
    out.push(b'|');
    out.extend_from_slice(sending_facility.as_bytes());
    out.push(b'|');
    out.extend_from_slice(timestamp.as_bytes());
    out.extend_from_slice(b"||ACK^A01|");
    out.extend_from_slice(control_id.as_bytes());
    out.push(b'|');
    out.extend_from_slice(processing_id.as_bytes());
    out.push(b'|');
    out.extend_from_slice(version_id.as_bytes());
    out.push(b'\r');
    // MSA segment — `AA` means Application Accept.
    out.extend_from_slice(b"MSA|AA|");
    out.extend_from_slice(control_id.as_bytes());
    out.push(b'\r');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    const SAMPLE_ADT_A01: &[u8] = b"MSH|^~\\&|ADT1|GOOD HEALTH HOSPITAL|GHH LAB, INC.|GOOD HEALTH HOSPITAL|20260315093015||ADT^A01^ADT_A01|MSG00001|P|2.5\rEVN|A01|20260315093015\rPID|1||PATID1234^5^M11^ADT1^MR||SMITH^ALICE^M||19800512|F\rPV1|1|I|2000^2012^01|||||||SUR||||ADM|A0\r";

    fn parse_sample() -> crate::Message {
        parse(SAMPLE_ADT_A01).unwrap()
    }

    #[test]
    fn typed_accessors_for_adt_a01() {
        let msg = parse_sample();
        let adt = AdtA01::from_message(&msg).unwrap();

        assert_eq!(adt.event_code(), Some("A01"));
        assert_eq!(adt.event_recorded_at(), Some("20260315093015"));

        assert_eq!(adt.patient_id(), Some("PATID1234"));
        assert_eq!(adt.patient_id_type(), Some("MR"));

        assert_eq!(adt.family_name(), Some("SMITH"));
        assert_eq!(adt.given_name(), Some("ALICE"));
        assert_eq!(adt.middle_name(), Some("M"));

        assert_eq!(adt.date_of_birth(), Some("19800512"));
        assert_eq!(adt.gender(), Some("F"));

        assert_eq!(adt.patient_class(), Some("I"));
        assert_eq!(adt.assigned_ward(), Some("2000"));
        assert_eq!(adt.assigned_room(), Some("2012"));

        assert_eq!(adt.message_control_id(), Some("MSG00001"));
    }

    #[test]
    fn rejects_non_adt_message() {
        let raw = b"MSH|^~\\&|S|F|R|RF|20260315||ORU^R01|M1|P|2.5\rPID|1||X||SMITH^ALICE\rPV1|1|O|||\r";
        let msg = parse(raw).unwrap();
        let err = AdtA01::from_message(&msg).unwrap_err();
        assert!(matches!(
            err,
            AdtError::NotAdtA01 { message_type, trigger }
                if message_type == "ORU" && trigger == "R01"
        ));
    }

    #[test]
    fn ack_swaps_sender_and_receiver_and_uses_msa_aa() {
        let msg = parse_sample();
        let adt = AdtA01::from_message(&msg).unwrap();
        let ack = build_ack(&adt).unwrap();
        let s = std::str::from_utf8(&ack).unwrap();
        // Original sender becomes ACK receiver and vice versa.
        assert!(s.contains("|GHH LAB, INC.|GOOD HEALTH HOSPITAL|ADT1|GOOD HEALTH HOSPITAL|"));
        // MSA with control id.
        assert!(s.contains("MSA|AA|MSG00001"));
        // Same control id is echoed in MSH-10.
        assert!(s.contains("|ACK^A01|MSG00001|"));
    }
}
