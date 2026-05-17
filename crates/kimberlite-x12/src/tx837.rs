//! 837 — Healthcare Claim. The wire format every U.S. claim submission
//! rides on. Recognises Professional (`837P`), Institutional
//! (`837I`), and Dental (`837D`) variants by their implementation
//! convention reference (`ST03`).

use crate::envelope::{Interchange, TransactionSet};
use thiserror::Error;

/// Which flavour of 837 this is. Determined by the implementation
/// convention reference declared on `ST03`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimFormat {
    /// 837P — Professional (physician services, ambulance, etc.).
    /// IG reference: `005010X222A1`.
    Professional,
    /// 837I — Institutional (hospital inpatient, outpatient, SNF).
    /// IG reference: `005010X223A2` (typical).
    Institutional,
    /// 837D — Dental claims.
    /// IG reference: `005010X224A2`.
    Dental,
    /// 837 of unrecognised flavour. The implementation convention
    /// string is preserved so the caller can route by full ID.
    Other,
}

impl ClaimFormat {
    fn from_implementation(s: &str) -> Self {
        if s.starts_with("005010X222") {
            Self::Professional
        } else if s.starts_with("005010X223") {
            Self::Institutional
        } else if s.starts_with("005010X224") {
            Self::Dental
        } else {
            Self::Other
        }
    }
}

/// A parsed 837 transaction set, typed as a claim.
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    pub format: ClaimFormat,
    pub implementation_convention: Option<String>,
    pub transaction: &'a TransactionSet,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClaimError {
    #[error("transaction is not an 837 (ST01 = {0:?})")]
    NotAClaim(Option<String>),

    #[error("transaction set declared {declared} segments but parser saw {actual}")]
    SegmentCountMismatch { declared: usize, actual: usize },
}

impl<'a> Claim<'a> {
    /// Wrap a generic transaction set as a typed 837 claim.
    pub fn from_transaction(tx: &'a TransactionSet) -> Result<Self, ClaimError> {
        if tx.transaction_type() != Some("837") {
            return Err(ClaimError::NotAClaim(
                tx.transaction_type().map(str::to_owned),
            ));
        }
        if let (Some(declared), actual) = (tx.declared_segment_count(), tx.actual_segment_count()) {
            if declared != actual {
                return Err(ClaimError::SegmentCountMismatch { declared, actual });
            }
        }
        let impl_conv = tx.implementation_convention().map(str::to_owned);
        let format = impl_conv
            .as_deref()
            .map_or(ClaimFormat::Other, ClaimFormat::from_implementation);
        Ok(Self {
            format,
            implementation_convention: impl_conv,
            transaction: tx,
        })
    }

    /// Find every claim header (`CLM`) segment in the transaction.
    /// 837 batches typically carry one claim per ST/SE pair, but the
    /// spec permits many.
    pub fn claim_headers(&self) -> impl Iterator<Item = &crate::segment::Segment> {
        self.transaction.segments_by_id("CLM")
    }

    /// Beginning of Hierarchical Transaction segment (`BHT03` is the
    /// submitter's reference identifier — the "claim batch ID" most
    /// clearinghouses surface in their UIs).
    pub fn submitter_batch_id(&self) -> Option<&str> {
        self.transaction
            .first_segment("BHT")
            .and_then(|s| s.text(3))
    }
}

/// Find every 837 transaction in an interchange, regardless of which
/// functional group it sits in. Convenience wrapper for callers that
/// ingest a mixed interchange and only care about claims.
pub fn claims_in(interchange: &Interchange) -> impl Iterator<Item = Result<Claim<'_>, ClaimError>> {
    interchange
        .transactions()
        .filter(|tx| tx.transaction_type() == Some("837"))
        .map(Claim::from_transaction)
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn minimal_837() -> Vec<u8> {
        let isa = "ISA*00*          *00*          *ZZ*SENDERID       *ZZ*RECEIVERID     \
                   *240101*0900*^*00501*000000001*0*P*:~";
        let gs = "GS*HC*SENDERAPP*RECEIVERAPP*20240101*0900*1*X*005010X222A1~";
        let st = "ST*837*0001*005010X222A1~";
        let bht = "BHT*0019*00*REF-1234*20240101*0900*CH~";
        let clm = "CLM*CLAIM-001*100.00***11:B:1*Y*A*Y*Y~";
        let se = "SE*4*0001~";
        let ge = "GE*1*1~";
        let iea = "IEA*1*000000001~";
        format!("{isa}{gs}{st}{bht}{clm}{se}{ge}{iea}").into_bytes()
    }

    #[test]
    fn recognises_837_professional() {
        let bytes = minimal_837();
        let interchange = parse(&bytes).unwrap();
        let claim = claims_in(&interchange).next().unwrap().unwrap();
        assert_eq!(claim.format, ClaimFormat::Professional);
        assert_eq!(claim.submitter_batch_id(), Some("REF-1234"));
        assert_eq!(claim.claim_headers().count(), 1);
    }

    #[test]
    fn rejects_non_837_transaction() {
        let bytes = include_bytes_835();
        let interchange = parse(&bytes).unwrap();
        let tx = interchange.transactions().next().unwrap();
        let err = Claim::from_transaction(tx).unwrap_err();
        assert!(matches!(err, ClaimError::NotAClaim(Some(ref t)) if t == "835"));
    }

    fn include_bytes_835() -> Vec<u8> {
        let isa = "ISA*00*          *00*          *ZZ*PAYERID        *ZZ*PROVIDERID     \
                   *240102*1000*^*00501*000000002*0*P*:~";
        let gs = "GS*HP*PAYERAPP*PROVIDERAPP*20240102*1000*2*X*005010X221A1~";
        let st = "ST*835*0001~";
        let bpr = "BPR*I*1500.00*C*ACH~";
        let se = "SE*3*0001~";
        let ge = "GE*1*2~";
        let iea = "IEA*1*000000002~";
        format!("{isa}{gs}{st}{bpr}{se}{ge}{iea}").into_bytes()
    }
}
