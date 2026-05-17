//! 835 — Healthcare Claim Payment / Advice. Issued by payers as the
//! adjudicated response to an 837. Carries the payment total, the
//! per-claim allowed / paid / patient-responsibility split, and the
//! claim-adjustment-reason codes that explain the math.

use crate::envelope::{Interchange, TransactionSet};
use crate::segment::Segment;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Remittance<'a> {
    pub transaction: &'a TransactionSet,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemittanceError {
    #[error("transaction is not an 835 (ST01 = {0:?})")]
    NotARemittance(Option<String>),

    #[error("required BPR (Financial Information) segment is missing")]
    MissingBpr,
}

impl<'a> Remittance<'a> {
    pub fn from_transaction(tx: &'a TransactionSet) -> Result<Self, RemittanceError> {
        if tx.transaction_type() != Some("835") {
            return Err(RemittanceError::NotARemittance(
                tx.transaction_type().map(str::to_owned),
            ));
        }
        if tx.first_segment("BPR").is_none() {
            return Err(RemittanceError::MissingBpr);
        }
        Ok(Self { transaction: tx })
    }

    /// Financial Information segment (BPR) — present once per
    /// remittance and carries the bulk payment metadata.
    pub fn bpr(&self) -> Option<&Segment> {
        self.transaction.first_segment("BPR")
    }

    /// Total paid amount declared by the payer (`BPR02`).
    pub fn total_paid_amount(&self) -> Option<&str> {
        self.bpr().and_then(|s| s.text(2))
    }

    /// Credit/Debit flag (`BPR03`). `"C"` = credit (most common,
    /// payer paying provider), `"D"` = debit (recoupment).
    pub fn credit_debit(&self) -> Option<&str> {
        self.bpr().and_then(|s| s.text(3))
    }

    /// Payment method code (`BPR04`). `"ACH"` (electronic),
    /// `"CHK"` (paper check), `"NON"` (no payment — claim denied),
    /// etc.
    pub fn payment_method(&self) -> Option<&str> {
        self.bpr().and_then(|s| s.text(4))
    }

    /// Walk every CLP (Claim Payment Information) segment in the
    /// remittance. One per claim being adjudicated.
    pub fn claim_payments(&self) -> impl Iterator<Item = &Segment> {
        self.transaction.segments_by_id("CLP")
    }
}

/// Find every 835 transaction in an interchange.
pub fn remittances_in(
    interchange: &Interchange,
) -> impl Iterator<Item = Result<Remittance<'_>, RemittanceError>> {
    interchange
        .transactions()
        .filter(|tx| tx.transaction_type() == Some("835"))
        .map(Remittance::from_transaction)
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn minimal_835() -> Vec<u8> {
        let isa = "ISA*00*          *00*          *ZZ*PAYERID        *ZZ*PROVIDERID     \
                   *240102*1000*^*00501*000000002*0*P*:~";
        let gs = "GS*HP*PAYERAPP*PROVIDERAPP*20240102*1000*2*X*005010X221A1~";
        let st = "ST*835*0001~";
        let bpr = "BPR*I*1500.00*C*ACH*CTX*01*999999992*DA*123456789*1234567890**01*999999991*DA*987654321*20240102~";
        let clp = "CLP*CLAIM-001*1*200.00*150.00*50.00*MC*PAYER-REF-1~";
        let se = "SE*4*0001~";
        let ge = "GE*1*2~";
        let iea = "IEA*1*000000002~";
        format!("{isa}{gs}{st}{bpr}{clp}{se}{ge}{iea}").into_bytes()
    }

    #[test]
    fn parses_835_envelope() {
        let bytes = minimal_835();
        let interchange = parse(&bytes).unwrap();
        let rem = remittances_in(&interchange).next().unwrap().unwrap();
        assert_eq!(rem.total_paid_amount(), Some("1500.00"));
        assert_eq!(rem.credit_debit(), Some("C"));
        assert_eq!(rem.payment_method(), Some("ACH"));
        assert_eq!(rem.claim_payments().count(), 1);
    }

    #[test]
    fn rejects_non_835() {
        let isa = "ISA*00*          *00*          *ZZ*A              *ZZ*B              \
                   *240101*0900*^*00501*000000001*0*P*:~";
        let gs = "GS*HC*X*Y*20240101*0900*1*X*005010X222A1~";
        let st = "ST*837*0001*005010X222A1~";
        let bht = "BHT*0019*00*REF*20240101*0900*CH~";
        let se = "SE*3*0001~";
        let ge = "GE*1*1~";
        let iea = "IEA*1*000000001~";
        let bytes = format!("{isa}{gs}{st}{bht}{se}{ge}{iea}").into_bytes();
        let interchange = parse(&bytes).unwrap();
        let tx = interchange.transactions().next().unwrap();
        let err = Remittance::from_transaction(tx).unwrap_err();
        assert!(matches!(err, RemittanceError::NotARemittance(_)));
    }
}
