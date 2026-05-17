//! Purpose limitation for personal data processing.
//!
//! Two regimes share this surface:
//!
//! - **HIPAA TPO + extensions** — `Treatment`, `Payment`, `Operations`,
//!   `PublicHealth`, `Emergency`. The canonical purposes a PHI access
//!   request can be tagged with at query time (45 CFR § 164.502, § 164.506,
//!   § 164.512). Healthcare purpose-of-use enforcement gates queries
//!   on these variants.
//! - **GDPR Article 6** — `Marketing`, `Analytics`, `Contractual`,
//!   `LegalObligation`, `VitalInterests`, `PublicTask`, `Research`,
//!   `Security`. Lawful-basis tracking for international healthcare /
//!   non-PHI personal data.
//!
//! # GDPR Requirements
//!
//! **Article 6**: Processing must have lawful basis (consent, contract, legal obligation, etc.)
//! **Article 5(1)(b)**: Purpose limitation - data collected for specified, explicit purposes
//! **Article 5(1)(c)**: Data minimization - adequate, relevant, limited to what's necessary
//!
//! # Architecture
//!
//! ```text
//! Purpose = {
//!     Marketing,           // Article 6(1)(a) - Consent required
//!     Analytics,           // Article 6(1)(f) - Legitimate interest
//!     Contractual,         // Article 6(1)(b) - Contract performance
//!     LegalObligation,     // Article 6(1)(c) - Legal requirement
//!     VitalInterests,      // Article 6(1)(d) - Life or death
//!     PublicTask,          // Article 6(1)(e) - Public interest
//! }
//! ```
//!
//! # Example
//!
//! ```
//! use kimberlite_compliance::purpose::Purpose;
//! use kimberlite_compliance::classification::DataClass;
//!
//! // Validate purpose for data class
//! assert!(Purpose::Marketing.requires_consent());
//! assert!(!Purpose::Contractual.requires_consent());
//!
//! // Check if purpose allows processing
//! assert!(Purpose::Marketing.is_valid_for(DataClass::PII));
//! assert!(!Purpose::Marketing.is_valid_for(DataClass::PHI)); // Healthcare needs stricter rules
//! ```

#![allow(clippy::match_same_arms)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::classification::DataClass;

#[derive(Debug, Error)]
pub enum PurposeError {
    #[error("Purpose {0:?} requires consent but none provided")]
    ConsentRequired(Purpose),

    #[error("Purpose {0:?} is invalid for data class {1:?}")]
    InvalidForDataClass(Purpose, DataClass),

    #[error("Purpose {0:?} conflicts with data minimization principle")]
    DataMinimizationViolation(Purpose),

    #[error("Purpose not specified")]
    Unspecified,
}

pub type Result<T> = std::result::Result<T, PurposeError>;

/// Lawful basis for data processing (GDPR Article 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Purpose {
    /// Marketing, advertising, promotional communications
    /// **Lawful basis:** Article 6(1)(a) - Consent
    Marketing,

    /// Usage analytics, performance monitoring, product improvement
    /// **Lawful basis:** Article 6(1)(f) - Legitimate interest
    Analytics,

    /// Contract performance (e.g., fulfilling orders, providing services)
    /// **Lawful basis:** Article 6(1)(b) - Contract
    Contractual,

    /// Compliance with legal obligation (e.g., tax reporting, law enforcement)
    /// **Lawful basis:** Article 6(1)(c) - Legal obligation
    LegalObligation,

    /// Vital interests (life or death situations)
    /// **Lawful basis:** Article 6(1)(d) - Vital interests
    VitalInterests,

    /// Public task or official authority
    /// **Lawful basis:** Article 6(1)(e) - Public task
    PublicTask,

    /// Research (scientific, historical, statistical)
    /// **Lawful basis:** Article 6(1)(f) or Article 9(2)(j) for special categories
    Research,

    /// Fraud prevention and security
    /// **Lawful basis:** Article 6(1)(f) - Legitimate interest
    Security,

    // ========================================================================
    // HIPAA TPO + extensions (45 CFR § 164.506, § 164.512)
    // ========================================================================
    /// Direct patient care — examination, diagnosis, prescription, referral.
    /// **HIPAA basis:** § 164.506(c)(2) — Treatment (T of TPO).
    /// **Consent:** Not required for TPO; covered by the NPP.
    Treatment,

    /// Billing, claims adjudication, reimbursement, eligibility — RCM and payer
    /// workflows.
    /// **HIPAA basis:** § 164.506(c)(3) — Payment (P of TPO).
    Payment,

    /// Quality improvement, credentialing, training, accreditation, business
    /// management.
    /// **HIPAA basis:** § 164.506(c)(4) — Health-care Operations (O of TPO).
    Operations,

    /// Public-health surveillance, reportable disease notification, vital
    /// statistics, FDA adverse-event reporting.
    /// **HIPAA basis:** § 164.512(b) — Uses and disclosures for public-health
    /// activities.
    PublicHealth,

    /// Emergency treatment when consent cannot reasonably be obtained — the
    /// break-glass purpose. Pairs with the `BreakGlassActivated` audit event.
    /// **HIPAA basis:** § 164.510(b)(3) — Emergency situations / § 164.512(j)
    /// (avert serious threat).
    Emergency,
}

impl Purpose {
    /// Check if this purpose requires explicit consent (GDPR Article 7 / HIPAA Authorization).
    ///
    /// HIPAA TPO (Treatment/Payment/Operations) does NOT require separate
    /// consent — it is covered by the Notice of Privacy Practices. Public
    /// health and emergency uses are explicitly exempted from authorization.
    pub fn requires_consent(&self) -> bool {
        matches!(self, Purpose::Marketing | Purpose::Research)
    }

    /// Whether this purpose is one of the HIPAA TPO categories or its
    /// healthcare extensions. Healthcare purpose-of-use enforcement at
    /// query time should constrain to this set when the stream is `PHI`.
    pub fn is_healthcare(&self) -> bool {
        matches!(
            self,
            Purpose::Treatment
                | Purpose::Payment
                | Purpose::Operations
                | Purpose::PublicHealth
                | Purpose::Emergency
        )
    }

    /// Check if this purpose is valid for a given data class
    pub fn is_valid_for(&self, data_class: DataClass) -> bool {
        match (self, data_class) {
            // PHI (Protected Health Information) - HIPAA restricted
            (Purpose::Marketing, DataClass::PHI) => false, // Cannot market with PHI
            (Purpose::Analytics, DataClass::PHI) => false, // Cannot analyze PHI without specific consent
            (Purpose::Research, DataClass::PHI) => true,   // Allowed with IRB approval
            (Purpose::Contractual, DataClass::PHI) => true, // Healthcare delivery
            (Purpose::LegalObligation, DataClass::PHI) => true, // Reporting requirements
            (Purpose::VitalInterests, DataClass::PHI) => true, // Medical emergencies
            (Purpose::Security, DataClass::PHI) => true,   // Fraud prevention
            // HIPAA TPO + extensions are the canonical PHI purposes
            (Purpose::Treatment, DataClass::PHI) => true,
            (Purpose::Payment, DataClass::PHI) => true,
            (Purpose::Operations, DataClass::PHI) => true,
            (Purpose::PublicHealth, DataClass::PHI) => true,
            (Purpose::Emergency, DataClass::PHI) => true,

            // Deidentified data - Less restrictive
            (_, DataClass::Deidentified) => true,

            // PII (Personally Identifiable Information) - GDPR regulated
            (Purpose::Marketing, DataClass::PII) => true, // With consent
            (Purpose::Analytics, DataClass::PII) => true, // Legitimate interest
            (Purpose::Contractual, DataClass::PII) => true, // Contract performance
            (Purpose::LegalObligation, DataClass::PII) => true,
            (Purpose::VitalInterests, DataClass::PII) => true,
            (Purpose::PublicTask, DataClass::PII) => true,
            (Purpose::Research, DataClass::PII) => true, // With consent
            (Purpose::Security, DataClass::PII) => true,

            // Sensitive PII (GDPR Article 9 special categories)
            (Purpose::Marketing, DataClass::Sensitive) => false, // Cannot market with sensitive data
            (Purpose::Analytics, DataClass::Sensitive) => false, // Restricted
            (Purpose::Contractual, DataClass::Sensitive) => true, // If necessary for contract
            (Purpose::LegalObligation, DataClass::Sensitive) => true,
            (Purpose::VitalInterests, DataClass::Sensitive) => true,
            (Purpose::PublicTask, DataClass::Sensitive) => true,
            (Purpose::Research, DataClass::Sensitive) => true, // Article 9(2)(j)
            (Purpose::Security, DataClass::Sensitive) => true,

            // PCI (Payment Card Information)
            (Purpose::Marketing, DataClass::PCI) => false, // PCI DSS forbids marketing use
            (Purpose::Analytics, DataClass::PCI) => false, // Restricted
            (Purpose::Contractual, DataClass::PCI) => true, // Payment processing only
            (Purpose::LegalObligation, DataClass::PCI) => true, // Fraud reporting
            (Purpose::Security, DataClass::PCI) => true,   // Fraud prevention
            (_, DataClass::PCI) => false,

            // Financial data (SOX, GLBA)
            (Purpose::Marketing, DataClass::Financial) => false,
            (Purpose::Analytics, DataClass::Financial) => true, // Internal analytics OK
            (Purpose::Contractual, DataClass::Financial) => true,
            (Purpose::LegalObligation, DataClass::Financial) => true,
            (Purpose::Security, DataClass::Financial) => true,
            (_, DataClass::Financial) => false,

            // Confidential business data
            (Purpose::Contractual, DataClass::Confidential) => true,
            (Purpose::LegalObligation, DataClass::Confidential) => true,
            (Purpose::Security, DataClass::Confidential) => true,
            (_, DataClass::Confidential) => false,

            // Public data - No restrictions
            (_, DataClass::Public) => true,

            // PublicTask only valid for government/public entities
            (Purpose::PublicTask, _) => true,

            // Healthcare TPO + extensions — only PII / Sensitive remain
            // (PHI explicit above; PCI/Financial/Confidential/Public
            // already caught by their class-wide arms). All HIPAA
            // purposes are allowed on non-PHI patient data: billing
            // addresses (Payment + PII), genetic data in research
            // (Operations + Sensitive), etc.
            (
                Purpose::Treatment
                | Purpose::Payment
                | Purpose::Operations
                | Purpose::PublicHealth
                | Purpose::Emergency,
                _,
            ) => true,
        }
    }

    /// Get the GDPR Article 6 lawful basis or HIPAA section for healthcare purposes.
    pub fn lawful_basis(&self) -> &'static str {
        match self {
            Purpose::Marketing => "Article 6(1)(a) - Consent",
            Purpose::Analytics => "Article 6(1)(f) - Legitimate interest",
            Purpose::Contractual => "Article 6(1)(b) - Contract",
            Purpose::LegalObligation => "Article 6(1)(c) - Legal obligation",
            Purpose::VitalInterests => "Article 6(1)(d) - Vital interests",
            Purpose::PublicTask => "Article 6(1)(e) - Public task",
            Purpose::Research => "Article 6(1)(f) or Article 9(2)(j) - Research",
            Purpose::Security => "Article 6(1)(f) - Legitimate interest",
            Purpose::Treatment => "HIPAA § 164.506(c)(2) - Treatment (TPO)",
            Purpose::Payment => "HIPAA § 164.506(c)(3) - Payment (TPO)",
            Purpose::Operations => "HIPAA § 164.506(c)(4) - Health-care Operations (TPO)",
            Purpose::PublicHealth => "HIPAA § 164.512(b) - Public-health activities",
            Purpose::Emergency => "HIPAA § 164.510(b)(3) / § 164.512(j) - Emergency",
        }
    }

    /// Check if purpose aligns with data minimization principle
    pub fn is_data_minimization_compliant(&self, data_class: DataClass) -> bool {
        match (self, data_class) {
            // Cannot use PHI/PCI/Sensitive for marketing/analytics
            (
                Purpose::Marketing | Purpose::Analytics,
                DataClass::PHI | DataClass::PCI | DataClass::Sensitive,
            ) => false,

            // Using confidential data for non-business purposes
            (Purpose::Marketing | Purpose::Analytics, DataClass::Confidential) => false,

            // Using financial data for marketing
            (Purpose::Marketing, DataClass::Financial) => false,

            // Everything else is OK
            _ => true,
        }
    }

    /// All valid purposes (GDPR + HIPAA TPO).
    pub fn all() -> &'static [Purpose] {
        &[
            Purpose::Marketing,
            Purpose::Analytics,
            Purpose::Contractual,
            Purpose::LegalObligation,
            Purpose::VitalInterests,
            Purpose::PublicTask,
            Purpose::Research,
            Purpose::Security,
            Purpose::Treatment,
            Purpose::Payment,
            Purpose::Operations,
            Purpose::PublicHealth,
            Purpose::Emergency,
        ]
    }
}

impl std::fmt::Display for Purpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Purpose::Marketing => write!(f, "Marketing"),
            Purpose::Analytics => write!(f, "Analytics"),
            Purpose::Contractual => write!(f, "Contractual"),
            Purpose::LegalObligation => write!(f, "Legal Obligation"),
            Purpose::VitalInterests => write!(f, "Vital Interests"),
            Purpose::PublicTask => write!(f, "Public Task"),
            Purpose::Research => write!(f, "Research"),
            Purpose::Security => write!(f, "Security"),
            Purpose::Treatment => write!(f, "Treatment"),
            Purpose::Payment => write!(f, "Payment"),
            Purpose::Operations => write!(f, "Operations"),
            Purpose::PublicHealth => write!(f, "Public Health"),
            Purpose::Emergency => write!(f, "Emergency"),
        }
    }
}

/// Validate that a purpose is appropriate for a data class
pub fn validate_purpose(data_class: DataClass, purpose: Purpose) -> Result<()> {
    if !purpose.is_valid_for(data_class) {
        return Err(PurposeError::InvalidForDataClass(purpose, data_class));
    }

    if !purpose.is_data_minimization_compliant(data_class) {
        return Err(PurposeError::DataMinimizationViolation(purpose));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_required() {
        assert!(Purpose::Marketing.requires_consent());
        assert!(Purpose::Research.requires_consent());
        assert!(!Purpose::Contractual.requires_consent());
        assert!(!Purpose::Analytics.requires_consent());
    }

    #[test]
    fn test_purpose_for_phi() {
        assert!(!Purpose::Marketing.is_valid_for(DataClass::PHI));
        assert!(!Purpose::Analytics.is_valid_for(DataClass::PHI));
        assert!(Purpose::Contractual.is_valid_for(DataClass::PHI));
        assert!(Purpose::VitalInterests.is_valid_for(DataClass::PHI));
    }

    #[test]
    fn test_purpose_for_pci() {
        assert!(!Purpose::Marketing.is_valid_for(DataClass::PCI));
        assert!(!Purpose::Analytics.is_valid_for(DataClass::PCI));
        assert!(Purpose::Contractual.is_valid_for(DataClass::PCI));
        assert!(Purpose::Security.is_valid_for(DataClass::PCI));
    }

    #[test]
    fn test_purpose_for_public() {
        // All purposes valid for public data
        for purpose in Purpose::all() {
            assert!(purpose.is_valid_for(DataClass::Public));
        }
    }

    #[test]
    fn test_data_minimization() {
        assert!(!Purpose::Marketing.is_data_minimization_compliant(DataClass::PHI));
        assert!(!Purpose::Analytics.is_data_minimization_compliant(DataClass::PCI));
        assert!(Purpose::Contractual.is_data_minimization_compliant(DataClass::PII));
        assert!(Purpose::Security.is_data_minimization_compliant(DataClass::Sensitive));
    }

    #[test]
    fn test_validate_purpose() {
        // Valid combinations
        assert!(validate_purpose(DataClass::PII, Purpose::Marketing).is_ok());
        assert!(validate_purpose(DataClass::PHI, Purpose::Contractual).is_ok());

        // Invalid combinations
        assert!(validate_purpose(DataClass::PHI, Purpose::Marketing).is_err());
        assert!(validate_purpose(DataClass::PCI, Purpose::Analytics).is_err());
    }

    #[test]
    fn test_lawful_basis() {
        assert_eq!(
            Purpose::Marketing.lawful_basis(),
            "Article 6(1)(a) - Consent"
        );
        assert_eq!(
            Purpose::Contractual.lawful_basis(),
            "Article 6(1)(b) - Contract"
        );
        assert_eq!(
            Purpose::LegalObligation.lawful_basis(),
            "Article 6(1)(c) - Legal obligation"
        );
    }

    #[test]
    fn test_all_purposes() {
        let purposes = Purpose::all();
        assert_eq!(purposes.len(), 13);
        assert!(purposes.contains(&Purpose::Marketing));
        assert!(purposes.contains(&Purpose::Security));
        assert!(purposes.contains(&Purpose::Treatment));
        assert!(purposes.contains(&Purpose::Emergency));
    }

    #[test]
    fn test_hipaa_tpo_for_phi() {
        for p in [
            Purpose::Treatment,
            Purpose::Payment,
            Purpose::Operations,
            Purpose::PublicHealth,
            Purpose::Emergency,
        ] {
            assert!(
                p.is_valid_for(DataClass::PHI),
                "{p:?} must be valid for PHI"
            );
            assert!(p.is_healthcare());
        }
    }

    #[test]
    fn test_hipaa_tpo_does_not_require_consent() {
        for p in [Purpose::Treatment, Purpose::Payment, Purpose::Operations] {
            assert!(
                !p.requires_consent(),
                "HIPAA TPO purpose {p:?} should not require separate consent"
            );
        }
    }

    #[test]
    fn test_payment_purpose_classes() {
        // Payment is valid for the PHI/PII classes a healthcare billing
        // workflow touches. Financial/Confidential are PCI/SOX/general
        // business classes and are blocked by their class-wide arms.
        assert!(Purpose::Payment.is_valid_for(DataClass::PHI));
        assert!(Purpose::Payment.is_valid_for(DataClass::PII));
        assert!(!Purpose::Payment.is_valid_for(DataClass::Financial));
        assert!(!Purpose::Payment.is_valid_for(DataClass::Confidential));
    }

    #[test]
    fn test_emergency_lawful_basis_is_hipaa() {
        assert!(Purpose::Emergency.lawful_basis().contains("HIPAA"));
        assert!(Purpose::Treatment.lawful_basis().contains("HIPAA"));
    }

    #[test]
    fn test_purpose_display() {
        assert_eq!(Purpose::Marketing.to_string(), "Marketing");
        assert_eq!(Purpose::LegalObligation.to_string(), "Legal Obligation");
    }

    #[test]
    fn test_sensitive_data_restrictions() {
        // Sensitive data (GDPR Article 9) has strict rules
        assert!(!Purpose::Marketing.is_valid_for(DataClass::Sensitive));
        assert!(!Purpose::Analytics.is_valid_for(DataClass::Sensitive));
        assert!(Purpose::Research.is_valid_for(DataClass::Sensitive)); // Article 9(2)(j)
        assert!(Purpose::VitalInterests.is_valid_for(DataClass::Sensitive));
    }

    #[test]
    fn test_financial_data_restrictions() {
        assert!(!Purpose::Marketing.is_valid_for(DataClass::Financial));
        assert!(Purpose::Analytics.is_valid_for(DataClass::Financial)); // Internal use OK
        assert!(Purpose::Contractual.is_valid_for(DataClass::Financial));
    }
}
