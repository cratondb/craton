//! Stream naming convention + healthcare-first stream metadata.
//!
//! Every FHIR resource type gets its own stream per tenant:
//!
//! ```text
//! tenant 42, Patient resources       → "fhir.Patient.42"
//! tenant 42, Observation resources   → "fhir.Observation.42"
//! tenant 42, Bundle ingestion log    → "fhir.Bundle.42"
//! ```
//!
//! Streams are created with [`kimberlite_types::DataClass::PHI`] by
//! default (the healthcare-first default introduced in Sprint 2) and
//! retention is the HIPAA-derived 6-year policy from
//! [`kimberlite_compliance::retention::RetentionPolicy::from_data_class`].
//! Callers that need a non-PHI stream (e.g. a stream of de-identified
//! research extracts) must override explicitly.

use kimberlite_compliance::retention::RetentionPolicy;
use kimberlite_fhir::resource::FhirResource;
use kimberlite_fhir::resources::{Bundle, Encounter, Observation, Organization, Patient, Practitioner};
use kimberlite_types::DataClass;

/// The set of FHIR resource kinds this storage adapter supports.
///
/// This enum gives us exhaustive matching at compile-time, so adding
/// a new resource forces every site that switches on resource kind
/// to be updated. Extend in lock-step with [`kimberlite_fhir::resources`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FhirResourceKind {
    Patient,
    Practitioner,
    Organization,
    Encounter,
    Observation,
    Bundle,
}

impl FhirResourceKind {
    /// FHIR R4 `resourceType` string.
    pub fn as_resource_type(self) -> &'static str {
        match self {
            Self::Patient => Patient::RESOURCE_TYPE,
            Self::Practitioner => Practitioner::RESOURCE_TYPE,
            Self::Organization => Organization::RESOURCE_TYPE,
            Self::Encounter => Encounter::RESOURCE_TYPE,
            Self::Observation => Observation::RESOURCE_TYPE,
            Self::Bundle => Bundle::RESOURCE_TYPE,
        }
    }

    /// Parse a FHIR `resourceType` string into a `FhirResourceKind`.
    /// Returns `None` for resource types not supported by this adapter.
    pub fn from_resource_type(s: &str) -> Option<Self> {
        match s {
            "Patient" => Some(Self::Patient),
            "Practitioner" => Some(Self::Practitioner),
            "Organization" => Some(Self::Organization),
            "Encounter" => Some(Self::Encounter),
            "Observation" => Some(Self::Observation),
            "Bundle" => Some(Self::Bundle),
            _ => None,
        }
    }

    /// Default [`DataClass`] for a stream of this resource. All
    /// FHIR resource types in the wedge set carry PHI in practice
    /// — even `Practitioner` and `Organization` can hold provider
    /// identifiers (NPI) that are themselves PHI under
    /// `45 CFR § 164.514(b)` Safe Harbor identifier 18.
    pub fn default_data_class(self) -> DataClass {
        DataClass::PHI
    }
}

/// Logical stream name for a given (tenant, resource kind).
///
/// Returns a string of the form `"fhir.<ResourceType>.<tenant_id>"`.
/// The tenant is included so that listing all streams gives an
/// at-a-glance per-tenant inventory; the stream registry binds
/// names to numeric `StreamId`s separately.
pub fn fhir_stream_name(tenant_id: u64, kind: FhirResourceKind) -> String {
    format!("fhir.{}.{}", kind.as_resource_type(), tenant_id)
}

/// Default retention policy for a FHIR stream — HIPAA-aligned 6-year
/// minimum on PHI streams via the existing classification table.
pub fn fhir_stream_policy(kind: FhirResourceKind) -> RetentionPolicy {
    RetentionPolicy::from_data_class(kind.default_data_class())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_name_includes_resource_type_and_tenant() {
        assert_eq!(
            fhir_stream_name(42, FhirResourceKind::Patient),
            "fhir.Patient.42"
        );
        assert_eq!(
            fhir_stream_name(7001, FhirResourceKind::Observation),
            "fhir.Observation.7001"
        );
    }

    #[test]
    fn all_resource_kinds_default_to_phi() {
        for kind in [
            FhirResourceKind::Patient,
            FhirResourceKind::Practitioner,
            FhirResourceKind::Organization,
            FhirResourceKind::Encounter,
            FhirResourceKind::Observation,
            FhirResourceKind::Bundle,
        ] {
            assert_eq!(kind.default_data_class(), DataClass::PHI);
        }
    }

    #[test]
    fn resource_kind_round_trips_through_string() {
        for kind in [
            FhirResourceKind::Patient,
            FhirResourceKind::Practitioner,
            FhirResourceKind::Organization,
            FhirResourceKind::Encounter,
            FhirResourceKind::Observation,
            FhirResourceKind::Bundle,
        ] {
            let s = kind.as_resource_type();
            assert_eq!(FhirResourceKind::from_resource_type(s), Some(kind));
        }
    }

    #[test]
    fn unknown_resource_type_returns_none() {
        assert_eq!(FhirResourceKind::from_resource_type("DiagnosticReport"), None);
        assert_eq!(FhirResourceKind::from_resource_type(""), None);
    }

    #[test]
    fn fhir_stream_policy_inherits_phi_retention() {
        let p = fhir_stream_policy(FhirResourceKind::Patient);
        // HIPAA § 164.530 → 6 years = 2190 days, see
        // kimberlite-compliance/src/retention.rs and classification.rs.
        assert_eq!(p.min_retention_days, Some(2_190));
    }
}
