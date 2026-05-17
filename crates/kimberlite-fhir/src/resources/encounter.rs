//! FHIR R4 [Encounter](https://www.hl7.org/fhir/R4/encounter.html).

use serde::{Deserialize, Serialize};

use crate::datatypes::{CodeableConcept, Coding, Identifier, Meta, Period, Reference};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Encounter` — an interaction between a patient and one or
/// more healthcare providers, for the purpose of providing care.
///
/// `status` and `class` are REQUIRED by the FHIR R4 cardinality rules;
/// `subject` is required by US Core. We keep them `Option<_>` to
/// permit constructing partial Encounters during ingestion (a
/// triage note arriving before the full ADT message) and let callers
/// validate at the boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Encounter {
    #[serde(rename = "resourceType")]
    pub resource_type: EncounterResourceTag,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier: Vec<Identifier>,

    /// One of `planned | arrived | triaged | in-progress | onleave |
    /// finished | cancelled | entered-in-error | unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// FHIR `Encounter.class` — `IMP` (inpatient), `AMB` (ambulatory),
    /// `EMER` (emergency), etc. Modelled as a single `Coding` per the
    /// FHIR R4 spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<Coding>,

    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "type")]
    pub type_: Vec<CodeableConcept>,

    /// Reference to the Patient (or Group) the encounter is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Reference>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<Period>,

    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "reasonCode")]
    pub reason_code: Vec<CodeableConcept>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "serviceProvider")]
    pub service_provider: Option<Reference>,

    #[serde(flatten)]
    pub extras: FhirExtras,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum EncounterResourceTag {
    #[default]
    Encounter,
}

impl FhirResource for Encounter {
    const RESOURCE_TYPE: &'static str = "Encounter";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ambulatory_encounter() {
        let e = Encounter {
            id: Some("enc-001".into()),
            status: Some("finished".into()),
            class: Some(Coding {
                system: Some("http://terminology.hl7.org/CodeSystem/v3-ActCode".into()),
                code: Some("AMB".into()),
                display: Some("ambulatory".into()),
                ..Default::default()
            }),
            subject: Some(Reference::literal("Patient", "alice-001")),
            period: Some(Period {
                start: Some("2026-03-15T09:00:00Z".into()),
                end: Some("2026-03-15T09:30:00Z".into()),
            }),
            ..Default::default()
        };
        let bytes = e.to_json().unwrap();
        let parsed = Encounter::from_json(&bytes).unwrap();
        assert_eq!(e, parsed);
    }

    #[test]
    fn subject_reference_points_to_patient() {
        let raw = br#"{
            "resourceType": "Encounter",
            "id": "e1",
            "status": "in-progress",
            "subject": {"reference": "Patient/p1", "type": "Patient"}
        }"#;
        let e = Encounter::from_json(raw).unwrap();
        let subj = e.subject.as_ref().unwrap();
        assert_eq!(subj.reference.as_deref(), Some("Patient/p1"));
        assert_eq!(subj.type_.as_deref(), Some("Patient"));
    }
}
