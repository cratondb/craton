//! Projection row types — the SQL-queryable surface of each FHIR
//! resource stream.
//!
//! Every typed FHIR resource projects to a flat row of indexed
//! columns. The Kimberlite SQL layer materialises these rows in
//! tables named `fhir_patient`, `fhir_observation`, etc., letting
//! callers run plain SQL `SELECT * WHERE family_name = 'Smith'`
//! without dragging the full canonical JSON through the executor.
//!
//! ## Column choices
//!
//! Indexed columns are the fields a SMART on FHIR client searches by
//! most often, per the US Core search-parameter set:
//!
//! - **Patient**: `family`, `given`, `birthdate`, `gender`, `identifier`
//! - **Practitioner**: `family`, `given`, `npi`
//! - **Organization**: `name`, `identifier`
//! - **Encounter**: `status`, `class`, `subject`, `period_start`
//! - **Observation**: `status`, `code`, `subject`, `effective_time`
//!
//! Fields not in this set still survive — they're in the canonical
//! JSON the event carries — but they're not search-indexed in v1.

use kimberlite_fhir::resources::{Encounter, Observation, Organization, Patient, Practitioner};
use serde::{Deserialize, Serialize};

/// Common trait every projection row type implements. Lets the
/// projector / SQL materialiser treat them uniformly.
pub trait Projection: Serialize + for<'de> Deserialize<'de> + Sized {
    /// Source resource type (`Patient`, `Encounter`, …) — pairs with
    /// the SQL table name `fhir_<lowercase>`.
    const RESOURCE_TYPE: &'static str;

    /// Suggested SQL table name. Convention: `fhir_` + lowercase
    /// resource type. Override if the resource clashes with a SQL
    /// reserved word.
    fn table_name() -> String {
        format!("fhir_{}", Self::RESOURCE_TYPE.to_lowercase())
    }

    /// The logical FHIR `id` — primary key of the projection row.
    fn id(&self) -> &str;
}

// ============================================================================
// Patient projection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatientProjection {
    pub id: String,
    /// `HumanName.family` from the first name entry (the "official"
    /// name in FHIR ordering convention).
    pub family_name: Option<String>,
    /// `HumanName.given` joined by `' '` — preserves the FHIR
    /// ordering semantic where the first given is the primary one.
    pub given_names: Option<String>,
    pub birth_date: Option<String>,
    pub gender: Option<String>,
    /// First identifier `value` if any. The full identifier list is
    /// in the canonical JSON; this column is for search.
    pub primary_identifier: Option<String>,
    /// Identifier `system` paired with `primary_identifier`.
    pub primary_identifier_system: Option<String>,
}

impl Projection for PatientProjection {
    const RESOURCE_TYPE: &'static str = "Patient";

    fn id(&self) -> &str {
        &self.id
    }
}

impl PatientProjection {
    pub fn from_resource(p: &Patient) -> Option<Self> {
        let id = p.id.clone()?;
        let first_name = p.name.first();
        let first_identifier = p.identifier.first();
        Some(Self {
            id,
            family_name: first_name.and_then(|n| n.family.clone()),
            given_names: first_name.map(|n| n.given.join(" ")).filter(|s| !s.is_empty()),
            birth_date: p.birth_date.clone(),
            gender: p.gender.map(|g| format!("{g:?}").to_lowercase()),
            primary_identifier: first_identifier.and_then(|i| i.value.clone()),
            primary_identifier_system: first_identifier.and_then(|i| i.system.clone()),
        })
    }
}

// ============================================================================
// Practitioner projection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PractitionerProjection {
    pub id: String,
    pub family_name: Option<String>,
    pub given_names: Option<String>,
    /// US NPI — identifier with system
    /// `http://hl7.org/fhir/sid/us-npi`, if present.
    pub npi: Option<String>,
}

impl Projection for PractitionerProjection {
    const RESOURCE_TYPE: &'static str = "Practitioner";

    fn id(&self) -> &str {
        &self.id
    }
}

impl PractitionerProjection {
    pub fn from_resource(p: &Practitioner) -> Option<Self> {
        let id = p.id.clone()?;
        let first_name = p.name.first();
        let npi = p
            .identifier
            .iter()
            .find(|i| i.system.as_deref() == Some("http://hl7.org/fhir/sid/us-npi"))
            .and_then(|i| i.value.clone());
        Some(Self {
            id,
            family_name: first_name.and_then(|n| n.family.clone()),
            given_names: first_name.map(|n| n.given.join(" ")).filter(|s| !s.is_empty()),
            npi,
        })
    }
}

// ============================================================================
// Organization projection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrganizationProjection {
    pub id: String,
    pub name: Option<String>,
    pub primary_identifier: Option<String>,
    pub primary_identifier_system: Option<String>,
}

impl Projection for OrganizationProjection {
    const RESOURCE_TYPE: &'static str = "Organization";

    fn id(&self) -> &str {
        &self.id
    }
}

impl OrganizationProjection {
    pub fn from_resource(o: &Organization) -> Option<Self> {
        let id = o.id.clone()?;
        let first_identifier = o.identifier.first();
        Some(Self {
            id,
            name: o.name.clone(),
            primary_identifier: first_identifier.and_then(|i| i.value.clone()),
            primary_identifier_system: first_identifier.and_then(|i| i.system.clone()),
        })
    }
}

// ============================================================================
// Encounter projection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncounterProjection {
    pub id: String,
    pub status: Option<String>,
    /// `Encounter.class.code` — `IMP`, `AMB`, `EMER`, etc.
    pub class_code: Option<String>,
    /// `Encounter.subject.reference` — `"Patient/<id>"`.
    pub subject_ref: Option<String>,
    /// `Encounter.period.start`, the start of the visit.
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

impl Projection for EncounterProjection {
    const RESOURCE_TYPE: &'static str = "Encounter";

    fn id(&self) -> &str {
        &self.id
    }
}

impl EncounterProjection {
    pub fn from_resource(e: &Encounter) -> Option<Self> {
        let id = e.id.clone()?;
        Some(Self {
            id,
            status: e.status.clone(),
            class_code: e.class.as_ref().and_then(|c| c.code.clone()),
            subject_ref: e.subject.as_ref().and_then(|r| r.reference.clone()),
            period_start: e.period.as_ref().and_then(|p| p.start.clone()),
            period_end: e.period.as_ref().and_then(|p| p.end.clone()),
        })
    }
}

// ============================================================================
// Observation projection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationProjection {
    pub id: String,
    pub status: String,
    /// First coding's code (LOINC code, typically).
    pub code: Option<String>,
    /// First coding's system (e.g. `http://loinc.org`).
    pub code_system: Option<String>,
    pub subject_ref: Option<String>,
    pub effective_date_time: Option<String>,
    /// For numeric observations, the unit and value flattened for
    /// search (`value=72.5 unit=kg`).
    pub value_numeric: Option<f64>,
    pub value_unit: Option<String>,
    /// For string observations.
    pub value_string: Option<String>,
}

impl Projection for ObservationProjection {
    const RESOURCE_TYPE: &'static str = "Observation";

    fn id(&self) -> &str {
        &self.id
    }
}

impl ObservationProjection {
    pub fn from_resource(o: &Observation) -> Option<Self> {
        use kimberlite_fhir::resources::ObservationValue;
        let id = o.id.clone()?;
        let first_coding = o.code.coding.first();
        let (value_numeric, value_unit, value_string) = match &o.value {
            Some(ObservationValue::Quantity(q)) => (q.value, q.unit.clone(), None),
            Some(ObservationValue::String(s)) => (None, None, Some(s.clone())),
            Some(ObservationValue::CodeableConcept(c)) => (None, None, c.text.clone()),
            Some(ObservationValue::Boolean(b)) => {
                (None, None, Some(b.to_string()))
            }
            Some(ObservationValue::Integer(i)) => {
                (Some(*i as f64), None, None)
            }
            None => (None, None, None),
        };
        Some(Self {
            id,
            status: format!("{:?}", o.status).to_lowercase(),
            code: first_coding.and_then(|c| c.code.clone()),
            code_system: first_coding.and_then(|c| c.system.clone()),
            subject_ref: o.subject.as_ref().and_then(|r| r.reference.clone()),
            effective_date_time: o.effective_date_time.clone(),
            value_numeric,
            value_unit,
            value_string,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kimberlite_fhir::datatypes::{CodeableConcept, Coding, HumanName, Identifier, Quantity, Reference};
    use kimberlite_fhir::resources::{ObservationStatus, ObservationValue, PatientGender};

    #[test]
    fn patient_projection_indexes_name_and_birthdate() {
        let p = Patient {
            id: Some("p1".into()),
            name: vec![HumanName {
                family: Some("Smith".into()),
                given: vec!["Alice".into(), "M.".into()],
                ..Default::default()
            }],
            birth_date: Some("1980-05-12".into()),
            gender: Some(PatientGender::Female),
            identifier: vec![Identifier {
                system: Some("http://hospital.example.org/mrn".into()),
                value: Some("MRN-12345".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let proj = PatientProjection::from_resource(&p).unwrap();
        assert_eq!(proj.id, "p1");
        assert_eq!(proj.family_name.as_deref(), Some("Smith"));
        assert_eq!(proj.given_names.as_deref(), Some("Alice M."));
        assert_eq!(proj.birth_date.as_deref(), Some("1980-05-12"));
        assert_eq!(proj.gender.as_deref(), Some("female"));
        assert_eq!(proj.primary_identifier.as_deref(), Some("MRN-12345"));
        assert_eq!(
            proj.primary_identifier_system.as_deref(),
            Some("http://hospital.example.org/mrn")
        );
    }

    #[test]
    fn patient_without_id_does_not_project() {
        let p = Patient {
            id: None,
            ..Default::default()
        };
        assert!(PatientProjection::from_resource(&p).is_none());
    }

    #[test]
    fn practitioner_extracts_npi_specifically() {
        let pr = Practitioner {
            id: Some("dr1".into()),
            name: vec![HumanName {
                family: Some("Jones".into()),
                ..Default::default()
            }],
            identifier: vec![
                Identifier {
                    system: Some("http://hospital.example.org/badge".into()),
                    value: Some("BADGE-9".into()),
                    ..Default::default()
                },
                Identifier {
                    system: Some("http://hl7.org/fhir/sid/us-npi".into()),
                    value: Some("1234567890".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let proj = PractitionerProjection::from_resource(&pr).unwrap();
        assert_eq!(proj.npi.as_deref(), Some("1234567890"));
    }

    #[test]
    fn encounter_extracts_class_code_and_subject() {
        let e = Encounter {
            id: Some("e1".into()),
            status: Some("finished".into()),
            class: Some(Coding {
                code: Some("AMB".into()),
                system: Some("http://terminology.hl7.org/CodeSystem/v3-ActCode".into()),
                ..Default::default()
            }),
            subject: Some(Reference::literal("Patient", "p1")),
            ..Default::default()
        };
        let proj = EncounterProjection::from_resource(&e).unwrap();
        assert_eq!(proj.class_code.as_deref(), Some("AMB"));
        assert_eq!(proj.subject_ref.as_deref(), Some("Patient/p1"));
    }

    #[test]
    fn observation_quantity_extracts_numeric_and_unit() {
        let o = Observation {
            id: Some("o1".into()),
            status: ObservationStatus::Final,
            code: CodeableConcept {
                coding: vec![Coding {
                    system: Some("http://loinc.org".into()),
                    code: Some("29463-7".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            subject: Some(Reference::literal("Patient", "p1")),
            effective_date_time: Some("2026-03-15T09:15:00Z".into()),
            value: Some(ObservationValue::Quantity(Quantity {
                value: Some(72.5),
                unit: Some("kg".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let proj = ObservationProjection::from_resource(&o).unwrap();
        assert_eq!(proj.code.as_deref(), Some("29463-7"));
        assert_eq!(proj.code_system.as_deref(), Some("http://loinc.org"));
        assert_eq!(proj.value_numeric, Some(72.5));
        assert_eq!(proj.value_unit.as_deref(), Some("kg"));
        assert_eq!(proj.status, "final");
    }

    #[test]
    fn observation_string_value_routes_to_value_string_column() {
        let o = Observation {
            id: Some("o2".into()),
            status: ObservationStatus::Final,
            code: CodeableConcept::default(),
            value: Some(ObservationValue::String("normal sinus rhythm".into())),
            ..Default::default()
        };
        let proj = ObservationProjection::from_resource(&o).unwrap();
        assert_eq!(
            proj.value_string.as_deref(),
            Some("normal sinus rhythm")
        );
        assert!(proj.value_numeric.is_none());
    }

    #[test]
    fn table_name_is_snake_cased() {
        assert_eq!(PatientProjection::table_name(), "fhir_patient");
        assert_eq!(EncounterProjection::table_name(), "fhir_encounter");
        assert_eq!(ObservationProjection::table_name(), "fhir_observation");
    }
}
