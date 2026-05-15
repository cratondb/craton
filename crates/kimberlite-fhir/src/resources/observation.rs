//! FHIR R4 [Observation](https://www.hl7.org/fhir/R4/observation.html).

use serde::{Deserialize, Serialize};

use crate::datatypes::{CodeableConcept, Identifier, Meta, Period, Quantity, Reference};
use crate::resource::{FhirExtras, FhirResource};

/// FHIR `Observation` — measurements and simple assertions about a
/// patient, device, or other subject (vital signs, lab results,
/// social history, clinical findings).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Observation {
    #[serde(rename = "resourceType")]
    pub resource_type: ObservationResourceTag,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier: Vec<Identifier>,

    pub status: ObservationStatus,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category: Vec<CodeableConcept>,

    /// REQUIRED — the kind of observation (LOINC code, etc.).
    pub code: CodeableConcept,

    /// REQUIRED — the patient (or other subject) of the observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Reference>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encounter: Option<Reference>,

    /// FHIR `effective[x]` — only `effectiveDateTime` and
    /// `effectivePeriod` are modelled here. Set at most one.
    #[serde(skip_serializing_if = "Option::is_none", rename = "effectiveDateTime")]
    pub effective_date_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "effectivePeriod")]
    pub effective_period: Option<Period>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued: Option<String>,

    /// FHIR `value[x]` — the actual measurement. Several types are
    /// permitted by the spec; the most common appear here.
    #[serde(flatten)]
    pub value: Option<ObservationValue>,

    #[serde(flatten)]
    pub extras: FhirExtras,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum ObservationResourceTag {
    #[default]
    Observation,
}

/// FHIR `Observation.status` — required cardinality 1..1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationStatus {
    Registered,
    Preliminary,
    #[default]
    Final,
    Amended,
    Corrected,
    Cancelled,
    EnteredInError,
    Unknown,
}

/// FHIR `Observation.value[x]` — the actual measurement, in one of
/// several legal shapes. Implemented as an externally-tagged enum so
/// it serialises as the single legal `valueQuantity` /
/// `valueCodeableConcept` / `valueString` / `valueBoolean` key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ObservationValue {
    #[serde(rename = "valueQuantity")]
    Quantity(Quantity),
    #[serde(rename = "valueCodeableConcept")]
    CodeableConcept(CodeableConcept),
    #[serde(rename = "valueString")]
    String(String),
    #[serde(rename = "valueBoolean")]
    Boolean(bool),
    #[serde(rename = "valueInteger")]
    Integer(i64),
}

impl FhirResource for Observation {
    const RESOURCE_TYPE: &'static str = "Observation";

    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datatypes::Coding;

    fn weight_obs() -> Observation {
        Observation {
            id: Some("obs-weight-001".into()),
            status: ObservationStatus::Final,
            code: CodeableConcept {
                coding: vec![Coding {
                    system: Some("http://loinc.org".into()),
                    code: Some("29463-7".into()),
                    display: Some("Body Weight".into()),
                    ..Default::default()
                }],
                text: Some("Body Weight".into()),
            },
            subject: Some(Reference::literal("Patient", "alice-001")),
            effective_date_time: Some("2026-03-15T09:15:00Z".into()),
            value: Some(ObservationValue::Quantity(Quantity {
                value: Some(72.5),
                unit: Some("kg".into()),
                system: Some("http://unitsofmeasure.org".into()),
                code: Some("kg".into()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn round_trip_quantity_value() {
        let o = weight_obs();
        let bytes = o.to_json().unwrap();
        let parsed = Observation::from_json(&bytes).unwrap();
        assert_eq!(o, parsed);
    }

    #[test]
    fn value_quantity_serialises_as_key() {
        let bytes = weight_obs().to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.get("valueQuantity").is_some());
        // The wrapper key from the Rust enum variant should NOT leak.
        assert!(v.get("value").is_none());
        assert!(v.get("Quantity").is_none());
    }

    #[test]
    fn value_boolean_round_trips() {
        let raw = br#"{
            "resourceType": "Observation",
            "status": "final",
            "code": {"text": "Asleep"},
            "valueBoolean": true
        }"#;
        let o = Observation::from_json(raw).unwrap();
        assert!(matches!(o.value, Some(ObservationValue::Boolean(true))));
        let re_emitted = o.to_json_string().unwrap();
        assert!(re_emitted.contains(r#""valueBoolean":true"#));
    }
}
