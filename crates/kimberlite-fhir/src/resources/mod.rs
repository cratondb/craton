//! FHIR R4 resource types — the wedge set.

pub mod bundle;
pub mod encounter;
pub mod observation;
pub mod organization;
pub mod patient;
pub mod practitioner;

pub use bundle::{Bundle, BundleEntry, BundleEntryRequest, BundleEntryResponse, BundleType};
pub use encounter::Encounter;
pub use observation::{Observation, ObservationStatus, ObservationValue};
pub use organization::Organization;
pub use patient::{Patient, PatientGender};
pub use practitioner::Practitioner;
