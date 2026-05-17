//! End-to-end tests across scope parsing + authorize() decision +
//! launch-context resolution. The decision-matrix test is the
//! contract the example app and the SDK will both lean on.

use super::context::{Action, LaunchContext};
use super::decision::{ScopeDecision, authorize};
use super::scope::SmartScopeSet;

fn ctx_with_patient(id: &str) -> LaunchContext {
    LaunchContext::for_patient(id)
}

#[test]
fn patient_scope_with_context_allows_with_constraint() {
    let scopes = SmartScopeSet::parse("patient/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Observation",
        Action::Read,
    );
    assert_eq!(
        dec,
        ScopeDecision::AllowWithPatientContext {
            patient_id: "alice-001".into()
        }
    );
}

#[test]
fn patient_scope_without_context_is_misconfigured_launch() {
    let scopes = SmartScopeSet::parse("patient/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &LaunchContext::empty(),
        "Observation",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::MissingPatientContext);
}

#[test]
fn user_scope_grants_unrestricted_allow() {
    let scopes = SmartScopeSet::parse("user/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Observation",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Allow);
}

#[test]
fn user_scope_elevates_over_patient_scope() {
    // Both scopes match the request — the broader Allow wins.
    let scopes = SmartScopeSet::parse("patient/Observation.read user/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Observation",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Allow);
}

#[test]
fn read_scope_denies_write() {
    let scopes = SmartScopeSet::parse("patient/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Observation",
        Action::Write,
    );
    assert_eq!(dec, ScopeDecision::Deny);
}

#[test]
fn wildcard_resource_matches_any_type() {
    let scopes = SmartScopeSet::parse("patient/*.read").unwrap();
    for resource_type in ["Patient", "Observation", "Encounter", "Practitioner"] {
        let dec = authorize(
            &scopes,
            &ctx_with_patient("alice-001"),
            resource_type,
            Action::Read,
        );
        assert!(
            matches!(dec, ScopeDecision::AllowWithPatientContext { .. }),
            "expected patient-bound Allow for {resource_type}, got {dec:?}"
        );
    }
}

#[test]
fn star_action_grants_read_and_write() {
    let scopes = SmartScopeSet::parse("user/Observation.*").unwrap();
    assert_eq!(
        authorize(
            &scopes,
            &LaunchContext::empty(),
            "Observation",
            Action::Read
        ),
        ScopeDecision::Allow
    );
    assert_eq!(
        authorize(
            &scopes,
            &LaunchContext::empty(),
            "Observation",
            Action::Write
        ),
        ScopeDecision::Allow
    );
}

#[test]
fn system_scope_works_without_launch_context() {
    let scopes = SmartScopeSet::parse("system/*.read").unwrap();
    let dec = authorize(
        &scopes,
        &LaunchContext::empty(),
        "Observation",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Allow);
}

#[test]
fn unrelated_resource_is_denied() {
    let scopes = SmartScopeSet::parse("patient/Observation.read").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Patient",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Deny);
}

#[test]
fn standalone_scopes_dont_grant_resource_access() {
    // openid / profile / fhirUser don't authorize FHIR reads.
    let scopes =
        SmartScopeSet::parse("openid profile fhirUser launch/patient offline_access").unwrap();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Observation",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Deny);
}

#[test]
fn empty_scope_set_denies_everything() {
    let scopes = SmartScopeSet::default();
    let dec = authorize(
        &scopes,
        &ctx_with_patient("alice-001"),
        "Patient",
        Action::Read,
    );
    assert_eq!(dec, ScopeDecision::Deny);
}

#[test]
fn realistic_clinical_app_scope_set() {
    // The shape a typical SMART-launched clinical app requests.
    let scopes = SmartScopeSet::parse(
        "openid fhirUser launch/patient patient/Patient.read patient/Observation.read patient/Encounter.read",
    )
    .unwrap();

    let ctx = ctx_with_patient("alice-001");
    for r in ["Patient", "Observation", "Encounter"] {
        assert!(
            matches!(
                authorize(&scopes, &ctx, r, Action::Read),
                ScopeDecision::AllowWithPatientContext { patient_id } if patient_id == "alice-001"
            ),
            "expected patient-bound read for {r}"
        );
    }
    // But not Practitioner — the app didn't request that scope.
    assert_eq!(
        authorize(&scopes, &ctx, "Practitioner", Action::Read),
        ScopeDecision::Deny
    );
    // And no writes either.
    assert_eq!(
        authorize(&scopes, &ctx, "Observation", Action::Write),
        ScopeDecision::Deny
    );
}
