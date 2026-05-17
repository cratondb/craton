//! The `authorize` decision function.
//!
//! Given the scopes the access token carries, the launch context it
//! binds, and the (resource_type, action) the caller is attempting,
//! return a [`ScopeDecision`] saying whether the call is permitted
//! and, for `patient/...` scopes, the patient-id the call MUST be
//! constrained to.

use serde::{Deserialize, Serialize};

use super::context::{Action, LaunchContext};
use super::scope::{ScopeActions, ScopeContext, SmartScope, SmartScopeSet};

/// Outcome of a scope check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeDecision {
    /// Caller is fully authorized — no further constraint.
    Allow,

    /// Caller is authorized but the query MUST be constrained to the
    /// named patient. The query layer should AND a
    /// `subject.reference = "Patient/<id>"` predicate onto the
    /// caller's query before execution.
    AllowWithPatientContext { patient_id: String },

    /// The token's scopes don't permit this (resource, action) pair.
    Deny,

    /// A `patient/...` scope matched but the launch context has no
    /// `patient_id`. Forensically meaningful because it indicates a
    /// misconfigured launch — distinguish from a pure scope
    /// mismatch so the server can return a precise OAuth error
    /// (`invalid_token` vs `insufficient_scope`).
    MissingPatientContext,
}

/// Authorize a (resource_type, action) request against the token's
/// scopes and launch context.
///
/// Scope-matching is **first-match-wins-broadest**: every resource
/// scope in the set is considered, the *most permissive* outcome
/// is returned. So a set containing both `user/Observation.read`
/// and `patient/Observation.read` permits an unrestricted read
/// (user >= patient) — that's the SMART semantics.
pub fn authorize(
    scopes: &SmartScopeSet,
    launch: &LaunchContext,
    resource_type: &str,
    action: Action,
) -> ScopeDecision {
    // Track best-so-far so user/system trumps patient when both apply.
    let mut best = ScopeDecision::Deny;

    for s in scopes.resource_scopes() {
        let SmartScope::Resource {
            context,
            resource_type: filter,
            actions,
        } = s
        else {
            continue;
        };

        if !filter.matches(resource_type) {
            continue;
        }
        if !action_permitted(*actions, action) {
            continue;
        }

        let candidate = match context {
            ScopeContext::User | ScopeContext::System => ScopeDecision::Allow,
            ScopeContext::Patient => match &launch.patient_id {
                Some(pid) => ScopeDecision::AllowWithPatientContext {
                    patient_id: pid.clone(),
                },
                None => ScopeDecision::MissingPatientContext,
            },
        };

        best = elevate(best, candidate);

        // Fully unrestricted Allow — no point checking further.
        if matches!(best, ScopeDecision::Allow) {
            return best;
        }
    }

    best
}

/// True if a scope with `granted` actions covers `requested`.
fn action_permitted(granted: ScopeActions, requested: Action) -> bool {
    match requested {
        Action::Read => granted.read,
        Action::Write => granted.write,
    }
}

/// `Allow` beats `AllowWithPatientContext` beats `MissingPatientContext`
/// beats `Deny`. Used to merge candidate outcomes within a scope set.
fn elevate(current: ScopeDecision, candidate: ScopeDecision) -> ScopeDecision {
    use ScopeDecision::{Allow, AllowWithPatientContext, Deny, MissingPatientContext};
    match (&current, &candidate) {
        (Allow, _) | (_, Allow) => Allow,
        (AllowWithPatientContext { .. }, _) => current,
        (_, AllowWithPatientContext { .. }) => candidate,
        (MissingPatientContext, _) | (_, MissingPatientContext) => MissingPatientContext,
        _ => Deny,
    }
}
