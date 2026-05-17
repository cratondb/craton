//! SMART on FHIR v1 scope parsing.
//!
//! Scope strings appear in the `scope` parameter of an authorization
//! request and on the returned access token. The grammar:
//!
//! ```text
//! scope     := standalone_id | resource_scope
//! standalone_id := "openid" | "profile" | "fhirUser" | "offline_access"
//!                | "launch" | "launch/patient" | "launch/encounter"
//! resource_scope := context "/" resource "." action
//! context   := "patient" | "user" | "system"
//! resource  := <fhir-resource-type> | "*"
//! action    := "read" | "write" | "*"
//! ```
//!
//! A scope string passed to the authorization server is a
//! space-separated set; [`SmartScopeSet::parse`] tokenises and
//! preserves order.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeParseError {
    #[error("empty scope token")]
    Empty,

    #[error("scope `{scope}` has unrecognised context — expected `patient`, `user`, or `system`")]
    UnknownContext { scope: String },

    #[error("scope `{scope}` has unrecognised action — expected `read`, `write`, or `*`")]
    UnknownAction { scope: String },

    #[error(
        "scope `{0}` is malformed — expected `<context>/<resource>.<action>` or a well-known identifier"
    )]
    Malformed(String),
}

/// One SMART scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmartScope {
    /// `openid` — caller wants an OIDC `id_token`.
    Openid,
    /// `profile` — caller wants the user's profile claims in the id_token.
    Profile,
    /// `fhirUser` — caller wants the `fhirUser` claim resolving to a
    /// `Practitioner` / `Patient` / `RelatedPerson` resource.
    FhirUser,
    /// `offline_access` — caller wants a long-lived refresh_token.
    OfflineAccess,
    /// `launch` — EHR-launch context (the launching app issues this
    /// during an EHR launch handshake; standalone-launch apps
    /// usually issue `launch/patient` instead).
    Launch,
    /// `launch/patient` — request that the authorization server bind
    /// a Patient resource to the granted token.
    LaunchPatient,
    /// `launch/encounter` — same for Encounter.
    LaunchEncounter,
    /// Resource access scope — the workhorse of SMART authorization.
    Resource {
        context: ScopeContext,
        resource_type: ResourceFilter,
        actions: ScopeActions,
    },
}

/// The "audience" half of a resource scope: whose data the caller
/// can touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeContext {
    /// `patient/...` — the caller can only read/write resources
    /// belonging to the patient in the launch context.
    Patient,
    /// `user/...` — the caller can read/write any resources the
    /// authenticated user could see in their EHR session.
    User,
    /// `system/...` — server-to-server access; no user context
    /// required.
    System,
}

/// The resource-type half of a resource scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceFilter {
    /// `*` — every resource type the context allows.
    All,
    /// A specific FHIR R4 resource type (`Patient`, `Observation`, …).
    Specific(String),
}

impl ResourceFilter {
    /// Whether this filter matches the named resource type.
    pub fn matches(&self, resource_type: &str) -> bool {
        match self {
            Self::All => true,
            Self::Specific(s) => s == resource_type,
        }
    }
}

/// SMART v1 actions allowed by a resource scope.
///
/// `read` means GET (single-read and search); `write` means
/// POST/PUT/PATCH/DELETE. `*` enables both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScopeActions {
    pub read: bool,
    pub write: bool,
}

impl ScopeActions {
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
        }
    }
    pub const fn write_only() -> Self {
        Self {
            read: false,
            write: true,
        }
    }
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
        }
    }
}

impl SmartScope {
    /// Parse a single scope token.
    pub fn parse(s: &str) -> Result<Self, ScopeParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ScopeParseError::Empty);
        }

        match s {
            "openid" => return Ok(Self::Openid),
            "profile" => return Ok(Self::Profile),
            "fhirUser" => return Ok(Self::FhirUser),
            "offline_access" => return Ok(Self::OfflineAccess),
            "launch" => return Ok(Self::Launch),
            "launch/patient" => return Ok(Self::LaunchPatient),
            "launch/encounter" => return Ok(Self::LaunchEncounter),
            _ => {}
        }

        // Resource scope: <context>/<resource>.<action>
        let (context_part, rest) = s
            .split_once('/')
            .ok_or_else(|| ScopeParseError::Malformed(s.to_string()))?;
        let (resource_part, action_part) = rest
            .split_once('.')
            .ok_or_else(|| ScopeParseError::Malformed(s.to_string()))?;

        let context = match context_part {
            "patient" => ScopeContext::Patient,
            "user" => ScopeContext::User,
            "system" => ScopeContext::System,
            _ => {
                return Err(ScopeParseError::UnknownContext {
                    scope: s.to_string(),
                });
            }
        };

        let resource_type = match resource_part {
            "*" => ResourceFilter::All,
            other if !other.is_empty() && other.chars().all(|c| c.is_ascii_alphanumeric()) => {
                ResourceFilter::Specific(other.to_string())
            }
            _ => return Err(ScopeParseError::Malformed(s.to_string())),
        };

        let actions = match action_part {
            "read" => ScopeActions::read_only(),
            "write" => ScopeActions::write_only(),
            "*" => ScopeActions::read_write(),
            _ => {
                return Err(ScopeParseError::UnknownAction {
                    scope: s.to_string(),
                });
            }
        };

        Ok(Self::Resource {
            context,
            resource_type,
            actions,
        })
    }
}

/// A collection of SMART scopes, in declaration order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartScopeSet(pub Vec<SmartScope>);

impl SmartScopeSet {
    /// Parse a space-separated scope string.
    ///
    /// Whitespace between tokens is collapsed; empty tokens are
    /// skipped (matching how OAuth servers treat extra spaces).
    pub fn parse(s: &str) -> Result<Self, ScopeParseError> {
        let mut out = Vec::new();
        for tok in s.split_whitespace() {
            out.push(SmartScope::parse(tok)?);
        }
        Ok(Self(out))
    }

    /// Whether the set carries a given scope (used by the OIDC
    /// claim emitter — `set.contains(&SmartScope::Openid)`).
    pub fn contains(&self, scope: &SmartScope) -> bool {
        self.0.iter().any(|s| s == scope)
    }

    /// Iterate just the resource-access scopes.
    pub fn resource_scopes(&self) -> impl Iterator<Item = &SmartScope> {
        self.0
            .iter()
            .filter(|s| matches!(s, SmartScope::Resource { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standalone_identifiers() {
        for (s, expected) in [
            ("openid", SmartScope::Openid),
            ("profile", SmartScope::Profile),
            ("fhirUser", SmartScope::FhirUser),
            ("offline_access", SmartScope::OfflineAccess),
            ("launch", SmartScope::Launch),
            ("launch/patient", SmartScope::LaunchPatient),
            ("launch/encounter", SmartScope::LaunchEncounter),
        ] {
            assert_eq!(SmartScope::parse(s).unwrap(), expected);
        }
    }

    #[test]
    fn parses_patient_resource_read() {
        let s = SmartScope::parse("patient/Observation.read").unwrap();
        assert_eq!(
            s,
            SmartScope::Resource {
                context: ScopeContext::Patient,
                resource_type: ResourceFilter::Specific("Observation".into()),
                actions: ScopeActions::read_only(),
            }
        );
    }

    #[test]
    fn parses_user_wildcard_write() {
        let s = SmartScope::parse("user/*.write").unwrap();
        assert_eq!(
            s,
            SmartScope::Resource {
                context: ScopeContext::User,
                resource_type: ResourceFilter::All,
                actions: ScopeActions::write_only(),
            }
        );
    }

    #[test]
    fn star_action_grants_read_and_write() {
        let s = SmartScope::parse("system/Patient.*").unwrap();
        let SmartScope::Resource { actions, .. } = s else {
            panic!("expected resource scope");
        };
        assert!(actions.read);
        assert!(actions.write);
    }

    #[test]
    fn rejects_unknown_context() {
        let err = SmartScope::parse("guest/Patient.read").unwrap_err();
        assert!(matches!(err, ScopeParseError::UnknownContext { .. }));
    }

    #[test]
    fn rejects_unknown_action() {
        let err = SmartScope::parse("user/Patient.execute").unwrap_err();
        assert!(matches!(err, ScopeParseError::UnknownAction { .. }));
    }

    #[test]
    fn rejects_malformed() {
        for s in ["", "garbage", "user/", "/Patient.read", "user.read"] {
            assert!(SmartScope::parse(s).is_err(), "{s:?} should not parse");
        }
    }

    #[test]
    fn scope_set_parses_space_separated() {
        let set = SmartScopeSet::parse(
            "openid profile fhirUser launch/patient patient/*.read patient/Observation.write",
        )
        .unwrap();
        assert_eq!(set.0.len(), 6);
        assert!(set.contains(&SmartScope::Openid));
        assert!(set.contains(&SmartScope::LaunchPatient));
    }

    #[test]
    fn scope_set_resource_iter_filters_correctly() {
        let set = SmartScopeSet::parse("openid patient/*.read user/Patient.write").unwrap();
        assert_eq!(set.resource_scopes().count(), 2);
    }

    #[test]
    fn resource_filter_matches_specific_or_all() {
        assert!(ResourceFilter::All.matches("Patient"));
        assert!(ResourceFilter::All.matches("Observation"));
        assert!(ResourceFilter::Specific("Patient".into()).matches("Patient"));
        assert!(!ResourceFilter::Specific("Patient".into()).matches("Observation"));
    }

    #[test]
    fn extra_whitespace_in_set_is_tolerated() {
        let set = SmartScopeSet::parse("  openid   profile  \n fhirUser ").unwrap();
        assert_eq!(set.0.len(), 3);
    }
}
