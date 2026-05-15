//! # SMART on FHIR — authorization primitives
//!
//! Implements the **library primitives** needed to authorize a SMART
//! on FHIR app's queries against a FHIR resource server:
//!
//! - [`scope`] — parsing of SMART v1 scope strings
//!   (`patient/Observation.read`, `openid`, `launch/patient`, …)
//! - [`context`] — runtime [`LaunchContext`][context::LaunchContext]
//!   carried in the token (`patient` / `encounter` / `fhirUser`)
//! - [`decision`] — the [`authorize`][decision::authorize] function
//!   that turns a scope set + launch context + (resource, action)
//!   into a [`ScopeDecision`][decision::ScopeDecision]
//! - [`token`] — JWT validation primitive returning an
//!   [`AccessToken`][token::AccessToken] with parsed claims
//!
//! This crate does **not** ship the HTTP `/authorize` / `/token`
//! endpoints. Those live in the application — see
//! `examples/smart-on-fhir-app/` for a reference implementation
//! built on top of these primitives.
//!
//! ## Wedge scope
//!
//! - SMART v1 scope grammar (`<context>/<Resource>.<action>` +
//!   well-known identifiers)
//! - Standalone launch (no EHR-launch parameter handshake)
//! - JWT-shaped access tokens validated against an asymmetric key
//!
//! Granular v2 scopes (`patient/Observation.read?category=vital-signs`),
//! EHR launch, and token introspection are deferred.

pub mod context;
pub mod decision;
pub mod scope;
pub mod token;

pub use context::{Action, LaunchContext};
pub use decision::{authorize, ScopeDecision};
pub use scope::{ResourceFilter, ScopeActions, ScopeContext, SmartScope, SmartScopeSet};
pub use token::{AccessToken, TokenError, TokenValidator};

#[cfg(test)]
mod tests;
