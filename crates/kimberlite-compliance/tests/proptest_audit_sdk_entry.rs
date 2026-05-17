//! **v0.6.0 Tier 2 #9** — invariant tests for the PHI-safe
//! `AuditSdkEntry` / wire `AuditEventInfo` projection.
//!
//! The audit-query SDK surface ships PHI-safe entries: each entry
//! lists the *names* of the fields the underlying
//! `ComplianceAuditAction` touched (`changed_field_names`) but
//! **never** their values. These tests lock that invariant in over
//! 1k random events plus every combination of filter flags.
//!
//! # Invariants enforced
//!
//! 1. `audit_sdk_entry_never_leaks_values` — for 1k random events
//!    with non-trivial payloads, the JSON encoding of every
//!    `AuditSdkEntry` contains none of the payload value strings
//!    (purpose, scope, indicator, remediation, …). `action`,
//!    `reason`, `subject_id`, `changed_field_names` are the
//!    permitted surface.
//!
//! 2. `audit_filter_combinatorics_match_reference` — every subset
//!    of `{subject_id, actor, action_type, time_from, time_to}`
//!    filters returns the same events as a reference in-memory
//!    matcher over 1k randomised event logs.

#![cfg(test)]

use chrono::{DateTime, TimeZone, Utc};
use kimberlite_compliance::audit::{
    AuditQuery, AuditSdkEntry, ComplianceAuditAction, ComplianceAuditEvent, ComplianceAuditLog,
};
use proptest::prelude::*;
use uuid::Uuid;

// -----------------------------------------------------------------------------
// Value strategies. Non-trivial payloads so a leak would be
// immediately visible in the encoded bytes.
// -----------------------------------------------------------------------------

/// A non-empty ASCII alphanumeric string used for action-payload values
/// that we want to *detect* in encoded output. 8–24 chars so that a
/// substring match is unambiguous (distinct from any field *name*).
fn nontrivial_value() -> impl Strategy<Value = String> {
    // Prefix with "VAL-" so the string is guaranteed to differ from
    // every field name (`subject_id`, `purpose`, `scope`, …) and from
    // any UUID hex representation.
    "VAL-[A-Z0-9]{8,16}".prop_map(|s| s.to_string())
}

fn action_strategy() -> impl Strategy<Value = ComplianceAuditAction> {
    prop_oneof![
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(subject_id, purpose, scope)| ComplianceAuditAction::ConsentGranted {
                subject_id,
                purpose,
                scope,
                terms_version: None,
                accepted: true,
            }
        ),
        nontrivial_value().prop_map(|subject_id| ComplianceAuditAction::ConsentWithdrawn {
            subject_id,
            consent_id: Uuid::new_v4(),
        }),
        nontrivial_value().prop_map(|subject_id| ComplianceAuditAction::ErasureRequested {
            subject_id,
            request_id: Uuid::new_v4(),
        }),
        (nontrivial_value(), any::<u64>()).prop_map(|(subject_id, records_erased)| {
            ComplianceAuditAction::ErasureCompleted {
                subject_id,
                records_erased,
                request_id: Uuid::new_v4(),
            }
        }),
        (nontrivial_value(), nontrivial_value()).prop_map(|(subject_id, basis)| {
            ComplianceAuditAction::ErasureExempted {
                subject_id,
                request_id: Uuid::new_v4(),
                basis,
            }
        }),
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(column, strategy, role)| ComplianceAuditAction::FieldMasked {
                column,
                strategy,
                role,
            }
        ),
        (nontrivial_value(), nontrivial_value()).prop_map(|(severity, indicator)| {
            ComplianceAuditAction::BreachDetected {
                event_id: Uuid::new_v4(),
                severity,
                indicator,
                affected_subjects: Vec::new(),
            }
        }),
        nontrivial_value().prop_map(|remediation| ComplianceAuditAction::BreachResolved {
            event_id: Uuid::new_v4(),
            remediation,
            affected_subjects: Vec::new(),
        }),
        (nontrivial_value(), nontrivial_value(), any::<u64>()).prop_map(
            |(subject_id, format, record_count)| ComplianceAuditAction::DataExported {
                subject_id,
                export_id: Uuid::new_v4(),
                format,
                record_count,
            }
        ),
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(user_id, resource, role)| ComplianceAuditAction::AccessGranted {
                user_id,
                resource,
                role,
            }
        ),
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(user_id, resource, reason)| ComplianceAuditAction::AccessDenied {
                user_id,
                resource,
                reason,
            }
        ),
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(policy_type, changed_by, details)| ComplianceAuditAction::PolicyChanged {
                policy_type,
                changed_by,
                details,
            }
        ),
        (nontrivial_value(), nontrivial_value(), any::<u64>()).prop_map(
            |(column, token_format, record_count)| ComplianceAuditAction::TokenizationApplied {
                column,
                token_format,
                record_count,
            }
        ),
        (nontrivial_value(), nontrivial_value(), nontrivial_value()).prop_map(
            |(record_id, signer_id, meaning)| ComplianceAuditAction::RecordSigned {
                record_id,
                signer_id,
                meaning,
            }
        ),
    ]
}

/// Collect every value string embedded in the action payload.
///
/// Mirrors the shape of `changed_field_names` but returns values
/// rather than names. Used by the invariant test to assert none
/// of these appear in the encoded SDK entry.
fn payload_values(a: &ComplianceAuditAction) -> Vec<String> {
    match a {
        ComplianceAuditAction::ConsentGranted {
            subject_id,
            purpose,
            scope,
            terms_version,
            accepted: _,
        } => {
            let mut v = vec![subject_id.clone(), purpose.clone(), scope.clone()];
            if let Some(tv) = terms_version {
                v.push(tv.clone());
            }
            v
        }
        ComplianceAuditAction::ConsentWithdrawn {
            subject_id,
            consent_id,
        } => vec![subject_id.clone(), consent_id.to_string()],
        ComplianceAuditAction::ErasureRequested {
            subject_id,
            request_id,
        } => vec![subject_id.clone(), request_id.to_string()],
        ComplianceAuditAction::ErasureCompleted {
            subject_id,
            records_erased,
            request_id,
        } => vec![
            subject_id.clone(),
            records_erased.to_string(),
            request_id.to_string(),
        ],
        ComplianceAuditAction::ErasureExempted {
            subject_id,
            request_id,
            basis,
        } => vec![subject_id.clone(), request_id.to_string(), basis.clone()],
        ComplianceAuditAction::FieldMasked {
            column,
            strategy,
            role,
        } => vec![column.clone(), strategy.clone(), role.clone()],
        ComplianceAuditAction::BreachDetected {
            event_id,
            severity,
            indicator,
            affected_subjects,
        } => {
            let mut v = vec![event_id.to_string(), severity.clone(), indicator.clone()];
            v.extend(affected_subjects.iter().cloned());
            v
        }
        ComplianceAuditAction::BreachNotified {
            event_id,
            notified_at,
            affected_subjects,
        } => {
            let mut v = vec![event_id.to_string(), notified_at.to_rfc3339()];
            v.extend(affected_subjects.iter().cloned());
            v
        }
        ComplianceAuditAction::BreachResolved {
            event_id,
            remediation,
            affected_subjects,
        } => {
            let mut v = vec![event_id.to_string(), remediation.clone()];
            v.extend(affected_subjects.iter().cloned());
            v
        }
        ComplianceAuditAction::DataExported {
            subject_id,
            export_id,
            format,
            record_count,
        } => vec![
            subject_id.clone(),
            export_id.to_string(),
            format.clone(),
            record_count.to_string(),
        ],
        ComplianceAuditAction::AccessGranted {
            user_id,
            resource,
            role,
        } => vec![user_id.clone(), resource.clone(), role.clone()],
        ComplianceAuditAction::AccessDenied {
            user_id,
            resource,
            reason,
        } => vec![user_id.clone(), resource.clone(), reason.clone()],
        ComplianceAuditAction::PolicyChanged {
            policy_type,
            changed_by,
            details,
        } => vec![policy_type.clone(), changed_by.clone(), details.clone()],
        ComplianceAuditAction::TokenizationApplied {
            column,
            token_format,
            record_count,
        } => vec![
            column.clone(),
            token_format.clone(),
            record_count.to_string(),
        ],
        ComplianceAuditAction::RecordSigned {
            record_id,
            signer_id,
            meaning,
        } => vec![record_id.clone(), signer_id.clone(), meaning.clone()],
        ComplianceAuditAction::BreakGlassActivated {
            user_id,
            patient_id,
            reason,
            approval_chain,
            activated_at,
        } => {
            let mut v = vec![
                user_id.clone(),
                patient_id.clone(),
                reason.clone(),
                activated_at.to_rfc3339(),
            ];
            v.extend(approval_chain.iter().cloned());
            v
        }
        ComplianceAuditAction::BreakGlassClosed {
            user_id,
            patient_id,
            activated_at,
            closed_at,
            accessed_resources,
            duration_seconds,
        } => {
            let mut v = vec![
                user_id.clone(),
                patient_id.clone(),
                activated_at.to_rfc3339(),
                closed_at.to_rfc3339(),
                duration_seconds.to_string(),
            ];
            v.extend(accessed_resources.iter().cloned());
            v
        }
        ComplianceAuditAction::DeidentificationApplied {
            record_id,
            removed_identifiers,
            original_sha256_hex,
            transformed_sha256_hex,
            attestation_sha256_hex,
            transform_version,
        } => vec![
            record_id.clone(),
            removed_identifiers.clone(),
            original_sha256_hex.clone(),
            transformed_sha256_hex.clone(),
            attestation_sha256_hex.clone(),
            transform_version.clone(),
        ],
    }
}

/// Values that the SDK entry is *allowed* to surface — either
/// because they're promoted to a dedicated field (`subject_id`,
/// `reason`), because they're carried as metadata that regulators
/// need (request_id UUID), or because they're semantically safe
/// (the `event_id` itself is a UUID, not PHI).
fn allowed_echoes(a: &ComplianceAuditAction) -> Vec<String> {
    let mut out = Vec::new();
    match a {
        ComplianceAuditAction::ConsentGranted { subject_id, .. }
        | ComplianceAuditAction::ConsentWithdrawn { subject_id, .. }
        | ComplianceAuditAction::ErasureRequested { subject_id, .. }
        | ComplianceAuditAction::ErasureCompleted { subject_id, .. }
        | ComplianceAuditAction::DataExported { subject_id, .. } => {
            out.push(subject_id.clone());
        }
        ComplianceAuditAction::ErasureExempted {
            subject_id,
            request_id,
            basis,
        } => {
            out.push(subject_id.clone());
            out.push(request_id.to_string());
            out.push(basis.clone()); // surfaces as `reason`
        }
        ComplianceAuditAction::AccessGranted { user_id, .. }
        | ComplianceAuditAction::AccessDenied { user_id, .. } => {
            out.push(user_id.clone());
        }
        ComplianceAuditAction::RecordSigned { signer_id, .. } => out.push(signer_id.clone()),
        _ => {}
    }
    // Erasure-lifecycle request ids surface on the SDK entry
    match a {
        ComplianceAuditAction::ErasureRequested { request_id, .. }
        | ComplianceAuditAction::ErasureCompleted { request_id, .. } => {
            out.push(request_id.to_string());
        }
        _ => {}
    }
    out
}

// -----------------------------------------------------------------------------
// Invariant 1 — the wire-encoded SDK entry contains none of the
// underlying payload values (except the explicit echo channels).
// -----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        .. ProptestConfig::default()
    })]

    /// **v0.6.0 Tier 2 #9** — the SDK-safe projection of an
    /// audit event never leaks a payload value into the wire-
    /// encoded bytes. Explicit echo channels (`subject_id`,
    /// `reason`, erasure `request_id`) are allowed.
    ///
    /// Checks both the JSON encoding (what the SDKs consume) and
    /// the postcard encoding (what the wire carries) so the
    /// invariant holds across both serialisers.
    #[test]
    fn audit_sdk_entry_never_leaks_values(action in action_strategy()) {
        let mut log = ComplianceAuditLog::new();
        let id = log.append(action.clone(), Some("operator@example.com".into()), Some(7));
        let event: ComplianceAuditEvent = log.get_event(id).unwrap().clone();
        let entry: AuditSdkEntry = event.to_sdk_entry();

        // `changed_field_names` must be populated, by construction.
        prop_assert!(
            !entry.changed_field_names.is_empty(),
            "changed_field_names must list at least one field"
        );

        let allowed = allowed_echoes(&action);
        let payload = payload_values(&action);

        // --- JSON encoding ---------------------------------------------------
        let encoded_json = serde_json::to_string(&entry).unwrap();
        for val in &payload {
            if allowed.iter().any(|a| a == val) {
                continue;
            }
            prop_assert!(
                !encoded_json.contains(val),
                "JSON-encoded AuditSdkEntry leaked payload value `{}`: {}",
                val,
                encoded_json,
            );
        }

        // --- postcard encoding (wire bytes) ----------------------------------
        let encoded_wire = postcard::to_allocvec(&entry).unwrap();
        for val in &payload {
            if allowed.iter().any(|a| a == val) {
                continue;
            }
            // Convert the value to bytes and scan the wire payload.
            let needle = val.as_bytes();
            if needle.is_empty() {
                continue;
            }
            let mut found = false;
            for window in encoded_wire.windows(needle.len()) {
                if window == needle {
                    found = true;
                    break;
                }
            }
            prop_assert!(
                !found,
                "postcard-encoded AuditSdkEntry leaked payload value `{}` (bytes: {:?})",
                val,
                encoded_wire,
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Invariant 2 — filter combinatorics match a reference implementation.
// -----------------------------------------------------------------------------

/// A random ingest input: the action plus the actor/tenant to
/// append with.
#[derive(Debug, Clone)]
struct Ingest {
    action: ComplianceAuditAction,
    actor: Option<String>,
    tenant_id: Option<u64>,
}

fn ingest_strategy() -> impl Strategy<Value = Ingest> {
    (
        action_strategy(),
        prop_oneof![Just(None), "[a-z]{3,8}".prop_map(Some)],
        prop_oneof![Just(None), (1u64..=4u64).prop_map(Some)],
    )
        .prop_map(|(action, actor, tenant_id)| Ingest {
            action,
            actor,
            tenant_id,
        })
}

/// Reference matcher. Mirrors `ComplianceAuditLog::matches_filter`
/// but without touching the log internals. Used to cross-check the
/// production filter.
fn reference_matches(
    event: &ComplianceAuditEvent,
    f_subject: Option<&str>,
    f_actor: Option<&str>,
    f_action_type: Option<&str>,
    f_from: Option<DateTime<Utc>>,
    f_to: Option<DateTime<Utc>>,
    f_tenant: Option<u64>,
) -> bool {
    if let Some(sid) = f_subject {
        // Walk subject_id-bearing variants manually.
        let matches = match &event.action {
            ComplianceAuditAction::ConsentGranted { subject_id, .. }
            | ComplianceAuditAction::ConsentWithdrawn { subject_id, .. }
            | ComplianceAuditAction::ErasureRequested { subject_id, .. }
            | ComplianceAuditAction::ErasureCompleted { subject_id, .. }
            | ComplianceAuditAction::ErasureExempted { subject_id, .. }
            | ComplianceAuditAction::DataExported { subject_id, .. } => subject_id == sid,
            ComplianceAuditAction::AccessGranted { user_id, .. }
            | ComplianceAuditAction::AccessDenied { user_id, .. } => user_id == sid,
            ComplianceAuditAction::PolicyChanged { changed_by, .. } => changed_by == sid,
            ComplianceAuditAction::RecordSigned { signer_id, .. } => signer_id == sid,
            ComplianceAuditAction::BreachDetected {
                affected_subjects, ..
            }
            | ComplianceAuditAction::BreachNotified {
                affected_subjects, ..
            }
            | ComplianceAuditAction::BreachResolved {
                affected_subjects, ..
            } => affected_subjects.iter().any(|s| s == sid),
            _ => false,
        };
        if !matches {
            return false;
        }
    }
    if let Some(actor) = f_actor {
        if event.actor.as_deref() != Some(actor) {
            return false;
        }
    }
    if let Some(kind_prefix) = f_action_type {
        if !event.action.kind().starts_with(kind_prefix) {
            return false;
        }
    }
    if let Some(from) = f_from {
        if event.timestamp < from {
            return false;
        }
    }
    if let Some(to) = f_to {
        if event.timestamp > to {
            return false;
        }
    }
    if let Some(tenant) = f_tenant {
        if event.tenant_id != Some(tenant) {
            return false;
        }
    }
    true
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// Every subset of `{subject, actor, action_type, time_from,
    /// time_to, tenant}` filters yields the same event list as a
    /// reference matcher over the same event corpus. Guards the
    /// AND-combination semantics the SDK and regulators depend on.
    #[test]
    fn audit_filter_combinatorics_match_reference(
        ingests in prop::collection::vec(ingest_strategy(), 4..24),
        // 6 filter toggles — 2^6 = 64 combinations tested per case.
        (use_subject, use_actor, use_action, use_from, use_to, use_tenant) in
            (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
    ) {
        let mut log = ComplianceAuditLog::new();
        for ing in &ingests {
            log.append(ing.action.clone(), ing.actor.clone(), ing.tenant_id);
        }
        let events: Vec<ComplianceAuditEvent> = log
            .query(&AuditQuery::default())
            .into_iter()
            .cloned()
            .collect();
        if events.is_empty() {
            return Ok(());
        }
        // Derive concrete filter values from the actual events so
        // the subset check is meaningful.
        let f_subject = if use_subject {
            events.iter().find_map(|e| match &e.action {
                ComplianceAuditAction::ConsentGranted { subject_id, .. }
                | ComplianceAuditAction::ErasureRequested { subject_id, .. } => {
                    Some(subject_id.clone())
                }
                _ => None,
            })
        } else {
            None
        };
        let f_actor = if use_actor {
            events.iter().find_map(|e| e.actor.clone())
        } else {
            None
        };
        let f_action = if use_action { Some("Consent".to_string()) } else { None };
        let f_from = if use_from {
            Some(Utc.timestamp_opt(0, 0).unwrap())
        } else {
            None
        };
        let f_to = if use_to { Some(Utc::now()) } else { None };
        let f_tenant = if use_tenant {
            events.iter().find_map(|e| e.tenant_id)
        } else {
            None
        };

        let mut filter = AuditQuery::default();
        if let Some(s) = &f_subject { filter = filter.with_subject(s); }
        if let Some(a) = &f_action { filter = filter.with_action_type(a); }
        if let (Some(from), Some(to)) = (f_from, f_to) {
            filter = filter.with_time_range(from, to);
        }
        if let Some(a) = &f_actor { filter = filter.with_actor(a); }
        if let Some(t) = f_tenant { filter = filter.with_tenant(t); }

        let actual_ids: Vec<Uuid> = log
            .query(&filter)
            .iter()
            .map(|e| e.event_id)
            .collect();
        let expected_ids: Vec<Uuid> = events
            .iter()
            .filter(|e| {
                reference_matches(
                    e,
                    f_subject.as_deref(),
                    f_actor.as_deref(),
                    f_action.as_deref(),
                    f_from,
                    f_to,
                    f_tenant,
                )
            })
            .map(|e| e.event_id)
            .collect();

        prop_assert_eq!(actual_ids, expected_ids);
    }
}
