//! Stream retention policy enforcement.
//!
//! Implements automatic data lifecycle management based on compliance
//! framework requirements (HIPAA 6yr, SOX 7yr, PCI 1yr, GDPR purpose-limited).
//!
//! Retention policies control when data can be deleted:
//! - **Minimum retention**: Data MUST be kept for at least this long (legal requirement).
//! - **Maximum retention**: Data SHOULD be deleted after this (GDPR storage limitation).
//! - **Exemptions**: Legal holds and active investigations override deletion.

use std::collections::HashMap;
use std::time::SystemTime;

use kimberlite_types::DataClass;
use thiserror::Error;

use crate::classification;

/// Errors from retention policy operations.
#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("Stream {stream_id} is under legal hold until {hold_reason}")]
    LegalHold { stream_id: u64, hold_reason: String },

    #[error(
        "Stream {stream_id} has not met minimum retention ({min_days} days, {elapsed_days} elapsed)"
    )]
    MinimumRetentionNotMet {
        stream_id: u64,
        min_days: u32,
        elapsed_days: u32,
    },

    #[error("Stream {stream_id} not found in retention tracker")]
    StreamNotFound { stream_id: u64 },
}

pub type Result<T> = std::result::Result<T, RetentionError>;

/// HIPAA-mandated minimum retention for audit logs themselves:
/// 6 years from the date of creation OR the date when last in effect,
/// whichever is later (45 CFR § 164.530(j)(2)).
///
/// This is distinct from data retention — even after the underlying
/// PHI has been deleted under its own retention rules, the audit log
/// recording who accessed it must persist.
pub const HIPAA_AUDIT_LOG_MIN_DAYS: u32 = 2_190;

/// Default age of majority in the United States (most states).
/// Outliers covered by [`age_of_majority_years_for_state`]: AL/NE = 19,
/// MS = 21. Other jurisdictions need the override.
pub const DEFAULT_AGE_OF_MAJORITY_YEARS: u32 = 18;

/// Default pediatric records extension. The patient's records must be
/// kept this many years *past* age of majority, per the most common
/// state rule (e.g. NY § 18 NYCRR 405.10 — 6y after age-of-majority).
/// States vary 2–10 years; callers pass an explicit value when the
/// default doesn't apply.
pub const DEFAULT_PEDIATRIC_EXTENSION_YEARS: u32 = 6;

/// Age-of-majority lookup for U.S. states with non-default rules.
/// Returns the default (18) for any unrecognised input; callers should
/// supply the explicit value when the state isn't a simple
/// 2-letter postal code.
pub fn age_of_majority_years_for_state(state_postal: &str) -> u32 {
    match state_postal.to_ascii_uppercase().as_str() {
        // 19 in AL and NE.
        "AL" | "NE" => 19,
        // 21 in MS.
        "MS" => 21,
        _ => DEFAULT_AGE_OF_MAJORITY_YEARS,
    }
}

/// Pediatric retention rule. Records in the stream must be retained
/// until the patient reaches age of majority plus the extension
/// period. The rule is birthdate-anchored, so its expiry date is
/// patient-specific — this is the v1 shape used by per-patient
/// outboard streams (one stream per pediatric subject).
///
/// Per-record pediatric rules in a multi-subject stream are a v0.11
/// scope item; they require schema-level birthdate carriage and a
/// per-record retention check inside the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PediatricRetention {
    /// Patient date of birth, as a `SystemTime` (UNIX epoch + offset).
    /// Birthdates before 1970 are represented as UNIX_EPOCH (the rule
    /// is non-binding for adult patients anyway).
    pub birthdate: SystemTime,
    /// Age of majority in years. Defaults to
    /// [`DEFAULT_AGE_OF_MAJORITY_YEARS`]; use
    /// [`age_of_majority_years_for_state`] for per-state lookup.
    pub age_of_majority_years: u32,
    /// Years of extension past age of majority. Defaults to
    /// [`DEFAULT_PEDIATRIC_EXTENSION_YEARS`].
    pub extension_years: u32,
}

impl PediatricRetention {
    /// Convenience constructor using all defaults (most U.S. states).
    pub fn default_us(birthdate: SystemTime) -> Self {
        Self {
            birthdate,
            age_of_majority_years: DEFAULT_AGE_OF_MAJORITY_YEARS,
            extension_years: DEFAULT_PEDIATRIC_EXTENSION_YEARS,
        }
    }

    /// State-aware constructor. Falls back to defaults when the state
    /// has no non-default age of majority.
    pub fn for_state(birthdate: SystemTime, state_postal: &str) -> Self {
        Self {
            birthdate,
            age_of_majority_years: age_of_majority_years_for_state(state_postal),
            extension_years: DEFAULT_PEDIATRIC_EXTENSION_YEARS,
        }
    }

    /// Minimum retention end-date for the subject. Records must be
    /// kept until at least this instant. Saturates if the addition
    /// would overflow.
    pub fn retain_until(&self) -> SystemTime {
        let total_years = self
            .age_of_majority_years
            .saturating_add(self.extension_years);
        // ~365.2425-day year accommodates leap years close enough for
        // a 18+6=24 year horizon. Closed-form is fine for compliance
        // timing (we're not navigating spacecraft).
        let total_days = u64::from(total_years) * 36_524 / 100;
        let total_seconds = total_days.saturating_mul(86_400);
        self.birthdate
            .checked_add(std::time::Duration::from_secs(total_seconds))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    /// True iff `now` is at or past the rule's retention horizon.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.retain_until()
    }
}

/// Kind of stream — drives whether `RetentionPolicy::for_audit_log()` or
/// `RetentionPolicy::from_data_class()` applies. The two classes can
/// have different minimum retention, and audit-log streams are exempt
/// from GDPR storage-limitation deletion when the action they log is
/// itself an audit-required event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Application data stream — retention derived from `DataClass`.
    Data,
    /// Append-only audit log stream — retention is HIPAA §164.530(j)(2)
    /// regardless of the data class of the resources it references.
    AuditLog,
}

impl Default for StreamKind {
    fn default() -> Self {
        Self::Data
    }
}

/// Retention policy for a stream.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Minimum retention period in days (legal requirement).
    /// Data MUST NOT be deleted before this period.
    pub min_retention_days: Option<u32>,
    /// Maximum retention period in days (GDPR storage limitation).
    /// Data SHOULD be deleted after this period unless exempted.
    pub max_retention_days: Option<u32>,
    /// Whether the stream is under legal hold (overrides max retention).
    pub legal_hold: bool,
    /// Reason for legal hold (for audit trail).
    pub hold_reason: Option<String>,
    /// What kind of stream this policy applies to. Audit-log streams
    /// have HIPAA's 6-year minimum independent of the data class.
    pub stream_kind: StreamKind,
    /// Pediatric (birthdate-anchored) retention rule. When present,
    /// the rule's `retain_until` is the effective minimum regardless
    /// of `min_retention_days` — pediatric records must be kept until
    /// the patient reaches age-of-majority + extension, period.
    pub pediatric: Option<PediatricRetention>,
}

impl RetentionPolicy {
    /// Creates a retention policy from data classification.
    ///
    /// Uses compliance framework requirements to determine retention periods.
    pub fn from_data_class(data_class: DataClass) -> Self {
        Self {
            min_retention_days: classification::min_retention_days(data_class),
            max_retention_days: classification::max_retention_days(data_class),
            legal_hold: false,
            hold_reason: None,
            stream_kind: StreamKind::Data,
            pediatric: None,
        }
    }

    /// Retention policy for an audit-log stream — HIPAA § 164.530(j)(2)
    /// mandates a 6-year minimum *for the audit log itself*, regardless
    /// of the retention applied to the data it references. The policy
    /// has no max_retention because audit logs are never automatically
    /// deleted; storage-limitation requests against an audit-log stream
    /// must be reviewed manually.
    pub fn for_audit_log() -> Self {
        Self {
            min_retention_days: Some(HIPAA_AUDIT_LOG_MIN_DAYS),
            max_retention_days: None,
            legal_hold: false,
            hold_reason: None,
            stream_kind: StreamKind::AuditLog,
            pediatric: None,
        }
    }

    /// Creates a custom retention policy (data-class kind).
    pub fn custom(min_days: Option<u32>, max_days: Option<u32>) -> Self {
        Self {
            min_retention_days: min_days,
            max_retention_days: max_days,
            legal_hold: false,
            hold_reason: None,
            stream_kind: StreamKind::Data,
            pediatric: None,
        }
    }

    /// Pediatric (birthdate-anchored) retention policy. Use for
    /// per-patient outboard streams in clinical systems. The
    /// pediatric rule overrides the standard `min_retention_days`
    /// — records must be kept until age-of-majority + extension.
    pub fn pediatric(rule: PediatricRetention) -> Self {
        let mut policy = Self::from_data_class(DataClass::PHI);
        policy.pediatric = Some(rule);
        policy
    }

    /// Attach a pediatric rule to an existing policy. Builder-style
    /// for the case where you already have a per-class policy and
    /// want to layer the birthdate-anchored override on top.
    pub fn with_pediatric(mut self, rule: PediatricRetention) -> Self {
        self.pediatric = Some(rule);
        self
    }

    /// Places the stream under legal hold.
    pub fn with_legal_hold(mut self, reason: String) -> Self {
        self.legal_hold = true;
        self.hold_reason = Some(reason);
        self
    }

    /// Whether this policy describes an audit-log stream.
    pub fn is_audit_log(&self) -> bool {
        matches!(self.stream_kind, StreamKind::AuditLog)
    }
}

/// Tracked stream with creation time and retention policy.
#[derive(Debug, Clone)]
struct TrackedStream {
    /// When the stream was created.
    created_at: SystemTime,
    /// Data classification.
    data_class: DataClass,
    /// Retention policy.
    policy: RetentionPolicy,
}

/// Retention action recommended by the enforcer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionAction {
    /// Stream is within retention period, no action needed.
    Retain,
    /// Stream has exceeded max retention and should be deleted.
    Delete { reason: String },
    /// Stream has exceeded max retention but is under legal hold.
    HoldActive { reason: String },
    /// Stream is approaching max retention (within 30 days).
    ExpiringWarning { days_remaining: u32 },
}

/// Enforces retention policies across all tracked streams.
///
/// Tracks stream creation times, applies compliance-based retention rules,
/// and identifies streams eligible for automatic deletion.
#[derive(Debug)]
pub struct RetentionEnforcer {
    /// Tracked streams by ID.
    streams: HashMap<u64, TrackedStream>,
}

impl RetentionEnforcer {
    /// Creates a new retention enforcer.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Registers a stream with its data classification.
    ///
    /// The retention policy is automatically derived from the data class.
    pub fn register_stream(&mut self, stream_id: u64, data_class: DataClass) {
        let policy = RetentionPolicy::from_data_class(data_class);
        self.streams.insert(
            stream_id,
            TrackedStream {
                created_at: SystemTime::now(),
                data_class,
                policy,
            },
        );
    }

    /// Registers a stream with a custom retention policy.
    pub fn register_stream_with_policy(
        &mut self,
        stream_id: u64,
        data_class: DataClass,
        policy: RetentionPolicy,
    ) {
        self.streams.insert(
            stream_id,
            TrackedStream {
                created_at: SystemTime::now(),
                data_class,
                policy,
            },
        );
    }

    /// Registers a stream with a specific creation time (for testing/migration).
    pub fn register_stream_at(
        &mut self,
        stream_id: u64,
        data_class: DataClass,
        created_at: SystemTime,
    ) {
        let policy = RetentionPolicy::from_data_class(data_class);
        self.streams.insert(
            stream_id,
            TrackedStream {
                created_at,
                data_class,
                policy,
            },
        );
    }

    /// Registers an audit-log stream. Audit logs retain for 6 years
    /// (HIPAA § 164.530(j)(2)) independent of the data class of the
    /// resources they reference. The `data_class` parameter records
    /// the highest sensitivity of resources logged (typically PHI)
    /// for reporting purposes; it does not influence the retention
    /// duration on an audit-log stream.
    pub fn register_audit_log_stream(&mut self, stream_id: u64, data_class: DataClass) {
        let policy = RetentionPolicy::for_audit_log();
        self.streams.insert(
            stream_id,
            TrackedStream {
                created_at: SystemTime::now(),
                data_class,
                policy,
            },
        );
    }

    /// Registers a pediatric per-patient stream. The minimum
    /// retention end-date is computed from the patient's birthdate
    /// plus age-of-majority plus extension years (see
    /// [`PediatricRetention`]). Suitable for per-patient outboard
    /// streams in clinical-research and pediatric-care wedges.
    pub fn register_pediatric_stream(&mut self, stream_id: u64, rule: PediatricRetention) {
        let policy = RetentionPolicy::pediatric(rule);
        self.streams.insert(
            stream_id,
            TrackedStream {
                created_at: SystemTime::now(),
                data_class: DataClass::PHI,
                policy,
            },
        );
    }

    /// Places a stream under legal hold.
    pub fn set_legal_hold(&mut self, stream_id: u64, reason: String) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RetentionError::StreamNotFound { stream_id })?;
        stream.policy.legal_hold = true;
        stream.policy.hold_reason = Some(reason);
        Ok(())
    }

    /// Removes legal hold from a stream.
    pub fn remove_legal_hold(&mut self, stream_id: u64) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(RetentionError::StreamNotFound { stream_id })?;
        stream.policy.legal_hold = false;
        stream.policy.hold_reason = None;
        Ok(())
    }

    /// Checks whether a stream can be deleted.
    ///
    /// Returns `Ok(())` if deletion is allowed, or an error explaining why not.
    pub fn can_delete(&self, stream_id: u64) -> Result<()> {
        let stream = self
            .streams
            .get(&stream_id)
            .ok_or(RetentionError::StreamNotFound { stream_id })?;

        // Legal hold overrides everything
        if stream.policy.legal_hold {
            return Err(RetentionError::LegalHold {
                stream_id,
                hold_reason: stream
                    .policy
                    .hold_reason
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string()),
            });
        }

        // Pediatric rule dominates when present — records must be
        // retained until age-of-majority + extension years past the
        // patient's birthdate, regardless of how long the stream
        // itself has existed. Check this *before* the data-class
        // min_retention_days so the pediatric horizon wins when it's
        // the binding constraint.
        if let Some(rule) = stream.policy.pediatric {
            let now = SystemTime::now();
            if !rule.is_expired(now) {
                let remaining = rule.retain_until().duration_since(now).unwrap_or_default();
                let elapsed_days =
                    stream.created_at.elapsed().unwrap_or_default().as_secs() / 86_400;
                return Err(RetentionError::MinimumRetentionNotMet {
                    stream_id,
                    min_days: (remaining.as_secs() / 86_400) as u32,
                    elapsed_days: elapsed_days as u32,
                });
            }
        }

        // Check minimum retention from data classification.
        if let Some(min_days) = stream.policy.min_retention_days {
            let elapsed = stream.created_at.elapsed().unwrap_or_default();
            let elapsed_days = (elapsed.as_secs() / 86_400) as u32;

            if elapsed_days < min_days {
                return Err(RetentionError::MinimumRetentionNotMet {
                    stream_id,
                    min_days,
                    elapsed_days,
                });
            }
        }

        Ok(())
    }

    /// Evaluates the retention action for a stream.
    pub fn evaluate(&self, stream_id: u64) -> Result<RetentionAction> {
        let stream = self
            .streams
            .get(&stream_id)
            .ok_or(RetentionError::StreamNotFound { stream_id })?;

        let elapsed = stream.created_at.elapsed().unwrap_or_default();
        let elapsed_days = (elapsed.as_secs() / 86_400) as u32;

        // Check max retention
        if let Some(max_days) = stream.policy.max_retention_days {
            if elapsed_days >= max_days {
                if stream.policy.legal_hold {
                    return Ok(RetentionAction::HoldActive {
                        reason: stream
                            .policy
                            .hold_reason
                            .clone()
                            .unwrap_or_else(|| "unspecified".to_string()),
                    });
                }

                // Check minimum retention is also met
                if let Some(min_days) = stream.policy.min_retention_days {
                    if elapsed_days < min_days {
                        return Ok(RetentionAction::Retain);
                    }
                }

                return Ok(RetentionAction::Delete {
                    reason: format!(
                        "exceeded max retention of {} days (elapsed: {} days, class: {:?})",
                        max_days, elapsed_days, stream.data_class
                    ),
                });
            }

            // Warning if within 30 days of expiry
            let days_remaining = max_days.saturating_sub(elapsed_days);
            if days_remaining <= 30 {
                return Ok(RetentionAction::ExpiringWarning { days_remaining });
            }
        }

        Ok(RetentionAction::Retain)
    }

    /// Scans all tracked streams and returns those eligible for deletion.
    ///
    /// This is the main entry point for background retention cleanup.
    pub fn scan_for_deletion(&self) -> Vec<(u64, RetentionAction)> {
        let mut actions = Vec::new();

        for &stream_id in self.streams.keys() {
            if let Ok(action) = self.evaluate(stream_id) {
                match &action {
                    RetentionAction::Delete { .. }
                    | RetentionAction::ExpiringWarning { .. }
                    | RetentionAction::HoldActive { .. } => {
                        actions.push((stream_id, action));
                    }
                    RetentionAction::Retain => {}
                }
            }
        }

        // Sort by stream ID for deterministic output
        actions.sort_by_key(|(id, _)| *id);
        actions
    }

    /// Returns the number of tracked streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Returns the retention policy for a stream.
    pub fn get_policy(&self, stream_id: u64) -> Option<&RetentionPolicy> {
        self.streams.get(&stream_id).map(|s| &s.policy)
    }
}

impl Default for RetentionEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_policy_from_data_class_phi() {
        let policy = RetentionPolicy::from_data_class(DataClass::PHI);
        assert_eq!(policy.min_retention_days, Some(2_190)); // 6 years HIPAA
        assert!(!policy.legal_hold);
    }

    #[test]
    fn test_policy_from_data_class_financial() {
        let policy = RetentionPolicy::from_data_class(DataClass::Financial);
        assert_eq!(policy.min_retention_days, Some(2_555)); // 7 years SOX
    }

    #[test]
    fn test_policy_from_data_class_pci() {
        let policy = RetentionPolicy::from_data_class(DataClass::PCI);
        assert_eq!(policy.min_retention_days, Some(365)); // 1 year PCI DSS
    }

    #[test]
    fn test_policy_from_data_class_public() {
        let policy = RetentionPolicy::from_data_class(DataClass::Public);
        assert_eq!(policy.min_retention_days, None);
        assert_eq!(policy.max_retention_days, None);
    }

    #[test]
    fn test_register_and_evaluate_retain() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_stream(1, DataClass::PHI);

        // Stream just created — should retain
        let action = enforcer.evaluate(1).unwrap();
        assert_eq!(action, RetentionAction::Retain);
    }

    #[test]
    fn test_cannot_delete_within_minimum_retention() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_stream(1, DataClass::PHI);

        // PHI has 6-year minimum — cannot delete immediately
        let result = enforcer.can_delete(1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RetentionError::MinimumRetentionNotMet { min_days: 2190, .. }
        ));
    }

    #[test]
    fn test_can_delete_public_data_immediately() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_stream(1, DataClass::Public);

        // Public data has no minimum retention
        let result = enforcer.can_delete(1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_legal_hold_prevents_deletion() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_stream(1, DataClass::Public);
        enforcer
            .set_legal_hold(1, "SEC investigation #42".to_string())
            .unwrap();

        let result = enforcer.can_delete(1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RetentionError::LegalHold { stream_id: 1, .. }
        ));
    }

    #[test]
    fn test_remove_legal_hold() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_stream(1, DataClass::Public);
        enforcer
            .set_legal_hold(1, "investigation".to_string())
            .unwrap();

        assert!(enforcer.can_delete(1).is_err());

        enforcer.remove_legal_hold(1).unwrap();
        assert!(enforcer.can_delete(1).is_ok());
    }

    #[test]
    fn test_evaluate_with_max_retention_exceeded() {
        let mut enforcer = RetentionEnforcer::new();

        // Create a stream with custom max retention of 0 days (for testing)
        let policy = RetentionPolicy::custom(None, Some(0));
        enforcer.register_stream_with_policy(1, DataClass::Public, policy);

        let action = enforcer.evaluate(1).unwrap();
        assert!(matches!(action, RetentionAction::Delete { .. }));
    }

    #[test]
    fn test_evaluate_hold_active_overrides_deletion() {
        let mut enforcer = RetentionEnforcer::new();

        let policy =
            RetentionPolicy::custom(None, Some(0)).with_legal_hold("ongoing audit".to_string());
        enforcer.register_stream_with_policy(1, DataClass::Public, policy);

        let action = enforcer.evaluate(1).unwrap();
        assert!(matches!(action, RetentionAction::HoldActive { .. }));
    }

    #[test]
    fn test_scan_for_deletion() {
        let mut enforcer = RetentionEnforcer::new();

        // Stream 1: should be retained (just created, PHI)
        enforcer.register_stream(1, DataClass::PHI);

        // Stream 2: expired (custom 0-day max retention)
        let expired_policy = RetentionPolicy::custom(None, Some(0));
        enforcer.register_stream_with_policy(2, DataClass::Public, expired_policy);

        let actions = enforcer.scan_for_deletion();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].0, 2);
        assert!(matches!(actions[0].1, RetentionAction::Delete { .. }));
    }

    #[test]
    fn test_expiring_warning() {
        let mut enforcer = RetentionEnforcer::new();

        // Create a stream with max retention that will show warning
        // We need to set created_at to be close to max retention
        let max_days = 365u32;
        let elapsed_secs = u64::from(max_days - 10) * 86_400; // 10 days remaining
        let created_at = SystemTime::now() - Duration::from_secs(elapsed_secs);

        let policy = RetentionPolicy::custom(None, Some(max_days));
        enforcer.streams.insert(
            1,
            TrackedStream {
                created_at,
                data_class: DataClass::Public,
                policy,
            },
        );

        let action = enforcer.evaluate(1).unwrap();
        assert!(matches!(
            action,
            RetentionAction::ExpiringWarning { days_remaining }
            if days_remaining <= 30
        ));
    }

    #[test]
    fn test_stream_not_found() {
        let enforcer = RetentionEnforcer::new();
        assert!(matches!(
            enforcer.evaluate(99).unwrap_err(),
            RetentionError::StreamNotFound { stream_id: 99 }
        ));
    }

    #[test]
    fn test_custom_policy() {
        let mut enforcer = RetentionEnforcer::new();
        let policy = RetentionPolicy::custom(Some(90), Some(365));
        enforcer.register_stream_with_policy(1, DataClass::Confidential, policy);

        let stored_policy = enforcer.get_policy(1).unwrap();
        assert_eq!(stored_policy.min_retention_days, Some(90));
        assert_eq!(stored_policy.max_retention_days, Some(365));
    }

    #[test]
    fn test_audit_log_policy_uses_hipaa_min() {
        let policy = RetentionPolicy::for_audit_log();
        assert_eq!(policy.min_retention_days, Some(HIPAA_AUDIT_LOG_MIN_DAYS));
        assert_eq!(policy.min_retention_days, Some(2_190));
        assert_eq!(policy.max_retention_days, None);
        assert!(policy.is_audit_log());
        assert_eq!(policy.stream_kind, StreamKind::AuditLog);
    }

    #[test]
    fn test_data_class_policy_is_not_audit_log() {
        let policy = RetentionPolicy::from_data_class(DataClass::PHI);
        assert!(!policy.is_audit_log());
        assert_eq!(policy.stream_kind, StreamKind::Data);
    }

    #[test]
    fn test_register_audit_log_stream_blocks_early_deletion() {
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_audit_log_stream(42, DataClass::PHI);
        let result = enforcer.can_delete(42);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RetentionError::MinimumRetentionNotMet {
                min_days: 2_190,
                ..
            }
        ));
    }

    #[test]
    fn test_audit_log_retention_independent_of_data_class() {
        // Even a Public-class audit log stream retains for 6 years.
        let mut enforcer = RetentionEnforcer::new();
        enforcer.register_audit_log_stream(42, DataClass::Public);
        let policy = enforcer.get_policy(42).unwrap();
        assert_eq!(policy.min_retention_days, Some(HIPAA_AUDIT_LOG_MIN_DAYS));
    }

    // ------------------------------------------------------------------
    // Pediatric retention
    // ------------------------------------------------------------------

    fn years_ago(years: u32) -> SystemTime {
        let secs = u64::from(years) * 36_524 / 100 * 86_400;
        SystemTime::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    #[test]
    fn pediatric_default_us_horizon_is_age_24() {
        let birthdate = years_ago(10); // 10-year-old patient today
        let rule = PediatricRetention::default_us(birthdate);
        assert_eq!(rule.age_of_majority_years, 18);
        assert_eq!(rule.extension_years, 6);
        let now = SystemTime::now();
        assert!(
            !rule.is_expired(now),
            "10-year-old's record not yet expired"
        );
    }

    #[test]
    fn pediatric_horizon_passes_for_old_birthdate() {
        let birthdate = years_ago(40); // patient is 40 today
        let rule = PediatricRetention::default_us(birthdate);
        assert!(rule.is_expired(SystemTime::now()));
    }

    #[test]
    fn age_of_majority_state_overrides() {
        assert_eq!(age_of_majority_years_for_state("AL"), 19);
        assert_eq!(age_of_majority_years_for_state("NE"), 19);
        assert_eq!(age_of_majority_years_for_state("MS"), 21);
        assert_eq!(age_of_majority_years_for_state("ca"), 18);
        assert_eq!(age_of_majority_years_for_state("NY"), 18);
        assert_eq!(age_of_majority_years_for_state("ZZ"), 18);
    }

    #[test]
    fn pediatric_policy_blocks_deletion_before_horizon() {
        let mut enforcer = RetentionEnforcer::new();
        let birthdate = years_ago(5); // 5-year-old patient
        let rule = PediatricRetention::for_state(birthdate, "CA");
        enforcer.register_pediatric_stream(100, rule);
        let err = enforcer.can_delete(100).unwrap_err();
        assert!(matches!(err, RetentionError::MinimumRetentionNotMet { .. }));
    }

    #[test]
    fn pediatric_policy_permits_deletion_after_horizon() {
        let mut enforcer = RetentionEnforcer::new();
        let birthdate = years_ago(40);
        let rule = PediatricRetention::default_us(birthdate);
        // Backdate the stream creation so the data-class min is met too.
        enforcer.register_stream_at(
            100,
            DataClass::PHI,
            SystemTime::now()
                .checked_sub(Duration::from_secs(7 * 365 * 86_400))
                .unwrap_or(SystemTime::UNIX_EPOCH),
        );
        // Layer the pediatric rule onto the existing tracked stream.
        let policy = RetentionPolicy::from_data_class(DataClass::PHI).with_pediatric(rule);
        enforcer.streams.get_mut(&100).unwrap().policy = policy;
        // Patient is now 40 → pediatric expired → can delete.
        enforcer
            .can_delete(100)
            .expect("deletion allowed past horizon");
    }

    #[test]
    fn pediatric_horizon_respects_alabama_age_19() {
        let birthdate = years_ago(24); // patient is 24 today
        // Default U.S.: 18 + 6 = 24 → expired (boundary).
        let default_rule = PediatricRetention::default_us(birthdate);
        // Alabama: 19 + 6 = 25 → not yet expired.
        let al_rule = PediatricRetention::for_state(birthdate, "AL");
        assert!(al_rule.retain_until() > default_rule.retain_until());
    }

    #[test]
    fn pediatric_rule_overrides_min_retention_when_longer() {
        // Newborn: 18+6=24 years of retention horizon — far longer
        // than the 6-year HIPAA min for PHI. Pediatric must dominate.
        let mut enforcer = RetentionEnforcer::new();
        let birthdate = SystemTime::now();
        let rule = PediatricRetention::default_us(birthdate);
        let policy = RetentionPolicy::pediatric(rule);
        enforcer.register_stream_with_policy(7, DataClass::PHI, policy);
        let err = enforcer.can_delete(7).unwrap_err();
        match err {
            RetentionError::MinimumRetentionNotMet { min_days, .. } => {
                // Roughly 24 years' worth of days.
                assert!(
                    min_days > 8000,
                    "expected ~8700 days of remaining retention, got {min_days}"
                );
            }
            other => panic!("expected MinimumRetentionNotMet, got {other:?}"),
        }
    }
}
