//! Enhanced Audit Logging for Compliance Operations
//!
//! Implements comprehensive audit event tracking satisfying:
//! - **SOC 2 CC7.2** - Change Detection (monitoring and logging of all changes)
//! - **ISO 27001 A.12.4.1** - Event Logging (recording user activities, exceptions, faults)
//!
//! # Architecture
//!
//! ```text
//! ComplianceAuditLog = {
//!     events: Vec<ComplianceAuditEvent>,   // Append-only, immutable
//!     append(action, actor, tenant) -> Uuid,
//!     query(filter) -> Vec<&Event>,
//!     export_json(filter) -> String,
//! }
//! ```
//!
//! The audit log is append-only: events cannot be modified or deleted after
//! insertion. This guarantees `AuditLogImmutability` -- a core compliance
//! property proven in the TLA+ meta-framework.
//!
//! # Example
//!
//! ```
//! use kimberlite_compliance::audit::{ComplianceAuditLog, ComplianceAuditAction, AuditQuery};
//! use uuid::Uuid;
//!
//! let mut log = ComplianceAuditLog::new();
//!
//! // Record a consent event. v0.6.2 added `terms_version` and
//! // `accepted` fields — the variant covers declines too
//! // (`accepted: false`), with `terms_version` capturing exactly
//! // which terms-of-service revision the subject responded to.
//! let event_id = log.append(
//!     ComplianceAuditAction::ConsentGranted {
//!         subject_id: "user@example.com".into(),
//!         purpose: "Marketing".into(),
//!         scope: "ContactInfo".into(),
//!         terms_version: Some("2026-05-04".into()),
//!         accepted: true,
//!     },
//!     Some("admin".into()),
//!     Some(1),
//! );
//!
//! // Query by subject
//! let query = AuditQuery::default().with_subject("user@example.com");
//! let results = log.query(&query);
//! assert_eq!(results.len(), 1);
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Audit event not found: {0}")]
    EventNotFound(Uuid),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// v0.6.2 — `#[serde(default)]` value for
/// `ComplianceAuditAction::ConsentGranted::accepted`. Pre-v0.6.2 audit
/// events had no acceptance flag; deserialize them as `true` so the
/// audit log keeps reading clean across the upgrade.
fn default_accepted_audit() -> bool {
    true
}

/// Extended audit actions covering all compliance modules.
///
/// Each variant captures the structured context needed for compliance
/// reporting and forensic analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceAuditAction {
    // -- Consent management (GDPR Article 7) --
    /// Consent was recorded for a data subject. The variant name is
    /// retained for wire/audit-format compatibility — `accepted = false`
    /// captures explicit declines, which are themselves compliance
    /// events ("subject was asked, said no, against `terms_version`").
    ConsentGranted {
        subject_id: String,
        purpose: String,
        scope: String,
        /// Terms-of-service version the subject responded to. `None`
        /// on pre-v0.6.2 events. Added in v0.6.2.
        #[serde(default)]
        terms_version: Option<String>,
        /// Whether the subject accepted (`true`, default) or declined
        /// (`false`). Pre-v0.6.2 events are acceptance-only and
        /// deserialize as `true`. Added in v0.6.2.
        #[serde(default = "default_accepted_audit")]
        accepted: bool,
    },
    /// Consent was withdrawn by a data subject
    ConsentWithdrawn {
        subject_id: String,
        consent_id: Uuid,
    },

    // -- Erasure (GDPR Article 17) --
    /// A data erasure request was submitted
    ErasureRequested {
        subject_id: String,
        request_id: Uuid,
    },
    /// Erasure completed successfully
    ErasureCompleted {
        subject_id: String,
        records_erased: u64,
        request_id: Uuid,
    },
    /// Erasure was denied under a legal exemption
    ErasureExempted {
        subject_id: String,
        request_id: Uuid,
        basis: String,
    },

    // -- Field masking --
    /// A field masking rule was applied
    FieldMasked {
        column: String,
        strategy: String,
        role: String,
    },

    // -- Breach detection (GDPR Article 33/34) --
    /// A potential data breach was detected
    BreachDetected {
        event_id: Uuid,
        severity: String,
        indicator: String,
        affected_subjects: Vec<String>,
    },
    /// Breach notification was sent to authorities/subjects
    BreachNotified {
        event_id: Uuid,
        notified_at: DateTime<Utc>,
        affected_subjects: Vec<String>,
    },
    /// A breach was resolved with remediation
    BreachResolved {
        event_id: Uuid,
        remediation: String,
        affected_subjects: Vec<String>,
    },

    // -- Data portability (GDPR Article 20) --
    /// Data was exported for a subject
    DataExported {
        subject_id: String,
        export_id: Uuid,
        format: String,
        record_count: u64,
    },

    // -- Access control --
    /// Access was granted to a resource
    AccessGranted {
        user_id: String,
        resource: String,
        role: String,
    },
    /// Access was denied to a resource
    AccessDenied {
        user_id: String,
        resource: String,
        reason: String,
    },

    // -- Policy changes --
    /// A compliance policy was changed
    PolicyChanged {
        policy_type: String,
        changed_by: String,
        details: String,
    },

    // -- PCI DSS tokenization (Requirement 3.4) --
    /// Data tokenization was applied to cardholder data
    TokenizationApplied {
        column: String,
        token_format: String,
        record_count: u64,
    },

    // -- 21 CFR Part 11 electronic signatures --
    /// An electronic record was signed (per-record Ed25519 signature)
    RecordSigned {
        record_id: String,
        signer_id: String,
        meaning: String,
    },

    // -- Break-glass emergency access (HIPAA § 164.510(b)(3) / § 164.312(a)(2)(ii)) --
    /// Emergency-override access to PHI was activated. The user attests
    /// that consent could not reasonably be obtained at the moment of
    /// care. The reason is mandatory free-text; `approval_chain` is the
    /// ordered list of authorising actors (operator → on-call manager →
    /// privacy officer, etc.). The event is the *opening* of a session;
    /// every resource touched inside it should eventually appear in the
    /// paired `BreakGlassClosed` event.
    BreakGlassActivated {
        user_id: String,
        patient_id: String,
        reason: String,
        approval_chain: Vec<String>,
        activated_at: DateTime<Utc>,
    },
    /// A break-glass session was closed. `accessed_resources` enumerates
    /// every PHI resource read while the override was active —
    /// regulators and the patient's covered entity inspect this list as
    /// part of post-hoc review. `duration_seconds` is the wall-clock
    /// length of the session.
    BreakGlassClosed {
        user_id: String,
        patient_id: String,
        activated_at: DateTime<Utc>,
        closed_at: DateTime<Utc>,
        accessed_resources: Vec<String>,
        duration_seconds: u64,
    },
}

impl ComplianceAuditAction {
    /// Returns the action type prefix for filtering (e.g., "Consent", "Erasure").
    fn action_type_prefix(&self) -> &'static str {
        match self {
            Self::ConsentGranted { .. } | Self::ConsentWithdrawn { .. } => "Consent",
            Self::ErasureRequested { .. }
            | Self::ErasureCompleted { .. }
            | Self::ErasureExempted { .. } => "Erasure",
            Self::FieldMasked { .. } => "FieldMasked",
            Self::BreachDetected { .. }
            | Self::BreachNotified { .. }
            | Self::BreachResolved { .. } => "Breach",
            Self::DataExported { .. } => "DataExported",
            Self::AccessGranted { .. } | Self::AccessDenied { .. } => "Access",
            Self::PolicyChanged { .. } => "PolicyChanged",
            Self::TokenizationApplied { .. } => "Tokenization",
            Self::RecordSigned { .. } => "RecordSigned",
            Self::BreakGlassActivated { .. } | Self::BreakGlassClosed { .. } => "BreakGlass",
        }
    }

    /// Returns the canonical action kind as a stable `&'static str`.
    ///
    /// Kept in sync with the `ComplianceAuditAction` variants. Used by
    /// the SDK query surface ([`ComplianceAuditEvent::to_sdk_entry`])
    /// and the Phase 6 wire `AuditEntry`. Safe for external callers —
    /// reveals no values, only the type of operation.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ConsentGranted { .. } => "ConsentGranted",
            Self::ConsentWithdrawn { .. } => "ConsentWithdrawn",
            Self::ErasureRequested { .. } => "ErasureRequested",
            Self::ErasureCompleted { .. } => "ErasureCompleted",
            Self::ErasureExempted { .. } => "ErasureExempted",
            Self::FieldMasked { .. } => "FieldMasked",
            Self::BreachDetected { .. } => "BreachDetected",
            Self::BreachNotified { .. } => "BreachNotified",
            Self::BreachResolved { .. } => "BreachResolved",
            Self::DataExported { .. } => "DataExported",
            Self::AccessGranted { .. } => "AccessGranted",
            Self::AccessDenied { .. } => "AccessDenied",
            Self::PolicyChanged { .. } => "PolicyChanged",
            Self::TokenizationApplied { .. } => "TokenizationApplied",
            Self::RecordSigned { .. } => "RecordSigned",
            Self::BreakGlassActivated { .. } => "BreakGlassActivated",
            Self::BreakGlassClosed { .. } => "BreakGlassClosed",
        }
    }

    /// Returns the **names** (not values) of the fields this action
    /// carries in its payload — the "what changed" without the
    /// payload itself.
    ///
    /// This is the PHI-safe projection that backs
    /// [`ComplianceAuditEvent::to_sdk_entry`] / the SDK query
    /// response. The list is stable per variant so regulators can
    /// render it in dashboards without risking leakage of the
    /// underlying values.
    ///
    /// # Invariant (v0.6.0 Tier 2 #9)
    ///
    /// Every string returned here is a **schema name** — never a
    /// value extracted from the action payload. The property test
    /// `audit_sdk_entry_never_leaks_values` enforces this over
    /// 1k random events.
    pub fn changed_field_names(&self) -> Vec<String> {
        let names: &[&str] = match self {
            Self::ConsentGranted { .. } => &[
                "subject_id",
                "purpose",
                "scope",
                "terms_version",
                "accepted",
            ],
            Self::ConsentWithdrawn { .. } => &["subject_id", "consent_id"],
            Self::ErasureRequested { .. } => &["subject_id", "request_id"],
            Self::ErasureCompleted { .. } => &["subject_id", "records_erased", "request_id"],
            Self::ErasureExempted { .. } => &["subject_id", "request_id", "basis"],
            Self::FieldMasked { .. } => &["column", "strategy", "role"],
            Self::BreachDetected { .. } => {
                &["event_id", "severity", "indicator", "affected_subjects"]
            }
            Self::BreachNotified { .. } => &["event_id", "notified_at", "affected_subjects"],
            Self::BreachResolved { .. } => &["event_id", "remediation", "affected_subjects"],
            Self::DataExported { .. } => &["subject_id", "export_id", "format", "record_count"],
            Self::AccessGranted { .. } => &["user_id", "resource", "role"],
            Self::AccessDenied { .. } => &["user_id", "resource", "reason"],
            Self::PolicyChanged { .. } => &["policy_type", "changed_by", "details"],
            Self::TokenizationApplied { .. } => &["column", "token_format", "record_count"],
            Self::RecordSigned { .. } => &["record_id", "signer_id", "meaning"],
            Self::BreakGlassActivated { .. } => &[
                "user_id",
                "patient_id",
                "reason",
                "approval_chain",
                "activated_at",
            ],
            Self::BreakGlassClosed { .. } => &[
                "user_id",
                "patient_id",
                "activated_at",
                "closed_at",
                "accessed_resources",
                "duration_seconds",
            ],
        };
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// Check if this action references the given subject identifier.
    ///
    /// Inspects all string fields that could represent a data subject.
    fn matches_subject(&self, subject_id: &str) -> bool {
        match self {
            Self::ConsentGranted {
                subject_id: sid, ..
            }
            | Self::ConsentWithdrawn {
                subject_id: sid, ..
            }
            | Self::ErasureRequested {
                subject_id: sid, ..
            }
            | Self::ErasureCompleted {
                subject_id: sid, ..
            }
            | Self::ErasureExempted {
                subject_id: sid, ..
            }
            | Self::DataExported {
                subject_id: sid, ..
            } => sid == subject_id,

            Self::AccessGranted { user_id, .. } | Self::AccessDenied { user_id, .. } => {
                user_id == subject_id
            }

            Self::PolicyChanged { changed_by, .. } => changed_by == subject_id,

            Self::RecordSigned { signer_id, .. } => signer_id == subject_id,

            Self::BreachDetected {
                affected_subjects, ..
            }
            | Self::BreachNotified {
                affected_subjects, ..
            }
            | Self::BreachResolved {
                affected_subjects, ..
            } => affected_subjects.iter().any(|s| s.as_str() == subject_id),

            // Break-glass events match either the activating user OR
            // the patient subject — both are forensically relevant.
            Self::BreakGlassActivated {
                user_id,
                patient_id,
                ..
            }
            | Self::BreakGlassClosed {
                user_id,
                patient_id,
                ..
            } => user_id == subject_id || patient_id == subject_id,

            // Actions without subject identifiers
            Self::FieldMasked { .. } | Self::TokenizationApplied { .. } => false,
        }
    }
}

/// Who performed the audit-logged action.
///
/// AUDIT-2026-04 L-2: replaces the ambiguous `Option<String>` that made
/// anonymous audit rows the accidental default. Every `append*` call
/// now names the actor explicitly — a system-generated event like
/// automatic breach detection is
/// [`Actor::System(ComponentName::BreachDetector)`][Actor::System] and is
/// forensically distinguishable from a human operator whose identity
/// simply wasn't threaded through a call site.
///
/// Serialisation-compat note: the underlying `ComplianceAuditEvent`
/// persists the actor as `Option<String>` (H-2 hash-chain records on
/// disk depend on this shape). The `Actor` enum is the canonical
/// logical surface — `ComplianceAuditEvent::actor_kind` projects the
/// stored string back to an `Actor` variant. New code should build
/// events via the typed `append_with_actor` path rather than passing
/// bare `Option<String>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    /// Authenticated human or API-key identity.
    Authenticated(String),
    /// System-generated event attributed to a named component.
    System(ComponentName),
    /// No identity — acceptable only for events that genuinely have no
    /// attributable initiator (e.g. startup-time self-audits). A bare
    /// `Actor::Anonymous` on a user-visible action is a forensic smell.
    Anonymous,
}

impl Actor {
    /// Projects the typed enum to the legacy `Option<String>` wire shape.
    /// `Authenticated(s)` → `Some(s)`, `System(c)` → `Some("system:<c>")`,
    /// `Anonymous` → `None`. Kept stable for H-2 hash-chain compatibility.
    pub fn to_legacy_string(&self) -> Option<String> {
        match self {
            Actor::Authenticated(s) => Some(s.clone()),
            Actor::System(component) => Some(format!("system:{}", component.as_str())),
            Actor::Anonymous => None,
        }
    }

    /// Inverse of [`Actor::to_legacy_string`].
    pub fn from_legacy_string(value: Option<&str>) -> Self {
        match value {
            Some(s) if s.starts_with("system:") => {
                Actor::System(ComponentName::from_str(s.trim_start_matches("system:")))
            }
            Some(s) => Actor::Authenticated(s.to_string()),
            None => Actor::Anonymous,
        }
    }
}

impl From<Option<String>> for Actor {
    fn from(value: Option<String>) -> Self {
        Actor::from_legacy_string(value.as_deref())
    }
}

/// Named system component that originated an audit event.
///
/// Use a typed variant over ad-hoc strings so regulators filtering
/// `Actor::System(...)` events see a closed set. `Other(String)` is the
/// escape hatch for one-off components that don't warrant a first-class
/// variant — new usages should graduate to their own variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentName {
    /// Automated breach-detection subsystem.
    BreachDetector,
    /// Scheduled erasure worker (GDPR Article 17).
    ErasureWorker,
    /// Consent lifecycle reconciler.
    ConsentReconciler,
    /// Any other system component — prefer a named variant where possible.
    Other(String),
}

impl ComponentName {
    /// Stable string representation used in the legacy wire shape.
    pub fn as_str(&self) -> String {
        match self {
            ComponentName::BreachDetector => "breach_detector".to_string(),
            ComponentName::ErasureWorker => "erasure_worker".to_string(),
            ComponentName::ConsentReconciler => "consent_reconciler".to_string(),
            ComponentName::Other(s) => s.clone(),
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "breach_detector" => ComponentName::BreachDetector,
            "erasure_worker" => ComponentName::ErasureWorker,
            "consent_reconciler" => ComponentName::ConsentReconciler,
            other => ComponentName::Other(other.to_string()),
        }
    }
}

/// Scope of an audit event.
///
/// AUDIT-2026-04 L-6: replaces the ambiguous `Option<u64>` tenant_id.
/// Untenanted events are now explicitly `Global` or `System` rather
/// than defaulting to `None` and silently appearing in every tenant's
/// audit view (or, depending on the filter predicate, none).
///
/// Serialisation-compat note: persisted events continue to carry the
/// raw `Option<u64>` field; [`ComplianceAuditEvent::scope`] projects it
/// to this enum. `Tenant(t)` ↔ `Some(t)`, both `Global` and `System`
/// ↔ `None` (distinguished by the actor at projection time — a
/// `System` scope implies `actor_kind()` is `Actor::System(_)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// No tenant binding; visible to all tenant filters.
    Global,
    /// System-level event (maintenance, cross-tenant admin).
    System,
    /// Bound to a specific tenant.
    Tenant(kimberlite_types::TenantId),
}

impl Scope {
    /// Projects the enum to the legacy `Option<u64>` wire shape used on
    /// disk. `Tenant(t)` → `Some(t.into())`; `Global`/`System` both
    /// serialise as `None` — the actor variant disambiguates them at
    /// read time.
    pub fn to_legacy_u64(self) -> Option<u64> {
        match self {
            Scope::Tenant(tenant_id) => Some(u64::from(tenant_id)),
            Scope::Global | Scope::System => None,
        }
    }

    /// Inverse of [`Scope::to_legacy_u64`], paired with the actor for
    /// `None`-disambiguation (`System(_)` actor ⇒ `Scope::System`,
    /// otherwise `Scope::Global`).
    pub fn from_legacy(tenant_id: Option<u64>, actor: &Actor) -> Self {
        match tenant_id {
            Some(t) => Scope::Tenant(kimberlite_types::TenantId::new(t)),
            None => match actor {
                Actor::System(_) => Scope::System,
                _ => Scope::Global,
            },
        }
    }
}

impl From<Option<u64>> for Scope {
    fn from(value: Option<u64>) -> Self {
        match value {
            Some(t) => Scope::Tenant(kimberlite_types::TenantId::new(t)),
            None => Scope::Global,
        }
    }
}

/// A single audit event with full context.
///
/// Once appended to the log, an event is immutable. All fields are set at
/// creation time and cannot be changed.
///
/// # AUDIT-2026-04 H-2 — hash chain
///
/// `prev_hash` captures the `event_hash` of the previous event (or the
/// zero hash for the first event). `event_hash` is
/// `SHA-256(prev_hash || canonical_bytes(all other fields))` — where
/// canonical bytes use postcard, a deterministic binary serializer.
/// The chain makes the log *tamper-evident*: mutating any event breaks
/// the downstream chain and `ComplianceAuditLog::verify_chain` flags
/// the earliest break.
///
/// Prior to AUDIT-2026-04, docs advertised "immutable, hash-chained,
/// tamper-evident" but the struct had neither hash field and the log
/// was a bare `Vec`. See `docs/compliance/certification-package.md:362`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditEvent {
    /// Unique event identifier
    pub event_id: Uuid,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// What happened
    pub action: ComplianceAuditAction,
    /// Who performed the action (operator, system, etc.)
    pub actor: Option<String>,
    /// Tenant context (multi-tenant isolation)
    pub tenant_id: Option<u64>,
    /// Source IP address for access auditing
    pub ip_address: Option<String>,
    /// Correlation ID linking related events across a workflow
    pub correlation_id: Option<Uuid>,
    /// Source country for location-based audit trail (ISO 3166-1 alpha-2)
    pub source_country: Option<String>,
    /// AUDIT-2026-04 H-2 — chain link to previous event.
    ///
    /// `[0; 32]` for the first event in a log; otherwise the previous
    /// event's `event_hash`. `#[serde(default)]` so pre-H-2 records
    /// on disk still deserialize (they are treated as chain-start).
    #[serde(default = "zero_hash")]
    pub prev_hash: [u8; 32],
    /// AUDIT-2026-04 H-2 — this event's binding hash.
    ///
    /// Computed as `SHA-256(prev_hash || canonical_body_bytes)` where
    /// `canonical_body_bytes` is a deterministic postcard
    /// serialization of the event minus this field.
    #[serde(default = "zero_hash")]
    pub event_hash: [u8; 32],
}

fn zero_hash() -> [u8; 32] {
    [0u8; 32]
}

impl ComplianceAuditEvent {
    /// Returns the typed [`Actor`] projection of the stored `actor`
    /// string. AUDIT-2026-04 L-2.
    pub fn actor_kind(&self) -> Actor {
        Actor::from_legacy_string(self.actor.as_deref())
    }

    /// Returns the typed [`Scope`] projection of the stored `tenant_id`,
    /// using the actor to disambiguate `None` between `Scope::Global`
    /// and `Scope::System`. AUDIT-2026-04 L-6.
    pub fn scope(&self) -> Scope {
        Scope::from_legacy(self.tenant_id, &self.actor_kind())
    }

    /// **v0.6.0 Tier 2 #9** — project to the SDK-safe
    /// [`AuditSdkEntry`].
    ///
    /// The projection **strips every value** from the action payload
    /// and keeps only the field names via
    /// [`ComplianceAuditAction::changed_field_names`]. It also extracts
    /// a structured subject identifier (the same one the filter
    /// layer matches on) so callers can correlate without re-parsing
    /// the action.
    ///
    /// Use this at the wire boundary so PHI / before-values never
    /// reach an SDK caller. The property test
    /// `audit_sdk_entry_never_leaks_values` enforces leakage-freedom
    /// over 1k randomised events.
    pub fn to_sdk_entry(&self) -> AuditSdkEntry {
        AuditSdkEntry {
            event_id: self.event_id,
            actor: self.actor.clone(),
            action: self.action.kind().to_string(),
            subject_id: subject_id_of(&self.action),
            correlation_id: self.correlation_id,
            request_id: request_id_of(&self.action),
            occurred_at: self.timestamp,
            reason: reason_of(&self.action),
            changed_field_names: self.action.changed_field_names(),
        }
    }
}

/// **v0.6.0 Tier 2 #9** — the SDK-safe projection of a
/// [`ComplianceAuditEvent`].
///
/// Carries **no values** from the action payload — only
/// [`Self::changed_field_names`] lists the *names* of what was
/// recorded. Handing this shape across the wire, FFI, or SDK
/// boundary is PHI-safe by construction: nothing here can encode a
/// before/after value.
///
/// The response type mirrors the client SDKs' typed row:
///
/// ```text
/// { actor, action, subjectId, correlationId, requestId,
///   occurredAt, reason, changedFieldNames }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSdkEntry {
    /// Unique event identifier (same UUID as the underlying
    /// [`ComplianceAuditEvent::event_id`]).
    pub event_id: Uuid,
    /// Who performed the action (legacy string form). Typically an
    /// email, component name, or `None` for anonymous events.
    pub actor: Option<String>,
    /// The action kind as a stable string (e.g. `"ConsentGranted"`).
    /// Matches [`ComplianceAuditAction::kind`].
    pub action: String,
    /// The data subject this action targets, when the action has one.
    /// Actions that don't reference a subject (e.g. `FieldMasked`)
    /// return `None`.
    pub subject_id: Option<String>,
    /// Correlation id linking related events across a workflow.
    pub correlation_id: Option<Uuid>,
    /// Request identifier — populated for actions that carry one
    /// (erasure lifecycle), `None` otherwise.
    pub request_id: Option<Uuid>,
    /// When the event occurred (UTC).
    pub occurred_at: DateTime<Utc>,
    /// Free-form justification for the access — populated for
    /// `ErasureExempted` where the `basis` string is the reason.
    /// `None` for actions that don't carry a reason.
    pub reason: Option<String>,
    /// **Field names only.** Never values. See
    /// [`ComplianceAuditAction::changed_field_names`].
    pub changed_field_names: Vec<String>,
}

/// Extracts the subject id from an action, if it carries one.
///
/// Mirrors the subject-matcher in [`ComplianceAuditAction::matches_subject`].
/// Actions without a subject field (e.g. `FieldMasked`,
/// `TokenizationApplied`) return `None`.
fn subject_id_of(a: &ComplianceAuditAction) -> Option<String> {
    match a {
        ComplianceAuditAction::ConsentGranted { subject_id, .. }
        | ComplianceAuditAction::ConsentWithdrawn { subject_id, .. }
        | ComplianceAuditAction::ErasureRequested { subject_id, .. }
        | ComplianceAuditAction::ErasureCompleted { subject_id, .. }
        | ComplianceAuditAction::ErasureExempted { subject_id, .. }
        | ComplianceAuditAction::DataExported { subject_id, .. } => Some(subject_id.clone()),
        ComplianceAuditAction::AccessGranted { user_id, .. }
        | ComplianceAuditAction::AccessDenied { user_id, .. } => Some(user_id.clone()),
        ComplianceAuditAction::RecordSigned { signer_id, .. } => Some(signer_id.clone()),
        // Break-glass subject is the patient whose PHI was touched —
        // the activating user is captured as the actor.
        ComplianceAuditAction::BreakGlassActivated { patient_id, .. }
        | ComplianceAuditAction::BreakGlassClosed { patient_id, .. } => Some(patient_id.clone()),
        ComplianceAuditAction::FieldMasked { .. }
        | ComplianceAuditAction::PolicyChanged { .. }
        | ComplianceAuditAction::BreachDetected { .. }
        | ComplianceAuditAction::BreachNotified { .. }
        | ComplianceAuditAction::BreachResolved { .. }
        | ComplianceAuditAction::TokenizationApplied { .. } => None,
    }
}

/// Extracts the request id carried by erasure-lifecycle actions.
fn request_id_of(a: &ComplianceAuditAction) -> Option<Uuid> {
    match a {
        ComplianceAuditAction::ErasureRequested { request_id, .. }
        | ComplianceAuditAction::ErasureCompleted { request_id, .. }
        | ComplianceAuditAction::ErasureExempted { request_id, .. } => Some(*request_id),
        _ => None,
    }
}

/// Extracts a free-form reason from actions that carry one — only
/// `ErasureExempted` does in the current shape (the GDPR Article
/// 17(3) exemption basis).
fn reason_of(a: &ComplianceAuditAction) -> Option<String> {
    match a {
        ComplianceAuditAction::ErasureExempted { basis, .. } => Some(basis.clone()),
        _ => None,
    }
}

/// Query filter for the audit log.
///
/// All fields are optional. When multiple fields are set, they are combined
/// with AND logic. Use builder methods for ergonomic construction.
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
    pub subject_id: Option<String>,
    pub action_type: Option<String>,
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub actor: Option<String>,
    pub tenant_id: Option<u64>,
    pub limit: Option<usize>,
}

impl AuditQuery {
    /// Filter by data subject identifier.
    pub fn with_subject(mut self, subject_id: &str) -> Self {
        self.subject_id = Some(subject_id.to_string());
        self
    }

    /// Filter by action type prefix (e.g., "Consent", "Erasure", "Breach").
    pub fn with_action_type(mut self, action_type: &str) -> Self {
        self.action_type = Some(action_type.to_string());
        self
    }

    /// Filter to events within a time range (inclusive).
    pub fn with_time_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.time_from = Some(from);
        self.time_to = Some(to);
        self
    }

    /// Filter by the actor who performed the action (legacy string form).
    pub fn with_actor(mut self, actor: &str) -> Self {
        self.actor = Some(actor.to_string());
        self
    }

    /// Filter by tenant ID.
    pub fn with_tenant(mut self, tenant_id: u64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Filter by typed [`Actor`]. Equivalent to `with_actor` under the
    /// hood (via [`Actor::to_legacy_string`]), but preserves the
    /// System/Anonymous/Authenticated distinction at the API boundary.
    /// AUDIT-2026-04 L-2.
    pub fn with_actor_kind(mut self, actor: &Actor) -> Self {
        self.actor = actor.to_legacy_string();
        self
    }

    /// Filter by typed [`Scope`]. `Scope::Global` and `Scope::System`
    /// both translate to "no tenant filter" on the legacy wire field;
    /// callers that need to distinguish them should additionally set
    /// `with_actor_kind`. AUDIT-2026-04 L-6.
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.tenant_id = scope.to_legacy_u64();
        self
    }

    /// Limit the number of results returned.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Immutable, append-only audit log for compliance operations.
///
/// Satisfies:
/// - SOC 2 CC7.2: All compliance-relevant changes are recorded
/// - ISO 27001 A.12.4.1: User activities and security events are logged
/// - GDPR Article 30: Records of processing activities
///
/// The log enforces append-only semantics: events can be added but never
/// modified or removed. This is a structural guarantee -- the API provides
/// no mutation or deletion methods.
#[derive(Debug, Default)]
pub struct ComplianceAuditLog {
    events: Vec<ComplianceAuditEvent>,
    /// AUDIT-2026-04 H-2 — chain-head hash, updated on every append.
    ///
    /// Starts at `[0; 32]`. `chain_head == self.events.last().event_hash`
    /// is an invariant `verify_chain` asserts.
    chain_head: [u8; 32],
}

/// AUDIT-2026-04 H-2 — error variants for chain-verification failures.
///
/// These are intentionally detailed so a real breach forensics team
/// can pinpoint where the chain broke and which field was mutated.
#[derive(Debug, PartialEq, Eq)]
pub enum AuditChainError {
    /// Event at `index` has a `prev_hash` that doesn't match the
    /// previous event's `event_hash`. Usually means an event was
    /// inserted/removed mid-chain.
    PrevHashMismatch { index: usize },
    /// Event at `index` has a stored `event_hash` that doesn't match
    /// a fresh recomputation. Means the event's body was mutated
    /// after signing.
    EventHashMismatch { index: usize },
    /// The first event's `prev_hash` is not the zero-hash — log head
    /// was truncated.
    FirstEventPrevHashNonZero,
    /// `log.chain_head` doesn't equal the last event's `event_hash`.
    ChainHeadMismatch,
    /// postcard serialization failed (should never happen for valid
    /// data; indicates corruption or a types refactor).
    CanonicalizationFailed,
}

impl std::fmt::Display for AuditChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrevHashMismatch { index } => write!(
                f,
                "audit chain break: event[{index}].prev_hash != event[{prev}].event_hash",
                prev = index.saturating_sub(1)
            ),
            Self::EventHashMismatch { index } => {
                write!(f, "audit chain break: event[{index}] body has been mutated")
            }
            Self::FirstEventPrevHashNonZero => {
                f.write_str("audit chain break: head event prev_hash is nonzero (log truncated?)")
            }
            Self::ChainHeadMismatch => {
                f.write_str("audit chain break: log.chain_head != last event's event_hash")
            }
            Self::CanonicalizationFailed => {
                f.write_str("audit chain break: canonical serialization failed")
            }
        }
    }
}

impl std::error::Error for AuditChainError {}

impl ComplianceAuditLog {
    /// Create a new empty audit log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an audit event and return its unique ID.
    ///
    /// This is the primary entry point for recording compliance events.
    /// The event is timestamped at the moment of insertion.
    ///
    /// # Assertions
    ///
    /// - Post: event count increases by exactly 1
    pub fn append(
        &mut self,
        action: ComplianceAuditAction,
        actor: Option<String>,
        tenant_id: Option<u64>,
    ) -> Uuid {
        self.append_with_context(action, actor, tenant_id, None, None)
    }

    /// Typed append — the preferred surface for new code.
    ///
    /// AUDIT-2026-04 L-2 / L-6: callers name the actor and scope via
    /// the [`Actor`] and [`Scope`] enums rather than passing
    /// `Option<String>` / `Option<u64>` that silently defaulted to
    /// anonymous/global semantics.
    pub fn append_with_actor(
        &mut self,
        action: ComplianceAuditAction,
        actor: Actor,
        scope: Scope,
    ) -> Uuid {
        self.append_with_context(
            action,
            actor.to_legacy_string(),
            scope.to_legacy_u64(),
            None,
            None,
        )
    }

    /// Append an audit event with full contextual metadata.
    ///
    /// Use this when IP address or correlation ID are available.
    ///
    /// # Assertions
    ///
    /// - Post: event count increases by exactly 1
    /// - Post: the returned ID can be retrieved with `get_event`
    pub fn append_with_context(
        &mut self,
        action: ComplianceAuditAction,
        actor: Option<String>,
        tenant_id: Option<u64>,
        ip_address: Option<String>,
        correlation_id: Option<Uuid>,
    ) -> Uuid {
        let count_before = self.events.len();

        // Record coverage for each action variant (SOMETIMES properties).
        match &action {
            ComplianceAuditAction::ConsentGranted { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.consent_granted",
                    "audit log records a ConsentGranted event"
                );
            }
            ComplianceAuditAction::ConsentWithdrawn { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.consent_withdrawn",
                    "audit log records a ConsentWithdrawn event"
                );
            }
            ComplianceAuditAction::ErasureRequested { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.erasure_requested",
                    "audit log records an ErasureRequested event"
                );
            }
            ComplianceAuditAction::ErasureCompleted { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.erasure_completed",
                    "audit log records an ErasureCompleted event"
                );
            }
            ComplianceAuditAction::ErasureExempted { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.erasure_exempted",
                    "audit log records an ErasureExempted event"
                );
            }
            ComplianceAuditAction::FieldMasked { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.field_masked",
                    "audit log records a FieldMasked event"
                );
            }
            ComplianceAuditAction::BreachDetected { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.breach_detected",
                    "audit log records a BreachDetected event"
                );
            }
            ComplianceAuditAction::BreachNotified { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.breach_notified",
                    "audit log records a BreachNotified event"
                );
            }
            ComplianceAuditAction::BreachResolved { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.breach_resolved",
                    "audit log records a BreachResolved event"
                );
            }
            ComplianceAuditAction::DataExported { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.data_exported",
                    "audit log records a DataExported event"
                );
            }
            ComplianceAuditAction::AccessGranted { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.access_granted",
                    "audit log records an AccessGranted event"
                );
            }
            ComplianceAuditAction::AccessDenied { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.access_denied",
                    "audit log records an AccessDenied event"
                );
            }
            ComplianceAuditAction::PolicyChanged { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.policy_changed",
                    "audit log records a PolicyChanged event"
                );
            }
            ComplianceAuditAction::TokenizationApplied { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.tokenization_applied",
                    "audit log records a TokenizationApplied event"
                );
            }
            ComplianceAuditAction::RecordSigned { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.record_signed",
                    "audit log records a RecordSigned event"
                );
            }
            ComplianceAuditAction::BreakGlassActivated { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.break_glass_activated",
                    "audit log records a BreakGlassActivated event"
                );
            }
            ComplianceAuditAction::BreakGlassClosed { .. } => {
                kimberlite_properties::reached!(
                    "compliance.audit.break_glass_closed",
                    "audit log records a BreakGlassClosed event"
                );
            }
        }

        let event_id = Uuid::new_v4();
        // AUDIT-2026-04 H-2: compute the chain link. The event's
        // `prev_hash` is the current chain head; its `event_hash` is
        // computed over (prev_hash || canonical_body_bytes). Then the
        // chain head advances to this event's hash.
        let prev_hash = self.chain_head;
        let mut event = ComplianceAuditEvent {
            event_id,
            timestamp: Utc::now(),
            action,
            actor,
            tenant_id,
            ip_address,
            correlation_id,
            source_country: None,
            prev_hash,
            event_hash: [0u8; 32], // filled in below
        };
        let event_hash = compute_event_hash(&event)
            .expect("postcard serialization of ComplianceAuditEvent must not fail");
        event.event_hash = event_hash;
        self.chain_head = event_hash;

        self.events.push(event);

        // Post-condition: exactly one event was added
        assert_eq!(
            self.events.len(),
            count_before + 1,
            "Audit log append must increase event count by exactly 1"
        );

        // ALWAYS: append-only log grows monotonically (offset never decreases).
        kimberlite_properties::always!(
            self.events.len() > count_before,
            "compliance.audit.append_only_monotonic",
            "audit log length must increase monotonically on append"
        );

        // NEVER: the event we just appended could already have been retrievable
        // before insertion (fresh UUID collision would violate immutability).
        kimberlite_properties::never!(
            count_before > self.events.len(),
            "compliance.audit.no_shrink",
            "audit log must never shrink across an append"
        );

        event_id
    }

    /// Query events matching the given filter.
    ///
    /// All filter fields use AND logic. An empty query returns all events.
    /// Results are returned in insertion order (chronological).
    pub fn query(&self, filter: &AuditQuery) -> Vec<&ComplianceAuditEvent> {
        let mut results: Vec<&ComplianceAuditEvent> = self
            .events
            .iter()
            .filter(|event| Self::matches_filter(event, filter))
            .collect();

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        results
    }

    /// Look up a single event by its unique ID.
    pub fn get_event(&self, event_id: Uuid) -> Option<&ComplianceAuditEvent> {
        self.events.iter().find(|e| e.event_id == event_id)
    }

    /// Return all events recorded since the given timestamp (inclusive).
    pub fn events_since(&self, since: DateTime<Utc>) -> Vec<&ComplianceAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= since)
            .collect()
    }

    /// Return all events that reference the given data subject.
    ///
    /// Inspects the action payload of each event to find matching subject
    /// identifiers, user IDs, or actor fields.
    pub fn events_for_subject(&self, subject_id: &str) -> Vec<&ComplianceAuditEvent> {
        assert!(
            !subject_id.is_empty(),
            "subject_id must not be empty for subject query"
        );

        self.events
            .iter()
            .filter(|e| e.action.matches_subject(subject_id))
            .collect()
    }

    /// Total number of events in the log.
    pub fn count(&self) -> usize {
        self.events.len()
    }

    /// Export filtered events as a JSON array string.
    ///
    /// Useful for compliance reporting, external audit tools, and SIEM
    /// integration.
    pub fn export_json(&self, filter: &AuditQuery) -> Result<String> {
        let events = self.query(filter);
        serde_json::to_string_pretty(&events).map_err(AuditError::from)
    }

    /// Check whether a single event matches all active filter criteria.
    fn matches_filter(event: &ComplianceAuditEvent, filter: &AuditQuery) -> bool {
        // Subject filter
        if let Some(ref subject_id) = filter.subject_id {
            if !event.action.matches_subject(subject_id) {
                return false;
            }
        }

        // Action type prefix filter
        if let Some(ref action_type) = filter.action_type {
            if !event
                .action
                .action_type_prefix()
                .starts_with(action_type.as_str())
            {
                return false;
            }
        }

        // Time range filter (inclusive)
        if let Some(from) = filter.time_from {
            if event.timestamp < from {
                return false;
            }
        }
        if let Some(to) = filter.time_to {
            if event.timestamp > to {
                return false;
            }
        }

        // Actor filter
        if let Some(ref actor) = filter.actor {
            match &event.actor {
                Some(event_actor) if event_actor == actor => {}
                _ => return false,
            }
        }

        // Tenant filter
        if let Some(tenant_id) = filter.tenant_id {
            match event.tenant_id {
                Some(event_tenant) if event_tenant == tenant_id => {}
                _ => return false,
            }
        }

        true
    }

    // ========================================================================
    // AUDIT-2026-04 H-2 — hash chain verification
    // ========================================================================

    /// Current chain-head hash. After `N` appends this is the
    /// `event_hash` of event `N-1`. Empty log returns the zero hash.
    pub fn chain_head(&self) -> [u8; 32] {
        self.chain_head
    }

    /// **AUDIT-2026-04 H-2.** Walk the entire chain and verify:
    ///
    /// 1. `events[0].prev_hash == [0; 32]` — the chain starts fresh.
    /// 2. For every `i >= 1`:
    ///    `events[i].prev_hash == events[i-1].event_hash`.
    /// 3. For every `i`:
    ///    `events[i].event_hash == SHA-256(prev_hash || canonical_body)`.
    /// 4. `self.chain_head == events.last().event_hash` (or zero for
    ///    empty).
    ///
    /// Any failure returns a specific `AuditChainError` variant naming
    /// the earliest broken event.
    ///
    /// This is the mechanism that makes the log *tamper-evident* —
    /// any out-of-band mutation (disk corruption, adversarial edit,
    /// roll-forward attack) surfaces at a well-defined event index.
    pub fn verify_chain(&self) -> std::result::Result<(), AuditChainError> {
        if self.events.is_empty() {
            if self.chain_head != [0u8; 32] {
                return Err(AuditChainError::ChainHeadMismatch);
            }
            return Ok(());
        }

        let first = &self.events[0];
        if first.prev_hash != [0u8; 32] {
            return Err(AuditChainError::FirstEventPrevHashNonZero);
        }

        let mut prev_hash = [0u8; 32];
        for (i, event) in self.events.iter().enumerate() {
            if event.prev_hash != prev_hash {
                return Err(AuditChainError::PrevHashMismatch { index: i });
            }
            let recomputed =
                compute_event_hash(event).map_err(|_| AuditChainError::CanonicalizationFailed)?;
            if recomputed != event.event_hash {
                return Err(AuditChainError::EventHashMismatch { index: i });
            }
            prev_hash = event.event_hash;
        }
        if prev_hash != self.chain_head {
            return Err(AuditChainError::ChainHeadMismatch);
        }
        Ok(())
    }
}

/// **AUDIT-2026-04 H-2** — canonical event hash.
///
/// Computes `SHA-256(prev_hash || canonical_body_bytes)` where
/// canonical_body_bytes is a deterministic postcard serialization of
/// the event with `event_hash` zeroed (so the field we're computing
/// doesn't feed into its own input).
///
/// Pure function (PRESSURECRAFT §1 FCIS) — no state, no IO.
fn compute_event_hash(
    event: &ComplianceAuditEvent,
) -> std::result::Result<[u8; 32], postcard::Error> {
    use sha2::{Digest, Sha256};

    // Serialize the event with event_hash zeroed, so the hash covers
    // every field *except* the hash field itself.
    let mut canonical_body = event.clone();
    canonical_body.event_hash = [0u8; 32];
    let bytes = postcard::to_allocvec(&canonical_body)?;

    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(event.prev_hash);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_append_event() {
        let mut log = ComplianceAuditLog::new();
        assert_eq!(log.count(), 0);

        let event_id = log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "user@example.com".into(),
                purpose: "Marketing".into(),
                scope: "ContactInfo".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(1),
        );

        assert_eq!(log.count(), 1);

        let event = log
            .get_event(event_id)
            .expect("event must exist after append");
        assert_eq!(event.event_id, event_id);
        assert_eq!(event.actor.as_deref(), Some("admin"));
        assert_eq!(event.tenant_id, Some(1));
    }

    #[test]
    fn test_query_by_subject() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "alice@example.com".into(),
                purpose: "Analytics".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::ErasureRequested {
                subject_id: "bob@example.com".into(),
                request_id: Uuid::new_v4(),
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::ConsentWithdrawn {
                subject_id: "alice@example.com".into(),
                consent_id: Uuid::new_v4(),
            },
            None,
            None,
        );

        let query = AuditQuery::default().with_subject("alice@example.com");
        let results = log.query(&query);
        assert_eq!(results.len(), 2, "should find both events for alice");

        let query = AuditQuery::default().with_subject("bob@example.com");
        let results = log.query(&query);
        assert_eq!(results.len(), 1, "should find one event for bob");

        let query = AuditQuery::default().with_subject("nobody@example.com");
        let results = log.query(&query);
        assert_eq!(
            results.len(),
            0,
            "should find no events for unknown subject"
        );
    }

    #[test]
    fn test_query_by_action_type() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "user@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::ConsentWithdrawn {
                subject_id: "user@example.com".into(),
                consent_id: Uuid::new_v4(),
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::ErasureRequested {
                subject_id: "user@example.com".into(),
                request_id: Uuid::new_v4(),
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::BreachDetected {
                event_id: Uuid::new_v4(),
                severity: "High".into(),
                indicator: "unusual_access".into(),
                affected_subjects: vec![],
            },
            None,
            None,
        );

        // "Consent" prefix should match ConsentGranted and ConsentWithdrawn
        let query = AuditQuery::default().with_action_type("Consent");
        let results = log.query(&query);
        assert_eq!(results.len(), 2, "Consent prefix should match 2 events");

        // "Erasure" prefix should match ErasureRequested
        let query = AuditQuery::default().with_action_type("Erasure");
        let results = log.query(&query);
        assert_eq!(results.len(), 1, "Erasure prefix should match 1 event");

        // "Breach" prefix should match BreachDetected
        let query = AuditQuery::default().with_action_type("Breach");
        let results = log.query(&query);
        assert_eq!(results.len(), 1, "Breach prefix should match 1 event");
    }

    #[test]
    fn test_query_by_time_range() {
        let mut log = ComplianceAuditLog::new();

        // Insert events with known timing
        let before = Utc::now();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "user@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        let after_first = Utc::now();

        // Use events_since to verify time-based filtering
        let since_before = log.events_since(before);
        assert_eq!(since_before.len(), 1, "event should be after 'before'");

        // Query with time range that includes the event
        let query = AuditQuery::default().with_time_range(before, after_first);
        let results = log.query(&query);
        assert_eq!(results.len(), 1, "event should be in range");

        // Query with time range in the past
        let past_start = before - Duration::hours(2);
        let past_end = before - Duration::hours(1);
        let query = AuditQuery::default().with_time_range(past_start, past_end);
        let results = log.query(&query);
        assert_eq!(results.len(), 0, "no events should be in past range");
    }

    #[test]
    fn test_query_by_actor() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::PolicyChanged {
                policy_type: "retention".into(),
                changed_by: "cto".into(),
                details: "extended to 7 years".into(),
            },
            Some("admin_alice".into()),
            None,
        );

        log.append(
            ComplianceAuditAction::AccessGranted {
                user_id: "new_hire".into(),
                resource: "production_db".into(),
                role: "reader".into(),
            },
            Some("admin_bob".into()),
            None,
        );

        let query = AuditQuery::default().with_actor("admin_alice");
        let results = log.query(&query);
        assert_eq!(results.len(), 1);

        let query = AuditQuery::default().with_actor("admin_bob");
        let results = log.query(&query);
        assert_eq!(results.len(), 1);

        let query = AuditQuery::default().with_actor("unknown");
        let results = log.query(&query);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_immutability() {
        let mut log = ComplianceAuditLog::new();

        let event_id = log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "user@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(1),
        );

        // Retrieve event -- we only get a shared reference
        let event = log.get_event(event_id).expect("event must exist");
        let original_timestamp = event.timestamp;
        let original_actor = event.actor.clone();

        // Append another event -- the first event must be unchanged
        log.append(
            ComplianceAuditAction::ErasureRequested {
                subject_id: "other@example.com".into(),
                request_id: Uuid::new_v4(),
            },
            Some("other_admin".into()),
            None,
        );

        let event = log
            .get_event(event_id)
            .expect("original event must still exist");
        assert_eq!(event.timestamp, original_timestamp);
        assert_eq!(event.actor, original_actor);
        assert_eq!(log.count(), 2);
    }

    #[test]
    fn test_export_json() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::AccessGranted {
                user_id: "alice".into(),
                resource: "secrets".into(),
                role: "admin".into(),
            },
            Some("system".into()),
            Some(42),
        );

        log.append(
            ComplianceAuditAction::AccessDenied {
                user_id: "mallory".into(),
                resource: "secrets".into(),
                reason: "insufficient_permissions".into(),
            },
            Some("system".into()),
            Some(42),
        );

        let json = log
            .export_json(&AuditQuery::default())
            .expect("export must succeed");

        // Verify it's valid JSON by parsing it back
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&json).expect("exported JSON must parse");
        assert_eq!(parsed.len(), 2);

        // Verify content
        assert!(json.contains("AccessGranted"));
        assert!(json.contains("AccessDenied"));
        assert!(json.contains("alice"));
        assert!(json.contains("mallory"));
    }

    #[test]
    fn test_correlation_id() {
        let mut log = ComplianceAuditLog::new();
        let correlation = Uuid::new_v4();

        // Two events sharing a correlation ID (e.g., breach lifecycle)
        let detect_id = log.append_with_context(
            ComplianceAuditAction::BreachDetected {
                event_id: Uuid::new_v4(),
                severity: "Critical".into(),
                indicator: "exfiltration_pattern".into(),
                affected_subjects: vec![],
            },
            Some("ids_system".into()),
            Some(1),
            Some("10.0.0.1".into()),
            Some(correlation),
        );

        let notify_id = log.append_with_context(
            ComplianceAuditAction::BreachNotified {
                event_id: Uuid::new_v4(),
                notified_at: Utc::now(),
                affected_subjects: vec![],
            },
            Some("ids_system".into()),
            Some(1),
            Some("10.0.0.1".into()),
            Some(correlation),
        );

        // An unrelated event
        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "unrelated@example.com".into(),
                purpose: "Analytics".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        let detect_event = log.get_event(detect_id).expect("detect event must exist");
        let notify_event = log.get_event(notify_id).expect("notify event must exist");

        assert_eq!(detect_event.correlation_id, Some(correlation));
        assert_eq!(notify_event.correlation_id, Some(correlation));
        assert_eq!(detect_event.correlation_id, notify_event.correlation_id);

        // Verify ip_address was recorded
        assert_eq!(detect_event.ip_address.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_empty_query_returns_all() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "a@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::ErasureRequested {
                subject_id: "b@example.com".into(),
                request_id: Uuid::new_v4(),
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::BreachDetected {
                event_id: Uuid::new_v4(),
                severity: "Low".into(),
                indicator: "anomaly".into(),
                affected_subjects: vec![],
            },
            None,
            None,
        );

        let query = AuditQuery::default();
        let results = log.query(&query);
        assert_eq!(results.len(), 3, "empty query must return all events");
        assert_eq!(results.len(), log.count());
    }

    #[test]
    fn test_query_with_limit() {
        let mut log = ComplianceAuditLog::new();

        for i in 0..10 {
            log.append(
                ComplianceAuditAction::AccessGranted {
                    user_id: format!("user_{i}"),
                    resource: "db".into(),
                    role: "reader".into(),
                },
                None,
                None,
            );
        }

        let query = AuditQuery::default().with_limit(3);
        let results = log.query(&query);
        assert_eq!(results.len(), 3, "limit should cap results");

        // Results should be the first 3 (insertion order)
        assert!(results[0].action.matches_subject("user_0"));
    }

    #[test]
    fn test_events_for_subject() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "target@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::DataExported {
                subject_id: "target@example.com".into(),
                export_id: Uuid::new_v4(),
                format: "JSON".into(),
                record_count: 42,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::AccessDenied {
                user_id: "other@example.com".into(),
                resource: "db".into(),
                reason: "no_role".into(),
            },
            None,
            None,
        );

        let results = log.events_for_subject("target@example.com");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_combined_filters() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "alice@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(1),
        );

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "alice@example.com".into(),
                purpose: "Analytics".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(2),
        );

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "bob@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(1),
        );

        // Combine subject + tenant filter
        let query = AuditQuery::default()
            .with_subject("alice@example.com")
            .with_tenant(1);
        let results = log.query(&query);
        assert_eq!(
            results.len(),
            1,
            "only alice's event in tenant 1 should match"
        );
    }

    #[test]
    fn test_export_json_with_filter() {
        let mut log = ComplianceAuditLog::new();

        log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "user@example.com".into(),
                purpose: "Marketing".into(),
                scope: "AllData".into(),
                terms_version: None,
                accepted: true,
            },
            None,
            None,
        );

        log.append(
            ComplianceAuditAction::BreachDetected {
                event_id: Uuid::new_v4(),
                severity: "High".into(),
                indicator: "anomaly".into(),
                affected_subjects: vec![],
            },
            None,
            None,
        );

        // Export only consent events
        let query = AuditQuery::default().with_action_type("Consent");
        let json = log.export_json(&query).expect("export must succeed");

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).expect("JSON must parse");
        assert_eq!(parsed.len(), 1);
    }

    // ========================================================================
    // AUDIT-2026-04 H-2 — hash chain tests
    // ========================================================================

    fn mk_consent_action(subject: &str) -> ComplianceAuditAction {
        ComplianceAuditAction::ConsentGranted {
            subject_id: subject.into(),
            purpose: "Marketing".into(),
            scope: "ContactInfo".into(),
            terms_version: None,
            accepted: true,
        }
    }

    /// Baseline: empty log has zero chain head and verifies.
    #[test]
    fn chain_head_is_zero_for_empty_log() {
        let log = ComplianceAuditLog::new();
        assert_eq!(log.chain_head(), [0u8; 32]);
        assert!(log.verify_chain().is_ok());
    }

    /// A fresh append produces a non-zero chain head that points at
    /// the stored event's event_hash, and the chain verifies.
    #[test]
    fn single_append_produces_valid_chain() {
        let mut log = ComplianceAuditLog::new();
        let id = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let head = log.chain_head();
        assert_ne!(head, [0u8; 32], "chain head must advance on append");
        let event = log.get_event(id).unwrap();
        assert_eq!(event.event_hash, head);
        assert_eq!(event.prev_hash, [0u8; 32]);
        log.verify_chain().expect("fresh log must verify");
    }

    /// Multi-event chain: prev_hash of event N equals event_hash of
    /// event N-1. The chain verifies, and the chain head matches the
    /// last event's event_hash.
    #[test]
    fn multi_event_chain_links_consecutively() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("b@example.com"), None, Some(2));
        let _ = log.append(mk_consent_action("c@example.com"), None, Some(3));

        let events = log.query(&AuditQuery::default());
        assert_eq!(events.len(), 3);

        assert_eq!(events[0].prev_hash, [0u8; 32]);
        assert_eq!(events[1].prev_hash, events[0].event_hash);
        assert_eq!(events[2].prev_hash, events[1].event_hash);
        assert_eq!(log.chain_head(), events[2].event_hash);

        log.verify_chain().expect("chain of 3 must verify");
    }

    /// AUDIT-2026-04 H-2 critical: tampering with an event body
    /// breaks the chain — `verify_chain` pinpoints the broken event.
    #[test]
    fn verify_chain_detects_body_tampering() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("b@example.com"), None, Some(2));

        // Mutate event[0]'s actor field.
        log.events[0].actor = Some("adversary".to_string());
        let err = log.verify_chain().unwrap_err();
        assert!(
            matches!(err, AuditChainError::EventHashMismatch { index: 0 }),
            "expected EventHashMismatch at index 0, got {err:?}"
        );
    }

    /// AUDIT-2026-04 H-2 critical: tampering with a prev_hash field
    /// alone (without re-signing) breaks the chain link.
    #[test]
    fn verify_chain_detects_link_tampering() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("b@example.com"), None, Some(2));

        // Flip one bit in event[1].prev_hash.
        log.events[1].prev_hash[0] ^= 0xFF;
        let err = log.verify_chain().unwrap_err();
        assert!(
            matches!(err, AuditChainError::PrevHashMismatch { index: 1 }),
            "expected PrevHashMismatch at index 1, got {err:?}"
        );
    }

    /// Truncating the head of the log (removing event[0]) must be
    /// detectable via the first event's non-zero prev_hash.
    #[test]
    fn verify_chain_detects_head_truncation() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("b@example.com"), None, Some(2));

        // Remove event[0] — now event[1] is the new head but its
        // prev_hash references the destroyed event.
        log.events.remove(0);
        let err = log.verify_chain().unwrap_err();
        assert!(
            matches!(err, AuditChainError::FirstEventPrevHashNonZero),
            "expected FirstEventPrevHashNonZero, got {err:?}"
        );
    }

    /// Serialization round-trip preserves the chain: dumping to JSON
    /// and re-parsing yields a log that still verifies. This is the
    /// foundation for durable persistence (the storage-backed store
    /// lands in a follow-up per AUDIT-2026-04 H-2 remediation plan).
    #[test]
    fn chain_survives_json_round_trip() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("a@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("b@example.com"), None, Some(2));
        let _ = log.append(mk_consent_action("c@example.com"), None, Some(3));
        let head = log.chain_head();

        let events: Vec<ComplianceAuditEvent> = log
            .query(&AuditQuery::default())
            .into_iter()
            .cloned()
            .collect();
        let json = serde_json::to_string(&events).unwrap();
        let restored: Vec<ComplianceAuditEvent> = serde_json::from_str(&json).unwrap();

        // Reconstruct a log from the restored events and verify.
        let mut log2 = ComplianceAuditLog::new();
        log2.events = restored;
        log2.chain_head = head;
        log2.verify_chain()
            .expect("round-tripped chain must still verify");
    }

    /// Two different events with otherwise-identical action
    /// content produce different hashes because their event_ids,
    /// timestamps, and chain positions differ.
    #[test]
    fn identical_actions_produce_distinct_hashes() {
        let mut log = ComplianceAuditLog::new();
        let _ = log.append(mk_consent_action("same@example.com"), None, Some(1));
        let _ = log.append(mk_consent_action("same@example.com"), None, Some(1));
        let events = log.query(&AuditQuery::default());
        assert_ne!(events[0].event_hash, events[1].event_hash);
    }

    // ========================================================================
    // AUDIT-2026-04 L-2 / L-6: typed Actor / Scope surface
    // ========================================================================

    /// `Actor::System(_)` events are forensically distinct from
    /// anonymous events — the stored string encodes the component so
    /// round-tripping through the wire shape preserves the variant.
    #[test]
    fn actor_system_round_trips_through_legacy_string() {
        let sys = Actor::System(ComponentName::BreachDetector);
        let wire = sys.to_legacy_string();
        assert_eq!(wire.as_deref(), Some("system:breach_detector"));
        assert_eq!(Actor::from_legacy_string(wire.as_deref()), sys);
    }

    /// Authenticated actors carry their subject string verbatim.
    #[test]
    fn actor_authenticated_round_trips() {
        let a = Actor::Authenticated("alice@example.com".to_string());
        let wire = a.to_legacy_string();
        assert_eq!(wire.as_deref(), Some("alice@example.com"));
        assert_eq!(Actor::from_legacy_string(wire.as_deref()), a);
    }

    /// `Actor::Anonymous` ↔ `None` in the legacy wire shape.
    #[test]
    fn actor_anonymous_maps_to_none() {
        assert_eq!(Actor::Anonymous.to_legacy_string(), None);
        assert_eq!(Actor::from_legacy_string(None), Actor::Anonymous);
    }

    /// `append_with_actor` is the preferred typed entry point. Events
    /// recorded through it round-trip their actor variant via
    /// `actor_kind()`.
    #[test]
    fn append_with_actor_preserves_typed_actor() {
        let mut log = ComplianceAuditLog::new();
        let id = log.append_with_actor(
            mk_consent_action("user@example.com"),
            Actor::System(ComponentName::ConsentReconciler),
            Scope::Tenant(kimberlite_types::TenantId::new(42)),
        );
        let event = log.get_event(id).expect("event exists");
        assert_eq!(
            event.actor_kind(),
            Actor::System(ComponentName::ConsentReconciler)
        );
        assert_eq!(
            event.scope(),
            Scope::Tenant(kimberlite_types::TenantId::new(42))
        );
    }

    /// `Scope::System` differs from `Scope::Global` only via the actor
    /// variant — a `None` tenant with a `System` actor implies System
    /// scope, otherwise Global.
    #[test]
    fn scope_distinguishes_system_from_global_via_actor() {
        let mut log = ComplianceAuditLog::new();
        let sys_id = log.append_with_actor(
            mk_consent_action("u@example.com"),
            Actor::System(ComponentName::BreachDetector),
            Scope::System,
        );
        let global_id = log.append_with_actor(
            mk_consent_action("v@example.com"),
            Actor::Authenticated("admin".into()),
            Scope::Global,
        );

        assert_eq!(log.get_event(sys_id).unwrap().scope(), Scope::System);
        assert_eq!(log.get_event(global_id).unwrap().scope(), Scope::Global);
    }

    // ========================================================================
    // v0.6.0 Tier 2 #9 — SDK-safe AuditSdkEntry projection
    // ========================================================================

    /// `to_sdk_entry` carries the action kind string but never a
    /// value from the payload. The `changed_field_names` list is the
    /// *schema* of the action, not its contents.
    #[test]
    fn to_sdk_entry_strips_action_values_and_keeps_names() {
        let mut log = ComplianceAuditLog::new();
        let id = log.append(
            ComplianceAuditAction::ConsentGranted {
                subject_id: "alice@example.com".into(),
                purpose: "Marketing-Retargeting".into(),
                scope: "SensitiveContactInfo".into(),
                terms_version: None,
                accepted: true,
            },
            Some("admin".into()),
            Some(1),
        );
        let ev = log.get_event(id).unwrap();
        let entry = ev.to_sdk_entry();

        // Kind string is the action name, not a value.
        assert_eq!(entry.action, "ConsentGranted");
        // Subject is derived from the action payload — it is the
        // one field we promote so callers can correlate. Everything
        // else (purpose, scope) is field-name only.
        assert_eq!(entry.subject_id.as_deref(), Some("alice@example.com"));
        assert_eq!(
            entry.changed_field_names,
            // v0.6.2 — `terms_version` and `accepted` joined the
            // ConsentGranted variant. Field NAMES travel to the SDK
            // entry; field VALUES never do (asserted below).
            vec![
                "subject_id",
                "purpose",
                "scope",
                "terms_version",
                "accepted",
            ],
        );

        // The encoded entry must NOT mention the value strings.
        let encoded = serde_json::to_string(&entry).unwrap();
        assert!(
            !encoded.contains("Marketing-Retargeting"),
            "encoded SDK entry leaked a purpose value: {encoded}"
        );
        assert!(
            !encoded.contains("SensitiveContactInfo"),
            "encoded SDK entry leaked a scope value: {encoded}"
        );
    }

    /// Actions without a subject field (e.g. `FieldMasked`) project
    /// to `subject_id: None` and still carry the correct name list.
    #[test]
    fn to_sdk_entry_handles_subjectless_actions() {
        let mut log = ComplianceAuditLog::new();
        let id = log.append(
            ComplianceAuditAction::FieldMasked {
                column: "ssn".into(),
                strategy: "redact".into(),
                role: "support".into(),
            },
            Some("system".into()),
            Some(1),
        );
        let entry = log.get_event(id).unwrap().to_sdk_entry();
        assert_eq!(entry.action, "FieldMasked");
        assert!(entry.subject_id.is_none());
        assert_eq!(
            entry.changed_field_names,
            vec!["column", "strategy", "role"],
        );
        let encoded = serde_json::to_string(&entry).unwrap();
        assert!(!encoded.contains("ssn"));
        assert!(!encoded.contains("redact"));
    }

    /// `ErasureExempted` carries a `basis` string that the SDK entry
    /// surfaces via `reason` (regulators need to see *why*).
    /// The payload value IS allowed to appear — it's the reason, not
    /// the PHI. All other field values remain stripped.
    #[test]
    fn to_sdk_entry_surfaces_erasure_reason_only() {
        let mut log = ComplianceAuditLog::new();
        let req_id = Uuid::new_v4();
        let id = log.append(
            ComplianceAuditAction::ErasureExempted {
                subject_id: "bob@example.com".into(),
                request_id: req_id,
                basis: "LegalObligation".into(),
            },
            None,
            None,
        );
        let entry = log.get_event(id).unwrap().to_sdk_entry();
        assert_eq!(entry.reason.as_deref(), Some("LegalObligation"));
        assert_eq!(entry.request_id, Some(req_id));
        assert_eq!(entry.subject_id.as_deref(), Some("bob@example.com"));
    }

    /// Every variant's `changed_field_names` count matches the
    /// number of serde-named fields on the variant. Guards against
    /// a future contributor adding a variant / field without
    /// updating the name list.
    #[test]
    fn changed_field_names_are_exhaustive_per_variant() {
        let pairs: &[(ComplianceAuditAction, usize)] = &[
            (
                ComplianceAuditAction::ConsentGranted {
                    subject_id: String::new(),
                    purpose: String::new(),
                    scope: String::new(),
                    terms_version: None,
                    accepted: true,
                },
                // v0.6.2: + terms_version, accepted
                5,
            ),
            (
                ComplianceAuditAction::ConsentWithdrawn {
                    subject_id: String::new(),
                    consent_id: Uuid::nil(),
                },
                2,
            ),
            (
                ComplianceAuditAction::ErasureRequested {
                    subject_id: String::new(),
                    request_id: Uuid::nil(),
                },
                2,
            ),
            (
                ComplianceAuditAction::ErasureCompleted {
                    subject_id: String::new(),
                    records_erased: 0,
                    request_id: Uuid::nil(),
                },
                3,
            ),
            (
                ComplianceAuditAction::ErasureExempted {
                    subject_id: String::new(),
                    request_id: Uuid::nil(),
                    basis: String::new(),
                },
                3,
            ),
            (
                ComplianceAuditAction::FieldMasked {
                    column: String::new(),
                    strategy: String::new(),
                    role: String::new(),
                },
                3,
            ),
        ];
        for (a, expected) in pairs {
            assert_eq!(
                a.changed_field_names().len(),
                *expected,
                "variant {:?} field-name count drift",
                a.kind()
            );
        }
    }

    // ========================================================================
    // End v0.6.0 Tier 2 #9 unit tests
    // ========================================================================

    /// Typed filter methods translate to the legacy wire shape so the
    /// existing Vec-based filter stays correct.
    #[test]
    fn with_actor_kind_and_with_scope_filter_correctly() {
        let mut log = ComplianceAuditLog::new();
        log.append_with_actor(
            mk_consent_action("a@example.com"),
            Actor::Authenticated("alice".into()),
            Scope::Tenant(kimberlite_types::TenantId::new(1)),
        );
        log.append_with_actor(
            mk_consent_action("b@example.com"),
            Actor::System(ComponentName::BreachDetector),
            Scope::Tenant(kimberlite_types::TenantId::new(2)),
        );

        let alice_only = log
            .query(&AuditQuery::default().with_actor_kind(&Actor::Authenticated("alice".into())));
        assert_eq!(alice_only.len(), 1);

        let tenant_2 = log.query(
            &AuditQuery::default().with_scope(Scope::Tenant(kimberlite_types::TenantId::new(2))),
        );
        assert_eq!(tenant_2.len(), 1);
    }
}
