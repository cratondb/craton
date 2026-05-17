//! Extended VOPR test scenarios for comprehensive simulation testing.
//!
//! This module provides pre-configured test scenarios that combine various
//! fault injection patterns to test specific correctness properties.

use crate::{
    ByzantineInjector, GrayFailureInjector, NetworkConfig, SimRng, StorageConfig, SwizzleClogger,
};
use kimberlite_vsr::ReplicaId;

// ============================================================================
// Scenario Types
// ============================================================================

/// Predefined test scenarios for VOPR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioType {
    /// Baseline: no faults, normal operation
    Baseline,
    /// Swizzle-clogging: intermittent network congestion
    SwizzleClogging,
    /// Gray failures: partial node failures (slow, intermittent, partial)
    GrayFailures,
    /// Multi-tenant isolation: concurrent tenants with fault injection
    MultiTenantIsolation,
    /// Time compression: accelerated time to test long-running scenarios
    TimeCompression,
    /// Combined: all fault types enabled
    Combined,
    /// Byzantine: view change log merge overwrites committed entries (Bug #1)
    ByzantineViewChangeMerge,
    /// Byzantine: commit number desynchronization (Bug #2)
    ByzantineCommitDesync,
    /// Byzantine: inflated commit number in DoViewChange (Bug #3)
    ByzantineInflatedCommit,
    /// Byzantine: invalid entry metadata (Bug #4)
    ByzantineInvalidMetadata,
    /// Byzantine: malicious view change selection (Bug #5)
    ByzantineMaliciousViewChange,
    /// Byzantine: leader selection race condition (Bug #6)
    ByzantineLeaderRace,

    // AUDIT-2026-03 H-1: Complete Byzantine Attack Coverage
    /// Byzantine: Replay old messages from previous view
    ByzantineReplayOldView,
    /// Byzantine: Corrupt message checksums
    ByzantineCorruptChecksums,
    /// Byzantine: Block DoViewChange messages to specific replicas
    ByzantineViewChangeBlocking,
    /// Byzantine: Flood replicas with excessive Prepare messages
    ByzantinePrepareFlood,
    /// Byzantine: Selectively ignore messages from specific replicas
    ByzantineSelectiveSilence,

    // Phase 3A Bug-Specific Scenarios
    /// Byzantine: DoViewChange log_tail length mismatch (Bug 3.1)
    ByzantineDvcTailLengthMismatch,
    /// Byzantine: DoViewChange with identical claims (Bug 3.3)
    ByzantineDvcIdenticalClaims,
    /// Byzantine: Oversized StartView log_tail (Bug 3.4 - DoS)
    ByzantineOversizedStartView,
    /// Byzantine: Invalid repair range (Bug 3.5)
    ByzantineInvalidRepairRange,
    /// Byzantine: Invalid kernel command (Bug 3.2)
    ByzantineInvalidKernelCommand,

    // Corruption Detection Scenarios
    /// Corruption: Random bit flip in log entry
    CorruptionBitFlip,
    /// Corruption: Checksum validation test
    CorruptionChecksumValidation,
    /// Corruption: Silent disk failure
    CorruptionSilentDiskFailure,
    /// Corruption: Torn write detection (AUDIT-2026-03 M-8)
    CorruptionTornWrite,

    // Recovery & Crash Scenarios
    /// Crash during commit application
    CrashDuringCommit,
    /// Crash during view change
    CrashDuringViewChange,
    /// Recovery with corrupt log
    RecoveryCorruptLog,

    // Gray Failure Scenarios
    /// Gray failure: Slow disk I/O
    GrayFailureSlowDisk,
    /// Gray failure: Intermittent network
    GrayFailureIntermittentNetwork,

    // Race Condition Scenarios
    /// Race: Concurrent view changes
    RaceConcurrentViewChanges,
    /// Race: Commit during DoViewChange
    RaceCommitDuringDvc,

    // Phase 1: Clock Synchronization Scenarios
    /// Clock: Drift detection and tolerance
    ClockDrift,
    /// Clock: Offset exceeds tolerance
    ClockOffsetExceeded,
    /// Clock: NTP-style failures
    ClockNtpFailure,
    /// Clock: Backward jump during partition (monotonicity test)
    ClockBackwardJump,

    // Phase 1: Client Session Scenarios
    /// Client Session: Successive crashes (VRR Bug #1)
    ClientSessionCrash,
    /// Client Session: View change lockout prevention (VRR Bug #2)
    ClientSessionViewChangeLockout,
    /// Client Session: Deterministic eviction
    ClientSessionEviction,

    // Phase 2: Repair Budget & Timeout Scenarios
    /// Repair: Budget prevents repair storms
    RepairBudgetPreventsStorm,
    /// Repair: EWMA-based smart replica selection
    RepairEwmaSelection,
    /// Repair: Sync timeout escalates to state transfer
    RepairSyncTimeout,
    /// Timeout: Primary abdicate when partitioned
    PrimaryAbdicatePartition,
    /// Timeout: Commit stall detection
    CommitStallDetection,
    /// Timeout: Ping heartbeat regular health checks
    PingHeartbeat,
    /// Timeout: Commit message fallback via heartbeat
    CommitMessageFallback,
    /// Timeout: Start view change window prevents split-brain
    StartViewChangeWindow,
    /// Timeout: Comprehensive timeout coverage test
    TimeoutComprehensive,

    // Phase 3: Storage Integrity Scenarios
    /// Scrub: Detects corruption via checksum validation
    ScrubDetectsCorruption,
    /// Scrub: Tour completes within time limit
    ScrubCompletesTour,
    /// Scrub: Rate limiting respects IOPS budget
    ScrubRateLimited,
    /// Scrub: Triggers repair on corruption detection
    ScrubTriggersRepair,

    // Phase 4: Cluster Reconfiguration Scenarios
    /// Reconfig: Add replicas (3 → 5)
    ReconfigAddReplicas,
    /// Reconfig: Remove replicas (5 → 3)
    ReconfigRemoveReplicas,
    /// Reconfig: During network partition
    ReconfigDuringPartition,
    /// Reconfig: View change during joint consensus
    ReconfigDuringViewChange,
    /// Reconfig: Concurrent reconfiguration requests
    ReconfigConcurrentRequests,
    /// Reconfig: Joint quorum validation (both configs)
    ReconfigJointQuorumValidation,

    // Phase 4.2: Rolling Upgrade Scenarios
    /// Upgrade: Gradual rollout (sequential upgrade of replicas)
    UpgradeGradualRollout,
    /// Upgrade: Replica failure during upgrade
    UpgradeWithFailure,
    /// Upgrade: Rollback to previous version
    UpgradeRollback,
    /// Upgrade: Feature flag activation
    UpgradeFeatureActivation,

    // Phase 4.3: Standby Replica Scenarios
    /// Standby: Follows log without participating in quorum
    StandbyFollowsLog,
    /// Standby: Promotion to active replica
    StandbyPromotion,
    /// Standby: Read scaling (multiple standby replicas serve queries)
    StandbyReadScaling,

    // Phase 3.2: RBAC (Role-Based Access Control) Scenarios
    /// RBAC: Unauthorized column access attempt
    RbacUnauthorizedColumnAccess,
    /// RBAC: Role escalation attack prevention
    RbacRoleEscalationAttack,
    /// RBAC: Row-level security enforcement
    RbacRowLevelSecurity,
    /// RBAC: Audit trail completeness
    RbacAuditTrailComplete,

    // AUDIT-2026-03 M-3: Signature Attack Scenarios
    /// Signature: Byzantine replica sends messages with forged signatures
    SignatureForgedMessage,
    /// Signature: Byzantine replica tampers with message content after signing
    SignatureTamperedContent,
    /// Signature: Byzantine replica sends unsigned messages
    SignatureUnsignedMessage,
    /// Signature: Byzantine replica uses wrong key to sign messages
    SignatureWrongKey,

    // v0.6.0 Tier 1 #5: ALTER TABLE crash-recovery hardening
    /// Schema evolution: Crash mid-`ALTER TABLE ADD COLUMN` with
    /// concurrent INSERT workload; recovery must preserve hash-chain
    /// integrity, `schema_version` monotonicity, event ordering, and
    /// NULL-materialisation for rows predating the ALTER.
    AlterTableCrashRecovery,

    // v0.6.0 Tier 2 #7: Masking policy scenarios
    /// Masking policy role-transition: concurrent reads under a
    /// `SET ROLE` workload against a table with an attached masking
    /// policy. Hash-chain integrity + offset monotonicity are
    /// enforced by the existing invariant checkers; the masking
    /// itself is a kernel-side invariant on every read so any role
    /// transition that would yield an unmasked value to a non-exempt
    /// role trips the kernel's `RoleGuard::should_mask` pre-check.
    MaskingRoleTransition,

    // v0.6.0 Tier 2 #4: eraseSubject crash-recovery
    /// `eraseSubject` crash-recovery: storage-layer crashes injected
    /// mid-erasure-loop (DEK shred half-complete, projection walk
    /// in-progress). Post-recovery must produce a valid hash-chain
    /// and either a signed completion proof or an in-progress audit
    /// record that a subsequent erase call can resume — no silent
    /// incomplete-erasure state.
    EraseSubjectWithCrash,

    // ========================================================================
    // v0.7.0 — workload-generator families for v0.6.0 command surfaces
    // AUDIT-2026-05 M-7. Scaffolded — full drivers ship per-family in
    // subsequent commits. Each variant carries the canary mutation it
    // surfaces so the driver author has the contract pinned upfront.
    // ========================================================================

    // ---- Masking* family ------------------------------------------------
    /// Masking class monotonicity: a row written under classification
    /// `Confidential` must never surface at a lower class
    /// (`Public`/`Internal`) on subsequent reads. Canary: a planner
    /// rewrite path that drops the masking-policy attachment without
    /// re-classifying the data.
    MaskingClassMonotonicity,
    /// Duplicate `CreateMask` definition: submitting two
    /// `CreateMaskingPolicy` commands with the same name must reject
    /// the second one rather than silently overwriting. Canary: an
    /// idempotency-style "second create succeeds" implementation that
    /// loses the audit trail of the original.
    MaskingDuplicateClassDefinition,
    /// Crash after DDL but before replay: storage crash between
    /// `Effect::CreateMaskingPolicy` and the projection-store write.
    /// Recovery must replay the masking class BEFORE replaying any
    /// row that references the column it masks. Canary: a recovery
    /// reordering that admits a row read against an unmasked column
    /// before the policy attaches.
    MaskingCrashAfterDdlBeforeReplay,
    /// Read during rotation: concurrent `AlterTable AttachMaskingPolicy`
    /// while reads are in flight. The kernel's `RoleGuard::should_mask`
    /// pre-check must observe the new policy or the old one — never a
    /// torn intermediate. Canary: a half-applied class swap that lets
    /// a read see the old policy's mask scope but the new policy's
    /// strategy.
    MaskingClassReadDuringRotation,

    // ---- Upsert* family -------------------------------------------------
    /// Concurrent INSERTs racing on the same primary key with `ON
    /// CONFLICT DO UPDATE`. Single-writer-per-tenant VSR linearises;
    /// `rows_affected` must be consistent across both connections.
    /// Canary: an executor that double-counts `rows_affected` when
    /// the conflict resolution returns `Updated`.
    UpsertConcurrentInsertSamePk,
    /// Crash mid-conflict resolution: storage crash injected between
    /// the conflict detection and the `UpsertApplied` event emit.
    /// Replay must produce exactly one `UpsertApplied` per logical
    /// upsert. Canary: replay duplicates the effect, surfacing as
    /// inflated `rows_affected` on next read.
    UpsertCrashMidConflict,
    /// `RETURNING` reflects the post-upsert row, not the pre-upsert
    /// state. Canary: a planner path that captures the row image
    /// before the upsert applies (e.g., from the WHERE-clause scan
    /// rather than the post-effect projection state).
    UpsertWithComputedReturning,
    /// `INSERT ... ON CONFLICT (col)` against a non-unique index —
    /// the planner must reject this at planning time. Canary: the
    /// planner accepts the statement and the conflict resolution
    /// chooses one row at random.
    UpsertOnNonUniqueIndex,

    // ---- AsOfTimestamp* family -----------------------------------------
    /// `AS OF TIMESTAMP <t>` where `t` is older than the retention
    /// horizon. Must surface `AsOfBeforeRetentionHorizon` rather than
    /// silently returning empty. Canary: an executor that maps "no
    /// rows in retained range" to `Vec::new()` without consulting
    /// the horizon.
    AsOfBeforeRetentionHorizon,
    /// `AS OF TIMESTAMP` issued mid-write: time-travel read must see
    /// either the pre-write state OR the post-write state, never a
    /// half-applied effect. Canary: the reader observes a
    /// projection-store row before the corresponding kernel-state
    /// commit (or vice versa).
    AsOfDuringWrite,
    /// Clock skew between replicas: `AS OF` resolutions on different
    /// replicas must agree on the resolved offset. A later
    /// `AS OF t` returning fewer rows than an earlier `AS OF (t - δ)`
    /// is a monotonicity violation. Canary: the resolver uses the
    /// local replica's clock instead of the consensus-attested
    /// timestamp.
    AsOfMonotonicityUnderClockSkew,
    /// Same `AS OF TIMESTAMP` query, replayed on different replicas,
    /// must yield identical row sets. Canary: a non-deterministic
    /// tie-breaker in the timestamp-resolver returns different
    /// offsets across replicas.
    AsOfRoundTripDeterminism,

    // ---- EraseAutoDiscovery* family ------------------------------------
    /// `eraseSubject` auto-discovery across schema versions: a
    /// column added pre-erase via `ALTER TABLE ADD COLUMN PII` MUST
    /// be discovered. Canary: discovery walks the v0 schema and
    /// misses post-ALTER columns.
    EraseAutoDiscoveryAcrossSchemaVersions,
    /// Auto-discovery encountering a dropped column: a column
    /// removed via `ALTER TABLE DROP COLUMN` between erase request
    /// and discovery walk must be skipped without erroring. Canary:
    /// discovery panics or counts the dropped column as an
    /// in-progress erasure that never completes.
    EraseAutoDiscoveryWithDroppedColumn,
    /// Discovery determinism: same erase request on the same data
    /// produces the same certificate hash on every replica. Canary:
    /// HashMap iteration order leaks into the discovery sequence,
    /// breaking the certificate-hash invariant.
    EraseAutoDiscoveryDeterminism,
    /// Crash mid-scan during auto-discovery: storage crash between
    /// the kernel-state catalog read and the per-stream erasure
    /// loop. Recovery must re-issue the scan, not report the
    /// partial result as complete. Canary: an in-progress-erasure
    /// audit record gets misclassified as `Completed`.
    EraseAutoDiscoveryWithCrashMidScan,

    // ========================================================================
    // Q2 (v0.9.x) — Healthcare clinical workload scenarios.
    // Scaffolded — drivers ship per-scenario as the kimberlite-hl7v2
    // ingest path and kimberlite-fhir-store projection workers land
    // in subsequent commits. Each variant pins the clinical workload
    // shape together with the audit-grade invariant it MUST satisfy.
    // ========================================================================
    /// **EHR admissions surge** — 10x burst of ADT^A01 messages
    /// arriving via MLLP (flu season, mass-casualty triage, scheduled
    /// open-enrollment day). The PV1 visit creation and the
    /// `fhir.Patient.<tenant>` + `fhir.Encounter.<tenant>` stream
    /// appends must remain atomic per-message — a half-applied
    /// Patient with no corresponding Encounter is a HIPAA
    /// integrity event. Canary: the ingest worker batches Patient
    /// and Encounter writes into separate transactions and the
    /// Patient stream gets ahead of Encounter under sustained
    /// surge.
    EhrAdmissionsSurge,

    /// **Lab result delayed delivery** — ORU^R01 observation results
    /// arriving hours or days after the originating Encounter (real
    /// pathology turnaround). The `Observation.encounter` reference
    /// must resolve to the historical Encounter as it existed at
    /// the time of the lab order, not the encounter's current
    /// post-discharge state. Time-travel via `AS OF TIMESTAMP <order_time>`
    /// MUST return the same Encounter projection regardless of when
    /// the resolving read is issued. Canary: the FHIR projector
    /// uses the *write-time* Encounter snapshot instead of the
    /// kernel's MVCC at-offset view, leaking post-discharge state
    /// into pre-discharge result interpretations.
    LabResultDelayedDelivery,

    /// **Claims batch reconciliation** — nightly cycle where X12 837
    /// (institutional claim) submissions are matched against 835
    /// (electronic remittance advice) responses. The append-only
    /// claims-event stream must remain monotonic across the full
    /// 100k-row batch even when storage faults are injected
    /// mid-batch. A retry under fault must produce the same
    /// post-state as a clean run (idempotency). Canary: a retried
    /// 837 submit double-counts in the `claims_submitted` counter
    /// because the storage adapter doesn't dedupe on `Field 1000-NM1`
    /// claim-control-number.
    ClaimsBatchReconciliation,

    /// **Break-glass under load** — emergency override of PHI access
    /// (HIPAA § 164.510(b)(3)) activated by a clinician during
    /// sustained high write throughput on the same patient's
    /// streams. The `BreakGlassActivated` audit event MUST appear
    /// at a strictly earlier offset than every PHI read the
    /// activating user issues inside the session, and
    /// `BreakGlassClosed` MUST list every resource id touched —
    /// even when 1000 inserts/sec are racing the same chain head.
    /// Canary: under contention, the audit-log inserter batches the
    /// `BreakGlassActivated` event and a PHI read lands at an
    /// earlier offset, leaving the regulator with a forensic
    /// hole.
    BreakGlassUnderLoad,

    /// **Consent revocation cascade** — patient withdraws consent
    /// (GDPR Art. 7(3) / HIPAA Authorization revocation) while
    /// research queries against their PHI are in flight. New
    /// queries after the revocation timestamp MUST return empty
    /// for the revoked-scope rows; in-flight queries started
    /// before revocation MUST complete with the pre-revocation
    /// snapshot (consistency over abruption); the
    /// `ConsentWithdrawn` audit event MUST chain-precede the
    /// erasure-request audit event MUST chain-precede the
    /// `Effect::ProjectionRowsPurge`. Canary: a torn revocation
    /// where the consent table updates atomically but the
    /// projection purge is asynchronous, allowing a research
    /// query started 50ms after revocation to still see the
    /// withdrawn rows.
    ConsentRevocationCascade,

    // ========================================================================
    // Q2 (v0.9.x) — Cluster-level supervisor scenarios. Sibling to the
    // VSR consensus scenarios above: these target the `kimberlite-cluster`
    // process supervisor, not the VSR protocol. The supervisor today is
    // a single-machine harness; these scenarios pin the contracts the
    // production-ready supervisor must satisfy. Drivers ship per-scenario
    // as T1.* (real subprocess spawn + HTTP health endpoints) of the
    // graduation plan lands. See
    // docs-internal/design-docs/active/cluster-graduation-v0.9.x.md.
    // ========================================================================
    /// **Cluster: single-node process crash** — SIGKILL one
    /// follower's `kimberlite start` subprocess. The supervisor
    /// MUST detect the death within `health_check_interval_ms`,
    /// restart the node with bounded exponential backoff, and
    /// audit-log every restart attempt (count + reason). The
    /// other N-1 nodes MUST remain writable throughout. Canary:
    /// a supervisor that retries restart at unbounded frequency
    /// (no backoff) on a node whose binary is broken — burning
    /// CPU and saturating fd tables instead of exposing
    /// `/readyz: red` to the ops team.
    ClusterNodeProcessCrash,

    /// **Cluster: cascading node failure** — N-1 nodes (where
    /// N is quorum size on a 3-node cluster: 2 of 3) crash in
    /// rapid sequence. The cluster MUST refuse writes (no quorum)
    /// but MUST NOT lose any entry that was committed before
    /// the cascade. When nodes recover, the new leader's log
    /// MUST contain every committed entry from before the
    /// cascade, in order. Canary: a supervisor that retries the
    /// pre-cascade leader's restart too aggressively, racing the
    /// view-change protocol and causing a split-brain transient.
    ClusterCascadingNodeFailure,

    /// **Cluster: health-check timeout** — a node's `kimberlite start`
    /// process hangs (e.g. stuck in a tight loop on a kernel
    /// fault) without crashing. The supervisor MUST flip the
    /// node's `/readyz` to red within `health_check_timeout_ms`,
    /// escalate to a forced restart, and the cluster MUST initiate
    /// a view change to elect a new leader if the hung node was
    /// leader. Canary: a supervisor that relies solely on
    /// `child.try_wait()` (process-still-alive) and misses the
    /// hung-but-running case, leaving the cluster wedged.
    ClusterHealthCheckTimeout,

    /// **Cluster: config reload under load** — `cluster.toml` is
    /// updated mid-write (e.g. an operator edits a peer's IP).
    /// The supervisor MUST apply the new config without losing
    /// any in-flight committed write and without dropping the
    /// VSR view. Reloads that would shrink quorum below safety
    /// MUST be rejected with a typed error. Canary: a supervisor
    /// that restarts each node sequentially with the new config
    /// without coordinating the view-change, causing a
    /// transient quorum loss between the first node's restart
    /// and the new leader's election.
    ClusterConfigReloadUnderLoad,

    /// **Cluster: rolling restart full cluster** — operator
    /// performs a rolling restart (stop node, wait for follower
    /// to catch up, start node) across all N nodes in sequence.
    /// At every step the cluster MUST remain writable with
    /// quorum preserved, and at completion every committed
    /// entry that existed pre-restart MUST exist post-restart
    /// at the same offset. Canary: the supervisor's
    /// `stop_node()` returns before the node's data is flushed
    /// to disk, so a subsequent start sees a torn log tail.
    ClusterRollingRestartFullCluster,
}

impl ScenarioType {
    /// Returns a human-readable name for the scenario.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Baseline => "Baseline (No Faults)",
            Self::SwizzleClogging => "Swizzle-Clogging",
            Self::GrayFailures => "Gray Failures",
            Self::MultiTenantIsolation => "Multi-Tenant Isolation",
            Self::TimeCompression => "Time Compression",
            Self::Combined => "Combined Faults",
            Self::ByzantineViewChangeMerge => "Byzantine: View Change Merge",
            Self::ByzantineCommitDesync => "Byzantine: Commit Desync",
            Self::ByzantineInflatedCommit => "Byzantine: Inflated Commit",
            Self::ByzantineInvalidMetadata => "Byzantine: Invalid Metadata",
            Self::ByzantineMaliciousViewChange => "Byzantine: Malicious View Change",
            Self::ByzantineLeaderRace => "Byzantine: Leader Race",
            Self::ByzantineReplayOldView => "Byzantine: Replay Old View",
            Self::ByzantineCorruptChecksums => "Byzantine: Corrupt Checksums",
            Self::ByzantineViewChangeBlocking => "Byzantine: View Change Blocking",
            Self::ByzantinePrepareFlood => "Byzantine: Prepare Flood",
            Self::ByzantineSelectiveSilence => "Byzantine: Selective Silence",
            Self::ByzantineDvcTailLengthMismatch => "Byzantine: DVC Tail Length Mismatch",
            Self::ByzantineDvcIdenticalClaims => "Byzantine: DVC Identical Claims",
            Self::ByzantineOversizedStartView => "Byzantine: Oversized StartView",
            Self::ByzantineInvalidRepairRange => "Byzantine: Invalid Repair Range",
            Self::ByzantineInvalidKernelCommand => "Byzantine: Invalid Kernel Command",
            Self::CorruptionBitFlip => "Corruption: Bit Flip",
            Self::CorruptionChecksumValidation => "Corruption: Checksum Validation",
            Self::CorruptionSilentDiskFailure => "Corruption: Silent Disk Failure",
            Self::CorruptionTornWrite => "Corruption: Torn Write Detection (M-8)",
            Self::CrashDuringCommit => "Crash: During Commit",
            Self::CrashDuringViewChange => "Crash: During View Change",
            Self::RecoveryCorruptLog => "Recovery: Corrupt Log",
            Self::GrayFailureSlowDisk => "Gray Failure: Slow Disk",
            Self::GrayFailureIntermittentNetwork => "Gray Failure: Intermittent Network",
            Self::RaceConcurrentViewChanges => "Race: Concurrent View Changes",
            Self::RaceCommitDuringDvc => "Race: Commit During DVC",
            Self::ClockDrift => "Clock: Drift Detection",
            Self::ClockOffsetExceeded => "Clock: Offset Exceeded",
            Self::ClockNtpFailure => "Clock: NTP Failure",
            Self::ClockBackwardJump => "Clock: Backward Jump",
            Self::ClientSessionCrash => "Client Session: Crash Recovery",
            Self::ClientSessionViewChangeLockout => "Client Session: View Change Lockout",
            Self::ClientSessionEviction => "Client Session: Eviction",
            Self::RepairBudgetPreventsStorm => "Repair: Budget Prevents Storm",
            Self::RepairEwmaSelection => "Repair: EWMA Selection",
            Self::RepairSyncTimeout => "Repair: Sync Timeout",
            Self::PrimaryAbdicatePartition => "Timeout: Primary Abdicate",
            Self::CommitStallDetection => "Timeout: Commit Stall",
            Self::PingHeartbeat => "Timeout: Ping Heartbeat",
            Self::CommitMessageFallback => "Timeout: Commit Message Fallback",
            Self::StartViewChangeWindow => "Timeout: Start View Change Window",
            Self::TimeoutComprehensive => "Timeout: Comprehensive",
            Self::ScrubDetectsCorruption => "Scrub: Detects Corruption",
            Self::ScrubCompletesTour => "Scrub: Completes Tour",
            Self::ScrubRateLimited => "Scrub: Rate Limited",
            Self::ScrubTriggersRepair => "Scrub: Triggers Repair",
            Self::ReconfigAddReplicas => "Reconfig: Add Replicas",
            Self::ReconfigRemoveReplicas => "Reconfig: Remove Replicas",
            Self::ReconfigDuringPartition => "Reconfig: During Partition",
            Self::ReconfigDuringViewChange => "Reconfig: During View Change",
            Self::ReconfigConcurrentRequests => "Reconfig: Concurrent Requests",
            Self::ReconfigJointQuorumValidation => "Reconfig: Joint Quorum Validation",
            Self::UpgradeGradualRollout => "Upgrade: Gradual Rollout",
            Self::UpgradeWithFailure => "Upgrade: With Failure",
            Self::UpgradeRollback => "Upgrade: Rollback",
            Self::UpgradeFeatureActivation => "Upgrade: Feature Activation",
            Self::StandbyFollowsLog => "Standby: Follows Log",
            Self::StandbyPromotion => "Standby: Promotion",
            Self::StandbyReadScaling => "Standby: Read Scaling",
            Self::RbacUnauthorizedColumnAccess => "RBAC: Unauthorized Column Access",
            Self::RbacRoleEscalationAttack => "RBAC: Role Escalation Attack",
            Self::RbacRowLevelSecurity => "RBAC: Row-Level Security",
            Self::RbacAuditTrailComplete => "RBAC: Audit Trail Complete",
            Self::SignatureForgedMessage => "Signature: Forged Message",
            Self::SignatureTamperedContent => "Signature: Tampered Content",
            Self::SignatureUnsignedMessage => "Signature: Unsigned Message",
            Self::SignatureWrongKey => "Signature: Wrong Key",
            Self::AlterTableCrashRecovery => "ALTER TABLE: Crash Recovery",
            Self::MaskingRoleTransition => "Masking: Role Transition",
            Self::EraseSubjectWithCrash => "Erasure: Subject With Crash",
            // v0.7.0 — Masking* family.
            Self::MaskingClassMonotonicity => "Masking: Class Monotonicity",
            Self::MaskingDuplicateClassDefinition => "Masking: Duplicate Class Definition",
            Self::MaskingCrashAfterDdlBeforeReplay => "Masking: Crash After DDL Before Replay",
            Self::MaskingClassReadDuringRotation => "Masking: Read During Rotation",
            // v0.7.0 — Upsert* family.
            Self::UpsertConcurrentInsertSamePk => "Upsert: Concurrent Insert Same PK",
            Self::UpsertCrashMidConflict => "Upsert: Crash Mid Conflict",
            Self::UpsertWithComputedReturning => "Upsert: With Computed RETURNING",
            Self::UpsertOnNonUniqueIndex => "Upsert: On Non-Unique Index",
            // v0.7.0 — AsOfTimestamp* family.
            Self::AsOfBeforeRetentionHorizon => "AS OF: Before Retention Horizon",
            Self::AsOfDuringWrite => "AS OF: During Write",
            Self::AsOfMonotonicityUnderClockSkew => "AS OF: Monotonicity Under Clock Skew",
            Self::AsOfRoundTripDeterminism => "AS OF: Round-Trip Determinism",
            // v0.7.0 — EraseAutoDiscovery* family.
            Self::EraseAutoDiscoveryAcrossSchemaVersions => {
                "Erase Auto-Discovery: Across Schema Versions"
            }
            Self::EraseAutoDiscoveryWithDroppedColumn => "Erase Auto-Discovery: Dropped Column",
            Self::EraseAutoDiscoveryDeterminism => "Erase Auto-Discovery: Determinism",
            Self::EraseAutoDiscoveryWithCrashMidScan => "Erase Auto-Discovery: Crash Mid-Scan",
            Self::EhrAdmissionsSurge => "Clinical: EHR Admissions Surge",
            Self::LabResultDelayedDelivery => "Clinical: Lab Result Delayed Delivery",
            Self::ClaimsBatchReconciliation => "Clinical: Claims Batch Reconciliation",
            Self::BreakGlassUnderLoad => "Clinical: Break-Glass Under Load",
            Self::ConsentRevocationCascade => "Clinical: Consent Revocation Cascade",
            Self::ClusterNodeProcessCrash => "Cluster: Single-Node Process Crash",
            Self::ClusterCascadingNodeFailure => "Cluster: Cascading Node Failure",
            Self::ClusterHealthCheckTimeout => "Cluster: Health-Check Timeout",
            Self::ClusterConfigReloadUnderLoad => "Cluster: Config Reload Under Load",
            Self::ClusterRollingRestartFullCluster => "Cluster: Rolling Restart (Full Cluster)",
        }
    }

    /// Returns a description of what this scenario tests.
    #[allow(clippy::too_many_lines)]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Baseline => "Normal operation without faults to establish baseline performance",
            Self::SwizzleClogging => "Intermittent network congestion and link flapping",
            Self::GrayFailures => {
                "Partial node failures: slow responses, intermittent errors, read-only nodes"
            }
            Self::MultiTenantIsolation => {
                "Multiple tenants with independent data, testing isolation under faults"
            }
            Self::TimeCompression => "10x accelerated time to test long-running operations",
            Self::Combined => "All fault types enabled simultaneously for stress testing",
            Self::ByzantineViewChangeMerge => {
                "Attack: Force view change after commits, inject conflicting entries (targets vsr_agreement)"
            }
            Self::ByzantineCommitDesync => {
                "Attack: Send StartView with high commit_number but truncated log (targets vsr_prefix_property)"
            }
            Self::ByzantineInflatedCommit => {
                "Attack: Byzantine replica claims impossibly high commit_number (targets vsr_durability)"
            }
            Self::ByzantineInvalidMetadata => {
                "Attack: Send Prepare with mismatched entry metadata (targets vsr_agreement)"
            }
            Self::ByzantineMaliciousViewChange => {
                "Attack: Send DoViewChange with inconsistent log (targets vsr_view_change_safety)"
            }
            Self::ByzantineLeaderRace => {
                "Attack: Create asymmetric partition during leader selection (targets vsr_agreement)"
            }
            Self::ByzantineReplayOldView => {
                "Attack: Re-send messages from previous view to confuse replicas (AUDIT-2026-03 H-1)"
            }
            Self::ByzantineCorruptChecksums => {
                "Attack: Send log entries with invalid checksums (AUDIT-2026-03 H-1)"
            }
            Self::ByzantineViewChangeBlocking => {
                "Attack: Withhold DoViewChange from specific replicas to delay view change (AUDIT-2026-03 H-1)"
            }
            Self::ByzantinePrepareFlood => {
                "Attack: Overwhelm replicas with excessive Prepare messages (AUDIT-2026-03 H-1)"
            }
            Self::ByzantineSelectiveSilence => {
                "Attack: Ignore messages from specific replicas to create asymmetric partitions (AUDIT-2026-03 H-1)"
            }
            Self::ByzantineDvcTailLengthMismatch => {
                "Attack: Send DoViewChange with log_tail length != (op_number - commit_number) (Bug 3.1)"
            }
            Self::ByzantineDvcIdenticalClaims => {
                "Attack: Multiple replicas send DoViewChange with identical (last_normal_view, op_number) (Bug 3.3)"
            }
            Self::ByzantineOversizedStartView => {
                "Attack: Send StartView with millions of entries to exhaust memory (Bug 3.4 - DoS)"
            }
            Self::ByzantineInvalidRepairRange => {
                "Attack: Send RepairRequest with start >= end to confuse replica (Bug 3.5)"
            }
            Self::ByzantineInvalidKernelCommand => {
                "Attack: Send Prepare with command that causes kernel error (Bug 3.2)"
            }
            Self::CorruptionBitFlip => {
                "Test: Random bit flip in log entry, verify checksum detects it"
            }
            Self::CorruptionChecksumValidation => {
                "Test: Corrupt checksum field, verify validation rejects it"
            }
            Self::CorruptionSilentDiskFailure => {
                "Test: Simulate silent disk corruption, verify detection and repair"
            }
            Self::CorruptionTornWrite => {
                "Test: Detect incomplete writes (power loss mid-write) via sentinel markers (M-8)"
            }
            Self::CrashDuringCommit => {
                "Test: Replica crashes mid-commit, verify recovery maintains consistency"
            }
            Self::CrashDuringViewChange => {
                "Test: Replica crashes during view change, verify safe recovery"
            }
            Self::RecoveryCorruptLog => {
                "Test: Replica recovers with corrupt log, verify repair from healthy peers"
            }
            Self::GrayFailureSlowDisk => {
                "Test: Disk I/O randomly slow, verify system maintains liveness"
            }
            Self::GrayFailureIntermittentNetwork => {
                "Test: Network intermittently drops packets, verify eventual consistency"
            }
            Self::RaceConcurrentViewChanges => {
                "Test: Multiple view changes triggered simultaneously, verify single leader emerges"
            }
            Self::RaceCommitDuringDvc => {
                "Test: Commit happens while DoViewChange in progress, verify safety"
            }
            Self::ClockDrift => {
                "Test: Gradual clock drift across replicas, verify tolerance detection within bounds"
            }
            Self::ClockOffsetExceeded => {
                "Test: Clock offset exceeds CLOCK_OFFSET_TOLERANCE_MS (500ms), verify rejection"
            }
            Self::ClockNtpFailure => {
                "Test: Simulate NTP server failure (no clock samples), verify graceful degradation"
            }
            Self::ClockBackwardJump => {
                "Test: Primary partitioned with backward clock jump, verify monotonicity preserved across view change"
            }
            Self::ClientSessionCrash => {
                "Test: Client crash and restart with request number reset, verify no collisions (VRR Bug #1)"
            }
            Self::ClientSessionViewChangeLockout => {
                "Test: Uncommitted requests during view change, verify no client lockout (VRR Bug #2)"
            }
            Self::ClientSessionEviction => {
                "Test: Session eviction when max_sessions exceeded, verify deterministic by timestamp"
            }
            Self::RepairBudgetPreventsStorm => {
                "Test: Multiple lagging replicas, verify repair budget prevents message queue overflow"
            }
            Self::RepairEwmaSelection => {
                "Test: Replicas with varying latency, verify EWMA-based smart replica selection"
            }
            Self::RepairSyncTimeout => {
                "Test: Repair stuck for >100 ops, verify escalation to state transfer"
            }
            Self::PrimaryAbdicatePartition => {
                "Test: Leader partitioned from quorum, verify abdication prevents deadlock"
            }
            Self::CommitStallDetection => {
                "Test: Pipeline growth without commit progress, verify stall detection and backpressure"
            }
            Self::PingHeartbeat => {
                "Test: Ping timeout triggers regular heartbeats, verify network health monitoring"
            }
            Self::CommitMessageFallback => {
                "Test: Commit message delayed/dropped, verify heartbeat fallback notifies backups"
            }
            Self::StartViewChangeWindow => {
                "Test: View change window timeout, verify split-brain prevention via delayed installation"
            }
            Self::TimeoutComprehensive => {
                "Test: All timeout types under various fault conditions, verify complete liveness coverage"
            }
            Self::ScrubDetectsCorruption => {
                "Test: Inject corrupted entry (bad checksum), verify scrubber detects it"
            }
            Self::ScrubCompletesTour => {
                "Test: Scrubber tours entire log within reasonable time (IOPS budget permitting)"
            }
            Self::ScrubRateLimited => {
                "Test: Scrubbing respects IOPS budget (max 10 reads/tick), doesn't impact production"
            }
            Self::ScrubTriggersRepair => {
                "Test: Corruption detection triggers automatic repair to restore data integrity"
            }
            Self::ReconfigAddReplicas => {
                "Test: Joint consensus safely adds replicas (3 → 5) without split-brain"
            }
            Self::ReconfigRemoveReplicas => {
                "Test: Joint consensus safely removes replicas (5 → 3) with quorum preservation"
            }
            Self::ReconfigDuringPartition => {
                "Test: Reconfigurations survive network partitions and view changes"
            }
            Self::ReconfigDuringViewChange => {
                "Test: View change during joint consensus preserves reconfiguration state"
            }
            Self::ReconfigConcurrentRequests => {
                "Test: Concurrent reconfiguration requests are rejected (one at a time)"
            }
            Self::ReconfigJointQuorumValidation => {
                "Test: Joint consensus requires quorum in BOTH old and new configs"
            }
            Self::UpgradeGradualRollout => {
                "Test: Sequential upgrade of replicas without service disruption"
            }
            Self::UpgradeWithFailure => {
                "Test: Replica failure during upgrade, verify cluster remains operational"
            }
            Self::UpgradeRollback => "Test: Rollback to previous version when issues detected",
            Self::UpgradeFeatureActivation => {
                "Test: Features activate only when all replicas upgraded"
            }
            Self::StandbyFollowsLog => {
                "Test: Standby replicas receive log updates but never send PrepareOK (Kani Proof #68)"
            }
            Self::StandbyPromotion => {
                "Test: Standby promotion to active preserves log consistency (Kani Proof #69)"
            }
            Self::StandbyReadScaling => {
                "Test: Multiple standbys serve eventually consistent reads, no quorum impact"
            }
            Self::RbacUnauthorizedColumnAccess => {
                "Test: User attempts to access denied column (e.g., SSN), verify query rewriting filters it out"
            }
            Self::RbacRoleEscalationAttack => {
                "Test: User attempts to escalate from User to Admin role, verify enforcement prevents it"
            }
            Self::RbacRowLevelSecurity => {
                "Test: Multi-tenant query without tenant_id filter, verify WHERE clause injection isolates tenants"
            }
            Self::RbacAuditTrailComplete => {
                "Test: All access attempts (allowed and denied) are logged with role, timestamp, and decision"
            }
            Self::SignatureForgedMessage => {
                "Byzantine replica forges message signatures to impersonate other replicas. Tests Ed25519 verification."
            }
            Self::SignatureTamperedContent => {
                "Byzantine replica signs a valid message, then tampers with content. Tests integrity protection."
            }
            Self::SignatureUnsignedMessage => {
                "Byzantine replica sends messages without signatures. Tests mandatory signature enforcement."
            }
            Self::SignatureWrongKey => {
                "Byzantine replica uses incorrect signing key. Tests key-identity binding verification."
            }
            Self::AlterTableCrashRecovery => {
                "ALTER TABLE ADD COLUMN under concurrent INSERT workload + storage crash. Recovery must preserve hash-chain integrity, schema_version monotonicity, and NULL-materialise pre-ALTER rows. (v0.6.0 Tier 1 #5)"
            }
            Self::MaskingRoleTransition => {
                "Concurrent reads against a masked column during SET ROLE transitions. Hash-chain integrity + offset monotonicity are VOPR invariants; masking itself is a kernel-side invariant on every read via RoleGuard::should_mask so any unmasked leakage to a non-exempt role is impossible by construction. (v0.6.0 Tier 2 #7)"
            }
            Self::EraseSubjectWithCrash => {
                "eraseSubject crash-recovery: storage crashes injected mid-erasure-loop. Post-recovery yields a valid hash-chain and either a signed completion proof or a resumable in-progress audit record — no silent incomplete-erasure state. (v0.6.0 Tier 2 #4)"
            }

            // v0.7.0 — Masking* family.
            Self::MaskingClassMonotonicity => {
                "Masking class monotonicity: a row written under a higher classification must never re-surface at a lower class. (v0.7.0 scaffold)"
            }
            Self::MaskingDuplicateClassDefinition => {
                "Duplicate `CreateMaskingPolicy` with the same name must reject the second submission. (v0.7.0 scaffold)"
            }
            Self::MaskingCrashAfterDdlBeforeReplay => {
                "Crash between policy effect emit and projection-store write must replay the policy before any data row that references the masked column. (v0.7.0 scaffold)"
            }
            Self::MaskingClassReadDuringRotation => {
                "Concurrent ALTER TABLE AttachMaskingPolicy with in-flight reads must observe a single coherent policy view. (v0.7.0 scaffold)"
            }

            // v0.7.0 — Upsert* family.
            Self::UpsertConcurrentInsertSamePk => {
                "Concurrent INSERT ... ON CONFLICT on the same PK serialises through the single-writer queue with consistent rows_affected. (v0.7.0 scaffold)"
            }
            Self::UpsertCrashMidConflict => {
                "Storage crash mid-conflict resolution: replay produces exactly one UpsertApplied effect per logical upsert. (v0.7.0 scaffold)"
            }
            Self::UpsertWithComputedReturning => {
                "RETURNING reflects the post-upsert row, not the pre-upsert state. (v0.7.0 scaffold)"
            }
            Self::UpsertOnNonUniqueIndex => {
                "INSERT ... ON CONFLICT (col) against a non-unique index must be rejected at planning time. (v0.7.0 scaffold)"
            }

            // v0.7.0 — AsOfTimestamp* family.
            Self::AsOfBeforeRetentionHorizon => {
                "AS OF TIMESTAMP older than retention horizon surfaces AsOfBeforeRetentionHorizon, not silent empty. (v0.7.0 scaffold)"
            }
            Self::AsOfDuringWrite => {
                "Time-travel read concurrent with a write sees pre-write or post-write state, never a half-applied effect. (v0.7.0 scaffold)"
            }
            Self::AsOfMonotonicityUnderClockSkew => {
                "AS OF resolutions across replicas with skewed clocks agree on the resolved offset; later AS OF never returns fewer rows. (v0.7.0 scaffold)"
            }
            Self::AsOfRoundTripDeterminism => {
                "Same AS OF TIMESTAMP query yields identical row sets on every replica. (v0.7.0 scaffold)"
            }

            // v0.7.0 — EraseAutoDiscovery* family.
            Self::EraseAutoDiscoveryAcrossSchemaVersions => {
                "eraseSubject auto-discovery includes columns added post-ALTER TABLE. (v0.7.0 scaffold)"
            }
            Self::EraseAutoDiscoveryWithDroppedColumn => {
                "Auto-discovery skips dropped columns without error. (v0.7.0 scaffold)"
            }
            Self::EraseAutoDiscoveryDeterminism => {
                "Discovery sequence is replica-deterministic; certificate hash matches across replicas. (v0.7.0 scaffold)"
            }
            Self::EraseAutoDiscoveryWithCrashMidScan => {
                "Storage crash mid-discovery re-issues the scan; partial results never reported as Completed. (v0.7.0 scaffold)"
            }
            Self::EhrAdmissionsSurge => {
                "10x ADT^A01 burst — Patient + Encounter stream appends must remain atomic per-message under sustained MLLP load. (Q2 scaffold)"
            }
            Self::LabResultDelayedDelivery => {
                "ORU^R01 results arrive hours after the originating Encounter; AS OF resolves the historical Encounter snapshot, not the post-discharge state. (Q2 scaffold)"
            }
            Self::ClaimsBatchReconciliation => {
                "Nightly X12 837 → 835 reconciliation across 100k claims; retry under storage fault is idempotent on claim-control-number. (Q2 scaffold)"
            }
            Self::BreakGlassUnderLoad => {
                "Break-glass activation under 1k inserts/sec — BreakGlassActivated audit MUST precede every PHI read in the session, BreakGlassClosed MUST enumerate every accessed resource. (Q2 scaffold)"
            }
            Self::ConsentRevocationCascade => {
                "Consent withdrawal during in-flight research queries; in-flight queries see pre-revocation snapshot, new queries see empty, audit chain links Withdrawn → ErasureRequested → ProjectionRowsPurge. (Q2 scaffold)"
            }
            Self::ClusterNodeProcessCrash => {
                "SIGKILL a follower's subprocess; supervisor restarts with bounded backoff and audits every attempt; other N-1 nodes remain writable. (v0.9.x cluster scenario)"
            }
            Self::ClusterCascadingNodeFailure => {
                "N-1 nodes crash in rapid sequence; cluster blocks writes but loses no committed entries; recovery preserves pre-cascade log in order. (v0.9.x cluster scenario)"
            }
            Self::ClusterHealthCheckTimeout => {
                "Node process hangs without crashing; /readyz flips red within timeout, supervisor escalates to forced restart, view change elects new leader if the hung node was primary. (v0.9.x cluster scenario)"
            }
            Self::ClusterConfigReloadUnderLoad => {
                "cluster.toml updated mid-write; supervisor applies new config without losing in-flight writes or dropping VSR view; quorum-shrinking reloads rejected. (v0.9.x cluster scenario)"
            }
            Self::ClusterRollingRestartFullCluster => {
                "Rolling restart sequenced across all N nodes; cluster writable throughout with quorum preserved; every pre-restart committed entry survives at the same offset. (v0.9.x cluster scenario)"
            }
        }
    }

    /// Returns true for scenarios whose simulator driver does not yet
    /// orchestrate the full behavior the scenario name implies.
    ///
    /// Each entry here has a real `ScenarioConfig` (network/storage/fault
    /// injectors) and runs to completion, but lacks a specialized driver
    /// step (sequential upgrade, explicit rollback, standby promotion
    /// handshake, concurrent-reconfig rejection, etc.). Gated behind the
    /// `aspirational-scenarios` feature so the default `just vopr-scenarios`
    /// list only advertises the battle-tested set. ROADMAP v0.5.0 item:
    /// "VOPR scaffolded scenarios — ship or delete."
    ///
    /// This function is the single source of truth — update here, not at
    /// call sites. Future releases should promote each entry back to
    /// non-aspirational as their drivers ship.
    pub fn is_aspirational(&self) -> bool {
        matches!(
            self,
            Self::ReconfigDuringViewChange
                | Self::ReconfigConcurrentRequests
                | Self::ReconfigJointQuorumValidation
                | Self::UpgradeGradualRollout
                | Self::UpgradeRollback
                | Self::UpgradeFeatureActivation
                | Self::StandbyPromotion
                | Self::StandbyReadScaling
                // v0.7.0 — workload-generator scaffolds. Drivers
                // ship per-family in subsequent commits; until
                // then the entries are visible via
                // `--list-aspirational-scenarios` only.
                | Self::MaskingClassMonotonicity
                | Self::MaskingDuplicateClassDefinition
                | Self::MaskingCrashAfterDdlBeforeReplay
                | Self::MaskingClassReadDuringRotation
                | Self::UpsertConcurrentInsertSamePk
                | Self::UpsertCrashMidConflict
                | Self::UpsertWithComputedReturning
                | Self::UpsertOnNonUniqueIndex
                | Self::AsOfDuringWrite
                | Self::AsOfMonotonicityUnderClockSkew
                | Self::AsOfRoundTripDeterminism
                | Self::EraseAutoDiscoveryAcrossSchemaVersions
                | Self::EraseAutoDiscoveryWithDroppedColumn
                | Self::EraseAutoDiscoveryDeterminism
                | Self::EraseAutoDiscoveryWithCrashMidScan // Note: the 5 Q2 healthcare clinical scenarios + the
                                                           // AsOfBeforeRetentionHorizon scenario were promoted to
                                                           // real drivers in the v0.9.0 healthcare-pivot sweep —
                                                           // see `fn ehr_admissions_surge` and siblings below.
                                                           // They are no longer aspirational.
        )
    }

    /// Returns the scenarios that ship in the default build — i.e. every
    /// scenario that is NOT aspirational. This is what
    /// `vopr --list-scenarios` and `just vopr-scenarios` display by default.
    pub fn shipping() -> Vec<ScenarioType> {
        Self::all()
            .iter()
            .copied()
            .filter(|s| !s.is_aspirational())
            .collect()
    }

    /// Returns all scenario types.
    pub fn all() -> &'static [ScenarioType] {
        &[
            Self::Baseline,
            Self::SwizzleClogging,
            Self::GrayFailures,
            Self::MultiTenantIsolation,
            Self::TimeCompression,
            Self::Combined,
            Self::ByzantineViewChangeMerge,
            Self::ByzantineCommitDesync,
            Self::ByzantineInflatedCommit,
            Self::ByzantineInvalidMetadata,
            Self::ByzantineMaliciousViewChange,
            Self::ByzantineLeaderRace,
            Self::ByzantineReplayOldView,
            Self::ByzantineCorruptChecksums,
            Self::ByzantineViewChangeBlocking,
            Self::ByzantinePrepareFlood,
            Self::ByzantineSelectiveSilence,
            Self::ByzantineDvcTailLengthMismatch,
            Self::ByzantineDvcIdenticalClaims,
            Self::ByzantineOversizedStartView,
            Self::ByzantineInvalidRepairRange,
            Self::ByzantineInvalidKernelCommand,
            Self::CorruptionBitFlip,
            Self::CorruptionChecksumValidation,
            Self::CorruptionSilentDiskFailure,
            Self::CrashDuringCommit,
            Self::CrashDuringViewChange,
            Self::RecoveryCorruptLog,
            Self::GrayFailureSlowDisk,
            Self::GrayFailureIntermittentNetwork,
            Self::RaceConcurrentViewChanges,
            Self::RaceCommitDuringDvc,
            Self::ClockDrift,
            Self::ClockOffsetExceeded,
            Self::ClockNtpFailure,
            Self::ClockBackwardJump,
            Self::ClientSessionCrash,
            Self::ClientSessionViewChangeLockout,
            Self::ClientSessionEviction,
            Self::RepairBudgetPreventsStorm,
            Self::RepairEwmaSelection,
            Self::RepairSyncTimeout,
            Self::PrimaryAbdicatePartition,
            Self::CommitStallDetection,
            Self::PingHeartbeat,
            Self::CommitMessageFallback,
            Self::StartViewChangeWindow,
            Self::TimeoutComprehensive,
            Self::ScrubDetectsCorruption,
            Self::ScrubCompletesTour,
            Self::ScrubRateLimited,
            Self::ScrubTriggersRepair,
            Self::ReconfigAddReplicas,
            Self::ReconfigRemoveReplicas,
            Self::ReconfigDuringPartition,
            Self::ReconfigDuringViewChange,
            Self::ReconfigConcurrentRequests,
            Self::ReconfigJointQuorumValidation,
            Self::UpgradeGradualRollout,
            Self::UpgradeWithFailure,
            Self::UpgradeRollback,
            Self::UpgradeFeatureActivation,
            Self::RbacUnauthorizedColumnAccess,
            Self::RbacRoleEscalationAttack,
            Self::RbacRowLevelSecurity,
            Self::RbacAuditTrailComplete,
            Self::SignatureForgedMessage,
            Self::SignatureTamperedContent,
            Self::SignatureUnsignedMessage,
            Self::SignatureWrongKey,
            Self::AlterTableCrashRecovery,
            Self::MaskingRoleTransition,
            Self::EraseSubjectWithCrash,
            // v0.7.0 — workload-generator scaffolds.
            Self::MaskingClassMonotonicity,
            Self::MaskingDuplicateClassDefinition,
            Self::MaskingCrashAfterDdlBeforeReplay,
            Self::MaskingClassReadDuringRotation,
            Self::UpsertConcurrentInsertSamePk,
            Self::UpsertCrashMidConflict,
            Self::UpsertWithComputedReturning,
            Self::UpsertOnNonUniqueIndex,
            Self::AsOfBeforeRetentionHorizon,
            Self::AsOfDuringWrite,
            Self::AsOfMonotonicityUnderClockSkew,
            Self::AsOfRoundTripDeterminism,
            Self::EraseAutoDiscoveryAcrossSchemaVersions,
            Self::EraseAutoDiscoveryWithDroppedColumn,
            Self::EraseAutoDiscoveryDeterminism,
            Self::EraseAutoDiscoveryWithCrashMidScan,
            // Q2 — Healthcare clinical scenarios.
            Self::EhrAdmissionsSurge,
            Self::LabResultDelayedDelivery,
            Self::ClaimsBatchReconciliation,
            Self::BreakGlassUnderLoad,
            Self::ConsentRevocationCascade,
            // Q2 — Cluster supervisor scenarios.
            Self::ClusterNodeProcessCrash,
            Self::ClusterCascadingNodeFailure,
            Self::ClusterHealthCheckTimeout,
            Self::ClusterConfigReloadUnderLoad,
            Self::ClusterRollingRestartFullCluster,
        ]
    }
}

// ============================================================================
// Scenario Configuration
// ============================================================================

/// Configuration for a specific test scenario.
#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    /// Scenario type.
    pub scenario_type: ScenarioType,
    /// Network configuration.
    pub network_config: NetworkConfig,
    /// Storage configuration.
    pub storage_config: StorageConfig,
    /// Swizzle-clogger (if enabled).
    pub swizzle_clogger: Option<SwizzleClogger>,
    /// Gray failure injector (if enabled).
    pub gray_failure_injector: Option<GrayFailureInjector>,
    /// Byzantine fault injector (if enabled).
    pub byzantine_injector: Option<ByzantineInjector>,
    /// Number of tenants (for multi-tenant scenarios).
    pub num_tenants: usize,
    /// Time compression factor (1.0 = normal, 10.0 = 10x faster).
    pub time_compression_factor: f64,
    /// Maximum simulation time (nanoseconds).
    pub max_time_ns: u64,
    /// Maximum events per simulation.
    pub max_events: u64,
}

impl ScenarioConfig {
    /// Creates a new scenario configuration for the given type.
    pub fn new(scenario_type: ScenarioType, seed: u64) -> Self {
        let mut rng = SimRng::new(seed);

        match scenario_type {
            ScenarioType::Baseline => Self::baseline(),
            ScenarioType::SwizzleClogging => Self::swizzle_clogging(&mut rng),
            ScenarioType::GrayFailures => Self::gray_failures(),
            ScenarioType::MultiTenantIsolation => Self::multi_tenant_isolation(&mut rng),
            ScenarioType::TimeCompression => Self::time_compression(),
            ScenarioType::Combined => Self::combined(&mut rng),
            ScenarioType::ByzantineViewChangeMerge => Self::byzantine_view_change_merge(),
            ScenarioType::ByzantineCommitDesync => Self::byzantine_commit_desync(),
            ScenarioType::ByzantineInflatedCommit => Self::byzantine_inflated_commit(),
            ScenarioType::ByzantineInvalidMetadata => Self::byzantine_invalid_metadata(),
            ScenarioType::ByzantineMaliciousViewChange => Self::byzantine_malicious_view_change(),
            ScenarioType::ByzantineLeaderRace => Self::byzantine_leader_race(),
            ScenarioType::ByzantineReplayOldView => Self::byzantine_replay_old_view(),
            ScenarioType::ByzantineCorruptChecksums => Self::byzantine_corrupt_checksums(),
            ScenarioType::ByzantineViewChangeBlocking => Self::byzantine_view_change_blocking(),
            ScenarioType::ByzantinePrepareFlood => Self::byzantine_prepare_flood(),
            ScenarioType::ByzantineSelectiveSilence => Self::byzantine_selective_silence(),
            ScenarioType::ByzantineDvcTailLengthMismatch => {
                Self::byzantine_dvc_tail_length_mismatch()
            }
            ScenarioType::ByzantineDvcIdenticalClaims => Self::byzantine_dvc_identical_claims(),
            ScenarioType::ByzantineOversizedStartView => Self::byzantine_oversized_start_view(),
            ScenarioType::ByzantineInvalidRepairRange => Self::byzantine_invalid_repair_range(),
            ScenarioType::ByzantineInvalidKernelCommand => Self::byzantine_invalid_kernel_command(),
            ScenarioType::CorruptionBitFlip => Self::corruption_bit_flip(),
            ScenarioType::CorruptionChecksumValidation => Self::corruption_checksum_validation(),
            ScenarioType::CorruptionSilentDiskFailure => Self::corruption_silent_disk_failure(),
            ScenarioType::CorruptionTornWrite => Self::corruption_torn_write(),
            ScenarioType::CrashDuringCommit => Self::crash_during_commit(),
            ScenarioType::CrashDuringViewChange => Self::crash_during_view_change(),
            ScenarioType::RecoveryCorruptLog => Self::recovery_corrupt_log(),
            ScenarioType::GrayFailureSlowDisk => Self::gray_failure_slow_disk(),
            ScenarioType::GrayFailureIntermittentNetwork => {
                Self::gray_failure_intermittent_network()
            }
            ScenarioType::RaceConcurrentViewChanges => Self::race_concurrent_view_changes(),
            ScenarioType::RaceCommitDuringDvc => Self::race_commit_during_dvc(),
            ScenarioType::ClockDrift => Self::clock_drift(),
            ScenarioType::ClockOffsetExceeded => Self::clock_offset_exceeded(),
            ScenarioType::ClockNtpFailure => Self::clock_ntp_failure(),
            ScenarioType::ClockBackwardJump => Self::clock_backward_jump(),
            ScenarioType::ClientSessionCrash => Self::client_session_crash(),
            ScenarioType::ClientSessionViewChangeLockout => {
                Self::client_session_view_change_lockout()
            }
            ScenarioType::ClientSessionEviction => Self::client_session_eviction(),
            ScenarioType::RepairBudgetPreventsStorm => Self::repair_budget_prevents_storm(&mut rng),
            ScenarioType::RepairEwmaSelection => Self::repair_ewma_selection(&mut rng),
            ScenarioType::RepairSyncTimeout => Self::repair_sync_timeout(),
            ScenarioType::PrimaryAbdicatePartition => Self::primary_abdicate_partition(&mut rng),
            ScenarioType::CommitStallDetection => Self::commit_stall_detection(),
            ScenarioType::PingHeartbeat => Self::ping_heartbeat(),
            ScenarioType::CommitMessageFallback => Self::commit_message_fallback(&mut rng),
            ScenarioType::StartViewChangeWindow => Self::start_view_change_window(),
            ScenarioType::TimeoutComprehensive => Self::timeout_comprehensive(&mut rng),
            ScenarioType::ScrubDetectsCorruption => Self::scrub_detects_corruption(),
            ScenarioType::ScrubCompletesTour => Self::scrub_completes_tour(),
            ScenarioType::ScrubRateLimited => Self::scrub_rate_limited(),
            ScenarioType::ScrubTriggersRepair => Self::scrub_triggers_repair(),
            ScenarioType::ReconfigAddReplicas => Self::reconfig_add_replicas(),
            ScenarioType::ReconfigRemoveReplicas => Self::reconfig_remove_replicas(),
            ScenarioType::ReconfigDuringPartition => Self::reconfig_during_partition(&mut rng),
            ScenarioType::ReconfigDuringViewChange => Self::reconfig_during_view_change(&mut rng),
            ScenarioType::ReconfigConcurrentRequests => Self::reconfig_concurrent_requests(),
            ScenarioType::ReconfigJointQuorumValidation => Self::reconfig_joint_quorum_validation(),
            ScenarioType::UpgradeGradualRollout => Self::upgrade_gradual_rollout(),
            ScenarioType::UpgradeWithFailure => Self::upgrade_with_failure(&mut rng),
            ScenarioType::UpgradeRollback => Self::upgrade_rollback(),
            ScenarioType::UpgradeFeatureActivation => Self::upgrade_feature_activation(),
            ScenarioType::StandbyFollowsLog => Self::standby_follows_log(),
            ScenarioType::StandbyPromotion => Self::standby_promotion(),
            ScenarioType::StandbyReadScaling => Self::standby_read_scaling(),
            ScenarioType::RbacUnauthorizedColumnAccess => Self::rbac_unauthorized_column_access(),
            ScenarioType::RbacRoleEscalationAttack => Self::rbac_role_escalation_attack(),
            ScenarioType::RbacRowLevelSecurity => Self::rbac_row_level_security(&mut rng),
            ScenarioType::RbacAuditTrailComplete => Self::rbac_audit_trail_complete(),
            ScenarioType::SignatureForgedMessage => Self::signature_forged_message(),
            ScenarioType::SignatureTamperedContent => Self::signature_tampered_content(),
            ScenarioType::SignatureUnsignedMessage => Self::signature_unsigned_message(),
            ScenarioType::SignatureWrongKey => Self::signature_wrong_key(),
            ScenarioType::AlterTableCrashRecovery => Self::alter_table_crash_recovery(&mut rng),
            ScenarioType::MaskingRoleTransition => Self::masking_role_transition(&mut rng),
            ScenarioType::EraseSubjectWithCrash => Self::erase_subject_with_crash(&mut rng),

            // v0.7.0 — workload-generator scaffolds. Each delegates to
            // the in-tree `aspirational_v07` factory, which builds a
            // baseline `ScenarioConfig` annotated with the canary
            // contract. Drivers ship per-family in subsequent
            // commits; the scaffold keeps the variants reachable
            // through `ScenarioConfig::new` so `vopr --list-aspirational-scenarios`
            // surfaces the contract today.
            ScenarioType::MaskingClassMonotonicity
            | ScenarioType::MaskingDuplicateClassDefinition
            | ScenarioType::MaskingCrashAfterDdlBeforeReplay
            | ScenarioType::MaskingClassReadDuringRotation
            | ScenarioType::UpsertConcurrentInsertSamePk
            | ScenarioType::UpsertCrashMidConflict
            | ScenarioType::UpsertWithComputedReturning
            | ScenarioType::UpsertOnNonUniqueIndex
            | ScenarioType::AsOfDuringWrite
            | ScenarioType::AsOfMonotonicityUnderClockSkew
            | ScenarioType::AsOfRoundTripDeterminism
            | ScenarioType::EraseAutoDiscoveryAcrossSchemaVersions
            | ScenarioType::EraseAutoDiscoveryWithDroppedColumn
            | ScenarioType::EraseAutoDiscoveryDeterminism
            | ScenarioType::EraseAutoDiscoveryWithCrashMidScan => {
                Self::aspirational_v07(scenario_type)
            }

            // Q3 (v0.9.0) — Healthcare clinical scenarios. Promoted out
            // of the aspirational_v07 set as part of the healthcare-pivot
            // release sweep. Each driver captures the fault shape that
            // the canary in description() must catch — the FHIR
            // projector worker and audit-log inserter run against the
            // same underlying VOPR primitives (gray-failure cycling,
            // storage reordering, swizzle clogging), but the parameters
            // are tuned to the clinical fault surface rather than the
            // generic baseline.
            ScenarioType::EhrAdmissionsSurge => Self::ehr_admissions_surge(),
            ScenarioType::LabResultDelayedDelivery => Self::lab_result_delayed_delivery(),
            ScenarioType::ClaimsBatchReconciliation => Self::claims_batch_reconciliation(),
            ScenarioType::BreakGlassUnderLoad => Self::break_glass_under_load(),
            ScenarioType::ConsentRevocationCascade => Self::consent_revocation_cascade(),

            // Q3 (v0.9.0) — `AS OF` retention-horizon scenario. The
            // canary is "time-travel queries against an offset older
            // than the retention horizon must surface
            // AsOfBeforeRetentionHorizon, not silent empty results".
            // Storage faults + sustained writes push the retention
            // boundary while readers issue AS OF queries at random
            // historical offsets.
            ScenarioType::AsOfBeforeRetentionHorizon => Self::as_of_before_retention_horizon(),

            // Q2 (v0.9.x) — Cluster supervisor scenarios. Each driver
            // expresses the fault shape the real `kimberlite-cluster`
            // supervisor would surface to the replicated log under the
            // canary contract in `description()`. Promoted out of the
            // aspirational set as part of the T2.3 driver pass.
            ScenarioType::ClusterNodeProcessCrash => Self::cluster_node_process_crash(),
            ScenarioType::ClusterCascadingNodeFailure => Self::cluster_cascading_node_failure(),
            ScenarioType::ClusterHealthCheckTimeout => Self::cluster_health_check_timeout(),
            ScenarioType::ClusterConfigReloadUnderLoad => Self::cluster_config_reload_under_load(),
            ScenarioType::ClusterRollingRestartFullCluster => {
                Self::cluster_rolling_restart_full_cluster()
            }
        }
    }

    /// v0.7.0 scaffold factory for the 16 workload-generator scenarios.
    /// Returns a baseline `ScenarioConfig` carrying the scenario_type
    /// so `--list-aspirational-scenarios` can describe the canary
    /// contract. The actual driver step is wired up in subsequent
    /// commits per family; until then these scenarios run the
    /// baseline workload.
    fn aspirational_v07(scenario_type: ScenarioType) -> Self {
        // AUDIT-2026-05 M-7. Use baseline scaffolding so no exotic
        // injectors fire prematurely.
        let mut cfg = Self::baseline();
        cfg.scenario_type = scenario_type;
        cfg
    }

    /// Baseline scenario: no faults.
    fn baseline() -> Self {
        Self {
            scenario_type: ScenarioType::Baseline,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000, // 1ms
                max_delay_ns: 5_000_000, // 5ms
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds
            max_events: 10_000,
        }
    }

    /// Swizzle-clogging scenario: intermittent network congestion.
    fn swizzle_clogging(rng: &mut SimRng) -> Self {
        // Choose aggressive or mild clogging randomly
        let clogger = if rng.next_bool() {
            SwizzleClogger::aggressive()
        } else {
            SwizzleClogger::mild()
        };

        Self {
            scenario_type: ScenarioType::SwizzleClogging,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.05, // 5% base drop rate
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(clogger),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000, // More events to observe clogging effects
        }
    }

    /// Gray failures scenario: partial node failures.
    fn gray_failures() -> Self {
        let gray_injector = GrayFailureInjector::new(
            0.1, // 10% chance of entering gray failure
            0.3, // 30% chance of recovery
        );

        Self {
            scenario_type: ScenarioType::GrayFailures,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 20_000_000, // Higher latency for slow nodes
                drop_probability: 0.02,
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(gray_injector),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Multi-tenant isolation scenario: multiple tenants with faults.
    fn multi_tenant_isolation(rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::MultiTenantIsolation,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: rng.next_f64() * 0.05, // 0-5%
                duplicate_probability: rng.next_f64() * 0.02,
                max_in_flight: 2000, // More capacity for multiple tenants
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 2_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                write_failure_probability: rng.next_f64() * 0.01,
                read_corruption_probability: rng.next_f64() * 0.001,
                fsync_failure_probability: rng.next_f64() * 0.01,
                partial_write_probability: rng.next_f64() * 0.01,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.4)),
            byzantine_injector: None,
            num_tenants: 5, // Test with 5 concurrent tenants
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds (more work)
            max_events: 25_000,          // More events for multiple tenants
        }
    }

    /// Time compression scenario: 10x accelerated time.
    fn time_compression() -> Self {
        Self {
            scenario_type: ScenarioType::TimeCompression,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.01,
                duplicate_probability: 0.005,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 10.0, // 10x faster
            max_time_ns: 100_000_000_000,  // 100 seconds simulated (10s real)
            max_events: 50_000,            // More events in compressed time
        }
    }

    /// Combined scenario: all fault types enabled.
    fn combined(rng: &mut SimRng) -> Self {
        let clogger = if rng.next_bool() {
            SwizzleClogger::aggressive()
        } else {
            SwizzleClogger::mild()
        };

        let gray_injector = GrayFailureInjector::new(0.15, 0.25);

        Self {
            scenario_type: ScenarioType::Combined,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 50_000_000,               // High variability
                drop_probability: rng.next_f64() * 0.1, // 0-10%
                duplicate_probability: rng.next_f64() * 0.05,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 500_000,
                write_failure_probability: rng.next_f64() * 0.02,
                read_corruption_probability: rng.next_f64() * 0.002,
                fsync_failure_probability: rng.next_f64() * 0.02,
                partial_write_probability: rng.next_f64() * 0.02,
                ..Default::default()
            },
            swizzle_clogger: Some(clogger),
            gray_failure_injector: Some(gray_injector),
            byzantine_injector: None,
            num_tenants: 3,               // Multiple tenants
            time_compression_factor: 5.0, // 5x compression
            max_time_ns: 50_000_000_000,  // 50 seconds simulated
            max_events: 30_000,
        }
    }

    /// Byzantine scenario: View change log merge (Bug #1).
    fn byzantine_view_change_merge() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineViewChangeMerge,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1, // Force view changes
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::ViewChangeMergeOverwrite.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000, // More events to trigger view changes
        }
    }

    /// Byzantine scenario: Commit number desync (Bug #2).
    fn byzantine_commit_desync() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineCommitDesync,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1,
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::CommitNumberDesync.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: Inflated commit number (Bug #3).
    fn byzantine_inflated_commit() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineInflatedCommit,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1,
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::InflatedCommitNumber.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: Invalid entry metadata (Bug #4).
    fn byzantine_invalid_metadata() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineInvalidMetadata,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.05,
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::InvalidEntryMetadata.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Byzantine scenario: Malicious view change selection (Bug #5).
    fn byzantine_malicious_view_change() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineMaliciousViewChange,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::MaliciousViewChangeSelection.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: Leader selection race (Bug #6).
    fn byzantine_leader_race() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineLeaderRace,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 15_000_000, // High variance for races
                drop_probability: 0.15,   // More partitions
                duplicate_probability: 0.03,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::LeaderSelectionRace.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 25_000, // More events for race conditions
        }
    }

    /// Byzantine scenario: Replay old view messages (AUDIT-2026-03 H-1).
    fn byzantine_replay_old_view() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::ByzantineReplayOldView,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.05,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::ReplayOldView {
                    old_view: 2, // Replay messages from 2 views ago
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Byzantine scenario: Corrupt message checksums (AUDIT-2026-03 H-1).
    fn byzantine_corrupt_checksums() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::ByzantineCorruptChecksums,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::CorruptChecksums {
                    corruption_rate: 0.1, // 10% checksum corruption rate
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Byzantine scenario: Block DoViewChange messages (AUDIT-2026-03 H-1).
    fn byzantine_view_change_blocking() -> Self {
        use crate::ProtocolAttack;
        use kimberlite_vsr::ReplicaId;
        Self {
            scenario_type: ScenarioType::ByzantineViewChangeBlocking,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::ViewChangeBlocking {
                    blocked_replicas: vec![ReplicaId::new(2), ReplicaId::new(3)], // Block 2 replicas
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000, // More events to observe liveness impact
        }
    }

    /// Byzantine scenario: Flood with excessive Prepare messages (AUDIT-2026-03 H-1).
    fn byzantine_prepare_flood() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::ByzantinePrepareFlood,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.05,
                duplicate_probability: 0.02,
                max_in_flight: 2000, // Higher to allow flood
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::PrepareFlood {
                    rate_multiplier: 10, // Send 10x normal Prepare messages
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 30_000, // More events for flooding scenario
        }
    }

    /// Byzantine scenario: Selectively ignore messages from specific replicas (AUDIT-2026-03 H-1).
    fn byzantine_selective_silence() -> Self {
        use crate::ProtocolAttack;
        use kimberlite_vsr::ReplicaId;
        Self {
            scenario_type: ScenarioType::ByzantineSelectiveSilence,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::SelectiveSilence {
                    ignored_replicas: vec![ReplicaId::new(1), ReplicaId::new(4)], // Ignore 2 replicas
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: DoViewChange log_tail length mismatch (Bug 3.1).
    fn byzantine_dvc_tail_length_mismatch() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineDvcTailLengthMismatch,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::InflatedCommitNumber.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: DoViewChange with identical claims (Bug 3.3).
    fn byzantine_dvc_identical_claims() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineDvcIdenticalClaims,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::MaliciousViewChangeSelection.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: Oversized StartView log_tail (Bug 3.4 - DoS).
    fn byzantine_oversized_start_view() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineOversizedStartView,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::ViewChangeMergeOverwrite.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Byzantine scenario: Invalid repair range (Bug 3.5).
    fn byzantine_invalid_repair_range() -> Self {
        Self {
            scenario_type: ScenarioType::ByzantineInvalidRepairRange,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.1, // Some drops to trigger repair
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::new()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Byzantine scenario: Invalid kernel command (Bug 3.2).
    fn byzantine_invalid_kernel_command() -> Self {
        use crate::AttackPattern;
        Self {
            scenario_type: ScenarioType::ByzantineInvalidKernelCommand,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(AttackPattern::InflatedCommitNumber.injector()),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Corruption scenario: Random bit flip in log entry.
    fn corruption_bit_flip() -> Self {
        Self {
            scenario_type: ScenarioType::CorruptionBitFlip,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig {
                read_corruption_probability: 0.01, // 1% corruption rate
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Corruption scenario: Checksum validation test.
    fn corruption_checksum_validation() -> Self {
        Self {
            scenario_type: ScenarioType::CorruptionChecksumValidation,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig {
                read_corruption_probability: 0.05, // 5% corruption rate
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Corruption scenario: Silent disk failure.
    fn corruption_silent_disk_failure() -> Self {
        Self {
            scenario_type: ScenarioType::CorruptionSilentDiskFailure,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig {
                read_corruption_probability: 0.02,
                write_failure_probability: 0.01,
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Corruption scenario: Torn write detection (AUDIT-2026-03 M-8).
    ///
    /// Simulates incomplete writes from power loss or crash mid-write.
    /// Tests that RECORD_START/END sentinel markers detect torn writes.
    fn corruption_torn_write() -> Self {
        Self {
            scenario_type: ScenarioType::CorruptionTornWrite,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig {
                // Simulate torn writes (partial writes from power loss mid-write)
                partial_write_probability: 0.05, // 5% torn write rate
                write_failure_probability: 0.02, // 2% write failure rate
                enable_crash_recovery: true,     // Enable crash simulation
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.1)), // Occasional crashes
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Crash scenario: During commit application.
    fn crash_during_commit() -> Self {
        Self {
            scenario_type: ScenarioType::CrashDuringCommit,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Crash scenario: During view change.
    fn crash_during_view_change() -> Self {
        Self {
            scenario_type: ScenarioType::CrashDuringViewChange,
            network_config: NetworkConfig {
                drop_probability: 0.1, // Cause view changes
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.1, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 25_000,
        }
    }

    /// Recovery scenario: Corrupt log.
    fn recovery_corrupt_log() -> Self {
        Self {
            scenario_type: ScenarioType::RecoveryCorruptLog,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig {
                read_corruption_probability: 0.03,
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.02, 0.05)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Gray failure scenario: Slow disk I/O.
    fn gray_failure_slow_disk() -> Self {
        Self {
            scenario_type: ScenarioType::GrayFailureSlowDisk,
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.3, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 15_000,
        }
    }

    /// Gray failure scenario: Intermittent network.
    fn gray_failure_intermittent_network() -> Self {
        Self {
            scenario_type: ScenarioType::GrayFailureIntermittentNetwork,
            network_config: NetworkConfig {
                drop_probability: 0.2,
                duplicate_probability: 0.05,
                min_delay_ns: 1_000_000,
                max_delay_ns: 20_000_000,
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.2, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// Race scenario: Concurrent view changes.
    fn race_concurrent_view_changes() -> Self {
        Self {
            scenario_type: ScenarioType::RaceConcurrentViewChanges,
            network_config: NetworkConfig {
                drop_probability: 0.15,
                min_delay_ns: 1_000_000,
                max_delay_ns: 15_000_000,
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 30_000,
        }
    }

    /// Race scenario: Commit during DoViewChange.
    fn race_commit_during_dvc() -> Self {
        Self {
            scenario_type: ScenarioType::RaceCommitDuringDvc,
            network_config: NetworkConfig {
                drop_probability: 0.1,
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                ..Default::default()
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 25_000,
        }
    }

    // ========================================================================
    // Phase 1: Clock Synchronization Scenarios
    // ========================================================================

    /// Clock scenario: Gradual drift detection.
    ///
    /// Tests that replicas detect and handle gradual clock drift within
    /// tolerance bounds (CLOCK_OFFSET_TOLERANCE_MS = 500ms).
    fn clock_drift() -> Self {
        Self {
            scenario_type: ScenarioType::ClockDrift,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds for drift to accumulate
            max_events: 50_000,
        }
    }

    /// Clock scenario: Offset exceeds tolerance.
    ///
    /// Tests that replicas reject clock samples when offset exceeds
    /// CLOCK_OFFSET_TOLERANCE_MS (500ms).
    fn clock_offset_exceeded() -> Self {
        Self {
            scenario_type: ScenarioType::ClockOffsetExceeded,
            network_config: NetworkConfig {
                min_delay_ns: 5_000_000,   // Higher delay to cause offset
                max_delay_ns: 100_000_000, // Very high delay (100ms)
                drop_probability: 0.1,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.15, 0.05)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 30_000,
        }
    }

    /// Clock scenario: NTP failure simulation.
    ///
    /// Tests graceful degradation when clock samples are unavailable
    /// (simulating NTP server failure).
    fn clock_ntp_failure() -> Self {
        Self {
            scenario_type: ScenarioType::ClockNtpFailure,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.3, // High drop rate to prevent clock samples
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.2, 0.05)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 25_000,
        }
    }

    /// Clock scenario: Backward jump during partition.
    ///
    /// Tests that clock monotonicity is preserved when:
    /// 1. Primary gets partitioned from cluster
    /// 2. System clock jumps backward (simulating NTP adjustment)
    /// 3. View change occurs and new primary takes over
    /// 4. Original primary rejoins with stale clock
    ///
    /// **Critical test:** Ensures HIPAA/GDPR audit timestamp monotonicity
    /// even under extreme clock conditions (backward jumps).
    fn clock_backward_jump() -> Self {
        Self {
            scenario_type: ScenarioType::ClockBackwardJump,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.15, // Moderate drops to trigger partition
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()), // Network partition simulation
            gray_failure_injector: Some(GrayFailureInjector::new(0.1, 0.2)), // Intermittent failures
            byzantine_injector: None, // No Byzantine attacks, just clock issues
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 seconds for partition + view change + recovery
            max_events: 40_000,
        }
    }

    // ========================================================================
    // Phase 1: Client Session Scenarios
    // ========================================================================

    /// Client session scenario: Crash recovery (VRR Bug #1).
    ///
    /// Tests that successive client crashes with request number reset
    /// don't cause request collisions (wrong cached replies returned).
    fn client_session_crash() -> Self {
        Self {
            scenario_type: ScenarioType::ClientSessionCrash,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.05,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.1, 0.2)), // Simulate client crashes
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 40_000,
        }
    }

    /// Client session scenario: View change lockout prevention (VRR Bug #2).
    ///
    /// Tests that uncommitted client sessions are discarded during view
    /// change to prevent client lockout (new leader rejects client).
    fn client_session_view_change_lockout() -> Self {
        Self {
            scenario_type: ScenarioType::ClientSessionViewChangeLockout,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.15, // Trigger view changes
                duplicate_probability: 0.03,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.1, 0.1)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 35_000,
        }
    }

    /// Client session scenario: Deterministic eviction.
    ///
    /// Tests that session eviction is deterministic across all replicas
    /// when max_sessions limit is exceeded (evicts by oldest commit_timestamp).
    fn client_session_eviction() -> Self {
        Self {
            scenario_type: ScenarioType::ClientSessionEviction,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.01,
                max_in_flight: 2000, // Higher capacity for many sessions
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 3, // Multiple tenants to create many sessions
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 100_000,         // High event count to trigger eviction
        }
    }

    /// Phase 2 Scenario: Repair budget prevents repair storm.
    ///
    /// Tests that when multiple replicas fall behind, the repair budget
    /// system prevents message queue overflow by rate-limiting repair requests.
    fn repair_budget_prevents_storm(_rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::RepairBudgetPreventsStorm,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000, // Higher latency
                drop_probability: 0.15,   // High drop rate to create lag
                duplicate_probability: 0.0,
                max_in_flight: 100, // Limited capacity to test overflow
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: Some(GrayFailureInjector::new(
                0.3, // 30% failure probability
                0.1, // 10% recovery probability (stay slow)
            )),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds
            max_events: 50_000,
        }
    }

    /// Phase 2 Scenario: EWMA-based smart replica selection.
    ///
    /// Tests that repair requests are intelligently routed to fast replicas
    /// based on EWMA latency tracking.
    fn repair_ewma_selection(_rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::RepairEwmaSelection,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 50_000_000, // Wide latency variance
                drop_probability: 0.05,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(
                0.4,  // 40% failure probability (slow replicas)
                0.05, // 5% recovery (persistent slowness)
            )),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 40_000,
        }
    }

    /// Phase 2 Scenario: Repair sync timeout escalates to state transfer.
    ///
    /// Tests that when repair is stuck for a large gap (>100 ops), the
    /// repair sync timeout triggers escalation to state transfer.
    fn repair_sync_timeout() -> Self {
        Self {
            scenario_type: ScenarioType::RepairSyncTimeout,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.30, // Very high drop rate to stall repair
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 seconds (long enough for timeout)
            max_events: 50_000,
        }
    }

    /// Phase 2 Scenario: Primary abdicate when partitioned from quorum.
    ///
    /// Tests that when the leader is partitioned from a quorum of replicas,
    /// the primary abdicate timeout causes it to step down, preventing deadlock.
    fn primary_abdicate_partition(_rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::PrimaryAbdicatePartition,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0, // Controlled via swizzle
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::new(
                0.5, // 50% clog probability
                0.3, // 30% unclog probability
                3.0, // 3x delay multiplier
                0.8, // 80% drop when clogged
            )),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 30_000,
        }
    }

    /// Phase 2 Scenario: Commit stall detection and backpressure.
    ///
    /// Tests that when the pipeline grows without commit progress, the
    /// commit stall timeout detects the condition and applies backpressure.
    fn commit_stall_detection() -> Self {
        Self {
            scenario_type: ScenarioType::CommitStallDetection,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.10, // Moderate drop rate
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 60_000,          // High load to create pipeline pressure
        }
    }

    /// Phase 2.2 Scenario: Ping heartbeat health checks.
    ///
    /// Tests that ping timeout triggers regular heartbeats from the leader,
    /// ensuring continuous network health monitoring and early failure detection.
    fn ping_heartbeat() -> Self {
        Self {
            scenario_type: ScenarioType::PingHeartbeat,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.05, // Some drops to test heartbeat resilience
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds
            max_events: 10_000,
        }
    }

    /// Phase 2.2 Scenario: Commit message fallback via heartbeat.
    ///
    /// Tests that when commit messages are delayed or dropped, the commit message
    /// timeout triggers heartbeat fallback to notify backups of commit progress.
    fn commit_message_fallback(rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::CommitMessageFallback,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 20_000_000, // Higher latency to cause delays
                drop_probability: rng.next_f64() * 0.15, // 0-15% drop rate
                duplicate_probability: 0.01,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 20_000,
        }
    }

    /// Phase 2.2 Scenario: Start view change window timeout.
    ///
    /// Tests that the view change window timeout prevents premature view change
    /// completion, ensuring split-brain prevention through delayed installation.
    fn start_view_change_window() -> Self {
        Self {
            scenario_type: ScenarioType::StartViewChangeWindow,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 15_000_000, // Moderate latency
                drop_probability: 0.10,   // Trigger view changes
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()), // Trigger view changes
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 30_000,
        }
    }

    /// Phase 2.2 Scenario: Comprehensive timeout testing.
    ///
    /// Tests all timeout types (heartbeat, prepare, view change, recovery,
    /// clock sync, ping, primary abdicate, repair sync, commit stall, commit
    /// message, start view change window) under various fault conditions.
    fn timeout_comprehensive(rng: &mut SimRng) -> Self {
        let gray_injector = GrayFailureInjector::new(
            0.15, // 15% chance of gray failure
            0.25, // 25% recovery chance
        );

        Self {
            scenario_type: ScenarioType::TimeoutComprehensive,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 30_000_000, // High latency to trigger timeouts
                drop_probability: rng.next_f64() * 0.20, // 0-20% drops
                duplicate_probability: rng.next_f64() * 0.05,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000, // Slow writes
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 500_000,
                write_failure_probability: rng.next_f64() * 0.05,
                read_corruption_probability: rng.next_f64() * 0.01,
                fsync_failure_probability: rng.next_f64() * 0.05,
                partial_write_probability: rng.next_f64() * 0.02,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: Some(gray_injector),
            byzantine_injector: None,
            num_tenants: 3, // Multiple tenants to increase load
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds
            max_events: 50_000,          // High event count to exercise all timeouts
        }
    }

    // ========================================================================
    // Phase 3: Storage Integrity Scenarios
    // ========================================================================

    /// Phase 3 Scenario: Scrubber detects corruption.
    ///
    /// Tests that background scrubbing detects corrupted entries via checksum
    /// validation and triggers appropriate repair.
    fn scrub_detects_corruption() -> Self {
        Self {
            scenario_type: ScenarioType::ScrubDetectsCorruption,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0, // Clean network for deterministic corruption
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None, // Note: Would use CorruptionInjector if available
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds (enough for tour)
            max_events: 10_000,
        }
    }

    /// Phase 3 Scenario: Scrubber completes tour.
    ///
    /// Tests that the scrubber successfully tours the entire log within
    /// a reasonable time window, validating all entries.
    fn scrub_completes_tour() -> Self {
        Self {
            scenario_type: ScenarioType::ScrubCompletesTour,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds (long enough for full tour)
            max_events: 50_000,          // Large log to test tour completion
        }
    }

    /// Phase 3 Scenario: Scrubber respects rate limits.
    ///
    /// Tests that scrubbing respects the IOPS budget (max 10 reads/tick)
    /// and doesn't impact production traffic.
    fn scrub_rate_limited() -> Self {
        Self {
            scenario_type: ScenarioType::ScrubRateLimited,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 100_000,         // High load to test rate limiting under pressure
        }
    }

    /// Phase 3 Scenario: Scrubber triggers repair on corruption.
    ///
    /// Tests that when the scrubber detects corruption, it automatically
    /// triggers repair to restore data integrity.
    fn scrub_triggers_repair() -> Self {
        Self {
            scenario_type: ScenarioType::ScrubTriggersRepair,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02, // Some loss to test repair under stress
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 20_000,
        }
    }

    // ========================================================================
    // Phase 4: Cluster Reconfiguration Scenarios
    // ========================================================================

    /// Phase 4 scenario: Add replicas (3 → 5).
    ///
    /// Tests joint consensus protocol for adding replicas safely.
    fn reconfig_add_replicas() -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigAddReplicas,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0, // No loss initially
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds for reconfiguration
            max_events: 10_000,
        }
    }

    /// Phase 4 scenario: Remove replicas (5 → 3).
    ///
    /// Tests joint consensus protocol for removing replicas safely.
    fn reconfig_remove_replicas() -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigRemoveReplicas,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000,
            max_events: 10_000,
        }
    }

    /// Phase 4 scenario: Reconfiguration during network partition.
    ///
    /// Tests that reconfigurations survive network partitions and view changes.
    fn reconfig_during_partition(_rng: &mut crate::rng::SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigDuringPartition,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.1, // 10% loss to create partitions
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds (needs time for recovery)
            max_events: 15_000,
        }
    }

    /// Phase 4 scenario: View change during joint consensus.
    ///
    /// Tests that view changes during reconfiguration preserve the joint consensus state.
    /// Leader fails during joint consensus, new leader must recover reconfiguration state.
    fn reconfig_during_view_change(_rng: &mut crate::rng::SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigDuringViewChange,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.05, // 5% loss to trigger view changes
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 seconds (time for view change + reconfig)
            max_events: 12_000,
        }
    }

    /// Phase 4 scenario: Concurrent reconfiguration requests.
    ///
    /// Tests that multiple concurrent reconfiguration requests are rejected.
    /// Only one reconfiguration can be in progress at a time.
    fn reconfig_concurrent_requests() -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigConcurrentRequests,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 10_000,
        }
    }

    /// Phase 4 scenario: Joint quorum validation.
    ///
    /// Tests that joint consensus correctly requires quorum in BOTH old and new configs.
    /// Attempts to commit with quorum in only one config should fail.
    fn reconfig_joint_quorum_validation() -> Self {
        Self {
            scenario_type: ScenarioType::ReconfigJointQuorumValidation,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 10_000,
        }
    }

    // ========================================================================
    // Phase 4.2: Rolling Upgrade Scenarios
    // ========================================================================

    /// Phase 4.2 scenario: Gradual rollout (sequential upgrade).
    ///
    /// Tests upgrading replicas one-by-one from v0.3.0 → v0.4.0 without service disruption.
    /// Cluster version should increase as each replica upgrades.
    fn upgrade_gradual_rollout() -> Self {
        Self {
            scenario_type: ScenarioType::UpgradeGradualRollout,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0, // No packet loss during upgrade
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds (time for sequential upgrades)
            max_events: 15_000,
        }
    }

    /// Phase 4.2 scenario: Replica failure during upgrade.
    ///
    /// Tests that cluster remains operational when a replica fails mid-upgrade.
    /// Verifies: ongoing operations complete, new leader elected if needed.
    fn upgrade_with_failure(_rng: &mut crate::rng::SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::UpgradeWithFailure,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.05, // 5% loss to simulate instability
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.1, 0.3)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 35_000_000_000, // 35 seconds (longer for recovery)
            max_events: 18_000,
        }
    }

    /// Phase 4.2 scenario: Rollback to previous version.
    ///
    /// Tests rolling back from v0.4.0 → v0.3.0 when issues detected.
    /// Cluster version should decrease as replicas roll back.
    fn upgrade_rollback() -> Self {
        Self {
            scenario_type: ScenarioType::UpgradeRollback,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 seconds
            max_events: 12_000,
        }
    }

    /// Phase 4.2 scenario: Feature flag activation.
    ///
    /// Tests that new features (e.g., ClusterReconfig) activate only when
    /// all replicas reach the required version (v0.4.0).
    fn upgrade_feature_activation() -> Self {
        Self {
            scenario_type: ScenarioType::UpgradeFeatureActivation,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 seconds
            max_events: 10_000,
        }
    }

    // ========================================================================
    // Phase 4.3: Standby Replica Scenarios
    // ========================================================================

    /// Phase 4.3 scenario: Standby follows log without participating in quorum.
    ///
    /// Tests that standby replicas:
    /// - Receive Prepare messages from active replicas
    /// - Append entries to log but DON'T send PrepareOK
    /// - Track commit_number from Commit messages
    /// - Never affect quorum decisions
    ///
    /// Verification (Kani Proof #68): Standby NEVER sends PrepareOK.
    fn standby_follows_log() -> Self {
        Self {
            scenario_type: ScenarioType::StandbyFollowsLog,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.02, // 2% loss (normal network conditions)
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 seconds
            max_events: 12_000,
        }
    }

    /// Phase 4.3 scenario: Standby promotion to active replica.
    ///
    /// Tests that standby replicas can be safely promoted to active status:
    /// - Standby must be up-to-date (log matches active primary)
    /// - Promotion requires cluster reconfiguration (joint consensus)
    /// - Promoted replica begins participating in quorum
    /// - Log consistency is preserved (no divergence)
    ///
    /// Verification (Kani Proof #69): Promotion preserves log consistency.
    fn standby_promotion() -> Self {
        Self {
            scenario_type: ScenarioType::StandbyPromotion,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0, // No loss during promotion
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 seconds
            max_events: 15_000,
        }
    }

    /// Phase 4.3 scenario: Read scaling with multiple standby replicas.
    ///
    /// Tests that multiple standby replicas can serve read-only queries:
    /// - Standby replicas serve eventually consistent reads
    /// - Reads may lag behind committed operations
    /// - No impact on active cluster performance (quorum)
    /// - Load distributed across multiple standbys
    ///
    /// Use case: Geographic DR + read scaling (offload queries from active replicas).
    fn standby_read_scaling() -> Self {
        Self {
            scenario_type: ScenarioType::StandbyReadScaling,
            network_config: NetworkConfig {
                min_delay_ns: 2_000_000, // Higher latency (geographic distribution)
                max_delay_ns: 10_000_000,
                drop_probability: 0.03, // 3% loss (cross-datacenter)
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.2)), // Slow reads
            byzantine_injector: None,
            num_tenants: 3, // Multi-tenant read workload
            time_compression_factor: 1.0,
            max_time_ns: 40_000_000_000, // 40 seconds
            max_events: 20_000,
        }
    }

    // ========================================================================
    // Phase 3.2: RBAC (Role-Based Access Control) Scenarios
    // ========================================================================

    /// Phase 3.2 scenario: Unauthorized column access attempt.
    ///
    /// Tests that users cannot access columns denied by their role policy.
    fn rbac_unauthorized_column_access() -> Self {
        Self {
            scenario_type: ScenarioType::RbacUnauthorizedColumnAccess,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds
            max_events: 5_000,
        }
    }

    /// Phase 3.2 scenario: Role escalation attack prevention.
    ///
    /// Tests that users cannot escalate their role privileges.
    fn rbac_role_escalation_attack() -> Self {
        Self {
            scenario_type: ScenarioType::RbacRoleEscalationAttack,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds
            max_events: 5_000,
        }
    }

    /// Phase 3.2 scenario: Row-level security enforcement.
    ///
    /// Tests that multi-tenant queries are automatically filtered by tenant_id.
    fn rbac_row_level_security(_rng: &mut crate::rng::SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::RbacRowLevelSecurity,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 5, // Multiple tenants for RLS testing
            time_compression_factor: 1.0,
            max_time_ns: 15_000_000_000, // 15 seconds
            max_events: 10_000,
        }
    }

    /// Phase 3.2 scenario: Audit trail completeness.
    ///
    /// Tests that all access attempts (allowed and denied) are logged.
    fn rbac_audit_trail_complete() -> Self {
        Self {
            scenario_type: ScenarioType::RbacAuditTrailComplete,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000, // 10 seconds
            max_events: 5_000,
        }
    }

    // ========================================================================
    // Signature Attack Scenarios (AUDIT-2026-03 M-3)
    // ========================================================================

    fn signature_forged_message() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::SignatureForgedMessage,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::ForgedSignature,
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 10_000,
        }
    }

    fn signature_tampered_content() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::SignatureTamperedContent,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::TamperedContent,
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 10_000,
        }
    }

    fn signature_unsigned_message() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::SignatureUnsignedMessage,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::UnsignedMessage,
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 10_000,
        }
    }

    fn signature_wrong_key() -> Self {
        use crate::ProtocolAttack;
        Self {
            scenario_type: ScenarioType::SignatureWrongKey,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: Some(ByzantineInjector::from_protocol_attack(
                ProtocolAttack::WrongKey {
                    wrong_replica_id: ReplicaId::new(99), // Use non-existent replica ID
                },
            )),
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 10_000,
        }
    }

    /// v0.6.0 Tier 1 #5 — ALTER TABLE crash recovery scenario.
    ///
    /// Simulates the downstream (Notebar) failure-report shape:
    /// schema evolution under concurrent DML with a storage crash
    /// injected during the ALTER window. The config mirrors the
    /// existing `CrashDuringCommit` profile but bumps partial-write
    /// and fsync-failure probabilities so the crash is likely to
    /// land in the `TableMetadataWrite` → `AuditLogAppend` effect
    /// pair from `kernel.rs:520-525,597-602`. A small amount of
    /// gray-failure jitter is layered in so the ALTER doesn't
    /// always arrive on a quiescent log — the hardening target is
    /// "ALTER + INSERT concurrency" specifically.
    ///
    /// Recovery invariants checked by the shared VOPR invariant
    /// suite under this config:
    ///   (i)   hash-chain integrity — every appended event's
    ///         `prev_hash` matches the previous event's content
    ///         hash (`kimberlite-storage` `latest_chain_hash`
    ///         recovery path).
    ///   (ii)  `schema_version` monotonicity — enforced by the
    ///         kernel's production `assert!()` in `kernel.rs:508`
    ///         and `:586`; any VSR replay that decreases it would
    ///         panic.
    ///   (iii) Event-ordering preserved — append-only log ordering
    ///         is a VOPR invariant already (`offset_monotonicity`).
    ///   (iv)  Pre-ALTER rows project NULL for the new column —
    ///         exercised end-to-end by the dedicated integration
    ///         test in `crates/kimberlite/tests/
    ///         alter_table_crash_recovery.rs` (see `docs-internal/
    ///         vopr/scenario-catalogue.md`).
    fn alter_table_crash_recovery(rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::AlterTableCrashRecovery,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: rng.next_f64() * 0.02, // 0–2 % packet loss
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                // Push crash-shaped faults — the whole point of the scenario.
                write_failure_probability: rng.next_f64() * 0.02,
                fsync_failure_probability: rng.next_f64() * 0.02,
                partial_write_probability: rng.next_f64() * 0.02,
                // Light read corruption so post-recovery SELECTs exercise
                // the checksum path; the kernel must reject corrupt rows.
                read_corruption_probability: rng.next_f64() * 0.001,
                ..Default::default()
            },
            swizzle_clogger: None,
            // Light gray-failure jitter — ALTER should have to coexist
            // with a misbehaving peer, not a pristine log.
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.3)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// v0.6.0 Tier 2 #7 — Masking policy role-transition scenario.
    ///
    /// Exercises concurrent reads against a table with an attached
    /// masking policy while a workload repeatedly rotates the
    /// session-role. Three invariants matter end-to-end:
    ///
    ///   (i)   Hash-chain integrity under a mild fault profile —
    ///         enforced by the existing `HashChainChecker` invariant.
    ///   (ii)  Offset monotonicity under concurrent reads + writes —
    ///         enforced by the existing offset-monotonicity invariant.
    ///   (iii) No unmasked leakage to a non-exempt role — kernel-side
    ///         invariant in `RoleGuard::should_mask`; every masked
    ///         column read is gated on the session role, so an
    ///         unmasked value never reaches the result set for a
    ///         non-exempt role regardless of transition timing.
    ///
    /// The scenario is parameterised as a workload variant over the
    /// baseline fault profile so the three invariants above are
    /// checked under realistic network + storage jitter. Deeper
    /// masking-specific checkers are a follow-up (see
    /// docs-internal/vopr/scenario-catalogue.md).
    fn masking_role_transition(rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::MaskingRoleTransition,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: rng.next_f64() * 0.01, // 0–1 % packet loss
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                // Light fault profile — the scenario stresses role
                // transitions, not disk recovery.
                write_failure_probability: rng.next_f64() * 0.005,
                fsync_failure_probability: 0.0,
                partial_write_probability: 0.0,
                read_corruption_probability: 0.0,
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    /// v0.6.0 Tier 2 #4 — `eraseSubject` crash-recovery scenario.
    ///
    /// Injects storage-layer crashes while an `eraseSubject` call is
    /// in-flight (DEK shred half-complete, projection walk
    /// in-progress). Recovery must produce a valid hash-chain AND
    /// either a signed completion proof (if the erase finished) or a
    /// resumable in-progress audit record (if not) — never silent
    /// incomplete erasure.
    ///
    /// Invariants enforced:
    ///
    ///   (i)   Hash-chain integrity across the crash — existing
    ///         `HashChainChecker`.
    ///   (ii)  Signed attestation witness verifies — verified by the
    ///         kernel's attestation path on every emitted proof; any
    ///         malformed witness trips a production assertion.
    ///   (iii) Atomicity: either every subject row is gone OR the
    ///         audit trail explicitly marks the erase as in-progress
    ///         with a resumable request-id — no silent half-erase.
    ///
    /// Uses an aggressive fault profile (fsync + partial-write +
    /// write-failure) so crashes land mid-operation with high
    /// probability across the simulated seed space.
    fn erase_subject_with_crash(rng: &mut SimRng) -> Self {
        Self {
            scenario_type: ScenarioType::EraseSubjectWithCrash,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: rng.next_f64() * 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                // Crash-shaped faults — the whole point of the scenario.
                write_failure_probability: rng.next_f64() * 0.03,
                fsync_failure_probability: rng.next_f64() * 0.02,
                partial_write_probability: rng.next_f64() * 0.02,
                // Light read corruption so post-recovery re-reads exercise
                // the checksum path.
                read_corruption_probability: rng.next_f64() * 0.001,
                ..Default::default()
            },
            swizzle_clogger: None,
            gray_failure_injector: Some(GrayFailureInjector::new(0.05, 0.3)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 10_000_000_000,
            max_events: 20_000,
        }
    }

    // ========================================================================
    // Q2 (v0.9.x) — Cluster supervisor scenarios. Sibling to the VSR
    // consensus scenarios above. The in-process VOPR runtime does not
    // model an OS-level process supervisor, so these drivers express
    // the same fault shapes the real `kimberlite-cluster` supervisor
    // would experience — one or more replicas going dark, hanging,
    // or being restarted in sequence — and rely on the existing VSR
    // invariants (offset monotonicity, prefix property, durability,
    // hash-chain integrity) to surface any violation. The canary
    // contracts in `description()` describe the supervisor-level
    // behaviour each driver stresses; the in-process drivers reproduce
    // the *consequences* of those supervisor behaviours on the
    // replicated log, which is where any safety regression would land.
    // ========================================================================

    /// Q2 (v0.9.x) cluster scenario: single-node process crash.
    ///
    /// Models the SIGKILL-then-supervisor-restart-with-bounded-backoff
    /// path. One replica enters gray failure at a moderate rate
    /// (≈ once per 5-7 simulated cycles) and recovers at a comparable
    /// rate, mirroring the supervisor's restart-window cadence. Other
    /// N-1 nodes stay healthy. Storage stays clean — the canary is
    /// "leader keeps accepting writes through a follower crash", not
    /// a disk failure.
    fn cluster_node_process_crash() -> Self {
        Self {
            scenario_type: ScenarioType::ClusterNodeProcessCrash,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            // 15 % entry / 30 % recovery — single replica cycles through
            // crash + restart without the whole cluster ever losing quorum.
            gray_failure_injector: Some(GrayFailureInjector::new(0.15, 0.30)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000, // 20 s for multiple restart cycles
            max_events: 25_000,
        }
    }

    /// Q2 (v0.9.x) cluster scenario: cascading node failure.
    ///
    /// N-1 replicas go dark in rapid sequence; the cluster blocks new
    /// writes but loses no committed entries. Aggressive gray-failure
    /// entry (35 %) and low recovery (8 %) push multiple replicas
    /// simultaneously into the failed state. Elevated network drop +
    /// aggressive swizzle-clogging models the partition-during-cascade
    /// shape the runbook's "quorum loss recovery" section covers.
    fn cluster_cascading_node_failure() -> Self {
        Self {
            scenario_type: ScenarioType::ClusterCascadingNodeFailure,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 20_000_000,
                drop_probability: 0.15,
                duplicate_probability: 0.02,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            // High entry, slow recovery — multiple replicas down at once.
            gray_failure_injector: Some(GrayFailureInjector::new(0.35, 0.08)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 s — cascade + recovery window
            max_events: 30_000,
        }
    }

    /// Q2 (v0.9.x) cluster scenario: health-check timeout (node hangs).
    ///
    /// Models a node that stops servicing traffic without exiting — the
    /// `/readyz` probe flips red, but the process is still alive so
    /// systemd's `Restart=on-failure` doesn't fire. The canary contract
    /// is "view change elects a new leader if the hung node was primary".
    /// Very low recovery (3 %) keeps the hung node stuck; elevated network
    /// latency models the hang surfacing as slow rather than absent
    /// responses (the classic gray-failure shape).
    fn cluster_health_check_timeout() -> Self {
        Self {
            scenario_type: ScenarioType::ClusterHealthCheckTimeout,
            network_config: NetworkConfig {
                min_delay_ns: 5_000_000,
                max_delay_ns: 100_000_000, // 100 ms — "responding but late"
                drop_probability: 0.05,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: Some(SwizzleClogger::mild()),
            // Moderate entry, near-zero recovery — once a node hangs it
            // stays hung until the supervisor escalates to forced restart.
            gray_failure_injector: Some(GrayFailureInjector::new(0.20, 0.03)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000, // 25 s — view change + recovery
            max_events: 20_000,
        }
    }

    /// Q2 (v0.9.x) cluster scenario: config reload under load.
    ///
    /// Models `cluster.toml` being updated mid-write. The in-process
    /// VOPR runtime doesn't reload config, so this driver expresses the
    /// *consequence* the canary checks: no in-flight write loses
    /// durability when the supervisor briefly perturbs the replica set.
    /// Mild gray failures + elevated write load reproduce the
    /// "supervisor stalled momentarily while applying new config" shape
    /// the runbook's rolling-config-change section covers.
    fn cluster_config_reload_under_load() -> Self {
        Self {
            scenario_type: ScenarioType::ClusterConfigReloadUnderLoad,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 15_000_000,
                drop_probability: 0.05, // Brief perturbation during reload
                duplicate_probability: 0.01,
                max_in_flight: 2000, // Higher in-flight to stress reload window
            },
            storage_config: StorageConfig {
                // Light storage variability — writes durable through the
                // reload window, fsync still completes.
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 5_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: Some(GrayFailureInjector::new(0.08, 0.25)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000,
            max_events: 30_000, // High event volume — many in-flight writes
        }
    }

    /// Q2 (v0.9.x) cluster scenario: rolling restart of the full cluster.
    ///
    /// Models the operator's rolling-upgrade workflow: each node restarted
    /// in sequence, leadership transferring along the way. Sustained
    /// medium-rate gray-failure cycling (each node crashes and recovers
    /// in turn) over a long simulated window. Cluster stays writable
    /// throughout — every pre-restart committed entry must survive at
    /// the same offset (the prefix-property invariant catches violations).
    fn cluster_rolling_restart_full_cluster() -> Self {
        Self {
            scenario_type: ScenarioType::ClusterRollingRestartFullCluster,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            },
            storage_config: StorageConfig::default(),
            swizzle_clogger: None,
            // Sustained moderate cycling — each node takes a turn down.
            gray_failure_injector: Some(GrayFailureInjector::new(0.18, 0.22)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 40_000_000_000, // 40 s — span N restart windows
            max_events: 35_000,
        }
    }

    // ========================================================================
    // Q3 (v0.9.0) — Healthcare clinical scenario drivers. Each driver
    // expresses the fault shape that the FHIR projection worker, X12
    // claims ingester, audit-log inserter, and time-travel reader must
    // survive under load. Tuned parameters mirror the canary contracts
    // documented on each ScenarioType variant.
    // ========================================================================

    /// Q3 (v0.9.0) clinical scenario: EHR admissions surge.
    ///
    /// HL7 v2 ADT^A01 admissions burst (flu season, mass-casualty
    /// triage) arrives via MLLP. The PV1 visit creation and the
    /// `fhir.Patient.<tenant>` + `fhir.Encounter.<tenant>` stream
    /// appends must remain atomic per-message. Storage reordering +
    /// sustained high in-flight load reproduces the race where the
    /// Patient stream gets ahead of the Encounter projection.
    fn ehr_admissions_surge() -> Self {
        Self {
            scenario_type: ScenarioType::EhrAdmissionsSurge,
            network_config: NetworkConfig {
                min_delay_ns: 500_000,
                max_delay_ns: 10_000_000,
                drop_probability: 0.01,
                duplicate_probability: 0.0,
                max_in_flight: 4_000, // Sustained surge load
            },
            storage_config: StorageConfig {
                // Tight write latencies that occasionally spike
                // (admission bursts contend for the FHIR projection
                // write path).
                min_write_latency_ns: 200_000,
                max_write_latency_ns: 8_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 500_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000, // 30 s — sustained surge window
            max_events: 50_000,          // High volume — admissions bursting
        }
    }

    /// Q3 (v0.9.0) clinical scenario: lab result delayed delivery.
    ///
    /// ORU^R01 results arriving hours/days after the originating
    /// Encounter. The FHIR projector must resolve `Observation.encounter`
    /// against the historical Encounter snapshot, not the current
    /// post-discharge state. Storage reordering models the
    /// out-of-order arrival; the canary checks that AS-OF queries
    /// return the same Encounter projection regardless of when the
    /// resolving read is issued.
    fn lab_result_delayed_delivery() -> Self {
        Self {
            scenario_type: ScenarioType::LabResultDelayedDelivery,
            network_config: NetworkConfig {
                min_delay_ns: 5_000_000,
                max_delay_ns: 200_000_000, // Up to 200ms — pathology turnaround
                drop_probability: 0.02,
                duplicate_probability: 0.01,
                max_in_flight: 1_500,
            },
            storage_config: StorageConfig {
                // Wide read latency range — historical Encounter
                // snapshot fetches contend with recent observation
                // writes.
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 20_000_000,
                min_read_latency_ns: 100_000,
                max_read_latency_ns: 2_000_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 35_000_000_000,
            max_events: 25_000,
        }
    }

    /// Q3 (v0.9.0) clinical scenario: claims batch reconciliation.
    ///
    /// Nightly X12 837 institutional-claim batch matched against 835
    /// remittance responses. Append-only claims-event stream must
    /// remain monotonic across the full batch even under injected
    /// storage faults. A retried 837 submit must produce the same
    /// post-state as a clean run (idempotency on
    /// claim-control-number). High event volume plus storage
    /// reordering plus occasional gray-failure cycling reproduces
    /// the retry-during-fault shape.
    fn claims_batch_reconciliation() -> Self {
        Self {
            scenario_type: ScenarioType::ClaimsBatchReconciliation,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 25_000_000,
                drop_probability: 0.08, // Triggers retries within the batch
                duplicate_probability: 0.05, // Models clearinghouse re-submits
                max_in_flight: 2_000,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 1_000_000,
                max_write_latency_ns: 30_000_000,
                min_read_latency_ns: 200_000,
                max_read_latency_ns: 5_000_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            // Brief gray-failure cycling to interrupt the batch mid-run
            // and force the reconciler down the retry path.
            gray_failure_injector: Some(GrayFailureInjector::new(0.10, 0.30)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 45_000_000_000, // 45 s — full batch + retries
            max_events: 100_000,         // Models a 100k-claim batch
        }
    }

    /// Q3 (v0.9.0) clinical scenario: break-glass under load.
    ///
    /// HIPAA § 164.510(b)(3) emergency override activated by a
    /// clinician while 1000+ inserts/sec race the same patient's
    /// streams. `BreakGlassActivated` audit event MUST appear at a
    /// strictly earlier offset than every PHI read in the session;
    /// `BreakGlassClosed` MUST list every resource id touched. The
    /// canary watches for a torn audit chain where the activation
    /// event ends up sequenced after a PHI read.
    fn break_glass_under_load() -> Self {
        Self {
            scenario_type: ScenarioType::BreakGlassUnderLoad,
            network_config: NetworkConfig {
                min_delay_ns: 500_000,
                max_delay_ns: 8_000_000,
                drop_probability: 0.01,
                duplicate_probability: 0.0,
                max_in_flight: 5_000, // Heavy concurrent PHI access
            },
            storage_config: StorageConfig {
                // Wide write latency range — the audit-log inserter and
                // the PHI projection writer contend for the same log
                // tail.
                min_write_latency_ns: 100_000,
                max_write_latency_ns: 15_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 1_000_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::mild()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 20_000_000_000,
            max_events: 60_000, // High event rate stresses the chain head
        }
    }

    /// Q3 (v0.9.0) clinical scenario: consent revocation cascade.
    ///
    /// Patient withdraws consent (GDPR Art. 7(3) / HIPAA Authorization
    /// revocation) while research queries against their PHI are in
    /// flight. New queries after the revocation timestamp must return
    /// empty; in-flight queries started before revocation must
    /// complete with the pre-revocation snapshot. The audit chain
    /// `ConsentWithdrawn → erasure-request → Effect::ProjectionRowsPurge`
    /// must remain ordered. Models a torn revocation by injecting
    /// storage write reordering between the consent table update and
    /// the projection purge.
    fn consent_revocation_cascade() -> Self {
        Self {
            scenario_type: ScenarioType::ConsentRevocationCascade,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 12_000_000,
                drop_probability: 0.02,
                duplicate_probability: 0.01,
                max_in_flight: 2_500,
            },
            storage_config: StorageConfig {
                // Aggressive write reordering — the consent-table
                // update and the projection purge ride separate
                // batches.
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 20_000_000,
                min_read_latency_ns: 100_000,
                max_read_latency_ns: 3_000_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::aggressive()),
            gray_failure_injector: None,
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 25_000_000_000,
            max_events: 40_000,
        }
    }

    /// Q3 (v0.9.0) scenario: `AS OF` before retention horizon.
    ///
    /// Time-travel queries against an offset older than the retention
    /// horizon must surface `AsOfBeforeRetentionHorizon`, not silent
    /// empty results. Models sustained writes pushing the retention
    /// boundary forward while readers issue AS-OF queries at random
    /// historical offsets. Storage reordering + gray-failure cycling
    /// stresses the retention-horizon scan path under fault.
    fn as_of_before_retention_horizon() -> Self {
        Self {
            scenario_type: ScenarioType::AsOfBeforeRetentionHorizon,
            network_config: NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 15_000_000,
                drop_probability: 0.03,
                duplicate_probability: 0.0,
                max_in_flight: 1_500,
            },
            storage_config: StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 10_000_000,
                min_read_latency_ns: 100_000,
                max_read_latency_ns: 2_000_000,
                ..Default::default()
            },
            swizzle_clogger: Some(SwizzleClogger::mild()),
            // Brief gray failures interrupt the retention-scan path,
            // exercising the recovery code that re-establishes the
            // horizon after a fault.
            gray_failure_injector: Some(GrayFailureInjector::new(0.08, 0.20)),
            byzantine_injector: None,
            num_tenants: 1,
            time_compression_factor: 1.0,
            max_time_ns: 30_000_000_000,
            max_events: 35_000,
        }
    }

    /// Applies time compression to a duration.
    #[allow(clippy::cast_sign_loss, clippy::cast_precision_loss)]
    pub fn compress_time(&self, duration_ns: u64) -> u64 {
        if self.time_compression_factor <= 1.0 {
            duration_ns
        } else {
            (duration_ns as f64 / self.time_compression_factor) as u64
        }
    }

    /// Decompresses time for display purposes.
    #[allow(clippy::cast_sign_loss, clippy::cast_precision_loss)]
    pub fn decompress_time(&self, compressed_ns: u64) -> u64 {
        if self.time_compression_factor <= 1.0 {
            compressed_ns
        } else {
            (compressed_ns as f64 * self.time_compression_factor) as u64
        }
    }
}

// ============================================================================
// Tenant Workload Generator
// ============================================================================

/// Generates tenant-specific workloads for multi-tenant scenarios.
#[derive(Debug)]
pub struct TenantWorkloadGenerator {
    /// Number of tenants.
    num_tenants: usize,
    /// Key space per tenant (non-overlapping).
    keys_per_tenant: u64,
}

impl TenantWorkloadGenerator {
    /// Creates a new tenant workload generator.
    pub fn new(num_tenants: usize) -> Self {
        Self {
            num_tenants,
            keys_per_tenant: 100, // Each tenant has 100 keys
        }
    }

    /// Gets the key range for a tenant.
    ///
    /// Returns (`start_key`, `end_key`) exclusive.
    pub fn tenant_key_range(&self, tenant_id: usize) -> (u64, u64) {
        let start = (tenant_id as u64) * self.keys_per_tenant;
        let end = start + self.keys_per_tenant;
        (start, end)
    }

    /// Generates a random key for a tenant.
    pub fn random_key(&self, tenant_id: usize, rng: &mut SimRng) -> u64 {
        let (start, end) = self.tenant_key_range(tenant_id);
        start + (rng.next_u64() % (end - start))
    }

    /// Verifies that a key belongs to a tenant.
    pub fn verify_tenant_isolation(&self, key: u64, expected_tenant: usize) -> bool {
        let (start, end) = self.tenant_key_range(expected_tenant);
        key >= start && key < end
    }

    /// Returns the total number of tenants.
    pub fn num_tenants(&self) -> usize {
        self.num_tenants
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_names() {
        for scenario in ScenarioType::all() {
            assert!(!scenario.name().is_empty());
            assert!(!scenario.description().is_empty());
        }
    }

    #[test]
    fn shipping_list_excludes_aspirational() {
        let shipping = ScenarioType::shipping();
        let all = ScenarioType::all();
        assert!(
            shipping.len() < all.len(),
            "shipping() must be a strict subset of all() once at least one aspirational scenario exists",
        );
        for s in &shipping {
            assert!(
                !s.is_aspirational(),
                "shipping list leaked aspirational scenario {s:?}",
            );
        }
    }

    #[test]
    fn aspirational_scenarios_still_build_configs() {
        // Even though gated out of the default list, aspirational scenarios
        // must continue to compile and construct valid configs so opt-in
        // (--include-aspirational / --features aspirational-scenarios) works
        // without surprise panics.
        for s in ScenarioType::all() {
            if s.is_aspirational() {
                let _ = ScenarioConfig::new(*s, 0xA5A5);
            }
        }
    }

    #[test]
    fn test_baseline_scenario() {
        let config = ScenarioConfig::new(ScenarioType::Baseline, 12345);
        assert_eq!(config.scenario_type, ScenarioType::Baseline);
        assert!(config.swizzle_clogger.is_none());
        assert!(config.gray_failure_injector.is_none());
        assert_eq!(config.num_tenants, 1);
        assert_eq!(config.time_compression_factor, 1.0);
    }

    #[test]
    fn test_swizzle_clogging_scenario() {
        let config = ScenarioConfig::new(ScenarioType::SwizzleClogging, 12345);
        assert!(config.swizzle_clogger.is_some());
        assert!(config.gray_failure_injector.is_none());
    }

    #[test]
    fn test_gray_failures_scenario() {
        let config = ScenarioConfig::new(ScenarioType::GrayFailures, 12345);
        assert!(config.swizzle_clogger.is_none());
        assert!(config.gray_failure_injector.is_some());
    }

    #[test]
    fn test_multi_tenant_scenario() {
        let config = ScenarioConfig::new(ScenarioType::MultiTenantIsolation, 12345);
        assert_eq!(config.num_tenants, 5);
        assert!(config.swizzle_clogger.is_some());
        assert!(config.gray_failure_injector.is_some());
    }

    #[test]
    fn test_time_compression() {
        let config = ScenarioConfig::new(ScenarioType::TimeCompression, 12345);
        assert_eq!(config.time_compression_factor, 10.0);

        // 10 seconds compressed = 1 second
        let compressed = config.compress_time(10_000_000_000);
        assert_eq!(compressed, 1_000_000_000);

        // Decompression should reverse it
        let decompressed = config.decompress_time(compressed);
        assert_eq!(decompressed, 10_000_000_000);
    }

    #[test]
    fn test_combined_scenario() {
        let config = ScenarioConfig::new(ScenarioType::Combined, 12345);
        assert!(config.swizzle_clogger.is_some());
        assert!(config.gray_failure_injector.is_some());
        assert_eq!(config.num_tenants, 3);
        assert_eq!(config.time_compression_factor, 5.0);
    }

    /// v0.6.0 Tier 1 #5 — verifies the AlterTableCrashRecovery
    /// config has the crash-shaped storage faults and gray-failure
    /// jitter the scenario is built around.
    #[test]
    fn test_alter_table_crash_recovery_scenario() {
        let config = ScenarioConfig::new(ScenarioType::AlterTableCrashRecovery, 12345);
        assert_eq!(config.scenario_type, ScenarioType::AlterTableCrashRecovery);
        // Gray-failure jitter is the primary concurrency signal.
        assert!(config.gray_failure_injector.is_some());
        // Storage faults are the crash signal — configured with
        // non-zero upper bounds.
        assert!(config.storage_config.partial_write_probability >= 0.0);
        assert!(config.storage_config.fsync_failure_probability >= 0.0);
        assert!(config.storage_config.write_failure_probability >= 0.0);
        // Listed as a shipping scenario (non-aspirational).
        assert!(!ScenarioType::AlterTableCrashRecovery.is_aspirational());
        // The config survives round-tripping through `all()`.
        assert!(ScenarioType::all().contains(&ScenarioType::AlterTableCrashRecovery));
        // Name and description are non-empty.
        assert!(!ScenarioType::AlterTableCrashRecovery.name().is_empty());
        assert!(
            !ScenarioType::AlterTableCrashRecovery
                .description()
                .is_empty()
        );
    }

    /// v0.6.0 Tier 2 #7 — verifies the MaskingRoleTransition config
    /// is correctly wired through `ScenarioConfig::new` and appears
    /// in the shipping list.
    #[test]
    fn test_masking_role_transition_scenario() {
        let config = ScenarioConfig::new(ScenarioType::MaskingRoleTransition, 12345);
        assert_eq!(config.scenario_type, ScenarioType::MaskingRoleTransition);
        // Light fault profile — the scenario stresses role
        // transitions, not disk recovery.
        assert!(config.storage_config.fsync_failure_probability < 0.01);
        assert!(!ScenarioType::MaskingRoleTransition.is_aspirational());
        assert!(ScenarioType::all().contains(&ScenarioType::MaskingRoleTransition));
        assert!(!ScenarioType::MaskingRoleTransition.name().is_empty());
        assert!(!ScenarioType::MaskingRoleTransition.description().is_empty());
    }

    /// v0.6.0 Tier 2 #4 — verifies the EraseSubjectWithCrash config
    /// carries crash-shaped storage faults and is listed as shipping.
    #[test]
    fn test_erase_subject_with_crash_scenario() {
        let config = ScenarioConfig::new(ScenarioType::EraseSubjectWithCrash, 12345);
        assert_eq!(config.scenario_type, ScenarioType::EraseSubjectWithCrash);
        // Crash-shaped storage faults are the point of the scenario.
        assert!(config.storage_config.write_failure_probability >= 0.0);
        assert!(config.storage_config.fsync_failure_probability >= 0.0);
        assert!(config.storage_config.partial_write_probability >= 0.0);
        // Gray-failure jitter for concurrency realism.
        assert!(config.gray_failure_injector.is_some());
        assert!(!ScenarioType::EraseSubjectWithCrash.is_aspirational());
        assert!(ScenarioType::all().contains(&ScenarioType::EraseSubjectWithCrash));
        assert!(!ScenarioType::EraseSubjectWithCrash.name().is_empty());
        assert!(!ScenarioType::EraseSubjectWithCrash.description().is_empty());
    }

    /// v0.9.x T2.3 — verifies all 5 cluster supervisor scenarios are
    /// promoted out of the aspirational set, dispatched to real driver
    /// methods (not `aspirational_v07`), and produce non-baseline
    /// configs that surface the fault shapes the canary contracts
    /// describe.
    #[test]
    fn test_cluster_scenarios_have_real_drivers() {
        let cluster_scenarios = [
            ScenarioType::ClusterNodeProcessCrash,
            ScenarioType::ClusterCascadingNodeFailure,
            ScenarioType::ClusterHealthCheckTimeout,
            ScenarioType::ClusterConfigReloadUnderLoad,
            ScenarioType::ClusterRollingRestartFullCluster,
        ];

        for scenario in cluster_scenarios {
            let config = ScenarioConfig::new(scenario, 12345);
            assert_eq!(config.scenario_type, scenario);
            assert!(
                !scenario.is_aspirational(),
                "{scenario:?} still tagged aspirational after T2.3 driver pass",
            );
            assert!(ScenarioType::all().contains(&scenario));
            assert!(!scenario.name().is_empty());
            assert!(!scenario.description().is_empty());
            // Every cluster scenario stresses replica availability —
            // gray-failure injection is the in-process VOPR equivalent
            // of OS-process crashes / hangs / restarts.
            assert!(
                config.gray_failure_injector.is_some(),
                "{scenario:?} driver did not enable gray-failure injection",
            );
            // Non-baseline event budget — cluster scenarios need
            // headroom to span multiple supervisor restart windows.
            assert!(
                config.max_events > 15_000,
                "{scenario:?} max_events {} is too low for cluster cadence",
                config.max_events,
            );
        }
    }

    /// v0.9.0 healthcare-pivot sweep — verifies all 6 healthcare clinical
    /// scenarios (5 Q2 clinical + AsOfBeforeRetentionHorizon) are promoted
    /// out of the aspirational set, dispatched to real driver methods, and
    /// produce non-baseline configs with the fault shapes the canary
    /// contracts describe.
    #[test]
    fn test_healthcare_scenarios_have_real_drivers() {
        let healthcare_scenarios = [
            ScenarioType::EhrAdmissionsSurge,
            ScenarioType::LabResultDelayedDelivery,
            ScenarioType::ClaimsBatchReconciliation,
            ScenarioType::BreakGlassUnderLoad,
            ScenarioType::ConsentRevocationCascade,
            ScenarioType::AsOfBeforeRetentionHorizon,
        ];

        for scenario in healthcare_scenarios {
            let config = ScenarioConfig::new(scenario, 12345);
            assert_eq!(config.scenario_type, scenario);
            assert!(
                !scenario.is_aspirational(),
                "{scenario:?} still tagged aspirational after healthcare-pivot driver pass",
            );
            assert!(ScenarioType::all().contains(&scenario));
            assert!(!scenario.name().is_empty());
            assert!(!scenario.description().is_empty());
            // Healthcare scenarios all stress the storage / projection
            // path — every driver carries a non-default storage_config
            // or a swizzle_clogger to express the fault surface.
            let baseline_storage = StorageConfig::default();
            let drives_storage = config.storage_config.max_write_latency_ns
                != baseline_storage.max_write_latency_ns
                || config.swizzle_clogger.is_some();
            assert!(
                drives_storage,
                "{scenario:?} driver does not stress the storage / projection path",
            );
            // Non-baseline event budget — healthcare scenarios run long
            // enough to span an admission burst, a claims batch, or a
            // multi-second AS-OF window.
            assert!(
                config.max_events >= 25_000,
                "{scenario:?} max_events {} is too low for the clinical cadence",
                config.max_events,
            );
        }
    }

    /// v0.9.x T2.3 — verifies the cascading-failure driver carries the
    /// aggressive-cascade shape (high gray-failure entry, low recovery,
    /// elevated network drop) the canary contract calls out.
    #[test]
    fn test_cluster_cascading_node_failure_shape() {
        let config = ScenarioConfig::new(ScenarioType::ClusterCascadingNodeFailure, 12345);
        assert!(config.swizzle_clogger.is_some());
        assert!(config.gray_failure_injector.is_some());
        assert!(config.network_config.drop_probability >= 0.10);
        // 30s+ runtime to span the cascade + recovery window.
        assert!(config.max_time_ns >= 25_000_000_000);
    }

    /// v0.9.x T2.3 — verifies the health-check-timeout driver carries
    /// the "respond-but-late + near-zero recovery" gray-failure shape
    /// (the classic hung-process pattern).
    #[test]
    fn test_cluster_health_check_timeout_shape() {
        let config = ScenarioConfig::new(ScenarioType::ClusterHealthCheckTimeout, 12345);
        // Elevated latency models the hang showing up as slow responses.
        assert!(config.network_config.max_delay_ns >= 50_000_000);
        assert!(config.gray_failure_injector.is_some());
    }

    /// v0.9.x T2.3 — verifies the rolling-restart driver carries the
    /// sustained-cycling shape (matched gray-failure entry/recovery
    /// rates over a long simulated window).
    #[test]
    fn test_cluster_rolling_restart_shape() {
        let config = ScenarioConfig::new(ScenarioType::ClusterRollingRestartFullCluster, 12345);
        assert!(config.gray_failure_injector.is_some());
        // Long-enough window to span N restart cycles.
        assert!(config.max_time_ns >= 30_000_000_000);
        // High event count — restarts overlap with sustained writes.
        assert!(config.max_events >= 25_000);
    }

    #[test]
    fn test_tenant_key_isolation() {
        let generator = TenantWorkloadGenerator::new(3);

        // Tenant 0: keys 0-99
        assert_eq!(generator.tenant_key_range(0), (0, 100));
        // Tenant 1: keys 100-199
        assert_eq!(generator.tenant_key_range(1), (100, 200));
        // Tenant 2: keys 200-299
        assert_eq!(generator.tenant_key_range(2), (200, 300));

        // Verify isolation
        assert!(generator.verify_tenant_isolation(50, 0));
        assert!(!generator.verify_tenant_isolation(50, 1));
        assert!(generator.verify_tenant_isolation(150, 1));
        assert!(!generator.verify_tenant_isolation(150, 0));
    }

    #[test]
    fn test_tenant_random_keys() {
        let generator = TenantWorkloadGenerator::new(2);
        let mut rng = SimRng::new(12345);

        // Generate 100 random keys for tenant 0
        for _ in 0..100 {
            let key = generator.random_key(0, &mut rng);
            assert!(generator.verify_tenant_isolation(key, 0));
        }

        // Generate 100 random keys for tenant 1
        for _ in 0..100 {
            let key = generator.random_key(1, &mut rng);
            assert!(generator.verify_tenant_isolation(key, 1));
        }
    }
}
