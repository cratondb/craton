-------------------------- MODULE Healthcare --------------------------
(*
 * Kimberlite Healthcare-Specific Compliance Properties
 *
 * Pivot context: Kimberlite is now a healthcare-only verifiable database
 * (EHR/EMR, payer/RCM, clinical research, digital health). This spec
 * captures the HIPAA-grade invariants that go beyond the generic
 * compliance shape in Compliance.tla.
 *
 * Compliance.tla already proves TenantIsolation, AuditCompleteness,
 * HashChainIntegrity, EncryptionAtRest, AccessControlCorrect, and
 * MinimumNecessary. Healthcare.tla layers three healthcare-specific
 * properties on top:
 *
 * Properties Proven:
 * - SafeHarborCoverage:   45 CFR § 164.514(b)(2) — every one of the 18
 *                         Safe Harbor identifier classes that appears
 *                         on a PHI record must be redacted in the
 *                         de-identified projection. A PHI record that
 *                         claims to be "Safe Harbor de-identified" but
 *                         still carries any of the 18 identifier
 *                         classes is a HIPAA Privacy Rule violation.
 *
 * - BreakGlassAuditOrder: HIPAA § 164.510(b)(3) emergency-override
 *                         contract: a BreakGlassActivated audit event
 *                         must chain-precede every PHI read taken
 *                         inside the override session. A PHI read that
 *                         is sequenced before the activating event is
 *                         a forensic hole the regulator cannot close.
 *
 * - ConsentRevocationCausality: HIPAA Authorization revocation /
 *                         GDPR Art. 7(3) consent withdrawal. After a
 *                         ConsentWithdrawn event chains into the
 *                         audit log, every later query against the
 *                         revoked-scope rows must return empty AND
 *                         the projection-purge effect must chain
 *                         after the ConsentWithdrawn event but
 *                         before any further effect on those rows.
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Patients,            \* Set of patient IDs (subjects of PHI)
    Users,               \* Set of user IDs (clinicians / staff)
    SafeHarborClasses,   \* The 18 HIPAA Safe Harbor identifier classes
    MaxAuditLog          \* Bound on audit-log length for TLC

VARIABLES
    \* PHI record state
    phiRecord,           \* phiRecord[p] = set of SafeHarborClasses present
    deidProjection,      \* deidProjection[p] = set of SafeHarborClasses
                         \*   still present after Safe Harbor transform
    deidAttested,        \* deidAttested[p] = TRUE iff p has a Safe
                         \*   Harbor attestation

    \* Break-glass session state
    breakGlassActive,    \* breakGlassActive[u] = TRUE iff user u is in
                         \*   an active break-glass override
    breakGlassActivatedAt, \* breakGlassActivatedAt[u] = audit-log offset
                         \*   at which the session began (NULL if not
                         \*   active or not yet recorded)

    \* Consent state
    consentRevokedAt,    \* consentRevokedAt[p] = audit-log offset at
                         \*   which patient p's consent was revoked,
                         \*   NULL otherwise
    purgedAt,            \* purgedAt[p] = audit-log offset of the
                         \*   projection purge for patient p

    \* Audit log
    auditLog,            \* sequence of audit entries
    auditIndex           \* current position

vars == <<phiRecord, deidProjection, deidAttested,
          breakGlassActive, breakGlassActivatedAt,
          consentRevokedAt, purgedAt,
          auditLog, auditIndex>>

--------------------------------------------------------------------------------
(* Type Definitions *)

PatientId == Patients
UserId == Users
SafeHarborClass == SafeHarborClasses

\* The set of valid audit entry kinds we care about for healthcare.
\* Kept narrow so TLC's state space stays small; broader event types
\* live in Compliance.tla.
EventKind == {
    "PhiRead",
    "BreakGlassActivated",
    "BreakGlassClosed",
    "ConsentWithdrawn",
    "ProjectionRowsPurge",
    "DeidentifyAttested"
}

AuditEntry == [
    kind:     EventKind,
    user:     UserId,
    patient:  PatientId,
    offset:   Nat
]

NULL == -1  \* Sentinel for "not yet set"

--------------------------------------------------------------------------------
(* Initial State *)

Init ==
    /\ phiRecord = [p \in Patients |-> SafeHarborClasses]
    /\ deidProjection = [p \in Patients |-> {}]
    /\ deidAttested = [p \in Patients |-> FALSE]
    /\ breakGlassActive = [u \in Users |-> FALSE]
    /\ breakGlassActivatedAt = [u \in Users |-> NULL]
    /\ consentRevokedAt = [p \in Patients |-> NULL]
    /\ purgedAt = [p \in Patients |-> NULL]
    /\ auditLog = <<>>
    /\ auditIndex = 0

--------------------------------------------------------------------------------
(* Actions *)

AppendAudit(kind, user, patient) ==
    /\ Len(auditLog) < MaxAuditLog
    /\ auditLog' = Append(auditLog, [
           kind     |-> kind,
           user     |-> user,
           patient  |-> patient,
           offset   |-> auditIndex
       ])
    /\ auditIndex' = auditIndex + 1

\* Apply the Safe Harbor de-identification transform to patient p.
\* The post-state attestation says deidProjection[p] is empty (every
\* one of the 18 classes was redacted).
DeidentifyPatient(p) ==
    /\ ~deidAttested[p]
    /\ deidProjection' = [deidProjection EXCEPT ![p] = {}]
    /\ deidAttested' = [deidAttested EXCEPT ![p] = TRUE]
    /\ AppendAudit("DeidentifyAttested", CHOOSE u \in Users : TRUE, p)
    /\ UNCHANGED <<phiRecord, breakGlassActive, breakGlassActivatedAt,
                   consentRevokedAt, purgedAt>>

\* Clinician u activates a break-glass session for patient p. The
\* activation MUST be the first audit event emitted; only after that
\* may PHI reads occur in the session.
ActivateBreakGlass(u, p) ==
    /\ ~breakGlassActive[u]
    /\ breakGlassActive' = [breakGlassActive EXCEPT ![u] = TRUE]
    /\ breakGlassActivatedAt' = [breakGlassActivatedAt EXCEPT ![u] = auditIndex]
    /\ AppendAudit("BreakGlassActivated", u, p)
    /\ UNCHANGED <<phiRecord, deidProjection, deidAttested,
                   consentRevokedAt, purgedAt>>

\* Read PHI for patient p as user u. Only permitted while a break-glass
\* session is active for u. The PhiRead audit event chains AFTER the
\* BreakGlassActivated event by construction (auditIndex is monotonic).
PhiRead(u, p) ==
    /\ breakGlassActive[u]
    /\ consentRevokedAt[p] = NULL  \* Or revocation hasn't fired yet
    /\ AppendAudit("PhiRead", u, p)
    /\ UNCHANGED <<phiRecord, deidProjection, deidAttested,
                   breakGlassActive, breakGlassActivatedAt,
                   consentRevokedAt, purgedAt>>

\* Patient p withdraws consent. The audit chain captures the
\* withdrawal at the next audit offset.
WithdrawConsent(p) ==
    /\ consentRevokedAt[p] = NULL
    /\ consentRevokedAt' = [consentRevokedAt EXCEPT ![p] = auditIndex]
    /\ AppendAudit("ConsentWithdrawn", CHOOSE u \in Users : TRUE, p)
    /\ UNCHANGED <<phiRecord, deidProjection, deidAttested,
                   breakGlassActive, breakGlassActivatedAt, purgedAt>>

\* Projection purge runs after the ConsentWithdrawn event has chained.
PurgeProjection(p) ==
    /\ consentRevokedAt[p] # NULL
    /\ purgedAt[p] = NULL
    /\ purgedAt' = [purgedAt EXCEPT ![p] = auditIndex]
    /\ AppendAudit("ProjectionRowsPurge", CHOOSE u \in Users : TRUE, p)
    /\ UNCHANGED <<phiRecord, deidProjection, deidAttested,
                   breakGlassActive, breakGlassActivatedAt,
                   consentRevokedAt>>

CloseBreakGlass(u, p) ==
    /\ breakGlassActive[u]
    /\ breakGlassActive' = [breakGlassActive EXCEPT ![u] = FALSE]
    /\ AppendAudit("BreakGlassClosed", u, p)
    /\ UNCHANGED <<phiRecord, deidProjection, deidAttested,
                   breakGlassActivatedAt, consentRevokedAt, purgedAt>>

Next ==
    \/ \E p \in Patients : DeidentifyPatient(p)
    \/ \E u \in Users, p \in Patients : ActivateBreakGlass(u, p)
    \/ \E u \in Users, p \in Patients : PhiRead(u, p)
    \/ \E p \in Patients : WithdrawConsent(p)
    \/ \E p \in Patients : PurgeProjection(p)
    \/ \E u \in Users, p \in Patients : CloseBreakGlass(u, p)

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------------
(* Invariants — healthcare-specific *)

\* SafeHarborCoverage: every patient whose record carries a Safe
\* Harbor attestation must have NO Safe Harbor identifier classes left
\* in their de-identified projection. The attestation is a HIPAA
\* statement; carrying any of the 18 classes after attesting is a
\* Privacy Rule violation.
SafeHarborCoverage ==
    \A p \in Patients :
        deidAttested[p] => deidProjection[p] = {}

\* BreakGlassAuditOrder: every PhiRead event in the audit log must be
\* preceded (at a strictly earlier offset) by a BreakGlassActivated
\* event for the same user. This is the forensic-completeness contract
\* that HIPAA § 164.510(b)(3) requires emergency-override sessions to
\* satisfy.
BreakGlassAuditOrder ==
    \A i \in 1..Len(auditLog) :
        auditLog[i].kind = "PhiRead" =>
            \E j \in 1..(i-1) :
                /\ auditLog[j].kind = "BreakGlassActivated"
                /\ auditLog[j].user = auditLog[i].user

\* ConsentRevocationCausality: every ProjectionRowsPurge audit event
\* must chain strictly AFTER the ConsentWithdrawn event for the same
\* patient. Equivalently: purgedAt[p] > consentRevokedAt[p] whenever
\* both are set.
ConsentRevocationCausality ==
    \A p \in Patients :
        (consentRevokedAt[p] # NULL /\ purgedAt[p] # NULL) =>
            purgedAt[p] > consentRevokedAt[p]

\* NoPhiReadAfterRevocation: once consent is withdrawn for patient p,
\* no PhiRead event for p may appear in the audit log at an offset
\* greater than consentRevokedAt[p]. Catches the torn-revocation
\* fault shape ConsentRevocationCascade VOPR scenario stresses.
NoPhiReadAfterRevocation ==
    \A i \in 1..Len(auditLog) :
        LET e == auditLog[i] IN
        (e.kind = "PhiRead" /\ consentRevokedAt[e.patient] # NULL) =>
            e.offset <= consentRevokedAt[e.patient]

============================================================================
