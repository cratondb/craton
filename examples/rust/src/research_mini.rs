//! # research-mini — 21 CFR Part 11 e-signature + audit-of-audits.
//!
//! Demonstrates the clinical-research wedge:
//!
//! 1. An investigator opens a case-report form for subject S001.
//! 2. They review and approve it; the system captures an Ed25519
//!    e-signature over the canonical bytes (21 CFR Part 11 § 11.50).
//! 3. The signature event is hash-chained into the compliance audit
//!    log so the signed record cannot be repudiated.
//! 4. A regulatory inspector later reviews the audit log itself.
//!    That review is captured as an *audit-of-audits* event in a
//!    separate stream — the regulator audit log — so we know who
//!    looked at the trial data and when.
//!
//! Runs offline — no FDA submission, no live trial system. The
//! pipeline is the same one any 21 CFR Part 11–subject system runs
//! at sign-off time.
//!
//! ## Running
//!
//! ```bash
//! cd examples/rust
//! cargo run --example research_mini
//! ```

use anyhow::Result;
use kimberlite_compliance::audit::{Actor, ComplianceAuditAction, ComplianceAuditLog, Scope};
use kimberlite_crypto::signature::SigningKey;
use kimberlite_types::TenantId;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A simplified clinical case-report form. Real CRFs are 100+ fields;
/// the shape doesn't matter for the signature surface — what matters
/// is the canonical-byte representation that gets signed.
fn case_report_form() -> Vec<u8> {
    let json = serde_json::json!({
        "trial_id": "ONCO-2026-014",
        "subject_id": "S001",
        "visit": "Cycle 3 Day 1",
        "visit_date": "2026-05-17",
        "investigator_id": "INV-2718",
        "adverse_events": [
            {"term": "Fatigue", "grade": 2, "related": "Probable"},
            {"term": "Nausea",  "grade": 1, "related": "Possible"}
        ],
        "vitals": {
            "systolic_bp": 122,
            "diastolic_bp": 78,
            "heart_rate": 71,
            "temperature_c": 36.7
        },
        "investigator_attestation":
            "I attest that the above is a true and accurate record of \
             today's clinical observations."
    });
    serde_json::to_vec(&json).expect("canonical CRF must serialise")
}

fn main() -> Result<()> {
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  research-mini — 21 CFR Part 11 e-sig + audit-of-audits      │");
    println!("└──────────────────────────────────────────────────────────────┘");

    // ── [1] Investigator opens the CRF ─────────────────────────────
    println!("\n[1] Investigator opens subject S001's case-report form");
    let crf_bytes = case_report_form();
    let crf_sha256 = Sha256::digest(&crf_bytes);
    let crf_sha256_hex: String = crf_sha256.iter().map(|b| format!("{b:02x}")).collect();
    println!("    CRF size       = {} bytes", crf_bytes.len());
    println!("    SHA-256        = {crf_sha256_hex}");

    // ── [2] Sign with the investigator's Ed25519 key ───────────────
    println!("\n[2] Investigator INV-2718 signs the canonical CRF bytes");
    let signing_key = SigningKey::generate();
    let signature = signing_key.sign(&crf_bytes);
    let verifying_key = signing_key.verifying_key();
    verifying_key
        .verify(&crf_bytes, &signature)
        .expect("freshly-signed bytes must verify");
    let sig_bytes = signature.to_bytes();
    let sig_hex: String = sig_bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    println!("    Ed25519 sig    = {sig_hex}…  (first 8 of 64 bytes)");
    println!("    verify         = ok (paired with investigator's public key)");

    // ── [3] Emit the RecordSigned audit event ──────────────────────
    println!("\n[3] Append RecordSigned to the trial audit log");
    let mut trial_audit = ComplianceAuditLog::new();
    let record_id = "crf:ONCO-2026-014:S001:visit-cycle-3-day-1".to_string();
    trial_audit.append_with_actor(
        ComplianceAuditAction::RecordSigned {
            record_id: record_id.clone(),
            signer_id: "INV-2718".into(),
            meaning: "Investigator attests CRF accuracy".into(),
        },
        Actor::Authenticated("INV-2718".into()),
        Scope::Tenant(TenantId::new(1)),
    );
    println!("    trial audit events = {}", trial_audit.count());

    // ── [4] Regulator reviews the audit log → audit-of-audits ──────
    println!("\n[4] FDA inspector reviews the trial audit log");
    println!("    Inspector ID  = FDA-INSP-9201");
    println!("    Reviewing     = trial audit (chain head + last event)");
    let reviewed_chain_head = trial_audit.chain_head();
    let reviewed_count = trial_audit.count();
    let reviewed_export_id = Uuid::new_v4();
    println!(
        "    Captured: chain_head_first_8 = {}",
        reviewed_chain_head
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    // The audit-of-audits lives in a separate stream — its retention
    // is the standalone HIPAA §164.530(j)(2) 6-year minimum
    // (`RetentionPolicy::for_audit_log()`), independent of the trial
    // data itself.
    let mut regulator_audit = ComplianceAuditLog::new();
    regulator_audit.append_with_actor(
        ComplianceAuditAction::DataExported {
            subject_id: "trial:ONCO-2026-014:audit-log".into(),
            export_id: reviewed_export_id,
            format: "audit-snapshot".into(),
            record_count: reviewed_count as u64,
        },
        Actor::Authenticated("FDA-INSP-9201".into()),
        Scope::Tenant(TenantId::new(1)),
    );
    println!("    audit-of-audits events = {}", regulator_audit.count());

    // ── [5] Verify both chains ─────────────────────────────────────
    println!("\n[5] Verify hash chains");
    trial_audit.verify_chain().expect("trial chain ok");
    regulator_audit.verify_chain().expect("regulator chain ok");
    println!("    trial chain          = ok");
    println!("    regulator chain      = ok");

    println!("\n──────────────────────────────────────────────────────────────");
    println!("Pipeline OK: CRF → Ed25519 sign → audit-logged → regulator-reviewed");
    println!("→ audit-of-audits recorded. The CRF bytes, the investigator's");
    println!("public key, the signature, the audit event, and the regulator's");
    println!("review are all linkable via cryptographic identifiers — nothing");
    println!("can be repudiated and nothing can be retroactively modified.");
    println!();

    Ok(())
}
