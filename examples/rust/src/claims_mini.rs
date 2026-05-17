//! # claims-mini — X12 837 claim ingest → adjudication audit trail.
//!
//! Demonstrates the Q3 healthcare wedge for payer/RCM integrations:
//!
//! 1. Receive an X12 EDI 837P (Professional) claim batch
//! 2. Parse the ISA/GS/ST envelope via `kimberlite-x12`
//! 3. Walk every CLM (claim header) in the transaction
//! 4. Emit a `ClaimReceived` audit event chained into the
//!    compliance audit log
//! 5. Receive the 835 (remittance advice) response and tie the
//!    payment back to the original claim ID
//!
//! Runs offline — no clearinghouse connection. The wire bytes are
//! baked-in fixtures so the demo is reproducible without external
//! dependencies.
//!
//! ## Running
//!
//! ```bash
//! cd examples/rust
//! cargo run --example claims_mini
//! ```

use anyhow::Result;
use kimberlite_compliance::audit::{
    Actor, ComplianceAuditAction, ComplianceAuditLog, ComponentName, Scope,
};
use kimberlite_types::TenantId;
use kimberlite_x12::{parse, tx835, tx837, ClaimFormat};

/// Realistic 837P claim batch with one claim header.
const INBOUND_837: &[u8] = b"ISA*00*          *00*          *ZZ*PROVIDER123    *ZZ*PAYER789       *240101*0900*^*00501*000000042*0*P*:~GS*HC*PROVIDERAPP*PAYERAPP*20240101*0900*42*X*005010X222A1~ST*837*0001*005010X222A1~BHT*0019*00*BATCH-2024-01-01-001*20240101*0900*CH~CLM*CLAIM-A001*250.00***11:B:1*Y*A*Y*Y~SE*4*0001~GE*1*42~IEA*1*000000042~";

/// Matching 835 remittance — payer adjudicated CLAIM-A001 and is
/// paying $200.00 of the $250.00 billed.
const INBOUND_835: &[u8] = b"ISA*00*          *00*          *ZZ*PAYER789       *ZZ*PROVIDER123    *240105*1400*^*00501*000000099*0*P*:~GS*HP*PAYERAPP*PROVIDERAPP*20240105*1400*99*X*005010X221A1~ST*835*0001~BPR*I*200.00*C*ACH*CTX*01*999999992*DA*123456789*PROVIDER123*20240105~CLP*CLAIM-A001*1*250.00*200.00*50.00*HM*PAYER-REF-A001~SE*4*0001~GE*1*99~IEA*1*000000099~";

fn main() -> Result<()> {
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  claims-mini — X12 837 → audit → 835 reconciliation          │");
    println!("└──────────────────────────────────────────────────────────────┘");

    let mut audit = ComplianceAuditLog::new();

    // ── [1] Parse the inbound 837 ───────────────────────────────────
    println!("\n[1] Parse the inbound 837 claim batch");
    let claim_interchange = parse(INBOUND_837)?;
    println!(
        "    sender     = {}",
        claim_interchange.sender_id().unwrap_or("?").trim()
    );
    println!(
        "    receiver   = {}",
        claim_interchange.receiver_id().unwrap_or("?").trim()
    );
    println!(
        "    control #  = {}",
        claim_interchange.control_number().unwrap_or("?")
    );

    // ── [2] Walk every 837 claim in the interchange ─────────────────
    println!("\n[2] Walk claims and emit audit events");
    let mut claim_ids = Vec::new();
    for claim_result in tx837::claims_in(&claim_interchange) {
        let claim = claim_result?;
        let batch_id = claim.submitter_batch_id().unwrap_or("?");
        let format_label = match claim.format {
            ClaimFormat::Professional => "837P",
            ClaimFormat::Institutional => "837I",
            ClaimFormat::Dental => "837D",
            ClaimFormat::Other => "837?",
        };
        println!("    {format_label} — submitter_batch_id = {batch_id}");

        for header in claim.claim_headers() {
            let claim_id = header.text(1).unwrap_or("?").to_string();
            let charge_amount = header.text(2).unwrap_or("?").to_string();
            println!("       CLM01={claim_id}   CLM02={charge_amount}");
            // The audit event is the compliance hook for every claim
            // entering the system — payer audits and dispute response
            // workflows query the audit log against this.
            audit.append_with_actor(
                ComplianceAuditAction::DataExported {
                    subject_id: claim_id.clone(),
                    export_id: uuid::Uuid::new_v4(),
                    format: format_label.to_string(),
                    record_count: 1,
                },
                Actor::System(ComponentName::Other("claims_ingest".into())),
                Scope::Tenant(TenantId::new(1)),
            );
            claim_ids.push(claim_id);
        }
    }

    // ── [3] Receive and parse the matching 835 remittance ───────────
    println!("\n[3] Parse the matching 835 remittance");
    let remit_interchange = parse(INBOUND_835)?;
    for rem_result in tx835::remittances_in(&remit_interchange) {
        let rem = rem_result?;
        println!(
            "    BPR02 (total paid) = ${}",
            rem.total_paid_amount().unwrap_or("?")
        );
        println!(
            "    payment method     = {}",
            rem.payment_method().unwrap_or("?")
        );
        for clp in rem.claim_payments() {
            let original_id = clp.text(1).unwrap_or("?").to_string();
            let status = clp.text(2).unwrap_or("?");
            let billed = clp.text(3).unwrap_or("?");
            let paid = clp.text(4).unwrap_or("?");
            let patient_resp = clp.text(5).unwrap_or("?");
            println!(
                "    CLP — claim={original_id}  status={status}  \
                 billed=${billed}  paid=${paid}  patient_resp=${patient_resp}"
            );
            // Cross-reference: every paid claim should have had its
            // intake event already recorded. Anything that doesn't
            // match is a clearinghouse / payer error worth flagging.
            if !claim_ids.contains(&original_id) {
                eprintln!("    ⚠  no matching 837 intake event for {original_id}");
            }
        }
    }

    // ── [4] Verify the audit chain ──────────────────────────────────
    println!("\n[4] Audit-chain summary");
    println!("    events recorded = {}", audit.count());
    let head = audit.chain_head();
    let head_hex: String = head.iter().take(8).map(|b| format!("{b:02x}")).collect();
    println!("    chain head      = {head_hex}…  (first 8 of 32 bytes)");
    audit.verify_chain().expect("audit chain integrity");
    println!("    verify_chain    = ok");

    println!("\n──────────────────────────────────────────────────────────────");
    println!("Pipeline OK: 837 parsed → audit-logged → 835 reconciled.");
    println!("Real ingest workers run this once per inbound EDI file, persist");
    println!("the raw bytes to a PHI-classified stream, and surface the audit");
    println!("events to RCM dashboards / payer dispute workflows.");
    println!();

    Ok(())
}
