//! Comparison Page Handlers
//!
//! Database comparison pages: vs PostgreSQL, TigerBeetle, CockroachDB.

use axum::{extract::Path, response::IntoResponse};

use crate::templates::{CompareTemplate, ComparisonData, ComparisonRow, UseCase};

/// Handler for /compare/{slug} - renders competitor comparison page.
pub async fn compare(Path(slug): Path<String>) -> impl IntoResponse {
    match slug.as_str() {
        "postgresql" => CompareTemplate::new(postgresql_data()),
        "tigerbeetle" => CompareTemplate::new(tigerbeetle_data()),
        "cockroachdb" => CompareTemplate::new(cockroachdb_data()),
        _ => CompareTemplate::new(not_found_data()),
    }
}

fn postgresql_data() -> ComparisonData {
    ComparisonData {
        competitor: "PostgreSQL".to_string(),
        slug: "postgresql".to_string(),
        tagline: "From bolt-on compliance to built-in compliance.".to_string(),
        intro: "PostgreSQL is the world's most advanced open source relational database. \
                Kimberlite is a compliance-first database where every record is immutable, \
                hash-chained, and formally verified. They solve fundamentally different problems."
            .to_string(),
        competitor_best_for: "General-purpose OLTP/OLAP, broad ecosystem, mature tooling, \
                              traditional relational workloads"
            .to_string(),
        kimberlite_best_for: "Healthcare workloads requiring immutable audit trails, \
                              HIPAA-grade compliance, and cryptographic PHI integrity"
            .to_string(),
        competitor_use_cases: vec![
            UseCase {
                title: "General-purpose applications".to_string(),
                detail: "Web apps, SaaS platforms, content management".to_string(),
            },
            UseCase {
                title: "Mature ecosystem".to_string(),
                detail: "Thousands of extensions, ORMs, and tools".to_string(),
            },
            UseCase {
                title: "Flexible data modeling".to_string(),
                detail: "JSON, full-text search, GIS, time-series extensions".to_string(),
            },
        ],
        kimberlite_use_cases: vec![
            UseCase {
                title: "Audit-critical PHI".to_string(),
                detail: "Patient records, clinical notes, claims, prescriptions, lab results".to_string(),
            },
            UseCase {
                title: "Compliance by construction".to_string(),
                detail: "HIPAA Safe Harbor + audit chain formally verified, not bolted on"
                    .to_string(),
            },
            UseCase {
                title: "Cryptographic integrity".to_string(),
                detail: "Hash-chained records with dual-hash (SHA-256 + BLAKE3) verification"
                    .to_string(),
            },
        ],
        rows: vec![
            ComparisonRow {
                feature: "Data model".to_string(),
                competitor_value: "Mutable rows (UPDATE/DELETE)".to_string(),
                kimberlite_value: "Immutable append-only log".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Audit trail".to_string(),
                competitor_value: "Bolt-on (pg_audit, triggers)".to_string(),
                kimberlite_value: "Built-in, hash-chained, immutable".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Compliance frameworks".to_string(),
                competitor_value: "Manual configuration per framework".to_string(),
                kimberlite_value: "HIPAA-native; GDPR/SOC2/ISO-27001 overlays — 92 TLAPS proofs".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Formal verification".to_string(),
                competitor_value: "None".to_string(),
                kimberlite_value: "136+ proofs (TLA+, Coq, Kani, Alloy, Ivy, Flux)".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "SQL support".to_string(),
                competitor_value: "Full SQL standard + extensions".to_string(),
                kimberlite_value: "Core SQL (SELECT, JOIN, CTE, aggregates)".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Ecosystem".to_string(),
                competitor_value: "Thousands of extensions and tools".to_string(),
                kimberlite_value: "Rust, Python, TypeScript, Go SDKs".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Data integrity".to_string(),
                competitor_value: "Checksums on pages".to_string(),
                kimberlite_value: "Per-record CRC32 + dual hash chains".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Multi-tenancy".to_string(),
                competitor_value: "Schema-based (manual isolation)".to_string(),
                kimberlite_value: "Built-in tenant isolation with ABAC".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Access control".to_string(),
                competitor_value: "Role-based (GRANT/REVOKE)".to_string(),
                kimberlite_value: "RBAC + ABAC + row-level + field masking".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "License".to_string(),
                competitor_value: "PostgreSQL License (permissive)".to_string(),
                kimberlite_value: "Apache 2.0".to_string(),
                kimberlite_advantage: false,
            },
        ],
        architecture_left_title: "PostgreSQL: Mutable State".to_string(),
        architecture_left_description: "PostgreSQL stores mutable rows. An UPDATE overwrites the \
                                        previous value. History requires triggers, audit tables, \
                                        or extensions like pg_audit. Compliance is layered on top."
            .to_string(),
        architecture_right_title: "Kimberlite: Immutable Log".to_string(),
        architecture_right_description: "Kimberlite stores every event in an immutable, \
                                         hash-chained log. Current state is derived by replaying \
                                         the log. History is inherent. Compliance is \
                                         structural, not optional."
            .to_string(),
    }
}

fn tigerbeetle_data() -> ComparisonData {
    ComparisonData {
        competitor: "TigerBeetle".to_string(),
        slug: "tigerbeetle".to_string(),
        tagline: "Shared DNA, different missions.".to_string(),
        intro: "TigerBeetle and Kimberlite share design philosophy: deterministic simulation \
                testing, immutable logs, and formal verification approaches. TigerBeetle is a \
                purpose-built financial accounting database. Kimberlite is a verifiable database \
                for healthcare — EHR/EMR systems, payer-RCM, clinical research, digital health."
            .to_string(),
        competitor_best_for: "High-throughput double-entry accounting, financial ledgers, \
                              payment processing"
            .to_string(),
        kimberlite_best_for: "PHI-bearing healthcare workloads: EHR/EMR, payer/RCM claims, \
                              clinical research, digital health, hospital operations"
            .to_string(),
        competitor_use_cases: vec![
            UseCase {
                title: "Financial accounting".to_string(),
                detail: "Double-entry ledger with ACID transfers".to_string(),
            },
            UseCase {
                title: "Extreme throughput".to_string(),
                detail: "Millions of transfers/sec with io_uring".to_string(),
            },
            UseCase {
                title: "Purpose-built API".to_string(),
                detail: "Optimized for create_transfers and create_accounts".to_string(),
            },
        ],
        kimberlite_use_cases: vec![
            UseCase {
                title: "Healthcare-native data".to_string(),
                detail: "FHIR R4 resources, HL7 v2 messages, X12 837 claims, audit-by-default".to_string(),
            },
            UseCase {
                title: "Full SQL queries".to_string(),
                detail: "SELECT, JOIN, CTE, aggregates, GROUP BY, HAVING, UNION".to_string(),
            },
            UseCase {
                title: "HIPAA-grade compliance".to_string(),
                detail: "Safe Harbor de-identification, BAA-ready audit chain, GDPR overlay".to_string(),
            },
        ],
        rows: vec![
            ComparisonRow {
                feature: "Purpose".to_string(),
                competitor_value: "Financial accounting ledger".to_string(),
                kimberlite_value: "General-purpose compliance database".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Query language".to_string(),
                competitor_value: "Custom binary protocol only".to_string(),
                kimberlite_value: "Full SQL (JOINs, CTEs, subqueries, aggregates)".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Industry coverage".to_string(),
                competitor_value: "Finance only".to_string(),
                kimberlite_value: "Healthcare-first: EHR, payer/RCM, clinical research, digital health"
                    .to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Compliance".to_string(),
                competitor_value: "None built-in".to_string(),
                kimberlite_value: "HIPAA-native; GDPR/SOC2/ISO-27001 overlays".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Simulation testing".to_string(),
                competitor_value: "VOPR (deterministic simulation)".to_string(),
                kimberlite_value: "VOPR (74 scenario variants, 19 invariant checkers)".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Performance".to_string(),
                competitor_value: "io_uring, millions of ops/sec".to_string(),
                kimberlite_value: "Hardware-accelerated crypto, zero-copy frames".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Data model".to_string(),
                competitor_value: "Fixed schema (accounts + transfers)".to_string(),
                kimberlite_value: "User-defined schemas with SQL DDL".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Multi-tenancy".to_string(),
                competitor_value: "Not built-in".to_string(),
                kimberlite_value: "Built-in with ABAC policies".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Consensus".to_string(),
                competitor_value: "VSR (Viewstamped Replication)".to_string(),
                kimberlite_value: "VSR (Viewstamped Replication)".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "License".to_string(),
                competitor_value: "Apache 2.0".to_string(),
                kimberlite_value: "Apache 2.0".to_string(),
                kimberlite_advantage: false,
            },
        ],
        architecture_left_title: "TigerBeetle: Accounting Ledger".to_string(),
        architecture_left_description: "TigerBeetle is a specialized financial database with a \
                                        fixed schema of accounts and transfers. It achieves \
                                        extreme performance through io_uring and a purpose-built \
                                        binary protocol. Not designed for general-purpose queries."
            .to_string(),
        architecture_right_title: "Kimberlite: Healthcare Database".to_string(),
        architecture_right_description: "Kimberlite is a verifiable database built for healthcare. \
                                         User-defined schemas, full SQL, FHIR R4 + HL7 v2 + X12 \
                                         native types, HIPAA-grade audit chain, and per-tenant \
                                         encryption. Designed for auditability that holds up under \
                                         OCR review, payer dispute, and patient subject-access requests."
            .to_string(),
    }
}

fn cockroachdb_data() -> ComparisonData {
    ComparisonData {
        competitor: "CockroachDB".to_string(),
        slug: "cockroachdb".to_string(),
        tagline: "Distributed scale vs. compliance depth.".to_string(),
        intro: "CockroachDB is a distributed SQL database built for global scale and high \
                availability. Kimberlite is a compliance-first database built for regulated \
                industries. CockroachDB optimizes for horizontal scalability; Kimberlite \
                optimizes for auditability and formal verification."
            .to_string(),
        competitor_best_for: "Geo-distributed applications, PostgreSQL compatibility at global \
                              scale, high availability"
            .to_string(),
        kimberlite_best_for: "Healthcare workloads requiring immutable audit trails, HIPAA-grade \
                              compliance, and cryptographic PHI integrity"
            .to_string(),
        competitor_use_cases: vec![
            UseCase {
                title: "Global distribution".to_string(),
                detail: "Multi-region with automatic conflict resolution".to_string(),
            },
            UseCase {
                title: "PostgreSQL compatibility".to_string(),
                detail: "Drop-in replacement with existing tools and ORMs".to_string(),
            },
            UseCase {
                title: "Horizontal scaling".to_string(),
                detail: "Add nodes to scale reads and writes linearly".to_string(),
            },
        ],
        kimberlite_use_cases: vec![
            UseCase {
                title: "Immutable audit trails".to_string(),
                detail: "Hash-chained records that cannot be altered or deleted".to_string(),
            },
            UseCase {
                title: "Formal compliance proofs".to_string(),
                detail: "92 TLAPS proofs covering HIPAA and overlay frameworks (GDPR/SOC2/ISO-27001)".to_string(),
            },
            UseCase {
                title: "True open source".to_string(),
                detail: "Apache 2.0 with all features, including compliance".to_string(),
            },
        ],
        rows: vec![
            ComparisonRow {
                feature: "Primary goal".to_string(),
                competitor_value: "Global scale and high availability".to_string(),
                kimberlite_value: "Compliance and auditability".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Data model".to_string(),
                competitor_value: "Mutable rows (PostgreSQL-compatible)".to_string(),
                kimberlite_value: "Immutable append-only log".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Compliance frameworks".to_string(),
                competitor_value: "Manual configuration".to_string(),
                kimberlite_value: "HIPAA-native; GDPR/SOC2/ISO-27001 overlays — 92 TLAPS proofs".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Formal verification".to_string(),
                competitor_value: "None".to_string(),
                kimberlite_value: "136+ proofs across 7 verification tools".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Geo-distribution".to_string(),
                competitor_value: "Multi-region with locality-aware routing".to_string(),
                kimberlite_value: "Single-region (multi-region planned)".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "Wire protocol".to_string(),
                competitor_value: "PostgreSQL wire protocol".to_string(),
                kimberlite_value: "Custom protocol optimized for audit workloads".to_string(),
                kimberlite_advantage: false,
            },
            ComparisonRow {
                feature: "License".to_string(),
                competitor_value: "Business Source License (BSL)".to_string(),
                kimberlite_value: "Apache 2.0".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Data integrity".to_string(),
                competitor_value: "Raft consensus + checksums".to_string(),
                kimberlite_value: "VSR consensus + dual hash chains + CRC32".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Access control".to_string(),
                competitor_value: "PostgreSQL RBAC".to_string(),
                kimberlite_value: "RBAC + ABAC + field masking + consent management".to_string(),
                kimberlite_advantage: true,
            },
            ComparisonRow {
                feature: "Simulation testing".to_string(),
                competitor_value: "Standard test suites".to_string(),
                kimberlite_value: "VOPR deterministic simulation (~50 substantive scenarios)".to_string(),
                kimberlite_advantage: true,
            },
        ],
        architecture_left_title: "CockroachDB: Distributed SQL".to_string(),
        architecture_left_description: "CockroachDB distributes data across nodes using Raft \
                                        consensus. It prioritizes horizontal scalability and \
                                        PostgreSQL compatibility. Compliance requires external \
                                        tooling and manual configuration."
            .to_string(),
        architecture_right_title: "Kimberlite: Compliance-First".to_string(),
        architecture_right_description: "Kimberlite stores data in an immutable, hash-chained \
                                         log with VSR consensus. Compliance is structural: 23 \
                                         regulatory frameworks are formally verified with 92 \
                                         mathematical proofs."
            .to_string(),
    }
}

fn not_found_data() -> ComparisonData {
    ComparisonData {
        competitor: "Unknown".to_string(),
        slug: "unknown".to_string(),
        tagline: "Comparison not found.".to_string(),
        intro: "We don't have a comparison page for this database yet. Check out our comparisons \
                with PostgreSQL, TigerBeetle, and CockroachDB."
            .to_string(),
        competitor_best_for: String::new(),
        kimberlite_best_for: String::new(),
        competitor_use_cases: vec![],
        kimberlite_use_cases: vec![],
        rows: vec![],
        architecture_left_title: String::new(),
        architecture_left_description: String::new(),
        architecture_right_title: String::new(),
        architecture_right_description: String::new(),
    }
}
