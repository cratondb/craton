//! # kimberlite-rbac: Role-Based Access Control
//!
//! Provides fine-grained access control for Kimberlite:
//! - **Role-based access control** (4 roles: Admin, Analyst, User, Auditor)
//! - **Field-level security** (column filtering)
//! - **Row-level security** (RLS with WHERE clause injection)
//! - **Policy enforcement** at query time
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  Query Request                               │
//! └─────────────────┬───────────────────────────┘
//!                   │
//!                   ▼
//! ┌─────────────────────────────────────────────┐
//! │  PolicyEnforcer                              │
//! │  ├─ Stream-level access control              │
//! │  ├─ Column filtering (field-level security)  │
//! │  └─ Row filtering (RLS)                      │
//! └─────────────────┬───────────────────────────┘
//!                   │
//!                   ▼
//! ┌─────────────────────────────────────────────┐
//! │  Rewritten Query                             │
//! │  - Unauthorized columns removed              │
//! │  - WHERE clause injected                     │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Roles
//!
//! | Role     | Read | Write | Delete | Export | Cross-Tenant | Audit Logs |
//! |----------|------|-------|--------|--------|--------------|------------|
//! | Auditor  | ✓    | ✗     | ✗      | ✗      | ✗            | ✓          |
//! | User     | ✓    | ✓     | ✗      | ✗      | ✗            | ✗          |
//! | Analyst  | ✓    | ✗     | ✗      | ✓      | ✓            | ✗          |
//! | Admin    | ✓    | ✓     | ✓      | ✓      | ✓            | ✓          |
//!
//! ## Examples
//!
//! ### Standard Policies
//!
//! ```
//! use kimberlite_rbac::policy::StandardPolicies;
//! use kimberlite_types::TenantId;
//!
//! // Admin: full access
//! let admin_policy = StandardPolicies::admin();
//!
//! // User: tenant-isolated access
//! let user_policy = StandardPolicies::user(TenantId::new(42));
//!
//! // Analyst: cross-tenant read, no write
//! let analyst_policy = StandardPolicies::analyst();
//!
//! // Auditor: audit logs only
//! let auditor_policy = StandardPolicies::auditor();
//! ```
//!
//! ### Custom Policies
//!
//! ```
//! use kimberlite_rbac::policy::{AccessPolicy, RowFilter, RowFilterOperator};
//! use kimberlite_rbac::roles::Role;
//! use kimberlite_types::TenantId;
//!
//! let policy = AccessPolicy::new(Role::User)
//!     .with_tenant(TenantId::new(42))
//!     .allow_stream("patient_*")      // Only patient streams
//!     .deny_stream("patient_sensitive") // Except sensitive data
//!     .allow_column("*")
//!     .deny_column("ssn")              // No SSN access
//!     .with_row_filter(RowFilter::new(
//!         "tenant_id",
//!         RowFilterOperator::Eq,
//!         "42",
//!     ));
//! ```
//!
//! ### Policy Enforcement
//!
//! ```
//! use kimberlite_rbac::enforcement::PolicyEnforcer;
//! use kimberlite_rbac::policy::StandardPolicies;
//! use kimberlite_types::TenantId;
//!
//! let policy = StandardPolicies::user(TenantId::new(42));
//! let enforcer = PolicyEnforcer::new(policy);
//!
//! // Check stream access
//! enforcer.enforce_stream_access("patient_records")?;
//!
//! // Filter columns
//! let requested = vec!["name".to_string(), "ssn".to_string()];
//! let allowed = enforcer.filter_columns(&requested);
//!
//! // Generate WHERE clause for row-level security
//! let where_clause = enforcer.generate_where_clause()?;
//! // Result: "tenant_id = 42"
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Compliance
//!
//! RBAC supports multi-framework compliance:
//!
//! - **HIPAA § 164.312(a)(1)**: Role-based access controls
//! - **GDPR Article 32(1)(b)**: Access controls and confidentiality
//! - **SOC 2 CC6.1**: Logical access controls
//! - **PCI DSS Requirement 7**: Restrict access to cardholder data
//! - **ISO 27001 A.5.15**: Access control policy
//! - **`FedRAMP` AC-3**: Access enforcement
//!
//! ## Formal Verification
//!
//! All RBAC properties are formally verified:
//!
//! - **TLA+ Specification**: `specs/tla/compliance/RBAC.tla`
//!   - `NoUnauthorizedAccess` theorem
//!   - `PolicyCompleteness` theorem
//!   - `AuditTrailComplete` theorem
//!
//! - **Kani Proofs**: `src/lib.rs` (bounded model checking)
//!   - Proof #33: Role separation
//!   - Proof #34: Column filter completeness
//!   - Proof #35: Row filter enforcement
//!   - Proof #36: Audit completeness
//!
//! - **VOPR Scenarios**: `kimberlite-sim/src/scenarios/`
//!   - `unauthorized_column_access`
//!   - `role_escalation_attack`
//!   - `row_level_security`
//!   - `audit_trail_completeness`

pub mod enforcement;
pub mod masking;
pub mod permissions;
pub mod policy;
pub mod roles;
pub mod smart_on_fhir;

// Re-export commonly used types
pub use enforcement::{EnforcementError, PolicyEnforcer};
pub use permissions::{Permission, PermissionSet};
pub use policy::{
    AccessPolicy, ColumnFilter, RowFilter, RowFilterOperator, StandardPolicies, StreamFilter,
};
pub use roles::Role;

// Kani proofs for bounded model checking
#[cfg(kani)]
mod kani_proofs;
