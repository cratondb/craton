---
title: "Role-Based Access Control (RBAC)"
section: "concepts"
slug: "rbac"
order: 8
---

# Role-Based Access Control (RBAC)

Kimberlite provides **fine-grained Role-Based Access Control (RBAC)** to enforce data access policies at query time:
- **4 roles** with escalating privileges (Auditor, User, Analyst, Admin)
- **Field-level security** (column filtering)
- **Row-level security** (RLS with WHERE clause injection)
- **Healthcare-grade compliance** (HIPAA-native; GDPR / SOC 2 / ISO 27001 / FedRAMP overlays for federal-touching healthcare)

---

## Why RBAC Matters

**Data access control is critical for compliance:**
- ❌ HIPAA violations: $50K+ fines per violation (§ 164.312(a)(1))
- ❌ GDPR violations: €20M or 4% revenue (Article 32(1)(b))
- ❌ PCI DSS non-compliance: Loss of payment processing (Requirement 7)
- ❌ Data breaches from inadequate access controls

**Kimberlite RBAC provides:**
- ✅ **Role-based policies** - 4 pre-defined roles with clear privilege boundaries
- ✅ **Field-level security** - Hide sensitive columns (SSN, passwords) from unauthorized users
- ✅ **Row-level security** - Automatic tenant isolation for multi-tenant applications
- ✅ **Audit trails** - All access attempts are logged for compliance audits
- ✅ **Formal verification** - TLA+ proofs + Kani bounded model checking

---

## Roles

Kimberlite supports **4 roles** with escalating privileges:

| Role     | Read | Write | Delete | Export | Cross-Tenant | Audit Logs | Restrictiveness |
|----------|------|-------|--------|--------|--------------|------------|----------------|
| **Auditor** | ✓    | ✗     | ✗      | ✗      | ✗            | ✓          | Most (3)       |
| **User**    | ✓    | ✓     | ✗      | ✗      | ✗            | ✗          | High (2)       |
| **Analyst** | ✓    | ✗     | ✗      | ✓      | ✓            | ✗          | Medium (1)     |
| **Admin**   | ✓    | ✓     | ✓      | ✓      | ✓            | ✓          | Least (0)      |

### 1. Auditor

**Purpose:** Compliance auditors reviewing access patterns.

**Permissions:**
- ✅ Read audit logs only (`audit_*` streams)
- ❌ Cannot access application data
- ❌ Cannot write or delete
- ❌ Cannot export data

**Use Cases:**
- HIPAA-required workforce auditors (per §164.308(a)(1)(ii)(D))
- OCR investigations and BAA-bearing third parties
- Security teams reviewing access patterns
- External audit firms (Big 4)

**Example:**
```rust
use kimberlite_rbac::policy::StandardPolicies;

let policy = StandardPolicies::auditor();
// Allows: audit_log, audit_access, audit_system
// Denies: patient_records, user_profiles, etc.
```

---

### 2. User

**Purpose:** Standard application users with tenant-isolated access.

**Permissions:**
- ✅ Read/write own data (tenant-isolated)
- ❌ Cannot access other tenants' data
- ❌ Cannot delete data (compliance)
- ❌ Cannot export data
- ❌ Cannot access audit logs

**Use Cases:**
- End-users in multi-tenant SaaS applications
- Service accounts with limited scope
- Mobile app users

**Example:**
```rust
use kimberlite_rbac::policy::StandardPolicies;
use kimberlite_types::TenantId;

let tenant_id = TenantId::new(42);
let policy = StandardPolicies::user(tenant_id);

// Automatic WHERE clause injection:
// SELECT * FROM users WHERE tenant_id = 42
```

---

### 3. Analyst

**Purpose:** Business intelligence analysts with cross-tenant read access.

**Permissions:**
- ✅ Read across all tenants (no isolation)
- ✅ Export data for analysis
- ❌ Cannot write or delete
- ❌ Cannot access audit logs

**Use Cases:**
- BI analysts generating reports
- Data scientists training ML models
- Dashboard and reporting systems

**Example:**
```rust
use kimberlite_rbac::policy::StandardPolicies;

let policy = StandardPolicies::analyst();
// Cross-tenant read: SELECT * FROM users
// No WHERE tenant_id filter applied
```

---

### 4. Admin

**Purpose:** System administrators with full access.

**Permissions:**
- ✅ Full read/write/delete access
- ✅ Cross-tenant access
- ✅ Access to audit logs
- ✅ Can grant/revoke permissions
- ✅ Can export data

**Use Cases:**
- System administrators
- DevOps engineers
- Emergency break-glass access

**Example:**
```rust
use kimberlite_rbac::policy::StandardPolicies;

let policy = StandardPolicies::admin();
// No restrictions on streams, columns, or tenants
```

---

## Field-Level Security (Column Filtering)

**Hide sensitive columns** from unauthorized users:

```rust
use kimberlite_rbac::policy::AccessPolicy;
use kimberlite_rbac::roles::Role;

let policy = AccessPolicy::new(Role::Analyst)
    .allow_stream("users")
    .allow_column("*")        // Allow all columns by default
    .deny_column("ssn")       // Except SSN
    .deny_column("password"); // And password

// Query: SELECT name, email, ssn FROM users
// Rewritten: SELECT name, email FROM users
// (ssn column removed)
```

**Wildcard patterns:**
```rust
let policy = AccessPolicy::new(Role::Analyst)
    .allow_stream("*")
    .allow_column("*")
    .deny_column("pii_*");    // Deny all columns starting with "pii_"

// Denies: pii_ssn, pii_address, pii_phone
// Allows: public_name, public_email
```

---

## Row-Level Security (RLS)

**Automatic tenant isolation** for User role:

```rust
use kimberlite_rbac::policy::StandardPolicies;
use kimberlite_types::TenantId;

let tenant_id = TenantId::new(42);
let policy = StandardPolicies::user(tenant_id);

// Original query:
// SELECT * FROM users

// Rewritten query:
// SELECT * FROM users WHERE tenant_id = 42
```

**Custom row filters:**
```rust
use kimberlite_rbac::policy::{AccessPolicy, RowFilter, RowFilterOperator};

let policy = AccessPolicy::new(Role::User)
    .allow_stream("*")
    .allow_column("*")
    .with_row_filter(RowFilter::new(
        "tenant_id",
        RowFilterOperator::Eq,
        "42",
    ))
    .with_row_filter(RowFilter::new(
        "status",
        RowFilterOperator::Eq,
        "active",
    ));

// WHERE tenant_id = 42 AND status = 'active'
```

---

## Policy Enforcement

Policies are enforced at **query time**:

```
┌─────────────────────────────────────┐
│  Original Query                      │
│  SELECT name, ssn FROM users         │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  RBAC Filter                         │
│  ├─ Check stream access              │
│  ├─ Filter columns (remove "ssn")    │
│  └─ Inject WHERE clause              │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  Rewritten Query                     │
│  SELECT name FROM users              │
│  WHERE tenant_id = 42                │
└─────────────────────────────────────┘
```

---

## Compliance Mappings

| Framework | Requirement | RBAC Feature |
|-----------|-------------|--------------|
| **HIPAA** | § 164.312(a)(1) - Access controls | Role-based policies, tenant isolation |
| **GDPR** | Article 32(1)(b) - Confidentiality | Column filtering, audit trails |
| **SOC 2** | CC6.1 - Logical access controls | Role separation, policy enforcement |
| **PCI DSS** | Requirement 7 - Restrict access | Stream/column filtering, audit logs |
| **ISO 27001** | A.5.15 - Access control policy | Comprehensive RBAC framework |
| **FedRAMP** | AC-3 - Access enforcement | Policy-based access control |

---

## Formal Verification

All RBAC properties are **formally verified**:

### TLA+ Specification
**File:** `specs/tla/compliance/RBAC.tla`

**Theorems Proven:**
1. `NoUnauthorizedAccess` - No query succeeds without valid policy
2. `PolicyCompleteness` - All access attempts governed by policy
3. `AuditTrailComplete` - All access attempts logged

**Safety Properties:**
- Stream isolation (unauthorized streams never accessed)
- Column filtering correctness (denied columns never returned)
- Tenant isolation (User role restricted to own tenant)
- Monotonic timestamps (audit log chronologically ordered)

### Kani Bounded Model Checking
**File:** `crates/kimberlite-rbac/src/kani_proofs.rs`

**Proofs:**
- Proof #33: Role separation
- Proof #34: Column filter completeness
- Proof #35: Row filter enforcement
- Proof #36: Audit completeness

---

## Best Practices

### 1. Start with Least Privilege

**Default to most restrictive role**, then grant additional privileges as needed:

```rust
// ✅ Good: Start with User role
let policy = StandardPolicies::user(tenant_id);

// ❌ Bad: Start with Admin role
let policy = StandardPolicies::admin(); // Too permissive!
```

---

### 2. Use Standard Policies

**Prefer `StandardPolicies`** over custom policies for common use cases:

```rust
// ✅ Good: Use standard policy
let policy = StandardPolicies::user(tenant_id);

// ⚠️ Okay: Custom policy when needed
let policy = AccessPolicy::new(Role::User)
    .with_tenant(tenant_id)
    .allow_stream("*")
    .deny_stream("sensitive_*");
```

---

### 3. Document Custom Policies

If you override standard policies, **document why**:

```rust
// Override: Marketing team needs cross-tenant read for campaign analysis
// Approved by: John Doe (Security Lead)
// Date: 2024-01-15
let policy = AccessPolicy::new(Role::Analyst)
    .allow_stream("campaigns")
    .allow_column("*")
    .deny_column("pii_*");
```

---

### 4. Test Policy Changes

**Test RBAC policies** before deploying to production:

```rust
use kimberlite_rbac::enforcement::PolicyEnforcer;

let enforcer = PolicyEnforcer::new(policy).without_audit();

// Test stream access
assert!(enforcer.enforce_stream_access("users").is_ok());

// Test column filtering
let columns = vec!["name".to_string(), "ssn".to_string()];
let allowed = enforcer.filter_columns(&columns);
assert!(!allowed.contains(&"ssn".to_string()));
```

---

### 5. Monitor Audit Logs

**Regularly review audit logs** for unauthorized access attempts:

```sql
SELECT role, stream, decision, COUNT(*) as attempts
FROM audit_access_log
WHERE decision = 'DENY'
GROUP BY role, stream, decision
ORDER BY attempts DESC;
```

---

## Integration with ABAC and Masking

RBAC is the **first layer** of Kimberlite's access control stack. Two additional layers provide fine-grained enforcement:

1. **RBAC** (this document) — coarse-grained role-based column filtering and row-level security
2. **[Field-Level Masking](field-masking.md)** — transforms allowed columns based on role (e.g., SSN → `***-**-6789`)
3. **[ABAC](abac.md)** — context-aware decisions based on time, location, device, and clearance level

All three layers must allow access for a request to succeed. This provides **defense in depth**: even if RBAC allows access to a column, masking may redact the value, and ABAC may deny based on environmental context.

---

## See Also

- [Attribute-Based Access Control](abac.md) - Context-aware access (Layer 2)
- [Field-Level Masking](field-masking.md) - Data masking strategies (Layer 3)
- [Data Classification](data-classification.md) - 8-level classification system
- [Consent Management](consent-management.md) - GDPR consent tracking
- [Access Control Guide](/docs/coding/guides/access-control) - Implementation patterns
- [Compliance Overview](compliance.md) - Multi-framework compliance architecture

---

**Key Takeaway:** Kimberlite's RBAC system provides **formally verified**, **fine-grained access control** with automatic tenant isolation, field-level security, and comprehensive audit trails. All RBAC properties are proven correct using TLA+ and Kani bounded model checking.
