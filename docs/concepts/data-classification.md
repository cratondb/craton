---
title: "Data Classification"
section: "concepts"
slug: "data-classification"
order: 6
---

# Data Classification

Kimberlite provides **8 data classification levels** built for healthcare compliance — HIPAA-native (PHI, de-identified, audit records) with overlay framework support (GDPR, PCI DSS for billing card-on-file, ISO 27001, FedRAMP for federal-touching healthcare).

---

## Why Classification Matters

**Data classification determines:**
- **Encryption requirements** - Which data must be encrypted at rest
- **Access controls** - Who can access the data
- **Audit logging** - What must be logged
- **Retention policies** - How long data must be kept
- **Compliance scope** - Which regulations apply

**Without proper classification**, you risk:
- ❌ HIPAA violations ($50K+ fines per violation)
- ❌ GDPR violations (€20M or 4% revenue)
- ❌ PCI DSS non-compliance (loss of payment processing)
- ❌ Data breaches from inadequate protection

---

## Classification Levels (8 Total)

Kimberlite supports 8 classification levels, ordered from least to most restrictive:

```
Public < Deidentified < Confidential < PII < Financial < PCI < Sensitive < PHI
```

### 1. Protected Health Information (PHI)

**Definition:** Medical records and health information subject to HIPAA regulations.

**Examples:**
- Patient medical records
- Diagnoses and treatment plans
- Lab results and prescriptions
- Clinical notes

**Compliance:** HIPAA Privacy Rule, HIPAA Security Rule

**Requirements:**
- ✅ Encryption at rest (HIPAA § 164.312(a)(2)(iv))
- ✅ Audit logging (HIPAA § 164.312(b))
- ✅ Access controls (HIPAA § 164.312(a)(1))
- Minimum retention: **6 years** from last treatment (HIPAA § 164.530)

**Applicable Frameworks:** HIPAA, GDPR (as PII), ISO 27001, FedRAMP

---

### 2. Deidentified Data

**Definition:** Data stripped of all 18 HIPAA identifiers per Safe Harbor method.

**Examples:**
- Anonymized patient datasets
- Aggregate statistics
- De-identified cohort studies

**Compliance:** HIPAA Safe Harbor Method (§ 164.514(b)(2))

**Requirements:**
- No encryption required (no identifiers present)
- No audit logging required
- Can be used for research without consent

**Applicable Frameworks:** HIPAA only

**Note:** Must remove all 18 identifiers: names, addresses, dates (except year), phone numbers, email, SSN, medical record numbers, account numbers, certificate/license numbers, vehicle identifiers, device identifiers, URLs, IP addresses, biometric identifiers, full-face photos, and any other unique identifying numbers.

---

### 3. Personally Identifiable Information (PII)

**Definition:** Information that can identify an individual (GDPR Article 4).

**Examples:**
- Names, email addresses, phone numbers
- IP addresses, location data
- User profiles, customer contacts
- Online identifiers (cookies, device IDs)

**Compliance:** GDPR Articles 5-11 (lawfulness, consent, purpose limitation)

**Requirements:**
- ✅ Encryption at rest (GDPR Article 32(1)(a))
- ✅ Audit logging (GDPR Article 30)
- ✅ Access controls (GDPR Article 32(1)(b))
- Purpose-limited retention (GDPR Article 5(1)(e))

**Data Subject Rights:**
- Right to access (GDPR Article 15)
- Right to rectification (GDPR Article 16)
- Right to erasure/"right to be forgotten" (GDPR Article 17)
- Right to data portability (GDPR Article 20)

**Applicable Frameworks:** GDPR, ISO 27001, FedRAMP

---

### 4. Sensitive Personal Data

**Definition:** Special category data requiring explicit consent (GDPR Article 9).

**Examples:**
- Racial or ethnic origin
- Political opinions, religious beliefs
- Trade union membership
- Genetic data, biometric data
- Health data (not covered by HIPAA)
- Data concerning sex life or sexual orientation

**Compliance:** GDPR Article 9 (explicit consent required)

**Requirements:**
- ✅ Encryption at rest (GDPR Article 32)
- ✅ Audit logging (GDPR Article 30)
- ✅ Explicit consent (GDPR Article 9)
- ✅ Data Protection Impact Assessment (GDPR Article 35)
- Stricter access controls than regular PII

**Processing Restrictions:** Processing prohibited unless:
- Explicit consent obtained
- Processing necessary for employment/social security
- Legal claims or vital interests
- Legitimate activities of foundation/association
- Data made public by data subject
- Specific legal authorization

**Applicable Frameworks:** GDPR, ISO 27001, FedRAMP

---

### 5. Payment Card Industry Data (PCI)

**Definition:** Cardholder data subject to PCI DSS requirements.

**Examples:**
- Credit/debit card numbers (Primary Account Number - PAN)
- Cardholder name with PAN
- Expiration date with PAN
- Service code

**Compliance:** PCI DSS Requirements 1-12

**Requirements:**
- ✅ Encryption at rest (PCI DSS Requirement 3)
- ✅ Audit logging (PCI DSS Requirement 10)
- ✅ Access controls (PCI DSS Requirement 7)
- ✅ Network segmentation (PCI DSS Requirement 1)
- Minimum retention: **3 months** required, **1 year** recommended

**Critical Restrictions:**
- ❌ NEVER store full magnetic stripe data
- ❌ NEVER store CVV/CVV2/CVC2 after authorization
- ❌ NEVER store PIN or PIN block
- ✅ Mask PAN when displaying (show last 4 digits only)

**Applicable Frameworks:** PCI DSS, GDPR (as PII), ISO 27001, FedRAMP

---

### 6. Financial Data

**Definition:** Financial records associated with healthcare operations — claims payments, payer remittance, clinic invoicing, ledger entries. `DataClass::Financial` is retained from the pre-pivot multi-vertical scope and remains useful in healthcare contexts (revenue cycle management, clinical research grant accounting, hospital billing). It does *not* imply SOX coverage in v0.9.0+; finance verticals are out of product scope.

**Examples:**
- X12 835 remittance records
- Claim adjustment / denial events
- Hospital billing entries
- Clinical research grant ledgers
- Practice invoicing

**Compliance:** General financial recordkeeping; HIPAA still applies if any field references the patient.

**Requirements:**
- ✅ Encryption at rest
- ✅ Audit logging
- ✅ Immutable audit trails
- Minimum retention: see operator policy (HIPAA §164.530(j)(2): 6 years for any PHI-touching record)

**Applicability:** Any clinic, payer, or research organization that issues or receives healthcare payments

**Applicable Frameworks:** HIPAA (when PHI-linked), ISO 27001, internal financial-controls policies

---

### 7. Confidential Data

**Definition:** Internal business data and trade secrets.

**Examples:**
- Proprietary algorithms
- Business strategies and plans
- Internal communications
- Employee records
- Trade secrets, intellectual property

**Compliance:** ISO 27001 Annex A.8 (Asset Management)

**Requirements:**
- ✅ Encryption at rest (best practice)
- ✅ Audit logging (best practice)
- ✅ Access restricted to authorized personnel
- Retention: Business-defined

**Applicable Frameworks:** ISO 27001, FedRAMP

---

### 8. Public Data

**Definition:** Publicly available information with no restrictions.

**Examples:**
- Public website content
- Press releases
- Published research papers
- Blog posts
- Public announcements

**Compliance:** No special requirements

**Requirements:**
- No encryption required
- No audit logging required
- Unrestricted access

**Applicable Frameworks:** None (no compliance restrictions)

---

## Automatic Classification

Kimberlite can **automatically infer** data classification based on stream names:

```rust
use kimberlite_kernel::classification::infer_from_stream_name;
use kimberlite_types::DataClass;

// Healthcare patterns
assert_eq!(infer_from_stream_name("patient_records"), DataClass::PHI);
assert_eq!(infer_from_stream_name("deidentified_cohort"), DataClass::Deidentified);

// Privacy patterns
assert_eq!(infer_from_stream_name("user_profiles"), DataClass::PII);
assert_eq!(infer_from_stream_name("biometric_scans"), DataClass::Sensitive);

// Financial patterns
assert_eq!(infer_from_stream_name("credit_card_txns"), DataClass::PCI);
assert_eq!(infer_from_stream_name("general_ledger"), DataClass::Financial);

// General patterns
assert_eq!(infer_from_stream_name("internal_docs"), DataClass::Confidential);
assert_eq!(infer_from_stream_name("blog_posts"), DataClass::Public);
```

**Pattern Keywords:**

| Classification | Keywords |
|----------------|----------|
| PHI | patient, medical, health, diagnosis, prescription, lab_result, clinical |
| Deidentified | deidentified, anonymized, aggregate |
| PCI | credit_card, payment, card_transaction, cvv, pan |
| Financial | financial, ledger, accounting, audit_trail, balance_sheet, revenue |
| Sensitive | biometric, genetic, racial, ethnic, political, religious, sexual_orientation, trade_union |
| PII | user, customer, person, profile, contact, email, phone, address |
| Confidential | internal, confidential, proprietary, trade_secret, strategy |
| Public | public, announcement, press_release, blog, documentation |

**Safe Default:** If no patterns match, Kimberlite defaults to **Confidential** (better to be too restrictive than too permissive).

---

## Content-Based Classification (ML)

Beyond stream name inference, Kimberlite provides **content-based classification** that scans actual field values to detect sensitive data patterns:

```rust
use kimberlite_kernel::classification::{classify_content, ContentScanner};

// Scan individual fields
let scanner = ContentScanner;
assert!(scanner.scan_ssn("My SSN is 123-45-6789"));
assert!(scanner.scan_credit_card("Card: 4111111111111111"));
assert!(scanner.scan_email("Contact: user@example.com"));
assert!(scanner.scan_medical_terms("Diagnosis: acute myocardial infarction"));
assert!(scanner.scan_financial_terms("CUSIP: 037833100"));

// Classify content with confidence scoring
let result = classify_content(&["patient diagnosis: diabetes mellitus type 2"]);
assert_eq!(result.data_class, DataClass::PHI);
assert!(result.confidence > 0.5);
```

**Detected Patterns:**

| Pattern | Detection Method | Classification |
|---------|-----------------|----------------|
| SSN (XXX-XX-XXXX) | Regex | PII |
| Credit card numbers | Regex + Luhn check | PCI |
| Email addresses | Regex | PII |
| Medical terms | Keyword dictionary (ICD-10 codes, drug names, diagnoses) | PHI |
| Financial terms | Keyword dictionary (CUSIP, ISIN, account numbers) | Financial |

**Confidence Scoring:**
- Each field scan contributes a confidence weight (0.0-1.0)
- Multiple detections across fields increase overall confidence
- The `higher_class()` function ensures the most restrictive classification wins
- Results include `matched_patterns` for audit trail transparency

**Use Cases:**
- **Automated compliance tagging** during data ingestion
- **Classification validation** — verify user-assigned classification matches content
- **Data discovery** — scan existing streams to identify unclassified sensitive data
- **Breach assessment** — quickly determine data classes affected by an incident

---

## Validation

Kimberlite **prevents users from under-classifying data**:

```rust
use kimberlite_kernel::classification::validate_user_classification;
use kimberlite_types::DataClass;

// ✅ Allowed: User matches inference
validate_user_classification("patient_records", DataClass::PHI); // true

// ✅ Allowed: User is MORE restrictive (safe)
validate_user_classification("blog_posts", DataClass::Confidential); // true

// ❌ Denied: User is LESS restrictive (dangerous!)
validate_user_classification("patient_records", DataClass::Public); // false
validate_user_classification("credit_cards", DataClass::Confidential); // false
```

**Restrictiveness Ordering:**
```
Public (0) < Deidentified (1) < Confidential (2) < PII (3) <
Financial (4) < PCI (5) < Sensitive (6) < PHI (7)
```

---

## Framework Mapping

| Classification | HIPAA | GDPR | PCI DSS | ISO 27001 | FedRAMP |
|----------------|-------|------|---------|-----------|---------|
| PHI | ✅ | ✅ (special-category) | — | ✅ | ✅ |
| Deidentified | ✅ (Safe Harbor) | — | — | — | — |
| PII | — | ✅ | — | ✅ | ✅ |
| Sensitive | — | ✅ (Art 9) | — | ✅ | ✅ |
| PCI | — | ✅ (PII) | ✅ | ✅ | ✅ |
| Financial | ✅ (when PHI-linked) | — | — | ✅ | ✅ |
| Confidential | — | — | — | ✅ | ✅ |
| Public | — | — | — | — | — |

---

## Usage Examples

### Creating a Stream with Classification

```rust
use kimberlite::Kimberlite;
use kimberlite_types::{DataClass, Placement};

let kmb = Kimberlite::open("./data")?;

// Healthcare stream
kmb.create_stream(
    "patient_vitals",
    DataClass::PHI,           // Protected Health Information
    Placement::Region("us-east-1"),
)?;

// Payment stream
kmb.create_stream(
    "credit_card_transactions",
    DataClass::PCI,           // Payment Card Industry data
    Placement::Region("us-east-1"),
)?;

// Public stream
kmb.create_stream(
    "public_announcements",
    DataClass::Public,        // No restrictions
    Placement::Global,
)?;
```

### Querying Classification Requirements

```rust
use kimberlite_compliance::classification::*;
use kimberlite_types::DataClass;

// Check encryption requirements
assert!(requires_encryption(DataClass::PHI));       // true
assert!(requires_encryption(DataClass::PCI));       // true
assert!(!requires_encryption(DataClass::Public));   // false

// Check audit logging requirements
assert!(requires_audit_logging(DataClass::PHI));    // true
assert!(!requires_audit_logging(DataClass::Public)); // false

// Check consent requirements (GDPR Article 9)
assert!(requires_explicit_consent(DataClass::Sensitive)); // true
assert!(!requires_explicit_consent(DataClass::PII));      // false

// Get minimum retention periods
assert_eq!(min_retention_days(DataClass::PHI), Some(2_190));      // 6 years
assert_eq!(min_retention_days(DataClass::Financial), Some(2_555)); // 7 years
assert_eq!(min_retention_days(DataClass::PCI), Some(365));        // 1 year
assert_eq!(min_retention_days(DataClass::Public), None);          // No requirement

// Get applicable frameworks
let phi_frameworks = applicable_frameworks(DataClass::PHI);
assert!(phi_frameworks.contains(&"HIPAA"));
assert!(phi_frameworks.contains(&"GDPR"));
assert!(phi_frameworks.contains(&"ISO27001"));
```

---

## Best Practices

### 1. Start Restrictive, Relax Later

**Default to Confidential** if unsure. It's easier to relax restrictions later than to retroactively add them.

```rust
// Safe default
DataClass::Confidential

// Don't guess - if it might be PHI, classify as PHI
DataClass::PHI
```

### 2. Use Pattern-Based Naming

Name streams to match classification patterns:

```rust
// Good: Clear classification
"patient_medical_records"        // → PHI
"deidentified_patient_cohort"   // → Deidentified
"user_email_addresses"          // → PII
"credit_card_vault"             // → PCI
"public_blog_posts"             // → Public

// Bad: Ambiguous
"data_stream_1"                 // → Confidential (default)
"records"                       // → Confidential (default)
```

### 3. Document Exceptions

If you override automatic classification, document why:

```rust
// Override: Marketing emails are public (user consent obtained)
create_stream("user_emails", DataClass::Public, Placement::Global)?;
// ^ Documented in privacy policy: users opt-in to public marketing
```

### 4. Audit Classification Changes

Track when classifications change:

```rust
// Log classification changes for compliance audit trail
tracing::info!(
    stream = "patient_records",
    old_class = "Confidential",
    new_class = "PHI",
    reason = "Discovered stream contains diagnoses",
    user = "admin@hospital.com"
);
```

### 5. Multi-Framework Compliance

For data spanning multiple frameworks, use the **most restrictive** classification:

```rust
// Health data in EU: Both HIPAA and GDPR apply
// Use PHI (most restrictive)
DataClass::PHI
```

---

## Formal Verification

All data classification properties are **formally verified** with:

**TLA+ Specification:** `specs/tla/compliance/MetaFramework.tla`
- `DataClassIntegrity` invariant
- `DataClassificationComplete` theorem (all 8 levels defined)
- `EncryptionEnforced` theorem (encryption requirements verified)
- `FrameworkMappingCorrect` theorem (framework mappings verified)

**Kani Proofs:** `crates/kimberlite-kernel/src/kani_proofs.rs`
- Proof #31: Classification restrictiveness ordering
- Proof #32: Classification inference determinism

**Property Tests:** `crates/kimberlite-kernel/src/classification.rs`
- 11 unit tests covering all classification levels
- Inference pattern matching
- User classification validation

---

## Migration Guide

### Upgrading from 3-Level to 8-Level Classification

**Before (v0.3.0):**
```rust
DataClass::PHI         // Protected Health Information
DataClass::NonPHI      // Everything else
DataClass::Deidentified // Anonymized data
```

**After (v0.4.0):**
```rust
DataClass::PHI         // Protected Health Information (unchanged)
DataClass::Deidentified // Anonymized data (unchanged)

// NonPHI split into 6 categories:
DataClass::PII         // User data (GDPR)
DataClass::Sensitive   // Special category data (GDPR Art 9)
DataClass::PCI         // Payment card data (PCI DSS)
DataClass::Financial   // Financial records (claims, remittance, hospital billing — retained from pre-pivot scope, no SOX implication)
DataClass::Confidential // Internal business data
DataClass::Public      // Publicly available data
```

**Automatic Migration:**
All existing `NonPHI` streams are migrated to `Public` (least restrictive). **Review and reclassify** based on content.

---

## See Also

- [Compliance Overview](compliance.md) - Multi-framework compliance architecture
- [Encryption](/docs/coding/recipes/encryption) - Encryption recipes
- [Audit Trails](/docs/coding/recipes/audit-trails) - Audit trail recipes
- [Security](/docs/operating/security) - Security and compliance operations
- [Access Control](/docs/coding/guides/access-control) - RBAC and field-level security

---

**Key Takeaway:** Proper data classification is the **foundation of compliance**. Kimberlite's 8-level classification system is HIPAA-native — every PHI-bearing field is tagged at the storage boundary — and composes with GDPR / PCI DSS / ISO 27001 / FedRAMP as overlays for healthcare workloads that need them, with **formal verification** guarantees.
