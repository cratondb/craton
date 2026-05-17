---
title: "Start"
section: "start"
slug: "start"
order: 1
---

# Start

Get Kimberlite running in 2 minutes. This guide shows you how to install Kimberlite, start a cluster, and try compliance features.

## Install

<details open>
<summary>Linux & macOS</summary>

```bash
curl -fsSL https://kimberlite.dev/install.sh | sh
```

The script detects your OS and architecture automatically. After install, `kimberlite` (and its `kmb` alias) are available in your PATH.

```bash
kimberlite version
```

You should see a version table with the Rust version, target architecture, and OS.
</details>

<details>
<summary>Windows</summary>

Download the binary from the [download page](https://kimberlite.dev/download) and extract it. Then verify:

```powershell
.\kimberlite.exe version
```
</details>

<details>
<summary>Docker</summary>

```bash
docker pull ghcr.io/kimberlitedb/kimberlite:latest
docker run --rm ghcr.io/kimberlitedb/kimberlite:latest version
```
</details>

<details>
<summary>Build from Source</summary>

Requires Rust 1.88+:

```bash
git clone https://github.com/kimberlitedb/kimberlite.git
cd kimberlite
cargo build --release --bin kimberlite
./target/release/kimberlite version
```
</details>

## Start the Dev Server

Initialize a project and start the development server:

```bash
# Interactive wizard (prompts for path and template)
kimberlite init

# Or skip the wizard:
kimberlite init my-app
cd my-app

# Start the dev server (database + auto-migration)
kimberlite dev
```

The database is now running on port 5432.

## Create Your First Table

Open the interactive SQL shell:

```bash
kimberlite repl --tenant 1
```

Create a table:

```sql
CREATE TABLE patients (
    id INT PRIMARY KEY,
    name TEXT NOT NULL,
    ssn TEXT NOT NULL,
    diagnosis TEXT
);
```

Insert some data:

```sql
INSERT INTO patients VALUES (1, 'Alice Johnson', '123-45-6789', 'Hypertension');
```

```sql
INSERT INTO patients VALUES (2, 'Bob Smith', '987-65-4321', 'Diabetes');
```

Query it:

```sql
SELECT * FROM patients;
```

Output:
```
 id  name           ssn           diagnosis
 1   Alice Johnson  123-45-6789   Hypertension
 2   Bob Smith      987-65-4321   Diabetes
(2 rows)
```

## Try Compliance Features

Kimberlite is built for healthcare. Here are some compliance features you can try right now.

### Data Masking (HIPAA-Compliant)

Mask sensitive fields like SSNs:

```sql
CREATE MASK ssn_mask ON patients.ssn USING REDACT;
```

Query again — SSN is now masked:

```sql
SELECT * FROM patients;
```

Output:
```
 id  name           ssn    diagnosis
 1   Alice Johnson  ****   Hypertension
 2   Bob Smith      ****   Diabetes
(2 rows)
```

### Data Classification

Tag fields with compliance categories:

```sql
ALTER TABLE patients MODIFY COLUMN ssn SET CLASSIFICATION 'PHI';
```

```sql
ALTER TABLE patients MODIFY COLUMN diagnosis SET CLASSIFICATION 'MEDICAL';
```

View classification metadata:

```sql
SHOW CLASSIFICATIONS FOR patients;
```

Output:
```
 column     classification
 ssn        PHI
 diagnosis  MEDICAL
```

### Role-Based Access Control

Create roles with specific permissions:

```sql
CREATE ROLE billing_clerk;
```

```sql
GRANT SELECT (id, name, ssn) ON patients TO billing_clerk;
```

```sql
CREATE ROLE doctor;
```

```sql
GRANT SELECT ON patients TO doctor;
```

```sql
CREATE USER clerk1 WITH ROLE billing_clerk;
```

### Audit Trail (Automatic)

Every change is recorded automatically. View the audit log:

```sql
SELECT * FROM _kimberlite_audit;
```

Output:
```
 timestamp            user     operation  table_name  record_id
 2026-03-21 10:15:12  admin    CREATE     patients    NULL
 2026-03-21 10:15:28  admin    INSERT     patients    1
 2026-03-21 10:15:32  admin    INSERT     patients    2
```

### Time-Travel Queries

Kimberlite stores every change as an immutable log entry. Query the database at any past state using `AT OFFSET`:

```sql
SELECT * FROM patients AT OFFSET 1;
```

This returns the state of the table as it was at log position 1 (before any inserts were applied).

### Consent Management

Track user consent for data processing:

```sql
INSERT INTO _kimberlite_consent (subject_id, purpose, granted)
VALUES ('patient:1', 'marketing', true);
```

Query consent records:

```sql
SELECT * FROM _kimberlite_consent;
```

### Right to Erasure (GDPR)

Mark data for deletion (while preserving audit trail):

```sql
UPDATE patients SET name = 'REDACTED', ssn = 'REDACTED' WHERE id = 1;
```

The change is logged automatically. View the audit trail:

```sql
SELECT * FROM _kimberlite_audit WHERE table_name = 'patients';
```

## What Makes Kimberlite Different?

Traditional databases bolt on compliance features as afterthoughts. Kimberlite is built from the ground up for healthcare:

- **HIPAA-native** - Privacy + Security + Breach Notification Rules modeled in TLA+; Safe Harbor de-identification covers all 18 §164.514(b)(2) identifiers; overlays compose for GDPR / SOC 2 / ISO 27001 / FedRAMP
- **Append-only architecture** - Nothing is ever deleted, perfect audit trails (HIPAA §164.530(j)(2): 6 years; pediatric: until age of majority + 7)
- **Built-in data classification** - PHI, PII, PCI automatically tagged
- **Time-travel queries** - Query any historical state (subject-access, OCR review, payer dispute, malpractice litigation)
- **Field-level masking** - Selective redaction of sensitive data
- **Formal verification** - Safety properties proven with TLA+, Coq, and Alloy
- **Multi-tenant isolation** - Complete PHI separation per clinic / payer / sponsor

## Next Steps

### Build an Application

Try our SDK quickstarts:

- [Python](/docs/coding/python) - Build apps with Python
- [TypeScript](/docs/coding/typescript) - Node.js applications
- [Rust](/docs/coding/rust) - Native Rust integration
- [Go](/docs/coding/go) - Go applications

### Explore Features

Learn about Kimberlite's unique capabilities:

- [Compliance](/docs/concepts/compliance) - 23 frameworks explained
- [Data Classification](/docs/concepts/data-classification) - PHI, PII, PCI tags
- [RBAC](/docs/concepts/rbac) - Role-based access control
- [ABAC](/docs/concepts/abac) - Attribute-based policies
- [Multitenancy](/docs/concepts/multitenancy) - Tenant isolation
- [Architecture](/docs/concepts/architecture) - How it works

### Deploy to Production

Run Kimberlite in production:

- [Deployment](/docs/operating/deployment) - Single-node and clusters
- [Monitoring](/docs/operating/monitoring) - Metrics and alerts
- [Security](/docs/operating/security) - Hardening and best practices
- [Performance](/docs/operating/performance) - Tuning for scale

### Command Reference

Learn all available commands:

- [CLI Reference](/docs/reference/cli) - All commands and options
- [SQL Reference](/docs/reference/sql/overview) - SQL dialect and extensions
- [Protocol](/docs/reference/protocol) - Wire protocol specification

## Getting Help

- **Documentation** - Browse [all docs](/docs)
- **Examples** - See the `examples/` directory in the repository
- **Issues** - Report bugs on [GitHub](https://github.com/kimberlitedb/kimberlite/issues)
- **Discussions** - Ask questions on [GitHub Discussions](https://github.com/kimberlitedb/kimberlite/discussions)

---

**Ready to build?** Pick a [language quickstart](/docs/coding) and start coding.
