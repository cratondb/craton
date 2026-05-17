---
title: "Quick Start"
section: "start"
slug: "quick-start"
order: 2
---

# Quick Start

Get Kimberlite running and execute your first SQL queries in 5 minutes.

## Prerequisites

- `kimberlite` binary installed -- see [Start](/docs/start)

## Step 1: Create a Project

Run the interactive init wizard:

```bash
kimberlite init
```

The wizard walks you through project setup with diamond-styled prompts:

```
  ◆  Kimberlite  v0.8.0
  │
  │  The compliance-first database
  │

  ◆  Where should we create your project?
  │ ./my-app

  │

  ◆  Which template would you like?
  │ > default          Empty project with minimal setup
  │   ehr              EHR/EMR (patients, encounters, observations — FHIR R4 wedge)
  │   claims           Payer/RCM (X12 837 ingestion, 835 remittance, audit chain)
  │   research         Clinical research (consent, IRB retention, Safe Harbor de-id)
  │   multi-tenant     Clinic SaaS isolation (organizations, users, resources)

  │

  ◆  Creating project...
  ✓ Created project structure
  ✓ Wrote kimberlite.toml
  ✓ Created .gitignore
  ✓ Created README.md

  ◆  Your project is ready!
  │
  │  Location    /Users/you/my-app
  │  Template    default
  │  Config      kimberlite.toml

  └  Next steps
     cd my-app && kimberlite dev
```

You can also skip the wizard entirely:

```bash
kimberlite init my-app --template healthcare --yes
cd my-app
```

## Step 2: Start the Dev Server

```bash
kimberlite dev
```

You will see the dev server banner and startup sequence:

```
┌─────────────────────────────────────────────────────┐
│ Kimberlite Development Server                       │
└─────────────────────────────────────────────────────┘

✓ Config loaded
✓ Database started on 127.0.0.1:5432
✓ Studio started on http://127.0.0.1:5555

Ready! Press Ctrl+C to stop all services.

 Database:  127.0.0.1:5432
 Studio:    http://127.0.0.1:5555
 REPL:      kimberlite repl --tenant 1
 Logs:      .kimberlite/logs/dev.log
```

This starts:
- **Database server** at `127.0.0.1:5432`
- **Studio UI** at `http://127.0.0.1:5555` (disable with `--no-studio`)

## Step 3: Open the REPL

In a new terminal, from your project directory:

```bash
kimberlite repl --tenant 1
```

You will see the Kimberlite REPL connect and display its header:

```
✓ Connected to 127.0.0.1:5432

◆ Kimberlite SQL REPL

  Server: 127.0.0.1:5432
  Tenant: 1

Type .help for help, .exit to quit. Tab for completion.

kimberlite>
```

The REPL supports SQL syntax highlighting, tab completion for keywords and table names, and multi-line input (lines without a trailing `;` continue on the next line with a `...>` prompt).

## Step 4: Create a Table

```sql
CREATE TABLE patients (
    id BIGINT,
    name TEXT,
    dob TEXT,
    PRIMARY KEY (id)
);
```

## Step 5: Insert Data

```sql
INSERT INTO patients VALUES (1, 'Jane Doe', '1980-01-15');
```

```sql
INSERT INTO patients VALUES (2, 'John Smith', '1992-07-22');
```

```sql
INSERT INTO patients VALUES (3, 'Alice Johnson', '1975-03-08');
```

## Step 6: Query Data

```sql
SELECT * FROM patients;
```

```sql
SELECT * FROM patients WHERE id = 1;
```

```sql
SELECT * FROM patients WHERE name LIKE 'J%';
```

Expected output:

```
 id  name           dob
 1   Jane Doe       1980-01-15
 2   John Smith     1992-07-22
 3   Alice Johnson  1975-03-08
(3 rows)
```

## Step 7: Time-Travel Query

Kimberlite stores every change as an immutable log entry. Query the database at any past state:

Insert a new record:

```sql
INSERT INTO patients VALUES (4, 'Bob Williams', '1988-11-30');
```

Query at offset 3 (before the insert above):

```sql
SELECT * FROM patients AT OFFSET 3;
```

Query at the current state (latest):

```sql
SELECT * FROM patients;
```

## What's Next

- **[First Application](first-app.md)** -- Build a healthcare compliance app
- **[SQL Reference](../reference/sql/overview)** -- Full SQL syntax
- **[Concepts](../concepts/)** -- Why Kimberlite works this way
