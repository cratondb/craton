---
title: "CLI Reference"
section: "reference"
slug: "cli"
order: 1
---

# CLI Reference

Complete reference for the Kimberlite command-line interface (`kimberlite`).

## Installation

See the [Start guide](../start/) for installation instructions.

## Global Options

These options work with all commands:

```bash
--no-color    # Disable colored output
--help        # Show help for any command
--version     # Show version information
```

Environment variables:

```bash
NO_COLOR=1    # Disable colored output (respects standard)
```

## Commands

### kimberlite version

Show version information.

```bash
kimberlite version
```

Output shows a version table with Rust version, target architecture, and OS.

---

### kimberlite init

Initialize a new Kimberlite project with scaffolding.

```bash
kimberlite init [PATH]
```

**Interactive Mode:**

Running `kimberlite init` without arguments launches an interactive wizard that
guides you through project setup:

1. **Welcome** — shows the Kimberlite version
2. **Path prompt** — where to create your project (default: `./my-app`)
3. **Template selection** — choose from Default, EHR, Claims, Research, or Multi-tenant
4. **Scaffolding** — creates directories, config, `.gitignore`, and README
5. **Summary** — shows what was created and next steps

**Arguments:**
- `PATH` - Project directory path. If omitted, the wizard prompts for it

**Options:**
- `--yes` - Run in non-interactive mode (skip wizard, use defaults). Auto-enabled in CI/piped environments
- `--template <NAME>` - Use a project template (skips template prompt in wizard)

**Templates:**
- `ehr` - EHR/EMR application (patients, encounters, observations — FHIR R4 wedge)
- `claims` - Payer/RCM application (X12 837 ingestion, 835 remittance, audit chain)
- `research` - Clinical research application (consent, IRB retention, Safe Harbor de-id)
- `multi-tenant` - Multi-tenant healthcare SaaS scaffold (organizations, users, resources)

**Example:**

```bash
# Interactive wizard (recommended)
kimberlite init

# Create new project with healthcare template
kimberlite init ./my-health-app --template healthcare

# Non-interactive init (CI-friendly)
kimberlite init my-app --yes
```

**Creates:**
```
project/
├── kimberlite.toml       # Configuration
├── migrations/           # Database migrations
│   └── 001_init.sql
├── .gitignore
└── README.md
```

---

### kimberlite dev

Start development server with database, Studio UI, and auto-migration.

```bash
kimberlite dev [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)
- `--no-migrate` - Skip automatic migrations
- `--no-studio` - Skip Studio web UI
- `--cluster` - Start in cluster mode (3 nodes)
- `--port <PORT>` - Custom database port
- `--studio-port <PORT>` - Custom Studio port

**Example:**

```bash
# Start dev server (DB on 5432, Studio on default port)
kimberlite dev

# Custom ports
kimberlite dev --port 8000 --studio-port 8001

# Database only (no Studio)
kimberlite dev --no-studio

# Cluster mode for testing replication
kimberlite dev --cluster
```

**What it does:**
1. Applies pending migrations
2. Starts database server
3. Launches Studio web UI (unless `--no-studio`)
4. Watches for migration changes (unless `--no-migrate`)

Press `Ctrl+C` to stop all services.

---

### kimberlite start

Start the Kimberlite server in production mode.

```bash
kimberlite start <PATH> [OPTIONS]
```

**Arguments:**
- `PATH` - Path to data directory

**Options:**
- `-a, --address <ADDR>` - Bind address (default: `5432`)
- `--development` - Development mode (no replication)

**Address formats:**
- Port only: `5432` (binds to `127.0.0.1:5432`)
- Full address: `0.0.0.0:5432` (binds to all interfaces)
- IPv6: `[::1]:5432`

**Example:**

```bash
# Start on default port
kimberlite start ./data

# Bind to all interfaces on port 8000
kimberlite start ./data --address 0.0.0.0:8000

# Development mode (single node, no replication)
kimberlite start ./data --development
```

**Production checklist:**
1. Use absolute path for data directory
2. Run as dedicated user (not root)
3. Use systemd or equivalent for process management
4. Configure firewall rules
5. Enable TLS (see [Security](../operating/security.md))

---

### kimberlite repl

Interactive SQL REPL for running queries.

```bash
kimberlite repl [OPTIONS]
```

**Options:**
- `-a, --address <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Example:**

```bash
# Connect to local server as tenant 1
kimberlite repl --address 127.0.0.1:5432 --tenant 1
```

**REPL commands:**
```sql
-- Execute SQL
SELECT * FROM patients;

-- Multi-line queries
CREATE TABLE users (
  id INT PRIMARY KEY,
  email TEXT NOT NULL
);

-- REPL-specific commands
.help               -- Show help message
.tables             -- List all tables
.exit               -- Exit the REPL (also .quit or .q)
```

**Keyboard shortcuts:**
- `Ctrl+D` - Exit REPL
- `Ctrl+R` - Search command history
- `Up/Down` - Browse command history
- `Tab` - SQL keyword and table name completion

---

### kimberlite query

Execute a single SQL query.

```bash
kimberlite query <SQL> [OPTIONS]
```

**Arguments:**
- `SQL` - SQL query string

**Options:**
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)
- `-a, --at <OFFSET>` - Query at specific offset (time-travel)

**Example:**

```bash
# Simple query
kimberlite query "SELECT * FROM users" --tenant 1

# Parameterized query (use $1, $2, etc.)
kimberlite query "SELECT * FROM users WHERE id = \$1" --tenant 1

# Time-travel query
kimberlite query "SELECT * FROM users" --tenant 1 --at 1000

# Remote server
kimberlite query "SELECT COUNT(*) FROM patients" \
  --server prod.example.com:5432 \
  --tenant 5
```

**Output:** Results are displayed as a table.

---

## Tenant Management

### kimberlite tenant create

Create a new tenant.

```bash
kimberlite tenant create [OPTIONS]
```

**Options:**
- `-i, --id <ID>` - Tenant ID (numeric)
- `-n, --name <NAME>` - Tenant name
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `--force` - Skip confirmation prompt

**Example:**

```bash
# Create tenant
kimberlite tenant create --id 1 --name "Acme Corp"

# Production (requires confirmation)
kimberlite tenant create --id 1 --name "Acme Corp" --force
```

---

### kimberlite tenant list

List all tenants.

```bash
kimberlite tenant list [OPTIONS]
```

**Options:**
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)

**Example:**

```bash
kimberlite tenant list
```

Output:
```
 ID  Name            Created
 1   Acme Corp       2026-01-15 10:00:00
 2   Beta Inc        2026-01-20 14:30:00
```

---

### kimberlite tenant delete

Delete a tenant and all its data.

```bash
kimberlite tenant delete [OPTIONS]
```

**Options:**
- `-i, --id <ID>` - Tenant ID
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `--force` - Skip confirmation prompt

**Example:**

```bash
# Delete tenant (prompts for confirmation)
kimberlite tenant delete --id 1

# Force delete without confirmation
kimberlite tenant delete --id 1 --force
```

**Warning:** This permanently deletes all data for the tenant. Use with caution.

---

### kimberlite tenant info

Show tenant information.

```bash
kimberlite tenant info [OPTIONS]
```

**Options:**
- `-i, --id <ID>` - Tenant ID
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)

**Example:**

```bash
kimberlite tenant info --id 1
```

Output:
```
Tenant: Acme Corp (ID: 1)
Created: 2026-01-15 10:00:00
Tables: 12
Total size: 1.2 GB
Last activity: 2026-02-11 09:45:00
```

---

## Cluster Management

### kimberlite cluster init

Initialize a new cluster configuration.

```bash
kimberlite cluster init [OPTIONS]
```

**Options:**
- `-n, --nodes <COUNT>` - Number of nodes (default: 3)
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
# Create 3-node cluster config
kimberlite cluster init

# Create 5-node cluster
kimberlite cluster init --nodes 5
```

**Creates:**
```
.kimberlite/
├── cluster.toml
├── node-0/
├── node-1/
└── node-2/
```

---

### kimberlite cluster start

Start all cluster nodes.

```bash
kimberlite cluster start [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite cluster start
```

Output:
```
Starting cluster...
✓ Node 0 started on port 5432
✓ Node 1 started on port 5433
✓ Node 2 started on port 5434
Cluster ready (leader: node 0)
```

---

### kimberlite cluster stop

Stop cluster node(s).

```bash
kimberlite cluster stop [OPTIONS]
```

**Options:**
- `--node <ID>` - Node ID to stop (if not specified, stops all)
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
# Stop all nodes
kimberlite cluster stop

# Stop specific node
kimberlite cluster stop --node 1
```

---

### kimberlite cluster status

Show cluster status.

```bash
kimberlite cluster status [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite cluster status
```

Output:
```
Cluster Status
--------------
Leader: node-0
View: 5

Node  Status   Address           Role       Last Heartbeat
 0    Healthy  127.0.0.1:5432    Leader     0.1s ago
 1    Healthy  127.0.0.1:5433    Follower   0.2s ago
 2    Healthy  127.0.0.1:5434    Follower   0.1s ago
```

---

### kimberlite cluster destroy

Destroy cluster configuration and data.

```bash
kimberlite cluster destroy [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)
- `--force` - Skip confirmation prompt

**Example:**

```bash
# Destroy cluster (prompts for confirmation)
kimberlite cluster destroy

# Force destroy
kimberlite cluster destroy --force
```

**Warning:** This deletes all cluster data. Cannot be undone.

---

## Migration Management

### kimberlite migration create

Create a new migration file.

```bash
kimberlite migration create <NAME> [OPTIONS]
```

**Arguments:**
- `NAME` - Migration name (use snake_case)

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite migration create add_users_table
```

**Creates:**
```
migrations/
└── 20260211_094500_add_users_table.sql
```

**Migration template:**
```sql
-- Migration: add_users_table
-- Created: 2026-02-11 09:45:00

-- Up migration
CREATE TABLE users (
    id INT PRIMARY KEY,
    email TEXT NOT NULL
);

-- Down migration (for rollback)
-- DROP TABLE users;
```

---

### kimberlite migration apply

Apply pending migrations.

```bash
kimberlite migration apply [OPTIONS]
```

**Options:**
- `--to <NUMBER>` - Apply up to specific migration
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
# Apply all pending migrations
kimberlite migration apply

# Apply up to migration 5
kimberlite migration apply --to 5
```

Output:
```
Applying migrations...
✓ 001_init.sql
✓ 002_add_users.sql
✓ 003_add_patients.sql
Applied 3 migrations in 1.2s
```

---

### kimberlite migration rollback

Rollback migrations.

```bash
kimberlite migration rollback [COUNT] [OPTIONS]
```

**Arguments:**
- `COUNT` - Number of migrations to rollback (default: 1)

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
# Rollback last migration
kimberlite migration rollback

# Rollback last 3 migrations
kimberlite migration rollback 3
```

Output:
```
Rolling back migrations...
✓ Rolled back 003_add_patients.sql
Rolled back 1 migration
```

---

### kimberlite migration status

Show migration status.

```bash
kimberlite migration status [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite migration status
```

Output:
```
Migration Status
----------------
Applied:
✓ 001_init.sql (2026-02-10 10:00:00)
✓ 002_add_users.sql (2026-02-10 11:00:00)

Pending:
  003_add_patients.sql
  004_add_rbac.sql

2 applied, 2 pending
```

---

### kimberlite migration validate

Validate migration files.

```bash
kimberlite migration validate [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite migration validate
```

Output:
```
Validating migrations...
✓ All migration files are valid
✓ No duplicate migration numbers
✓ All migrations have down migrations
```

---

## Stream Management

### kimberlite stream create

Create a new event stream.

```bash
kimberlite stream create <NAME> [OPTIONS]
```

**Arguments:**
- `NAME` - Stream name

**Options:**
- `-c, --class <CLASS>` - Data classification (default: `non-phi`)
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Classifications:**
- `non-phi` - Non-sensitive data
- `phi` - Protected Health Information (HIPAA)
- `deidentified` - De-identified data

**Example:**

```bash
# Create stream for PHI data
kimberlite stream create patient_events --class phi --tenant 1

# Create stream for logs
kimberlite stream create audit_logs --class non-phi --tenant 1
```

---

### kimberlite stream list

List all streams.

```bash
kimberlite stream list [OPTIONS]
```

**Options:**
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Example:**

```bash
kimberlite stream list --tenant 1
```

Output:
```
 ID  Name            Classification  Events  Size
 1   patient_events  PHI             1,234   1.2MB
 2   audit_logs      NON-PHI         5,678   3.4MB
```

---

### kimberlite stream append

Append events to a stream.

```bash
kimberlite stream append <STREAM_ID> <EVENTS...> [OPTIONS]
```

**Arguments:**
- `STREAM_ID` - Stream ID
- `EVENTS` - One or more event JSON strings

**Options:**
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Example:**

```bash
# Append single event
kimberlite stream append 1 '{"type":"admission","patient_id":"P123"}' --tenant 1

# Append multiple events
kimberlite stream append 1 \
  '{"type":"admission","patient_id":"P123"}' \
  '{"type":"diagnosis","patient_id":"P123","code":"I10"}' \
  --tenant 1
```

---

### kimberlite stream read

Read events from a stream.

```bash
kimberlite stream read <STREAM_ID> [OPTIONS]
```

**Arguments:**
- `STREAM_ID` - Stream ID

**Options:**
- `-f, --from <OFFSET>` - Starting offset (default: 0)
- `-m, --max-bytes <BYTES>` - Maximum bytes to read (default: 65536)
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Example:**

```bash
# Read from beginning
kimberlite stream read 1 --tenant 1

# Read from offset 100
kimberlite stream read 1 --from 100 --tenant 1

# Read with size limit
kimberlite stream read 1 --max-bytes 1048576 --tenant 1
```

Output:
```
Offset: 0
Data: {"type":"admission","patient_id":"P123"}

Offset: 1
Data: {"type":"diagnosis","patient_id":"P123","code":"I10"}

Read 2 events (1.2 KB)
```

---

## Backup & Restore

### kimberlite backup create

Create a full backup of the data directory.

```bash
kimberlite backup create [OPTIONS]
```

**Options:**
- `-d, --data-dir <DIR>` - Data directory to back up (required)
- `-o, --output <DIR>` - Backup output directory (default: `./backups`)

**Example:**

```bash
# Create backup
kimberlite backup create --data-dir ./data

# Custom output directory
kimberlite backup create --data-dir ./data --output /mnt/backups
```

Output:
```
Creating backup...
✓ Copied 1,234 files (5.6 GB)
✓ Verified checksums
Backup created: ./backups/kimberlite-backup-20260211-094500
```

---

### kimberlite backup restore

Restore a backup to a target directory.

```bash
kimberlite backup restore <BACKUP> [OPTIONS]
```

**Arguments:**
- `BACKUP` - Path to backup directory

**Options:**
- `-t, --target <DIR>` - Target directory (required)
- `--force` - Overwrite if target is not empty

**Example:**

```bash
# Restore backup
kimberlite backup restore ./backups/kimberlite-backup-20260211-094500 \
  --target ./data-restored

# Force overwrite
kimberlite backup restore ./backups/kimberlite-backup-20260211-094500 \
  --target ./data \
  --force
```

**Warning:** Use `--force` carefully. It will overwrite existing data.

---

### kimberlite backup list

List available backups.

```bash
kimberlite backup list [BACKUP_DIR]
```

**Arguments:**
- `BACKUP_DIR` - Directory containing backups (default: `./backups`)

**Example:**

```bash
kimberlite backup list
```

Output:
```
Available Backups
-----------------
kimberlite-backup-20260211-094500  (5.6 GB)  2026-02-11 09:45:00
kimberlite-backup-20260210-103000  (5.4 GB)  2026-02-10 10:30:00
kimberlite-backup-20260209-150000  (5.2 GB)  2026-02-09 15:00:00
```

---

### kimberlite backup verify

Verify backup integrity.

```bash
kimberlite backup verify <BACKUP>
```

**Arguments:**
- `BACKUP` - Path to backup directory

**Example:**

```bash
kimberlite backup verify ./backups/kimberlite-backup-20260211-094500
```

Output:
```
Verifying backup...
✓ All checksums valid
✓ All files present
✓ Backup is intact
```

---

## Configuration

### kimberlite config show

Show current configuration.

```bash
kimberlite config show [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)
- `-f, --format <FORMAT>` - Output format: `text`, `json`, `toml` (default: `text`)

**Example:**

```bash
# Show as text
kimberlite config show

# Show as JSON
kimberlite config show --format json

# Show as TOML
kimberlite config show --format toml
```

---

### kimberlite config set

Set a configuration value.

```bash
kimberlite config set <KEY> <VALUE> [OPTIONS]
```

**Arguments:**
- `KEY` - Configuration key (e.g., `database.bind_address`)
- `VALUE` - Configuration value

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
# Set bind address
kimberlite config set database.bind_address "0.0.0.0:5432"

# Set replica count
kimberlite config set cluster.replica_count 5

# Set log level
kimberlite config set logging.level debug
```

---

### kimberlite config validate

Validate configuration files.

```bash
kimberlite config validate [OPTIONS]
```

**Options:**
- `-p, --project <DIR>` - Project directory (default: `.`)

**Example:**

```bash
kimberlite config validate
```

Output:
```
Validating configuration...
✓ kimberlite.toml is valid
✓ cluster.toml is valid
✓ All settings within valid ranges
```

---

## Utilities

### kimberlite info

Show server information.

```bash
kimberlite info [OPTIONS]
```

**Options:**
- `-s, --server <ADDR>` - Server address (default: `127.0.0.1:5432`)
- `-t, --tenant <ID>` - Tenant ID (required)

**Example:**

```bash
kimberlite info --server 127.0.0.1:5432 --tenant 1
```

Output:
```
Server Information
------------------
Version: 0.4.0
Uptime: 3 days, 5 hours
Cluster: 3 nodes (healthy)
Database size: 10.2 GB
Active connections: 42
Current view: 157
```

---

### kimberlite completion

Generate shell completions.

```bash
kimberlite completion <SHELL>
```

**Arguments:**
- `SHELL` - Shell type: `bash`, `elvish`, `fish`, `powershell`, `zsh`

**Example:**

```bash
# Bash
kimberlite completion bash > ~/.local/share/bash-completion/completions/kimberlite

# Zsh
kimberlite completion zsh > ~/.zfunc/_kimberlite

# Fish
kimberlite completion fish > ~/.config/fish/completions/kimberlite.fish

# PowerShell
kimberlite completion powershell > kimberlite.ps1
```

**Usage:**
- Bash: Add to `~/.bashrc`: `source ~/.local/share/bash-completion/completions/kimberlite`
- Zsh: Add to `~/.zshrc`: `fpath=(~/.zfunc $fpath)` then `autoload -Uz compinit && compinit`
- Fish: Completions auto-load from `~/.config/fish/completions/`
- PowerShell: Add to profile: `. kimberlite.ps1`

---

## Exit Codes

The CLI uses standard exit codes:

- `0` - Success
- `1` - General error
- `2` - Command line usage error
- `3` - Connection error
- `4` - Authentication error
- `5` - Permission denied
- `6` - Resource not found

**Example:**

```bash
kimberlite query "SELECT * FROM users" --tenant 1
echo $?  # Check exit code
```

---

## Environment Variables

The CLI respects these environment variables:

```bash
NO_COLOR=1                 # Disable colored output
KIMBERLITE_ADDRESS=:5432   # Default server address
KIMBERLITE_TENANT=1        # Default tenant ID
RUST_LOG=info              # Logging level (error, warn, info, debug, trace)
```

**Example:**

```bash
# Set defaults
export KIMBERLITE_ADDRESS=127.0.0.1:5432
export KIMBERLITE_TENANT=1

# Now --address and --tenant are optional
kimberlite query "SELECT * FROM users"
```

---

## Examples

### Common Workflows

**Initialize and start a project:**

```bash
# Initialize
kimberlite init my-app --template healthcare
cd my-app

# Start dev environment
kimberlite dev
```

**Production deployment:**

```bash
# Initialize cluster
kimberlite cluster init --nodes 3

# Start cluster
kimberlite cluster start

# Check status
kimberlite cluster status
```

**Database operations:**

```bash
# Create tenant
kimberlite tenant create --id 1 --name "Acme Corp"

# Create migration
kimberlite migration create add_users_table

# Apply migrations
kimberlite migration apply

# Query data
kimberlite query "SELECT * FROM users" --tenant 1
```

**Backup workflow:**

```bash
# Create backup
kimberlite backup create --data-dir ./data

# List backups
kimberlite backup list

# Verify backup
kimberlite backup verify ./backups/kimberlite-backup-20260211-094500

# Restore if needed
kimberlite backup restore ./backups/kimberlite-backup-20260211-094500 \
  --target ./data-restored
```

---

## Next Steps

- [SQL Reference](sql/overview.md) — SQL dialect and extensions
- [SDK Overview](sdk/overview.md) — client libraries
- [Deployment Guide](../operating/deployment.md) — production deployment
- [Security Guide](../operating/security.md) — hardening and best practices
