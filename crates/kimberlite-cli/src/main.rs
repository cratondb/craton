//! Kimberlite unified CLI.
//!
//! The compliance-first database for regulated industries.
//!
//! # Quick Start
//!
//! ```bash
//! # Initialize a project
//! kimberlite init
//!
//! # Start development server (DB + Studio)
//! kimberlite dev
//!
//! # Connect with the REPL
//! kimberlite repl --tenant 1
//! ```

#![allow(clippy::struct_excessive_bools)] // CLI config structs have many feature flags
#![allow(clippy::too_many_lines)] // CLI main and arg parsing can be long
#![allow(clippy::unnecessary_wraps)] // CLI functions return Result for consistency
#![allow(dead_code)] // CLI utilities may not all be used yet
#![allow(clippy::match_wildcard_for_single_variants)] // CLI match patterns use wildcard for clarity
#![allow(clippy::wildcard_enum_match_arm)] // CLI exhaustive matching preferred

mod commands;
mod style;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use kimberlite_dev::DevConfig;

/// Kimberlite - the compliance-first database for regulated industries.
#[derive(Parser)]
#[command(name = "kimberlite")]
#[command(author, version, about)]
#[command(
    long_about = "Kimberlite \u{2014} the compliance-first database for regulated industries.

Get started:
  kimberlite init              Create a new project (interactive wizard)
  kimberlite dev               Start development environment
  kimberlite repl --tenant 1   Connect to database

Learn more:
  kimberlite <command> --help  Help for a specific command
  https://kimberlite.dev/docs  Full documentation"
)]
#[command(propagate_version = true)]
struct Cli {
    /// Disable colored output.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show version information.
    Version,

    /// Initialize a new Kimberlite project (interactive wizard).
    #[command(long_about = "Initialize a new Kimberlite project.\n\n\
            Launches an interactive wizard to set up your project. Use --yes to skip\n\
            the wizard and use defaults (useful for CI/scripts).")]
    Init {
        /// Project directory path. If omitted, uses current directory.
        path: Option<String>,

        /// Skip the wizard and use defaults (auto-enabled in CI/piped environments).
        #[arg(long)]
        yes: bool,

        /// Project template (healthcare, finance, legal, multi-tenant).
        #[arg(long)]
        template: Option<String>,
    },

    /// Start development server (database + Studio UI + auto-migration).
    Dev {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,

        /// Skip auto-migration.
        #[arg(long)]
        no_migrate: bool,

        /// Skip Studio UI.
        #[arg(long)]
        no_studio: bool,

        /// Start in cluster mode.
        #[arg(long)]
        cluster: bool,

        /// Custom database port.
        #[arg(long)]
        port: Option<u16>,

        /// Custom Studio port.
        #[arg(long)]
        studio_port: Option<u16>,
    },

    /// Start the Kimberlite server (production mode).
    Start {
        /// Path to the data directory.
        path: String,

        /// Address to bind to (port only: 3000, or full: 127.0.0.1:3000).
        #[arg(short, long, default_value = "5432")]
        address: String,

        /// Enable development mode (no replication).
        #[arg(long)]
        development: bool,

        /// Run as a cluster replica. Requires `KMB_REPLICA_ID` and
        /// `KMB_CLUSTER_PEERS` env vars (format: `0=ip:port,1=ip:port,…`).
        /// Mutually exclusive with `--development`. In cluster mode the
        /// HTTP sidecar binds 0.0.0.0:9000 (override via `KMB_HTTP_PORT`)
        /// so the chaos harness and monitoring probes can reach it.
        #[arg(long, conflicts_with = "development")]
        cluster: bool,
    },

    /// Interactive SQL REPL with syntax highlighting and tab completion.
    Repl {
        /// Server address to connect to.
        #[arg(short, long, default_value = "127.0.0.1:5432")]
        address: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,
    },

    /// Execute a single SQL query.
    Query {
        /// SQL query string.
        sql: String,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,

        /// Query at a specific offset (time-travel).
        #[arg(short, long)]
        at: Option<u64>,
    },

    /// Tenant management commands.
    #[command(subcommand)]
    Tenant(TenantCommands),

    /// Cluster management commands.
    #[command(subcommand)]
    Cluster(ClusterCommands),

    /// Migration workflow commands.
    #[command(subcommand)]
    Migration(MigrationCommands),

    /// Launch Studio web UI.
    Studio {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,

        /// Custom port.
        #[arg(long)]
        port: Option<u16>,
    },

    /// Stream management commands.
    #[command(subcommand)]
    Stream(StreamCommands),

    /// Simulation and verification commands.
    #[command(subcommand)]
    Sim(SimCommands),

    /// Configuration management commands.
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Backup and restore commands.
    #[command(subcommand)]
    Backup(BackupCommands),

    /// Show server information.
    Info {
        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID.
        #[arg(short, long)]
        tenant: u64,
    },

    /// Generate shell completions.
    Completion {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum TenantCommands {
    /// Create a new tenant.
    Create {
        /// Tenant ID.
        #[arg(short, long)]
        id: u64,

        /// Tenant name.
        #[arg(short, long)]
        name: String,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Force creation without confirmation (production).
        #[arg(long)]
        force: bool,
    },

    /// List all tenants.
    List {
        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,
    },

    /// Delete a tenant.
    Delete {
        /// Tenant ID.
        #[arg(short, long)]
        id: u64,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Force deletion without confirmation.
        #[arg(long)]
        force: bool,
    },

    /// Show tenant information.
    Info {
        /// Tenant ID.
        #[arg(short, long)]
        id: u64,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,
    },
}

#[derive(Subcommand)]
enum ClusterCommands {
    /// Initialize a new cluster configuration.
    Init {
        /// Number of nodes. Ignored when `--host` is provided (node
        /// count is then `hosts.len()`).
        #[arg(short, long, default_value = "3")]
        nodes: u32,

        /// Per-node host (routable IP or DNS name). Pass once per node
        /// in node-id order for a multi-host topology, e.g.
        /// `--host 10.0.1.5 --host 10.0.1.6 --host 10.0.1.7`. Omitted
        /// for a localhost cluster.
        #[arg(long = "host", value_name = "HOST")]
        hosts: Vec<String>,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Start cluster nodes locally.
    ///
    /// Without `--node-id`, every node in `cluster.toml` is spawned on
    /// this host — the localhost-development path. With `--node-id N`,
    /// only entry `N` is spawned; the other entries describe peers
    /// running on other hosts. This is the multi-host deployment path:
    /// each operator runs the same command on their box with the matching
    /// `--node-id`.
    Start {
        /// Spawn only this node id locally. Required for multi-host
        /// topologies; omit it for localhost clusters.
        #[arg(long)]
        node_id: Option<u32>,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Stop cluster node(s).
    Stop {
        /// Node ID to stop (if not specified, stops all).
        #[arg(long)]
        node: Option<u32>,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Show cluster status.
    Status {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Destroy cluster configuration.
    Destroy {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,

        /// Skip confirmation prompt.
        #[arg(long)]
        force: bool,
    },

    /// Create a `tar.zst` backup of the cluster's data dir.
    ///
    /// Captures `<project>/cluster/` — every node's data dir plus
    /// `cluster.toml` — into a single self-checksummed archive. The
    /// operator chooses when to run this (HIPAA § 164.308(a)(7)
    /// contingency plan): stop writes first for a clean snapshot, or
    /// accept the trailing-fsync-window-could-roll-back semantic.
    Backup {
        /// Project directory (the same path passed to `cluster init`).
        #[arg(short, long, default_value = ".")]
        project: String,

        /// Output archive path. Convention: `<name>.tar.zst`.
        #[arg(long, value_name = "ARCHIVE")]
        output: String,
    },

    /// Restore a cluster backup into a fresh data dir.
    ///
    /// The target directory must be empty or absent; restoring on top of
    /// a live cluster is rejected. After extract, every file's BLAKE3 is
    /// re-checked against the embedded manifest.
    Restore {
        /// Archive produced by `cluster backup`.
        #[arg(long, value_name = "ARCHIVE")]
        input: String,

        /// Fresh data dir to restore into (must be empty).
        #[arg(long, value_name = "DIR")]
        target: String,
    },
}

#[derive(Subcommand)]
enum MigrationCommands {
    /// Create a new migration file.
    Create {
        /// Migration name.
        name: String,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Apply pending migrations.
    Apply {
        /// Apply up to specific migration number.
        #[arg(long)]
        to: Option<u64>,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Rollback migrations.
    Rollback {
        /// Number of migrations to rollback.
        #[arg(default_value = "1")]
        count: u64,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Show migration status.
    Status {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Validate migration files.
    Validate {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },
}

#[derive(Subcommand)]
enum StreamCommands {
    /// Create a new stream.
    Create {
        /// Stream name.
        name: String,

        /// Data classification (non-phi, phi, deidentified).
        #[arg(short, long, default_value = "non-phi")]
        class: String,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,
    },

    /// List all streams.
    List {
        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,
    },

    /// Append events to a stream.
    Append {
        /// Stream ID.
        stream_id: u64,

        /// Events to append (as JSON strings).
        events: Vec<String>,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,
    },

    /// Read events from a stream.
    Read {
        /// Stream ID.
        stream_id: u64,

        /// Starting offset.
        #[arg(short, long, default_value = "0")]
        from: u64,

        /// Maximum bytes to read.
        #[arg(short, long, default_value = "65536")]
        max_bytes: u64,

        /// Server address.
        #[arg(short = 's', long, default_value = "127.0.0.1:5432")]
        server: String,

        /// Tenant ID (required).
        #[arg(short, long)]
        tenant: u64,
    },
}

#[derive(Subcommand)]
enum SimCommands {
    /// Run simulations.
    Run {
        /// Number of iterations.
        #[arg(short, long, default_value = "100")]
        iterations: u64,

        /// Random seed.
        #[arg(short, long)]
        seed: Option<u64>,

        /// Enable verbose output.
        #[arg(short, long)]
        verbose: bool,
    },

    /// Verify a specific simulation seed.
    Verify {
        /// Seed to reproduce.
        #[arg(short, long)]
        seed: u64,
    },

    /// Generate HTML report.
    Report {
        /// Output file path.
        #[arg(short, long, default_value = "report.html")]
        output: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration.
    Show {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,

        /// Output format (text, json, toml).
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Set a configuration value.
    Set {
        /// Configuration key (e.g., `database.bind_address`).
        key: String,

        /// Configuration value.
        value: String,

        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },

    /// Validate configuration files.
    Validate {
        /// Project directory.
        #[arg(short, long, default_value = ".")]
        project: String,
    },
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Create a full backup of the data directory.
    Create {
        /// Path to the data directory to back up.
        #[arg(short, long)]
        data_dir: String,

        /// Directory to store backup in.
        #[arg(short, long, default_value = "./backups")]
        output: String,
    },

    /// Restore a backup to a target directory.
    Restore {
        /// Path to the backup directory.
        backup: String,

        /// Target directory to restore to.
        #[arg(short, long)]
        target: String,

        /// Force overwrite if target is not empty.
        #[arg(long)]
        force: bool,
    },

    /// List available backups.
    List {
        /// Directory containing backups.
        #[arg(default_value = "./backups")]
        backup_dir: String,
    },

    /// Verify backup integrity.
    Verify {
        /// Path to the backup directory.
        backup: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    // Handle --no-color flag and NO_COLOR environment variable
    let no_color = cli.no_color || std::env::var("NO_COLOR").is_ok();
    if no_color {
        owo_colors::set_override(false);
        style::set_no_color(true);
    }

    match cli.command {
        Commands::Version => {
            commands::version::run();
            Ok(())
        }
        Commands::Init {
            path,
            yes,
            template,
        } => commands::init::run(path.as_deref(), yes, template.as_deref()),
        Commands::Dev {
            project,
            no_migrate,
            no_studio,
            cluster,
            port,
            studio_port,
        } => {
            style::banner::print_banner();
            let config = DevConfig {
                project_dir: project,
                no_migrate,
                no_studio,
                cluster,
                port,
                studio_port,
            };
            kimberlite_dev::run_dev_server(config).await
        }
        Commands::Start {
            path,
            address,
            development,
            cluster,
        } => commands::start::run(&path, &address, development, cluster),
        Commands::Repl { address, tenant } => commands::repl::run(&address, tenant),
        Commands::Query {
            sql,
            server,
            tenant,
            at,
        } => commands::query::run(&server, tenant, &sql, at),
        Commands::Tenant(cmd) => match cmd {
            TenantCommands::Create {
                id,
                name,
                server,
                force,
            } => commands::tenant::create(&server, id, &name, force),
            TenantCommands::List { server } => commands::tenant::list(&server),
            TenantCommands::Delete { id, server, force } => {
                commands::tenant::delete(&server, id, force)
            }
            TenantCommands::Info { id, server } => commands::tenant::info(&server, id),
        },
        Commands::Cluster(cmd) => match cmd {
            ClusterCommands::Init {
                nodes,
                hosts,
                project,
            } => commands::cluster::init(nodes, &hosts, &project),
            ClusterCommands::Start { node_id, project } => {
                commands::cluster::start(node_id, &project).await
            }
            ClusterCommands::Stop { node, project } => {
                commands::cluster::stop(node, &project).await
            }
            ClusterCommands::Status { project } => commands::cluster::status(&project),
            ClusterCommands::Destroy { project, force } => {
                commands::cluster::destroy(&project, force)
            }
            ClusterCommands::Backup { project, output } => {
                commands::cluster::backup(&project, &output)
            }
            ClusterCommands::Restore { input, target } => {
                commands::cluster::restore(&input, &target)
            }
        },
        Commands::Migration(cmd) => match cmd {
            MigrationCommands::Create { name, project } => {
                commands::migration::create(&name, &project)
            }
            MigrationCommands::Apply { to, project } => commands::migration::apply(to, &project),
            MigrationCommands::Rollback { count, project } => {
                commands::migration::rollback(count, &project)
            }
            MigrationCommands::Status { project } => commands::migration::status(&project),
            MigrationCommands::Validate { project } => commands::migration::validate(&project),
        },
        Commands::Studio {
            project: _project,
            port: _port,
        } => {
            println!("Studio not yet implemented (Phase 3)");
            Ok(())
        }
        Commands::Stream(cmd) => match cmd {
            StreamCommands::Create {
                name,
                class,
                server,
                tenant,
            } => commands::stream::create(&server, tenant, &name, &class),
            StreamCommands::List { server, tenant } => commands::stream::list(&server, tenant),
            StreamCommands::Append {
                stream_id,
                events,
                server,
                tenant,
            } => commands::stream::append(&server, tenant, stream_id, events),
            StreamCommands::Read {
                stream_id,
                from,
                max_bytes,
                server,
                tenant,
            } => commands::stream::read(&server, tenant, stream_id, from, max_bytes),
        },
        Commands::Sim(cmd) => match cmd {
            SimCommands::Run {
                iterations,
                seed,
                verbose,
            } => commands::sim::run(iterations, seed, verbose),
            SimCommands::Verify { seed } => commands::sim::verify(seed),
            SimCommands::Report { output } => commands::sim::report(&output),
        },
        Commands::Config(cmd) => match cmd {
            ConfigCommands::Show { project, format } => commands::config::show(&project, &format),
            ConfigCommands::Set {
                key,
                value,
                project,
            } => commands::config::set(&project, &key, &value),
            ConfigCommands::Validate { project } => commands::config::validate(&project),
        },
        Commands::Backup(cmd) => match cmd {
            BackupCommands::Create { data_dir, output } => {
                commands::backup::create(&data_dir, &output)
            }
            BackupCommands::Restore {
                backup,
                target,
                force,
            } => commands::backup::restore(&backup, &target, force),
            BackupCommands::List { backup_dir } => commands::backup::list(&backup_dir),
            BackupCommands::Verify { backup } => commands::backup::verify(&backup),
        },
        Commands::Info { server, tenant } => commands::info::run(&server, tenant),
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "kimberlite", &mut std::io::stdout());
            Ok(())
        }
    }
}
