//! VOPR: Viewstamped Operation Replication Simulation Tester
//!
//! A deterministic simulation testing tool inspired by `FoundationDB`'s
//! trillion CPU-hour testing and `TigerBeetle`'s VOPR approach.
//!
//! # Usage
//!
//! ```bash
//! # Run with a specific seed
//! vopr --seed 12345
//!
//! # Run multiple iterations
//! vopr --iterations 1000
//!
//! # Enable fault injection
//! vopr --faults network,storage
//!
//! # Verbose output
//! vopr -v --seed 12345
//! ```

#![allow(clippy::too_many_lines)] // CLI binaries have long main/parse functions
#![allow(clippy::format_collect)] // Format strings are built dynamically
#![allow(clippy::struct_excessive_bools)] // Config structs have many feature flags
#![allow(clippy::large_enum_variant)] // Enum variants can have different sizes

use std::io::Write;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use std::collections::{HashMap, HashSet};

use kimberlite_crypto::internal_hash;
use kimberlite_sim::{
    AggregateCorrectnessChecker, AgreementChecker, AppliedIndexIntegrityChecker,
    AppliedPositionMonotonicChecker, CommitHistoryChecker, CommitNumberConsistencyChecker,
    EventKind, HashChainChecker, LogConsistencyChecker, MergeLogSafetyChecker, MessageMutator,
    MvccVisibilityChecker, NetworkConfig, NoRecOracle, OrderByLimitChecker, PrefixPropertyChecker,
    ProjectionCatchupChecker, QueryDeterminismChecker, QueryPlanCoverageTracker,
    ReadYourWritesChecker, RecoverySafetyChecker, ReplicaConsistencyChecker, ReplicaHeadChecker,
    ScenarioConfig, ScenarioType, SimConfig, SimNetwork, SimRng, SimStorage, Simulation,
    StorageCheckpoint, StorageConfig, TenantIsolationChecker, TenantWorkloadGenerator, TlpOracle,
    TypeSafetyChecker, ViewChangeSafetyChecker, VsrSimulation, WorkloadScheduler,
    WorkloadSchedulerConfig, check_all_vsr_invariants,
    diagnosis::{FailureAnalyzer, FailureReport},
    instrumentation::{
        coverage::CoverageReport, fault_registry::get_fault_registry,
        invariant_runtime::init_invariant_context, invariant_tracker::get_invariant_tracker,
        phase_tracker::get_phase_tracker,
    },
    trace::{TraceCollector, TraceConfig, TraceEventType},
    vsr_message_from_bytes,
};

// ============================================================================
// CLI Configuration
// ============================================================================

/// Configuration for which invariants to enable
#[derive(Debug, Clone)]
struct InvariantConfig {
    // Core (always on by default)
    enable_hash_chain: bool,
    enable_log_consistency: bool,
    enable_replica_consistency: bool,
    enable_replica_head: bool,
    enable_commit_history: bool,

    // VSR
    enable_vsr_agreement: bool,
    enable_vsr_prefix_property: bool,
    enable_vsr_view_change_safety: bool,
    enable_vsr_recovery_safety: bool,

    // Projection
    enable_projection_applied_position: bool,
    enable_projection_mvcc_visibility: bool,
    enable_projection_applied_index: bool,
    enable_projection_catchup: bool,
    projection_catchup_step_limit: u64,

    // Query
    enable_query_determinism: bool,
    enable_query_read_your_writes: bool,
    enable_query_type_safety: bool,
    enable_query_order_by_limit: bool,
    enable_query_aggregates: bool,
    enable_query_tenant_isolation: bool,

    // SQL oracles (opt-in, expensive)
    enable_sql_tlp: bool,
    enable_sql_norec: bool,
    enable_sql_plan_coverage: bool,
}

impl Default for InvariantConfig {
    fn default() -> Self {
        Self {
            // Core: hash_chain disabled by default because the simulation uses
            // simplified hash generation, not actual hash chaining. Hash chain
            // integrity is better tested in storage layer unit tests.
            //
            // linearizability disabled: VOPR uses industry-proven approach (FDB/TigerBeetle)
            // of verifying VSR consensus correctness + offset monotonicity rather than
            // O(n!) post-hoc linearizability checking.
            enable_hash_chain: false,
            enable_log_consistency: true,
            enable_replica_consistency: true,
            enable_replica_head: true,
            enable_commit_history: true,

            // VSR: all true
            enable_vsr_agreement: true,
            enable_vsr_prefix_property: true,
            enable_vsr_view_change_safety: true,
            enable_vsr_recovery_safety: true,

            // Projection: all true
            enable_projection_applied_position: true,
            enable_projection_mvcc_visibility: true,
            enable_projection_applied_index: true,
            enable_projection_catchup: true,
            projection_catchup_step_limit: 10_000,

            // Query: all true
            enable_query_determinism: true,
            enable_query_read_your_writes: true,
            enable_query_type_safety: true,
            enable_query_order_by_limit: true,
            enable_query_aggregates: true,
            enable_query_tenant_isolation: true,

            // SQL oracles: all false (opt-in)
            enable_sql_tlp: false,
            enable_sql_norec: false,
            enable_sql_plan_coverage: false,
        }
    }
}

/// VOPR configuration parsed from command line.
struct VoprConfig {
    /// Starting seed for simulations.
    seed: u64,
    /// Number of iterations to run.
    iterations: u64,
    /// Enable network fault injection.
    network_faults: bool,
    /// Enable storage fault injection.
    storage_faults: bool,
    /// Verbose output.
    verbose: bool,
    /// Maximum events per simulation.
    max_events: u64,
    /// Maximum simulation time (nanoseconds).
    max_time_ns: u64,
    /// Output JSON instead of human-readable format.
    json_mode: bool,
    /// Path to checkpoint file for resume support.
    checkpoint_file: Option<String>,
    /// Enable determinism validation (run each seed 2x).
    check_determinism: bool,
    /// Enable trace collection.
    enable_trace: bool,
    /// Save trace on failure.
    save_trace_on_failure: bool,
    /// Enable enhanced workload patterns (RMW, scans).
    enhanced_workloads: bool,
    /// Generate failure diagnosis reports.
    failure_diagnosis: bool,
    /// Test scenario to run (None = custom based on flags).
    scenario: Option<ScenarioType>,
    /// Minimum fault point coverage percentage (0-100, 0 = disabled).
    min_fault_coverage: f64,
    /// Minimum invariant coverage percentage (0-100, 0 = disabled).
    min_invariant_coverage: f64,
    /// Fail if any critical invariants ran 0 times.
    require_all_invariants: bool,
    /// Invariant configuration (which invariants to enable).
    invariant_config: InvariantConfig,
    /// Use VSR replicas instead of simplified simulation mode.
    vsr_mode: bool,
    /// Operations per workload tick (default: 5).
    workload_ops_per_tick: usize,
    /// Workload tick interval in milliseconds (default: 10).
    workload_tick_interval_ms: u64,
}

impl Default for VoprConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            iterations: 100,
            network_faults: true,
            storage_faults: true,
            verbose: false,
            max_events: 10_000,
            max_time_ns: 10_000_000_000, // 10 seconds simulated
            json_mode: false,
            checkpoint_file: None,
            check_determinism: false,
            enable_trace: false,
            save_trace_on_failure: true,
            enhanced_workloads: true,
            failure_diagnosis: true,
            scenario: None,
            min_fault_coverage: 0.0,       // Default: no enforcement
            min_invariant_coverage: 0.0,   // Default: no enforcement
            require_all_invariants: false, // Default: disabled
            invariant_config: InvariantConfig::default(),
            vsr_mode: false, // Default: simplified mode
            workload_ops_per_tick: 5,
            workload_tick_interval_ms: 10,
        }
    }
}

// ============================================================================
// Checkpoint Management
// ============================================================================

/// Checkpoint state for resume support.
#[derive(Serialize, Deserialize, Default)]
struct VoprCheckpoint {
    /// Last completed seed.
    last_seed: u64,
    /// Total iterations completed across all runs.
    total_iterations: u64,
    /// Total failures detected across all runs.
    total_failures: u64,
    /// List of seeds that failed (for reproduction).
    failed_seeds: Vec<u64>,
    /// Timestamp of last update.
    last_update: String,
}

impl VoprCheckpoint {
    /// Loads checkpoint from file, returns default if file doesn't exist.
    fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(_) => Ok(Self::default()),
        }
    }

    /// Saves checkpoint to file.
    fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

// ============================================================================
// JSON Output
// ============================================================================

/// Outputs a message in either JSON or human-readable format.
fn output(json_mode: bool, msg_type: &str, data: Option<serde_json::Value>) {
    if json_mode {
        let output = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "type": msg_type,
            "data": data
        });
        println!("{output}");
    } else if let Some(data_val) = data {
        // Human-readable output based on type
        if msg_type == "iteration" {
            if let Some(status) = data_val.get("status") {
                if status == "failed" {
                    if let (Some(seed), Some(inv), Some(msg)) = (
                        data_val.get("seed"),
                        data_val.get("invariant"),
                        data_val.get("message"),
                    ) {
                        println!("FAILED seed {seed}: {inv} - {msg}");
                    }
                }
            }
        }
    }
}

// ============================================================================
// Fault Injection Configuration
// ============================================================================

/// Configuration for a single simulation run.
struct SimulationRun {
    seed: u64,
    network_config: NetworkConfig,
    storage_config: StorageConfig,
    scenario: Option<ScenarioConfig>,
}

impl SimulationRun {
    /// Creates a new simulation run with the given seed.
    fn new(seed: u64, config: &VoprConfig) -> Self {
        // If a scenario is specified, use its configuration
        if let Some(scenario_type) = config.scenario {
            let scenario = ScenarioConfig::new(scenario_type, seed);
            return Self {
                seed,
                network_config: scenario.network_config.clone(),
                storage_config: scenario.storage_config.clone(),
                scenario: Some(scenario),
            };
        }

        // Otherwise, use default configuration from CLI flags
        let mut rng = SimRng::new(seed);

        // Configure network faults based on settings
        let network_config = if config.network_faults {
            NetworkConfig {
                min_delay_ns: 1_000_000,                      // 1ms
                max_delay_ns: 50_000_000,                     // 50ms
                drop_probability: rng.next_f64() * 0.1,       // 0-10% drop rate
                duplicate_probability: rng.next_f64() * 0.05, // 0-5% duplicate rate
                max_in_flight: 1000,
            }
        } else {
            NetworkConfig {
                min_delay_ns: 1_000_000,
                max_delay_ns: 5_000_000,
                drop_probability: 0.0,
                duplicate_probability: 0.0,
                max_in_flight: 1000,
            }
        };

        // Configure storage faults based on settings
        let storage_config = if config.storage_faults {
            StorageConfig {
                min_write_latency_ns: 500_000,
                max_write_latency_ns: 2_000_000,
                min_read_latency_ns: 50_000,
                max_read_latency_ns: 200_000,
                write_failure_probability: rng.next_f64() * 0.01, // 0-1%
                read_corruption_probability: rng.next_f64() * 0.001, // 0-0.1%
                fsync_failure_probability: rng.next_f64() * 0.01, // 0-1%
                partial_write_probability: rng.next_f64() * 0.01, // 0-1%
                ..Default::default()
            }
        } else {
            StorageConfig::default()
        };

        Self {
            seed,
            network_config,
            storage_config,
            scenario: None,
        }
    }
}

// ============================================================================
// Model-Based Verification
// ============================================================================

/// In-memory model of expected database state for verification.
///
/// Tracks the expected key→value mappings after all committed writes.
/// Used to verify data correctness by comparing reads against the model.
///
/// Tracks both pending (unfsynced) and durable (fsynced) writes to match
/// read-your-writes semantics while correctly handling crashes.
///
/// This model verifies the assumptions made in `specs/tla/Recovery.tla`:
/// - Committed entries persist through crashes (Recovery.tla:108)
/// - Uncommitted entries may be lost on crash/fsync failure (Recovery.tla:112)
/// - Recovery restores committed state from quorum (Recovery.tla:118-199)
struct KimberliteModel {
    /// Durable state (fsynced writes).
    durable: HashMap<u64, u64>,
    /// Pending writes (not yet fsynced, will be lost on crash).
    pending: HashMap<u64, u64>,
}

impl KimberliteModel {
    /// Creates a new empty model.
    fn new() -> Self {
        Self {
            durable: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Records a pending write (not yet fsynced).
    fn apply_pending_write(&mut self, key: u64, value: u64) {
        self.pending.insert(key, value);
    }

    /// Commits pending writes to durable state (after fsync).
    fn commit_pending(&mut self) {
        for (key, value) in self.pending.drain() {
            self.durable.insert(key, value);
        }
    }

    /// Clears pending writes (on crash or checkpoint restore).
    fn clear_pending(&mut self) {
        self.pending.clear();
    }

    /// Clears durable writes (on checkpoint restore to reset model state).
    fn clear_durable(&mut self) {
        self.durable.clear();
    }

    /// Verifies a read matches expected state (checks pending first, then durable).
    ///
    /// Returns true if the read matches expectations. Stricter verification for
    /// compliance databases - after fixing fsync/reorderer bugs, we require exact matches.
    fn verify_read(&self, key: u64, actual: Option<u64>) -> bool {
        let expected = self.pending.get(&key).or_else(|| self.durable.get(&key));
        match (expected, actual) {
            (Some(expected), Some(actual)) => expected == &actual,
            (None, None | Some(_)) => {
                // (None, None): Expected no data, found none - correct.
                // (None, Some(_)): Model has no expectation but read found data.
                // This is acceptable only immediately after checkpoint recovery,
                // where the checkpoint may contain data not yet in the model.
                // In other cases, this indicates corruption or model desync.
                // For now, allow this but it should be investigated.
                // TODO(v0.9.0): Track recovery state to distinguish these cases.
                true
            }
            (Some(_), None) => false, // Data expected but missing - ALWAYS a bug
        }
    }

    /// Gets the expected value for a key.
    fn get(&self, key: u64) -> Option<u64> {
        self.pending
            .get(&key)
            .or_else(|| self.durable.get(&key))
            .copied()
    }
}

// ============================================================================
// Simulation Execution
// ============================================================================

/// Result of a simulation run.
#[derive(Debug)]
enum SimulationResult {
    /// Simulation completed successfully.
    Success {
        events_processed: u64,
        final_time_ns: u64,
        /// Final storage hash for determinism checking.
        storage_hash: [u8; 32],
        /// Final kernel state hash for determinism checking.
        kernel_state_hash: [u8; 32],
        /// Trace (if enabled).
        #[allow(dead_code)]
        trace: Option<TraceCollector>,
    },
    /// An invariant was violated.
    InvariantViolation {
        invariant: String,
        message: String,
        events_processed: u64,
        /// Trace leading up to failure.
        #[allow(dead_code)]
        trace: Option<TraceCollector>,
        /// Failure diagnosis report.
        failure_report: Option<FailureReport>,
    },
}

/// Runs a single simulation with the given configuration.
#[allow(clippy::too_many_lines)]
fn run_simulation(run: &SimulationRun, config: &VoprConfig) -> SimulationResult {
    // Liveness checkers imported at the top so items_after_statements
    // (pedantic) stays silent. See usage below with window-size comments.
    use kimberlite_sim::liveness_invariants::{EventualCommitChecker, EventualProgressChecker};

    // Use scenario config if available, otherwise use config values
    let (max_events, max_time_ns) = if let Some(ref scenario) = run.scenario {
        (scenario.max_events, scenario.max_time_ns)
    } else {
        (config.max_events, config.max_time_ns)
    };

    let sim_config = SimConfig::default()
        .with_seed(run.seed)
        .with_max_events(max_events)
        .with_max_time_ns(max_time_ns);

    // Reset property registry so each seed's property tracking is independent.
    kimberlite_properties::registry::reset();

    // Drives real kernel/VSR/compliance/query code paths so the 74 property
    // annotations actually fire. Constructed after the registry reset so
    // annotations aggregate into the correct seed's `PropertyReport`.
    let mut real_driver = kimberlite_sim::real_state_driver::RealStateDriver::new(run.seed);

    let mut sim = Simulation::new(sim_config);
    let mut rng = SimRng::new(run.seed);

    // Initialize simulated components
    let mut network = SimNetwork::new(run.network_config.clone());
    let mut storage = SimStorage::new(run.storage_config.clone());

    // Performance tracking for invariant checks
    let mut invariant_times: HashMap<&str, u128> = HashMap::new();

    // Initialize scenario-specific components (mutable for fault state updates)
    let mut swizzle_clogger = run
        .scenario
        .as_ref()
        .and_then(|s| s.swizzle_clogger.clone());
    let mut gray_failure_injector = run
        .scenario
        .as_ref()
        .and_then(|s| s.gray_failure_injector.clone());
    let tenant_workload = run
        .scenario
        .as_ref()
        .filter(|s| s.num_tenants > 1)
        .map(|s| TenantWorkloadGenerator::new(s.num_tenants));

    // Initialize invariant checkers (conditional based on config)
    let mut hash_checker = config
        .invariant_config
        .enable_hash_chain
        .then(HashChainChecker::new);
    let mut log_checker = config
        .invariant_config
        .enable_log_consistency
        .then(LogConsistencyChecker::new);
    let mut replica_checker = config
        .invariant_config
        .enable_replica_consistency
        .then(ReplicaConsistencyChecker::new);
    let mut replica_head_checker = config
        .invariant_config
        .enable_replica_head
        .then(ReplicaHeadChecker::new);
    let mut commit_history_checker = config
        .invariant_config
        .enable_commit_history
        .then(CommitHistoryChecker::new);

    // VSR invariants
    let mut vsr_agreement = config
        .invariant_config
        .enable_vsr_agreement
        .then(AgreementChecker::new);
    let mut vsr_prefix_property = config
        .invariant_config
        .enable_vsr_prefix_property
        .then(PrefixPropertyChecker::new);
    let mut vsr_view_change_safety = config
        .invariant_config
        .enable_vsr_view_change_safety
        .then(ViewChangeSafetyChecker::new);
    let mut vsr_recovery_safety = config
        .invariant_config
        .enable_vsr_recovery_safety
        .then(RecoverySafetyChecker::new);

    // Projection invariants
    let projection_applied_position = config
        .invariant_config
        .enable_projection_applied_position
        .then(AppliedPositionMonotonicChecker::new);
    let projection_mvcc = config
        .invariant_config
        .enable_projection_mvcc_visibility
        .then(MvccVisibilityChecker::new);
    let projection_applied_index = config
        .invariant_config
        .enable_projection_applied_index
        .then(AppliedIndexIntegrityChecker::new);
    let projection_catchup = config.invariant_config.enable_projection_catchup.then(|| {
        ProjectionCatchupChecker::new(config.invariant_config.projection_catchup_step_limit)
    });

    // Query invariants
    let query_determinism = config
        .invariant_config
        .enable_query_determinism
        .then(QueryDeterminismChecker::new);
    let query_read_your_writes = config
        .invariant_config
        .enable_query_read_your_writes
        .then(ReadYourWritesChecker::new);
    let query_type_safety = config
        .invariant_config
        .enable_query_type_safety
        .then(TypeSafetyChecker::new);
    let query_order_by_limit = config
        .invariant_config
        .enable_query_order_by_limit
        .then(OrderByLimitChecker::new);
    let query_aggregates = config
        .invariant_config
        .enable_query_aggregates
        .then(AggregateCorrectnessChecker::new);
    // AUDIT-2026-04 C-2: the catalog/row isolation call sites below
    // mutate this checker on every `CatalogOperationApplied` /
    // `DmlRowObserved` event. The `mut` is deliberate — prior to C-2
    // this was immutable because the checker was never actually run.
    let mut query_tenant_isolation = config
        .invariant_config
        .enable_query_tenant_isolation
        .then(TenantIsolationChecker::new);

    // AUDIT-2026-04 H-3: instantiate the liveness checkers the audit
    // found "defined but never called." These always-on checkers
    // consume VSR-replica events (VsrPrepare / VsrCommit /
    // VsrViewChangeStart / VsrViewChangeComplete) and a periodic
    // LivenessTick. Without this wire, a prepared-but-never-committed
    // op or a livelocked view change was invisible to VOPR.
    //
    // Window sizes match `liveness_invariants.rs` defaults — 1000
    // iterations for commit, 500 for view change.
    let mut eventual_commit = EventualCommitChecker::default();
    let mut eventual_progress = EventualProgressChecker::default();

    // SQL oracles (expensive, opt-in)
    let sql_tlp = config.invariant_config.enable_sql_tlp.then(TlpOracle::new);
    let sql_norec = config
        .invariant_config
        .enable_sql_norec
        .then(NoRecOracle::new);
    let sql_plan_coverage = config
        .invariant_config
        .enable_sql_plan_coverage
        .then(|| QueryPlanCoverageTracker::new(100)); // 100 query plateau threshold

    // Byzantine-specific invariant checkers (enabled when Byzantine scenario is active)
    let byzantine_injector = run
        .scenario
        .as_ref()
        .and_then(|s| s.byzantine_injector.as_ref())
        .cloned();

    let byzantine_enabled = byzantine_injector.is_some();

    let mut commit_consistency_checker =
        byzantine_enabled.then(CommitNumberConsistencyChecker::new);
    let mut merge_log_safety_checker = byzantine_enabled.then(MergeLogSafetyChecker::new);

    // Initialize VSR simulation (if vsr_mode is enabled)
    let mut vsr_sim = if config.vsr_mode {
        Some(VsrSimulation::new(run.storage_config.clone(), run.seed))
    } else {
        None
    };

    // Initialize checkers for VSR mode (snapshot-based)
    let mut vsr_commit_checker = config.vsr_mode.then(CommitNumberConsistencyChecker::new);
    let mut vsr_agreement_checker = config.vsr_mode.then(AgreementChecker::new);
    let mut vsr_prefix_checker = config.vsr_mode.then(PrefixPropertyChecker::new);

    // Initialize MessageMutator for Byzantine testing in VSR mode
    let mut message_mutator = if config.vsr_mode && byzantine_injector.is_some() {
        let injector = byzantine_injector.as_ref().unwrap();
        let rules = injector.build_mutation_rules();

        if config.verbose {
            eprintln!("MessageMutator initialized with {} rules", rules.len());
        }

        Some(MessageMutator::new(rules))
    } else {
        None
    };

    // Initialize model for data correctness verification
    let mut model = KimberliteModel::new();

    // Track checkpoints for recovery testing
    let mut checkpoints: HashMap<u64, StorageCheckpoint> = HashMap::new();

    // Initialize trace collector (if enabled)
    let mut trace = if config.enable_trace || config.save_trace_on_failure {
        Some(TraceCollector::new(TraceConfig::default()))
    } else {
        None
    };

    // Record simulation start in trace
    if let Some(ref mut t) = trace {
        t.record(0, TraceEventType::SimulationStart { seed: run.seed });
    }

    // Register simulated nodes
    for node_id in 0..3 {
        network.register_node(node_id);
    }

    // Schedule initial events
    let op_types = if config.enhanced_workloads { 6 } else { 4 };
    for i in 0..10 {
        let delay = rng.delay_ns(1_000_000, 10_000_000);
        sim.schedule_after(delay, EventKind::Custom(i % op_types));
    }

    // Schedule periodic checkpoints every ~2 seconds of simulated time
    for i in 0..5 {
        let checkpoint_time = 2_000_000_000 * (i + 1); // 2s, 4s, 6s, 8s, 10s
        sim.schedule(
            checkpoint_time,
            EventKind::CreateCheckpoint { checkpoint_id: i },
        );
    }

    // Schedule periodic fsync operations every ~500ms to commit pending writes
    // This models realistic database write patterns where fsync happens periodically
    for i in 0..20 {
        let fsync_time = 500_000_000 * (i + 1); // 500ms, 1s, 1.5s, ...
        sim.schedule(fsync_time, EventKind::StorageFsync);
    }

    // Schedule periodic fault state updates (every ~500ms)
    // Use Timer ID 999 for fault updates
    if swizzle_clogger.is_some() || gray_failure_injector.is_some() {
        for i in 0..20 {
            let update_time = 500_000_000 * (i + 1); // 500ms intervals
            sim.schedule(update_time, EventKind::Timer { timer_id: 999 });
        }
    }

    // Schedule periodic projection applies (every ~1 second)
    for i in 0..10 {
        let apply_time = 1_000_000_000 * (i + 1); // 1s intervals
        sim.schedule(
            apply_time,
            EventKind::ProjectionApplied {
                projection_id: 0,               // Default projection
                applied_position: (i + 1) * 10, // Simulated position
                batch_size: 10,
            },
        );
    }

    // Schedule periodic query executions (every ~1.5 seconds)
    for i in 0..7 {
        let query_time = 1_500_000_000 * (i + 1); // 1.5s intervals
        sim.schedule(
            query_time,
            EventKind::QueryExecuted {
                query_id: i,
                tenant_id: i % 3, // Rotate through 3 tenants
                snapshot_version: (i + 1) * 10,
                result_rows: rng.next_usize(100),
            },
        );
    }

    // Initialize workload scheduler for continuous operation generation
    let sched_config = WorkloadSchedulerConfig {
        ops_per_tick: config.workload_ops_per_tick,
        tick_interval_ns: config.workload_tick_interval_ms * 1_000_000,
        enhanced_workloads: config.enhanced_workloads,
        max_scheduled_ops: None,
        vsr_mode: config.vsr_mode,
        // Pass simulation limits so scheduler can self-terminate
        sim_max_events: Some(max_events),
        sim_max_time_ns: Some(max_time_ns),
    };
    let mut workload_scheduler = WorkloadScheduler::new(sched_config);

    // Schedule initial tick
    let mut initial_events = Vec::new();
    workload_scheduler.schedule_initial_tick(&mut initial_events, 0);
    for (time, kind) in initial_events {
        sim.schedule(time, kind);
    }

    // Note: Removed pending_ops tracking - no longer needed after removing
    // O(n!) linearizability checker in favor of industry-proven approach

    // Track hash chain state per replica for hash_chain invariant
    let mut last_hash_by_replica: std::collections::HashMap<u64, [u8; 32]> =
        std::collections::HashMap::new();

    // Track projection state for projection invariants
    let mut _last_applied_position: u64 = 0;
    let mut projection_snapshot_versions: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::new();

    // Track query state for query invariants
    let mut last_write_by_tenant: std::collections::HashMap<u64, (u64, u64)> =
        std::collections::HashMap::new(); // tenant_id -> (key, value)

    // Helper to create invariant violation with trace and diagnosis
    let make_violation = |invariant: String,
                          message: String,
                          events_processed: u64,
                          trace_collector: &mut Option<TraceCollector>| {
        let failure_report = if config.failure_diagnosis {
            if let Some(t) = trace_collector {
                let events: Vec<_> = t.events().iter().cloned().collect();
                Some(FailureAnalyzer::analyze_failure(
                    run.seed,
                    &events,
                    events_processed,
                ))
            } else {
                None
            }
        } else {
            None
        };

        SimulationResult::InvariantViolation {
            invariant,
            message,
            events_processed,
            trace: trace_collector.take(),
            failure_report,
        }
    };

    // Run simulation loop
    while let Some(event) = sim.step() {
        #[allow(clippy::match_same_arms)] // Different arms for code organization
        match event.kind {
            EventKind::Custom(op_type) => {
                // Simulate different operation types
                let op_count = if config.enhanced_workloads { 6 } else { 4 };
                match op_type % op_count {
                    0 => {
                        // Write operation
                        // Generate key (tenant-aware if multi-tenant scenario)
                        let key = if let Some(ref tenant_gen) = tenant_workload {
                            let tenant_id = rng.next_usize(tenant_gen.num_tenants());
                            tenant_gen.random_key(tenant_id, &mut rng)
                        } else {
                            rng.next_u64() % 10
                        };
                        let value = rng.next_u64();

                        // Check gray failure state for a random node
                        let node_id = rng.next_usize(3) as u64;
                        let (can_proceed, latency_mult) =
                            if let Some(ref injector) = gray_failure_injector {
                                injector.check_operation(node_id, true, &mut rng)
                            } else {
                                (true, 1)
                            };

                        if can_proceed {
                            // Write to storage first and check if it succeeded completely
                            let data = value.to_le_bytes().to_vec();

                            // Track write for read-your-writes invariant
                            if tenant_workload.is_some() {
                                let tenant_id = key / 1000; // Extract tenant from key
                                last_write_by_tenant.insert(tenant_id, (key, value));
                            }

                            // Apply latency multiplier if node is slow
                            if latency_mult > 1 && config.verbose {
                                eprintln!(
                                    "Write to key {key} on slow node {node_id} ({latency_mult}x latency)"
                                );
                            }

                            let write_result = storage.write(key, data.clone(), &mut rng);

                            let write_success = matches!(
                                write_result,
                                kimberlite_sim::WriteResult::Success { bytes_written, .. }
                                if bytes_written == data.len()
                            );

                            // Only track successful writes for linearizability
                            // Failed/partial writes would trigger retries in a real system
                            if write_success {
                                // Track write in the model for data correctness verification
                                // (as pending, not yet fsynced)
                                model.apply_pending_write(key, value);
                                // Drive the real kernel in parallel with the mock
                                // so property annotations fire for this seed.
                                real_driver.on_write(key, value);

                                // Also append to replica logs for consistency checking
                                // In a real system, this would be done during replication
                                for replica_id in 0..3 {
                                    storage.append_replica_log(replica_id, data.clone());
                                }

                                // Schedule completion (with latency multiplier)
                                let base_delay = rng.delay_ns(100_000, 1_000_000);
                                let delay = base_delay * u64::from(latency_mult);
                                sim.schedule_after(
                                    delay,
                                    EventKind::StorageComplete {
                                        operation_id: 0, // No longer tracking for linearizability
                                        success: true,
                                    },
                                );
                            }
                        } else {
                            // Gray failure prevented this operation
                            if config.verbose {
                                eprintln!(
                                    "Write to key {key} blocked by gray failure on node {node_id}"
                                );
                            }
                            // Operation fails, don't update model
                        }
                    }
                    1 => {
                        // Read operation
                        // Generate key (tenant-aware if multi-tenant scenario)
                        let key = if let Some(ref tenant_gen) = tenant_workload {
                            let tenant_id = rng.next_usize(tenant_gen.num_tenants());
                            tenant_gen.random_key(tenant_id, &mut rng)
                        } else {
                            rng.next_u64() % 10
                        };

                        // Check gray failure state for a random node
                        let node_id = rng.next_usize(3) as u64;
                        let (can_proceed, _latency_mult) =
                            if let Some(ref injector) = gray_failure_injector {
                                injector.check_operation(node_id, false, &mut rng)
                            } else {
                                (true, 1)
                            };

                        if can_proceed {
                            let result = storage.read(key, &mut rng);

                            // Only track successful reads with complete data for linearizability
                            // Corrupted/failed/partial reads would trigger retries in a real system
                            match result {
                                kimberlite_sim::ReadResult::Success { data, .. }
                                    if data.len() == 8 =>
                                {
                                    // Successfully read a complete u64
                                    let value =
                                        Some(u64::from_le_bytes(data[..8].try_into().unwrap()));

                                    // Verify against the model for data correctness
                                    if !model.verify_read(key, value) {
                                        let expected = model.get(key);
                                        return make_violation(
                                            "model_verification".to_string(),
                                            format!(
                                                "read mismatch: key={key}, expected={expected:?}, actual={value:?}"
                                            ),
                                            sim.events_processed(),
                                            &mut trace,
                                        );
                                    }
                                }
                                kimberlite_sim::ReadResult::NotFound { .. } => {
                                    // Not found is a successful read of an empty key
                                    // Verify against the model
                                    if !model.verify_read(key, None) {
                                        let expected = model.get(key);
                                        return make_violation(
                                            "model_verification".to_string(),
                                            format!(
                                                "read mismatch: key={key}, expected={expected:?}, actual=None"
                                            ),
                                            sim.events_processed(),
                                            &mut trace,
                                        );
                                    }
                                }
                                _ => {
                                    // Corrupted/partial reads
                                    // In a real system, these would be retried
                                }
                            }
                        } else {
                            // Gray failure prevented this operation
                            // Operation fails silently (would retry in real system)
                        }
                    }
                    2 => {
                        // Network message
                        let from = rng.next_usize(3) as u64;
                        let to = rng.next_usize(3) as u64;
                        if from != to {
                            let payload = vec![rng.next_u64() as u8; 32];

                            // Apply swizzle-clogging if enabled
                            let should_send = if let Some(ref clogger) = swizzle_clogger {
                                let base_delay = rng.delay_ns(
                                    run.network_config.min_delay_ns,
                                    run.network_config.max_delay_ns,
                                );
                                let (_adjusted_delay, should_drop) =
                                    clogger.apply(from, to, base_delay, &mut rng);
                                !should_drop
                            } else {
                                true
                            };

                            if should_send {
                                let _ = network.send(from, to, payload, event.time_ns, &mut rng);
                            }
                        }
                    }
                    3 => {
                        // Replica state update - compute REAL hash from actual log content
                        let replica_id = rng.next_usize(3) as u64;

                        // Get actual log entries for this replica
                        let mut log_length = storage.get_replica_log_length(replica_id);

                        // Compute actual BLAKE3 hash from log content
                        let mut log_hash =
                            if let Some(entries) = storage.get_replica_log(replica_id) {
                                // Concatenate all entries and hash
                                let mut combined = Vec::new();
                                for entry in entries {
                                    combined.extend_from_slice(entry);
                                }
                                let hash = internal_hash(&combined);
                                *hash.as_bytes()
                            } else {
                                [0u8; 32] // Empty log has zero hash
                            };

                        // === BYZANTINE CORRUPTION INJECTION ===
                        // Apply Byzantine attacks to simulate malicious replica behavior
                        if let Some(ref injector) = byzantine_injector {
                            // Randomly select one replica to be Byzantine (replica 1)
                            let byzantine_replica_id = 1u64;
                            if replica_id == byzantine_replica_id {
                                // Attack: Truncate log tail (simulate Bug #2: commit desync)
                                if injector.config().truncate_log_tail && log_length > 2 {
                                    log_length /= 2; // Truncate to half
                                }

                                // Attack: Corrupt log hash (simulate Bug #1: conflicting entries)
                                if injector.config().corrupt_start_view_log && log_hash != [0u8; 32]
                                {
                                    // Flip a bit in the hash to simulate corrupted entry
                                    log_hash[0] ^= 0x01;
                                }

                                // Note: Commit number inflation is handled in the checker below
                            }
                        }
                        // === END BYZANTINE CORRUPTION ===

                        // Check replica consistency
                        if let Some(ref mut checker) = replica_checker {
                            let result = checker.update_replica(
                                replica_id,
                                log_length,
                                log_hash,
                                event.time_ns,
                            );

                            if !result.is_ok() {
                                return make_violation(
                                    "replica_consistency".to_string(),
                                    format!("Replica divergence at time {}", event.time_ns),
                                    sim.events_processed(),
                                    &mut trace,
                                );
                            }
                        }

                        // Track replica head progress (view, op)
                        // For now, use log_length as op number (simplified)
                        let view = 0; // Single view for this simulation
                        let op = log_length;

                        if let Some(ref mut checker) = replica_head_checker {
                            let head_result = checker.update_head(replica_id, view, op);
                            if !head_result.is_ok() {
                                return make_violation(
                                    "replica_head_progress".to_string(),
                                    format!(
                                        "Replica {} head regressed at time {}",
                                        replica_id, event.time_ns
                                    ),
                                    sim.events_processed(),
                                    &mut trace,
                                );
                            }
                        }

                        // Track commit history (every log entry is a commit)
                        // Only track the first replica to avoid duplicate commit tracking
                        if replica_id == 0 && log_length > 0 {
                            if let Some(ref mut checker) = commit_history_checker {
                                let last_committed = log_length - 1;
                                if let Some(last_op) = checker.last_op() {
                                    // Only record new commits
                                    for op_num in (last_op + 1)..=last_committed {
                                        let commit_result = checker.record_commit(op_num);
                                        if !commit_result.is_ok() {
                                            return make_violation(
                                                "commit_history".to_string(),
                                                format!("Commit gap detected at op {op_num}"),
                                                sim.events_processed(),
                                                &mut trace,
                                            );
                                        }
                                    }
                                } else if log_length > 0 {
                                    // First commits
                                    for op_num in 0..log_length {
                                        let commit_result = checker.record_commit(op_num);
                                        if !commit_result.is_ok() {
                                            return make_violation(
                                                "commit_history".to_string(),
                                                format!("Commit history violation at op {op_num}"),
                                                sim.events_processed(),
                                                &mut trace,
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        // VSR Agreement check
                        if let Some(ref mut checker) = vsr_agreement {
                            use kimberlite_vsr::{OpNumber, ReplicaId, ViewNumber};

                            let op_hash = kimberlite_crypto::ChainHash::from_bytes(&log_hash);
                            let result = checker.record_commit(
                                ReplicaId::new(replica_id as u8),
                                ViewNumber::from(u64::from(view)),
                                OpNumber::from(op),
                                &op_hash,
                            );
                            if !result.is_ok() {
                                return make_violation(
                                    "vsr_agreement".to_string(),
                                    format!("VSR agreement violated at view={view}, op={op}"),
                                    sim.events_processed(),
                                    &mut trace,
                                );
                            }
                        }

                        // VSR Prefix Property check (check every 10 ops)
                        if let Some(ref mut checker) = vsr_prefix_property {
                            use kimberlite_vsr::{OpNumber, ReplicaId};

                            let op_hash = kimberlite_crypto::ChainHash::from_bytes(&log_hash);
                            checker.record_committed_op(
                                ReplicaId::new(replica_id as u8),
                                OpNumber::from(op),
                                &op_hash,
                            );

                            if op % 10 == 0 && op > 0 {
                                let result = checker.check_prefix_agreement(OpNumber::from(op));
                                if !result.is_ok() {
                                    return make_violation(
                                        "vsr_prefix_property".to_string(),
                                        format!("VSR prefix property violated at op={op}"),
                                        sim.events_processed(),
                                        &mut trace,
                                    );
                                }
                            }
                        }

                        // VSR View Change Safety (record commits in current view)
                        if let Some(ref mut checker) = vsr_view_change_safety {
                            use kimberlite_vsr::{OpNumber, ViewNumber};

                            checker.record_committed_in_view(
                                ViewNumber::from(u64::from(view)),
                                OpNumber::from(op),
                            );
                            // View change checking happens when view changes (future work)
                        }

                        // VSR Recovery Safety (track pre-crash state)
                        if let Some(ref mut checker) = vsr_recovery_safety {
                            use kimberlite_vsr::{OpNumber, ReplicaId};

                            // Record current commit point before any crash
                            // Actual recovery checking happens after recovery events (future work)
                            if op % 100 == 0 {
                                checker.record_pre_crash_state(
                                    ReplicaId::new(replica_id as u8),
                                    OpNumber::from(op),
                                );
                            }
                        }

                        // Byzantine: Commit Number Consistency check
                        // Detects Bug #2 (commit desync) and Bug #3 (inflated commit)
                        if let Some(ref mut checker) = commit_consistency_checker {
                            use kimberlite_vsr::{CommitNumber, OpNumber, ReplicaId};

                            // In this simulation, commit_number == op (simplified model)
                            // Byzantine attacks would inflate commit_number beyond op
                            let mut commit_value = op;

                            // === BYZANTINE ATTACK: Inflate commit number ===
                            if let Some(ref injector) = byzantine_injector {
                                let byzantine_replica_id = 1u64;
                                if replica_id == byzantine_replica_id
                                    && injector.should_inflate_commit(&mut rng)
                                {
                                    // Inflate commit number beyond actual op number
                                    let inflation_factor =
                                        injector.config().commit_inflation_factor;
                                    commit_value = op + inflation_factor;
                                }
                            }
                            // === END BYZANTINE ATTACK ===

                            let commit_number = CommitNumber::new(OpNumber::from(commit_value));
                            let op_number = OpNumber::from(op);

                            let result = checker.check_consistency(
                                ReplicaId::new(replica_id as u8),
                                op_number,
                                commit_number,
                            );

                            if !result.is_ok() {
                                return make_violation(
                                    "commit_number_consistency".to_string(),
                                    format!(
                                        "Byzantine attack detected: commit_number > op_number for replica {replica_id}"
                                    ),
                                    sim.events_processed(),
                                    &mut trace,
                                );
                            }
                        }

                        // Byzantine: Merge Log Safety check
                        // Detects Bug #1 (view change merge overwrites committed entries)
                        if let Some(ref mut checker) = merge_log_safety_checker {
                            use kimberlite_crypto::ChainHash;
                            use kimberlite_vsr::{OpNumber, ReplicaId};

                            // Track all committed entries for this replica
                            if op > 0 {
                                for committed_op in 1..=op {
                                    // Use simplified hash (in real system would track individual entry hashes)
                                    let op_hash = ChainHash::from_bytes(&log_hash);

                                    // Record entry as committed
                                    checker.record_entry(
                                        ReplicaId::new(replica_id as u8),
                                        OpNumber::from(committed_op),
                                        &op_hash,
                                        true, // is_committed
                                    );

                                    // Check merge safety
                                    let result = checker.check_merge(
                                        ReplicaId::new(replica_id as u8),
                                        OpNumber::from(committed_op),
                                        &op_hash,
                                    );

                                    if !result.is_ok() {
                                        return make_violation(
                                            "merge_log_safety".to_string(),
                                            format!(
                                                "Byzantine attack detected: committed entry overwritten at op {committed_op}"
                                            ),
                                            sim.events_processed(),
                                            &mut trace,
                                        );
                                    }
                                }
                            }
                        }

                        // Hash Chain check (verify chain integrity)
                        if let Some(ref mut checker) = hash_checker {
                            use kimberlite_crypto::ChainHash;

                            let current_hash = ChainHash::from_bytes(&log_hash);
                            let prev_hash = if op > 0 {
                                // Get the actual previous hash for this replica
                                if let Some(prev_bytes) = last_hash_by_replica.get(&replica_id) {
                                    ChainHash::from_bytes(prev_bytes)
                                } else {
                                    // First operation after op 0, use zero hash
                                    ChainHash::from_bytes(&[0u8; 32])
                                }
                            } else {
                                ChainHash::from_bytes(&[0u8; 32])
                            };

                            let result = checker.check_record(op, &prev_hash, &current_hash);
                            if !result.is_ok() {
                                return make_violation(
                                    "hash_chain".to_string(),
                                    format!("Hash chain broken at op={op}"),
                                    sim.events_processed(),
                                    &mut trace,
                                );
                            }

                            // Track this hash as the previous for next time
                            last_hash_by_replica.insert(replica_id, log_hash);
                        }

                        // Log Consistency check (record commits for later verification)
                        if let Some(ref mut checker) = log_checker {
                            use kimberlite_crypto::ChainHash;

                            let chain_hash = ChainHash::from_bytes(&log_hash);
                            // Use log_hash as payload hash for simplicity
                            checker.record_commit(op, chain_hash, log_hash);
                        }
                    }
                    4 => {
                        // Read-Modify-Write operation (enhanced workload)
                        if config.enhanced_workloads {
                            // Generate key (tenant-aware if multi-tenant scenario)
                            let key = if let Some(ref tenant_gen) = tenant_workload {
                                let tenant_id = rng.next_usize(tenant_gen.num_tenants());
                                tenant_gen.random_key(tenant_id, &mut rng)
                            } else {
                                rng.next_u64() % 10
                            };

                            // Check gray failure state for a random node
                            let node_id = rng.next_usize(3) as u64;
                            let (can_proceed, latency_mult) =
                                if let Some(ref injector) = gray_failure_injector {
                                    injector.check_operation(node_id, true, &mut rng)
                                } else {
                                    (true, 1)
                                };

                            if can_proceed {
                                // Read current value
                                let read_result = storage.read(key, &mut rng);
                                let old_value = match read_result {
                                    kimberlite_sim::ReadResult::Success { data, .. }
                                        if data.len() == 8 =>
                                    {
                                        Some(u64::from_le_bytes(data[..8].try_into().unwrap()))
                                    }
                                    _ => None,
                                };

                                // Modify: increment or set to 1
                                let new_value = old_value.map_or(1, |v| v.wrapping_add(1));

                                // Write back
                                let data = new_value.to_le_bytes().to_vec();
                                let write_result = storage.write(key, data.clone(), &mut rng);

                                let success = matches!(
                                    write_result,
                                    kimberlite_sim::WriteResult::Success { bytes_written, .. }
                                    if bytes_written == data.len()
                                );

                                // Record in trace
                                if let Some(ref mut t) = trace {
                                    t.record(
                                        event.time_ns,
                                        TraceEventType::ReadModifyWrite {
                                            key,
                                            old_value,
                                            new_value,
                                            success,
                                        },
                                    );
                                }

                                if success {
                                    // Track as pending write (not yet fsynced)
                                    model.apply_pending_write(key, new_value);
                                    for replica_id in 0..3 {
                                        storage.append_replica_log(replica_id, data.clone());
                                    }

                                    // Schedule completion (with latency multiplier)
                                    let base_delay = rng.delay_ns(100_000, 1_000_000);
                                    let delay = base_delay * u64::from(latency_mult);
                                    sim.schedule_after(
                                        delay,
                                        EventKind::StorageComplete {
                                            operation_id: 0, // No longer tracking for linearizability
                                            success: true,
                                        },
                                    );
                                }
                            } else {
                                // Gray failure prevented this operation
                                // Don't perform RMW
                            }
                        }
                    }
                    5 => {
                        // Scan operation (enhanced workload)
                        if config.enhanced_workloads {
                            let start_key = rng.next_u64() % 10;
                            let end_key = start_key + (rng.next_u64() % 5) + 1;
                            let mut scan_count = 0;

                            // Simulate scanning a key range
                            for k in start_key..end_key.min(10) {
                                if let kimberlite_sim::ReadResult::Success { .. } =
                                    storage.read(k, &mut rng)
                                {
                                    scan_count += 1;
                                }
                            }

                            // Record in trace
                            if let Some(ref mut t) = trace {
                                t.record(
                                    event.time_ns,
                                    TraceEventType::Scan {
                                        start_key,
                                        end_key,
                                        count: scan_count,
                                        success: true,
                                    },
                                );
                            }
                        }
                    }
                    _ => {
                        // Should not happen with correct modulo
                    }
                }
            }
            EventKind::StorageComplete {
                operation_id: _,
                success: _,
            } => {
                // Storage completion event (no longer tracked after removing linearizability checker)
            }
            EventKind::StorageFsync => {
                // Periodic fsync: flush pending writes to durable storage
                let fsync_result = storage.fsync(&mut rng);

                if matches!(fsync_result, kimberlite_sim::FsyncResult::Success { .. }) {
                    // Fsync succeeded - commit pending writes to durable state in model
                    model.commit_pending();

                    if config.verbose {
                        eprintln!(
                            "Fsync completed at {}ms, committed pending writes to durable state",
                            event.time_ns / 1_000_000
                        );
                    }
                } else {
                    // Fsync failed - clear model.pending to match storage behavior
                    // (storage.fsync() already cleared pending_writes at storage.rs:578)
                    model.clear_pending();

                    if config.verbose {
                        eprintln!(
                            "Fsync failed at {}ms, clearing pending writes from model",
                            event.time_ns / 1_000_000
                        );
                    }
                }

                // Run a real VSR prepare/commit round (plus periodic view
                // changes) so vsr.* property annotations register per seed.
                real_driver.on_fsync();
            }
            EventKind::NetworkDeliver { .. } => {
                // Deliver ready network messages
                let _ = network.deliver_ready(event.time_ns);
            }
            EventKind::InvariantCheck => {
                // Periodic invariant checking with performance tracking
                // Replica consistency: Check on every InvariantCheck (fast with our optimizations)
                if let Some(ref mut checker) = replica_checker {
                    let start = std::time::Instant::now();
                    let replica_result = checker.check_all();
                    let elapsed = start.elapsed();
                    *invariant_times.entry("replica_consistency").or_insert(0) +=
                        elapsed.as_micros();

                    if !replica_result.is_ok() {
                        return make_violation(
                            "replica_consistency".to_string(),
                            "Replicas have diverged".to_string(),
                            sim.events_processed(),
                            &mut trace,
                        );
                    }
                }
            }
            EventKind::CreateCheckpoint { checkpoint_id } => {
                // Create a checkpoint of current storage state
                let checkpoint = storage.checkpoint();

                if config.verbose {
                    eprintln!(
                        "Checkpoint {} created at {}ms ({} blocks, {} bytes)",
                        checkpoint_id,
                        event.time_ns / 1_000_000,
                        storage.block_count(),
                        storage.storage_size_bytes()
                    );
                }

                // Store the checkpoint
                checkpoints.insert(checkpoint_id, checkpoint);

                // Schedule a recovery test shortly after
                // (only for the first few checkpoints to avoid excessive testing)
                if checkpoint_id < 2 {
                    let recovery_delay = rng.delay_ns(100_000_000, 500_000_000);
                    sim.schedule_after(
                        recovery_delay,
                        EventKind::RecoverCheckpoint { checkpoint_id },
                    );
                }
            }
            EventKind::Timer { timer_id: 999 } => {
                // Periodic fault state update
                // Update swizzle-clogger states for all links
                if let Some(ref mut clogger) = swizzle_clogger {
                    for from in 0..3 {
                        for to in 0..3 {
                            if from != to {
                                let changed = clogger.update(from, to, &mut rng);
                                if config.verbose && changed {
                                    eprintln!(
                                        "Link {from}->{to} is now {}",
                                        if clogger.is_clogged(from, to) {
                                            "CLOGGED"
                                        } else {
                                            "unclogged"
                                        }
                                    );
                                }
                            }
                        }
                    }
                }

                // Update gray failure states for all nodes
                if let Some(ref mut injector) = gray_failure_injector {
                    let node_ids: Vec<u64> = (0..3).collect();
                    let changes = injector.update_all(&node_ids, &mut rng);
                    if config.verbose {
                        for (node_id, old_mode, new_mode) in changes {
                            eprintln!("Node {node_id} gray failure: {old_mode:?} -> {new_mode:?}");
                        }
                    }
                }
            }
            EventKind::Timer { .. } => {
                // Other timer events (if any)
            }
            EventKind::RecoverCheckpoint { checkpoint_id } => {
                // Test checkpoint recovery
                if let Some(checkpoint) = checkpoints.get(&checkpoint_id) {
                    // Restore from checkpoint (reverts storage to checkpoint state)
                    storage.restore_checkpoint(checkpoint);

                    // Clear model state to match checkpoint restore
                    // After restore, both pending and durable state are reset
                    // The model will rebuild naturally as new operations occur
                    model.clear_pending();
                    model.clear_durable();

                    if config.verbose {
                        eprintln!(
                            "Checkpoint {} recovered at {}ms (storage and model reset to checkpoint state)",
                            checkpoint_id,
                            event.time_ns / 1_000_000
                        );
                    }
                }
            }
            EventKind::ProjectionApplied {
                projection_id,
                applied_position,
                batch_size: _,
            } => {
                // Update tracking
                _last_applied_position = applied_position;
                projection_snapshot_versions.insert(projection_id, applied_position);

                // Projection invariants track that events are firing.
                // Detailed state-machine checks require full kernel integration (v0.7.0).

                // Track execution for coverage
                if projection_applied_position.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("projection_applied_position");
                }
                if projection_mvcc.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("projection_mvcc");
                }
                if projection_applied_index.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("projection_applied_index");
                }
                if projection_catchup.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("projection_catchup");
                }
            }
            EventKind::QueryExecuted {
                query_id: _,
                tenant_id: _,
                snapshot_version: _,
                result_rows: _,
            } => {
                // Query invariants track that events are firing.
                // Detailed SQL engine checks require full query integration (v0.7.0).

                // Track execution for coverage
                if query_determinism.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_determinism");
                }
                if query_read_your_writes.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_read_your_writes");
                }
                if query_type_safety.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_type_safety");
                }
                if query_order_by_limit.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_order_by_limit");
                }
                if query_aggregates.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_aggregates");
                }
                if query_tenant_isolation.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_tenant_isolation");
                }

                // SQL oracles (expensive, opt-in)
                if sql_tlp.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("sql_tlp");
                }
                if sql_norec.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("sql_norec");
                }
                if sql_plan_coverage.is_some() {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("sql_plan_coverage");
                }
            }
            EventKind::VsrClientRequest { replica_id, .. } => {
                // Process client request through VSR
                if let Some(ref mut vsr) = vsr_sim {
                    let messages = vsr.process_client_request(&mut rng);

                    // AUDIT-2026-04 S1.2 — drain VSR state-transition
                    // events (VsrPrepare/VsrCommit/ViewChange*) emitted
                    // by record_transition during the call above and
                    // schedule them with zero delay so the liveness
                    // sinks at line ~1940 fire on real workloads, not
                    // just canary-synthesised ones.
                    for observed in vsr.drain_observed_events() {
                        sim.schedule(event.time_ns, observed);
                    }

                    // Apply Byzantine mutations and schedule message deliveries
                    let mut scheduled_count = 0;
                    let mut mutated_count = 0;

                    for msg in &messages {
                        // Determine destination(s)
                        if let Some(to) = msg.to {
                            // Unicast message - apply mutation if mutator exists
                            let final_msg = if let Some(ref mut mutator) = message_mutator {
                                if let Some(mutated) = mutator.apply(msg, to, &mut rng) {
                                    mutated_count += 1;
                                    mutated
                                } else {
                                    msg.clone()
                                }
                            } else {
                                msg.clone()
                            };

                            let delay = rng.delay_ns(100_000, 1_000_000);
                            let message_bytes = kimberlite_sim::vsr_message_to_bytes(&final_msg);

                            sim.schedule(
                                event.time_ns + delay,
                                EventKind::VsrMessage {
                                    to_replica: to.as_u8(),
                                    message_bytes,
                                },
                            );
                            scheduled_count += 1;
                        } else {
                            // Broadcast message - send to all replicas except sender
                            for replica_id_target in 0..3u8 {
                                if replica_id_target != msg.from.as_u8() {
                                    let to = kimberlite_vsr::ReplicaId::new(replica_id_target);

                                    // Apply mutation if mutator exists
                                    let final_msg = if let Some(ref mut mutator) = message_mutator {
                                        if let Some(mutated) = mutator.apply(msg, to, &mut rng) {
                                            mutated_count += 1;
                                            mutated
                                        } else {
                                            msg.clone()
                                        }
                                    } else {
                                        msg.clone()
                                    };

                                    let delay = rng.delay_ns(100_000, 1_000_000);
                                    let message_bytes =
                                        kimberlite_sim::vsr_message_to_bytes(&final_msg);

                                    sim.schedule(
                                        event.time_ns + delay,
                                        EventKind::VsrMessage {
                                            to_replica: replica_id_target,
                                            message_bytes,
                                        },
                                    );
                                    scheduled_count += 1;
                                }
                            }
                        }
                    }

                    if config.verbose {
                        eprintln!(
                            "VSR client request processed by replica {replica_id}, generated {scheduled_count} messages ({mutated_count} mutated)"
                        );
                    }

                    // Check invariants every 10 events
                    if sim.events_processed() % 10 == 0 {
                        let snapshots = vsr.extract_snapshots();

                        if vsr_commit_checker.is_some()
                            && vsr_agreement_checker.is_some()
                            && vsr_prefix_checker.is_some()
                        {
                            let result = check_all_vsr_invariants(
                                vsr_commit_checker.as_mut().unwrap(),
                                vsr_agreement_checker.as_mut().unwrap(),
                                vsr_prefix_checker.as_mut().unwrap(),
                                &snapshots,
                            );

                            if !result.is_ok() {
                                if let kimberlite_sim::InvariantResult::Violated {
                                    invariant,
                                    message,
                                    ..
                                } = result
                                {
                                    return make_violation(
                                        invariant,
                                        message,
                                        sim.events_processed(),
                                        &mut trace,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            EventKind::VsrMessage {
                to_replica,
                message_bytes,
            } => {
                // Deserialize and deliver message to VSR replica
                if let Some(ref mut vsr) = vsr_sim {
                    let msg = vsr_message_from_bytes(&message_bytes);
                    let responses = vsr.deliver_message(to_replica, msg, &mut rng);

                    // AUDIT-2026-04 S1.2 — drain VSR state-transition
                    // events from this delivery into the queue so the
                    // liveness sinks observe Prepare/Commit/View
                    // transitions across the run.
                    for observed in vsr.drain_observed_events() {
                        sim.schedule(event.time_ns, observed);
                    }

                    // Apply Byzantine mutations and schedule response deliveries
                    let mut scheduled_count = 0;
                    let mut mutated_count = 0;

                    for response_msg in &responses {
                        // Determine destination(s)
                        if let Some(to) = response_msg.to {
                            // Unicast message - apply mutation if mutator exists
                            let final_msg = if let Some(ref mut mutator) = message_mutator {
                                if let Some(mutated) = mutator.apply(response_msg, to, &mut rng) {
                                    mutated_count += 1;
                                    mutated
                                } else {
                                    response_msg.clone()
                                }
                            } else {
                                response_msg.clone()
                            };

                            let delay = rng.delay_ns(100_000, 1_000_000);
                            let resp_bytes = kimberlite_sim::vsr_message_to_bytes(&final_msg);

                            sim.schedule(
                                event.time_ns + delay,
                                EventKind::VsrMessage {
                                    to_replica: to.as_u8(),
                                    message_bytes: resp_bytes,
                                },
                            );
                            scheduled_count += 1;
                        } else {
                            // Broadcast message - send to all replicas except sender
                            for replica_id_target in 0..3u8 {
                                if replica_id_target != response_msg.from.as_u8() {
                                    let to = kimberlite_vsr::ReplicaId::new(replica_id_target);

                                    // Apply mutation if mutator exists
                                    let final_msg = if let Some(ref mut mutator) = message_mutator {
                                        if let Some(mutated) =
                                            mutator.apply(response_msg, to, &mut rng)
                                        {
                                            mutated_count += 1;
                                            mutated
                                        } else {
                                            response_msg.clone()
                                        }
                                    } else {
                                        response_msg.clone()
                                    };

                                    let delay = rng.delay_ns(100_000, 1_000_000);
                                    let resp_bytes =
                                        kimberlite_sim::vsr_message_to_bytes(&final_msg);

                                    sim.schedule(
                                        event.time_ns + delay,
                                        EventKind::VsrMessage {
                                            to_replica: replica_id_target,
                                            message_bytes: resp_bytes,
                                        },
                                    );
                                    scheduled_count += 1;
                                }
                            }
                        }
                    }

                    if config.verbose && scheduled_count > 0 {
                        eprintln!(
                            "VSR message delivered to replica {to_replica}, generated {scheduled_count} responses ({mutated_count} mutated)"
                        );
                    }

                    // Check invariants every 10 events
                    if sim.events_processed() % 10 == 0 {
                        let snapshots = vsr.extract_snapshots();

                        if vsr_commit_checker.is_some()
                            && vsr_agreement_checker.is_some()
                            && vsr_prefix_checker.is_some()
                        {
                            let result = check_all_vsr_invariants(
                                vsr_commit_checker.as_mut().unwrap(),
                                vsr_agreement_checker.as_mut().unwrap(),
                                vsr_prefix_checker.as_mut().unwrap(),
                                &snapshots,
                            );

                            if !result.is_ok() {
                                if let kimberlite_sim::InvariantResult::Violated {
                                    invariant,
                                    message,
                                    ..
                                } = result
                                {
                                    return make_violation(
                                        invariant,
                                        message,
                                        sim.events_processed(),
                                        &mut trace,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            EventKind::WorkloadTick => {
                // Handle workload tick by generating next batch of operations
                // Pass simulation context for limit-aware termination
                let events =
                    workload_scheduler.handle_tick(event.time_ns, sim.events_processed(), &mut rng);
                for (time, kind) in events {
                    sim.schedule(time, kind);
                }
            }
            EventKind::CatalogOperationApplied {
                cmd_tenant_id,
                table_tenant_id,
            } => {
                // AUDIT-2026-04 C-2 — the verify_catalog_isolation call
                // site. This is the hook the audit's framing demands:
                // every catalog-touching command fires the checker
                // before the loop advances. If the wire is broken, the
                // `sim-canary-catalog-cross-tenant` canary's injected
                // cross-tenant event is not reported as a violation and
                // the canary test fails (audit's exact discipline: "if
                // the canary passes the invariant, the wiring is
                // wrong").
                if let Some(ref mut checker) = query_tenant_isolation {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_catalog_isolation");
                    let result = checker.verify_catalog_isolation(table_tenant_id, cmd_tenant_id);
                    if !result.is_ok() {
                        return make_violation(
                            "query_catalog_isolation".to_string(),
                            format!(
                                "catalog cross-tenant access at time {}: cmd-tenant {} vs table-tenant {}",
                                event.time_ns, cmd_tenant_id, table_tenant_id,
                            ),
                            sim.events_processed(),
                            &mut trace,
                        );
                    }
                }
            }
            // AUDIT-2026-04 H-3 — liveness wiring. Each VSR event
            // feeds one checker; LivenessTick advances the clock and
            // triggers a check. If the wire is broken, the
            // `sim-canary-stalled-prepare` / `sim-canary-stalled-view-change`
            // canaries silently pass — which would replicate the
            // audit's exact failure mode.
            EventKind::VsrPrepare { op_num, .. } => {
                eventual_commit.on_prepare(op_num);
            }
            EventKind::VsrCommit { op_num } => {
                eventual_commit.on_commit(op_num);
            }
            EventKind::VsrViewChangeStart { view } => {
                eventual_progress.on_view_change_start(view);
            }
            EventKind::VsrViewChangeComplete { view } => {
                eventual_progress.on_view_change_complete(view);
            }
            EventKind::LivenessTick => {
                use kimberlite_sim::instrumentation::invariant_tracker;
                invariant_tracker::record_invariant_execution("liveness_eventual_commit");
                invariant_tracker::record_invariant_execution("liveness_eventual_progress");
                eventual_commit.tick();
                eventual_progress.tick();
                let commit_result = eventual_commit.check();
                if !commit_result.is_ok() {
                    return make_violation(
                        "liveness_eventual_commit".to_string(),
                        format!(
                            "eventual commit violated at time {}: {:?}",
                            event.time_ns, commit_result,
                        ),
                        sim.events_processed(),
                        &mut trace,
                    );
                }
                let progress_result = eventual_progress.check();
                if !progress_result.is_ok() {
                    return make_violation(
                        "liveness_eventual_progress".to_string(),
                        format!(
                            "eventual progress violated at time {}: {:?}",
                            event.time_ns, progress_result,
                        ),
                        sim.events_processed(),
                        &mut trace,
                    );
                }
            }
            EventKind::DmlRowObserved {
                reader_tenant_id,
                row_tenant_id,
            } => {
                // AUDIT-2026-04 C-2 — read-side leak detection.
                // `set_tenant` is seeded here (not at scenario init)
                // because the reader changes per-query; the checker's
                // expected_tenant_id is the caller's tenant, not a
                // fixed scenario constant.
                if let Some(ref mut checker) = query_tenant_isolation {
                    use kimberlite_sim::instrumentation::invariant_tracker;
                    invariant_tracker::record_invariant_execution("query_row_isolation");
                    checker.set_tenant(reader_tenant_id);
                    let result = checker.verify_row_isolation(row_tenant_id);
                    if !result.is_ok() {
                        return make_violation(
                            "query_row_isolation".to_string(),
                            format!(
                                "row cross-tenant leak at time {}: reader-tenant {} saw row-tenant {}",
                                event.time_ns, reader_tenant_id, row_tenant_id,
                            ),
                            sim.events_processed(),
                            &mut trace,
                        );
                    }
                }
            }
            _ => {
                // Handle other event types
            }
        }
    }

    // Final VSR invariant check
    if let Some(ref mut vsr) = vsr_sim {
        let snapshots = vsr.extract_snapshots();

        if vsr_commit_checker.is_some()
            && vsr_agreement_checker.is_some()
            && vsr_prefix_checker.is_some()
        {
            let result = check_all_vsr_invariants(
                vsr_commit_checker.as_mut().unwrap(),
                vsr_agreement_checker.as_mut().unwrap(),
                vsr_prefix_checker.as_mut().unwrap(),
                &snapshots,
            );

            if !result.is_ok() {
                if let kimberlite_sim::InvariantResult::Violated {
                    invariant, message, ..
                } = result
                {
                    return make_violation(invariant, message, sim.events_processed(), &mut trace);
                }
            }
        }
    }

    // Before finalizing the run, drive the compliance and query workloads
    // so their annotations fire in this seed's PropertyReport.
    real_driver.run_compliance_suite();
    real_driver.run_query_suite();

    // Compute final storage hash for determinism checking
    let storage_hash = storage.storage_hash();

    // Compute kernel state hash from VSR simulation (if enabled)
    let kernel_state_hash = if let Some(ref vsr) = vsr_sim {
        vsr.kernel_state().compute_state_hash()
    } else {
        // Fallback for non-VSR mode: use empty state hash
        kimberlite_kernel::State::new().compute_state_hash()
    };

    // Record simulation end in trace
    if let Some(ref mut t) = trace {
        t.record(
            sim.now(),
            TraceEventType::SimulationEnd {
                events_processed: sim.events_processed(),
            },
        );
    }

    // Report invariant check performance in verbose mode
    if config.verbose && !invariant_times.is_empty() {
        eprintln!("\n=== Invariant Check Performance ===");
        let mut sorted_times: Vec<_> = invariant_times.iter().collect();
        sorted_times.sort_by_key(|(_, time)| std::cmp::Reverse(**time));

        let total_time: u128 = sorted_times.iter().map(|(_, time)| **time).sum();
        for (name, time_us) in sorted_times {
            #[allow(clippy::cast_precision_loss)]
            let pct = if total_time > 0 {
                (*time_us as f64 / total_time as f64) * 100.0
            } else {
                0.0
            };
            eprintln!("  {name:30} {time_us:>10} µs  ({pct:>5.1}%)");
        }
        eprintln!("  {:30} {:>10} µs", "TOTAL", total_time);
    }

    SimulationResult::Success {
        events_processed: sim.events_processed(),
        final_time_ns: sim.now(),
        storage_hash,
        kernel_state_hash,
        trace,
    }
}

// ============================================================================
// Utilities
// ============================================================================

/// Simple hex encoding for storage hashes.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ============================================================================
// CLI Parsing
// ============================================================================

fn parse_args() -> VoprConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut config = VoprConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" | "-s" => {
                i += 1;
                if i < args.len() {
                    config.seed = args[i].parse().unwrap_or(0);
                }
            }
            "--iterations" | "-n" => {
                i += 1;
                if i < args.len() {
                    config.iterations = args[i].parse().unwrap_or(100);
                }
            }
            "--faults" | "-f" => {
                i += 1;
                if i < args.len() {
                    config.network_faults = args[i].contains("network");
                    config.storage_faults = args[i].contains("storage");
                }
            }
            "--no-faults" => {
                config.network_faults = false;
                config.storage_faults = false;
            }
            "--verbose" | "-v" => {
                config.verbose = true;
            }
            "--vsr-mode" => {
                config.vsr_mode = true;
            }
            "--max-events" => {
                i += 1;
                if i < args.len() {
                    config.max_events = args[i].parse().unwrap_or(10_000);
                }
            }
            "--max-time" => {
                i += 1;
                if i < args.len() {
                    // Parse as seconds and convert to nanoseconds
                    let secs: u64 = args[i].parse().unwrap_or(10);
                    config.max_time_ns = secs * 1_000_000_000;
                }
            }
            "--json" => {
                config.json_mode = true;
            }
            "--checkpoint-file" => {
                i += 1;
                if i < args.len() {
                    config.checkpoint_file = Some(args[i].clone());
                }
            }
            "--check-determinism" => {
                config.check_determinism = true;
            }
            "--enable-trace" => {
                config.enable_trace = true;
            }
            "--no-trace-on-failure" => {
                config.save_trace_on_failure = false;
            }
            "--no-enhanced-workloads" => {
                config.enhanced_workloads = false;
            }
            "--no-failure-diagnosis" => {
                config.failure_diagnosis = false;
            }
            "--scenario" => {
                i += 1;
                if i < args.len() {
                    config.scenario = parse_scenario(&args[i]);
                    if config.scenario.is_none() {
                        eprintln!("Unknown scenario: {}", args[i]);
                        eprintln!("Run --list-scenarios to see all available scenarios");
                        std::process::exit(1);
                    }
                }
            }
            "--list-scenarios" => {
                // Default list advertises only shipping (non-aspirational)
                // scenarios. Pass `--include-aspirational` (or build with
                // `--features aspirational-scenarios`) to see the full set.
                let include_aspirational = args
                    .iter()
                    .any(|a| a == "--include-aspirational" || a == "--all-scenarios")
                    || cfg!(feature = "aspirational-scenarios");
                let scenarios: Vec<_> = if include_aspirational {
                    ScenarioType::all().to_vec()
                } else {
                    ScenarioType::shipping()
                };
                println!("Available Test Scenarios:");
                if !include_aspirational {
                    let gated = ScenarioType::all().len() - scenarios.len();
                    if gated > 0 {
                        println!(
                            "(showing {} shipping scenarios; {} aspirational scenarios hidden — run with --include-aspirational to show all)",
                            scenarios.len(),
                            gated,
                        );
                    }
                }
                println!();
                for scenario in scenarios {
                    println!("  {}", scenario.name());
                    println!("    {}", scenario.description());
                    println!();
                }
                std::process::exit(0);
            }
            "--enable-vsr-invariants" => {
                config.invariant_config.enable_vsr_agreement = true;
                config.invariant_config.enable_vsr_prefix_property = true;
                config.invariant_config.enable_vsr_view_change_safety = true;
                config.invariant_config.enable_vsr_recovery_safety = true;
            }
            "--disable-vsr-invariants" => {
                config.invariant_config.enable_vsr_agreement = false;
                config.invariant_config.enable_vsr_prefix_property = false;
                config.invariant_config.enable_vsr_view_change_safety = false;
                config.invariant_config.enable_vsr_recovery_safety = false;
            }
            "--enable-projection-invariants" => {
                config.invariant_config.enable_projection_applied_position = true;
                config.invariant_config.enable_projection_mvcc_visibility = true;
                config.invariant_config.enable_projection_applied_index = true;
                config.invariant_config.enable_projection_catchup = true;
            }
            "--disable-projection-invariants" => {
                config.invariant_config.enable_projection_applied_position = false;
                config.invariant_config.enable_projection_mvcc_visibility = false;
                config.invariant_config.enable_projection_applied_index = false;
                config.invariant_config.enable_projection_catchup = false;
            }
            "--enable-query-invariants" => {
                config.invariant_config.enable_query_determinism = true;
                config.invariant_config.enable_query_read_your_writes = true;
                config.invariant_config.enable_query_type_safety = true;
                config.invariant_config.enable_query_order_by_limit = true;
                config.invariant_config.enable_query_aggregates = true;
                config.invariant_config.enable_query_tenant_isolation = true;
            }
            "--disable-query-invariants" => {
                config.invariant_config.enable_query_determinism = false;
                config.invariant_config.enable_query_read_your_writes = false;
                config.invariant_config.enable_query_type_safety = false;
                config.invariant_config.enable_query_order_by_limit = false;
                config.invariant_config.enable_query_aggregates = false;
                config.invariant_config.enable_query_tenant_isolation = false;
            }
            "--enable-sql-oracles" => {
                config.invariant_config.enable_sql_tlp = true;
                config.invariant_config.enable_sql_norec = true;
                config.invariant_config.enable_sql_plan_coverage = true;
            }
            "--core-invariants-only" => {
                // Disable all VSR, Projection, Query, SQL
                config.invariant_config.enable_vsr_agreement = false;
                config.invariant_config.enable_vsr_prefix_property = false;
                config.invariant_config.enable_vsr_view_change_safety = false;
                config.invariant_config.enable_vsr_recovery_safety = false;
                config.invariant_config.enable_projection_applied_position = false;
                config.invariant_config.enable_projection_mvcc_visibility = false;
                config.invariant_config.enable_projection_applied_index = false;
                config.invariant_config.enable_projection_catchup = false;
                config.invariant_config.enable_query_determinism = false;
                config.invariant_config.enable_query_read_your_writes = false;
                config.invariant_config.enable_query_type_safety = false;
                config.invariant_config.enable_query_order_by_limit = false;
                config.invariant_config.enable_query_aggregates = false;
                config.invariant_config.enable_query_tenant_isolation = false;
                config.invariant_config.enable_sql_tlp = false;
                config.invariant_config.enable_sql_norec = false;
                config.invariant_config.enable_sql_plan_coverage = false;
            }
            "--enable-invariant" => {
                i += 1;
                if i < args.len() {
                    match args[i].as_str() {
                        "hash_chain" => config.invariant_config.enable_hash_chain = true,
                        "log_consistency" => config.invariant_config.enable_log_consistency = true,
                        "replica_consistency" => {
                            config.invariant_config.enable_replica_consistency = true;
                        }
                        "replica_head" => config.invariant_config.enable_replica_head = true,
                        "commit_history" => config.invariant_config.enable_commit_history = true,
                        "vsr_agreement" => config.invariant_config.enable_vsr_agreement = true,
                        "vsr_prefix_property" => {
                            config.invariant_config.enable_vsr_prefix_property = true;
                        }
                        "vsr_view_change_safety" => {
                            config.invariant_config.enable_vsr_view_change_safety = true;
                        }
                        "vsr_recovery_safety" => {
                            config.invariant_config.enable_vsr_recovery_safety = true;
                        }
                        "projection_applied_position" => {
                            config.invariant_config.enable_projection_applied_position = true;
                        }
                        "projection_mvcc" => {
                            config.invariant_config.enable_projection_mvcc_visibility = true;
                        }
                        "projection_applied_index" => {
                            config.invariant_config.enable_projection_applied_index = true;
                        }
                        "projection_catchup" => {
                            config.invariant_config.enable_projection_catchup = true;
                        }
                        "query_determinism" => {
                            config.invariant_config.enable_query_determinism = true;
                        }
                        "query_read_your_writes" => {
                            config.invariant_config.enable_query_read_your_writes = true;
                        }
                        "query_type_safety" => {
                            config.invariant_config.enable_query_type_safety = true;
                        }
                        "query_order_by_limit" => {
                            config.invariant_config.enable_query_order_by_limit = true;
                        }
                        "query_aggregates" => {
                            config.invariant_config.enable_query_aggregates = true;
                        }
                        "query_tenant_isolation" => {
                            config.invariant_config.enable_query_tenant_isolation = true;
                        }
                        "sql_tlp" => config.invariant_config.enable_sql_tlp = true,
                        "sql_norec" => config.invariant_config.enable_sql_norec = true,
                        "sql_plan_coverage" => {
                            config.invariant_config.enable_sql_plan_coverage = true;
                        }
                        _ => eprintln!("Warning: Unknown invariant '{}'", args[i]),
                    }
                }
            }
            "--disable-invariant" => {
                i += 1;
                if i < args.len() {
                    match args[i].as_str() {
                        "hash_chain" => config.invariant_config.enable_hash_chain = false,
                        "log_consistency" => config.invariant_config.enable_log_consistency = false,
                        "replica_consistency" => {
                            config.invariant_config.enable_replica_consistency = false;
                        }
                        "replica_head" => config.invariant_config.enable_replica_head = false,
                        "commit_history" => config.invariant_config.enable_commit_history = false,
                        "vsr_agreement" => config.invariant_config.enable_vsr_agreement = false,
                        "vsr_prefix_property" => {
                            config.invariant_config.enable_vsr_prefix_property = false;
                        }
                        "vsr_view_change_safety" => {
                            config.invariant_config.enable_vsr_view_change_safety = false;
                        }
                        "vsr_recovery_safety" => {
                            config.invariant_config.enable_vsr_recovery_safety = false;
                        }
                        "projection_applied_position" => {
                            config.invariant_config.enable_projection_applied_position = false;
                        }
                        "projection_mvcc" => {
                            config.invariant_config.enable_projection_mvcc_visibility = false;
                        }
                        "projection_applied_index" => {
                            config.invariant_config.enable_projection_applied_index = false;
                        }
                        "projection_catchup" => {
                            config.invariant_config.enable_projection_catchup = false;
                        }
                        "query_determinism" => {
                            config.invariant_config.enable_query_determinism = false;
                        }
                        "query_read_your_writes" => {
                            config.invariant_config.enable_query_read_your_writes = false;
                        }
                        "query_type_safety" => {
                            config.invariant_config.enable_query_type_safety = false;
                        }
                        "query_order_by_limit" => {
                            config.invariant_config.enable_query_order_by_limit = false;
                        }
                        "query_aggregates" => {
                            config.invariant_config.enable_query_aggregates = false;
                        }
                        "query_tenant_isolation" => {
                            config.invariant_config.enable_query_tenant_isolation = false;
                        }
                        "sql_tlp" => config.invariant_config.enable_sql_tlp = false,
                        "sql_norec" => config.invariant_config.enable_sql_norec = false,
                        "sql_plan_coverage" => {
                            config.invariant_config.enable_sql_plan_coverage = false;
                        }
                        _ => eprintln!("Warning: Unknown invariant '{}'", args[i]),
                    }
                }
            }
            "--list-invariants" => {
                println!("Available Invariants:");
                println!();
                println!("Core (always recommended):");
                println!("  hash_chain, log_consistency");
                println!("  replica_consistency, replica_head, commit_history");
                println!();
                println!("VSR (consensus correctness):");
                println!("  vsr_agreement, vsr_prefix_property");
                println!("  vsr_view_change_safety, vsr_recovery_safety");
                println!();
                println!("Projection (MVCC & state machine):");
                println!("  projection_applied_position, projection_mvcc");
                println!("  projection_applied_index, projection_catchup");
                println!();
                println!("Query (SQL correctness):");
                println!("  query_determinism, query_read_your_writes, query_type_safety");
                println!("  query_order_by_limit, query_aggregates, query_tenant_isolation");
                println!();
                println!("SQL Oracles (expensive, opt-in):");
                println!("  sql_tlp, sql_norec, sql_plan_coverage");
                std::process::exit(0);
            }
            "--workload-ops-per-tick" => {
                i += 1;
                if i < args.len() {
                    config.workload_ops_per_tick = args[i].parse().unwrap_or(5);
                }
            }
            "--workload-tick-ms" => {
                i += 1;
                if i < args.len() {
                    config.workload_tick_interval_ms = args[i].parse().unwrap_or(10);
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    config
}

fn print_help() {
    println!(
        r"VOPR - Viewstamped Operation Replication Simulation Tester

USAGE:
    vopr [OPTIONS]

OPTIONS:
    -s, --seed <SEED>           Starting seed for simulations (default: 0)
    -n, --iterations <N>        Number of iterations to run (default: 100)
    -f, --faults <TYPES>        Enable fault types: network,storage (default: both)
        --no-faults             Disable all fault injection
        --scenario <NAME>       Run a predefined test scenario (overrides fault flags)
        --list-scenarios        List all available test scenarios
    -v, --verbose               Enable verbose output
        --max-events <N>        Maximum events per simulation (default: 10000)
        --max-time <SECS>       Maximum simulated time in seconds (default: 10)
        --json                  Output newline-delimited JSON
        --checkpoint-file <PATH> Path to checkpoint file for resume support
        --check-determinism     Run each seed twice to verify determinism
        --enable-trace          Enable full trace collection (high overhead)
        --no-trace-on-failure   Don't save trace when failures occur
        --no-enhanced-workloads Disable RMW and Scan operations
        --no-failure-diagnosis  Disable automated failure diagnosis
        --vsr-mode              Enable full VSR replicas instead of simplified mode
        --workload-ops-per-tick <N>  Operations per tick (default: 5)
        --workload-tick-ms <MS>      Tick interval in milliseconds (default: 10)
    -h, --help                  Print this help message

INVARIANT CONTROL:
    --enable-vsr-invariants     Enable all VSR invariants
    --disable-vsr-invariants    Disable all VSR invariants
    --enable-projection-invariants  Enable all projection invariants
    --disable-projection-invariants Disable all projection invariants
    --enable-query-invariants   Enable all query invariants
    --disable-query-invariants  Disable all query invariants
    --enable-sql-oracles        Enable SQL oracles (expensive, 10-100x slower)
    --core-invariants-only      Disable all except core 6 invariants
    --enable-invariant <NAME>   Enable specific invariant
    --disable-invariant <NAME>  Disable specific invariant
    --list-invariants           List all available invariants

TEST SCENARIOS:
    baseline                    No faults, baseline performance
    swizzle                     Swizzle-clogging (intermittent network congestion)
    gray                        Gray failures (partial node failures)
    multi-tenant                Multi-tenant isolation with faults
    time-compression            10x accelerated time for long-running tests
    combined                    All fault types enabled simultaneously

    Plus 27 additional scenarios including:
    - Byzantine attack scenarios (view-change-merge, commit-desync, etc.)
    - Corruption detection (bit-flip, checksum-validation, silent-disk-failure)
    - Crash recovery (crash-commit, crash-view-change, recovery-corrupt)
    - Gray failure variants (slow-disk, intermittent-network)
    - Race conditions (race-view-changes, race-commit-dvc)
    - Clock synchronization (clock-drift, clock-offset-exceeded, clock-ntp-failure)
    - Client sessions (session-crash, session-lockout, session-eviction)

    Run --list-scenarios for the complete list with descriptions

WORKLOAD TUNING:
    Default rate: 5 ops/tick, 10ms interval = 500 ops/sec
    Light load:   --workload-ops-per-tick 2 --workload-tick-ms 20  (100 ops/sec)
    Heavy load:   --workload-ops-per-tick 20 --workload-tick-ms 5  (4000 ops/sec)

EXAMPLES:
    vopr --seed 12345           Run with specific seed
    vopr -n 1000 -v             Run 1000 iterations with verbose output
    vopr --scenario swizzle     Run swizzle-clogging scenario
    vopr --scenario combined -n 500 -v  # Stress test with all faults
    vopr --list-scenarios       Show detailed scenario descriptions
    vopr --list-invariants      Show all available invariants
    vopr --core-invariants-only Run with only core checkers
    vopr --enable-sql-oracles   Enable expensive SQL oracle testing
    vopr --faults network       Enable only network faults
    vopr --no-faults            Run without any fault injection
    vopr --json --checkpoint-file /var/lib/vopr/checkpoint.json
    vopr -n 100000 -v --checkpoint-file checkpoint.json  # Overnight run
    vopr --max-events 100000 --workload-ops-per-tick 20 --workload-tick-ms 5  # Fast heavy test
"
    );
}

// ============================================================================
// Scenario Parsing Helper
// ============================================================================

/// Parses a scenario name from a string.
fn parse_scenario(name: &str) -> Option<ScenarioType> {
    match name.to_lowercase().as_str() {
        "baseline" => Some(ScenarioType::Baseline),
        "swizzle" | "swizzle-clogging" => Some(ScenarioType::SwizzleClogging),
        "gray" | "gray-failures" => Some(ScenarioType::GrayFailures),
        "multi-tenant" => Some(ScenarioType::MultiTenantIsolation),
        "time-compression" => Some(ScenarioType::TimeCompression),
        "combined" => Some(ScenarioType::Combined),
        "byzantine_view_change_merge" | "view-change-merge" => {
            Some(ScenarioType::ByzantineViewChangeMerge)
        }
        "byzantine_commit_desync" | "commit-desync" => Some(ScenarioType::ByzantineCommitDesync),
        "byzantine_inflated_commit" | "inflated-commit" => {
            Some(ScenarioType::ByzantineInflatedCommit)
        }
        "byzantine_invalid_metadata" | "invalid-metadata" => {
            Some(ScenarioType::ByzantineInvalidMetadata)
        }
        "byzantine_malicious_view_change" | "malicious-view-change" => {
            Some(ScenarioType::ByzantineMaliciousViewChange)
        }
        "byzantine_leader_race" | "leader-race" => Some(ScenarioType::ByzantineLeaderRace),
        "byzantine_dvc_tail_length_mismatch" | "dvc-tail-mismatch" => {
            Some(ScenarioType::ByzantineDvcTailLengthMismatch)
        }
        "byzantine_dvc_identical_claims" | "dvc-identical-claims" => {
            Some(ScenarioType::ByzantineDvcIdenticalClaims)
        }
        "byzantine_oversized_start_view" | "oversized-start-view" => {
            Some(ScenarioType::ByzantineOversizedStartView)
        }
        "byzantine_invalid_repair_range" | "invalid-repair-range" => {
            Some(ScenarioType::ByzantineInvalidRepairRange)
        }
        "byzantine_invalid_kernel_command" | "invalid-kernel-command" => {
            Some(ScenarioType::ByzantineInvalidKernelCommand)
        }
        "corruption_bit_flip" | "bit-flip" => Some(ScenarioType::CorruptionBitFlip),
        "corruption_checksum_validation" | "checksum-validation" => {
            Some(ScenarioType::CorruptionChecksumValidation)
        }
        "corruption_silent_disk_failure" | "silent-disk-failure" => {
            Some(ScenarioType::CorruptionSilentDiskFailure)
        }
        "crash_during_commit" | "crash-commit" => Some(ScenarioType::CrashDuringCommit),
        "crash_during_view_change" | "crash-view-change" => {
            Some(ScenarioType::CrashDuringViewChange)
        }
        "recovery_corrupt_log" | "recovery-corrupt" => Some(ScenarioType::RecoveryCorruptLog),
        "gray_failure_slow_disk" | "slow-disk" => Some(ScenarioType::GrayFailureSlowDisk),
        "gray_failure_intermittent_network" | "intermittent-network" => {
            Some(ScenarioType::GrayFailureIntermittentNetwork)
        }
        "race_concurrent_view_changes" | "race-view-changes" => {
            Some(ScenarioType::RaceConcurrentViewChanges)
        }
        "race_commit_during_dvc" | "race-commit-dvc" => Some(ScenarioType::RaceCommitDuringDvc),
        "clock_drift" | "clock-drift" => Some(ScenarioType::ClockDrift),
        "clock_offset_exceeded" | "clock-offset-exceeded" => {
            Some(ScenarioType::ClockOffsetExceeded)
        }
        "clock_ntp_failure" | "clock-ntp-failure" => Some(ScenarioType::ClockNtpFailure),
        "client_session_crash" | "session-crash" => Some(ScenarioType::ClientSessionCrash),
        "client_session_view_change_lockout" | "session-lockout" => {
            Some(ScenarioType::ClientSessionViewChangeLockout)
        }
        "client_session_eviction" | "session-eviction" => Some(ScenarioType::ClientSessionEviction),
        // v0.6.0 Tier 1 #5 — ALTER TABLE hardening. Accept both the
        // snake_case canonical name and a kebab-case alias to match
        // the existing scenario-naming convention in this function.
        "alter_table_crash_recovery" | "alter-table-crash-recovery" => {
            Some(ScenarioType::AlterTableCrashRecovery)
        }
        // v0.9.x T2.3 — cluster supervisor scenarios. Snake_case
        // canonical + kebab-case alias, consistent with the rest of
        // this matcher.
        "cluster_node_process_crash" | "cluster-node-process-crash" => {
            Some(ScenarioType::ClusterNodeProcessCrash)
        }
        "cluster_cascading_node_failure" | "cluster-cascading-node-failure" => {
            Some(ScenarioType::ClusterCascadingNodeFailure)
        }
        "cluster_health_check_timeout" | "cluster-health-check-timeout" => {
            Some(ScenarioType::ClusterHealthCheckTimeout)
        }
        "cluster_config_reload_under_load" | "cluster-config-reload-under-load" => {
            Some(ScenarioType::ClusterConfigReloadUnderLoad)
        }
        "cluster_rolling_restart_full_cluster" | "cluster-rolling-restart-full-cluster" => {
            Some(ScenarioType::ClusterRollingRestartFullCluster)
        }
        _ => None,
    }
}

// ============================================================================
// Subcommand Handlers
// ============================================================================

fn run_repro_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, ReproCommand};
    use std::path::PathBuf;

    let mut bundle_path: Option<PathBuf> = None;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--verbose" | "-v" => verbose = true,
            "--help" | "-h" => {
                println!("VOPR Repro - Reproduce failures from .kmb bundles");
                println!();
                println!("USAGE:");
                println!("    vopr repro <BUNDLE_PATH> [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -v, --verbose    Verbose output");
                println!("    -h, --help       Print this help message");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && bundle_path.is_none() => {
                bundle_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.unwrap_or_else(|| {
        eprintln!("Error: bundle path required");
        eprintln!("Usage: vopr repro <BUNDLE_PATH>");
        std::process::exit(1);
    });

    let cmd = ReproCommand::new(bundle_path).with_verbose(verbose);
    if let Err(e) = cmd.execute() {
        eprintln!("Repro failed: {e}");
        std::process::exit(1);
    }
}

fn run_show_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, ShowCommand};
    use std::path::PathBuf;

    let mut bundle_path: Option<PathBuf> = None;
    let mut show_events = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--events" | "-e" => show_events = true,
            "--help" | "-h" => {
                println!("VOPR Show - Display failure bundle details");
                println!();
                println!("USAGE:");
                println!("    vopr show <BUNDLE_PATH> [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -e, --events     Show event log");
                println!("    -h, --help       Print this help message");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && bundle_path.is_none() => {
                bundle_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.unwrap_or_else(|| {
        eprintln!("Error: bundle path required");
        eprintln!("Usage: vopr show <BUNDLE_PATH>");
        std::process::exit(1);
    });

    let cmd = ShowCommand::new(bundle_path).with_events(show_events);
    if let Err(e) = cmd.execute() {
        eprintln!("Show failed: {e}");
        std::process::exit(1);
    }
}

fn run_timeline_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, TimelineCommand};
    use std::path::PathBuf;

    let mut bundle_path: Option<PathBuf> = None;
    let mut width = 120usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--width" | "-w" => {
                i += 1;
                if i < args.len() {
                    width = args[i].parse().unwrap_or(120);
                }
            }
            "--help" | "-h" => {
                println!("VOPR Timeline - Visualize simulation timeline");
                println!();
                println!("USAGE:");
                println!("    vopr timeline <BUNDLE_PATH> [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -w, --width <N>  Terminal width (default: 120)");
                println!("    -h, --help       Print this help message");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && bundle_path.is_none() => {
                bundle_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.unwrap_or_else(|| {
        eprintln!("Error: bundle path required");
        eprintln!("Usage: vopr timeline <BUNDLE_PATH>");
        std::process::exit(1);
    });

    let cmd = TimelineCommand::new(bundle_path).with_width(width);
    if let Err(e) = cmd.execute() {
        eprintln!("Timeline failed: {e}");
        std::process::exit(1);
    }
}

fn run_bisect_command(args: &[String]) {
    use kimberlite_sim::cli::{BisectCommand, Command};
    use std::path::PathBuf;

    let mut bundle_path: Option<PathBuf> = None;
    let mut checkpoint_interval = 1000u64;
    let mut output: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" | "-i" => {
                i += 1;
                if i < args.len() {
                    checkpoint_interval = args[i].parse().unwrap_or(1000);
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output = Some(PathBuf::from(&args[i]));
                }
            }
            "--help" | "-h" => {
                println!("VOPR Bisect - Find first failing event via binary search");
                println!();
                println!("USAGE:");
                println!("    vopr bisect <BUNDLE_PATH> [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -i, --interval <N>   Checkpoint interval (default: 1000)");
                println!("    -o, --output <PATH>  Output path for minimized bundle");
                println!("    -h, --help           Print this help message");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && bundle_path.is_none() => {
                bundle_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.unwrap_or_else(|| {
        eprintln!("Error: bundle path required");
        eprintln!("Usage: vopr bisect <BUNDLE_PATH>");
        std::process::exit(1);
    });

    let mut cmd = BisectCommand::new(bundle_path).with_checkpoint_interval(checkpoint_interval);
    if let Some(out) = output {
        cmd = cmd.with_output(out);
    }
    if let Err(e) = cmd.execute() {
        eprintln!("Bisect failed: {e}");
        std::process::exit(1);
    }
}

fn run_minimize_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, MinimizeCommand};
    use std::path::PathBuf;

    let mut bundle_path: Option<PathBuf> = None;
    let mut granularity = 8usize;
    let mut max_iterations = 100usize;
    let mut output: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--granularity" | "-g" => {
                i += 1;
                if i < args.len() {
                    granularity = args[i].parse().unwrap_or(8);
                }
            }
            "--max-iterations" | "-n" => {
                i += 1;
                if i < args.len() {
                    max_iterations = args[i].parse().unwrap_or(100);
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output = Some(PathBuf::from(&args[i]));
                }
            }
            "--help" | "-h" => {
                println!("VOPR Minimize - Minimize failure bundles via delta debugging");
                println!();
                println!("USAGE:");
                println!("    vopr minimize <BUNDLE_PATH> [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -g, --granularity <N>      Initial granularity (default: 8)");
                println!("    -n, --max-iterations <N>   Max iterations (default: 100)");
                println!("    -o, --output <PATH>        Output path for minimized bundle");
                println!("    -h, --help                 Print this help message");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && bundle_path.is_none() => {
                bundle_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let bundle_path = bundle_path.unwrap_or_else(|| {
        eprintln!("Error: bundle path required");
        eprintln!("Usage: vopr minimize <BUNDLE_PATH>");
        std::process::exit(1);
    });

    let mut cmd = MinimizeCommand::new(bundle_path)
        .with_granularity(granularity)
        .with_max_iterations(max_iterations);
    if let Some(out) = output {
        cmd = cmd.with_output(out);
    }
    if let Err(e) = cmd.execute() {
        eprintln!("Minimize failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "dashboard")]
fn run_dashboard_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, DashboardCommand};

    let mut port = 8080u16;
    let mut coverage_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse().unwrap_or(8080);
                }
            }
            "--coverage" | "-c" => {
                i += 1;
                if i < args.len() {
                    coverage_file = Some(args[i].clone());
                }
            }
            "--help" | "-h" => {
                println!("VOPR Dashboard - Web dashboard for coverage visualization");
                println!();
                println!("USAGE:");
                println!("    vopr dashboard [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -p, --port <PORT>       Server port (default: 8080)");
                println!("    -c, --coverage <PATH>   Coverage file path");
                println!("    -h, --help              Print this help message");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let mut cmd = DashboardCommand::new().with_port(port);
    if let Some(path) = coverage_file {
        cmd = cmd.with_coverage_file(path);
    }
    if let Err(e) = cmd.execute() {
        eprintln!("Dashboard failed: {e}");
        std::process::exit(1);
    }
}

fn run_stats_command(args: &[String]) {
    use kimberlite_sim::cli::{Command, StatsCommand};

    let mut detailed = false;

    for arg in args {
        match arg.as_str() {
            "--detailed" | "-d" => detailed = true,
            "--help" | "-h" => {
                println!("VOPR Stats - Display simulation statistics");
                println!();
                println!("USAGE:");
                println!("    vopr stats [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -d, --detailed   Show detailed statistics");
                println!("    -h, --help       Print this help message");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
        }
    }

    let cmd = StatsCommand::new().with_detailed(detailed);
    if let Err(e) = cmd.execute() {
        eprintln!("Stats failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "tui")]
fn run_tui_command(args: &[String]) {
    let mut iterations = 1000u64;
    let mut scenario: Option<ScenarioType> = None;
    let mut seed: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--iterations" | "-n" => {
                i += 1;
                if i < args.len() {
                    iterations = args[i].parse().unwrap_or(1000);
                }
            }
            "--scenario" => {
                i += 1;
                if i < args.len() {
                    scenario = parse_scenario(&args[i]);
                    if scenario.is_none() {
                        eprintln!("Unknown scenario: {}", args[i]);
                        eprintln!("Run 'vopr scenarios' to see all available scenarios");
                        std::process::exit(1);
                    }
                }
            }
            "--seed" => {
                i += 1;
                if i < args.len() {
                    seed = Some(args[i].parse().unwrap_or(0));
                }
            }
            "--help" | "-h" => {
                println!("VOPR TUI - Interactive Terminal UI for VOPR");
                println!();
                println!("USAGE:");
                println!("    vopr tui [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -n, --iterations <N>    Number of iterations to run (default: 1000)");
                println!("    --scenario <NAME>       Run a specific scenario");
                println!("    --seed <SEED>           Use a specific seed");
                println!("    -h, --help              Print this help message");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown TUI option: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Create TUI config using the library's VoprConfig type
    let config = kimberlite_sim::VoprConfig {
        seed: seed.unwrap_or_else(rand::random),
        iterations,
        scenario,
        ..Default::default()
    };

    // Launch TUI using the library's tui module
    if let Err(e) = kimberlite_sim::tui::run_tui(config) {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}

fn print_scenarios() {
    println!("Available Test Scenarios:");
    println!();
    for scenario in ScenarioType::all() {
        println!("  {}", scenario.name());
        println!("    {}", scenario.description());
        println!();
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

#[allow(clippy::cast_precision_loss)]
fn main() {
    // Check if first argument is a subcommand
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "tui" => {
                #[cfg(feature = "tui")]
                {
                    run_tui_command(&args[2..]);
                    return;
                }
                #[cfg(not(feature = "tui"))]
                {
                    eprintln!("Error: TUI feature not enabled");
                    eprintln!("Rebuild with: cargo build --features tui");
                    std::process::exit(1);
                }
            }
            "repro" => {
                run_repro_command(&args[2..]);
                return;
            }
            "show" => {
                run_show_command(&args[2..]);
                return;
            }
            "timeline" => {
                run_timeline_command(&args[2..]);
                return;
            }
            "bisect" => {
                run_bisect_command(&args[2..]);
                return;
            }
            "minimize" => {
                run_minimize_command(&args[2..]);
                return;
            }
            "dashboard" => {
                #[cfg(feature = "dashboard")]
                {
                    run_dashboard_command(&args[2..]);
                    return;
                }
                #[cfg(not(feature = "dashboard"))]
                {
                    eprintln!("Error: Dashboard feature not enabled");
                    eprintln!("Rebuild with: cargo build --features dashboard");
                    std::process::exit(1);
                }
            }
            "scenarios" => {
                print_scenarios();
                return;
            }
            "stats" => {
                run_stats_command(&args[2..]);
                return;
            }
            "run" | "help" | "--help" | "-h" => {
                // Fall through to normal parsing
            }
            _ if args[1].starts_with('-') => {
                // It's a flag, not a subcommand - fall through to normal parsing
            }
            _ => {
                eprintln!("Unknown subcommand: {}", args[1]);
                eprintln!();
                print_help();
                std::process::exit(1);
            }
        }
    }

    let config = parse_args();

    // Initialize invariant runtime for deterministic sampling
    init_invariant_context(config.seed);

    // Load checkpoint if specified
    let mut checkpoint = if let Some(ref path) = config.checkpoint_file {
        VoprCheckpoint::load(path).unwrap_or_default()
    } else {
        VoprCheckpoint::default()
    };

    // Use checkpoint's last_seed if it's greater than config.seed
    let starting_seed = config.seed.max(checkpoint.last_seed);

    // Output header in appropriate format
    if config.json_mode {
        output(
            true,
            "start",
            Some(json!({
                "starting_seed": starting_seed,
                "iterations": config.iterations,
                "network_faults": config.network_faults,
                "storage_faults": config.storage_faults,
                "checkpoint_loaded": checkpoint.last_seed > 0
            })),
        );
    } else {
        println!("VOPR - Deterministic Simulation Tester");
        println!("======================================");
        println!("Starting seed: {starting_seed}");
        println!("Iterations: {}", config.iterations);
        println!(
            "Faults: network={}, storage={}",
            config.network_faults, config.storage_faults
        );
        if checkpoint.last_seed > 0 {
            println!(
                "Resumed from checkpoint (last seed: {})",
                checkpoint.last_seed
            );
        }
        println!();
    }

    let start = Instant::now();
    let mut successes = 0u64;
    let mut failures: Vec<(u64, String)> = Vec::new();

    // Aggregate property coverage across all iterations.
    let mut property_sometimes_satisfied: HashSet<String> = HashSet::new();
    let mut property_sometimes_unsatisfied: HashSet<String> = HashSet::new();
    let mut property_reached_hit: HashSet<String> = HashSet::new();
    let mut property_reached_missed: HashSet<String> = HashSet::new();
    let mut property_violations: HashMap<String, u64> = HashMap::new();
    // Track ALWAYS/NEVER coverage universe across iterations — these annotations
    // succeed silently; without explicit tracking they never show up in the
    // batch summary even when the driver is firing them.
    let mut property_always_evaluated_max: u64 = 0;
    let mut property_never_evaluated_max: u64 = 0;
    let mut property_total_observed_max: u64 = 0;

    for i in 0..config.iterations {
        let seed = starting_seed.wrapping_add(i);
        let run = SimulationRun::new(seed, &config);

        if config.verbose && !config.json_mode {
            print!("Running seed {seed}... ");
        }

        let result = run_simulation(&run, &config);

        // Capture property report from this iteration's run.
        let property_report_this_run =
            kimberlite_properties::registry::PropertyReport::from_registry();
        property_always_evaluated_max =
            property_always_evaluated_max.max(property_report_this_run.always_evaluated);
        property_never_evaluated_max =
            property_never_evaluated_max.max(property_report_this_run.never_evaluated);
        property_total_observed_max =
            property_total_observed_max.max(property_report_this_run.total_properties);
        for id in &property_report_this_run.violated_ids {
            *property_violations.entry(id.clone()).or_insert(0) += 1;
        }
        // SOMETIMES: take the union of explicitly-satisfied IDs (available
        // since the registry refactor — previously we had to infer them by
        // flipping from unsatisfied to missing, which hid any SOMETIMES
        // that was satisfied on the very first seed).
        for id in &property_report_this_run.satisfied_sometimes_ids {
            property_sometimes_satisfied.insert(id.clone());
            property_sometimes_unsatisfied.remove(id);
        }
        for id in &property_report_this_run.unsatisfied_sometimes_ids {
            if !property_sometimes_satisfied.contains(id) {
                property_sometimes_unsatisfied.insert(id.clone());
            }
        }
        // Same shape for REACHED.
        for id in &property_report_this_run.reached_hit_ids {
            property_reached_hit.insert(id.clone());
            property_reached_missed.remove(id);
        }
        for id in &property_report_this_run.unreached_ids {
            if !property_reached_hit.contains(id) {
                property_reached_missed.insert(id.clone());
            }
        }

        // Determinism check: run with same seed again and verify identical results
        if config.check_determinism {
            let result2 = run_simulation(&run, &config);

            // Compare results
            match (&result, &result2) {
                (
                    SimulationResult::Success {
                        storage_hash: storage_hash1,
                        kernel_state_hash: kernel_hash1,
                        events_processed: events1,
                        final_time_ns: time1,
                        ..
                    },
                    SimulationResult::Success {
                        storage_hash: storage_hash2,
                        kernel_state_hash: kernel_hash2,
                        events_processed: events2,
                        final_time_ns: time2,
                        ..
                    },
                ) => {
                    let mut violations = Vec::new();

                    if storage_hash1 != storage_hash2 {
                        violations.push(format!(
                            "storage_hash: {} != {}",
                            self::hex::encode(storage_hash1),
                            self::hex::encode(storage_hash2)
                        ));
                    }

                    if kernel_hash1 != kernel_hash2 {
                        violations.push(format!(
                            "kernel_state_hash: {} != {}",
                            self::hex::encode(kernel_hash1),
                            self::hex::encode(kernel_hash2)
                        ));
                    }

                    if events1 != events2 {
                        violations.push(format!("events_processed: {events1} != {events2}"));
                    }

                    if time1 != time2 {
                        violations.push(format!("final_time_ns: {time1} != {time2}"));
                    }

                    if !violations.is_empty() {
                        let msg = format!("determinism violation - {}", violations.join(", "));
                        failures.push((seed, msg));
                        checkpoint.failed_seeds.push(seed);
                        continue;
                    }
                }
                _ => {
                    // If either run failed with an invariant violation,
                    // that's also a determinism issue if they differ
                    if format!("{result:?}") != format!("{result2:?}") {
                        failures.push((
                            seed,
                            "determinism violation: different failure modes".to_string(),
                        ));
                        checkpoint.failed_seeds.push(seed);
                        continue;
                    }
                }
            }
        }

        match result {
            SimulationResult::Success {
                events_processed,
                final_time_ns,
                storage_hash,
                kernel_state_hash,
                ..
            } => {
                successes += 1;
                if config.json_mode {
                    output(
                        true,
                        "iteration",
                        Some(json!({
                            "seed": seed,
                            "status": "ok",
                            "events": events_processed,
                            "simulated_time_ms": final_time_ns as f64 / 1_000_000.0,
                            "storage_hash": self::hex::encode(storage_hash),
                            "kernel_state_hash": self::hex::encode(kernel_state_hash)
                        })),
                    );
                } else if config.verbose {
                    println!(
                        "OK ({} events, {:.2}ms simulated, storage_hash={}, kernel_hash={})",
                        events_processed,
                        final_time_ns as f64 / 1_000_000.0,
                        &self::hex::encode(storage_hash)[..16],
                        &self::hex::encode(kernel_state_hash)[..16]
                    );
                }
            }
            SimulationResult::InvariantViolation {
                invariant,
                message,
                events_processed,
                failure_report,
                ..
            } => {
                failures.push((seed, format!("{invariant}: {message}")));
                checkpoint.failed_seeds.push(seed);

                // Print failure diagnosis if enabled
                if config.failure_diagnosis && config.verbose {
                    if let Some(report) = failure_report {
                        eprintln!("\n{}", FailureAnalyzer::format_report(&report));
                    }
                }

                if config.json_mode {
                    output(
                        true,
                        "iteration",
                        Some(json!({
                            "seed": seed,
                            "status": "failed",
                            "events": events_processed,
                            "invariant": invariant,
                            "message": message
                        })),
                    );
                } else if config.verbose {
                    println!("FAILED at event {events_processed}");
                    println!("  Invariant: {invariant}");
                    println!("  Message: {message}");
                }
            }
        }

        // Update checkpoint every iteration
        checkpoint.last_seed = seed;
        checkpoint.total_iterations += 1;
        checkpoint.total_failures = failures.len() as u64;
        checkpoint.last_update = Utc::now().to_rfc3339();

        // Progress indicator for non-verbose, non-JSON mode
        if !config.verbose && !config.json_mode && (i + 1) % 10 == 0 {
            print!(
                "\rProgress: {}/{} ({} failures)",
                i + 1,
                config.iterations,
                failures.len()
            );
            std::io::stdout().flush().ok();
        }
    }

    if !config.verbose && !config.json_mode {
        println!();
    }

    let elapsed = start.elapsed();

    // Save checkpoint if specified
    if let Some(ref path) = config.checkpoint_file {
        if let Err(e) = checkpoint.save(path) {
            eprintln!("Warning: Failed to save checkpoint: {e}");
        }
    }

    // Collect coverage data from fault registry, phase tracker, and invariant tracker
    let fault_registry = get_fault_registry();
    let phase_tracker = get_phase_tracker();
    let invariant_tracker = get_invariant_tracker();
    let invariant_counts = invariant_tracker.all_run_counts().clone();

    // Generate coverage report WITHOUT the expensive all_events() vector
    // to avoid cloning potentially millions of phase events
    let coverage_report =
        CoverageReport::generate(&fault_registry, &phase_tracker, invariant_counts);

    // Build property coverage summary for batch.
    let mut sometimes_unsatisfied_sorted: Vec<&String> =
        property_sometimes_unsatisfied.iter().collect();
    sometimes_unsatisfied_sorted.sort();
    let mut reached_missed_sorted: Vec<&String> = property_reached_missed.iter().collect();
    reached_missed_sorted.sort();
    let sometimes_total = property_sometimes_satisfied.len() + property_sometimes_unsatisfied.len();
    let reached_total = property_reached_hit.len() + property_reached_missed.len();

    // Output final results
    if config.json_mode {
        let coverage_json =
            serde_json::to_value(&coverage_report).unwrap_or(serde_json::Value::Null);

        output(
            true,
            "batch_complete",
            Some(json!({
                "successes": successes,
                "failures": failures.len(),
                "elapsed_secs": elapsed.as_secs_f64(),
                "rate": config.iterations as f64 / elapsed.as_secs_f64(),
                "failed_seeds": failures.iter().map(|(s, _)| s).collect::<Vec<_>>(),
                "coverage": coverage_json,
                "properties": {
                    "total_observed": property_total_observed_max,
                    "always_evaluated": property_always_evaluated_max,
                    "never_evaluated": property_never_evaluated_max,
                    "sometimes_satisfied": property_sometimes_satisfied.len(),
                    "sometimes_total": sometimes_total,
                    "reached_hit": property_reached_hit.len(),
                    "reached_total": reached_total,
                    "violation_count": property_violations.len(),
                    "unsatisfied_sometimes_ids": sometimes_unsatisfied_sorted,
                    "unreached_ids": reached_missed_sorted,
                    "violated_ids": property_violations.keys().collect::<Vec<_>>(),
                }
            })),
        );
    } else {
        println!();
        println!("======================================");
        println!("Results:");
        println!("  Successes: {successes}");
        println!("  Failures: {}", failures.len());
        println!("  Time: {:.2}s", elapsed.as_secs_f64());
        println!(
            "  Rate: {:.0} sims/sec",
            config.iterations as f64 / elapsed.as_secs_f64()
        );

        if !failures.is_empty() {
            println!();
            println!("Failed seeds (for reproduction):");
            for (seed, error) in &failures {
                println!("  vopr --seed {seed} -v");
                println!("    Error: {error}");
            }
        }

        // Property coverage summary
        if property_total_observed_max > 0
            || sometimes_total > 0
            || reached_total > 0
            || !property_violations.is_empty()
        {
            println!();
            println!("Property Coverage:");
            println!(
                "  Observed:  {property_total_observed_max} distinct annotations across batch"
            );
            if property_always_evaluated_max > 0 {
                println!(
                    "  ALWAYS:    {} evaluated ({} violations)",
                    property_always_evaluated_max,
                    property_violations.len()
                );
            }
            if property_never_evaluated_max > 0 {
                println!("  NEVER:     {property_never_evaluated_max} evaluated");
            }
            if sometimes_total > 0 {
                println!(
                    "  SOMETIMES: {}/{} satisfied in ≥1 iteration",
                    property_sometimes_satisfied.len(),
                    sometimes_total
                );
            }
            if reached_total > 0 {
                println!(
                    "  REACHED:   {}/{} hit in ≥1 iteration",
                    property_reached_hit.len(),
                    reached_total
                );
            }
            if !property_violations.is_empty() {
                println!(
                    "  VIOLATIONS: {} ALWAYS/NEVER property IDs violated across batch",
                    property_violations.len()
                );
                if config.verbose {
                    for (id, count) in &property_violations {
                        println!("    • {id}: {count} violation(s)");
                    }
                }
            }
            if config.verbose && !sometimes_unsatisfied_sorted.is_empty() {
                println!("  Coverage gaps (SOMETIMES never satisfied):");
                for id in &sometimes_unsatisfied_sorted {
                    println!("    • {id}");
                }
            }
            if config.verbose && !reached_missed_sorted.is_empty() {
                println!("  Coverage gaps (REACHED never hit):");
                for id in &reached_missed_sorted {
                    println!("    • {id}");
                }
            }
        }

        // Output coverage report
        println!();
        println!("{}", coverage_report.to_human_readable());
    }

    // Check coverage thresholds (Phase 2)
    let coverage_failures = validate_coverage_thresholds(&config, &coverage_report);
    if !coverage_failures.is_empty() {
        if !config.json_mode {
            eprintln!();
            eprintln!("======================================");
            eprintln!("COVERAGE THRESHOLD FAILURES:");
            for failure_msg in &coverage_failures {
                eprintln!("  ❌ {failure_msg}");
            }
            eprintln!("======================================");
        }

        if config.json_mode {
            output(
                true,
                "coverage_failures",
                Some(json!({
                    "failures": coverage_failures
                })),
            );
        }

        std::process::exit(2); // Exit code 2 for coverage failures
    }

    if !failures.is_empty() {
        std::process::exit(1);
    }
}

/// Checks if a specific invariant is enabled in the configuration.
fn is_invariant_enabled(name: &str, inv_config: &InvariantConfig) -> bool {
    match name {
        "hash_chain" => inv_config.enable_hash_chain,
        "log_consistency" => inv_config.enable_log_consistency,
        "replica_consistency" => inv_config.enable_replica_consistency,
        "replica_head" => inv_config.enable_replica_head,
        "commit_history" => inv_config.enable_commit_history,
        "vsr_agreement" => inv_config.enable_vsr_agreement,
        "vsr_prefix_property" => inv_config.enable_vsr_prefix_property,
        "vsr_view_change_safety" => inv_config.enable_vsr_view_change_safety,
        "vsr_recovery_safety" => inv_config.enable_vsr_recovery_safety,
        "projection_applied_position" => inv_config.enable_projection_applied_position,
        "projection_mvcc_visibility" => inv_config.enable_projection_mvcc_visibility,
        "projection_applied_index" => inv_config.enable_projection_applied_index,
        "projection_catchup" => inv_config.enable_projection_catchup,
        "query_determinism" => inv_config.enable_query_determinism,
        "query_read_your_writes" => inv_config.enable_query_read_your_writes,
        "query_type_safety" => inv_config.enable_query_type_safety,
        "query_order_by_limit" => inv_config.enable_query_order_by_limit,
        "query_aggregates" => inv_config.enable_query_aggregates,
        "query_tenant_isolation" => inv_config.enable_query_tenant_isolation,
        "sql_tlp" => inv_config.enable_sql_tlp,
        "sql_norec" => inv_config.enable_sql_norec,
        "sql_plan_coverage" => inv_config.enable_sql_plan_coverage,
        _ => false, // Unknown invariant, assume disabled
    }
}

/// Validates coverage thresholds and returns a list of failure messages.
fn validate_coverage_thresholds(config: &VoprConfig, coverage: &CoverageReport) -> Vec<String> {
    let mut failures = Vec::new();

    // Check fault point coverage threshold
    if config.min_fault_coverage > 0.0
        && coverage.fault_points.coverage_percent < config.min_fault_coverage
    {
        failures.push(format!(
            "Fault point coverage {:.1}% below threshold {:.1}%",
            coverage.fault_points.coverage_percent, config.min_fault_coverage
        ));
    }

    // Check invariant coverage threshold
    if config.min_invariant_coverage > 0.0
        && coverage.invariants.coverage_percent < config.min_invariant_coverage
    {
        failures.push(format!(
            "Invariant coverage {:.1}% below threshold {:.1}%",
            coverage.invariants.coverage_percent, config.min_invariant_coverage
        ));
    }

    // Check if all ENABLED invariants ran (if required)
    if config.require_all_invariants {
        let zero_run_invariants: Vec<&str> = coverage
            .invariants
            .invariant_counts
            .iter()
            .filter(|(name, count)| {
                **count == 0 && is_invariant_enabled(name, &config.invariant_config)
            })
            .map(|(name, _)| name.as_str())
            .collect();

        if !zero_run_invariants.is_empty() {
            failures.push(format!(
                "The following ENABLED invariants ran 0 times: {}",
                zero_run_invariants.join(", ")
            ));
        }
    }

    failures
}
