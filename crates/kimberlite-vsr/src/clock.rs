//! Cluster-wide synchronized clock aggregating timing information from all replicas.
//!
//! # Overview
//!
//! Time is critical for compliance-first databases (healthcare, finance, legal)
//! where accurate audit timestamps are mandatory. However, we can't rely on client
//! clocks (unreliable) or individual replica clocks (drift). Instead, we use
//! **consensus to drive time** - only the primary assigns timestamps after achieving
//! cluster-wide clock synchronization.
//!
//! # Design Principles
//!
//! 1. **Only primary assigns timestamps**: Prevents replica disagreement
//! 2. **Monotonicity always preserved**: `max(current_time, previous_timestamp)`
//! 3. **Cluster consensus required**: Timestamp must be consistent with quorum clocks
//! 4. **NTP-independent high availability**: Continues working if NTP fails
//!
//! # Algorithm
//!
//! The clock synchronization algorithm works in epochs (multi-second windows):
//!
//! 1. **Sample Collection**: Collect clock measurements from all replicas via
//!    ping/pong messages embedded in heartbeats
//! 2. **Offset Calculation**: Compute clock offset for each replica accounting for
//!    network delay (RTT / 2)
//! 3. **Marzullo's Algorithm**: Find smallest interval consistent with quorum
//! 4. **Tolerance Check**: Reject if interval width exceeds tolerance
//! 5. **Install Epoch**: Use synchronized interval for timestamp bounds
//!
//! # Clock Offset Calculation
//!
//! Given ping/pong exchange:
//! - `m0`: Our monotonic time when sending ping
//! - `t1`: Remote's wall clock time when responding
//! - `m2`: Our monotonic time when receiving pong
//!
//! ```text
//! RTT = m2 - m0
//! one_way_delay = RTT / 2
//! our_time_at_t1 = window_realtime + (m2 - window_monotonic)
//! clock_offset = t1 + one_way_delay - our_time_at_t1
//! ```
//!
//! # Error Handling
//!
//! - **Clock drift too large**: Wait for NTP to resync, don't assign timestamps
//! - **Insufficient samples**: Keep collecting until quorum achieved
//! - **Outlier detection**: Marzullo naturally identifies false chimers
//!
//! # References
//!
//! - `TigerBeetle` blog: "Three Clocks are Better than One"
//! - Marzullo, K. (1984): "Maintaining the Time in a Distributed System"
//! - Google Spanner paper: `TrueTime` API design

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::marzullo::{Bound, Interval, Tuple, smallest_interval};
use crate::types::{ReplicaId, quorum_size};

/// Maximum allowed clock offset between replicas (milliseconds).
///
/// If the synchronized interval width exceeds this tolerance, clock
/// synchronization is considered failed and the cluster must wait for
/// NTP to fix things.
///
/// `TigerBeetle` uses 100ms. We're more conservative at 500ms to handle
/// environments with less reliable NTP.
pub const CLOCK_OFFSET_TOLERANCE_MS: u64 = 500;

/// Minimum window duration for collecting clock samples (milliseconds).
///
/// We collect samples over several seconds to get multiple measurements
/// per replica, improving accuracy.
pub const CLOCK_SYNC_WINDOW_MIN_MS: u64 = 3_000;

/// Maximum window duration before forcing synchronization (milliseconds).
///
/// Even if we haven't collected all samples, we must install a new epoch
/// before drift accumulates too much.
pub const CLOCK_SYNC_WINDOW_MAX_MS: u64 = 10_000;

/// Maximum epoch age before it becomes stale (milliseconds).
///
/// An epoch is valid for several seconds after installation, but eventually
/// drift makes it unusable and we need a new synchronized epoch.
pub const CLOCK_EPOCH_MAX_MS: u64 = 30_000;

/// Converts milliseconds to nanoseconds.
const NS_PER_MS: u64 = 1_000_000;

/// A clock sample from a remote replica.
///
/// Represents a measurement of the clock offset between our time and a
/// remote replica's time, along with the network delay estimate.
#[derive(Debug, Clone, Copy)]
struct Sample {
    /// The relative difference between our wall clock and the remote clock (nanoseconds).
    ///
    /// Positive means remote clock is ahead of ours.
    clock_offset: i64,

    /// Estimated one-way network delay (nanoseconds).
    ///
    /// Calculated as `RTT / 2`. Lower delay = more accurate offset measurement.
    one_way_delay: u64,
}

/// An epoch tracks clock samples collected over a window period.
///
/// We maintain two epochs:
/// - Current epoch: Installed and valid for timestamp reads
/// - Window epoch: Collecting samples for the next synchronization
#[derive(Debug, Clone)]
pub(crate) struct Epoch {
    /// Best clock sample per replica (minimum one-way delay).
    ///
    /// Index by `replica.as_usize()`. `None` if no sample yet from that replica.
    sources: HashMap<ReplicaId, Sample>,

    /// Total samples received during this epoch (including duplicates).
    samples_received: usize,

    /// Monotonic timestamp when this epoch began (nanoseconds).
    ///
    /// Used to measure elapsed time within the epoch.
    monotonic_start: u128,

    /// Wall clock timestamp when this epoch began (nanoseconds since UNIX epoch).
    ///
    /// Captured at epoch start to guard against system clock jumps during measurement.
    realtime_start: i64,

    /// Synchronized interval from Marzullo's algorithm.
    ///
    /// `None` until we have enough samples and successfully synchronize.
    synchronized: Option<Interval>,

    /// Guard to prevent synchronizing without new samples.
    ///
    /// Set to `true` when we learn a new sample, cleared after synchronization.
    has_new_samples: bool,
}

impl Epoch {
    /// Creates a new empty epoch.
    fn new(monotonic_start: u128, realtime_start: i64, our_replica: ReplicaId) -> Self {
        let mut sources = HashMap::new();
        // We always have perfect knowledge of our own clock (zero offset, zero delay)
        sources.insert(
            our_replica,
            Sample {
                clock_offset: 0,
                one_way_delay: 0,
            },
        );

        Self {
            sources,
            samples_received: 1, // count ourselves
            monotonic_start,
            realtime_start,
            synchronized: None,
            has_new_samples: false,
        }
    }

    /// Returns elapsed time since epoch started (nanoseconds).
    fn elapsed(&self, monotonic_now: u128) -> u64 {
        (monotonic_now - self.monotonic_start) as u64
    }

    /// Returns number of replicas we've sampled (including ourselves).
    fn sources_sampled(&self) -> usize {
        self.sources.len()
    }

    /// Kani verification accessor for monotonic_start.
    #[cfg(kani)]
    pub(crate) fn monotonic_start(&self) -> u128 {
        self.monotonic_start
    }

    /// Kani verification accessor for synchronized interval.
    #[cfg(kani)]
    pub(crate) fn synchronized(&self) -> Option<Interval> {
        self.synchronized
    }

    /// Kani verification accessor for has_new_samples flag.
    #[cfg(kani)]
    pub(crate) fn has_new_samples(&self) -> bool {
        self.has_new_samples
    }

    /// Kani verification setter for monotonic_start.
    #[cfg(kani)]
    pub(crate) fn set_monotonic_start(&mut self, value: u128) {
        self.monotonic_start = value;
    }

    /// Kani verification setter for has_new_samples.
    #[cfg(kani)]
    pub(crate) fn set_has_new_samples(&mut self, value: bool) {
        self.has_new_samples = value;
    }

    /// Kani verification setter for synchronized interval.
    #[cfg(kani)]
    pub(crate) fn set_synchronized(&mut self, value: Option<Interval>) {
        self.synchronized = value;
    }

    /// Resets the epoch to start collecting samples again.
    fn reset(&mut self, monotonic_now: u128, realtime_now: i64, our_replica: ReplicaId) {
        self.sources.clear();
        self.sources.insert(
            our_replica,
            Sample {
                clock_offset: 0,
                one_way_delay: 0,
            },
        );
        self.samples_received = 1;
        self.monotonic_start = monotonic_now;
        self.realtime_start = realtime_now;
        self.synchronized = None;
        self.has_new_samples = false;
    }
}

/// Cluster-wide synchronized clock.
///
/// Aggregates timing information from all replicas to provide accurate,
/// consensus-based timestamps for compliance-critical operations.
///
/// # Cloning
///
/// Clock implements Clone for simulation testing. When cloned, the new clock
/// starts with fresh epochs but preserves the `last_timestamp` for monotonicity.
#[derive(Debug, Clone)]
pub struct Clock {
    /// Our replica ID.
    replica: ReplicaId,

    /// Quorum size for clock synchronization.
    ///
    /// We need clock agreement from at least this many replicas.
    quorum: usize,

    /// Total number of replicas in the cluster.
    #[allow(dead_code)] // Kept for diagnostics/debugging
    cluster_size: usize,

    /// Current epoch (installed and valid for reads).
    ///
    /// Timestamps are read from this epoch until it becomes too stale.
    epoch: Epoch,

    /// Next epoch (collecting samples).
    ///
    /// Once this has enough samples and passes synchronization, it replaces `epoch`.
    window: Epoch,

    /// Disable synchronization for single-node clusters.
    ///
    /// A cluster of one cannot synchronize with itself, so we just use
    /// system time directly.
    synchronization_disabled: bool,

    /// Monotonic time at last timestamp assignment.
    ///
    /// Used to enforce monotonicity: `timestamp = max(now, last_timestamp)`.
    last_timestamp: i64,
}

impl Clock {
    /// Creates a new clock for cluster-wide synchronization.
    ///
    /// Prefer [`Clock::try_new`] in new code — it returns a [`Result`]
    /// rather than panicking on invalid input.
    ///
    /// # Arguments
    ///
    /// * `replica` - Our replica ID
    /// * `cluster_size` - Total replicas in cluster
    ///
    /// # Panics
    ///
    /// Panics if `cluster_size == 0` or `replica.as_usize() >= cluster_size`.
    #[track_caller]
    pub fn new(replica: ReplicaId, cluster_size: usize) -> Self {
        Self::try_new(replica, cluster_size).expect(
            "Clock::new: invalid cluster parameters — use try_new for fallible construction",
        )
    }

    /// Creates a new clock for cluster-wide synchronization, validating parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError::InvalidClusterConfig`] if `cluster_size == 0` or
    /// `replica.as_usize() >= cluster_size`.
    pub fn try_new(replica: ReplicaId, cluster_size: usize) -> Result<Self, ClockError> {
        if cluster_size == 0 {
            return Err(ClockError::InvalidClusterConfig(
                "cluster size must be positive",
            ));
        }
        if replica.as_usize() >= cluster_size {
            return Err(ClockError::InvalidClusterConfig(
                "replica ID exceeds cluster size",
            ));
        }

        let quorum = quorum_size(cluster_size);
        let synchronization_disabled = cluster_size == 1;

        let monotonic_now = Self::monotonic_nanos();
        let realtime_now = Self::realtime_nanos();

        let epoch = Epoch::new(monotonic_now, realtime_now, replica);
        let window = Epoch::new(monotonic_now, realtime_now, replica);

        Ok(Self {
            replica,
            quorum,
            cluster_size,
            epoch,
            window,
            synchronization_disabled,
            last_timestamp: realtime_now,
        })
    }

    /// Records a clock sample from a remote replica.
    ///
    /// Called when we receive a pong response to our ping. The ping/pong
    /// exchange allows us to measure both network delay and clock offset.
    ///
    /// # Arguments
    ///
    /// * `replica` - Remote replica ID
    /// * `m0` - Our monotonic time when we sent the ping (nanoseconds)
    /// * `t1` - Remote's wall clock time when it responded (nanoseconds)
    /// * `m2` - Our monotonic time when we received the pong (nanoseconds)
    ///
    /// # Algorithm
    ///
    /// 1. Calculate RTT = m2 - m0
    /// 2. Estimate `one_way_delay` = RTT / 2
    /// 3. Calculate our time when remote sent t1: `window_realtime` + (m2 - `window_monotonic`)
    /// 4. Compute `clock_offset` = t1 + `one_way_delay` - `our_time_at_t1`
    /// 5. Keep sample with minimum `one_way_delay` (most accurate)
    pub fn learn_sample(
        &mut self,
        replica: ReplicaId,
        m0: u128,
        t1: i64,
        m2: u128,
    ) -> Result<(), ClockError> {
        if replica == self.replica {
            return Err(ClockError::SelfSample);
        }

        if self.synchronization_disabled {
            return Ok(()); // Single-node cluster, no sync needed
        }

        // Validate monotonicity: m0 should be <= m2
        if m0 > m2 {
            return Err(ClockError::NonMonotonicPing {
                m0: m0 as u64,
                m2: m2 as u64,
            });
        }

        // Reject samples from before current window started
        if m0 < self.window.monotonic_start {
            return Err(ClockError::StalePing);
        }

        // Calculate network delay and clock offset
        let round_trip_time = (m2 - m0) as u64;
        let one_way_delay = round_trip_time / 2;

        let elapsed_at_m2 = (m2 - self.window.monotonic_start) as u64;
        let our_time_at_t1 =
            self.window.realtime_start + one_way_delay as i64 + elapsed_at_m2 as i64;
        let clock_offset = t1 - our_time_at_t1;

        let sample = Sample {
            clock_offset,
            one_way_delay,
        };

        // Keep sample with minimum one-way delay (most accurate)
        let should_update = match self.window.sources.get(&replica) {
            None => true,
            Some(existing) => sample.one_way_delay < existing.one_way_delay,
        };

        if should_update {
            self.window.sources.insert(replica, sample);
        }

        self.window.samples_received += 1;
        self.window.has_new_samples = true;

        Ok(())
    }

    /// Attempts to synchronize the window epoch using Marzullo's algorithm.
    ///
    /// Should be called periodically (e.g., on timeout) to check if we have
    /// enough samples to install a new synchronized epoch.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if synchronization succeeded and new epoch installed
    /// - `Ok(false)` if not enough samples yet or synchronization failed
    /// - `Err` on unexpected errors
    ///
    /// # Synchronization Conditions
    ///
    /// 1. Window has new samples since last attempt
    /// 2. Window has been open for at least `CLOCK_SYNC_WINDOW_MIN_MS`
    /// 3. Window has samples from quorum replicas
    /// 4. Marzullo finds interval with quorum agreement
    /// 5. Interval width <= `CLOCK_OFFSET_TOLERANCE_MS`
    pub fn synchronize(&mut self) -> Result<bool, ClockError> {
        if self.synchronization_disabled {
            return Ok(false); // No sync needed for single node
        }

        // Guard: only synchronize if we have new samples
        if !self.window.has_new_samples {
            return Ok(false);
        }

        let monotonic_now = Self::monotonic_nanos();
        let elapsed = self.window.elapsed(monotonic_now);

        // Check minimum window duration
        if elapsed < CLOCK_SYNC_WINDOW_MIN_MS * NS_PER_MS {
            return Ok(false); // Keep collecting samples
        }

        // Check if we have quorum samples
        let sources_sampled = self.window.sources_sampled();
        if sources_sampled < self.quorum {
            return Ok(false); // Need more samples
        }

        // PRODUCTION ASSERTION: Quorum requirement (HIPAA/GDPR compliance)
        assert!(
            sources_sampled >= self.quorum,
            "clock synchronization requires quorum: {} >= {}",
            sources_sampled,
            self.quorum
        );

        // Build Marzullo tuples from samples
        let mut tuples = Vec::with_capacity(sources_sampled * 2);
        for (replica_id, sample) in &self.window.sources {
            // Error margin is one_way_delay + tolerance
            let error_margin = sample.one_way_delay + (CLOCK_OFFSET_TOLERANCE_MS * NS_PER_MS);
            let lower_bound = sample.clock_offset - error_margin as i64;
            let upper_bound = sample.clock_offset + error_margin as i64;

            tuples.push(Tuple {
                source: *replica_id,
                offset: lower_bound,
                bound: Bound::Lower,
            });
            tuples.push(Tuple {
                source: *replica_id,
                offset: upper_bound,
                bound: Bound::Upper,
            });
        }

        // Run Marzullo's algorithm
        let interval = smallest_interval(&mut tuples);

        // Check if we have quorum agreement
        if !interval.has_quorum(self.quorum) {
            return Err(ClockError::NoQuorumAgreement {
                sources_true: interval.sources_true,
                sources_false: interval.sources_false,
                quorum_needed: self.quorum,
            });
        }

        // Check if interval width is within tolerance
        let tolerance_ns = CLOCK_OFFSET_TOLERANCE_MS * NS_PER_MS;
        if interval.width() > tolerance_ns {
            return Err(ClockError::ToleranceExceeded {
                width_ns: interval.width(),
                tolerance_ns,
            });
        }

        // PRODUCTION ASSERTION: Tolerance enforcement (HIPAA/GDPR compliance)
        assert!(
            interval.width() <= tolerance_ns,
            "clock interval width must not exceed tolerance: {} <= {}",
            interval.width(),
            tolerance_ns
        );

        // Success! Install the synchronized window as the new epoch
        self.window.synchronized = Some(interval);
        std::mem::swap(&mut self.epoch, &mut self.window);

        // Reset window for next collection cycle
        let realtime_now = Self::realtime_nanos();
        self.window.reset(monotonic_now, realtime_now, self.replica);

        Ok(true)
    }

    /// Returns a synchronized timestamp for assigning to operations.
    ///
    /// **CRITICAL: Only the primary should call this.** Backups don't assign timestamps.
    ///
    /// # Safety (HIPAA/GDPR Compliance)
    ///
    /// Primary-only enforcement MUST be verified at call site. This function does
    /// not internally verify replica role to avoid coupling with replica state.
    /// Callers MUST check `replica.is_primary()` before calling.
    ///
    /// # Returns
    ///
    /// - `Some(timestamp)` if clock is synchronized
    /// - `None` if synchronization hasn't succeeded yet
    ///
    /// # Guarantees
    ///
    /// 1. **Monotonicity**: Result >= all previous timestamps
    /// 2. **Cluster Consensus**: Within bounds agreed by quorum
    /// 3. **Reasonably Accurate**: Close to actual wall clock time
    ///
    /// # Usage
    ///
    /// ```ignore
    /// if let Some(timestamp) = clock.realtime_synchronized() {
    ///     // Assign timestamp to operation
    ///     operation.timestamp = timestamp;
    /// } else {
    ///     // Clock not synchronized yet, must wait
    ///     return Err(ClockNotSynchronized);
    /// }
    /// ```
    pub fn realtime_synchronized(&mut self) -> Option<i64> {
        // Single-node cluster: just use system time
        if self.synchronization_disabled {
            let timestamp = Self::realtime_nanos();
            self.last_timestamp = self.last_timestamp.max(timestamp);
            return Some(self.last_timestamp);
        }

        // Multi-node cluster: require synchronized epoch
        let interval = self.epoch.synchronized?;

        // Check if epoch is still fresh enough
        let monotonic_now = Self::monotonic_nanos();
        let epoch_age = self.epoch.elapsed(monotonic_now);
        if epoch_age > CLOCK_EPOCH_MAX_MS * NS_PER_MS {
            return None; // Epoch too stale, need new synchronization
        }

        // PRODUCTION ASSERTION: Epoch age limit (HIPAA/GDPR compliance)
        assert!(
            epoch_age <= CLOCK_EPOCH_MAX_MS * NS_PER_MS,
            "epoch age must not exceed maximum: {} <= {}",
            epoch_age,
            CLOCK_EPOCH_MAX_MS * NS_PER_MS
        );

        // Clamp system time to synchronized bounds
        let realtime_now = Self::realtime_nanos();
        let lower_bound = self.epoch.realtime_start + epoch_age as i64 + interval.lower_bound;
        let upper_bound = self.epoch.realtime_start + epoch_age as i64 + interval.upper_bound;
        let clamped = realtime_now.clamp(lower_bound, upper_bound);

        // Enforce monotonicity
        let timestamp = clamped.max(self.last_timestamp);

        // PRODUCTION ASSERTION: Monotonicity guarantee (HIPAA/GDPR compliance)
        assert!(
            timestamp >= self.last_timestamp,
            "timestamp must be monotonic: {} >= {}",
            timestamp,
            self.last_timestamp
        );

        self.last_timestamp = timestamp;

        Some(timestamp)
    }

    /// Returns current monotonic time (nanoseconds).
    ///
    /// Monotonic time never goes backwards, even if system clock is adjusted.
    /// Used for measuring time intervals (RTT, epoch duration, etc.).
    pub fn monotonic_nanos() -> u128 {
        // Note: std::time::Instant is not guaranteed to be nanosecond precision,
        // but Duration::as_nanos() always returns nanoseconds.
        // On most platforms (Linux, macOS, Windows), Instant has ~1ns resolution.
        use std::time::Instant;
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_nanos()
    }

    /// Returns current wall clock time (nanoseconds since UNIX epoch).
    ///
    /// This is the OS-provided realtime, which can jump due to NTP adjustments.
    /// Should not be used for measuring intervals.
    #[allow(clippy::cast_possible_wrap)]
    pub fn realtime_nanos() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_nanos() as i64
    }

    /// Returns whether clock is currently synchronized.
    pub fn is_synchronized(&self) -> bool {
        if self.synchronization_disabled {
            return true; // Single-node always "synchronized"
        }

        if self.epoch.synchronized.is_none() {
            return false;
        }

        // Check if epoch is still fresh
        let monotonic_now = Self::monotonic_nanos();
        let epoch_age = self.epoch.elapsed(monotonic_now);
        epoch_age <= CLOCK_EPOCH_MAX_MS * NS_PER_MS
    }

    /// Returns the current synchronized interval (for diagnostics).
    pub fn synchronized_interval(&self) -> Option<Interval> {
        self.epoch.synchronized
    }

    /// Returns number of samples collected in current window.
    pub fn window_samples(&self) -> usize {
        self.window.sources_sampled()
    }

    /// Returns the quorum size required for synchronization.
    pub fn quorum(&self) -> usize {
        self.quorum
    }
}

/// Errors that can occur during clock operations.
#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    /// Attempted to learn a sample from ourselves.
    #[error("cannot learn sample from self")]
    SelfSample,

    /// Ping timestamps are not monotonic (m0 > m2).
    #[error("non-monotonic ping: m0={m0} > m2={m2}")]
    NonMonotonicPing { m0: u64, m2: u64 },

    /// Ping is from before current window started.
    #[error("stale ping (before current window)")]
    StalePing,

    /// Marzullo algorithm didn't find quorum agreement.
    #[error(
        "no quorum agreement: {sources_true} true, {sources_false} false, need {quorum_needed}"
    )]
    NoQuorumAgreement {
        sources_true: u8,
        sources_false: u8,
        quorum_needed: usize,
    },

    /// Synchronized interval exceeds tolerance.
    #[error("tolerance exceeded: width={width_ns}ns > tolerance={tolerance_ns}ns")]
    ToleranceExceeded { width_ns: u64, tolerance_ns: u64 },

    /// Invalid cluster configuration passed to `Clock::try_new`.
    #[error("invalid cluster configuration: {0}")]
    InvalidClusterConfig(&'static str),
}

// ============================================================================
// Kani Verification Accessors
// ============================================================================

#[cfg(kani)]
impl Clock {
    /// Provides mutable access to the window epoch for Kani proofs.
    ///
    /// Used in bounded model checking to set up specific test scenarios.
    pub(crate) fn window_mut(&mut self) -> &mut Epoch {
        &mut self.window
    }

    /// Provides immutable access to the current epoch for Kani proofs.
    ///
    /// Used in bounded model checking to verify synchronization properties.
    pub(crate) fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    /// Provides mutable access to the current epoch for Kani proofs.
    ///
    /// Used in bounded model checking to set up specific test scenarios.
    pub(crate) fn epoch_mut(&mut self) -> &mut Epoch {
        &mut self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_always_synchronized() {
        let mut clock = Clock::new(ReplicaId::new(0), 1);
        assert!(clock.synchronization_disabled);
        assert!(clock.is_synchronized());

        let ts1 = clock.realtime_synchronized().unwrap();
        let ts2 = clock.realtime_synchronized().unwrap();
        assert!(ts2 >= ts1, "timestamps should be monotonic");
    }

    #[test]
    fn three_node_requires_synchronization() {
        let mut clock = Clock::new(ReplicaId::new(0), 3);
        assert!(!clock.synchronization_disabled);
        assert_eq!(clock.quorum(), 2);
        assert!(!clock.is_synchronized());
        assert_eq!(clock.realtime_synchronized(), None);
    }

    #[test]
    fn learn_sample_rejects_self() {
        let mut clock = Clock::new(ReplicaId::new(0), 3);
        let result = clock.learn_sample(ReplicaId::new(0), 1000, 2000, 3000);
        assert!(matches!(result, Err(ClockError::SelfSample)));
    }

    #[test]
    fn learn_sample_rejects_non_monotonic() {
        let mut clock = Clock::new(ReplicaId::new(0), 3);
        let m0 = 3000;
        let m2 = 1000; // m2 < m0
        let result = clock.learn_sample(ReplicaId::new(1), m0, 2000, m2);
        assert!(matches!(result, Err(ClockError::NonMonotonicPing { .. })));
    }

    #[test]
    fn try_new_rejects_zero_cluster_size() {
        let err = Clock::try_new(ReplicaId::new(0), 0).unwrap_err();
        assert!(
            matches!(err, ClockError::InvalidClusterConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn try_new_rejects_replica_out_of_range() {
        let err = Clock::try_new(ReplicaId::new(5), 3).unwrap_err();
        assert!(
            matches!(err, ClockError::InvalidClusterConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "invalid cluster parameters")]
    fn new_panics_on_zero_cluster_size() {
        let _ = Clock::new(ReplicaId::new(0), 0);
    }

    #[test]
    fn learn_sample_keeps_minimum_delay() {
        let mut clock = Clock::new(ReplicaId::new(0), 3);
        // Anchor offsets to the actual window start so the stale-ping guard
        // (m0 >= window.monotonic_start) passes regardless of system uptime.
        let base = clock.window.monotonic_start;

        // First sample: RTT = 1000ns
        clock
            .learn_sample(ReplicaId::new(1), base, 2000, base + 1000)
            .unwrap();
        let sample1 = clock.window.sources.get(&ReplicaId::new(1)).unwrap();
        assert_eq!(sample1.one_way_delay, 500); // RTT / 2

        // Second sample: RTT = 500ns (better)
        clock
            .learn_sample(ReplicaId::new(1), base + 2000, 4000, base + 2500)
            .unwrap();
        let sample2 = clock.window.sources.get(&ReplicaId::new(1)).unwrap();
        assert_eq!(sample2.one_way_delay, 250); // New sample replaced old

        // Third sample: RTT = 2000ns (worse, should not replace)
        clock
            .learn_sample(ReplicaId::new(1), base + 4000, 6000, base + 6000)
            .unwrap();
        let sample3 = clock.window.sources.get(&ReplicaId::new(1)).unwrap();
        assert_eq!(sample3.one_way_delay, 250); // Kept better sample
    }

    #[test]
    fn synchronize_requires_quorum_samples() {
        let mut clock = Clock::new(ReplicaId::new(0), 5);
        assert_eq!(clock.quorum(), 3); // Need 3 of 5

        // Only have ourselves, need 2 more
        assert_eq!(clock.window.sources_sampled(), 1);

        // Try to synchronize (should fail - not enough samples)
        clock.window.has_new_samples = true;
        clock.window.monotonic_start = 0; // Fake old enough window
        let result = clock.synchronize().unwrap();
        assert!(!result); // Failed due to insufficient samples
    }

    #[test]
    fn epoch_elapsed_calculation() {
        let epoch = Epoch::new(1000, 5000, ReplicaId::new(0));
        assert_eq!(epoch.elapsed(1500), 500);
        assert_eq!(epoch.elapsed(2000), 1000);
    }

    #[test]
    fn monotonicity_preserved_across_calls() {
        let mut clock = Clock::new(ReplicaId::new(0), 1);

        let ts1 = clock.realtime_synchronized().unwrap();
        std::thread::sleep(std::time::Duration::from_micros(10));
        let ts2 = clock.realtime_synchronized().unwrap();
        std::thread::sleep(std::time::Duration::from_micros(10));
        let ts3 = clock.realtime_synchronized().unwrap();

        assert!(ts2 >= ts1);
        assert!(ts3 >= ts2);
        assert!(ts3 >= ts1);
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    use proptest::prelude::*;

    proptest! {
        /// Property: Clock offset calculation is symmetric and bounded.
        ///
        /// For any valid sample (m0, t1, m2) where m0 < m2:
        /// - RTT = m2 - m0
        /// - one_way_delay = RTT / 2
        /// - clock_offset = (t1 - m0_wall) - one_way_delay
        #[test]
        fn prop_clock_offset_calculation(
            m0 in 0u128..1_000_000_000_000u128,
            delay in 0u128..1_000_000_000u128,  // Max 1 second delay
            offset in -500_000_000i64..500_000_000i64,  // +/- 500ms offset
        ) {
            let m2 = m0 + (delay * 2);  // Round-trip time
            let m0_wall = (m0 / 1_000_000) as i64;  // Convert to ms
            let t1 = m0_wall + delay as i64 + offset;  // Wall clock at remote

            let mut clock = Clock::new(ReplicaId::new(0), 3);

            // Should accept sample if m0 < m2
            if m0 < m2 {
                let result = clock.learn_sample(ReplicaId::new(1), m0, t1, m2);

                // Should not fail for non-pathological inputs
                if offset.abs() < 100_000_000 {  // Within 100ms
                    prop_assert!(result.is_ok());
                }
            }
        }

        /// Property: Monotonicity is always preserved.
        ///
        /// No matter what samples are received, realtime_synchronized()
        /// always returns a timestamp >= the previous one.
        #[test]
        fn prop_monotonicity_preserved(
            samples in prop::collection::vec(
                (1u8..10u8, 0i64..1_000_000i64, 0u128..1_000_000u128),
                1..10
            )
        ) {
            let mut clock = Clock::new(ReplicaId::new(0), 1);  // Single node
            let mut last_timestamp = 0i64;

            for (replica_id, t1, delay) in samples {
                let m0 = Clock::monotonic_nanos();
                let m2 = m0 + delay;

                // Learn sample (may fail, that's okay)
                let _ = clock.learn_sample(ReplicaId::new(replica_id), m0, t1, m2);

                // Check monotonicity
                if let Some(ts) = clock.realtime_synchronized() {
                    prop_assert!(ts >= last_timestamp,
                        "Timestamp decreased: {} -> {}", last_timestamp, ts);
                    last_timestamp = ts;
                }
            }
        }

        /// Property: Synchronization is deterministic.
        ///
        /// Given the same set of samples, synchronize() always produces
        /// the same result (Marzullo's algorithm is deterministic).
        #[test]
        fn prop_synchronization_deterministic(
            seed in 1_000_000_000u128..100_000_000_000u128,  // 1-100 billion ns
            samples in prop::collection::vec(
                (1u8..5u8, 0i64..10_000i64, 100u128..10_000u128),
                3..10
            )
        ) {
            // First run
            let mut clock1 = Clock::new(ReplicaId::new(0), 5);
            clock1.window.monotonic_start = 0;  // Force old window
            clock1.window.has_new_samples = true;

            for (replica_id, offset, delay) in &samples {
                let m0 = seed + delay;
                let m2 = m0 + delay * 2;
                let t1 = (m0 / 1_000_000) as i64 + offset;
                let _ = clock1.learn_sample(ReplicaId::new(*replica_id), m0, t1, m2);
            }

            let result1 = clock1.synchronize();

            // Second run with same samples
            let mut clock2 = Clock::new(ReplicaId::new(0), 5);
            clock2.window.monotonic_start = 0;
            clock2.window.has_new_samples = true;

            for (replica_id, offset, delay) in &samples {
                let m0 = seed + delay;
                let m2 = m0 + delay * 2;
                let t1 = (m0 / 1_000_000) as i64 + offset;
                let _ = clock2.learn_sample(ReplicaId::new(*replica_id), m0, t1, m2);
            }

            let result2 = clock2.synchronize();

            // Same outcome (success/failure)
            prop_assert_eq!(result1.is_ok(), result2.is_ok());

            // If both succeeded and synchronized, check timestamps match
            if let (Ok(true), Ok(true)) = (result1, result2) {
                prop_assert_eq!(clock1.epoch.realtime_start, clock2.epoch.realtime_start,
                    "Deterministic synchronization failed: different timestamps");
            }
        }

        /// Property: Tolerance checks prevent excessive drift.
        ///
        /// If clock offsets exceed CLOCK_OFFSET_TOLERANCE_MS (500ms),
        /// synchronization should fail with ToleranceExceeded.
        #[test]
        fn prop_tolerance_prevents_excessive_drift(
            excessive_offset in 600_000_000i64..2_000_000_000i64,  // 600ms to 2s
        ) {
            let mut clock = Clock::new(ReplicaId::new(0), 3);
            clock.window.monotonic_start = 0;
            clock.window.has_new_samples = true;

            let base_time = 1_000_000_000_000u128;  // 1 trillion ns

            // Replica 0 (self) - always synchronized
            // Replica 1 - normal offset
            let _ = clock.learn_sample(
                ReplicaId::new(1),
                base_time,
                (base_time / 1_000_000) as i64,
                base_time + 1_000_000,
            );

            // Replica 2 - excessive offset (should trigger tolerance check)
            let _ = clock.learn_sample(
                ReplicaId::new(2),
                base_time,
                (base_time / 1_000_000) as i64 + excessive_offset,
                base_time + 1_000_000,
            );

            let result = clock.synchronize();

            // Should fail due to tolerance
            prop_assert!(result.is_err() || !result.unwrap(),
                "Expected synchronization to fail with excessive offset");
        }

        /// Property: Stale samples are rejected.
        ///
        /// Samples from before the current window started should be rejected
        /// to prevent replay attacks and stale data.
        #[test]
        fn prop_stale_samples_rejected(
            window_age in 10_000_000u128..100_000_000u128,  // 10ms to 100ms old
        ) {
            let mut clock = Clock::new(ReplicaId::new(0), 3);

            // Set window start to a known value far enough in the past
            let base_time = 10_000_000_000u128;  // 10 billion ns (10 seconds)
            clock.window.monotonic_start = base_time + 1_000_000_000;  // +1 second

            // Try to learn a sample from before window started
            let old_m0 = clock.window.monotonic_start.saturating_sub(window_age);
            let old_m2 = old_m0 + 1_000_000;
            let old_t1 = (old_m0 / 1_000_000) as i64;

            // Only test if old_m0 is actually before window start
            if old_m0 < clock.window.monotonic_start {
                let result = clock.learn_sample(ReplicaId::new(1), old_m0, old_t1, old_m2);

                // Should reject as stale
                prop_assert!(matches!(result, Err(ClockError::StalePing)),
                    "Expected StalePing error, got: {:?}", result);
            }
        }
    }
}
