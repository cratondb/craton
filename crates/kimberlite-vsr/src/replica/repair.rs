//! Repair protocol handlers.
//!
//! This module implements transparent repair and Protocol-Aware Recovery (PAR)
//! NACK handling for safe log truncation.
//!
//! # Transparent Repair
//!
//! When a replica detects missing or corrupt log entries:
//! 1. Sends `RepairRequest` for the needed range
//! 2. Healthy replicas respond with `RepairResponse` containing entries
//! 3. Corrupt replicas respond with `Nack` indicating they can't help
//! 4. Apply received entries after checksum verification
//!
//! # Protocol-Aware Recovery (PAR)
//!
//! PAR ensures safe log truncation by distinguishing between:
//! - **`NotSeen`**: The operation was never received (safe to truncate)
//! - **`SeenButCorrupt`**: The operation was seen but is now corrupt (NOT safe)
//!
//! To safely truncate an operation, we need a NACK quorum (f+1 replicas)
//! where ALL NACKs report `NotSeen`. If ANY replica reports `SeenButCorrupt`,
//! the operation may have been committed and cannot be truncated.
//!
//! This is critical for preventing data loss: without PAR, a replica might
//! truncate an operation that was committed but not yet replicated to
//! enough replicas.

use std::collections::HashMap;

use crate::message::{MessagePayload, Nack, NackReason, RepairRequest, RepairResponse};
use crate::types::{CommitNumber, Nonce, OpNumber, ReplicaId, ReplicaStatus};

use super::{ReplicaOutput, ReplicaState, msg_to};

// ============================================================================
// Repair State
// ============================================================================

/// State tracked during a repair operation.
#[derive(Debug, Clone)]
pub struct RepairState {
    /// Nonce for matching responses to our request.
    pub nonce: Nonce,

    /// Range of operations being repaired (inclusive start, exclusive end).
    pub op_range_start: OpNumber,
    pub op_range_end: OpNumber,

    /// Target replica we sent the repair request to (Phase 2: for budget tracking).
    pub target_replica: Option<ReplicaId>,

    /// Repair responses received.
    pub responses: HashMap<ReplicaId, RepairResponse>,

    /// NACKs received (for PAR).
    pub nacks: HashMap<ReplicaId, Nack>,
}

impl RepairState {
    /// Creates a new repair state.
    ///
    /// Prefer [`RepairState::try_new`] in new code.
    ///
    /// # Panics
    ///
    /// Panics if `op_range_start >= op_range_end` (empty repair range).
    #[track_caller]
    pub fn new(nonce: Nonce, op_range_start: OpNumber, op_range_end: OpNumber) -> Self {
        Self::try_new(nonce, op_range_start, op_range_end)
            .expect("RepairState::new: invalid op range — use try_new for fallible construction")
    }

    /// Creates a new repair state, validating the op range is non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`crate::VsrError::InvalidRepairRange`] if
    /// `op_range_start >= op_range_end`.
    pub fn try_new(
        nonce: Nonce,
        op_range_start: OpNumber,
        op_range_end: OpNumber,
    ) -> crate::VsrResult<Self> {
        if op_range_start >= op_range_end {
            return Err(crate::VsrError::InvalidRepairRange {
                start: op_range_start.as_u64(),
                end: op_range_end.as_u64(),
            });
        }
        Ok(Self {
            nonce,
            op_range_start,
            op_range_end,
            target_replica: None,
            responses: HashMap::new(),
            nacks: HashMap::new(),
        })
    }

    /// Sets the target replica (for budget tracking).
    pub fn set_target_replica(&mut self, replica: ReplicaId) {
        self.target_replica = Some(replica);
    }

    /// Returns the total number of replies (responses + nacks).
    pub fn total_replies(&self) -> usize {
        self.responses.len() + self.nacks.len()
    }

    /// Returns the number of NACKs with `NotSeen` reason.
    pub fn not_seen_count(&self) -> usize {
        self.nacks
            .values()
            .filter(|n| n.reason == NackReason::NotSeen)
            .count()
    }

    /// Returns true if any NACK indicates the operation was seen.
    pub fn any_seen(&self) -> bool {
        self.nacks
            .values()
            .any(|n| n.reason == NackReason::SeenButCorrupt)
    }

    /// Returns true if we have enough `NotSeen` NACKs for safe truncation.
    ///
    /// Requires f+1 replicas to report `NotSeen`, where f is max failures.
    pub fn can_safely_truncate(&self, max_failures: usize) -> bool {
        let nack_quorum = max_failures + 1;
        self.not_seen_count() >= nack_quorum && !self.any_seen()
    }
}

impl ReplicaState {
    // ========================================================================
    // Repair Initiation
    // ========================================================================

    /// Initiates repair for a range of operations.
    ///
    /// Returns the new state and a `RepairRequest` to a selected replica.
    ///
    /// Phase 2: Uses `RepairBudget` to select the best replica (EWMA-based)
    /// and enforces inflight limits to prevent repair storms.
    pub fn start_repair(
        mut self,
        op_range_start: OpNumber,
        op_range_end: OpNumber,
    ) -> (Self, ReplicaOutput) {
        if op_range_start >= op_range_end {
            return (self, ReplicaOutput::empty());
        }

        // Check if budget has available slots
        if !self.repair_budget.has_available_slots() {
            tracing::warn!(
                replica = %self.replica_id,
                "repair budget exhausted, deferring repair"
            );
            return (self, ReplicaOutput::empty());
        }

        // Select best replica using EWMA
        let mut rng = rand::thread_rng();
        let Some(target_replica) = self.repair_budget.select_replica(&mut rng) else {
            tracing::warn!(
                replica = %self.replica_id,
                "no available replica for repair"
            );
            return (self, ReplicaOutput::empty());
        };

        // Generate a nonce for this repair request
        let nonce = Nonce::generate();

        // Initialize repair state
        let mut repair_state = RepairState::new(nonce, op_range_start, op_range_end);
        repair_state.set_target_replica(target_replica);
        self.repair_state = Some(repair_state);

        // Track send in budget
        let send_time = std::time::Instant::now();
        self.repair_budget.record_repair_sent(
            target_replica,
            op_range_start,
            op_range_end,
            send_time,
        );

        // Create repair request
        let request = RepairRequest::new(self.replica_id, nonce, op_range_start, op_range_end);

        // Send to selected replica (not broadcast)
        let msg = self.sign_message(msg_to(
            self.replica_id,
            target_replica,
            MessagePayload::RepairRequest(request),
        ));

        tracing::debug!(
            replica = %self.replica_id,
            target = %target_replica.as_u8(),
            start = %op_range_start,
            end = %op_range_end,
            "initiated repair with budget"
        );

        (self, ReplicaOutput::with_messages(vec![msg]))
    }

    // ========================================================================
    // RepairRequest Handler
    // ========================================================================

    /// Handles a `RepairRequest` from another replica.
    ///
    /// Responds with either:
    /// - `RepairResponse` if we have the requested entries
    /// - `Nack` if we don't have them (with reason)
    pub(crate) fn on_repair_request(
        self,
        from: ReplicaId,
        request: &RepairRequest,
    ) -> (Self, ReplicaOutput) {
        // Validate repair range (Byzantine protection)
        if request.op_range_start >= request.op_range_end {
            tracing::warn!(
                from = %from.as_u8(),
                start = %request.op_range_start,
                end = %request.op_range_end,
                "Invalid repair range - Byzantine attack detected"
            );

            // Record Byzantine rejection for simulation testing
            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "invalid_repair_range",
                from,
                request.op_range_start.as_u64(),
                request.op_range_end.as_u64(),
            );

            // Send NACK with NotSeen (we can't fulfill an invalid request)
            let nack = Nack::new(
                self.replica_id,
                request.nonce,
                NackReason::NotSeen,
                self.op_number,
            );
            let msg = self.sign_message(msg_to(self.replica_id, from, MessagePayload::Nack(nack)));
            return (self, ReplicaOutput::with_messages(vec![msg]));
        }

        // Don't respond to our own request
        if from == self.replica_id {
            return (self, ReplicaOutput::empty());
        }

        // If we're recovering, send a NACK
        if self.status == ReplicaStatus::Recovering {
            let nack = Nack::new(
                self.replica_id,
                request.nonce,
                NackReason::Recovering,
                self.op_number,
            );
            let msg = self.sign_message(msg_to(self.replica_id, from, MessagePayload::Nack(nack)));
            return (self, ReplicaOutput::with_messages(vec![msg]));
        }

        // Try to fulfill the request
        let mut entries = Vec::new();
        let mut can_fulfill = true;
        let mut highest_seen = self.op_number;

        let mut op = request.op_range_start;
        while op < request.op_range_end {
            match self.log_entry(op) {
                Some(entry) if entry.verify_checksum() => {
                    entries.push(entry.clone());
                }
                Some(_) => {
                    // Entry exists but is corrupt
                    can_fulfill = false;
                    break;
                }
                None => {
                    // Entry doesn't exist
                    can_fulfill = false;
                    // Check if we ever saw this op
                    if op > self.op_number {
                        // We never saw this operation
                    } else {
                        // We should have this but don't - it's corrupt/lost
                        highest_seen = highest_seen.max(op);
                    }
                    break;
                }
            }
            op = op.next();
        }

        if can_fulfill {
            // Send the entries
            let response = RepairResponse::new(self.replica_id, request.nonce, entries);
            let msg = self.sign_message(msg_to(
                self.replica_id,
                from,
                MessagePayload::RepairResponse(response),
            ));
            (self, ReplicaOutput::with_messages(vec![msg]))
        } else {
            // Send NACK with appropriate reason (improved logic for PAR)
            let reason = if request.op_range_end <= self.op_number {
                // The entire requested range is before our op_number
                // We should have all these entries but don't - they're corrupt/lost
                NackReason::SeenButCorrupt
            } else if request.op_range_start > self.op_number {
                // The entire requested range is after our op_number
                // We never received any of these operations
                NackReason::NotSeen
            } else {
                // Partial overlap: some ops we should have, some we never saw
                // Conservative: report SeenButCorrupt since we're missing ops we should have
                NackReason::SeenButCorrupt
            };

            let nack = Nack::new(self.replica_id, request.nonce, reason, highest_seen);
            let msg = self.sign_message(msg_to(self.replica_id, from, MessagePayload::Nack(nack)));
            (self, ReplicaOutput::with_messages(vec![msg]))
        }
    }

    // ========================================================================
    // RepairResponse Handler
    // ========================================================================

    /// Handles a `RepairResponse` from another replica.
    ///
    /// Applies the received entries after verification.
    pub(crate) fn on_repair_response(
        mut self,
        from: ReplicaId,
        response: &RepairResponse,
    ) -> (Self, ReplicaOutput) {
        // Extract repair state info we need, then release the borrow
        let (nonce, range_start, range_end) = {
            let Some(ref repair_state) = self.repair_state else {
                return (self, ReplicaOutput::empty());
            };
            (
                repair_state.nonce,
                repair_state.op_range_start,
                repair_state.op_range_end,
            )
        };

        // Nonce must match
        if response.nonce != nonce {
            return (self, ReplicaOutput::empty());
        }

        // Record the response (re-borrow mutably)
        if let Some(ref mut repair_state) = self.repair_state {
            repair_state.responses.insert(from, response.clone());
        }

        // Collect entries to apply (to avoid borrow issues)
        let entries_to_apply: Vec<_> = response
            .entries
            .iter()
            .filter(|entry| {
                if !entry.verify_checksum() {
                    tracing::warn!(
                        op = %entry.op_number,
                        from = %from,
                        "received corrupt entry in repair response"
                    );
                    return false;
                }
                entry.op_number >= range_start && entry.op_number < range_end
            })
            .cloned()
            .collect();

        // Apply entries
        for entry in entries_to_apply {
            self = self.merge_log_tail(vec![entry]);
        }

        // Record successful repair completion in budget
        let receive_time = std::time::Instant::now();
        self.repair_budget
            .record_repair_completed(from, range_start, range_end, receive_time);

        // Check if repair is complete
        self.check_repair_complete()
    }

    // ========================================================================
    // Nack Handler (PAR)
    // ========================================================================

    /// Handles a `Nack` from another replica.
    ///
    /// Tracks NACKs for PAR - safe truncation requires a quorum of `NotSeen`.
    pub(crate) fn on_nack(mut self, from: ReplicaId, nack: Nack) -> (Self, ReplicaOutput) {
        // Extract repair range for budget tracking
        let (nonce, range_start, range_end) = {
            let Some(ref repair_state) = self.repair_state else {
                return (self, ReplicaOutput::empty());
            };
            (
                repair_state.nonce,
                repair_state.op_range_start,
                repair_state.op_range_end,
            )
        };

        // Nonce must match
        if nack.nonce != nonce {
            return (self, ReplicaOutput::empty());
        }

        tracing::debug!(
            replica = %self.replica_id,
            from = %from,
            reason = %nack.reason,
            highest_seen = %nack.highest_seen,
            "received NACK"
        );

        // Record the NACK
        if let Some(ref mut repair_state) = self.repair_state {
            repair_state.nacks.insert(from, nack);
        }

        // Record in budget (NACK also completes the repair attempt, even if unsuccessful)
        let receive_time = std::time::Instant::now();
        self.repair_budget
            .record_repair_completed(from, range_start, range_end, receive_time);

        // Check if repair is complete
        self.check_repair_complete()
    }

    /// Checks if repair is complete.
    ///
    /// Repair is complete when we either:
    /// 1. Have all the entries we need
    /// 2. Have enough NACKs to make a PAR decision
    fn check_repair_complete(mut self) -> (Self, ReplicaOutput) {
        let Some(ref repair_state) = self.repair_state else {
            return (self, ReplicaOutput::empty());
        };

        // Check if we have all entries
        let mut have_all = true;
        let mut op = repair_state.op_range_start;
        while op < repair_state.op_range_end {
            if self.log_entry(op).is_none() {
                have_all = false;
                break;
            }
            op = op.next();
        }

        if have_all {
            // Cache the range endpoint before we drop `repair_state`
            // so we can drive the apply loop below. `op_range_end` is
            // exclusive, so the last repaired op is `op_range_end - 1`.
            let range_end = repair_state.op_range_end;

            tracing::info!(
                replica = %self.replica_id,
                start = %repair_state.op_range_start,
                end = %range_end,
                "repair complete"
            );
            self.repair_state = None;

            // Drive the newly-populated log through the normal apply
            // path. Without this, the repaired entries sit in the log
            // but their commands are never applied to `kernel_state` —
            // no `Effect`s are produced, so the `AppliedCommit` fanout
            // in `event_loop::handle_output` never fires and downstream
            // observers (chaos write-log, future audit/projection
            // consumers) silently miss the ops a repaired follower just
            // caught up on.
            //
            // The leader told us these ops were committed (that's why
            // it kept sending Prepares with `commit_number >= end - 1`,
            // which is what got us to initiate repair in the first
            // place), so advancing our `commit_number` through them is
            // safe — any ops beyond the repaired range will be applied
            // by the next Prepare/Commit that arrives.
            let target = CommitNumber::new(OpNumber::new(range_end.as_u64().saturating_sub(1)));
            if target > self.commit_number {
                let (new_self, effects) = self.apply_commits_up_to(target);
                let mut output = ReplicaOutput::empty();
                output.effects = effects;
                return (new_self, output);
            }
            return (self, ReplicaOutput::empty());
        }

        // Check if we have enough information for a PAR decision
        let cluster_size = self.config.cluster_size();
        let max_failures = self.config.max_failures();

        // We've heard from everyone (or enough)
        if repair_state.total_replies() >= cluster_size - 1 {
            if repair_state.any_seen() {
                // At least one replica saw these operations - cannot truncate
                // This is a data integrity issue - we need manual intervention
                tracing::error!(
                    replica = %self.replica_id,
                    start = %repair_state.op_range_start,
                    end = %repair_state.op_range_end,
                    "repair failed: some replicas saw operations, cannot truncate"
                );
                self.repair_state = None;
            } else if repair_state.can_safely_truncate(max_failures) {
                // All NACKs are NotSeen - safe to consider these operations as never committed
                tracing::warn!(
                    replica = %self.replica_id,
                    start = %repair_state.op_range_start,
                    end = %repair_state.op_range_end,
                    nack_count = repair_state.not_seen_count(),
                    "PAR: safely abandoning uncommitted operations"
                );
                // The operations were never committed, so we don't need to track them
                self.repair_state = None;
            }
        }

        (self, ReplicaOutput::empty())
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns the current repair state, if any.
    pub fn repair_state(&self) -> Option<&RepairState> {
        self.repair_state.as_ref()
    }

    /// Returns true if a repair is in progress.
    pub fn is_repairing(&self) -> bool {
        self.repair_state.is_some()
    }

    /// Expires stale repair requests from the budget.
    ///
    /// Called periodically (e.g., on tick) to release slots for requests
    /// that have exceeded the 500ms timeout.
    pub fn expire_stale_repairs(mut self) -> (Self, ReplicaOutput) {
        let now = std::time::Instant::now();
        let expired = self.repair_budget.expire_stale_requests(now);

        if !expired.is_empty() {
            tracing::debug!(
                replica = %self.replica_id,
                count = expired.len(),
                "expired stale repair requests"
            );

            // For each expired repair, we might want to retry if we still need it
            // For now, just log it - retry logic can be added in future
        }

        (self, ReplicaOutput::empty())
    }

    /// Detects gaps or corruption in the log and initiates repair if needed.
    ///
    /// Returns true if repair was initiated.
    pub fn check_and_repair(self) -> (Self, ReplicaOutput, bool) {
        // Don't repair if already repairing or recovering
        if self.is_repairing() || self.is_recovering() {
            return (self, ReplicaOutput::empty(), false);
        }

        // Find gaps in the log
        let mut gap_start: Option<OpNumber> = None;
        let mut op = OpNumber::new(1);

        while op <= self.op_number {
            match self.log_entry(op) {
                Some(entry) if entry.verify_checksum() => {
                    // Entry is valid
                    if let Some(start) = gap_start {
                        // End of gap found
                        let (new_self, output) = self.start_repair(start, op);
                        return (new_self, output, true);
                    }
                }
                _ => {
                    // Entry is missing or corrupt
                    if gap_start.is_none() {
                        gap_start = Some(op);
                    }
                }
            }
            op = op.next();
        }

        // Check if there's a gap at the end
        if let Some(start) = gap_start {
            let end = self.op_number.next();
            let (new_self, output) = self.start_repair(start, end);
            return (new_self, output, true);
        }

        (self, ReplicaOutput::empty(), false)
    }
}

// ============================================================================
// Write Reorder Repair
// ============================================================================

/// Timeout for reorder gap fill requests (100ms in nanoseconds).
const REORDER_GAP_TIMEOUT_NS: u128 = 100_000_000;

/// Starts a reorder repair by requesting missing ops from the leader.
///
/// Called when a backup receives a Prepare with `received_op > expected_op`.
/// The backup buffers the out-of-order prepare and sends a
/// `WriteReorderGapRequest` to the leader for the missing operations.
///
/// # Arguments
///
/// * `state` - Current replica state
/// * `expected_op` - The next op the backup expected to receive
/// * `received_op` - The op number that was actually received (out of order)
///
/// # Returns
///
/// Output messages containing a `WriteReorderGapRequest` to the leader.
#[allow(dead_code)] // Called from backup prepare handler when detecting out-of-order ops
pub fn start_reorder_repair(
    state: &ReplicaState,
    expected_op: OpNumber,
    received_op: OpNumber,
) -> Vec<ReplicaOutput> {
    debug_assert!(
        received_op > expected_op,
        "reorder repair requires received_op ({}) > expected_op ({})",
        received_op.as_u64(),
        expected_op.as_u64()
    );

    // Collect the missing op numbers between expected and received
    let mut missing_ops = Vec::new();
    let mut op = expected_op;
    while op < received_op {
        if state.log_entry(op).is_none() && !state.reorder_buffer.contains_key(&op) {
            missing_ops.push(op);
        }
        op = op.next();
    }

    if missing_ops.is_empty() {
        return vec![ReplicaOutput::empty()];
    }

    tracing::debug!(
        replica = %state.replica_id,
        expected = %expected_op,
        received = %received_op,
        gap_count = missing_ops.len(),
        "detected write reorder gap, requesting missing ops from leader"
    );

    let leader = state.leader();
    let nonce = Nonce::generate();

    let request = crate::message::WriteReorderGapRequest::new(state.replica_id, nonce, missing_ops);

    let msg = state.sign_message(msg_to(
        state.replica_id,
        leader,
        MessagePayload::WriteReorderGapRequest(request),
    ));

    vec![ReplicaOutput::with_messages(vec![msg])]
}

/// Handles a gap request from a backup (leader-side).
///
/// The leader looks up the requested entries in its log and sends them
/// back to the requesting backup in a `WriteReorderGapResponse`.
///
/// # Arguments
///
/// * `state` - Current replica state (leader)
/// * `request` - The gap fill request from a backup
///
/// # Returns
///
/// New state and output messages containing a `WriteReorderGapResponse`.
pub fn on_write_reorder_gap_request(
    state: ReplicaState,
    request: &crate::message::WriteReorderGapRequest,
) -> (ReplicaState, ReplicaOutput) {
    // Only leader should respond to gap requests
    if !state.is_leader() {
        tracing::debug!(
            replica = %state.replica_id,
            from = %request.from,
            "ignoring WriteReorderGapRequest, not leader"
        );
        return (state, ReplicaOutput::empty());
    }

    // Don't respond to our own request
    if request.from == state.replica_id {
        return (state, ReplicaOutput::empty());
    }

    // Look up the requested entries
    let mut entries = Vec::new();
    for &op in &request.missing_ops {
        if let Some(entry) = state.log_entry(op) {
            if entry.verify_checksum() {
                entries.push(entry.clone());
            } else {
                tracing::warn!(
                    replica = %state.replica_id,
                    op = %op,
                    "corrupt entry in log during reorder gap fill"
                );
            }
        } else {
            tracing::debug!(
                replica = %state.replica_id,
                op = %op,
                "missing entry in log during reorder gap fill"
            );
        }
    }

    if entries.is_empty() {
        tracing::debug!(
            replica = %state.replica_id,
            from = %request.from,
            missing_count = request.missing_ops.len(),
            "no entries available for reorder gap fill"
        );
        return (state, ReplicaOutput::empty());
    }

    tracing::debug!(
        replica = %state.replica_id,
        from = %request.from,
        entries_count = entries.len(),
        requested_count = request.missing_ops.len(),
        "sending WriteReorderGapResponse"
    );

    let response =
        crate::message::WriteReorderGapResponse::new(state.replica_id, request.nonce, entries);

    let msg = state.sign_message(msg_to(
        state.replica_id,
        request.from,
        MessagePayload::WriteReorderGapResponse(response),
    ));

    (state, ReplicaOutput::with_messages(vec![msg]))
}

/// Handles a gap response (backup-side) -- applies buffered entries in order.
///
/// When the backup receives the missing entries from the leader, it inserts
/// them into the log and then drains its reorder buffer, applying entries
/// in sequential order until the next gap is encountered.
///
/// If the gap was not filled within 100ms (tracked via `reorder_deadlines`),
/// the repair escalates to a full `RepairRequest`.
///
/// # Arguments
///
/// * `state` - Current replica state (backup)
/// * `response` - The gap fill response from the leader
///
/// # Returns
///
/// New state and output (may contain additional messages if escalation needed).
pub fn on_write_reorder_gap_response(
    mut state: ReplicaState,
    response: &crate::message::WriteReorderGapResponse,
) -> (ReplicaState, ReplicaOutput) {
    if response.entries.is_empty() {
        return (state, ReplicaOutput::empty());
    }

    tracing::debug!(
        replica = %state.replica_id,
        from = %response.from,
        entries_count = response.entries.len(),
        "received WriteReorderGapResponse"
    );

    // Apply received entries to the log
    let entries_to_merge: Vec<_> = response
        .entries
        .iter()
        .filter(|entry| {
            if !entry.verify_checksum() {
                tracing::warn!(
                    replica = %state.replica_id,
                    op = %entry.op_number,
                    "corrupt entry in reorder gap response"
                );
                return false;
            }
            true
        })
        .cloned()
        .collect();

    state = state.merge_log_tail(entries_to_merge);

    // Clear deadlines for ops we just received
    for entry in &response.entries {
        state.reorder_deadlines.remove(&entry.op_number);
    }

    // Drain reorder buffer in sequential order
    let mut drained = 0u64;
    loop {
        let next_expected = state.op_number.next();
        if let Some(buffered_entry) = state.reorder_buffer.remove(&next_expected) {
            state = state.merge_log_tail(vec![buffered_entry]);
            state.reorder_deadlines.remove(&next_expected);
            drained += 1;
        } else {
            break;
        }
    }

    if drained > 0 {
        tracing::debug!(
            replica = %state.replica_id,
            drained = drained,
            "drained entries from reorder buffer"
        );
    }

    // Check for any remaining stale reorder deadlines and escalate if needed
    let now_ns = crate::clock::Clock::monotonic_nanos();
    let mut escalate_start: Option<OpNumber> = None;
    let mut escalate_end: Option<OpNumber> = None;

    let stale_ops: Vec<OpNumber> = state
        .reorder_deadlines
        .iter()
        .filter(|&(_, deadline)| now_ns > *deadline + REORDER_GAP_TIMEOUT_NS)
        .map(|(&op, _)| op)
        .collect();

    for op in &stale_ops {
        state.reorder_deadlines.remove(op);
        match escalate_start {
            None => {
                escalate_start = Some(*op);
                escalate_end = Some(op.next());
            }
            Some(start) => {
                if *op < start {
                    escalate_start = Some(*op);
                }
                if op.next() > escalate_end.unwrap_or(OpNumber::ZERO) {
                    escalate_end = Some(op.next());
                }
            }
        }
    }

    // Escalate to full repair if we have stale gaps
    if let (Some(start), Some(end)) = (escalate_start, escalate_end) {
        tracing::warn!(
            replica = %state.replica_id,
            start = %start,
            end = %end,
            stale_count = stale_ops.len(),
            "reorder gap fill timed out, escalating to full RepairRequest"
        );
        let (new_state, output) = state.start_repair(start, end);
        return (new_state, output);
    }

    (state, ReplicaOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClusterConfig;
    use crate::types::{LogEntry, OpNumber, ViewNumber};
    use kimberlite_kernel::Command;
    use kimberlite_types::{DataClass, Placement};

    fn test_config_3() -> ClusterConfig {
        ClusterConfig::new(vec![
            ReplicaId::new(0),
            ReplicaId::new(1),
            ReplicaId::new(2),
        ])
    }

    fn test_config_5() -> ClusterConfig {
        ClusterConfig::new(vec![
            ReplicaId::new(0),
            ReplicaId::new(1),
            ReplicaId::new(2),
            ReplicaId::new(3),
            ReplicaId::new(4),
        ])
    }

    fn test_command() -> Command {
        Command::create_stream_with_auto_id("test".into(), DataClass::Public, Placement::Global)
    }

    fn test_entry(op: u64, view: u64) -> LogEntry {
        LogEntry::new(
            OpNumber::new(op),
            ViewNumber::new(view),
            test_command(),
            None,
            None,
            None,
        )
    }

    #[test]
    fn repair_state_try_new_rejects_empty_range() {
        let err = RepairState::try_new(
            Nonce::from_bytes([1u8; crate::types::NONCE_LENGTH]),
            OpNumber::new(5),
            OpNumber::new(5),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                crate::VsrError::InvalidRepairRange { start: 5, end: 5 }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn repair_state_try_new_rejects_inverted_range() {
        let err = RepairState::try_new(
            Nonce::from_bytes([1u8; crate::types::NONCE_LENGTH]),
            OpNumber::new(10),
            OpNumber::new(5),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                crate::VsrError::InvalidRepairRange { start: 10, end: 5 }
            ),
            "got {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "invalid op range")]
    fn repair_state_new_panics_on_empty_range() {
        let _ = RepairState::new(
            Nonce::from_bytes([1u8; crate::types::NONCE_LENGTH]),
            OpNumber::new(5),
            OpNumber::new(5),
        );
    }

    #[test]
    fn start_repair_broadcasts_request() {
        let config = test_config_3();
        let replica = ReplicaState::new(ReplicaId::new(0), config);

        let (replica, output) = replica.start_repair(OpNumber::new(1), OpNumber::new(5));

        assert!(replica.is_repairing());
        assert_eq!(output.messages.len(), 1);
        assert!(matches!(
            output.messages[0].payload,
            MessagePayload::RepairRequest(_)
        ));
    }

    #[test]
    fn healthy_replica_responds_with_entries() {
        let config = test_config_3();
        let mut healthy = ReplicaState::new(ReplicaId::new(0), config);

        // Add entries
        healthy.log.push(test_entry(1, 0));
        healthy.log.push(test_entry(2, 0));
        healthy.log.push(test_entry(3, 0));
        healthy.op_number = OpNumber::new(3);

        // Receive repair request
        let request = RepairRequest::new(
            ReplicaId::new(1),
            Nonce::generate(),
            OpNumber::new(1),
            OpNumber::new(4),
        );

        let (_healthy, output) = healthy.on_repair_request(ReplicaId::new(1), &request);

        assert_eq!(output.messages.len(), 1);
        let msg = &output.messages[0];
        assert!(matches!(msg.payload, MessagePayload::RepairResponse(_)));

        if let MessagePayload::RepairResponse(ref resp) = msg.payload {
            assert_eq!(resp.entries.len(), 3);
        }
    }

    #[test]
    fn replica_nacks_when_missing_entries() {
        let config = test_config_3();
        let healthy = ReplicaState::new(ReplicaId::new(0), config);
        // No entries in log

        // Request entries we don't have
        let request = RepairRequest::new(
            ReplicaId::new(1),
            Nonce::generate(),
            OpNumber::new(5),
            OpNumber::new(10),
        );

        let (_healthy, output) = healthy.on_repair_request(ReplicaId::new(1), &request);

        assert_eq!(output.messages.len(), 1);
        let msg = &output.messages[0];
        assert!(matches!(msg.payload, MessagePayload::Nack(_)));

        if let MessagePayload::Nack(ref nack) = msg.payload {
            assert_eq!(nack.reason, NackReason::NotSeen);
        }
    }

    #[test]
    fn recovering_replica_nacks_with_recovering_reason() {
        let config = test_config_3();
        let mut replica = ReplicaState::new(ReplicaId::new(0), config);
        replica.status = ReplicaStatus::Recovering;

        let request = RepairRequest::new(
            ReplicaId::new(1),
            Nonce::generate(),
            OpNumber::new(1),
            OpNumber::new(5),
        );

        let (_replica, output) = replica.on_repair_request(ReplicaId::new(1), &request);

        if let MessagePayload::Nack(ref nack) = output.messages[0].payload {
            assert_eq!(nack.reason, NackReason::Recovering);
        }
    }

    #[test]
    fn repair_applies_received_entries() {
        let config = test_config_3();
        let replica = ReplicaState::new(ReplicaId::new(0), config);

        // Start repair
        let (replica, _) = replica.start_repair(OpNumber::new(1), OpNumber::new(3));
        let nonce = replica.repair_state().unwrap().nonce;

        // Receive response with entries
        let response = RepairResponse::new(
            ReplicaId::new(1),
            nonce,
            vec![test_entry(1, 0), test_entry(2, 0)],
        );

        let (replica, _) = replica.on_repair_response(ReplicaId::new(1), &response);

        // Entries should be applied
        assert!(replica.log_entry(OpNumber::new(1)).is_some());
        assert!(replica.log_entry(OpNumber::new(2)).is_some());
    }

    #[test]
    fn par_requires_quorum_of_not_seen() {
        let config = test_config_5();
        let max_failures = config.max_failures();
        let replica = ReplicaState::new(ReplicaId::new(0), config);

        // Start repair
        let (mut replica, _) = replica.start_repair(OpNumber::new(10), OpNumber::new(15));
        let nonce = replica.repair_state().unwrap().nonce;

        // Receive NotSeen from replicas 1 and 2 (need 3 for f+1 in 5-node cluster)
        for i in 1..=2 {
            let nack = Nack::new(
                ReplicaId::new(i),
                nonce,
                NackReason::NotSeen,
                OpNumber::new(5),
            );
            let (new_replica, _) = replica.on_nack(ReplicaId::new(i), nack);
            replica = new_replica;
        }

        // Still repairing - don't have quorum
        assert!(replica.is_repairing());

        // Third NotSeen gives us quorum
        let nack = Nack::new(
            ReplicaId::new(3),
            nonce,
            NackReason::NotSeen,
            OpNumber::new(5),
        );
        let (replica, _) = replica.on_nack(ReplicaId::new(3), nack);

        // Still need more responses to complete (cluster_size - 1)
        // But PAR state should be tracking correctly
        let repair_state = replica.repair_state().unwrap();
        assert!(repair_state.can_safely_truncate(max_failures));
    }

    #[test]
    fn par_blocks_truncation_when_seen_but_corrupt() {
        // Test the RepairState PAR logic directly (the replica auto-clears state
        // when it has enough information to make a PAR decision)
        let nonce = Nonce::generate();
        let mut repair_state = RepairState::new(nonce, OpNumber::new(5), OpNumber::new(10));

        // max_failures for a 3-node cluster is 1
        let max_failures = 1;

        // One replica says NotSeen
        let nack1 = Nack::new(
            ReplicaId::new(1),
            nonce,
            NackReason::NotSeen,
            OpNumber::new(3),
        );
        repair_state.nacks.insert(ReplicaId::new(1), nack1);

        // With just NotSeen, truncation could be safe (need f+1 = 2 for quorum)
        assert!(!repair_state.any_seen());
        assert!(!repair_state.can_safely_truncate(max_failures)); // Only 1, need 2

        // Another says SeenButCorrupt - blocks truncation!
        let nack2 = Nack::new(
            ReplicaId::new(2),
            nonce,
            NackReason::SeenButCorrupt,
            OpNumber::new(7),
        );
        repair_state.nacks.insert(ReplicaId::new(2), nack2);

        // Now any_seen() is true, so truncation is blocked
        assert!(repair_state.any_seen());
        assert!(!repair_state.can_safely_truncate(max_failures));
    }

    /// Repair completion must drive the newly-populated log through the
    /// normal apply path so observer fanout stays intact. Regression
    /// test for the chaos split-brain flake where a recovered follower
    /// held a stale chaos snapshot because repaired entries sat in the
    /// log un-applied.
    #[test]
    fn repair_completion_applies_caught_up_ops_and_emits_effects() {
        let config = test_config_3();
        let mut r0 = ReplicaState::new(ReplicaId::new(0), config);

        // Seed op 1 through the normal apply path so `kernel_state`
        // has the chaos stream registered — otherwise the repaired
        // CreateStream commands for ops 2..=5 would collide on the
        // same auto-assigned id.
        let (r0_after, _) = r0.prepare_new_operation(test_command(), None, None, None);
        r0 = r0_after;
        let (r0_after, _) = r0.apply_commits_up_to(CommitNumber::new(OpNumber::new(1)));
        r0 = r0_after;
        assert_eq!(r0.commit_number(), CommitNumber::new(OpNumber::new(1)));

        // Pretend we learned about ops 2..=5 but couldn't apply them
        // because of a gap — we kicked off a repair for [2, 6).
        let (mut r0, _) = r0.start_repair(OpNumber::new(2), OpNumber::new(6));
        // Manually backfill the log with distinct commands so apply
        // produces one `Effect::StreamMetadataWrite` per op.
        for op in 2..=5u64 {
            let entry = LogEntry::new(
                OpNumber::new(op),
                ViewNumber::ZERO,
                Command::create_stream_with_auto_id(
                    kimberlite_types::StreamName::new(format!("repaired-{op}")),
                    DataClass::Public,
                    Placement::Global,
                ),
                None,
                None,
                None,
            );
            r0.log.push(entry);
        }
        r0.op_number = OpNumber::new(5);

        // Trigger the completion path directly.
        let (r0_after, output) = r0.check_repair_complete();
        let r0 = r0_after;

        // Every caught-up op must have produced at least one effect,
        // otherwise the `AppliedCommit` fanout in `event_loop` never
        // fires and observers drift out of sync.
        assert!(
            output.effects.len() >= 4,
            "expected at least 4 effects (one per repaired op), got {}",
            output.effects.len(),
        );
        assert_eq!(r0.commit_number(), CommitNumber::new(OpNumber::new(5)));
        assert!(!r0.is_repairing());
    }

    #[test]
    fn repair_state_tracks_counts() {
        let nonce = Nonce::generate();
        let mut state = RepairState::new(nonce, OpNumber::new(1), OpNumber::new(10));

        // Add some NACKs
        state.nacks.insert(
            ReplicaId::new(1),
            Nack::new(
                ReplicaId::new(1),
                nonce,
                NackReason::NotSeen,
                OpNumber::new(0),
            ),
        );
        state.nacks.insert(
            ReplicaId::new(2),
            Nack::new(
                ReplicaId::new(2),
                nonce,
                NackReason::NotSeen,
                OpNumber::new(0),
            ),
        );
        state.nacks.insert(
            ReplicaId::new(3),
            Nack::new(
                ReplicaId::new(3),
                nonce,
                NackReason::Recovering,
                OpNumber::new(0),
            ),
        );

        assert_eq!(state.not_seen_count(), 2);
        assert_eq!(state.total_replies(), 3);
        assert!(!state.any_seen());

        // Add SeenButCorrupt
        state.nacks.insert(
            ReplicaId::new(4),
            Nack::new(
                ReplicaId::new(4),
                nonce,
                NackReason::SeenButCorrupt,
                OpNumber::new(5),
            ),
        );

        assert!(state.any_seen());
    }
}
