//! Normal operation protocol handlers.
//!
//! This module implements the handlers for normal VSR operation:
//! - Prepare (leader → backups)
//! - `PrepareOK` (backup → leader)
//! - Commit (leader → backups)
//! - Heartbeat (leader → backups)

use std::collections::HashSet;

use crate::instrumentation::METRICS;
use crate::message::{Commit, Heartbeat, MessagePayload, Prepare, PrepareOk};
use crate::types::{OpNumber, ReplicaId, ReplicaStatus};

use super::{ReplicaOutput, ReplicaState, msg_to};

impl ReplicaState {
    // ========================================================================
    // Prepare Handler (Backup)
    // ========================================================================

    /// Handles a Prepare message from the leader.
    ///
    /// The backup:
    /// 1. Validates the message (view, op number)
    /// 2. Adds the entry to its log
    /// 3. Sends `PrepareOK` back to the leader
    /// 4. Applies any newly committed operations
    // VSR Prepare handler — length reflects the number of validation cases
    // (view check, op-number check, idempotency, signature verify, replay
    // detection, log extend, commit advance). Decomposing would scatter the
    // protocol logic across helpers that only make sense read in sequence.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn on_prepare(mut self, from: ReplicaId, prepare: Prepare) -> (Self, ReplicaOutput) {
        // Record message received
        METRICS.increment_messages_received();

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6)
        let msg_id =
            crate::replica::state::MessageId::prepare(from, prepare.view, prepare.op_number);
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::warn!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %prepare.view,
                op = %prepare.op_number,
                "Replay attack detected: duplicate Prepare message"
            );
            METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "prepare_replay",
                from,
                prepare.op_number.as_u64(),
                self.op_number.as_u64(),
            );

            // DST: coverage signal — simulation should exercise replay detection
            kimberlite_properties::sometimes!(
                true,
                "vsr.prepare_replay_detected",
                "simulation should exercise Prepare replay detection"
            );

            return (self, ReplicaOutput::empty());
        }

        // Message must be from the leader
        if from != self.leader() {
            return (self, ReplicaOutput::empty());
        }

        // View must match
        if prepare.view != self.view {
            // If message is from a higher view, we need to catch up
            if prepare.view > self.view {
                tracing::info!(
                    replica = %self.replica_id,
                    our_view = %self.view,
                    msg_view = %prepare.view,
                    "received Prepare from higher view, initiating view change"
                );

                // Check how far behind we are - if just one view, do view change
                // If multiple views behind, consider state transfer
                let view_gap = prepare.view.as_u64().saturating_sub(self.view.as_u64());
                if view_gap > 3 {
                    // We're very far behind - initiate state transfer
                    let (new_self, output) = self.start_state_transfer(Some(prepare.view));
                    return (new_self, output);
                }
                // Otherwise, start a view change to the message's view
                let (new_self, output) = self.start_view_change_to(prepare.view);
                return (new_self, output);
            }
            // Message from lower view - ignore
            return (self, ReplicaOutput::empty());
        }

        // Validate log entry checksum BEFORE gap detection
        // This prevents Byzantine replicas from triggering expensive repairs
        // with corrupt entries and inflated op_numbers
        if !prepare.entry.verify_checksum() {
            tracing::warn!(
                replica = %self.replica_id,
                op = %prepare.op_number,
                from = %from.as_u8(),
                "Prepare entry failed checksum validation - Byzantine attack detected"
            );

            // Record checksum failure
            METRICS.increment_checksum_failures();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "prepare_checksum_failure",
                from,
                prepare.op_number.as_u64(),
                self.op_number.as_u64(),
            );

            // DST: coverage signal — simulation should exercise checksum failure detection
            kimberlite_properties::sometimes!(
                true,
                "vsr.prepare_checksum_failure_detected",
                "simulation should exercise Byzantine checksum failure detection"
            );

            return (self, ReplicaOutput::empty());
        }

        // Enforce pipeline depth limit (prevent memory exhaustion from Byzantine leader)
        // A Byzantine leader could send Prepare with op_number far ahead of commit_number,
        // exhausting memory by forcing the backup to buffer unbounded uncommitted entries.
        let pipeline_depth = prepare
            .op_number
            .as_u64()
            .saturating_sub(self.commit_number.as_u64());
        if pipeline_depth > self.config.max_pipeline_depth {
            tracing::warn!(
                replica = %self.replica_id,
                op_number = %prepare.op_number,
                commit_number = %self.commit_number,
                max_depth = %self.config.max_pipeline_depth,
                "Rejecting Prepare: pipeline depth limit exceeded"
            );
            return (self, ReplicaOutput::empty());
        }

        // Op number must be next expected or a reasonable gap
        let expected_op = self.op_number.next();
        if prepare.op_number < expected_op {
            // Already have this operation, but still send PrepareOK
            // (leader might have missed our previous response)
            // Send PrepareOk with backup's current wall clock time for clock sync
            let wall_clock_timestamp = crate::clock::Clock::realtime_nanos();
            let prepare_ok = PrepareOk::new(
                self.view,
                prepare.op_number,
                self.replica_id,
                wall_clock_timestamp,
                self.upgrade_state.self_version,
            );
            let msg = self.sign_message(msg_to(
                self.replica_id,
                from,
                MessagePayload::PrepareOk(prepare_ok),
            ));
            return (self, ReplicaOutput::with_messages(vec![msg]));
        }

        if prepare.op_number > expected_op {
            // Gap in sequence - we're missing operations
            // Initiate repair to get the missing entries
            tracing::debug!(
                replica = %self.replica_id,
                expected = %expected_op,
                got = %prepare.op_number,
                gap_size = prepare.op_number.distance_to(expected_op),
                "gap in Prepare sequence, initiating repair"
            );

            // Start repair for the missing range [expected_op, prepare.op_number)
            let (new_self, repair_output) = self.start_repair(expected_op, prepare.op_number);

            // Return with repair messages - we'll process this Prepare when repair completes
            return (new_self, repair_output);
        }

        // Add entry to log
        self.log.push(prepare.entry);
        self.op_number = prepare.op_number;

        // Safety invariant: commit_number ≤ op_number (VSR CommitBound).
        // Spec: specs/tla/VSR.cfg::CommitNotExceedOp (INVARIANT).
        // Production assert (not debug_assert) as of 2026-04-17 FV-EPYC
        // gap-closure — any Prepare that could move commit past op is a
        // consensus-safety violation we must not silently accept.
        assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "VSR CommitBound violated in on_prepare: commit={} > op={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        // Process reconfiguration command if present
        if let Some(ref reconfig_cmd) = prepare.reconfig {
            self = self.apply_reconfiguration_command(reconfig_cmd, prepare.op_number);
        }

        // Send PrepareOK
        // Send PrepareOk with backup's current wall clock time for clock sync
        let wall_clock_timestamp = crate::clock::Clock::realtime_nanos();
        let prepare_ok = PrepareOk::new(
            self.view,
            prepare.op_number,
            self.replica_id,
            wall_clock_timestamp,
            self.upgrade_state.self_version,
        );
        let msg = self.sign_message(msg_to(
            self.replica_id,
            from,
            MessagePayload::PrepareOk(prepare_ok),
        ));

        // Record message sent
        METRICS.increment_messages_sent("PrepareOk");

        // Apply any new commits from the leader's commit_number
        let (new_self, effects) = self.apply_commits_up_to(prepare.commit_number);

        let mut output = ReplicaOutput::with_messages(vec![msg]);
        output.effects = effects;

        (new_self, output)
    }

    // ========================================================================
    // PrepareOK Handler (Leader)
    // ========================================================================

    /// Handles a `PrepareOK` message from a backup.
    ///
    /// The leader:
    /// 1. Validates the message
    /// 2. Records the vote
    /// 3. Commits if quorum is reached
    pub(crate) fn on_prepare_ok(
        mut self,
        from: ReplicaId,
        prepare_ok: PrepareOk,
    ) -> (Self, ReplicaOutput) {
        // Must be leader
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // View must match
        if prepare_ok.view != self.view {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6)
        let msg_id = crate::replica::state::MessageId::prepare_ok(
            from,
            prepare_ok.view,
            prepare_ok.op_number,
        );
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::warn!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %prepare_ok.view,
                op = %prepare_ok.op_number,
                "Replay attack detected: duplicate PrepareOk message"
            );
            METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "prepare_ok_replay",
                from,
                prepare_ok.op_number.as_u64(),
                self.op_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // Operation must be pending (not yet committed)
        if prepare_ok.op_number <= self.commit_number.as_op_number() {
            return (self, ReplicaOutput::empty());
        }

        // Operation must exist in our log
        if prepare_ok.op_number > self.op_number {
            return (self, ReplicaOutput::empty());
        }

        // Track sender's version for rolling upgrades
        self.upgrade_state
            .update_replica_version(from, prepare_ok.version);

        // Record the vote
        let voters = self
            .prepare_ok_tracker
            .entry(prepare_ok.op_number)
            .or_default();
        voters.insert(from);

        // Learn clock sample from backup (leader collects samples for synchronization)
        // m0 = when we sent the Prepare (monotonic time at prepare send)
        // t1 = backup's wall clock time (from prepare_ok.wall_clock_timestamp)
        // m2 = now (monotonic time when we received PrepareOk)
        if let Some(&m0) = self.prepare_send_times.get(&prepare_ok.op_number) {
            let m2 = crate::clock::Clock::monotonic_nanos();
            let t1 = prepare_ok.wall_clock_timestamp;
            // Feed the sample to the clock (errors are non-fatal)
            let _ = self.clock.learn_sample(from, m0, t1, m2);
        }

        // Clean up send times for committed operations
        let committed = self.commit_number.as_op_number();
        self.prepare_send_times.retain(|op, _| *op > committed);

        // Try to commit
        self.try_commit(prepare_ok.op_number)
    }

    // ========================================================================
    // Commit Handler (Backup)
    // ========================================================================

    /// Handles a Commit message from the leader.
    ///
    /// The backup applies committed operations it hasn't yet executed.
    pub(crate) fn on_commit(mut self, from: ReplicaId, commit: Commit) -> (Self, ReplicaOutput) {
        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Message must be from the leader
        if from != self.leader() {
            return (self, ReplicaOutput::empty());
        }

        // View must match
        if commit.view != self.view {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6). Dedup key includes
        // commit_number so a leader's monotonic Commit stream isn't
        // falsely flagged — only a true replay of the same triple fires.
        let msg_id =
            crate::replica::state::MessageId::commit(from, commit.view, commit.commit_number);
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::debug!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %commit.view,
                commit = %commit.commit_number,
                "dropping duplicate Commit (same commit_number already seen)"
            );
            METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "commit_replay",
                from,
                commit.commit_number.as_u64(),
                self.commit_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // DST: coverage signal — fires whenever commit_number > op_number is observed,
        // whether from a lagging backup or a Byzantine leader.  The security guard
        // below prevents the dangerous path; this annotation records that the condition
        // was reached so the catchup/Byzantine scenario is exercised.
        kimberlite_properties::sometimes!(
            commit.commit_number.as_op_number() > self.op_number,
            "vsr.commit_target_exceeds_op",
            "simulation should exercise the case where a Commit target exceeds local op_number"
        );

        // Validate commit_number does not exceed our op_number (AUDIT-2026-03)
        // A Byzantine leader could send Commit(commit_number=1000) when op_number=5,
        // causing apply_commits_up_to(1000) to panic on missing log entries.
        if commit.commit_number.as_op_number() > self.op_number {
            tracing::warn!(
                replica = %self.replica_id,
                commit = %commit.commit_number,
                op_number = %self.op_number.as_u64(),
                "Rejecting Commit with commit_number exceeding op_number"
            );
            return (self, ReplicaOutput::empty());
        }

        // Apply commits
        if commit.commit_number > self.commit_number {
            let (new_self, effects) = self.apply_commits_up_to(commit.commit_number);
            return (
                new_self,
                ReplicaOutput::with_messages_and_effects(vec![], effects),
            );
        }

        (self, ReplicaOutput::empty())
    }

    // ========================================================================
    // Heartbeat Handler (Backup)
    // ========================================================================

    /// Handles a Heartbeat message from the leader.
    ///
    /// Heartbeats serve as:
    /// 1. Liveness signal (leader is alive)
    /// 2. Commit notification (piggybacks `commit_number`)
    pub(crate) fn on_heartbeat(
        mut self,
        from: ReplicaId,
        heartbeat: Heartbeat,
    ) -> (Self, ReplicaOutput) {
        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Higher-view catch-up MUST be checked before the
        // leader-of-self-view filter below: a replica that rejoined
        // after being the leader of an old view still has
        // `self.leader() == self.replica_id`, so a heartbeat from the
        // real leader of a higher view fails the leader check and
        // gets silently dropped. That leaves the rejoined replica
        // stuck reporting `is_leader=1` at an obsolete view forever,
        // and the cluster ends up with two leaders.
        //
        // We use `start_state_transfer` (not `start_view_change_to`)
        // here: the new leader is already in `Normal` at the higher
        // view, so re-running the view-change protocol cascades —
        // peers in `Normal` that receive a `StartViewChange` for
        // their current view interpret it as "current leader is
        // dead" and bump again to the next view (`on_start_view_change`
        // line 134). Empirically that cascade lands the cluster at
        // an unpredictable view, sometimes on one where the
        // rejoining old leader is the leader-of-record again, and
        // the integration test sees `leader_after == leader`. State
        // transfer is the correct primitive: r0 stays Normal, asks
        // peers for their committed state, applies it, and the
        // response upgrades `self.view` to the cluster's current view
        // with no view-change side effects.
        if heartbeat.view > self.view
            && from == self.config.leader_for_view(heartbeat.view)
        {
            tracing::info!(
                replica = %self.replica_id,
                our_view = %self.view,
                msg_view = %heartbeat.view,
                from = %from,
                "received Heartbeat from higher view, initiating state transfer"
            );
            let (new_self, output) = self.start_state_transfer(Some(heartbeat.view));
            return (new_self, output);
        }

        // Message must be from the leader
        if from != self.leader() {
            return (self, ReplicaOutput::empty());
        }

        // View must match
        if heartbeat.view != self.view {
            // If higher view, we might need to catch up — handled
            // above before the leader filter; lower-view heartbeats
            // are stale and dropped.
            return (self, ReplicaOutput::empty());
        }

        // Heartbeats are intentionally idempotent — a leader fires one
        // every ~heartbeat_interval regardless of whether commit_number
        // advanced, so deduping them would incorrectly silence the
        // liveness signal and spam metrics. No dedup check here.

        // Learn clock sample from leader's heartbeat (backups only)
        // m0 = heartbeat.monotonic_timestamp (when leader sent)
        // t1 = heartbeat.wall_clock_timestamp (leader's wall clock)
        // m2 = now (when we received it)
        if !self.is_leader() {
            let m0 = heartbeat.monotonic_timestamp;
            let t1 = heartbeat.wall_clock_timestamp;
            let m2 = crate::clock::Clock::monotonic_nanos();

            if let Err(e) = self.clock.learn_sample(from, m0, t1, m2) {
                tracing::debug!(
                    replica = %self.replica_id,
                    leader = %from,
                    error = ?e,
                    "failed to learn clock sample from heartbeat"
                );
            }
        }

        // Track sender's version for rolling upgrades
        self.upgrade_state
            .update_replica_version(from, heartbeat.version);

        // Apply any commits we're behind on
        if heartbeat.commit_number > self.commit_number {
            let (new_self, effects) = self.apply_commits_up_to(heartbeat.commit_number);
            return (
                new_self,
                ReplicaOutput::with_messages_and_effects(vec![], effects),
            );
        }

        (self, ReplicaOutput::empty())
    }

    // ========================================================================
    // Timeout Handlers
    // ========================================================================

    /// Handles heartbeat timeout (backup hasn't heard from leader).
    ///
    /// Initiates view change by sending `StartViewChange`.
    pub(crate) fn on_heartbeat_timeout(self) -> (Self, ReplicaOutput) {
        // Only backups care about heartbeat timeout
        if self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status to initiate view change
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Start view change to next view
        self.start_view_change()
    }

    /// Handles clock synchronization timeout (leader attempts to sync clock).
    ///
    /// The leader periodically tries to synchronize the cluster clock using
    /// samples collected from heartbeats.
    pub(crate) fn on_clock_sync_timeout(mut self) -> (Self, ReplicaOutput) {
        // Only leader synchronizes the clock
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Attempt synchronization
        match self.clock.synchronize() {
            Ok(true) => {
                tracing::debug!(
                    replica = %self.replica_id,
                    window_samples = self.clock.window_samples(),
                    interval = ?self.clock.synchronized_interval(),
                    "clock synchronized successfully"
                );
            }
            Ok(false) => {
                // Not enough samples or window not old enough yet
                tracing::trace!(
                    replica = %self.replica_id,
                    window_samples = self.clock.window_samples(),
                    quorum = self.clock.quorum(),
                    "clock synchronization deferred (insufficient samples or window too young)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    replica = %self.replica_id,
                    error = ?e,
                    "clock synchronization failed"
                );
            }
        }

        (self, ReplicaOutput::empty())
    }

    /// Handles prepare timeout (leader didn't get quorum).
    ///
    /// Retransmits the Prepare message.
    pub(crate) fn on_prepare_timeout(self, op: OpNumber) -> (Self, ReplicaOutput) {
        // Only leader cares about prepare timeout
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Operation must still be pending
        if op <= self.commit_number.as_op_number() {
            return (self, ReplicaOutput::empty());
        }

        // Get the log entry
        let entry = match self.log_entry(op) {
            Some(e) => e.clone(),
            None => return (self, ReplicaOutput::empty()),
        };

        // Retransmit Prepare
        let prepare = Prepare::new(self.view, op, entry, self.commit_number);
        let msg = self.sign_message(super::msg_broadcast(
            self.replica_id,
            MessagePayload::Prepare(prepare),
        ));

        (self, ReplicaOutput::with_messages(vec![msg]))
    }

    /// Handles ping timeout (periodic health check).
    ///
    /// Always-running timeout that ensures regular heartbeat activity and
    /// early detection of network failures.
    pub(crate) fn on_ping_timeout(self) -> (Self, ReplicaOutput) {
        // Leader sends heartbeat as ping
        if self.is_leader() && self.status == ReplicaStatus::Normal {
            if let Some(heartbeat) = self.generate_heartbeat() {
                return (self, ReplicaOutput::with_messages(vec![heartbeat]));
            }
        }

        // Backups just note the ping (heartbeat timeout handles leader detection)
        (self, ReplicaOutput::empty())
    }

    /// Handles primary abdicate timeout (leader steps down when partitioned).
    ///
    /// Critical for preventing deadlock when leader is partitioned from quorum
    /// but can still send messages to some replicas.
    pub(crate) fn on_primary_abdicate_timeout(self) -> (Self, ReplicaOutput) {
        // Only leader needs to check for abdication
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Check if we have recent PrepareOK responses from quorum
        // Count unique replicas that have sent PrepareOK for any pending operation
        let mut responding_replicas = HashSet::new();
        for replicas in self.prepare_ok_tracker.values() {
            responding_replicas.extend(replicas.iter().copied());
        }

        let quorum_size = self.config.cluster_size() / 2 + 1;
        let recent_responses = responding_replicas.len();

        // Include self in the count (leader always has its own vote)
        if recent_responses + 1 < quorum_size {
            tracing::warn!(
                replica = %self.replica_id,
                view = %self.view,
                recent_responses = recent_responses,
                quorum_required = quorum_size,
                "leader appears partitioned from quorum, abdicating"
            );

            // Abdicate by starting a view change
            // This allows a replica with quorum connectivity to become leader
            return self.start_view_change();
        }

        (self, ReplicaOutput::empty())
    }

    /// Handles repair sync timeout (escalate to state transfer).
    ///
    /// Triggered when repairs are not making progress, escalates from
    /// repair to full state transfer.
    pub(crate) fn on_repair_sync_timeout(self) -> (Self, ReplicaOutput) {
        // Only applicable if we're actively in repair
        let Some(ref repair_state) = self.repair_state else {
            return (self, ReplicaOutput::empty());
        };

        // Check if repair has been stuck for a while
        // If we have unanswered repair requests or large gaps, escalate
        let gap_size = repair_state.op_range_end.as_u64() - repair_state.op_range_start.as_u64();

        // If gap is large (>100 ops) and we haven't made progress, escalate
        if gap_size > 100 {
            tracing::warn!(
                replica = %self.replica_id,
                repair_start = %repair_state.op_range_start,
                repair_end = %repair_state.op_range_end,
                gap = gap_size,
                "repair not making progress, escalating to state transfer"
            );

            return self.start_state_transfer(None);
        }

        (self, ReplicaOutput::empty())
    }

    /// Handles commit stall timeout (detect pipeline stall).
    ///
    /// Detects when commits are not advancing, applies backpressure to
    /// prevent unbounded pipeline growth.
    pub(crate) fn on_commit_stall_timeout(self) -> (Self, ReplicaOutput) {
        // Only leader manages the pipeline
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Check if commit number hasn't advanced
        let pipeline_len = self.op_number.as_u64() - self.commit_number.as_op_number().as_u64();

        // If pipeline is growing beyond threshold (>10 ops), apply backpressure
        if pipeline_len > 10 {
            tracing::warn!(
                replica = %self.replica_id,
                op_number = %self.op_number,
                commit_number = %self.commit_number,
                pipeline_len = pipeline_len,
                "commit pipeline stalled, applying backpressure"
            );

            // Apply backpressure by temporarily stopping new client requests
            // This is a simple approach - in production might want exponential backoff
            // For now, just log the condition (the pending_requests queue handles the rest)
        }

        (self, ReplicaOutput::empty())
    }

    /// Handles commit message timeout (use heartbeat fallback).
    ///
    /// If commit messages are delayed or dropped, heartbeats ensure commit
    /// progress is eventually notified to backups (commit numbers piggybacked).
    pub(crate) fn on_commit_message_timeout(self) -> (Self, ReplicaOutput) {
        // Only leader sends commit messages
        if !self.is_leader() {
            return (self, ReplicaOutput::empty());
        }

        // Must be in normal status
        if self.status != ReplicaStatus::Normal {
            return (self, ReplicaOutput::empty());
        }

        // Production assertion: Leader handling commit message timeout must be in Normal status
        assert!(
            self.is_leader() && self.status == ReplicaStatus::Normal,
            "commit_message_timeout: leader={} status={:?}",
            self.is_leader(),
            self.status
        );

        // Send heartbeat to notify backups of commit progress
        // This acts as a fallback when Commit messages are delayed/dropped
        if let Some(heartbeat) = self.generate_heartbeat() {
            tracing::debug!(
                replica = %self.replica_id,
                commit_number = %self.commit_number,
                "commit message timeout, sending heartbeat fallback"
            );

            // Production assertion: Heartbeat contains valid commit number
            assert!(
                self.commit_number.as_u64() <= self.op_number.as_u64(),
                "commit_message_timeout: commit_number={} > op_number={}",
                self.commit_number.as_u64(),
                self.op_number.as_u64()
            );

            return (self, ReplicaOutput::with_messages(vec![heartbeat]));
        }

        (self, ReplicaOutput::empty())
    }

    /// Handles start view change window timeout (wait for votes).
    ///
    /// Prevents premature view change completion. After receiving
    /// `StartViewChange` quorum, new leader waits for `DoViewChange` votes
    /// before installing new view (prevents split-brain).
    pub(crate) fn on_start_view_change_window_timeout(self) -> (Self, ReplicaOutput) {
        // This timeout is only relevant during view change
        if self.status != ReplicaStatus::ViewChange {
            return (self, ReplicaOutput::empty());
        }

        // Production assertion: Replica processing this timeout must be in ViewChange status
        assert!(
            self.status == ReplicaStatus::ViewChange,
            "start_view_change_window_timeout: status={:?}, expected ViewChange",
            self.status
        );

        // Check if we're the potential new leader (view % cluster_size == our id)
        let potential_leader = self.view.as_u64() as usize % self.config.cluster_size();

        // Production assertion: Potential leader calculation produces valid replica index
        assert!(
            potential_leader < self.config.cluster_size(),
            "start_view_change_window_timeout: potential_leader={} >= cluster_size={}",
            potential_leader,
            self.config.cluster_size()
        );

        if potential_leader != self.replica_id.as_usize() {
            // Not our turn to be leader, ignore
            return (self, ReplicaOutput::empty());
        }

        // Check if we have received StartViewChange quorum but not enough DoViewChange votes yet
        // This timeout allows us to proceed if we've waited long enough
        tracing::debug!(
            replica = %self.replica_id,
            view = %self.view,
            potential_leader = %potential_leader,
            "start view change window expired, checking if ready to install new view"
        );

        // Production assertion: View number must be positive (not ZERO) during view change
        assert!(
            self.view.as_u64() > 0,
            "start_view_change_window_timeout: view={} must be > 0",
            self.view.as_u64()
        );

        // The actual view change logic is handled in view_change.rs
        // This timeout just signals that the waiting window has expired
        // and we can now consider installing the new view if we have quorum
        (self, ReplicaOutput::empty())
    }

    /// Handles scrub timeout (periodic background checksum validation).
    ///
    /// Runs continuously in background to tour the entire log, validating
    /// checksums on every entry to detect silent corruption before it causes
    /// double-fault data loss.
    pub(crate) fn on_scrub_timeout(mut self) -> (Self, ReplicaOutput) {
        use crate::log_scrubber::ScrubResult;

        // Reset budget for new tick
        self.log_scrubber.budget_mut().reset_tick();

        // Update scrubber's view of log head
        self.log_scrubber.update_log_head(self.op_number);

        // Scrub as many entries as budget allows
        loop {
            let result = self.log_scrubber.scrub_next(&self.log);

            match result {
                ScrubResult::Ok => {
                    // Entry validated successfully, continue
                }
                ScrubResult::Corruption => {
                    // Corruption detected! Trigger repair for this op
                    let corrupted_ops: Vec<_> = self
                        .log_scrubber
                        .corruptions()
                        .iter()
                        .map(|(op, _)| *op)
                        .collect();

                    if let Some(&last_corrupted) = corrupted_ops.last() {
                        tracing::error!(
                            replica = %self.replica_id,
                            corrupted_op = %last_corrupted,
                            "scrubber detected corruption, triggering repair"
                        );

                        // Start repair for corrupted range
                        return self.start_repair(last_corrupted, last_corrupted.next());
                    }
                    break;
                }
                ScrubResult::TourComplete => {
                    // Tour complete, start new tour
                    let new_head = self.op_number;
                    self.log_scrubber.start_new_tour(new_head);

                    tracing::debug!(
                        replica = %self.replica_id,
                        tour = self.log_scrubber.tour_count() - 1,
                        "scrub tour complete"
                    );
                    break;
                }
                ScrubResult::BudgetExhausted => {
                    // Budget depleted, wait for next tick
                    break;
                }
            }
        }

        (self, ReplicaOutput::empty())
    }

    // ========================================================================
    // Leader Heartbeat Generation
    // ========================================================================

    /// Generates a heartbeat message (for leader to call on tick).
    pub fn generate_heartbeat(&self) -> Option<crate::Message> {
        if !self.is_leader() || self.status != ReplicaStatus::Normal {
            return None;
        }

        // Send heartbeat with leader's clock samples for synchronization
        let monotonic_timestamp = crate::clock::Clock::monotonic_nanos();
        let wall_clock_timestamp = crate::clock::Clock::realtime_nanos();
        let heartbeat = Heartbeat::new(
            self.view,
            self.commit_number,
            monotonic_timestamp,
            wall_clock_timestamp,
            self.upgrade_state.self_version,
        );
        Some(self.sign_message(super::msg_broadcast(
            self.replica_id,
            MessagePayload::Heartbeat(heartbeat),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClusterConfig;
    use crate::types::{CommitNumber, LogEntry, OpNumber, ViewNumber};
    use kimberlite_kernel::Command;
    use kimberlite_types::{DataClass, Placement};

    fn test_config_3() -> ClusterConfig {
        ClusterConfig::new(vec![
            ReplicaId::new(0),
            ReplicaId::new(1),
            ReplicaId::new(2),
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
    fn leader_prepare_broadcasts_to_backups() {
        let config = test_config_3();
        let leader = ReplicaState::new(ReplicaId::new(0), config);

        let (_leader, output) = leader.prepare_new_operation(test_command(), None, None, None);

        // Should have broadcast Prepare message
        assert!(!output.messages.is_empty());

        let prepare_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::Prepare(_)));
        assert!(prepare_msg.is_some());
        assert!(prepare_msg.unwrap().is_broadcast());
    }

    #[test]
    fn backup_responds_with_prepare_ok() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Leader sends Prepare
        let prepare = Prepare::new(
            ViewNumber::ZERO,
            OpNumber::new(1),
            test_entry(1, 0),
            CommitNumber::ZERO,
        );

        let (backup, output) = backup.on_prepare(ReplicaId::new(0), prepare);

        // Backup should respond with PrepareOK
        assert_eq!(output.messages.len(), 1);

        let msg = &output.messages[0];
        assert!(matches!(msg.payload, MessagePayload::PrepareOk(_)));
        assert_eq!(msg.to, Some(ReplicaId::new(0))); // Sent to leader

        // Backup should have the entry in its log
        assert_eq!(backup.log_len(), 1);
        assert_eq!(backup.op_number(), OpNumber::new(1));
    }

    #[test]
    fn leader_commits_on_quorum() {
        let config = test_config_3();
        let mut leader = ReplicaState::new(ReplicaId::new(0), config);

        // Prepare an operation
        let (new_leader, _) = leader.prepare_new_operation(test_command(), None, None, None);
        leader = new_leader;

        // Leader counts itself as one vote
        // Need one more for quorum of 2

        // Backup 1 sends PrepareOK
        let prepare_ok = PrepareOk::new(
            ViewNumber::ZERO,
            OpNumber::new(1),
            ReplicaId::new(1),
            0,
            crate::upgrade::VersionInfo::V0_4_0,
        );
        let (leader, output) = leader.on_prepare_ok(ReplicaId::new(1), prepare_ok);

        // Should have committed
        assert_eq!(leader.commit_number().as_u64(), 1);

        // Should have broadcast Commit
        let commit_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::Commit(_)));
        assert!(commit_msg.is_some());

        // Should have effects from kernel
        assert!(!output.effects.is_empty());
    }

    #[test]
    fn backup_applies_commits_from_heartbeat() {
        let config = test_config_3();
        let mut backup = ReplicaState::new(ReplicaId::new(1), config);

        // Add an entry to backup's log (simulating successful Prepare)
        let entry = test_entry(1, 0);
        backup.log.push(entry);
        backup.op_number = OpNumber::new(1);

        // Leader sends heartbeat with commit
        let heartbeat = Heartbeat::new(
            ViewNumber::ZERO,
            CommitNumber::new(OpNumber::new(1)),
            0,
            0,
            crate::upgrade::VersionInfo::V0_4_0,
        );
        let (backup, output) = backup.on_heartbeat(ReplicaId::new(0), heartbeat);

        // Backup should have committed
        assert_eq!(backup.commit_number().as_u64(), 1);

        // Should have effects from applying the command
        assert!(!output.effects.is_empty());
    }

    #[test]
    fn backup_ignores_prepare_from_non_leader() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Non-leader sends Prepare
        let prepare = Prepare::new(
            ViewNumber::ZERO,
            OpNumber::new(1),
            test_entry(1, 0),
            CommitNumber::ZERO,
        );

        let (backup, output) = backup.on_prepare(ReplicaId::new(2), prepare); // From replica 2, not leader

        // Should be ignored
        assert!(output.is_empty());
        assert_eq!(backup.log_len(), 0);
    }

    #[test]
    fn backup_ignores_prepare_from_lower_view() {
        let config = test_config_3();
        let mut backup = ReplicaState::new(ReplicaId::new(1), config);
        // Simulate backup already being in view 5
        backup = backup.transition_to_view(ViewNumber::new(5));
        backup = backup.enter_normal_status();

        // Someone sends Prepare from old view 0
        let prepare = Prepare::new(
            ViewNumber::new(0), // Lower/old view
            OpNumber::new(1),
            test_entry(1, 0),
            CommitNumber::ZERO,
        );

        let (backup, output) = backup.on_prepare(ReplicaId::new(0), prepare);

        // Should be ignored - stale message from old view
        assert!(output.is_empty());
        assert_eq!(backup.log_len(), 0);
    }

    #[test]
    fn backup_initiates_state_transfer_from_much_higher_view() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Leader sends Prepare from view 99 (much higher than our view 0)
        let prepare = Prepare::new(
            ViewNumber::new(99), // Much higher view
            OpNumber::new(1),
            test_entry(1, 99),
            CommitNumber::ZERO,
        );

        let (backup, output) = backup.on_prepare(ReplicaId::new(0), prepare);

        // Should initiate state transfer (produces broadcast messages)
        assert!(!output.is_empty());
        assert!(backup.state_transfer_state.is_some());
    }

    #[test]
    fn backup_initiates_view_change_from_slightly_higher_view() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Leader sends Prepare from view 2 (slightly higher than our view 0)
        let prepare = Prepare::new(
            ViewNumber::new(2), // Slightly higher view
            OpNumber::new(1),
            test_entry(1, 2),
            CommitNumber::ZERO,
        );

        let (backup, output) = backup.on_prepare(ReplicaId::new(0), prepare);

        // Should initiate view change (produces broadcast messages)
        assert!(!output.is_empty());
        assert_eq!(backup.status(), crate::ReplicaStatus::ViewChange);
    }

    #[test]
    fn leader_generates_heartbeat() {
        let config = test_config_3();
        let leader = ReplicaState::new(ReplicaId::new(0), config.clone());
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Leader can generate heartbeat
        let heartbeat = leader.generate_heartbeat();
        assert!(heartbeat.is_some());

        // Backup cannot generate heartbeat
        let no_heartbeat = backup.generate_heartbeat();
        assert!(no_heartbeat.is_none());
    }

    #[test]
    fn heartbeat_timeout_triggers_view_change() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        let (backup, output) = backup.on_heartbeat_timeout();

        // Should have started view change
        assert_eq!(backup.status(), ReplicaStatus::ViewChange);
        assert_eq!(backup.view(), ViewNumber::new(1));

        // Should have broadcast StartViewChange
        let svc_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::StartViewChange(_)));
        assert!(svc_msg.is_some());
    }

    #[test]
    fn leader_retransmits_on_prepare_timeout() {
        let config = test_config_3();
        let leader = ReplicaState::new(ReplicaId::new(0), config);

        // Prepare an operation
        let (leader, _) = leader.prepare_new_operation(test_command(), None, None, None);

        // Simulate prepare timeout
        let (_, output) = leader.on_prepare_timeout(OpNumber::new(1));

        // Should retransmit Prepare
        let prepare_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::Prepare(_)));
        assert!(prepare_msg.is_some());
    }
}
