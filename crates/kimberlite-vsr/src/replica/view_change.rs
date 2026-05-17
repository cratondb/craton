//! View change protocol handlers.
//!
//! This module implements the VSR view change protocol:
//!
//! 1. **`StartViewChange`**: Backup suspects leader is dead, broadcasts to all
//! 2. **`DoViewChange`**: After receiving quorum of `StartViewChange`, send to new leader
//! 3. **`StartView`**: New leader broadcasts with authoritative log
//!
//! # Safety Properties
//!
//! - Operations committed in previous views are preserved
//! - At most one leader per view
//! - Progress guaranteed if a majority is available

use std::hash::{Hash, Hasher};

use crate::message::{self, DoViewChange, MessagePayload, StartView, StartViewChange};
use crate::types::{CommitNumber, ReplicaId, ReplicaStatus, ViewNumber};

use super::{ReplicaOutput, ReplicaState, msg_broadcast, msg_to};

/// Stable 64-bit hash of the parts of a `DoViewChange` that can
/// legitimately change between two retransmissions from the same
/// (sender, view) pair: `last_normal_view`, `op_number`, and the
/// integrity-checked `log_tail_hash`. Used as the dedup key so genuine
/// retransmissions with newer state pass through to the leader's
/// "use the better message" replacement logic, while byte-identical
/// replays still hash the same and get rejected by the dedup tracker.
///
/// `DefaultHasher` is fine here — this is a dedup key inside a single
/// process, not a cryptographic identity. The integrity check at
/// `view_change.rs::on_do_view_change` (via `log_tail_hash_of`)
/// already guards against tampering with the body.
fn do_view_change_content_hash(dvc: &DoViewChange) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dvc.last_normal_view.hash(&mut hasher);
    dvc.op_number.hash(&mut hasher);
    dvc.log_tail_hash.hash(&mut hasher);
    hasher.finish()
}

impl ReplicaState {
    // ========================================================================
    // View Change Initiation
    // ========================================================================

    /// Initiates a view change to the next view.
    ///
    /// Called when:
    /// - Backup hasn't heard from leader (heartbeat timeout)
    /// - Backup receives `StartViewChange` for higher view
    pub(crate) fn start_view_change(mut self) -> (Self, ReplicaOutput) {
        let new_view = self.view.next();

        // DST: coverage signal — simulation should exercise view changes
        kimberlite_properties::sometimes!(
            true,
            "vsr.view_change_initiated",
            "simulation must exercise the view change path"
        );

        // Transition to new view
        self = self.transition_to_view(new_view);

        // Vote for ourselves
        self.start_view_change_votes.insert(self.replica_id);

        // Broadcast StartViewChange
        let svc = StartViewChange::new(new_view, self.replica_id);
        let msg = self.sign_message(msg_broadcast(
            self.replica_id,
            MessagePayload::StartViewChange(svc),
        ));

        (self, ReplicaOutput::with_messages(vec![msg]))
    }

    // ========================================================================
    // StartViewChange Handler
    // ========================================================================

    /// Handles a `StartViewChange` message.
    ///
    /// If we receive a quorum of `StartViewChange` messages for the same view,
    /// we send `DoViewChange` to the new leader.
    pub(crate) fn on_start_view_change(
        mut self,
        from: ReplicaId,
        svc: StartViewChange,
    ) -> (Self, ReplicaOutput) {
        // If message is for a view we've already passed, ignore
        if svc.view < self.view {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6)
        let msg_id = crate::replica::state::MessageId::start_view_change(from, svc.view);
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::warn!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %svc.view,
                "Replay attack detected: duplicate StartViewChange message"
            );
            crate::instrumentation::METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "start_view_change_replay",
                from,
                0, // StartViewChange has no op_number
                self.op_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // If message is for a higher view than we're tracking, start our own view change
        if svc.view > self.view {
            let (new_self, mut output) = self.start_view_change_to(svc.view);
            self = new_self;

            // Record their vote
            self.start_view_change_votes.insert(from);

            // Check if we have quorum
            let (final_self, quorum_output) = self.check_start_view_change_quorum();
            output.merge(quorum_output);

            return (final_self, output);
        }

        // Message is for current view
        if self.status != ReplicaStatus::ViewChange {
            // We're in Normal status at view N, receiving StartViewChange for view N.
            // This can happen if:
            // 1. We've already completed the view change to view N (stale message)
            // 2. Message duplication/reordering
            //
            // In either case, we should start a new view change to view N+1,
            // since someone thinks the current leader is dead.
            let (new_self, output) = self.start_view_change();
            self = new_self;

            // Note: we don't count their vote for view N since we're now in view N+1.
            // They'll need to send a new StartViewChange for view N+1.

            return (self, output);
        }

        // We're already in view change for this view, just record the vote
        self.start_view_change_votes.insert(from);
        self.check_start_view_change_quorum()
    }

    /// Starts a view change to a specific view.
    ///
    /// Called when we receive a message from a higher view and need to catch up.
    pub(crate) fn start_view_change_to(mut self, view: ViewNumber) -> (Self, ReplicaOutput) {
        // Transition to the new view
        self = self.transition_to_view(view);

        // Vote for ourselves
        self.start_view_change_votes.insert(self.replica_id);

        // Broadcast StartViewChange
        let svc = StartViewChange::new(view, self.replica_id);
        let msg = self.sign_message(msg_broadcast(
            self.replica_id,
            MessagePayload::StartViewChange(svc),
        ));

        (self, ReplicaOutput::with_messages(vec![msg]))
    }

    /// Checks if we have a quorum of `StartViewChange` votes.
    ///
    /// If so, sends `DoViewChange` to the new leader.
    fn check_start_view_change_quorum(self) -> (Self, ReplicaOutput) {
        let quorum = self.config.quorum_size();

        if self.start_view_change_votes.len() >= quorum {
            // We have quorum, send DoViewChange to new leader
            let new_leader = self.config.leader_for_view(self.view);

            // Include reconfiguration state in DoViewChange to preserve it across view changes
            let dvc = DoViewChange::new_with_reconfig(
                self.view,
                self.replica_id,
                self.last_normal_view,
                self.op_number,
                self.commit_number,
                self.log_tail(),
                self.reconfig_state.clone(),
            );

            let msg = self.sign_message(msg_to(
                self.replica_id,
                new_leader,
                MessagePayload::DoViewChange(dvc),
            ));

            (self, ReplicaOutput::with_messages(vec![msg]))
        } else {
            (self, ReplicaOutput::empty())
        }
    }

    // ========================================================================
    // DoViewChange Handler (New Leader)
    // ========================================================================

    /// Handles a `DoViewChange` message (as new leader).
    ///
    /// Once we receive a quorum of `DoViewChange` messages, we:
    /// 1. Select the log with the highest `last_normal_view` and `op_number`
    /// 2. Broadcast `StartView` with the authoritative log
    /// 3. Enter normal operation as leader
    pub(crate) fn on_do_view_change(
        mut self,
        from: ReplicaId,
        dvc: DoViewChange,
    ) -> (Self, ReplicaOutput) {
        // Protect against DoS via oversized log_tail
        if dvc.log_tail.len() > Self::MAX_LOG_TAIL_ENTRIES {
            tracing::error!(
                from = %from.as_u8(),
                entries = dvc.log_tail.len(),
                max = Self::MAX_LOG_TAIL_ENTRIES,
                "DoViewChange log_tail exceeds maximum size - DoS attack detected"
            );

            // Record Byzantine rejection for simulation testing
            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "oversized_log_tail",
                from,
                dvc.log_tail.len() as u64,
                Self::MAX_LOG_TAIL_ENTRIES as u64,
            );

            return (self, ReplicaOutput::empty());
        }

        // Ignore if not for our current view
        if dvc.view != self.view {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6).
        //
        // The dedup key includes a hash of the DoViewChange's
        // `(last_normal_view, op_number, log_tail_hash)` so a sender
        // that legitimately retransmits with newer state (it learned a
        // higher last_normal_view since its first send) is NOT
        // misclassified as a replay — the leader's "use the better
        // message" replacement logic below depends on those
        // retransmissions reaching it. A byte-identical retransmission
        // still hashes the same and is rejected.
        let content_hash = do_view_change_content_hash(&dvc);
        let msg_id = crate::replica::state::MessageId::do_view_change(from, dvc.view, content_hash);
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::warn!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %dvc.view,
                "Replay attack detected: duplicate DoViewChange message"
            );
            crate::instrumentation::METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "do_view_change_replay",
                from,
                0, // DoViewChange has no op_number
                self.op_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // Validate log_tail_hash integrity (AUDIT-2026-03 4.4)
        let expected_hash = message::log_tail_hash_of(&dvc.log_tail);
        if dvc.log_tail_hash != expected_hash {
            tracing::error!(
                from = %from.as_u8(),
                view = %dvc.view,
                "DoViewChange log_tail_hash mismatch — data corruption or Byzantine attack"
            );

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "log_tail_hash_mismatch",
                from,
                0,
                0,
            );

            return (self, ReplicaOutput::empty());
        }

        // We must be the leader for this view
        if self.config.leader_for_view(self.view) != self.replica_id {
            return (self, ReplicaOutput::empty());
        }

        // Must be in ViewChange status
        if self.status != ReplicaStatus::ViewChange {
            // If we're in Normal status for this view, the view change already completed.
            // This is a stale DoViewChange message - ignore it.
            if self.status == ReplicaStatus::Normal {
                return (self, ReplicaOutput::empty());
            }
            // Otherwise (e.g., Recovering status), we shouldn't process view changes.
            return (self, ReplicaOutput::empty());
        }

        // Record the DoViewChange message
        // If we already have one from this replica, check if the new one is better
        if let Some(existing_idx) = self
            .do_view_change_msgs
            .iter()
            .position(|m| m.replica == from)
        {
            let existing = &self.do_view_change_msgs[existing_idx];

            // Check if new message is better: higher (last_normal_view, op_number)
            let is_better = (dvc.last_normal_view, dvc.op_number)
                > (existing.last_normal_view, existing.op_number);

            if is_better {
                tracing::debug!(
                    replica = %from.as_u8(),
                    old_view = %existing.last_normal_view,
                    old_op = %existing.op_number,
                    new_view = %dvc.last_normal_view,
                    new_op = %dvc.op_number,
                    "replacing DoViewChange with better message from same replica"
                );
                self.do_view_change_msgs[existing_idx] = dvc;
            } else {
                tracing::debug!(
                    replica = %from.as_u8(),
                    "ignoring duplicate DoViewChange that is not better"
                );
            }
        } else {
            // No existing message from this replica
            self.do_view_change_msgs.push(dvc);
        }

        // Check if we have quorum
        self.check_do_view_change_quorum()
    }

    /// Checks if we have a quorum of `DoViewChange` messages.
    ///
    /// If so, becomes leader and broadcasts `StartView`.
    fn check_do_view_change_quorum(mut self) -> (Self, ReplicaOutput) {
        let quorum = self.config.quorum_size();

        if self.do_view_change_msgs.len() < quorum {
            return (self, ReplicaOutput::empty());
        }

        // We have quorum! Become the leader.

        // Find the DoViewChange with the highest (last_normal_view, op_number)
        // This ensures we pick the most up-to-date log.
        //
        // CRITICAL: When multiple messages have identical (last_normal_view, op_number),
        // we must break the tie deterministically to prevent log divergence.
        // We use the hash of the last log entry, then replica ID as final tie-breaker.
        // Extract the log tail and reconfig state we need before moving self.
        let (best_log_tail, best_reconfig_state) = {
            let best_dvc = self
                .do_view_change_msgs
                .iter()
                .max_by(|a, b| {
                    // Primary: (last_normal_view, op_number)
                    let primary_cmp =
                        (a.last_normal_view, a.op_number).cmp(&(b.last_normal_view, b.op_number));

                    if primary_cmp != std::cmp::Ordering::Equal {
                        return primary_cmp;
                    }

                    // Tie-breaker 1: Checksum of last log entry (deterministic)
                    let a_checksum = a.log_tail.last().map_or(0, |e| e.checksum);
                    let b_checksum = b.log_tail.last().map_or(0, |e| e.checksum);
                    let checksum_cmp = a_checksum.cmp(&b_checksum);

                    if checksum_cmp != std::cmp::Ordering::Equal {
                        return checksum_cmp;
                    }

                    // Tie-breaker 2: Replica ID (final, always deterministic)
                    a.replica.as_u8().cmp(&b.replica.as_u8())
                })
                .expect("at least quorum messages");

            // Validate log_tail length matches claimed op_number when commit is reasonable
            // Note: We allow commit_number > op_number because the Byzantine protection
            // happens AFTER merge_log_tail() when we check against actual op_number
            if best_dvc.commit_number.as_op_number() <= best_dvc.op_number {
                let expected_tail_len =
                    (best_dvc.op_number.as_u64() - best_dvc.commit_number.as_u64()) as usize;
                if best_dvc.log_tail.len() != expected_tail_len {
                    tracing::error!(
                        replica = %best_dvc.replica.as_u8(),
                        claimed_ops = %best_dvc.op_number,
                        commit = %best_dvc.commit_number,
                        expected_tail_len = expected_tail_len,
                        actual_tail_len = best_dvc.log_tail.len(),
                        "DoViewChange log_tail length mismatch - Byzantine attack detected"
                    );

                    // Record Byzantine rejection for simulation testing
                    #[cfg(feature = "sim")]
                    crate::instrumentation::record_byzantine_rejection(
                        "log_tail_length_mismatch",
                        best_dvc.replica,
                        best_dvc.log_tail.len() as u64,
                        expected_tail_len as u64,
                    );

                    // Reject this view change quorum - cannot safely proceed
                    return (self, ReplicaOutput::empty());
                }
            }

            (best_dvc.log_tail.clone(), best_dvc.reconfig_state.clone())
        };

        // Merge the log tail from the best DoViewChange
        // IMPORTANT: This sets op_number based on actual log entries, not claimed op_number
        self = self.merge_log_tail(best_log_tail);

        // Restore reconfiguration state from the best DoViewChange
        // This ensures reconfigurations survive leader failures
        if let Some(reconfig_state) = best_reconfig_state {
            self.reconfig_state = reconfig_state;
        }

        // Calculate max achievable commit (protects against inflated values)
        // Use self.op_number which is now set based on actual log entries
        let max_commit = self.calculate_max_achievable_commit(self.op_number);

        // Apply commits up to the max achievable commit
        let (new_self, effects) = self.apply_commits_up_to(max_commit);
        self = new_self;

        // Invariant check before entering normal status
        debug_assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "view change: commit={} > op={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        // DST: view change safety — the new leader must have all committed ops
        kimberlite_properties::always!(
            self.commit_number.as_op_number() <= self.op_number,
            "vsr.view_change_commit_le_op",
            "after view change merge, commit must not exceed op_number"
        );
        // DST: view change quorum — must have received quorum of DoViewChange
        kimberlite_properties::always!(
            self.do_view_change_msgs.len() >= self.config.quorum_size(),
            "vsr.view_change_quorum_met",
            "new leader must have received quorum of DoViewChange messages"
        );
        // DST: coverage signal — simulation should exercise the full view change path
        kimberlite_properties::sometimes!(
            true,
            "vsr.view_change_completed",
            "simulation must exercise view change completion through DoViewChange quorum"
        );

        // Enter normal status as leader
        self = self.enter_normal_status();

        // Broadcast StartView with reconfiguration state
        let start_view = StartView::new_with_reconfig(
            self.view,
            self.op_number,
            self.commit_number,
            self.log_tail(),
            self.reconfig_state.clone(),
        );

        let msg = self.sign_message(msg_broadcast(
            self.replica_id,
            MessagePayload::StartView(start_view),
        ));

        (
            self,
            ReplicaOutput::with_messages_and_effects(vec![msg], effects),
        )
    }

    // ========================================================================
    // StartView Handler (Backup)
    // ========================================================================

    /// Maximum `log_tail` entries in a `StartView` message to prevent `DoS` attacks.
    ///
    /// A Byzantine leader could send millions of entries to exhaust memory.
    /// This limit allows reasonable catchup (10K uncommitted ops) while preventing `DoS`.
    const MAX_LOG_TAIL_ENTRIES: usize = 10_000;

    /// Handles a `StartView` message from the new leader.
    ///
    /// The backup:
    /// 1. Updates its log from the message
    /// 2. Applies any new commits
    /// 3. Enters normal operation
    // VSR StartView handler — length reflects DoS-guarded log ingestion,
    // log_tail_hash validation, reconfig state restoration, commit catch-up,
    // and status transition. Splitting into helpers would hide the linear
    // protocol ordering that's critical to audit.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn on_start_view(mut self, from: ReplicaId, sv: StartView) -> (Self, ReplicaOutput) {
        // Must be from the leader for this view
        if from != self.config.leader_for_view(sv.view) {
            return (self, ReplicaOutput::empty());
        }

        // Replay detection (AUDIT-2026-03 M-6)
        let msg_id = crate::replica::state::MessageId::start_view(from, sv.view);
        if self.message_dedup_tracker.check_and_record(msg_id).is_err() {
            tracing::warn!(
                replica = %self.replica_id,
                from = %from.as_u8(),
                view = %sv.view,
                "Replay attack detected: duplicate StartView message"
            );
            crate::instrumentation::METRICS.increment_replay_attacks();

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "start_view_replay",
                from,
                0, // StartView has no op_number
                self.op_number.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // Protect against DoS via oversized log_tail
        if sv.log_tail.len() > Self::MAX_LOG_TAIL_ENTRIES {
            tracing::error!(
                from = %from.as_u8(),
                entries = sv.log_tail.len(),
                max = Self::MAX_LOG_TAIL_ENTRIES,
                "StartView log_tail exceeds maximum size - DoS attack detected"
            );

            // Record Byzantine rejection for simulation testing
            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "oversized_log_tail",
                from,
                sv.log_tail.len() as u64,
                Self::MAX_LOG_TAIL_ENTRIES as u64,
            );

            return (self, ReplicaOutput::empty());
        }

        // Validate log_tail_hash integrity (AUDIT-2026-03 4.4)
        let expected_hash = message::log_tail_hash_of(&sv.log_tail);
        if sv.log_tail_hash != expected_hash {
            tracing::error!(
                from = %from.as_u8(),
                view = %sv.view,
                "StartView log_tail_hash mismatch — data corruption or Byzantine leader"
            );

            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "start_view_log_tail_hash_mismatch",
                from,
                0,
                0,
            );

            return (self, ReplicaOutput::empty());
        }

        // If we're behind, accept the new view
        if sv.view < self.view {
            tracing::warn!(
                claimed_view = %sv.view,
                actual_view = %self.view,
                "StartView has regressed view number - Byzantine attack or stale message"
            );

            // Record Byzantine rejection for simulation testing
            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "view_regression",
                from,
                sv.view.as_u64(),
                self.view.as_u64(),
            );

            return (self, ReplicaOutput::empty());
        }

        // Update to the new view if needed
        if sv.view > self.view {
            self.view = sv.view;
        }

        // Validate log_tail length matches claimed op_number when commit is reasonable
        // Note: We allow commit_number > op_number because the Byzantine protection
        // happens AFTER merge_log_tail() when we check against actual op_number
        if sv.commit_number.as_op_number() <= sv.op_number {
            let expected_tail_len = (sv.op_number.as_u64() - sv.commit_number.as_u64()) as usize;
            if sv.log_tail.len() != expected_tail_len {
                tracing::error!(
                    claimed_op = %sv.op_number,
                    commit = %sv.commit_number,
                    expected_tail_len = expected_tail_len,
                    actual_tail_len = sv.log_tail.len(),
                    "StartView log_tail length mismatch - Byzantine attack detected"
                );

                // Record Byzantine rejection for simulation testing
                #[cfg(feature = "sim")]
                crate::instrumentation::record_byzantine_rejection(
                    "log_tail_length_mismatch",
                    from,
                    sv.log_tail.len() as u64,
                    expected_tail_len as u64,
                );

                return (self, ReplicaOutput::empty());
            }
        }

        // Extract fields before consuming sv
        let reconfig_state = sv.reconfig_state;
        let commit_number = sv.commit_number;

        // Merge the log tail
        // IMPORTANT: This sets op_number based on actual log entries, not claimed op_number
        self = self.merge_log_tail(sv.log_tail);

        // Restore reconfiguration state from the new leader
        // This ensures backups adopt the leader's reconfiguration state
        if let Some(reconfig_state_value) = reconfig_state {
            self.reconfig_state = reconfig_state_value;
        }

        // Validate commit_number doesn't exceed our actual op_number (Byzantine protection)
        let safe_commit = if commit_number.as_op_number() > self.op_number {
            tracing::warn!(
                claimed_commit = %commit_number,
                actual_op = %self.op_number,
                "StartView has inflated commit_number, capping to op_number"
            );

            // Record Byzantine rejection for simulation testing
            #[cfg(feature = "sim")]
            crate::instrumentation::record_byzantine_rejection(
                "inflated_commit_number",
                from,
                commit_number.as_u64(),
                self.op_number.as_u64(),
            );

            CommitNumber::new(self.op_number)
        } else {
            commit_number
        };

        // Apply commits
        let (new_self, effects) = self.apply_commits_up_to(safe_commit);
        self = new_self;

        // Invariant check after applying commits
        debug_assert!(
            self.commit_number.as_op_number() <= self.op_number,
            "on_start_view: commit={} > op={}",
            self.commit_number.as_u64(),
            self.op_number.as_u64()
        );

        // Enter normal status
        self = self.enter_normal_status();

        (
            self,
            ReplicaOutput::with_messages_and_effects(vec![], effects),
        )
    }

    // ========================================================================
    // View Change Timeout
    // ========================================================================

    /// Handles view change timeout (view change taking too long).
    ///
    /// Starts a new view change to an even higher view.
    pub(crate) fn on_view_change_timeout(self) -> (Self, ReplicaOutput) {
        // Only relevant if we're in ViewChange status
        if self.status != ReplicaStatus::ViewChange {
            return (self, ReplicaOutput::empty());
        }

        // Start view change to next view
        self.start_view_change()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClusterConfig;
    use crate::types::{CommitNumber, LogEntry, OpNumber};
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
    fn start_view_change_transitions_status() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        let (backup, output) = backup.start_view_change();

        assert_eq!(backup.status(), ReplicaStatus::ViewChange);
        assert_eq!(backup.view(), ViewNumber::new(1));

        // Should broadcast StartViewChange
        assert_eq!(output.messages.len(), 1);
        assert!(matches!(
            output.messages[0].payload,
            MessagePayload::StartViewChange(_)
        ));
    }

    #[test]
    fn quorum_of_start_view_change_sends_do_view_change() {
        let config = test_config_3();
        let mut backup = ReplicaState::new(ReplicaId::new(1), config);

        // Start our own view change (votes for ourselves)
        let (new_backup, _) = backup.start_view_change();
        backup = new_backup;

        // Receive StartViewChange from replica 2
        let svc = StartViewChange::new(ViewNumber::new(1), ReplicaId::new(2));
        let (_backup, output) = backup.on_start_view_change(ReplicaId::new(2), svc);

        // Now we have quorum (ourselves + replica 2)
        // Should send DoViewChange to new leader (replica 1, which is us in view 1)
        let dvc_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::DoViewChange(_)));
        assert!(dvc_msg.is_some());
    }

    #[test]
    fn new_leader_waits_for_quorum_of_do_view_change() {
        let config = test_config_3();

        // In view 1, replica 1 is leader
        let mut new_leader = ReplicaState::new(ReplicaId::new(1), config.clone());
        new_leader = new_leader.transition_to_view(ViewNumber::new(1));

        // Receive DoViewChange from replica 0
        let dvc0 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::ZERO,
            CommitNumber::ZERO,
            vec![],
        );

        let (new_leader, output) = new_leader.on_do_view_change(ReplicaId::new(0), dvc0);

        // Don't have quorum yet (need 2, got 1)
        assert!(output.is_empty());
        assert_eq!(new_leader.status(), ReplicaStatus::ViewChange);

        // Receive DoViewChange from replica 2
        let dvc2 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(2),
            ViewNumber::ZERO,
            OpNumber::ZERO,
            CommitNumber::ZERO,
            vec![],
        );

        let (new_leader, output) = new_leader.on_do_view_change(ReplicaId::new(2), dvc2);

        // Now have quorum, should become leader
        assert_eq!(new_leader.status(), ReplicaStatus::Normal);
        assert!(new_leader.is_leader());

        // Should broadcast StartView
        let sv_msg = output
            .messages
            .iter()
            .find(|m| matches!(m.payload, MessagePayload::StartView(_)));
        assert!(sv_msg.is_some());
    }

    #[test]
    fn new_leader_picks_best_log() {
        let config = test_config_3();

        let mut new_leader = ReplicaState::new(ReplicaId::new(1), config.clone());
        new_leader = new_leader.transition_to_view(ViewNumber::new(1));

        // Replica 0 has op 1
        let dvc0 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::new(1),
            CommitNumber::ZERO,
            vec![test_entry(1, 0)],
        );

        // Replica 2 has op 1 and op 2
        let dvc2 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(2),
            ViewNumber::ZERO,
            OpNumber::new(2),
            CommitNumber::ZERO,
            vec![test_entry(1, 0), test_entry(2, 0)],
        );

        let (new_leader, _) = new_leader.on_do_view_change(ReplicaId::new(0), dvc0);
        let (new_leader, _) = new_leader.on_do_view_change(ReplicaId::new(2), dvc2);

        // Should have picked the log from replica 2 (highest op_number)
        assert_eq!(new_leader.op_number(), OpNumber::new(2));
        assert_eq!(new_leader.log_len(), 2);
    }

    #[test]
    fn backup_accepts_start_view() {
        let config = test_config_3();

        let mut backup = ReplicaState::new(ReplicaId::new(0), config);
        backup = backup.transition_to_view(ViewNumber::new(1));

        assert_eq!(backup.status(), ReplicaStatus::ViewChange);

        // New leader (replica 1) sends StartView
        let sv = StartView::new(
            ViewNumber::new(1),
            OpNumber::new(2),
            CommitNumber::ZERO,
            vec![test_entry(1, 1), test_entry(2, 1)],
        );

        let (backup, _) = backup.on_start_view(ReplicaId::new(1), sv);

        // Should be in normal status now
        assert_eq!(backup.status(), ReplicaStatus::Normal);
        assert_eq!(backup.view(), ViewNumber::new(1));
        assert_eq!(backup.op_number(), OpNumber::new(2));
        assert_eq!(backup.log_len(), 2);
    }

    #[test]
    fn view_change_timeout_starts_higher_view() {
        let config = test_config_3();

        let mut backup = ReplicaState::new(ReplicaId::new(1), config);
        backup = backup.transition_to_view(ViewNumber::new(1));

        let (backup, output) = backup.on_view_change_timeout();

        // Should start view change to view 2
        assert_eq!(backup.view(), ViewNumber::new(2));

        // Should broadcast StartViewChange for view 2
        let svc_msg = output.messages.iter().find(|m| {
            if let MessagePayload::StartViewChange(svc) = &m.payload {
                svc.view == ViewNumber::new(2)
            } else {
                false
            }
        });
        assert!(svc_msg.is_some());
    }

    #[test]
    fn higher_view_triggers_view_change() {
        let config = test_config_3();
        let backup = ReplicaState::new(ReplicaId::new(1), config);

        // Currently in view 0
        assert_eq!(backup.view(), ViewNumber::ZERO);

        // Receive StartViewChange for view 5
        let svc = StartViewChange::new(ViewNumber::new(5), ReplicaId::new(2));
        let (backup, _) = backup.on_start_view_change(ReplicaId::new(2), svc);

        // Should jump to view 5
        assert_eq!(backup.view(), ViewNumber::new(5));
        assert_eq!(backup.status(), ReplicaStatus::ViewChange);
    }

    #[test]
    fn byzantine_inflated_commit_in_do_view_change() {
        let config = test_config_3();

        // Replica 1 is the new leader in view 1
        let mut new_leader = ReplicaState::new(ReplicaId::new(1), config.clone());
        new_leader = new_leader.transition_to_view(ViewNumber::new(1));

        // Byzantine replica 0 sends DoViewChange with inflated commit_number
        // Claims commit_number=1000 but only has op_number=2
        let dvc0 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::new(2),
            CommitNumber::new(OpNumber::new(1000)), // INFLATED!
            vec![test_entry(1, 0), test_entry(2, 0)],
        );

        // Honest replica 2 sends DoViewChange with correct state
        let dvc2 = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(2),
            ViewNumber::ZERO,
            OpNumber::new(1),
            CommitNumber::ZERO,
            vec![test_entry(1, 0)],
        );

        let (new_leader, _) = new_leader.on_do_view_change(ReplicaId::new(0), dvc0);
        let (new_leader, _output) = new_leader.on_do_view_change(ReplicaId::new(2), dvc2);

        // Leader should now be in normal status
        assert_eq!(new_leader.status(), ReplicaStatus::Normal);

        // CRITICAL: Leader's commit_number should NOT exceed op_number
        // Even though Byzantine replica claimed commit=1000
        assert!(
            new_leader.commit_number().as_op_number() <= new_leader.op_number(),
            "commit_number={} > op_number={} - Byzantine attack succeeded!",
            new_leader.commit_number().as_u64(),
            new_leader.op_number().as_u64()
        );

        // Leader should have op_number=2 (from best DoViewChange)
        assert_eq!(new_leader.op_number(), OpNumber::new(2));

        // commit_number should be bounded by actual log entries, not inflated value
        assert!(new_leader.commit_number().as_u64() <= 2);
    }

    #[test]
    fn byzantine_inflated_commit_in_start_view() {
        let config = test_config_3();

        // Backup starts in view 0
        let backup = ReplicaState::new(ReplicaId::new(0), config);
        let backup = backup.transition_to_view(ViewNumber::new(1));

        assert_eq!(backup.status(), ReplicaStatus::ViewChange);

        // Byzantine leader (replica 1) sends StartView with inflated commit_number
        // Claims commit_number=1000 but only sends 2 entries
        let sv = StartView::new(
            ViewNumber::new(1),
            OpNumber::new(2),                       // Claims op_number=2
            CommitNumber::new(OpNumber::new(1000)), // But claims commit=1000!
            vec![test_entry(1, 1), test_entry(2, 1)],
        );

        let (backup, _) = backup.on_start_view(ReplicaId::new(1), sv);

        // Backup should be in normal status
        assert_eq!(backup.status(), ReplicaStatus::Normal);

        // CRITICAL: Backup's commit_number should NOT exceed op_number
        assert!(
            backup.commit_number().as_op_number() <= backup.op_number(),
            "commit_number={} > op_number={} - Byzantine attack succeeded!",
            backup.commit_number().as_u64(),
            backup.op_number().as_u64()
        );

        // Backup should have op_number=2 (from actual log entries merged)
        assert_eq!(backup.op_number(), OpNumber::new(2));

        // commit_number should be capped at 2 (not 1000)
        assert!(backup.commit_number().as_u64() <= 2);
    }

    #[test]
    fn reconfig_state_preserved_across_view_change() {
        use crate::reconfiguration::ReconfigState;

        let old_config = test_config_3();
        let mut new_config_replicas = old_config.replicas().collect::<Vec<_>>();
        new_config_replicas.push(ReplicaId::new(3));
        new_config_replicas.push(ReplicaId::new(4));
        let new_config = ClusterConfig::new(new_config_replicas);

        // Create replica 1 in joint consensus state
        let mut replica1 = ReplicaState::new(ReplicaId::new(1), old_config.clone());
        replica1.reconfig_state =
            ReconfigState::new_joint(old_config.clone(), new_config.clone(), OpNumber::new(5));
        replica1 = replica1.enter_normal_status(); // Start in Normal status

        // Replica 1 starts view change
        let (replica1, _) = replica1.start_view_change();
        assert_eq!(replica1.status(), ReplicaStatus::ViewChange);

        // Simulate receiving StartViewChange from replica 0
        let svc = StartViewChange::new(ViewNumber::new(1), ReplicaId::new(0));
        let (_replica1, output) = replica1.on_start_view_change(ReplicaId::new(0), svc);

        // Should have quorum and send DoViewChange
        let dvc_msg = output.messages.iter().find_map(|m| {
            if let MessagePayload::DoViewChange(dvc) = &m.payload {
                Some(dvc.clone())
            } else {
                None
            }
        });
        assert!(dvc_msg.is_some(), "Should send DoViewChange after quorum");
        let dvc = dvc_msg.unwrap();

        // CRITICAL: DoViewChange should include reconfig_state
        assert!(
            dvc.reconfig_state.is_some(),
            "DoViewChange should include reconfig_state"
        );
        assert!(
            dvc.reconfig_state.unwrap().is_joint(),
            "reconfig_state should be in joint consensus"
        );

        // Verify that backup receives StartView and restores reconfig_state
        let mut backup = ReplicaState::new(ReplicaId::new(2), old_config.clone());
        backup = backup.transition_to_view(ViewNumber::new(1));

        // Leader sends StartView with reconfig_state
        // Use matching op_number and commit_number so log_tail can be empty
        let sv = StartView::new_with_reconfig(
            ViewNumber::new(1),
            OpNumber::ZERO,
            CommitNumber::ZERO,
            vec![],
            ReconfigState::new_joint(old_config.clone(), new_config.clone(), OpNumber::new(5)),
        );

        assert!(
            sv.reconfig_state.is_some(),
            "StartView should have reconfig_state"
        );

        let (backup, _) = backup.on_start_view(ReplicaId::new(1), sv);

        // Backup should restore joint consensus state from StartView
        assert!(
            backup.reconfig_state.is_joint(),
            "Backup should restore joint consensus state from StartView"
        );
    }

    /// Helper: identical DoViewChange retransmissions are still rejected
    /// by the dedup gate. Guards against regressing the audit-2026-03
    /// replay-protection contract while we loosen dedup to admit
    /// "better message" retransmissions.
    #[test]
    fn duplicate_do_view_change_with_identical_content_is_rejected() {
        let config = test_config_3();
        let mut leader = ReplicaState::new(ReplicaId::new(1), config);
        leader = leader.transition_to_view(ViewNumber::new(1));

        let dvc = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::new(1),
            CommitNumber::ZERO,
            vec![test_entry(1, 0)],
        );

        let (leader, _) = leader.on_do_view_change(ReplicaId::new(0), dvc.clone());
        assert_eq!(
            leader.do_view_change_msgs.len(),
            1,
            "first DVC should be recorded"
        );

        // Replay the exact same bytes — must hash to the same key and
        // be rejected by the dedup tracker.
        let (leader, _) = leader.on_do_view_change(ReplicaId::new(0), dvc);
        assert_eq!(
            leader.do_view_change_msgs.len(),
            1,
            "byte-identical retransmission should NOT add a second entry"
        );
    }

    /// Sender legitimately retransmits a DoViewChange after learning a
    /// higher op_number. Pre-fix: dedup rejected it as "replay" and
    /// the leader's "use better message" replacement at lines ~287-318
    /// never got to run. Post-fix: content_hash differs, dedup admits
    /// it, replacement logic upgrades the cached entry.
    #[test]
    fn better_do_view_change_retransmission_replaces_existing() {
        let config = test_config_3();
        let mut leader = ReplicaState::new(ReplicaId::new(1), config);
        leader = leader.transition_to_view(ViewNumber::new(1));

        // First send: small log
        let dvc_initial = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::new(1),
            CommitNumber::ZERO,
            vec![test_entry(1, 0)],
        );
        let (leader, _) = leader.on_do_view_change(ReplicaId::new(0), dvc_initial);
        let recorded = leader
            .do_view_change_msgs
            .iter()
            .find(|m| m.replica == ReplicaId::new(0))
            .map(|m| m.op_number);
        assert_eq!(
            recorded,
            Some(OpNumber::new(1)),
            "leader should have recorded the initial op_number"
        );

        // Same sender, same view, but a longer/newer log — the dedup
        // gate must NOT shadow this update.
        let dvc_better = DoViewChange::new(
            ViewNumber::new(1),
            ReplicaId::new(0),
            ViewNumber::ZERO,
            OpNumber::new(3),
            CommitNumber::ZERO,
            vec![test_entry(1, 0), test_entry(2, 0), test_entry(3, 0)],
        );
        let (leader, _) = leader.on_do_view_change(ReplicaId::new(0), dvc_better);
        let recorded_after = leader
            .do_view_change_msgs
            .iter()
            .find(|m| m.replica == ReplicaId::new(0))
            .map(|m| m.op_number);
        assert_eq!(
            recorded_after,
            Some(OpNumber::new(3)),
            "leader should have replaced the cached DVC with the higher-op_number retransmission"
        );
    }
}
