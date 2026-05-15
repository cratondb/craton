//! Unit tests for kmb-types

use crate::{
    AppliedIndex, Checkpoint, CheckpointPolicy, DataClass, Generation, GroupId, HASH_LENGTH, Hash,
    IDEMPOTENCY_ID_LENGTH, IdempotencyId, Offset, RecordHeader, RecordKind, RecoveryReason,
    RecoveryRecord, Region, StreamId, StreamName, TenantId, Timestamp,
};

// ============================================================================
// DataClass Default — healthcare-first defaults assertion
// ============================================================================

#[test]
fn data_class_default_is_phi() {
    // Sprint 2 (healthcare-only pivot): any stream created without an
    // explicit classification is treated as PHI. Regressing this default
    // back to `Confidential` or `Public` would silently weaken HIPAA
    // posture on new streams — fail loud here so the change is intentional.
    assert_eq!(DataClass::default(), DataClass::PHI);
}

// ============================================================================
// ID Type Tests
// ============================================================================

#[test]
fn stream_id_from_u64_roundtrip() {
    let id = StreamId::new(42);
    let raw: u64 = id.into();
    assert_eq!(raw, 42);
}

#[test]
fn offset_addition() {
    let a = Offset::new(10);
    let b = Offset::new(5);
    assert_eq!((a + b).as_u64(), 15);
}

#[test]
fn offset_add_assign() {
    let mut a = Offset::new(10);
    a += Offset::new(5);
    assert_eq!(a.as_u64(), 15);
}

#[test]
fn offset_subtraction() {
    let a = Offset::new(10);
    let b = Offset::new(3);
    assert_eq!((a - b).as_u64(), 7);
}

// ============================================================================
// StreamName Tests
// ============================================================================

#[test]
fn stream_name_from_str() {
    let name = StreamName::new("test-stream");
    assert_eq!(name.as_str(), "test-stream");
}

#[test]
fn stream_name_from_string() {
    let name = StreamName::new(String::from("test-stream"));
    assert_eq!(name.as_str(), "test-stream");
}

// ============================================================================
// Region Tests
// ============================================================================

#[test]
fn region_display_known_regions() {
    assert_eq!(Region::USEast1.to_string(), "us-east-1");
    assert_eq!(Region::APSoutheast2.to_string(), "ap-southeast-2");
}

#[test]
fn region_display_custom() {
    let region = Region::custom("eu-west-1");
    assert_eq!(region.to_string(), "eu-west-1");
}

// ============================================================================
// Hash Tests
// ============================================================================

#[test]
fn hash_genesis_is_all_zeros() {
    let genesis = Hash::GENESIS;
    assert!(genesis.is_genesis());
    assert_eq!(genesis.as_bytes(), &[0u8; HASH_LENGTH]);
}

#[test]
fn hash_from_bytes_roundtrip() {
    let bytes = [42u8; HASH_LENGTH];
    let hash = Hash::from_bytes(bytes);
    assert_eq!(hash.as_bytes(), &bytes);
    assert!(!hash.is_genesis());
}

#[test]
fn hash_display_shows_hex() {
    let bytes = [0xab; HASH_LENGTH];
    let hash = Hash::from_bytes(bytes);
    let display = hash.to_string();
    assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
    assert!(display.chars().all(|c| c == 'a' || c == 'b'));
}

#[test]
fn hash_debug_shows_truncated() {
    let bytes = [0xab; HASH_LENGTH];
    let hash = Hash::from_bytes(bytes);
    let debug = format!("{hash:?}");
    assert!(debug.starts_with("Hash(abababab"));
    assert!(debug.ends_with("...)"));
}

// ============================================================================
// Timestamp Tests
// ============================================================================

#[test]
fn timestamp_epoch_is_zero() {
    assert_eq!(Timestamp::EPOCH.as_nanos(), 0);
    assert_eq!(Timestamp::EPOCH.as_secs(), 0);
}

#[test]
fn timestamp_from_nanos_roundtrip() {
    let ts = Timestamp::from_nanos(1_000_000_000);
    assert_eq!(ts.as_nanos(), 1_000_000_000);
    assert_eq!(ts.as_secs(), 1);
}

#[test]
fn timestamp_now_is_reasonable() {
    let ts = Timestamp::now();
    // Should be after 2020 (1577836800 seconds since epoch)
    assert!(ts.as_secs() > 1_577_836_800);
}

#[test]
fn timestamp_monotonic_increases() {
    let first = Timestamp::from_nanos(100);
    let second = Timestamp::now_monotonic(Some(first));
    assert!(second > first);
}

#[test]
fn timestamp_monotonic_handles_clock_skew() {
    // Simulate a timestamp far in the future
    let future = Timestamp::from_nanos(u64::MAX - 1000);
    let next = Timestamp::now_monotonic(Some(future));
    // Should be at least future + 1
    assert!(next > future);
}

#[test]
fn timestamp_display_format() {
    let ts = Timestamp::from_nanos(1_234_567_890);
    let display = ts.to_string();
    assert_eq!(display, "1.234567890");
}

// ============================================================================
// RecordKind Tests
// ============================================================================

#[test]
fn record_kind_byte_roundtrip() {
    for kind in [
        RecordKind::Data,
        RecordKind::Checkpoint,
        RecordKind::Tombstone,
    ] {
        let byte = kind.as_byte();
        let recovered = RecordKind::from_byte(byte);
        assert_eq!(recovered, Some(kind));
    }
}

#[test]
fn record_kind_invalid_byte_returns_none() {
    assert_eq!(RecordKind::from_byte(3), None);
    assert_eq!(RecordKind::from_byte(255), None);
}

#[test]
fn record_kind_default_is_data() {
    assert_eq!(RecordKind::default(), RecordKind::Data);
}

// ============================================================================
// RecordHeader Tests
// ============================================================================

#[test]
fn record_header_genesis_detection() {
    let header = RecordHeader::new(
        Offset::ZERO,
        Hash::GENESIS,
        Timestamp::EPOCH,
        100,
        RecordKind::Data,
    );
    assert!(header.is_genesis());
}

#[test]
fn record_header_non_genesis() {
    let header = RecordHeader::new(
        Offset::new(1),
        Hash::from_bytes([1u8; HASH_LENGTH]),
        Timestamp::from_nanos(1000),
        100,
        RecordKind::Data,
    );
    assert!(!header.is_genesis());
}

// ============================================================================
// AppliedIndex Tests
// ============================================================================

#[test]
fn applied_index_genesis() {
    let idx = AppliedIndex::genesis();
    assert_eq!(idx.offset, Offset::ZERO);
    assert!(idx.hash.is_genesis());
}

#[test]
fn applied_index_default_is_genesis() {
    assert_eq!(AppliedIndex::default(), AppliedIndex::genesis());
}

// ============================================================================
// Checkpoint Tests
// ============================================================================

#[test]
fn checkpoint_creation() {
    let cp = Checkpoint::new(
        Offset::new(999),
        Hash::from_bytes([1u8; HASH_LENGTH]),
        1000,
        Timestamp::from_nanos(1_000_000),
    );
    assert_eq!(cp.offset, Offset::new(999));
    assert_eq!(cp.record_count, 1000);
}

// ============================================================================
// CheckpointPolicy Tests
// ============================================================================

#[test]
fn checkpoint_policy_default() {
    let policy = CheckpointPolicy::default();
    assert_eq!(policy.every_n_records, 1000);
    assert!(policy.on_shutdown);
    assert!(!policy.explicit_only);
}

#[test]
fn checkpoint_policy_should_checkpoint() {
    let policy = CheckpointPolicy::every(100);

    // Checkpoint at offset 99 (100th record, 0-indexed)
    assert!(policy.should_checkpoint(Offset::new(99)));
    // Checkpoint at offset 199 (200th record)
    assert!(policy.should_checkpoint(Offset::new(199)));
    // No checkpoint at offset 50
    assert!(!policy.should_checkpoint(Offset::new(50)));
}

#[test]
fn checkpoint_policy_explicit_only_never_auto() {
    let policy = CheckpointPolicy::explicit_only();
    assert!(!policy.should_checkpoint(Offset::new(99)));
    assert!(!policy.should_checkpoint(Offset::new(999)));
}

// ============================================================================
// IdempotencyId Tests
// ============================================================================

#[test]
fn idempotency_id_generate_produces_unique() {
    let id1 = IdempotencyId::generate();
    let id2 = IdempotencyId::generate();
    assert_ne!(id1, id2);
}

#[test]
fn idempotency_id_from_bytes_roundtrip() {
    let bytes = [42u8; IDEMPOTENCY_ID_LENGTH];
    let id = IdempotencyId::from_bytes(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn idempotency_id_display_shows_hex() {
    let bytes = [0xab; IDEMPOTENCY_ID_LENGTH];
    let id = IdempotencyId::from_bytes(bytes);
    let display = id.to_string();
    assert_eq!(display.len(), 32); // 16 bytes * 2 hex chars
}

// ============================================================================
// Generation Tests
// ============================================================================

#[test]
fn generation_initial_is_zero() {
    assert_eq!(Generation::INITIAL.as_u64(), 0);
}

#[test]
fn generation_next_increments() {
    let g1 = Generation::new(5);
    let g2 = g1.next();
    assert_eq!(g2.as_u64(), 6);
}

#[test]
fn generation_next_saturates_at_max() {
    let g = Generation::new(u64::MAX);
    assert_eq!(g.next().as_u64(), u64::MAX);
}

#[test]
fn generation_ordering() {
    let g1 = Generation::new(1);
    let g2 = Generation::new(2);
    assert!(g1 < g2);
}

// ============================================================================
// RecoveryRecord Tests
// ============================================================================

#[test]
fn recovery_record_no_data_loss() {
    let record = RecoveryRecord::new(
        Generation::new(2),
        Generation::new(1),
        Offset::new(100),
        Offset::new(100),
        None,
        Timestamp::now(),
        RecoveryReason::NodeRestart,
    );
    assert!(!record.had_data_loss());
    assert_eq!(record.discarded_count(), 0);
}

#[test]
fn recovery_record_with_data_loss() {
    let record = RecoveryRecord::new(
        Generation::new(2),
        Generation::new(1),
        Offset::new(100),
        Offset::new(95),
        Some(Offset::new(96)..Offset::new(101)),
        Timestamp::now(),
        RecoveryReason::QuorumLoss,
    );
    assert!(record.had_data_loss());
    assert_eq!(record.discarded_count(), 5);
}

#[test]
fn recovery_reason_display() {
    assert_eq!(RecoveryReason::NodeRestart.to_string(), "node_restart");
    assert_eq!(RecoveryReason::QuorumLoss.to_string(), "quorum_loss");
    assert_eq!(
        RecoveryReason::CorruptionDetected.to_string(),
        "corruption_detected"
    );
    assert_eq!(
        RecoveryReason::ManualIntervention.to_string(),
        "manual_intervention"
    );
}

// ============================================================================
// StreamId ↔ TenantId Encoding Tests
// ============================================================================

#[test]
fn stream_id_tenant_encoding_roundtrip() {
    // Test specific tenant IDs with local stream ID 1
    for tenant_id in [1, 5, 100, 1000, 4_294_967_295] {
        let tid = TenantId::from(tenant_id);
        let stream_id = StreamId::from_tenant_and_local(tid, 1);
        let extracted = TenantId::from_stream_id(stream_id);
        assert_eq!(
            extracted,
            tid,
            "Tenant ID {tenant_id} failed roundtrip: got {:?}",
            u64::from(extracted)
        );
    }
}

#[test]
fn stream_id_local_id_extraction() {
    let stream_id = StreamId::from_tenant_and_local(TenantId::from(5), 42);
    assert_eq!(stream_id.local_id(), 42);

    let stream_id = StreamId::from_tenant_and_local(TenantId::from(1000), 9999);
    assert_eq!(stream_id.local_id(), 9999);
}

#[test]
fn stream_id_bit_layout_correctness() {
    // Verify bit layout: upper 32 bits = tenant_id, lower 32 bits = local_id
    let tenant_id = TenantId::from(5);
    let local_id = 1u32;
    let stream_id = StreamId::from_tenant_and_local(tenant_id, local_id);

    // Expected: (5 << 32) | 1 = 21474836481
    let expected: u64 = (5u64 << 32) | 1;
    assert_eq!(u64::from(stream_id), expected);

    // Extract and verify
    assert_eq!(TenantId::from_stream_id(stream_id), TenantId::from(5));
    assert_eq!(stream_id.local_id(), 1);
}

#[test]
fn stream_id_edge_cases() {
    // Tenant 0, local 0
    let stream_id = StreamId::from_tenant_and_local(TenantId::from(0), 0);
    assert_eq!(TenantId::from_stream_id(stream_id), TenantId::from(0));
    assert_eq!(stream_id.local_id(), 0);

    // Max tenant, max local
    let stream_id = StreamId::from_tenant_and_local(TenantId::from(u64::from(u32::MAX)), u32::MAX);
    assert_eq!(
        TenantId::from_stream_id(stream_id),
        TenantId::from(u64::from(u32::MAX))
    );
    assert_eq!(stream_id.local_id(), u32::MAX);
}

#[test]
fn stream_id_add_saturates_on_overflow() {
    // Regression for fuzz_kernel_command panic at lib.rs:161 — the kernel
    // increments `next_stream_id = taken + StreamId::new(1)`; when the
    // fuzzer feeds stream_id == u64::MAX the old unchecked `+` panicked
    // under debug assertions (`attempt to add with overflow`). Saturation
    // keeps the operation total.
    let max = StreamId::new(u64::MAX);
    assert_eq!(max + StreamId::new(1), StreamId::new(u64::MAX));
    assert_eq!(max + max, StreamId::new(u64::MAX));
}

// ============================================================================
// Property-Based Tests
// ============================================================================

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn offset_add_is_commutative(a in 0u64..1_000_000, b in 0u64..1_000_000) {
            let oa = Offset::new(a);
            let ob = Offset::new(b);
            prop_assert_eq!(oa + ob, ob + oa);
        }

        #[test]
        fn id_roundtrip_stream_id(id in any::<u64>()) {
            let stream_id = StreamId::new(id);
            let raw: u64 = stream_id.into();
            prop_assert_eq!(raw, id);
        }

        #[test]
        fn id_roundtrip_tenant_id(id in any::<u64>()) {
            let tenant_id = TenantId::new(id);
            let raw: u64 = tenant_id.into();
            prop_assert_eq!(raw, id);
        }

        #[test]
        fn id_roundtrip_group_id(id in any::<u64>()) {
            let group_id = GroupId::new(id);
            let raw: u64 = group_id.into();
            prop_assert_eq!(raw, id);
        }

        // Hash property tests
        #[test]
        fn hash_roundtrip(bytes in any::<[u8; HASH_LENGTH]>()) {
            let hash = Hash::from_bytes(bytes);
            let recovered: [u8; HASH_LENGTH] = hash.into();
            prop_assert_eq!(recovered, bytes);
        }

        #[test]
        fn hash_genesis_only_for_zeros(bytes in any::<[u8; HASH_LENGTH]>()) {
            let hash = Hash::from_bytes(bytes);
            prop_assert_eq!(hash.is_genesis(), bytes == [0u8; HASH_LENGTH]);
        }

        // Timestamp property tests
        #[test]
        fn timestamp_roundtrip(nanos in any::<u64>()) {
            let ts = Timestamp::from_nanos(nanos);
            prop_assert_eq!(ts.as_nanos(), nanos);
        }

        #[test]
        fn timestamp_secs_is_truncation(nanos in any::<u64>()) {
            let ts = Timestamp::from_nanos(nanos);
            prop_assert_eq!(ts.as_secs(), nanos / 1_000_000_000);
        }

        #[test]
        fn timestamp_monotonic_never_decreases(
            last_nanos in any::<u64>()
        ) {
            let last = Timestamp::from_nanos(last_nanos);
            let next = Timestamp::now_monotonic(Some(last));
            prop_assert!(next >= last);
        }

        // RecordKind property tests
        #[test]
        fn record_kind_valid_bytes_roundtrip(byte in 0u8..3) {
            let kind = RecordKind::from_byte(byte).unwrap();
            prop_assert_eq!(kind.as_byte(), byte);
        }

        #[test]
        fn record_kind_invalid_bytes_are_none(byte in 3u8..=255) {
            prop_assert!(RecordKind::from_byte(byte).is_none());
        }

        // Generation property tests
        #[test]
        fn generation_roundtrip(value in any::<u64>()) {
            let g = Generation::new(value);
            prop_assert_eq!(g.as_u64(), value);
        }

        #[test]
        fn generation_next_increases_or_saturates(value in any::<u64>()) {
            let g = Generation::new(value);
            let next = g.next();
            if value == u64::MAX {
                prop_assert_eq!(next.as_u64(), u64::MAX);
            } else {
                prop_assert_eq!(next.as_u64(), value + 1);
            }
        }

        // IdempotencyId property tests
        #[test]
        fn idempotency_id_roundtrip(bytes in any::<[u8; IDEMPOTENCY_ID_LENGTH]>()) {
            let id = IdempotencyId::from_bytes(bytes);
            let recovered: [u8; IDEMPOTENCY_ID_LENGTH] = id.into();
            prop_assert_eq!(recovered, bytes);
        }

        // CheckpointPolicy property tests
        #[test]
        fn checkpoint_policy_every_n_triggers_correctly(
            every_n in 1u64..1000,
            offset in 0u64..10000
        ) {
            let policy = CheckpointPolicy::every(every_n);
            let should = policy.should_checkpoint(Offset::new(offset));
            prop_assert_eq!(should, (offset + 1) % every_n == 0);
        }

        // StreamId ↔ TenantId encoding property tests
        #[test]
        fn stream_id_tenant_roundtrip_property(
            tenant_id in 0u64..=(u64::from(u32::MAX)),
            local_id in any::<u32>()
        ) {
            let tid = TenantId::from(tenant_id);
            let stream_id = StreamId::from_tenant_and_local(tid, local_id);

            // Tenant ID should roundtrip perfectly
            prop_assert_eq!(TenantId::from_stream_id(stream_id), tid);

            // Local ID should roundtrip perfectly
            prop_assert_eq!(stream_id.local_id(), local_id);
        }

        #[test]
        fn stream_id_different_tenants_different_streams(
            tenant1 in 0u64..=(u64::from(u32::MAX)),
            tenant2 in 0u64..=(u64::from(u32::MAX)),
            local_id in any::<u32>()
        ) {
            let stream1 = StreamId::from_tenant_and_local(TenantId::from(tenant1), local_id);
            let stream2 = StreamId::from_tenant_and_local(TenantId::from(tenant2), local_id);

            if tenant1 == tenant2 {
                prop_assert_eq!(stream1, stream2);
            } else {
                prop_assert_ne!(stream1, stream2);
            }
        }

        #[test]
        fn stream_id_same_tenant_different_locals_different_streams(
            tenant_id in 0u64..=(u64::from(u32::MAX)),
            local1 in any::<u32>(),
            local2 in any::<u32>()
        ) {
            let stream1 = StreamId::from_tenant_and_local(TenantId::from(tenant_id), local1);
            let stream2 = StreamId::from_tenant_and_local(TenantId::from(tenant_id), local2);

            if local1 == local2 {
                prop_assert_eq!(stream1, stream2);
            } else {
                prop_assert_ne!(stream1, stream2);
            }
        }
    }
}
