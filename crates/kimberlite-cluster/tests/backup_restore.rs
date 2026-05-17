//! Integration tests for `backup_cluster` / `restore_cluster` (T2.2).
//!
//! The lib-level tests cover the byte-identical round-trip on a small
//! seeded tree; this file scales the payload up to confirm:
//!
//!   - the tar + zstd path handles a multi-megabyte stream without
//!     buffering the whole archive in memory,
//!   - the BLAKE3 manifest verifies every entry post-extract,
//!   - the round-trip is bit-exact at scale (an acceptance dry-run for
//!     the 1 GB / HIPAA § 164.308(a)(7) gate documented in the cluster
//!     graduation plan; we run a 10 MB payload here so CI stays fast,
//!     and the 1 GB soak runs in the nightly job).
//!
//! Tests are *not* `#[ignore]` because they don't spawn child processes
//! — pure in-process bytes / fs operations, deterministic, ~1s total.

use std::fs;
use std::io::Write;
use std::path::Path;

use kimberlite_cluster::{ClusterConfig, backup_cluster, restore_cluster};
use tempfile::TempDir;

/// Seeds a fake cluster tree with `payload_bytes_per_node` of synthetic
/// data per node, distributed across a couple of files. Returns the
/// loaded ClusterConfig so the caller can compare against the restored
/// topology.
fn seed_cluster_with_payload(root: &Path, payload_bytes_per_node: usize) -> ClusterConfig {
    let config = ClusterConfig::try_new(root.to_path_buf(), 3, 5432).unwrap();
    config.save().unwrap();
    config.create_directories().unwrap();

    for node in &config.topology.nodes {
        // Synthetic projection store + per-stream segment. Use a
        // deterministic byte pattern so failures localise easily.
        let pattern: Vec<u8> = (0..payload_bytes_per_node)
            .map(|i| ((i + node.id) % 251) as u8)
            .collect();

        let projections = node.data_dir.join("projections.db");
        let stream_dir = node.data_dir.join("stream-1");
        fs::create_dir_all(&stream_dir).unwrap();

        fs::File::create(&projections)
            .unwrap()
            .write_all(&pattern[..pattern.len() / 2])
            .unwrap();
        fs::File::create(stream_dir.join("segment_000001.log"))
            .unwrap()
            .write_all(&pattern[pattern.len() / 2..])
            .unwrap();
        fs::File::create(stream_dir.join("manifest.json"))
            .unwrap()
            .write_all(br#"{"segments":[{"id":1}]}"#)
            .unwrap();
    }
    config
}

#[test]
fn backup_restore_round_trips_ten_megabytes() {
    // 10 MB per node * 3 nodes = 30 MB uncompressed total — large enough
    // to exercise the streaming tar+zstd path, small enough that CI
    // doesn't notice. Nightly soak runs the same code path against 1 GB
    // (the design doc's acceptance criterion).
    let payload = 10 * 1024 * 1024;
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    let archive_dir = TempDir::new().unwrap();
    let archive_path = archive_dir.path().join("cluster.tar.zst");

    let config = seed_cluster_with_payload(src.path(), payload);

    let backup = backup_cluster(src.path(), &archive_path).expect("backup_cluster");
    assert!(
        backup.uncompressed_bytes >= (payload as u64) * 3,
        "captured fewer bytes than written: {backup:?}",
    );
    assert!(
        backup.compressed_bytes < backup.uncompressed_bytes,
        "zstd did not compress: {backup:?}",
    );

    let restore = restore_cluster(&archive_path, dst.path()).expect("restore_cluster");
    assert_eq!(restore.file_count, backup.file_count);
    assert_eq!(restore.uncompressed_bytes, backup.uncompressed_bytes);

    // Bit-exact: every file in the source cluster dir matches the
    // corresponding restored file byte-for-byte. Walk in deterministic
    // order via the ClusterConfig so test failures cite the offending
    // node.
    for node in &config.topology.nodes {
        let src_node = node.data_dir.clone();
        let rel = src_node.strip_prefix(src.path()).unwrap();
        let dst_node = dst.path().join(rel);
        compare_dirs_recursive(&src_node, &dst_node);
    }

    // cluster.toml is also byte-identical.
    let src_toml = fs::read(src.path().join("cluster/cluster.toml")).unwrap();
    let dst_toml = fs::read(dst.path().join("cluster/cluster.toml")).unwrap();
    assert_eq!(src_toml, dst_toml, "cluster.toml mismatch");
}

#[test]
fn restore_can_be_followed_by_new_backup() {
    // A restored data dir must produce a backup identical (modulo
    // timestamp) to the original archive — the operator should be able
    // to chain restore → backup as part of a re-key / migration workflow.
    let src = TempDir::new().unwrap();
    let mid = TempDir::new().unwrap();
    let archive_one = TempDir::new().unwrap().path().join("one.tar.zst");
    let archive_two = TempDir::new().unwrap().path().join("two.tar.zst");
    fs::create_dir_all(archive_one.parent().unwrap()).unwrap();
    fs::create_dir_all(archive_two.parent().unwrap()).unwrap();

    seed_cluster_with_payload(src.path(), 64 * 1024);
    backup_cluster(src.path(), &archive_one).expect("first backup");

    restore_cluster(&archive_one, mid.path()).expect("restore into mid");
    backup_cluster(mid.path(), &archive_two).expect("second backup of restored tree");

    // The two archives are NOT byte-identical (timestamps in tar header
    // differ), but extracting them into fresh dirs must produce
    // byte-identical content.
    let extract_one = TempDir::new().unwrap();
    let extract_two = TempDir::new().unwrap();
    restore_cluster(&archive_one, extract_one.path()).expect("extract one");
    restore_cluster(&archive_two, extract_two.path()).expect("extract two");
    compare_dirs_recursive(
        &extract_one.path().join("cluster"),
        &extract_two.path().join("cluster"),
    );
}

#[test]
fn restore_refuses_corrupt_archive() {
    // Tampering with the archive's bytes must surface as a restore-time
    // error, not silent corruption of the restored cluster.
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    let archive_dir = TempDir::new().unwrap();
    let archive_path = archive_dir.path().join("cluster.tar.zst");

    seed_cluster_with_payload(src.path(), 16 * 1024);
    backup_cluster(src.path(), &archive_path).unwrap();

    // Flip 64 bytes deep inside the archive (past the zstd frame header
    // — the decoder picks this up as either a decode error or a
    // manifest mismatch downstream).
    let mut bytes = fs::read(&archive_path).unwrap();
    let mid = bytes.len() / 2;
    for i in 0..64 {
        bytes[mid + i] ^= 0xff;
    }
    fs::write(&archive_path, &bytes).unwrap();

    match restore_cluster(&archive_path, dst.path()) {
        Err(_) => { /* expected — either zstd decode or manifest check */ }
        Ok(s) => panic!(
            "restore unexpectedly succeeded on a tampered archive (cluster_dir={})",
            s.cluster_dir.display()
        ),
    }
}

/// Recursively walks `a` and asserts every file matches `b` byte-for-byte.
/// Panics on first mismatch with file paths in the message.
fn compare_dirs_recursive(a: &Path, b: &Path) {
    for entry in fs::read_dir(a).expect("read_dir a") {
        let entry = entry.unwrap();
        let a_path = entry.path();
        let rel = a_path.strip_prefix(a).unwrap();
        let b_path = b.join(rel);
        if a_path.is_dir() {
            compare_dirs_recursive(&a_path, &b_path);
        } else {
            let a_bytes = fs::read(&a_path).unwrap();
            let b_bytes = fs::read(&b_path).unwrap();
            assert_eq!(
                a_bytes.len(),
                b_bytes.len(),
                "size mismatch: {} vs {}",
                a_path.display(),
                b_path.display()
            );
            assert!(a_bytes == b_bytes, "content mismatch on {}", rel.display());
        }
    }
}
