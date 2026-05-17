//! Shim that re-exports the canonical testing helpers from the crate's
//! public-but-hidden `testing` module. Lives here so existing test
//! files that do `mod common; use common::*;` keep working without
//! touching the import paths.
//!
//! The actual helpers are at `crates/kimberlite-cluster/src/testing.rs`
//! — same source-of-truth across integration tests, the perf-baseline
//! harness, and the bench crate.

#![allow(dead_code, unused_imports)]

pub use kimberlite_cluster::testing::{
    HTTP_PORT_OFFSET, HttpResponse, find_leader_replica, http_get, locate_built_kimberlite,
    parse_gauge, pick_base_port, poll_http, wait_for_port, wait_for_tcp_ready,
};
