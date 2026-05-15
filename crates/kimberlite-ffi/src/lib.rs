//! # Kimberlite FFI
//!
//! C-compatible Foreign Function Interface for Kimberlite database.
//!
//! This crate provides a stable C ABI for language-specific SDK wrappers.
//! All functions use C-compatible types and follow these conventions:
//!
//! - Return `KmbError` (error code)
//! - Use out-parameters for results (e.g., `stream_id_out`)
//! - NULL-check all pointers
//! - UTF-8 validate all strings
//! - Bounds-check all arrays
//!
//! ## Memory Management
//!
//! - **Client-owned**: Caller must free with `kmb_*_free()` functions
//! - **Library-owned**: Valid until next call or client disconnect
//!
//! ## Thread Safety
//!
//! `KmbClient` is NOT thread-safe. Callers must synchronize access or use
//! separate client instances per thread.
//!
//! ## Safety
//!
//! Every `pub unsafe extern "C" fn` in this module shares the same contract:
//!
//! - All pointer arguments must be either NULL or valid for reads/writes of
//!   the declared element type. Callers MUST NULL-check before dereferencing
//!   what the out-parameter writes back.
//! - String arguments typed as `*const c_char` must either be NULL or point
//!   to a NUL-terminated UTF-8 byte sequence. Non-UTF-8 input is rejected
//!   at the boundary via `CStr::to_str()` and returns
//!   `KmbError::InvalidUtf8`.
//! - Array arguments (`ptr`, `len`) must either be (NULL, 0) or describe a
//!   valid `[T]` slice of exactly `len` elements. Out-of-bounds reads are
//!   undefined behaviour.
//! - Library-owned pointers returned by `kmb_*_borrow` style functions are
//!   only valid until the next FFI call against the owning client, or
//!   until the client is freed.
//! - Client-owned pointers returned to the caller MUST be released with
//!   the matching `kmb_*_free()` function exactly once.
//!
//! A per-function `# Safety` section would repeat the above verbatim; the
//! `clippy::missing_safety_doc` silence below is an intentional allow,
//! not a debt.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::slice;
use std::time::Duration;

use kimberlite_client::{
    AuditContext, Client, ClientConfig, ClientError, Pool, PoolConfig, PooledClient,
    SubscriptionCloseReason, clear_thread_audit, set_thread_audit,
};
use kimberlite_types::{DataClass, Offset, Placement, Region, StreamId, TenantId};
use kimberlite_wire::{ClusterMode as WireClusterMode, QueryParam, QueryResponse, QueryValue};
use kimberlite_wire::{
    ConsentPurpose as WireConsentPurpose, ErasureExemptionBasis as WireExemptionBasis,
};

/// Error codes returned by all FFI functions.
///
/// Error code 0 (`KMB_OK`) indicates success.
/// All other codes indicate various failure modes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbError {
    /// Success (no error)
    KmbOk = 0,
    /// NULL pointer passed where non-NULL required
    KmbErrNullPointer = 1,
    /// String is not valid UTF-8
    KmbErrInvalidUtf8 = 2,
    /// Failed to connect to server
    KmbErrConnectionFailed = 3,
    /// Stream ID does not exist
    KmbErrStreamNotFound = 4,
    /// Operation not permitted for this tenant
    KmbErrPermissionDenied = 5,
    /// Invalid data class value
    KmbErrInvalidDataClass = 6,
    /// Offset is beyond stream end
    KmbErrOffsetOutOfRange = 7,
    /// SQL syntax error
    KmbErrQuerySyntax = 8,
    /// Query execution error
    KmbErrQueryExecution = 9,
    /// Tenant ID does not exist
    KmbErrTenantNotFound = 10,
    /// Authentication failed
    KmbErrAuthFailed = 11,
    /// Operation timed out
    KmbErrTimeout = 12,
    /// Internal server error
    KmbErrInternal = 13,
    /// No cluster replicas available
    KmbErrClusterUnavailable = 14,
    /// Unknown error
    KmbErrUnknown = 15,
    /// Duplicate primary key on INSERT — unique constraint violation
    KmbErrUniqueConstraintViolation = 16,
}

/// Internal wrapper for the Rust client.
///
/// `#[repr(transparent)]` guarantees ABI identity with `Client`, which lets
/// `kmb_pooled_client_as_client` return a `*mut Client` cast as
/// `*mut KmbClient` and have the existing `kmb_client_*` handlers work on
/// it unchanged.
#[repr(transparent)]
struct ClientWrapper {
    client: Client,
}

/// Opaque handle to a client connection.
///
/// Created by `kmb_client_connect()`, freed by `kmb_client_disconnect()`.
#[repr(C)]
pub struct KmbClient {
    _private: [u8; 0],
}

/// Client connection configuration.
#[repr(C)]
pub struct KmbClientConfig {
    /// Array of "host:port" strings (NULL-terminated)
    pub addresses: *const *const c_char,
    /// Number of addresses
    pub address_count: usize,
    /// Tenant ID
    pub tenant_id: u64,
    /// Authentication token (NULL-terminated, may be empty)
    pub auth_token: *const c_char,
    /// Client name (e.g., "kimberlite-python")
    pub client_name: *const c_char,
    /// Client version (e.g., "0.1.0")
    pub client_version: *const c_char,
}

/// Data classification for streams.
///
/// Variants 0-2 are the original (Phi/NonPhi/Deidentified) ABI; variants 3-7
/// extend the enum to cover every `kimberlite_types::DataClass` value.
/// Old callers that only set 0/1/2 remain binary-compatible.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbDataClass {
    /// Protected Health Information (HIPAA-regulated)
    KmbDataClassPhi = 0,
    /// Non-PHI data (alias for Public).
    KmbDataClassNonPhi = 1,
    /// De-identified data
    KmbDataClassDeidentified = 2,
    /// Personally Identifiable Information (GDPR / CCPA)
    KmbDataClassPii = 3,
    /// Sensitive personal data (religion, health, sexual orientation, ...)
    KmbDataClassSensitive = 4,
    /// Payment Card Industry data (PCI DSS)
    KmbDataClassPci = 5,
    /// Financial records (SOX / GLBA)
    KmbDataClassFinancial = 6,
    /// Confidential business data
    KmbDataClassConfidential = 7,
    /// Public / unclassified data
    KmbDataClassPublic = 8,
}

/// Placement policy for a stream.
///
/// `KmbPlacementCustom` reads the placement name from the `custom_region`
/// argument of `kmb_client_create_stream_with_placement`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbPlacement {
    /// Global replication across all regions (default).
    KmbPlacementGlobal = 0,
    /// US East (N. Virginia) — us-east-1
    KmbPlacementUsEast1 = 1,
    /// Asia Pacific (Sydney) — ap-southeast-2
    KmbPlacementApSoutheast2 = 2,
    /// Custom region identifier (string supplied separately).
    KmbPlacementCustom = 3,
}

/// Result of `kmb_client_execute()` — analogous to a DML acknowledgement.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KmbExecuteResult {
    /// Number of rows inserted / updated / deleted.
    pub rows_affected: u64,
    /// Log offset at which the change was committed.
    pub log_offset: u64,
}

// ============================================================================
// Connection pool
// ============================================================================

/// Opaque handle to a connection pool.
///
/// Created with `kmb_pool_create()`, destroyed with `kmb_pool_destroy()`.
/// Pools are thread-safe; a single handle can be shared across threads.
#[repr(C)]
pub struct KmbPool {
    _private: [u8; 0],
}

/// Opaque handle to a pool-borrowed client. Dropping the handle returns the
/// connection to the pool. Free with `kmb_pool_release()` or pass the handle
/// to other `kmb_client_*` functions exactly like a regular `KmbClient`.
#[repr(C)]
pub struct KmbPooledClient {
    _private: [u8; 0],
}

/// Pool configuration.
///
/// `acquire_timeout_ms = 0` blocks forever.
/// `idle_timeout_ms = 0` disables idle eviction.
#[repr(C)]
pub struct KmbPoolConfig {
    /// Array of "host:port" strings (only the first is used).
    pub addresses: *const *const c_char,
    pub address_count: usize,
    /// Tenant ID
    pub tenant_id: u64,
    /// Authentication token (NULL-terminated, may be NULL or empty)
    pub auth_token: *const c_char,
    /// Maximum concurrent connections (must be > 0).
    pub max_size: usize,
    /// Milliseconds a caller will wait on `kmb_pool_acquire`; 0 = block forever.
    pub acquire_timeout_ms: u64,
    /// Milliseconds an idle connection stays in the pool before eviction; 0 = never.
    pub idle_timeout_ms: u64,
}

struct PoolWrapper {
    pool: Pool,
}

struct PooledClientWrapper {
    guard: PooledClient,
}

fn pool_client_error(err: ClientError) -> KmbError {
    map_error(err)
}

/// Create a connection pool.
///
/// # Safety
/// - `config` must point to a valid `KmbPoolConfig`
/// - `pool_out` must be non-null
/// - Call `kmb_pool_destroy` to free the returned handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_create(
    config: *const KmbPoolConfig,
    pool_out: *mut *mut KmbPool,
) -> KmbError {
    unsafe {
        if config.is_null() || pool_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let cfg = &*config;
        if cfg.max_size == 0 || cfg.address_count == 0 || cfg.addresses.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let addr_ptr = *cfg.addresses;
        if addr_ptr.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let addr = match CStr::from_ptr(addr_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        let auth_token = if cfg.auth_token.is_null() {
            None
        } else {
            match CStr::from_ptr(cfg.auth_token).to_str() {
                Ok(s) if !s.is_empty() => Some(s.to_string()),
                Ok(_) => None,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            }
        };

        let client_config = ClientConfig {
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            buffer_size: 64 * 1024,
            auth_token,
            auto_reconnect: true,
        };

        let pool_config = PoolConfig {
            max_size: cfg.max_size,
            acquire_timeout: if cfg.acquire_timeout_ms == 0 {
                None
            } else {
                Some(Duration::from_millis(cfg.acquire_timeout_ms))
            },
            idle_timeout: if cfg.idle_timeout_ms == 0 {
                None
            } else {
                Some(Duration::from_millis(cfg.idle_timeout_ms))
            },
            client_config,
        };

        let pool = match Pool::new(addr.as_str(), TenantId::new(cfg.tenant_id), pool_config) {
            Ok(p) => p,
            Err(e) => return pool_client_error(e),
        };

        let wrapper = Box::new(PoolWrapper { pool });
        *pool_out = Box::into_raw(wrapper) as *mut KmbPool;
        KmbError::KmbOk
    }
}

/// Acquire a client from the pool.
///
/// The returned `KmbPooledClient` can be passed to `kmb_client_*` functions
/// by casting via `kmb_pooled_client_as_client`. Release with
/// `kmb_pool_release` to return it to the pool; `kmb_pool_discard` closes
/// the underlying connection instead.
///
/// # Safety
/// - `pool` must be a valid handle from `kmb_pool_create`
/// - `client_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_acquire(
    pool: *mut KmbPool,
    client_out: *mut *mut KmbPooledClient,
) -> KmbError {
    unsafe {
        if pool.is_null() || client_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &*(pool as *const PoolWrapper);
        match wrapper.pool.acquire() {
            Ok(guard) => {
                let boxed = Box::new(PooledClientWrapper { guard });
                *client_out = Box::into_raw(boxed) as *mut KmbPooledClient;
                KmbError::KmbOk
            }
            Err(e) => pool_client_error(e),
        }
    }
}

/// Return a pooled client to the pool.
///
/// # Safety
/// - `client` must be a valid handle from `kmb_pool_acquire`
/// - After this call the handle is invalid
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_release(client: *mut KmbPooledClient) {
    unsafe {
        if client.is_null() {
            return;
        }
        let _ = Box::from_raw(client as *mut PooledClientWrapper);
        // Drop runs PooledClient::drop which returns the connection to the pool.
    }
}

/// Discard a pooled client (drop the underlying TCP connection instead of
/// returning it to the pool). Use after an unrecoverable protocol error.
///
/// # Safety
/// - `client` must be a valid handle from `kmb_pool_acquire`
/// - After this call the handle is invalid
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_discard(client: *mut KmbPooledClient) {
    unsafe {
        if client.is_null() {
            return;
        }
        let boxed = Box::from_raw(client as *mut PooledClientWrapper);
        boxed.guard.discard();
    }
}

/// View a pooled-client handle as a regular `KmbClient` pointer.
///
/// The returned pointer remains valid until the `KmbPooledClient` is
/// released or discarded. Do NOT pass the returned pointer to
/// `kmb_client_disconnect` — it does not own the connection.
///
/// Internally the existing `kmb_client_*` functions interpret `*mut KmbClient`
/// as `*mut ClientWrapper` where `ClientWrapper` has a single `Client` field
/// at offset 0, so a `*mut Client` is ABI-compatible with `*mut KmbClient`.
///
/// # Safety
/// - `client` must be a valid handle from `kmb_pool_acquire`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pooled_client_as_client(
    client: *mut KmbPooledClient,
) -> *mut KmbClient {
    unsafe {
        if client.is_null() {
            return std::ptr::null_mut();
        }
        let wrapper = &mut *(client as *mut PooledClientWrapper);
        // Deref the PooledClient guard to &mut Client, then cast to
        // *mut KmbClient. Caller must keep the pooled handle alive while
        // the returned pointer is in use.
        let c: &mut Client = &mut wrapper.guard;
        std::ptr::from_mut(c).cast::<KmbClient>()
    }
}

/// Current pool statistics. Writes `max_size`, `open`, `idle`, `in_use`,
/// and `shutdown` (0/1) via out-parameters. Any out-pointer may be NULL
/// to skip that field.
///
/// # Safety
/// - `pool` must be a valid handle from `kmb_pool_create`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_stats(
    pool: *mut KmbPool,
    max_size_out: *mut usize,
    open_out: *mut usize,
    idle_out: *mut usize,
    in_use_out: *mut usize,
    shutdown_out: *mut c_int,
) -> KmbError {
    unsafe {
        if pool.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &*(pool as *const PoolWrapper);
        let stats = wrapper.pool.stats();
        if !max_size_out.is_null() {
            *max_size_out = stats.max_size;
        }
        if !open_out.is_null() {
            *open_out = stats.open;
        }
        if !idle_out.is_null() {
            *idle_out = stats.idle;
        }
        if !in_use_out.is_null() {
            *in_use_out = stats.in_use;
        }
        if !shutdown_out.is_null() {
            *shutdown_out = c_int::from(stats.shutdown);
        }
        KmbError::KmbOk
    }
}

/// Shut down a pool. Idle connections close immediately; in-flight clients
/// close when released. Subsequent acquires fail with
/// `KMB_ERR_CONNECTION_FAILED`.
///
/// # Safety
/// - `pool` must be a valid handle from `kmb_pool_create`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_shutdown(pool: *mut KmbPool) {
    unsafe {
        if pool.is_null() {
            return;
        }
        let wrapper = &*(pool as *const PoolWrapper);
        wrapper.pool.shutdown();
    }
}

// ============================================================================
// Subscriptions (protocol v2)
// ============================================================================

/// Reason a subscription was closed. Matches `SubscriptionCloseReason` in
/// `kimberlite_wire`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbSubscriptionCloseReason {
    KmbCloseClientCancelled = 0,
    KmbCloseServerShutdown = 1,
    KmbCloseStreamDeleted = 2,
    KmbCloseBackpressureTimeout = 3,
    KmbCloseProtocolError = 4,
}

impl From<SubscriptionCloseReason> for KmbSubscriptionCloseReason {
    fn from(r: SubscriptionCloseReason) -> Self {
        match r {
            SubscriptionCloseReason::ClientCancelled => Self::KmbCloseClientCancelled,
            SubscriptionCloseReason::ServerShutdown => Self::KmbCloseServerShutdown,
            SubscriptionCloseReason::StreamDeleted => Self::KmbCloseStreamDeleted,
            SubscriptionCloseReason::BackpressureTimeout => Self::KmbCloseBackpressureTimeout,
            SubscriptionCloseReason::ProtocolError => Self::KmbCloseProtocolError,
        }
    }
}

/// Result from `kmb_subscribe`.
#[repr(C)]
pub struct KmbSubscribeResult {
    pub subscription_id: u64,
    pub start_offset: u64,
    pub initial_credits: u32,
}

/// A single event returned from `kmb_subscription_next`.
///
/// The `data` pointer is owned by the library and remains valid until the
/// next call on the same subscription. Copy the bytes if you need to
/// retain them longer.
#[repr(C)]
pub struct KmbSubscriptionEvent {
    pub offset: u64,
    pub data: *mut u8,
    pub data_len: usize,
    /// Set to 1 when the subscription has closed — `data`/`data_len` are
    /// meaningless and `close_reason` carries the reason.
    pub closed: c_int,
    pub close_reason: KmbSubscriptionCloseReason,
}

/// Subscribe to real-time events on a stream.
///
/// # Safety
/// - `client` must be a valid handle from `kmb_client_connect` (or
///   `kmb_pooled_client_as_client`)
/// - `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_subscribe(
    client: *mut KmbClient,
    stream_id: u64,
    from_offset: u64,
    initial_credits: u32,
    result_out: *mut KmbSubscribeResult,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        if initial_credits == 0 {
            return KmbError::KmbErrInternal;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.subscribe(
            StreamId::from(stream_id),
            Offset::new(from_offset),
            initial_credits,
            None,
        ) {
            Ok(resp) => {
                *result_out = KmbSubscribeResult {
                    subscription_id: resp.subscription_id,
                    start_offset: u64::from(resp.start_offset),
                    initial_credits: resp.credits,
                };
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Grant additional flow-control credits to an existing subscription.
///
/// # Safety
/// - `client` must be a valid handle
/// - `new_balance_out` may be NULL if unused
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_subscription_grant_credits(
    client: *mut KmbClient,
    subscription_id: u64,
    additional_credits: u32,
    new_balance_out: *mut u32,
) -> KmbError {
    unsafe {
        if client.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper
            .client
            .grant_credits(subscription_id, additional_credits)
        {
            Ok(new_balance) => {
                if !new_balance_out.is_null() {
                    *new_balance_out = new_balance;
                }
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Cancel a subscription.
///
/// # Safety
/// - `client` must be a valid handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_subscription_unsubscribe(
    client: *mut KmbClient,
    subscription_id: u64,
) -> KmbError {
    unsafe {
        if client.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.unsubscribe(subscription_id) {
            Ok(_) => KmbError::KmbOk,
            Err(e) => map_error(e),
        }
    }
}

/// Block until the next event for `subscription_id` arrives (or the
/// subscription closes).
///
/// The returned `KmbSubscriptionEvent` owns heap-allocated data — free it
/// via `kmb_subscription_event_free`.
///
/// # Safety
/// - `client` must be a valid handle
/// - `event_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_subscription_next(
    client: *mut KmbClient,
    subscription_id: u64,
    event_out: *mut KmbSubscriptionEvent,
) -> KmbError {
    unsafe {
        if client.is_null() || event_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let wrapper = &mut *(client as *mut ClientWrapper);

        loop {
            match wrapper.client.next_push() {
                Ok(Some(push)) => match push.payload {
                    kimberlite_wire::PushPayload::SubscriptionEvents {
                        subscription_id: sub,
                        start_offset,
                        mut events,
                        credits_remaining: _,
                    } if sub == subscription_id => {
                        if let Some(first) = events.drain(..1).next() {
                            let mut boxed = first.into_boxed_slice();
                            let ptr = boxed.as_mut_ptr();
                            let len = boxed.len();
                            std::mem::forget(boxed);

                            *event_out = KmbSubscriptionEvent {
                                offset: u64::from(start_offset),
                                data: ptr,
                                data_len: len,
                                closed: 0,
                                close_reason: KmbSubscriptionCloseReason::KmbCloseClientCancelled,
                            };
                            return KmbError::KmbOk;
                        }
                    }
                    kimberlite_wire::PushPayload::SubscriptionClosed {
                        subscription_id: sub,
                        reason,
                    } if sub == subscription_id => {
                        *event_out = KmbSubscriptionEvent {
                            offset: 0,
                            data: std::ptr::null_mut(),
                            data_len: 0,
                            closed: 1,
                            close_reason: reason.into(),
                        };
                        return KmbError::KmbOk;
                    }
                    // Push for another subscription — drop silently.
                    _ => {}
                },
                Ok(None) => {
                    // Socket EOF / timeout.
                    return KmbError::KmbErrConnectionFailed;
                }
                Err(e) => return map_error(e),
            }
        }
    }
}

// ============================================================================
// Phase 4 — admin + schema + server info
// ============================================================================

/// Generic metadata listing — a JSON-encoded UTF-8 string owned by the library.
///
/// Used for admin ops that return variable-length structured data
/// (list_tables, tenant_list, api_key_list, etc.). Simpler than defining
/// 12 distinct repr(C) structs, and callers already have JSON parsers.
///
/// Free via `kmb_admin_json_free`.
#[repr(C)]
pub struct KmbAdminJson {
    /// NULL-terminated UTF-8 JSON. Owned — free with `kmb_admin_json_free`.
    pub json: *mut c_char,
}

fn wrap_json(value: serde_json::Value) -> Result<KmbAdminJson, KmbError> {
    let s = serde_json::to_string(&value).map_err(|_| KmbError::KmbErrInternal)?;
    let c = CString::new(s).map_err(|_| KmbError::KmbErrInvalidUtf8)?;
    Ok(KmbAdminJson { json: c.into_raw() })
}

fn cluster_mode_str(m: WireClusterMode) -> &'static str {
    match m {
        WireClusterMode::Standalone => "Standalone",
        WireClusterMode::Clustered => "Clustered",
    }
}

// Silence dead-code warning when only the public callers need the helper.
#[allow(dead_code)]
fn _cluster_mode_str_alias() {
    let _ = cluster_mode_str(WireClusterMode::Standalone);
}

/// Free a JSON string returned by an admin FFI call.
///
/// # Safety
/// - `result` must be a value returned by `kmb_admin_*` (or a zeroed struct)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_json_free(result: *mut KmbAdminJson) {
    unsafe {
        if result.is_null() {
            return;
        }
        let r = &mut *result;
        if !r.json.is_null() {
            let _ = CString::from_raw(r.json);
            r.json = std::ptr::null_mut();
        }
    }
}

/// List tables in the caller's tenant. Returns `{"tables":[{"name":..,"column_count":..}]}`.
///
/// # Safety
/// - `client` must be valid
/// - `result_out` must be non-null; caller frees via `kmb_admin_json_free`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_list_tables(
    client: *mut KmbClient,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.list_tables() {
            Ok(tables) => {
                let json = serde_json::json!({
                    "tables": tables.iter().map(|t| serde_json::json!({
                        "name": t.name,
                        "column_count": t.column_count,
                    })).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Describe a table's columns. Returns `{"table_name":..,"columns":[...]}`.
///
/// # Safety
/// - `client`, `table_name`, `result_out` must be non-null
/// - `table_name` must be NULL-terminated UTF-8
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_describe_table(
    client: *mut KmbClient,
    table_name: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || table_name.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let name = match CStr::from_ptr(table_name).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.describe_table(name) {
            Ok(resp) => {
                let json = serde_json::json!({
                    "table_name": resp.table_name,
                    "columns": resp.columns.iter().map(|c| serde_json::json!({
                        "name": c.name,
                        "data_type": c.data_type,
                        "nullable": c.nullable,
                        "primary_key": c.primary_key,
                    })).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// List indexes on a table. Returns `{"indexes":[{"name":..,"columns":[...]}]}`.
///
/// # Safety
/// - `client`, `table_name`, `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_list_indexes(
    client: *mut KmbClient,
    table_name: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || table_name.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let name = match CStr::from_ptr(table_name).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.list_indexes(name) {
            Ok(indexes) => {
                let json = serde_json::json!({
                    "indexes": indexes.iter().map(|i| serde_json::json!({
                        "name": i.name,
                        "columns": i.columns,
                    })).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Register a tenant. Returns `{"tenant":{...},"created":true|false}`.
///
/// # Safety
/// - `client` and `result_out` must be non-null
/// - `name` may be NULL for an unnamed registration
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_tenant_create(
    client: *mut KmbClient,
    tenant_id: u64,
    name: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let name_opt = if name.is_null() {
            None
        } else {
            match CStr::from_ptr(name).to_str() {
                Ok(s) if !s.is_empty() => Some(s.to_string()),
                Ok(_) => None,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            }
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper
            .client
            .tenant_create(TenantId::new(tenant_id), name_opt)
        {
            Ok(r) => {
                let json = serde_json::json!({
                    "tenant": {
                        "tenant_id": u64::from(r.tenant.tenant_id),
                        "name": r.tenant.name,
                        "table_count": r.tenant.table_count,
                        "created_at_nanos": r.tenant.created_at_nanos,
                    },
                    "created": r.created,
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// List all registered tenants. Returns `{"tenants":[...]}`.
///
/// # Safety
/// - `client` and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_tenant_list(
    client: *mut KmbClient,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.tenant_list() {
            Ok(tenants) => {
                let json = serde_json::json!({
                    "tenants": tenants.iter().map(|t| serde_json::json!({
                        "tenant_id": u64::from(t.tenant_id),
                        "name": t.name,
                        "table_count": t.table_count,
                        "created_at_nanos": t.created_at_nanos,
                    })).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Delete a tenant. Returns `{"deleted":bool,"tables_dropped":n}`.
///
/// # Safety
/// - `client` and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_tenant_delete(
    client: *mut KmbClient,
    tenant_id: u64,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.tenant_delete(TenantId::new(tenant_id)) {
            Ok(r) => {
                let json = serde_json::json!({
                    "deleted": r.deleted,
                    "tables_dropped": r.tables_dropped,
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Fetch a tenant summary. Returns `{"tenant":{...}}`.
///
/// # Safety
/// - `client` and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_tenant_get(
    client: *mut KmbClient,
    tenant_id: u64,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.tenant_get(TenantId::new(tenant_id)) {
            Ok(info) => {
                let json = serde_json::json!({
                    "tenant": {
                        "tenant_id": u64::from(info.tenant_id),
                        "name": info.name,
                        "table_count": info.table_count,
                        "created_at_nanos": info.created_at_nanos,
                    }
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Issue a new API key. Returns `{"key":"...","info":{...}}`.
///
/// The plaintext `key` is returned exactly once — persist it immediately.
///
/// # Safety
/// - `client`, `subject`, and `result_out` must be non-null
/// - `roles_json` must be a NULL-terminated UTF-8 JSON array of strings
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_api_key_register(
    client: *mut KmbClient,
    subject: *const c_char,
    tenant_id: u64,
    roles_json: *const c_char,
    expires_at_nanos: u64, // 0 = non-expiring
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || subject.is_null() || roles_json.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let roles_str = match CStr::from_ptr(roles_json).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let roles: Vec<String> = match serde_json::from_str(roles_str) {
            Ok(v) => v,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let expires = if expires_at_nanos == 0 {
            None
        } else {
            Some(expires_at_nanos)
        };

        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper
            .client
            .api_key_register(subj, TenantId::new(tenant_id), roles, expires)
        {
            Ok(r) => {
                let json = serde_json::json!({
                    "key": r.key,
                    "info": {
                        "key_id": r.info.key_id,
                        "subject": r.info.subject,
                        "tenant_id": u64::from(r.info.tenant_id),
                        "roles": r.info.roles,
                        "expires_at_nanos": r.info.expires_at_nanos,
                    }
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Revoke an API key by plaintext. Returns `{"revoked":bool}`.
///
/// # Safety
/// - `client`, `key`, and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_api_key_revoke(
    client: *mut KmbClient,
    key: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || key.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let k = match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.api_key_revoke(k) {
            Ok(revoked) => {
                let json = serde_json::json!({ "revoked": revoked });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// List API-key metadata. `tenant_id == 0` means "all tenants". Returns
/// `{"keys":[{...}]}`. Never includes plaintext.
///
/// # Safety
/// - `client` and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_api_key_list(
    client: *mut KmbClient,
    tenant_id: u64,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let filter = if tenant_id == 0 {
            None
        } else {
            Some(TenantId::new(tenant_id))
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.api_key_list(filter) {
            Ok(keys) => {
                let json = serde_json::json!({
                    "keys": keys.iter().map(|k| serde_json::json!({
                        "key_id": k.key_id,
                        "subject": k.subject,
                        "tenant_id": u64::from(k.tenant_id),
                        "roles": k.roles,
                        "expires_at_nanos": k.expires_at_nanos,
                    })).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Atomically rotate an API key. Returns `{"new_key":"...","info":{...}}`.
///
/// # Safety
/// - `client`, `old_key`, and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_api_key_rotate(
    client: *mut KmbClient,
    old_key: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || old_key.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let k = match CStr::from_ptr(old_key).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.api_key_rotate(k) {
            Ok(r) => {
                let json = serde_json::json!({
                    "new_key": r.new_key,
                    "info": {
                        "key_id": r.info.key_id,
                        "subject": r.info.subject,
                        "tenant_id": u64::from(r.info.tenant_id),
                        "roles": r.info.roles,
                        "expires_at_nanos": r.info.expires_at_nanos,
                    }
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Get canonical server info. Returns
/// `{"build_version":..,"protocol_version":..,"capabilities":[...],"uptime_secs":..,"cluster_mode":"Standalone|Clustered","tenant_count":..}`.
///
/// # Safety
/// - `client` and `result_out` must be non-null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_server_info(
    client: *mut KmbClient,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.server_info() {
            Ok(info) => {
                let json = serde_json::json!({
                    "build_version": info.build_version,
                    "protocol_version": info.protocol_version,
                    "capabilities": info.capabilities,
                    "uptime_secs": info.uptime_secs,
                    "cluster_mode": cluster_mode_str(info.cluster_mode),
                    "tenant_count": info.tenant_count,
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

// ============================================================================
// Phase 6 — Masking policy catalogue (v0.6.0 Tier 2 #7)
// ============================================================================

/// Parse a JSON strategy descriptor into a `MaskingStrategySpec`.
///
/// Expected shapes:
/// - `{"kind":"RedactSsn|RedactPhone|RedactEmail|RedactCreditCard|Hash|Tokenize|Null"}`
/// - `{"kind":"RedactCustom","replacement":"<str>"}`
/// - `{"kind":"Truncate","max_chars":<int>}`
fn parse_masking_strategy(
    json: &serde_json::Value,
) -> std::result::Result<kimberlite_client::MaskingStrategySpec, String> {
    use kimberlite_client::MaskingStrategySpec;
    let kind = json
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing `kind`".to_string())?;
    match kind {
        "RedactSsn" => Ok(MaskingStrategySpec::RedactSsn),
        "RedactPhone" => Ok(MaskingStrategySpec::RedactPhone),
        "RedactEmail" => Ok(MaskingStrategySpec::RedactEmail),
        "RedactCreditCard" => Ok(MaskingStrategySpec::RedactCreditCard),
        "RedactCustom" => json
            .get("replacement")
            .and_then(|v| v.as_str())
            .map(|r| MaskingStrategySpec::RedactCustom {
                replacement: r.to_string(),
            })
            .ok_or_else(|| "RedactCustom requires a `replacement` string".to_string()),
        "Hash" => Ok(MaskingStrategySpec::Hash),
        "Tokenize" => Ok(MaskingStrategySpec::Tokenize),
        "Truncate" => json
            .get("max_chars")
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0)
            .map(|n| MaskingStrategySpec::Truncate {
                max_chars: n as usize,
            })
            .ok_or_else(|| "Truncate requires a positive `max_chars`".to_string()),
        "Null" => Ok(MaskingStrategySpec::Null),
        other => Err(format!("unknown masking strategy `{other}`")),
    }
}

fn wire_strategy_to_json(s: &kimberlite_wire::MaskingStrategyWire) -> serde_json::Value {
    use kimberlite_wire::MaskingStrategyWire;
    match s {
        MaskingStrategyWire::Redact {
            pattern,
            replacement,
        } => {
            let kind = match pattern.as_str() {
                "SSN" => "RedactSsn",
                "PHONE" => "RedactPhone",
                "EMAIL" => "RedactEmail",
                "CC" => "RedactCreditCard",
                _ => "RedactCustom",
            };
            if let Some(r) = replacement {
                serde_json::json!({ "kind": kind, "replacement": r })
            } else {
                serde_json::json!({ "kind": kind })
            }
        }
        MaskingStrategyWire::Hash => serde_json::json!({"kind":"Hash"}),
        MaskingStrategyWire::Tokenize => serde_json::json!({"kind":"Tokenize"}),
        MaskingStrategyWire::Truncate { max_chars } => {
            serde_json::json!({"kind":"Truncate", "max_chars": max_chars})
        }
        MaskingStrategyWire::Null => serde_json::json!({"kind":"Null"}),
    }
}

/// Create a masking policy.
///
/// # Arguments
/// - `name_ptr`: NULL-terminated UTF-8 policy name.
/// - `strategy_json_ptr`: NULL-terminated UTF-8 JSON of the strategy
///   descriptor. Shape: `{"kind": "Hash" | "Redact" | "Partial" |
///   "Tokenize" | "Truncate" | "Null", ...}`. `Partial` requires
///   `{"visible_prefix": N, "visible_suffix": M}`; `Truncate` requires
///   `{"max_chars": N}`. Other kinds are shape-only. See the Rust
///   `MaskingStrategyWire` enum on the server side for the source of
///   truth.
/// - `roles_json_ptr`: NULL-terminated UTF-8 JSON array of exempt role names.
///
/// # Safety
/// All pointers must be non-null and point to valid NULL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_masking_policy_create(
    client: *mut KmbClient,
    name_ptr: *const c_char,
    strategy_json_ptr: *const c_char,
    roles_json_ptr: *const c_char,
) -> KmbError {
    unsafe {
        if client.is_null()
            || name_ptr.is_null()
            || strategy_json_ptr.is_null()
            || roles_json_ptr.is_null()
        {
            return KmbError::KmbErrNullPointer;
        }
        let name = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let strategy_json = match CStr::from_ptr(strategy_json_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let roles_json = match CStr::from_ptr(roles_json_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        let strategy_value: serde_json::Value = match serde_json::from_str(strategy_json) {
            Ok(v) => v,
            Err(_) => return KmbError::KmbErrInternal,
        };
        let spec = match parse_masking_strategy(&strategy_value) {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInternal,
        };
        let roles: Vec<String> = match serde_json::from_str(roles_json) {
            Ok(v) => v,
            Err(_) => return KmbError::KmbErrInternal,
        };
        let role_refs: Vec<&str> = roles.iter().map(String::as_str).collect();

        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.masking_policy_create(name, spec, &role_refs) {
            Ok(()) => KmbError::KmbOk,
            Err(e) => map_error(e),
        }
    }
}

/// Drop a masking policy.
///
/// # Safety
/// `client` and `name_ptr` must be non-null, `name_ptr` NULL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_masking_policy_drop(
    client: *mut KmbClient,
    name_ptr: *const c_char,
) -> KmbError {
    unsafe {
        if client.is_null() || name_ptr.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let name = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.masking_policy_drop(name) {
            Ok(()) => KmbError::KmbOk,
            Err(e) => map_error(e),
        }
    }
}

/// Attach a pre-existing masking policy to a column.
///
/// # Safety
/// All pointers must be non-null and NULL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_masking_policy_attach(
    client: *mut KmbClient,
    table_ptr: *const c_char,
    column_ptr: *const c_char,
    policy_name_ptr: *const c_char,
) -> KmbError {
    unsafe {
        if client.is_null()
            || table_ptr.is_null()
            || column_ptr.is_null()
            || policy_name_ptr.is_null()
        {
            return KmbError::KmbErrNullPointer;
        }
        let table = match CStr::from_ptr(table_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let column = match CStr::from_ptr(column_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let policy = match CStr::from_ptr(policy_name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.masking_policy_attach(table, column, policy) {
            Ok(()) => KmbError::KmbOk,
            Err(e) => map_error(e),
        }
    }
}

/// Detach the masking policy from a column.
///
/// # Safety
/// All pointers must be non-null and NULL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_masking_policy_detach(
    client: *mut KmbClient,
    table_ptr: *const c_char,
    column_ptr: *const c_char,
) -> KmbError {
    unsafe {
        if client.is_null() || table_ptr.is_null() || column_ptr.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let table = match CStr::from_ptr(table_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let column = match CStr::from_ptr(column_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.masking_policy_detach(table, column) {
            Ok(()) => KmbError::KmbOk,
            Err(e) => map_error(e),
        }
    }
}

/// List every masking policy in the tenant's catalogue.
///
/// Returns `{"policies":[...], "attachments":[...]}` as JSON.
///
/// # Safety
/// `client` and `result_out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_admin_masking_policy_list(
    client: *mut KmbClient,
    include_attachments: bool,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.masking_policy_list(include_attachments) {
            Ok(resp) => {
                let policies: Vec<_> = resp
                    .policies
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "strategy": wire_strategy_to_json(&p.strategy),
                            "exempt_roles": p.exempt_roles,
                            "default_masked": p.default_masked,
                            "attachment_count": p.attachment_count,
                        })
                    })
                    .collect();
                let attachments: Vec<_> = resp
                    .attachments
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "table_name": a.table_name,
                            "column_name": a.column_name,
                            "policy_name": a.policy_name,
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "policies": policies,
                    "attachments": attachments,
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

// ============================================================================
// Phase 5 — Consent + Erasure (JSON-passthrough)
// ============================================================================

fn parse_consent_purpose(s: &str) -> Option<WireConsentPurpose> {
    Some(match s {
        "Marketing" => WireConsentPurpose::Marketing,
        "Analytics" => WireConsentPurpose::Analytics,
        "Contractual" => WireConsentPurpose::Contractual,
        "LegalObligation" => WireConsentPurpose::LegalObligation,
        "VitalInterests" => WireConsentPurpose::VitalInterests,
        "PublicTask" => WireConsentPurpose::PublicTask,
        "Research" => WireConsentPurpose::Research,
        "Security" => WireConsentPurpose::Security,
        "Treatment" => WireConsentPurpose::Treatment,
        "Payment" => WireConsentPurpose::Payment,
        "Operations" => WireConsentPurpose::Operations,
        "PublicHealth" => WireConsentPurpose::PublicHealth,
        "Emergency" => WireConsentPurpose::Emergency,
        _ => return None,
    })
}

fn parse_exemption_basis(s: &str) -> Option<WireExemptionBasis> {
    Some(match s {
        "LegalObligation" => WireExemptionBasis::LegalObligation,
        "PublicHealth" => WireExemptionBasis::PublicHealth,
        "Archiving" => WireExemptionBasis::Archiving,
        "LegalClaims" => WireExemptionBasis::LegalClaims,
        _ => return None,
    })
}

fn consent_basis_to_json(b: &kimberlite_wire::ConsentBasis) -> serde_json::Value {
    serde_json::json!({
        "article": format!("{:?}", b.article),
        "justification": b.justification,
    })
}

/// Parse `{"article":"Consent","justification":"..."}` into a wire
/// `ConsentBasis`. Accepts `null` / absent fields as `None` on
/// justification. Returns `None` if the article string is unknown.
fn parse_consent_basis(json: &str) -> Option<kimberlite_wire::ConsentBasis> {
    let raw: serde_json::Value = serde_json::from_str(json).ok()?;
    let article_str = raw.get("article")?.as_str()?;
    let article = match article_str {
        "Consent" => kimberlite_wire::GdprArticle::Consent,
        "Contract" => kimberlite_wire::GdprArticle::Contract,
        "LegalObligation" => kimberlite_wire::GdprArticle::LegalObligation,
        "VitalInterests" => kimberlite_wire::GdprArticle::VitalInterests,
        "PublicTask" => kimberlite_wire::GdprArticle::PublicTask,
        "LegitimateInterests" => kimberlite_wire::GdprArticle::LegitimateInterests,
        _ => return None,
    };
    let justification = raw
        .get("justification")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(kimberlite_wire::ConsentBasis {
        article,
        justification,
    })
}

fn consent_record_to_json(r: &kimberlite_wire::ConsentRecord) -> serde_json::Value {
    serde_json::json!({
        "consent_id": r.consent_id,
        "subject_id": r.subject_id,
        "purpose": format!("{:?}", r.purpose),
        "scope": format!("{:?}", r.scope),
        "granted_at_nanos": r.granted_at_nanos,
        "withdrawn_at_nanos": r.withdrawn_at_nanos,
        "expires_at_nanos": r.expires_at_nanos,
        "notes": r.notes,
        "basis": r.basis.as_ref().map(consent_basis_to_json),
    })
}

fn erasure_request_to_json(r: &kimberlite_wire::ErasureRequestInfo) -> serde_json::Value {
    use kimberlite_wire::ErasureStatusTag;
    let (status, fields): (&str, serde_json::Value) = match &r.status {
        ErasureStatusTag::Pending => ("Pending", serde_json::json!({})),
        ErasureStatusTag::InProgress { streams_remaining } => (
            "InProgress",
            serde_json::json!({ "streams_remaining": streams_remaining }),
        ),
        ErasureStatusTag::Complete {
            erased_at_nanos,
            total_records,
        } => (
            "Complete",
            serde_json::json!({ "erased_at_nanos": erased_at_nanos, "total_records": total_records }),
        ),
        ErasureStatusTag::Failed {
            reason,
            retry_at_nanos,
        } => (
            "Failed",
            serde_json::json!({ "reason": reason, "retry_at_nanos": retry_at_nanos }),
        ),
        ErasureStatusTag::Exempt { basis } => (
            "Exempt",
            serde_json::json!({ "basis": format!("{basis:?}") }),
        ),
    };
    serde_json::json!({
        "request_id": r.request_id,
        "subject_id": r.subject_id,
        "requested_at_nanos": r.requested_at_nanos,
        "deadline_nanos": r.deadline_nanos,
        "status": { "kind": status, "fields": fields },
        "records_erased": r.records_erased,
        "streams_affected": r.streams_affected.iter().map(|s| u64::from(*s)).collect::<Vec<_>>(),
    })
}

fn erasure_audit_to_json(a: &kimberlite_wire::ErasureAuditInfo) -> serde_json::Value {
    serde_json::json!({
        "request_id": a.request_id,
        "subject_id": a.subject_id,
        "requested_at_nanos": a.requested_at_nanos,
        "completed_at_nanos": a.completed_at_nanos,
        "records_erased": a.records_erased,
        "streams_affected": a.streams_affected.iter().map(|s| u64::from(*s)).collect::<Vec<_>>(),
        "erasure_proof_hex": a.erasure_proof_hex,
    })
}

/// AUDIT-2026-04 S3.6 — convert an `AuditEventInfo` to JSON for
/// FFI consumers. Every field optional-null-safe.
///
/// **v0.6.0 Tier 2 #9** — PHI-safe shape. The upstream wire type
/// no longer carries a full action-payload blob; only
/// `changed_field_names` (names, never values).
fn audit_event_to_json(e: &kimberlite_wire::AuditEventInfo) -> serde_json::Value {
    serde_json::json!({
        "event_id": e.event_id,
        "timestamp_nanos": e.timestamp_nanos,
        "action": e.action,
        "subject_id": e.subject_id,
        "actor": e.actor,
        "tenant_id": e.tenant_id,
        "ip_address": e.ip_address,
        "correlation_id": e.correlation_id,
        "request_id": e.request_id,
        "reason": e.reason,
        "source_country": e.source_country,
        "changed_field_names": e.changed_field_names,
    })
}

/// AUDIT-2026-04 S3.6 — convert a `PortabilityExportInfo` to JSON.
fn portability_export_to_json(p: &kimberlite_wire::PortabilityExportInfo) -> serde_json::Value {
    let format_str = match p.format {
        kimberlite_wire::ExportFormat::Json => "Json",
        kimberlite_wire::ExportFormat::Csv => "Csv",
    };
    serde_json::json!({
        "export_id": p.export_id,
        "subject_id": p.subject_id,
        "requester_id": p.requester_id,
        "requested_at_nanos": p.requested_at_nanos,
        "completed_at_nanos": p.completed_at_nanos,
        "format": format_str,
        "streams_included": p.streams_included.iter().map(|s| u64::from(*s)).collect::<Vec<_>>(),
        "record_count": p.record_count,
        "content_hash_hex": p.content_hash_hex,
        "signature_hex": p.signature_hex,
        "body_base64": p.body_base64,
    })
}

/// Grant consent. `purpose` is a string matching the `ConsentPurpose` enum.
/// `basis_json` is an optional null-pointer or UTF-8 JSON payload of shape
/// `{"article":"Consent","justification":"..."}` — added in wire v4 (v0.6.0)
/// to thread the GDPR Article 6(1) lawful basis onto the grant. Unknown
/// articles return `KmbErrInternal`; callers should pass `NULL` to preserve
/// legacy behaviour.
///
/// `options_json` is the v0.6.2 / wire v5 extension envelope, accepting
/// `NULL` (legacy behaviour) or a UTF-8 JSON object of shape
/// `{"terms_version":"v3","accepted":false}`. Both fields optional;
/// missing `accepted` defaults to `true`. v0.6.1 callers pass `NULL`
/// and the server records `terms_version = None`, `accepted = true`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_consent_grant(
    client: *mut KmbClient,
    subject_id: *const c_char,
    purpose: *const c_char,
    basis_json: *const c_char,
    options_json: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || subject_id.is_null() || purpose.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let purpose_str = match CStr::from_ptr(purpose).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wire_purpose = match parse_consent_purpose(purpose_str) {
            Some(p) => p,
            None => return KmbError::KmbErrInternal,
        };
        let wire_basis = if basis_json.is_null() {
            None
        } else {
            let raw = match CStr::from_ptr(basis_json).to_str() {
                Ok(s) => s,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            };
            match parse_consent_basis(raw) {
                Some(b) => Some(b),
                None => return KmbError::KmbErrInternal,
            }
        };
        let (terms_version, accepted) = if options_json.is_null() {
            (None, true)
        } else {
            let raw = match CStr::from_ptr(options_json).to_str() {
                Ok(s) => s,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            };
            match parse_consent_options(raw) {
                Some(opts) => opts,
                None => return KmbError::KmbErrInternal,
            }
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.consent_grant_with_terms(
            subj,
            wire_purpose,
            None,
            wire_basis,
            terms_version,
            accepted,
        ) {
            Ok(r) => {
                let json = serde_json::json!({
                    "consent_id": r.consent_id,
                    "granted_at_nanos": r.granted_at_nanos,
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Parse the v0.6.2 grant-options JSON envelope.
///
/// Returns `Some((terms_version, accepted))` with the defaults
/// applied (`accepted = true` when missing / null). Returns `None`
/// only on JSON syntax errors — unknown fields are silently ignored
/// to keep forward-compat for newer envelope shapes.
fn parse_consent_options(raw: &str) -> Option<(Option<String>, bool)> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = value.as_object()?;
    let terms_version = obj
        .get("terms_version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let accepted = obj
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Some((terms_version, accepted))
}

/// Withdraw consent by ID.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_consent_withdraw(
    client: *mut KmbClient,
    consent_id: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || consent_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let id = match CStr::from_ptr(consent_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.consent_withdraw(id) {
            Ok(r) => {
                let json = serde_json::json!({ "withdrawn_at_nanos": r.withdrawn_at_nanos });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Check consent. Returns `{"is_valid": bool}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_consent_check(
    client: *mut KmbClient,
    subject_id: *const c_char,
    purpose: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || subject_id.is_null() || purpose.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let purpose_str = match CStr::from_ptr(purpose).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wire_purpose = match parse_consent_purpose(purpose_str) {
            Some(p) => p,
            None => return KmbError::KmbErrInternal,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.consent_check(subj, wire_purpose) {
            Ok(is_valid) => {
                let json = serde_json::json!({ "is_valid": is_valid });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// List consent records. `valid_only = 1` hides withdrawn/expired.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_consent_list(
    client: *mut KmbClient,
    subject_id: *const c_char,
    valid_only: c_int,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || subject_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.consent_list(subj, valid_only != 0) {
            Ok(records) => {
                let json = serde_json::json!({
                    "consents": records.iter().map(consent_record_to_json).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Request erasure for a subject. Returns the request record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_request(
    client: *mut KmbClient,
    subject_id: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || subject_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.erasure_request(subj) {
            Ok(r) => match wrap_json(erasure_request_to_json(&r)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// Fetch current status of an erasure request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_status(
    client: *mut KmbClient,
    request_id: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || request_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let rid = match CStr::from_ptr(request_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.erasure_status(rid) {
            Ok(r) => match wrap_json(erasure_request_to_json(&r)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// Complete an erasure request (returns the audit record).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_complete(
    client: *mut KmbClient,
    request_id: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || request_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let rid = match CStr::from_ptr(request_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.erasure_complete(rid) {
            Ok(audit) => match wrap_json(erasure_audit_to_json(&audit)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// Mark an erasure request as exempt under GDPR Art. 17(3). `basis` is one of
/// `"LegalObligation" | "PublicHealth" | "Archiving" | "LegalClaims"`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_exempt(
    client: *mut KmbClient,
    request_id: *const c_char,
    basis: *const c_char,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || request_id.is_null() || basis.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let rid = match CStr::from_ptr(request_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let basis_str = match CStr::from_ptr(basis).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wire_basis = match parse_exemption_basis(basis_str) {
            Some(b) => b,
            None => return KmbError::KmbErrInternal,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.erasure_exempt(rid, wire_basis) {
            Ok(r) => match wrap_json(erasure_request_to_json(&r)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// Record that one stream has been erased as part of an ongoing
/// erasure request. Mirrors
/// `Client::erasure_mark_stream_erased` for SDKs that consume the
/// C ABI (Python, C, etc.).
///
/// `request_id` is the UUID string returned by
/// `kmb_compliance_erasure_request`. `stream_id` is the 64-bit stream
/// handle. `records_erased` is the count that was erased on this
/// stream.
///
/// Returns the updated `ErasureRequestInfo` as JSON in `result_out`.
///
/// # Safety
/// - `client` must be a valid `*mut KmbClient` returned by
///   `kmb_client_connect`
/// - `request_id` must be a valid NUL-terminated UTF-8 string
/// - `result_out` must point to a writable `KmbAdminJson`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_mark_stream_erased(
    client: *mut KmbClient,
    request_id: *const c_char,
    stream_id: u64,
    records_erased: u64,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || request_id.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let rid = match CStr::from_ptr(request_id).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let wrapper = &mut *(client as *mut ClientWrapper);
        let sid = kimberlite_types::StreamId::new(stream_id);
        match wrapper
            .client
            .erasure_mark_stream_erased(rid, sid, records_erased)
        {
            Ok(r) => match wrap_json(erasure_request_to_json(&r)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// AUDIT-2026-04 S3.6 — query the compliance audit log.
///
/// All filter arguments are nullable strings or sentinel `0`
/// values. `subject_id`, `action_type`, `actor` of NULL mean
/// "don't filter on this field". `time_from_nanos` /
/// `time_to_nanos` of 0 mean "unbounded in that direction".
/// `limit` of 0 uses the server's default.
///
/// Returns a JSON object `{ "events": [...] }` where each event
/// is rendered by `audit_event_to_json`.
///
/// # Safety
/// - `client` must be a valid `KmbClient`.
/// - Every non-NULL string pointer must be a valid NUL-terminated
///   UTF-8 string.
/// - `result_out` must point to a writable `KmbAdminJson`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_audit_query(
    client: *mut KmbClient,
    subject_id: *const c_char,
    action_type: *const c_char,
    time_from_nanos: u64,
    time_to_nanos: u64,
    actor: *const c_char,
    limit: u32,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        // Helper to decode an optional UTF-8 string pointer.
        fn opt_utf8(p: *const c_char) -> std::result::Result<Option<String>, KmbError> {
            if p.is_null() {
                return Ok(None);
            }
            unsafe {
                CStr::from_ptr(p)
                    .to_str()
                    .map(|s| Some(s.to_string()))
                    .map_err(|_| KmbError::KmbErrInvalidUtf8)
            }
        }

        let subj = match opt_utf8(subject_id) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let action = match opt_utf8(action_type) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let actor = match opt_utf8(actor) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let from = if time_from_nanos == 0 {
            None
        } else {
            Some(time_from_nanos)
        };
        let to = if time_to_nanos == 0 {
            None
        } else {
            Some(time_to_nanos)
        };
        let limit_opt = if limit == 0 { None } else { Some(limit) };

        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper
            .client
            .audit_query(subj, action, from, to, actor, limit_opt)
        {
            Ok(events) => {
                let json = serde_json::json!({
                    "events": events.iter().map(audit_event_to_json).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// AUDIT-2026-04 S3.6 — GDPR Article 20 portability export.
///
/// `format` is `"Json"` or `"Csv"`. `stream_ids_json` is a JSON
/// array of u64 stream IDs, or NULL for "every stream".
/// `max_records_per_stream` of 0 uses the server's default.
///
/// Returns the `PortabilityExportInfo` as JSON in `result_out`.
///
/// # Safety
/// - `client` must be a valid `KmbClient`.
/// - `subject_id`, `requester_id`, `format` must be
///   NUL-terminated UTF-8 strings.
/// - `stream_ids_json` may be NULL; otherwise it must be a
///   NUL-terminated UTF-8 JSON array of u64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_export_subject(
    client: *mut KmbClient,
    subject_id: *const c_char,
    requester_id: *const c_char,
    format: *const c_char,
    stream_ids_json: *const c_char,
    max_records_per_stream: u64,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null()
            || subject_id.is_null()
            || requester_id.is_null()
            || format.is_null()
            || result_out.is_null()
        {
            return KmbError::KmbErrNullPointer;
        }
        let subj = match CStr::from_ptr(subject_id).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let req = match CStr::from_ptr(requester_id).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let format_str = match CStr::from_ptr(format).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };
        let format_wire = match format_str {
            "Json" | "json" => kimberlite_wire::ExportFormat::Json,
            "Csv" | "csv" => kimberlite_wire::ExportFormat::Csv,
            _ => return KmbError::KmbErrInternal,
        };
        let stream_ids: Vec<kimberlite_types::StreamId> = if stream_ids_json.is_null() {
            Vec::new()
        } else {
            let j = match CStr::from_ptr(stream_ids_json).to_str() {
                Ok(s) => s,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            };
            match serde_json::from_str::<Vec<u64>>(j) {
                Ok(v) => v.into_iter().map(kimberlite_types::StreamId::new).collect(),
                Err(_) => return KmbError::KmbErrInternal,
            }
        };

        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.export_subject(
            subj,
            req,
            format_wire,
            stream_ids,
            max_records_per_stream,
        ) {
            Ok(export) => match wrap_json(portability_export_to_json(&export)) {
                Ok(r) => {
                    *result_out = r;
                    KmbError::KmbOk
                }
                Err(e) => e,
            },
            Err(e) => map_error(e),
        }
    }
}

/// List every audited erasure request for the tenant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_compliance_erasure_list(
    client: *mut KmbClient,
    result_out: *mut KmbAdminJson,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &mut *(client as *mut ClientWrapper);
        match wrapper.client.erasure_list() {
            Ok(records) => {
                let json = serde_json::json!({
                    "audit": records.iter().map(erasure_audit_to_json).collect::<Vec<_>>(),
                });
                match wrap_json(json) {
                    Ok(r) => {
                        *result_out = r;
                        KmbError::KmbOk
                    }
                    Err(e) => e,
                }
            }
            Err(e) => map_error(e),
        }
    }
}

/// Free the heap-allocated `data` inside a `KmbSubscriptionEvent`.
///
/// Safe to call with a closed event (`closed == 1`, `data == NULL`).
///
/// # Safety
/// - `event` must either be a valid event returned by `kmb_subscription_next`
///   or a freshly-zeroed struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_subscription_event_free(event: *mut KmbSubscriptionEvent) {
    unsafe {
        if event.is_null() {
            return;
        }
        let ev = &mut *event;
        if !ev.data.is_null() && ev.data_len > 0 {
            let _ = Vec::from_raw_parts(ev.data, ev.data_len, ev.data_len);
            ev.data = std::ptr::null_mut();
            ev.data_len = 0;
        }
    }
}

/// Destroy a pool, freeing all remaining resources. Implicitly calls shutdown.
///
/// # Safety
/// - `pool` must be a valid handle from `kmb_pool_create`
/// - After this call the handle is invalid
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_pool_destroy(pool: *mut KmbPool) {
    unsafe {
        if pool.is_null() {
            return;
        }
        let wrapper = Box::from_raw(pool as *mut PoolWrapper);
        wrapper.pool.shutdown();
        // Dropping the PoolWrapper drops the Arc — when the last clone is
        // gone, idle connections are dropped too.
    }
}

/// Result from read_events operation.
#[repr(C)]
pub struct KmbReadResult {
    /// Array of event data pointers
    pub events: *mut *mut u8,
    /// Parallel array of event lengths
    pub event_lengths: *mut usize,
    /// Number of events
    pub event_count: usize,
}

/// Query parameter type.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbQueryParamType {
    /// Null value
    KmbParamNull = 0,
    /// 64-bit integer
    KmbParamBigInt = 1,
    /// Text string
    KmbParamText = 2,
    /// Boolean
    KmbParamBoolean = 3,
    /// Timestamp (nanoseconds since epoch)
    KmbParamTimestamp = 4,
}

/// Query parameter value (input to query).
#[repr(C)]
pub struct KmbQueryParam {
    /// Parameter type
    pub param_type: KmbQueryParamType,
    /// BigInt value (used when param_type == KmbParamBigInt)
    pub bigint_val: i64,
    /// Text value (NULL-terminated, used when param_type == KmbParamText)
    pub text_val: *const c_char,
    /// Boolean value (used when param_type == KmbParamBoolean)
    pub bool_val: c_int,
    /// Timestamp value (used when param_type == KmbParamTimestamp)
    pub timestamp_val: i64,
}

/// Query value type (output from query).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmbQueryValueType {
    /// Null value
    KmbValueNull = 0,
    /// 64-bit integer
    KmbValueBigInt = 1,
    /// Text string
    KmbValueText = 2,
    /// Boolean
    KmbValueBoolean = 3,
    /// Timestamp (nanoseconds since epoch)
    KmbValueTimestamp = 4,
}

/// Query value (output from query).
#[repr(C)]
pub struct KmbQueryValue {
    /// Value type
    pub value_type: KmbQueryValueType,
    /// BigInt value (used when value_type == KmbValueBigInt)
    pub bigint_val: i64,
    /// Text value (NULL-terminated, owned by result, used when value_type == KmbValueText)
    pub text_val: *mut c_char,
    /// Boolean value (used when value_type == KmbValueBoolean)
    pub bool_val: c_int,
    /// Timestamp value (used when value_type == KmbValueTimestamp)
    pub timestamp_val: i64,
}

/// Query result (2D array of values).
#[repr(C)]
pub struct KmbQueryResult {
    /// Array of column names (NULL-terminated C strings, owned by result)
    pub columns: *mut *mut c_char,
    /// Number of columns
    pub column_count: usize,
    /// Array of rows (each row is an array of KmbQueryValue)
    pub rows: *mut *mut KmbQueryValue,
    /// Array of row lengths (number of values in each row)
    pub row_lengths: *mut usize,
    /// Number of rows
    pub row_count: usize,
}

// Helper functions

/// Convert Rust ClientError to FFI error code
fn map_error(err: ClientError) -> KmbError {
    match err {
        ClientError::Connection(_) => KmbError::KmbErrConnectionFailed,
        ClientError::HandshakeFailed(_) => KmbError::KmbErrAuthFailed,
        ClientError::Timeout => KmbError::KmbErrTimeout,
        ClientError::Server { code, .. } => {
            use kimberlite_wire::ErrorCode;
            match code {
                ErrorCode::StreamNotFound => KmbError::KmbErrStreamNotFound,
                ErrorCode::TenantNotFound => KmbError::KmbErrTenantNotFound,
                ErrorCode::AuthenticationFailed => KmbError::KmbErrAuthFailed,
                ErrorCode::InvalidOffset => KmbError::KmbErrOffsetOutOfRange,
                ErrorCode::QueryParseError => KmbError::KmbErrQuerySyntax,
                ErrorCode::QueryExecutionError => KmbError::KmbErrQueryExecution,
                ErrorCode::UniqueConstraintViolation => KmbError::KmbErrUniqueConstraintViolation,
                _ => KmbError::KmbErrInternal,
            }
        }
        ClientError::Wire(_) => KmbError::KmbErrInternal,
        ClientError::NotConnected => KmbError::KmbErrConnectionFailed,
        ClientError::ResponseMismatch { .. } => KmbError::KmbErrInternal,
        ClientError::UnexpectedResponse { .. } => KmbError::KmbErrInternal,
    }
}

/// Convert FFI data class to Rust DataClass
fn map_data_class(dc: KmbDataClass) -> Result<DataClass, KmbError> {
    match dc {
        KmbDataClass::KmbDataClassPhi => Ok(DataClass::PHI),
        KmbDataClass::KmbDataClassNonPhi => Ok(DataClass::Public),
        KmbDataClass::KmbDataClassDeidentified => Ok(DataClass::Deidentified),
        KmbDataClass::KmbDataClassPii => Ok(DataClass::PII),
        KmbDataClass::KmbDataClassSensitive => Ok(DataClass::Sensitive),
        KmbDataClass::KmbDataClassPci => Ok(DataClass::PCI),
        KmbDataClass::KmbDataClassFinancial => Ok(DataClass::Financial),
        KmbDataClass::KmbDataClassConfidential => Ok(DataClass::Confidential),
        KmbDataClass::KmbDataClassPublic => Ok(DataClass::Public),
    }
}

/// Convert FFI placement to Rust Placement.
///
/// Returns `KmbErrNullPointer` if `placement` is `KmbPlacementCustom` and
/// `custom_region` is null or not valid UTF-8.
unsafe fn map_placement(
    placement: KmbPlacement,
    custom_region: *const c_char,
) -> Result<Placement, KmbError> {
    match placement {
        KmbPlacement::KmbPlacementGlobal => Ok(Placement::Global),
        KmbPlacement::KmbPlacementUsEast1 => Ok(Placement::Region(Region::USEast1)),
        KmbPlacement::KmbPlacementApSoutheast2 => Ok(Placement::Region(Region::APSoutheast2)),
        KmbPlacement::KmbPlacementCustom => {
            if custom_region.is_null() {
                return Err(KmbError::KmbErrNullPointer);
            }
            let name = match unsafe { CStr::from_ptr(custom_region) }.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return Err(KmbError::KmbErrInvalidUtf8),
            };
            Ok(Placement::Region(Region::custom(name)))
        }
    }
}

/// Convert FFI query parameter to Rust QueryParam
unsafe fn convert_query_param(param: &KmbQueryParam) -> Result<QueryParam, KmbError> {
    unsafe {
        match param.param_type {
            KmbQueryParamType::KmbParamNull => Ok(QueryParam::Null),
            KmbQueryParamType::KmbParamBigInt => Ok(QueryParam::BigInt(param.bigint_val)),
            KmbQueryParamType::KmbParamText => {
                if param.text_val.is_null() {
                    return Err(KmbError::KmbErrNullPointer);
                }
                let text = match CStr::from_ptr(param.text_val).to_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => return Err(KmbError::KmbErrInvalidUtf8),
                };
                Ok(QueryParam::Text(text))
            }
            KmbQueryParamType::KmbParamBoolean => Ok(QueryParam::Boolean(param.bool_val != 0)),
            KmbQueryParamType::KmbParamTimestamp => Ok(QueryParam::Timestamp(param.timestamp_val)),
        }
    }
}

/// Convert Rust QueryValue to FFI KmbQueryValue
unsafe fn convert_query_value(value: QueryValue) -> Result<KmbQueryValue, KmbError> {
    match value {
        QueryValue::Null => Ok(KmbQueryValue {
            value_type: KmbQueryValueType::KmbValueNull,
            bigint_val: 0,
            text_val: std::ptr::null_mut(),
            bool_val: 0,
            timestamp_val: 0,
        }),
        QueryValue::BigInt(v) => Ok(KmbQueryValue {
            value_type: KmbQueryValueType::KmbValueBigInt,
            bigint_val: v,
            text_val: std::ptr::null_mut(),
            bool_val: 0,
            timestamp_val: 0,
        }),
        QueryValue::Text(s) => {
            let c_string = CString::new(s).map_err(|_| KmbError::KmbErrInvalidUtf8)?;
            Ok(KmbQueryValue {
                value_type: KmbQueryValueType::KmbValueText,
                bigint_val: 0,
                text_val: c_string.into_raw(),
                bool_val: 0,
                timestamp_val: 0,
            })
        }
        QueryValue::Boolean(v) => Ok(KmbQueryValue {
            value_type: KmbQueryValueType::KmbValueBoolean,
            bigint_val: 0,
            text_val: std::ptr::null_mut(),
            bool_val: if v { 1 } else { 0 },
            timestamp_val: 0,
        }),
        QueryValue::Timestamp(v) => Ok(KmbQueryValue {
            value_type: KmbQueryValueType::KmbValueTimestamp,
            bigint_val: 0,
            text_val: std::ptr::null_mut(),
            bool_val: 0,
            timestamp_val: v,
        }),
    }
}

/// Convert Rust QueryResponse to FFI KmbQueryResult
unsafe fn convert_query_response(response: QueryResponse) -> Result<KmbQueryResult, KmbError> {
    unsafe {
        let column_count = response.columns.len();
        let row_count = response.rows.len();

        // Allocate column names — clean up already-allocated pointers if any fail.
        let mut column_ptrs: Vec<*mut c_char> = Vec::with_capacity(column_count);
        for col_name in response.columns {
            match CString::new(col_name) {
                Ok(c_string) => column_ptrs.push(c_string.into_raw()),
                Err(_) => {
                    // Free every CString we already handed out before propagating the error.
                    for ptr in column_ptrs {
                        let _ = CString::from_raw(ptr);
                    }
                    return Err(KmbError::KmbErrInvalidUtf8);
                }
            }
        }

        // Allocate rows
        let mut row_ptrs: Vec<*mut KmbQueryValue> = Vec::with_capacity(row_count);
        let mut row_lens: Vec<usize> = Vec::with_capacity(row_count);

        for row in response.rows {
            let row_len = row.len();
            let mut row_values: Vec<KmbQueryValue> = Vec::with_capacity(row_len);

            for value in row {
                row_values.push(convert_query_value(value)?);
            }

            let row_ptr = row_values.as_mut_ptr();
            std::mem::forget(row_values); // Prevent drop, caller will free

            row_ptrs.push(row_ptr);
            row_lens.push(row_len);
        }

        let result = KmbQueryResult {
            columns: column_ptrs.as_mut_ptr(),
            column_count,
            rows: row_ptrs.as_mut_ptr(),
            row_lengths: row_lens.as_mut_ptr(),
            row_count,
        };

        std::mem::forget(column_ptrs); // Prevent drop
        std::mem::forget(row_ptrs); // Prevent drop
        std::mem::forget(row_lens); // Prevent drop

        Ok(result)
    }
}

// FFI functions

/// Connect to Kimberlite cluster.
///
/// # Arguments
/// - `config`: Connection configuration
/// - `client_out`: Output parameter for client handle
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `config` must be valid
/// - All string pointers in config must be valid NULL-terminated C strings
/// - Caller must call `kmb_client_disconnect()` to free client
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_connect(
    config: *const KmbClientConfig,
    client_out: *mut *mut KmbClient,
) -> KmbError {
    unsafe {
        if config.is_null() || client_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let cfg = &*config;

        // Validate and extract address
        if cfg.address_count == 0 || cfg.addresses.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let addr_ptr = *cfg.addresses;
        if addr_ptr.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let addr = match CStr::from_ptr(addr_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        // Extract auth token (optional)
        let auth_token = if !cfg.auth_token.is_null() {
            match CStr::from_ptr(cfg.auth_token).to_str() {
                Ok(s) if !s.is_empty() => Some(s.to_string()),
                Ok(_) => None,
                Err(_) => return KmbError::KmbErrInvalidUtf8,
            }
        } else {
            None
        };

        // Create client config
        let client_config = ClientConfig {
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            buffer_size: 64 * 1024,
            auth_token,
            auto_reconnect: true,
        };

        // Connect
        let client = match Client::connect(addr, TenantId::new(cfg.tenant_id), client_config) {
            Ok(c) => c,
            Err(e) => return map_error(e),
        };

        // Box and cast to opaque pointer
        let wrapper = Box::new(ClientWrapper { client });
        *client_out = Box::into_raw(wrapper) as *mut KmbClient;

        KmbError::KmbOk
    }
}

/// Disconnect from cluster and free client.
///
/// # Arguments
/// - `client`: Client handle from `kmb_client_connect()`
///
/// # Safety
/// - `client` must be a valid handle from `kmb_client_connect()`
/// - After this call, `client` is invalid and must not be used
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_disconnect(client: *mut KmbClient) {
    unsafe {
        if client.is_null() {
            return;
        }

        // Convert back to Box and drop
        let _ = Box::from_raw(client as *mut ClientWrapper);
    }
}

/// Create a new stream.
///
/// # Arguments
/// - `client`: Client handle
/// - `name`: Stream name (NULL-terminated UTF-8)
/// - `data_class`: Data classification
/// - `stream_id_out`: Output parameter for stream ID
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `name` must be valid NULL-terminated UTF-8 string
/// - `stream_id_out` must be valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_create_stream(
    client: *mut KmbClient,
    name: *const c_char,
    data_class: KmbDataClass,
    stream_id_out: *mut u64,
) -> KmbError {
    unsafe {
        if client.is_null() || name.is_null() || stream_id_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        // Extract name
        let name_str = match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        // Convert data class
        let dc = match map_data_class(data_class) {
            Ok(d) => d,
            Err(e) => return e,
        };

        // Get mutable reference to client
        let wrapper = &mut *(client as *mut ClientWrapper);

        // Create stream
        match wrapper.client.create_stream(name_str, dc) {
            Ok(stream_id) => {
                *stream_id_out = stream_id.into();
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Create a new stream with a specific placement policy.
///
/// # Arguments
/// - `client`: Client handle
/// - `name`: Stream name (NULL-terminated UTF-8)
/// - `data_class`: Data classification
/// - `placement`: Geographic placement policy
/// - `custom_region`: Custom region identifier (only read when
///   `placement == KmbPlacementCustom`; may be NULL otherwise)
/// - `stream_id_out`: Output parameter for stream ID
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `name` must be valid NULL-terminated UTF-8 string
/// - If `placement == KmbPlacementCustom`, `custom_region` must be valid
///   NULL-terminated UTF-8
/// - `stream_id_out` must be valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_create_stream_with_placement(
    client: *mut KmbClient,
    name: *const c_char,
    data_class: KmbDataClass,
    placement: KmbPlacement,
    custom_region: *const c_char,
    stream_id_out: *mut u64,
) -> KmbError {
    unsafe {
        if client.is_null() || name.is_null() || stream_id_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let name_str = match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        let dc = match map_data_class(data_class) {
            Ok(d) => d,
            Err(e) => return e,
        };

        let p = match map_placement(placement, custom_region) {
            Ok(p) => p,
            Err(e) => return e,
        };

        let wrapper = &mut *(client as *mut ClientWrapper);

        match wrapper.client.create_stream_with_placement(name_str, dc, p) {
            Ok(stream_id) => {
                *stream_id_out = stream_id.into();
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Returns the tenant ID this client is connected as.
///
/// # Safety
/// - `client` must be a valid handle
/// - `tenant_id_out` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_tenant_id(
    client: *mut KmbClient,
    tenant_id_out: *mut u64,
) -> KmbError {
    unsafe {
        if client.is_null() || tenant_id_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &*(client as *const ClientWrapper);
        *tenant_id_out = wrapper.client.tenant_id().into();
        KmbError::KmbOk
    }
}

/// Returns the wire request ID of the most recently sent request.
///
/// Useful for correlating client-side logs with server-side tracing output.
/// Writes `0` if no request has been sent yet.
///
/// # Safety
/// - `client` must be a valid handle
/// - `request_id_out` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_last_request_id(
    client: *mut KmbClient,
    request_id_out: *mut u64,
) -> KmbError {
    unsafe {
        if client.is_null() || request_id_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        let wrapper = &*(client as *const ClientWrapper);
        *request_id_out = wrapper.client.last_request_id().unwrap_or(0);
        KmbError::KmbOk
    }
}

/// Execute a DML or DDL statement (INSERT / UPDATE / DELETE / CREATE / ALTER).
///
/// # Arguments
/// - `client`: Client handle
/// - `sql`: SQL statement (NULL-terminated UTF-8)
/// - `params`: Array of query parameters (may be NULL if `param_count == 0`)
/// - `param_count`: Number of parameters
/// - `result_out`: Output parameter for rows-affected and log offset
///
/// # Safety
/// - `client` must be valid
/// - `sql` must be valid NULL-terminated UTF-8 string
/// - `params` must be array of `param_count` valid parameters (or NULL if
///   `param_count == 0`)
/// - `result_out` must be valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_execute(
    client: *mut KmbClient,
    sql: *const c_char,
    params: *const KmbQueryParam,
    param_count: usize,
    result_out: *mut KmbExecuteResult,
) -> KmbError {
    unsafe {
        if client.is_null() || sql.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }
        if param_count > 0 && params.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        let sql_str = match CStr::from_ptr(sql).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        let mut rust_params = Vec::with_capacity(param_count);
        if param_count > 0 {
            let param_slice = slice::from_raw_parts(params, param_count);
            for param in param_slice {
                match convert_query_param(param) {
                    Ok(p) => rust_params.push(p),
                    Err(e) => return e,
                }
            }
        }

        let wrapper = &mut *(client as *mut ClientWrapper);

        match wrapper.client.execute(sql_str, &rust_params) {
            Ok((rows, offset)) => {
                *result_out = KmbExecuteResult {
                    rows_affected: rows,
                    log_offset: offset,
                };
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Append events to a stream.
///
/// # Arguments
/// - `client`: Client handle
/// - `stream_id`: Stream ID
/// - `expected_offset`: Expected current stream offset (optimistic concurrency)
/// - `events`: Array of byte buffers
/// - `event_lengths`: Parallel array of buffer lengths
/// - `event_count`: Number of events
/// - `first_offset_out`: Output parameter for first offset
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `events` must be array of `event_count` valid pointers
/// - `event_lengths` must be array of `event_count` lengths
/// - `first_offset_out` must be valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_append(
    client: *mut KmbClient,
    stream_id: u64,
    expected_offset: u64,
    events: *const *const u8,
    event_lengths: *const usize,
    event_count: usize,
    first_offset_out: *mut u64,
) -> KmbError {
    unsafe {
        if client.is_null()
            || events.is_null()
            || event_lengths.is_null()
            || first_offset_out.is_null()
        {
            return KmbError::KmbErrNullPointer;
        }

        // Convert C arrays to Rust Vec
        let event_ptrs = slice::from_raw_parts(events, event_count);
        let lengths = slice::from_raw_parts(event_lengths, event_count);

        let mut rust_events = Vec::with_capacity(event_count);
        for i in 0..event_count {
            if event_ptrs[i].is_null() {
                return KmbError::KmbErrNullPointer;
            }
            let bytes = slice::from_raw_parts(event_ptrs[i], lengths[i]);
            rust_events.push(bytes.to_vec());
        }

        // Get mutable reference to client
        let wrapper = &mut *(client as *mut ClientWrapper);

        // Append events
        match wrapper.client.append(
            StreamId::from(stream_id),
            rust_events,
            Offset::from(expected_offset),
        ) {
            Ok(offset) => {
                *first_offset_out = offset.into();
                KmbError::KmbOk
            }
            Err(e) => map_error(e),
        }
    }
}

/// Read events from a stream.
///
/// # Arguments
/// - `client`: Client handle
/// - `stream_id`: Stream ID
/// - `from_offset`: Starting offset
/// - `max_bytes`: Maximum bytes to read
/// - `result_out`: Output parameter for read result
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `result_out` must be valid pointer
/// - Caller must call `kmb_read_result_free()` to free result
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_read_events(
    client: *mut KmbClient,
    stream_id: u64,
    from_offset: u64,
    max_bytes: u64,
    result_out: *mut *mut KmbReadResult,
) -> KmbError {
    unsafe {
        if client.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        // Get mutable reference to client
        let wrapper = &mut *(client as *mut ClientWrapper);

        // Read events
        let response = match wrapper.client.read_events(
            StreamId::from(stream_id),
            Offset::new(from_offset),
            max_bytes,
        ) {
            Ok(r) => r,
            Err(e) => return map_error(e),
        };

        let event_count = response.events.len();

        // Allocate arrays
        let mut event_ptrs: Vec<*mut u8> = Vec::with_capacity(event_count);
        let mut event_lens: Vec<usize> = Vec::with_capacity(event_count);

        for event in response.events {
            let len = event.len();
            let mut boxed = event.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed); // Prevent drop, caller will free
            event_ptrs.push(ptr);
            event_lens.push(len);
        }

        // Create result struct
        let result = Box::new(KmbReadResult {
            events: event_ptrs.as_mut_ptr(),
            event_lengths: event_lens.as_mut_ptr(),
            event_count,
        });

        std::mem::forget(event_ptrs); // Prevent drop, caller will free
        std::mem::forget(event_lens);

        *result_out = Box::into_raw(result);
        KmbError::KmbOk
    }
}

/// Free read result.
///
/// # Arguments
/// - `result`: Result from `kmb_client_read_events()`
///
/// # Safety
/// - `result` must be a valid result from `kmb_client_read_events()`
/// - After this call, `result` is invalid and must not be used
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_read_result_free(result: *mut KmbReadResult) {
    unsafe {
        if result.is_null() {
            return;
        }

        let r = Box::from_raw(result);

        // Free event arrays — must use correct lengths since buffers were allocated
        // via into_boxed_slice() with their true length as capacity.
        if !r.events.is_null() && !r.event_lengths.is_null() {
            // Reconstruct both arrays so we can pair each pointer with its length.
            let event_lens = Vec::from_raw_parts(r.event_lengths, r.event_count, r.event_count);
            let event_ptrs = Vec::from_raw_parts(r.events, r.event_count, r.event_count);
            for (ptr, len) in event_ptrs.iter().zip(event_lens.iter()) {
                if !ptr.is_null() {
                    // Reconstruct boxed slice with the correct length/capacity to free it.
                    let _ = Vec::from_raw_parts(*ptr, *len, *len);
                }
            }
            // event_ptrs and event_lens are dropped here, freeing both arrays.
        } else {
            // Handle the degenerate case where only one pointer is non-null.
            if !r.events.is_null() {
                let _ = Vec::from_raw_parts(r.events, r.event_count, r.event_count);
            }
            if !r.event_lengths.is_null() {
                let _ = Vec::from_raw_parts(r.event_lengths, r.event_count, r.event_count);
            }
        }
    }
}

/// Execute a SQL query against current state.
///
/// # Arguments
/// - `client`: Client handle
/// - `sql`: SQL query string (NULL-terminated UTF-8)
/// - `params`: Array of query parameters (may be NULL if param_count == 0)
/// - `param_count`: Number of parameters
/// - `result_out`: Output parameter for query result
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `sql` must be valid NULL-terminated UTF-8 string
/// - `params` must be array of `param_count` valid parameters (or NULL if param_count == 0)
/// - `result_out` must be valid pointer
/// - Caller must call `kmb_query_result_free()` to free result
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_query(
    client: *mut KmbClient,
    sql: *const c_char,
    params: *const KmbQueryParam,
    param_count: usize,
    result_out: *mut *mut KmbQueryResult,
) -> KmbError {
    unsafe {
        if client.is_null() || sql.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        if param_count > 0 && params.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        // Extract SQL string
        let sql_str = match CStr::from_ptr(sql).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        // Convert parameters
        let mut rust_params = Vec::with_capacity(param_count);
        if param_count > 0 {
            let param_slice = slice::from_raw_parts(params, param_count);
            for param in param_slice {
                match convert_query_param(param) {
                    Ok(p) => rust_params.push(p),
                    Err(e) => return e,
                }
            }
        }

        // Get mutable reference to client
        let wrapper = &mut *(client as *mut ClientWrapper);

        // Execute query
        let response = match wrapper.client.query(sql_str, &rust_params) {
            Ok(r) => r,
            Err(e) => return map_error(e),
        };

        // Convert response to FFI format
        let ffi_result = match convert_query_response(response) {
            Ok(r) => r,
            Err(e) => return e,
        };

        *result_out = Box::into_raw(Box::new(ffi_result));
        KmbError::KmbOk
    }
}

/// Execute a SQL query at a specific log position (point-in-time query).
///
/// # Arguments
/// - `client`: Client handle
/// - `sql`: SQL query string (NULL-terminated UTF-8)
/// - `params`: Array of query parameters (may be NULL if param_count == 0)
/// - `param_count`: Number of parameters
/// - `position`: Log position (offset) to query at
/// - `result_out`: Output parameter for query result
///
/// # Returns
/// - `KMB_OK` on success
/// - Error code on failure
///
/// # Safety
/// - `client` must be valid
/// - `sql` must be valid NULL-terminated UTF-8 string
/// - `params` must be array of `param_count` valid parameters (or NULL if param_count == 0)
/// - `result_out` must be valid pointer
/// - Caller must call `kmb_query_result_free()` to free result
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_client_query_at(
    client: *mut KmbClient,
    sql: *const c_char,
    params: *const KmbQueryParam,
    param_count: usize,
    position: u64,
    result_out: *mut *mut KmbQueryResult,
) -> KmbError {
    unsafe {
        if client.is_null() || sql.is_null() || result_out.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        if param_count > 0 && params.is_null() {
            return KmbError::KmbErrNullPointer;
        }

        // Extract SQL string
        let sql_str = match CStr::from_ptr(sql).to_str() {
            Ok(s) => s,
            Err(_) => return KmbError::KmbErrInvalidUtf8,
        };

        // Convert parameters
        let mut rust_params = Vec::with_capacity(param_count);
        if param_count > 0 {
            let param_slice = slice::from_raw_parts(params, param_count);
            for param in param_slice {
                match convert_query_param(param) {
                    Ok(p) => rust_params.push(p),
                    Err(e) => return e,
                }
            }
        }

        // Get mutable reference to client
        let wrapper = &mut *(client as *mut ClientWrapper);

        // Execute query at position
        let response = match wrapper
            .client
            .query_at(sql_str, &rust_params, Offset::new(position))
        {
            Ok(r) => r,
            Err(e) => return map_error(e),
        };

        // Convert response to FFI format
        let ffi_result = match convert_query_response(response) {
            Ok(r) => r,
            Err(e) => return e,
        };

        *result_out = Box::into_raw(Box::new(ffi_result));
        KmbError::KmbOk
    }
}

/// Free query result.
///
/// # Arguments
/// - `result`: Result from `kmb_client_query()` or `kmb_client_query_at()`
///
/// # Safety
/// - `result` must be a valid result from `kmb_client_query()` or `kmb_client_query_at()`
/// - After this call, `result` is invalid and must not be used
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_query_result_free(result: *mut KmbQueryResult) {
    unsafe {
        if result.is_null() {
            return;
        }

        let r = Box::from_raw(result);

        // Free column names
        if !r.columns.is_null() {
            let column_ptrs = Vec::from_raw_parts(r.columns, r.column_count, r.column_count);
            for ptr in column_ptrs {
                if !ptr.is_null() {
                    let _ = CString::from_raw(ptr);
                }
            }
        }

        // Free rows
        if !r.rows.is_null() {
            let row_ptrs = Vec::from_raw_parts(r.rows, r.row_count, r.row_count);
            let row_lens = if !r.row_lengths.is_null() {
                Vec::from_raw_parts(r.row_lengths, r.row_count, r.row_count)
            } else {
                vec![0; r.row_count]
            };

            for (row_ptr, row_len) in row_ptrs.into_iter().zip(row_lens.iter()) {
                if !row_ptr.is_null() {
                    let row_values = Vec::from_raw_parts(row_ptr, *row_len, *row_len);
                    // Free text values in each cell
                    for value in row_values {
                        if value.value_type == KmbQueryValueType::KmbValueText
                            && !value.text_val.is_null()
                        {
                            let _ = CString::from_raw(value.text_val);
                        }
                    }
                }
            }
        }
    }
}

/// Get human-readable error message for error code.
///
/// # Arguments
/// - `error`: Error code
///
/// # Returns
/// - Static NULL-terminated string (do not free)
///
/// # Safety
/// - Always safe to call
/// - Returned string is valid for lifetime of program
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_error_message(error: KmbError) -> *const c_char {
    let msg = match error {
        KmbError::KmbOk => "Success\0",
        KmbError::KmbErrNullPointer => "NULL pointer argument\0",
        KmbError::KmbErrInvalidUtf8 => "String is not valid UTF-8\0",
        KmbError::KmbErrConnectionFailed => "Failed to connect to server\0",
        KmbError::KmbErrStreamNotFound => "Stream ID does not exist\0",
        KmbError::KmbErrPermissionDenied => "Operation not permitted\0",
        KmbError::KmbErrInvalidDataClass => "Invalid data class value\0",
        KmbError::KmbErrOffsetOutOfRange => "Offset is beyond stream end\0",
        KmbError::KmbErrQuerySyntax => "SQL syntax error\0",
        KmbError::KmbErrQueryExecution => "Query execution error\0",
        KmbError::KmbErrTenantNotFound => "Tenant ID does not exist\0",
        KmbError::KmbErrAuthFailed => "Authentication failed\0",
        KmbError::KmbErrTimeout => "Operation timed out\0",
        KmbError::KmbErrInternal => "Internal server error\0",
        KmbError::KmbErrClusterUnavailable => "No cluster replicas available\0",
        KmbError::KmbErrUnknown => "Unknown error\0",
        KmbError::KmbErrUniqueConstraintViolation => "Duplicate primary key\0",
    };

    msg.as_ptr() as *const c_char
}

/// Check if an error code indicates a retryable failure.
///
/// # Arguments
/// - `error`: Error code
///
/// # Returns
/// - 1 if retryable, 0 otherwise
///
/// # Safety
/// - Always safe to call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_error_is_retryable(error: KmbError) -> c_int {
    match error {
        KmbError::KmbErrTimeout | KmbError::KmbErrClusterUnavailable | KmbError::KmbErrInternal => {
            1
        }
        _ => 0,
    }
}

// ============================================================================
// AUDIT-2026-04 S3.9 — thread-local audit context for FFI callers.
// ============================================================================

/// Set the audit context on the current thread. All subsequent FFI
/// client calls on this thread attach the context to their outgoing
/// wire [`Request.audit`][kimberlite_wire::Request::audit] so the
/// server-side compliance ledger records client attribution.
///
/// Language bindings are expected to call this before each SDK method
/// when an ambient audit context exists in the caller's language-level
/// carrier (Python `contextvars`, TS `AsyncLocalStorage`, Go
/// `context.Context`) and call [`kmb_audit_clear`] after.
///
/// All arguments are optional — passing `NULL` for any pointer leaves
/// that field unset.
///
/// # Safety
/// Each non-NULL pointer must be a valid NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_audit_set(
    actor: *const c_char,
    reason: *const c_char,
    correlation_id: *const c_char,
    idempotency_key: *const c_char,
) -> KmbError {
    unsafe fn read_opt(ptr: *const c_char) -> Result<Option<String>, KmbError> {
        if ptr.is_null() {
            return Ok(None);
        }
        unsafe {
            match CStr::from_ptr(ptr).to_str() {
                Ok("") => Ok(None),
                Ok(s) => Ok(Some(s.to_string())),
                Err(_) => Err(KmbError::KmbErrInvalidUtf8),
            }
        }
    }

    unsafe {
        let actor = match read_opt(actor) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let reason = match read_opt(reason) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let correlation = match read_opt(correlation_id) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let idempotency = match read_opt(idempotency_key) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut ctx = AuditContext::new(actor.unwrap_or_default(), reason.unwrap_or_default());
        if let Some(id) = idempotency {
            ctx = ctx.with_request_id(id);
        }
        if let Some(id) = correlation {
            ctx = ctx.with_correlation_id(id);
        }
        set_thread_audit(ctx);
        KmbError::KmbOk
    }
}

/// Clear the FFI audit context on the current thread. Called by the
/// language binding after an SDK method returns, so subsequent calls
/// don't pick up stale attribution.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kmb_audit_clear() -> KmbError {
    clear_thread_audit();
    KmbError::KmbOk
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_error_messages() {
        unsafe {
            let msg = kmb_error_message(KmbError::KmbOk);
            assert!(!msg.is_null());

            let msg = kmb_error_message(KmbError::KmbErrNullPointer);
            assert!(!msg.is_null());
        }
    }

    #[test]
    fn test_error_retryable() {
        unsafe {
            assert_eq!(kmb_error_is_retryable(KmbError::KmbOk), 0);
            assert_eq!(kmb_error_is_retryable(KmbError::KmbErrTimeout), 1);
            assert_eq!(
                kmb_error_is_retryable(KmbError::KmbErrClusterUnavailable),
                1
            );
            assert_eq!(kmb_error_is_retryable(KmbError::KmbErrNullPointer), 0);
        }
    }

    #[test]
    fn test_convert_query_param_null() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamNull,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Null));
        }
    }

    #[test]
    fn test_convert_query_param_bigint() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBigInt,
                bigint_val: 42,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::BigInt(42)));
        }
    }

    #[test]
    fn test_convert_query_param_text() {
        unsafe {
            let text = CString::new("hello").unwrap();
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamText,
                bigint_val: 0,
                text_val: text.as_ptr(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            if let QueryParam::Text(s) = result {
                assert_eq!(s, "hello");
            } else {
                panic!("expected text param");
            }
        }
    }

    #[test]
    fn test_convert_query_param_boolean() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBoolean,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 1,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Boolean(true)));
        }
    }

    #[test]
    fn test_convert_query_param_timestamp() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamTimestamp,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 1234567890,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Timestamp(1234567890)));
        }
    }

    #[test]
    fn test_convert_query_value_null() {
        unsafe {
            let value = QueryValue::Null;
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueNull);
        }
    }

    #[test]
    fn test_convert_query_value_bigint() {
        unsafe {
            let value = QueryValue::BigInt(42);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueBigInt);
            assert_eq!(result.bigint_val, 42);
        }
    }

    #[test]
    fn test_convert_query_value_text() {
        unsafe {
            let value = QueryValue::Text("world".to_string());
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueText);
            assert!(!result.text_val.is_null());
            let text = CStr::from_ptr(result.text_val).to_str().unwrap();
            assert_eq!(text, "world");
            // Clean up
            let _ = CString::from_raw(result.text_val);
        }
    }

    #[test]
    fn test_convert_query_value_boolean() {
        unsafe {
            let value = QueryValue::Boolean(true);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueBoolean);
            assert_eq!(result.bool_val, 1);
        }
    }

    #[test]
    fn test_convert_query_value_timestamp() {
        unsafe {
            let value = QueryValue::Timestamp(9876543210);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueTimestamp);
            assert_eq!(result.timestamp_val, 9876543210);
        }
    }

    // ========================================================================
    // NULL Pointer Validation Tests
    // ========================================================================

    #[test]
    fn test_connect_null_config() {
        unsafe {
            let mut client_out: *mut KmbClient = std::ptr::null_mut();
            let result = kmb_client_connect(std::ptr::null(), &mut client_out);
            assert_eq!(result, KmbError::KmbErrNullPointer);
        }
    }

    #[test]
    fn test_connect_null_client_out() {
        unsafe {
            let addr = CString::new("localhost:5000").unwrap();
            let addr_ptr = addr.as_ptr();
            let client_name = CString::new("test").unwrap();
            let client_version = CString::new("0.1.0").unwrap();
            let config = KmbClientConfig {
                addresses: &addr_ptr,
                address_count: 1,
                tenant_id: 1,
                auth_token: std::ptr::null(),
                client_name: client_name.as_ptr(),
                client_version: client_version.as_ptr(),
            };

            let result = kmb_client_connect(&config, std::ptr::null_mut());
            assert_eq!(result, KmbError::KmbErrNullPointer);
        }
    }

    #[test]
    fn test_connect_null_addresses() {
        unsafe {
            let mut client_out: *mut KmbClient = std::ptr::null_mut();
            let client_name = CString::new("test").unwrap();
            let client_version = CString::new("0.1.0").unwrap();
            let config = KmbClientConfig {
                addresses: std::ptr::null(),
                address_count: 1,
                tenant_id: 1,
                auth_token: std::ptr::null(),
                client_name: client_name.as_ptr(),
                client_version: client_version.as_ptr(),
            };

            let result = kmb_client_connect(&config, &mut client_out);
            assert_eq!(result, KmbError::KmbErrNullPointer);
        }
    }

    #[test]
    fn test_connect_zero_address_count() {
        unsafe {
            let mut client_out: *mut KmbClient = std::ptr::null_mut();
            let addr = CString::new("localhost:5000").unwrap();
            let addr_ptr = addr.as_ptr();
            let client_name = CString::new("test").unwrap();
            let client_version = CString::new("0.1.0").unwrap();
            let config = KmbClientConfig {
                addresses: &addr_ptr,
                address_count: 0,
                tenant_id: 1,
                auth_token: std::ptr::null(),
                client_name: client_name.as_ptr(),
                client_version: client_version.as_ptr(),
            };

            let result = kmb_client_connect(&config, &mut client_out);
            assert_eq!(result, KmbError::KmbErrNullPointer);
        }
    }

    #[test]
    fn test_disconnect_null_client() {
        unsafe {
            // Should not crash
            kmb_client_disconnect(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_read_result_free_null() {
        unsafe {
            // Should not crash
            kmb_read_result_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_query_result_free_null() {
        unsafe {
            // Should not crash
            kmb_query_result_free(std::ptr::null_mut());
        }
    }

    // ========================================================================
    // UTF-8 Validation Tests
    // ========================================================================

    #[test]
    fn test_connect_invalid_utf8_address() {
        unsafe {
            let mut client_out: *mut KmbClient = std::ptr::null_mut();

            // Create invalid UTF-8 sequence
            let invalid_bytes = [0xC3, 0x28, 0x00]; // Invalid UTF-8
            let addr_ptr = invalid_bytes.as_ptr() as *const c_char;
            let client_name = CString::new("test").unwrap();
            let client_version = CString::new("0.1.0").unwrap();

            let config = KmbClientConfig {
                addresses: &addr_ptr,
                address_count: 1,
                tenant_id: 1,
                auth_token: std::ptr::null(),
                client_name: client_name.as_ptr(),
                client_version: client_version.as_ptr(),
            };

            let result = kmb_client_connect(&config, &mut client_out);
            assert_eq!(result, KmbError::KmbErrInvalidUtf8);
        }
    }

    #[test]
    fn test_convert_query_param_text_null_pointer() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamText,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param);
            assert!(matches!(result, Err(KmbError::KmbErrNullPointer)));
        }
    }

    #[test]
    fn test_convert_query_param_text_invalid_utf8() {
        unsafe {
            // Create invalid UTF-8 sequence
            let invalid_bytes = [0xFF, 0xFE, 0xFD, 0x00];
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamText,
                bigint_val: 0,
                text_val: invalid_bytes.as_ptr() as *const c_char,
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param);
            assert!(matches!(result, Err(KmbError::KmbErrInvalidUtf8)));
        }
    }

    // ========================================================================
    // Data Class Conversion Tests
    // ========================================================================

    use test_case::test_case;

    #[test_case(KmbDataClass::KmbDataClassPhi, DataClass::PHI; "PHI")]
    #[test_case(KmbDataClass::KmbDataClassNonPhi, DataClass::Public; "NonPHI")]
    #[test_case(KmbDataClass::KmbDataClassDeidentified, DataClass::Deidentified; "Deidentified")]
    fn test_data_class_conversion(ffi_class: KmbDataClass, expected: DataClass) {
        let result = map_data_class(ffi_class).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================================================
    // Error Code Mapping Tests
    // ========================================================================

    #[test]
    fn test_map_error_connection() {
        let io_err =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection failed");
        let err = ClientError::Connection(io_err);
        assert_eq!(map_error(err), KmbError::KmbErrConnectionFailed);
    }

    #[test]
    fn test_map_error_handshake() {
        let err = ClientError::HandshakeFailed("handshake failed".to_string());
        assert_eq!(map_error(err), KmbError::KmbErrAuthFailed);
    }

    #[test]
    fn test_map_error_timeout() {
        let err = ClientError::Timeout;
        assert_eq!(map_error(err), KmbError::KmbErrTimeout);
    }

    #[test]
    fn test_map_error_not_connected() {
        let err = ClientError::NotConnected;
        assert_eq!(map_error(err), KmbError::KmbErrConnectionFailed);
    }

    // ========================================================================
    // Error Message Tests
    // ========================================================================

    #[test_case(KmbError::KmbOk, "Success"; "ok")]
    #[test_case(KmbError::KmbErrNullPointer, "NULL"; "null pointer")]
    #[test_case(KmbError::KmbErrInvalidUtf8, "UTF"; "invalid utf8")]
    #[test_case(KmbError::KmbErrConnectionFailed, "Failed to connect"; "connection failed")]
    #[test_case(KmbError::KmbErrStreamNotFound, "Stream"; "stream not found")]
    #[test_case(KmbError::KmbErrTimeout, "timed out"; "timeout")]
    fn test_error_message_contains_expected(error: KmbError, expected_substring: &str) {
        unsafe {
            let msg_ptr = kmb_error_message(error);
            assert!(!msg_ptr.is_null(), "Error message should not be null");

            let msg = CStr::from_ptr(msg_ptr).to_str().unwrap();
            assert!(
                msg.contains(expected_substring),
                "Expected '{msg}' to contain '{expected_substring}'"
            );
        }
    }

    #[test]
    fn test_all_error_messages_valid_utf8() {
        unsafe {
            let errors = [
                KmbError::KmbOk,
                KmbError::KmbErrNullPointer,
                KmbError::KmbErrInvalidUtf8,
                KmbError::KmbErrConnectionFailed,
                KmbError::KmbErrStreamNotFound,
                KmbError::KmbErrPermissionDenied,
                KmbError::KmbErrInvalidDataClass,
                KmbError::KmbErrOffsetOutOfRange,
                KmbError::KmbErrQuerySyntax,
                KmbError::KmbErrQueryExecution,
                KmbError::KmbErrTenantNotFound,
                KmbError::KmbErrAuthFailed,
                KmbError::KmbErrTimeout,
                KmbError::KmbErrInternal,
                KmbError::KmbErrClusterUnavailable,
                KmbError::KmbErrUnknown,
            ];

            for error in errors {
                let msg_ptr = kmb_error_message(error);
                assert!(
                    !msg_ptr.is_null(),
                    "Error message for {error:?} should not be null"
                );

                let result = CStr::from_ptr(msg_ptr).to_str();
                assert!(
                    result.is_ok(),
                    "Error message for {error:?} should be valid UTF-8"
                );
            }
        }
    }

    // ========================================================================
    // Retryable Error Tests
    // ========================================================================

    #[test_case(KmbError::KmbOk, 0; "ok not retryable")]
    #[test_case(KmbError::KmbErrTimeout, 1; "timeout retryable")]
    #[test_case(KmbError::KmbErrClusterUnavailable, 1; "cluster unavailable retryable")]
    #[test_case(KmbError::KmbErrNullPointer, 0; "null pointer not retryable")]
    #[test_case(KmbError::KmbErrInvalidUtf8, 0; "invalid utf8 not retryable")]
    #[test_case(KmbError::KmbErrPermissionDenied, 0; "permission denied not retryable")]
    #[test_case(KmbError::KmbErrQuerySyntax, 0; "query syntax not retryable")]
    fn test_error_retryable_classification(error: KmbError, expected: c_int) {
        unsafe {
            assert_eq!(kmb_error_is_retryable(error), expected);
        }
    }

    // ========================================================================
    // Query Parameter Conversion Edge Cases
    // ========================================================================

    #[test]
    fn test_convert_query_param_boolean_false() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBoolean,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Boolean(false)));
        }
    }

    #[test]
    fn test_convert_query_param_boolean_nonzero() {
        unsafe {
            // Any non-zero value should be true
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBoolean,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 42,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Boolean(true)));
        }
    }

    #[test]
    fn test_convert_query_param_text_empty_string() {
        unsafe {
            let text = CString::new("").unwrap();
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamText,
                bigint_val: 0,
                text_val: text.as_ptr(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            if let QueryParam::Text(s) = result {
                assert_eq!(s, "");
            } else {
                panic!("expected text param");
            }
        }
    }

    #[test]
    fn test_convert_query_param_text_unicode() {
        unsafe {
            let text = CString::new("Hello 世界 🌍").unwrap();
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamText,
                bigint_val: 0,
                text_val: text.as_ptr(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            if let QueryParam::Text(s) = result {
                assert_eq!(s, "Hello 世界 🌍");
            } else {
                panic!("expected text param");
            }
        }
    }

    #[test]
    fn test_convert_query_param_bigint_negative() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBigInt,
                bigint_val: -9223372036854775808, // i64::MIN
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::BigInt(-9223372036854775808)));
        }
    }

    #[test]
    fn test_convert_query_param_bigint_max() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamBigInt,
                bigint_val: 9223372036854775807, // i64::MAX
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::BigInt(9223372036854775807)));
        }
    }

    #[test]
    fn test_convert_query_param_timestamp_zero() {
        unsafe {
            let param = KmbQueryParam {
                param_type: KmbQueryParamType::KmbParamTimestamp,
                bigint_val: 0,
                text_val: std::ptr::null(),
                bool_val: 0,
                timestamp_val: 0,
            };
            let result = convert_query_param(&param).unwrap();
            assert!(matches!(result, QueryParam::Timestamp(0)));
        }
    }

    // ========================================================================
    // Query Value Conversion Edge Cases
    // ========================================================================

    #[test]
    fn test_convert_query_value_boolean_false() {
        unsafe {
            let value = QueryValue::Boolean(false);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueBoolean);
            assert_eq!(result.bool_val, 0);
        }
    }

    #[test]
    fn test_convert_query_value_text_empty() {
        unsafe {
            let value = QueryValue::Text(String::new());
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueText);
            assert!(!result.text_val.is_null());
            let text = CStr::from_ptr(result.text_val).to_str().unwrap();
            assert_eq!(text, "");
            // Clean up
            let _ = CString::from_raw(result.text_val);
        }
    }

    #[test]
    fn test_convert_query_value_text_unicode() {
        unsafe {
            let value = QueryValue::Text("Hello 世界 🌍".to_string());
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueText);
            assert!(!result.text_val.is_null());
            let text = CStr::from_ptr(result.text_val).to_str().unwrap();
            assert_eq!(text, "Hello 世界 🌍");
            // Clean up
            let _ = CString::from_raw(result.text_val);
        }
    }

    #[test]
    fn test_convert_query_value_bigint_negative() {
        unsafe {
            let value = QueryValue::BigInt(-1000);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueBigInt);
            assert_eq!(result.bigint_val, -1000);
        }
    }

    #[test]
    fn test_convert_query_value_timestamp_negative() {
        unsafe {
            let value = QueryValue::Timestamp(-1000);
            let result = convert_query_value(value).unwrap();
            assert_eq!(result.value_type, KmbQueryValueType::KmbValueTimestamp);
            assert_eq!(result.timestamp_val, -1000);
        }
    }

    // ========================================================================
    // Memory Safety Tests
    // ========================================================================

    #[test]
    fn test_query_value_text_no_double_free() {
        unsafe {
            let value = QueryValue::Text("test".to_string());
            let result = convert_query_value(value).unwrap();

            // Take ownership and free
            let _ = CString::from_raw(result.text_val);

            // Should not double-free (test passes if no crash)
        }
    }

    #[test]
    fn test_multiple_query_values_independent() {
        unsafe {
            let value1 = QueryValue::Text("first".to_string());
            let value2 = QueryValue::Text("second".to_string());

            let result1 = convert_query_value(value1).unwrap();
            let result2 = convert_query_value(value2).unwrap();

            // Verify they're independent
            let text1 = CStr::from_ptr(result1.text_val).to_str().unwrap();
            let text2 = CStr::from_ptr(result2.text_val).to_str().unwrap();
            assert_eq!(text1, "first");
            assert_eq!(text2, "second");

            // Clean up
            let _ = CString::from_raw(result1.text_val);
            let _ = CString::from_raw(result2.text_val);
        }
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    use proptest::prelude::*;

    proptest! {
        /// Property: Any valid UTF-8 string can be converted to query param and back
        #[test]
        fn prop_query_param_text_roundtrip(text in "\\PC{0,100}") {
            unsafe {
                let c_string = CString::new(text.clone()).unwrap();
                let param = KmbQueryParam {
                    param_type: KmbQueryParamType::KmbParamText,
                    bigint_val: 0,
                    text_val: c_string.as_ptr(),
                    bool_val: 0,
                    timestamp_val: 0,
                };

                let result = convert_query_param(&param).unwrap();
                if let QueryParam::Text(s) = result {
                    prop_assert_eq!(s, text);
                } else {
                    prop_assert!(false, "expected text param");
                }
            }
        }

        /// Property: Any i64 can be converted to BigInt param
        #[test]
        fn prop_query_param_bigint(value in any::<i64>()) {
            unsafe {
                let param = KmbQueryParam {
                    param_type: KmbQueryParamType::KmbParamBigInt,
                    bigint_val: value,
                    text_val: std::ptr::null(),
                    bool_val: 0,
                    timestamp_val: 0,
                };

                let result = convert_query_param(&param).unwrap();
                prop_assert!(matches!(result, QueryParam::BigInt(v) if v == value));
            }
        }

        /// Property: Any boolean can be converted
        #[test]
        fn prop_query_param_boolean(value in any::<bool>()) {
            unsafe {
                let param = KmbQueryParam {
                    param_type: KmbQueryParamType::KmbParamBoolean,
                    bigint_val: 0,
                    text_val: std::ptr::null(),
                    bool_val: if value { 1 } else { 0 },
                    timestamp_val: 0,
                };

                let result = convert_query_param(&param).unwrap();
                prop_assert!(matches!(result, QueryParam::Boolean(b) if b == value));
            }
        }

        /// Property: Any i64 timestamp can be converted
        #[test]
        fn prop_query_param_timestamp(value in any::<i64>()) {
            unsafe {
                let param = KmbQueryParam {
                    param_type: KmbQueryParamType::KmbParamTimestamp,
                    bigint_val: 0,
                    text_val: std::ptr::null(),
                    bool_val: 0,
                    timestamp_val: value,
                };

                let result = convert_query_param(&param).unwrap();
                prop_assert!(matches!(result, QueryParam::Timestamp(v) if v == value));
            }
        }

        /// Property: Query value BigInt preserves value
        #[test]
        fn prop_query_value_bigint(value in any::<i64>()) {
            unsafe {
                let qvalue = QueryValue::BigInt(value);
                let result = convert_query_value(qvalue).unwrap();

                prop_assert_eq!(result.value_type, KmbQueryValueType::KmbValueBigInt);
                prop_assert_eq!(result.bigint_val, value);
            }
        }

        /// Property: Query value Boolean preserves value
        #[test]
        fn prop_query_value_boolean(value in any::<bool>()) {
            unsafe {
                let qvalue = QueryValue::Boolean(value);
                let result = convert_query_value(qvalue).unwrap();

                prop_assert_eq!(result.value_type, KmbQueryValueType::KmbValueBoolean);
                prop_assert_eq!(result.bool_val, if value { 1 } else { 0 });
            }
        }

        /// Property: Query value Timestamp preserves value
        #[test]
        fn prop_query_value_timestamp(value in any::<i64>()) {
            unsafe {
                let qvalue = QueryValue::Timestamp(value);
                let result = convert_query_value(qvalue).unwrap();

                prop_assert_eq!(result.value_type, KmbQueryValueType::KmbValueTimestamp);
                prop_assert_eq!(result.timestamp_val, value);
            }
        }
    }
}
