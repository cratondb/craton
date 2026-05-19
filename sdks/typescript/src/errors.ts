/**
 * Error types for the Kimberlite TypeScript SDK.
 *
 * The native addon tags every client error with a `[KMB_ERR_<code>]` prefix
 * (see `crates/kimberlite-node/src/lib.rs::client_error_to_napi`). We parse
 * that prefix to dispatch to a specific subclass and expose the wire
 * `code` field for callers that want to `switch` on it without depending on
 * `instanceof`.
 */

/** Wire error-code tags emitted by the native addon. */
export type ErrorCode =
  | 'Unknown'
  | 'InternalError'
  | 'InvalidRequest'
  | 'AuthenticationFailed'
  | 'TenantNotFound'
  | 'StreamNotFound'
  | 'TableNotFound'
  | 'QueryParseError'
  | 'QueryExecutionError'
  | 'PositionAhead'
  | 'StreamAlreadyExists'
  | 'InvalidOffset'
  | 'StorageError'
  | 'ProjectionLag'
  | 'RateLimited'
  | 'NotLeader'
  | 'OffsetMismatch'
  | 'SubscriptionNotFound'
  | 'SubscriptionClosed'
  | 'SubscriptionBackpressure'
  | 'ApiKeyNotFound'
  | 'TenantAlreadyExists'
  | 'UniqueConstraintViolation'
  | 'TenantIdTooLarge'
  | 'RowVersionChainTooLarge'
  // Client-side synthetic codes (no wire counterpart):
  | 'Connection'
  | 'Timeout'
  | 'NotConnected'
  | 'HandshakeFailed'
  | 'Wire'
  | 'ResponseMismatch'
  | 'UnexpectedResponse';

const RETRYABLE_CODES = new Set<ErrorCode>([
  'Connection',
  'Timeout',
  'RateLimited',
  'NotLeader',
  'ProjectionLag',
]);

export class KimberliteError extends Error {
  /** Wire error-code tag extracted from the native error prefix. */
  readonly code: ErrorCode;

  constructor(message: string, code: ErrorCode = 'Unknown') {
    super(message);
    this.name = 'KimberliteError';
    this.code = code;
    Object.setPrototypeOf(this, KimberliteError.prototype);
  }

  /** True if the error is likely to succeed on retry (transient failure). */
  isRetryable(): boolean {
    return RETRYABLE_CODES.has(this.code);
  }
}

export class ConnectionError extends KimberliteError {
  constructor(message: string, code: ErrorCode = 'Connection') {
    super(message, code);
    this.name = 'ConnectionError';
    Object.setPrototypeOf(this, ConnectionError.prototype);
  }
}

/**
 * The framing buffer received a response larger than `2 * bufferSizeBytes`.
 *
 * Three remediations, in order of preference:
 * 1. Use `client.readAll(streamId)` for full-stream replays — it pages
 *    internally and never trips this limit.
 * 2. Lower `read({ maxBytes })` to fit in the buffer.
 * 3. Raise `bufferSizeBytes` at connect time (`Client.connect({ ..., bufferSizeBytes })`).
 *
 * The connection that hit this error has been drained of its framing
 * buffer; depending on autoReconnect behaviour, the next request may
 * succeed on a fresh socket. Subclass of `ConnectionError` so existing
 * `instanceof ConnectionError` retry policies still match.
 */
export class ResponseTooLargeError extends ConnectionError {
  constructor(message: string) {
    super(message, 'Connection');
    this.name = 'ResponseTooLargeError';
    Object.setPrototypeOf(this, ResponseTooLargeError.prototype);
  }
}

export class StreamNotFoundError extends KimberliteError {
  constructor(message: string) {
    super(message, 'StreamNotFound');
    this.name = 'StreamNotFoundError';
    Object.setPrototypeOf(this, StreamNotFoundError.prototype);
  }
}

export class PermissionDeniedError extends KimberliteError {
  constructor(message: string, code: ErrorCode = 'AuthenticationFailed') {
    super(message, code);
    this.name = 'PermissionDeniedError';
    Object.setPrototypeOf(this, PermissionDeniedError.prototype);
  }
}

export class AuthenticationError extends KimberliteError {
  constructor(message: string, code: ErrorCode = 'AuthenticationFailed') {
    super(message, code);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class TimeoutError extends KimberliteError {
  constructor(message: string) {
    super(message, 'Timeout');
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

export class InternalError extends KimberliteError {
  constructor(message: string, code: ErrorCode = 'InternalError') {
    super(message, code);
    this.name = 'InternalError';
    Object.setPrototypeOf(this, InternalError.prototype);
  }
}

export class ClusterUnavailableError extends KimberliteError {
  constructor(message: string) {
    super(message, 'InternalError');
    this.name = 'ClusterUnavailableError';
    Object.setPrototypeOf(this, ClusterUnavailableError.prototype);
  }
}

/**
 * Optimistic-concurrency conflict on append — the expected offset did not
 * match the stream's current offset. Re-read the offset and retry.
 */
export class OffsetMismatchError extends KimberliteError {
  constructor(message: string) {
    super(message, 'OffsetMismatch');
    this.name = 'OffsetMismatchError';
    Object.setPrototypeOf(this, OffsetMismatchError.prototype);
  }
}

/** The server rejected the request because rate limits were exceeded. */
export class RateLimitedError extends KimberliteError {
  constructor(message: string) {
    super(message, 'RateLimited');
    this.name = 'RateLimitedError';
    Object.setPrototypeOf(this, RateLimitedError.prototype);
  }
}

/**
 * The request was sent to a follower replica. The error message may include
 * a leader hint (see the `NotLeader` error mapping in the server).
 */
export class NotLeaderError extends KimberliteError {
  constructor(message: string) {
    super(message, 'NotLeader');
    this.name = 'NotLeaderError';
    Object.setPrototypeOf(this, NotLeaderError.prototype);
  }
}

/**
 * INSERT failed because the row's primary key already exists.
 *
 * Carries the wire-side error message (which includes the table name and
 * the rejected key tuple) so callers can replace try-INSERT-then-SELECT
 * recovery loops with a single typed catch.
 */
export class UniqueConstraintViolationError extends KimberliteError {
  constructor(message: string) {
    super(message, 'UniqueConstraintViolation');
    this.name = 'UniqueConstraintViolationError';
    Object.setPrototypeOf(this, UniqueConstraintViolationError.prototype);
  }
}

/**
 * The connection's tenant id exceeds the StreamId encoding ceiling
 * (`u32::MAX`).
 *
 * `StreamId` is a bit-packed `u64` with the tenant id in the upper 32
 * bits — values above that range silently truncate and corrupt
 * per-tenant filtering. v0.9.1 added an explicit reject at the server
 * boundary so callers see this typed error instead of a downstream
 * `StreamAlreadyExists`.
 *
 * Surfaced by notebar on macOS PIDs > 2^15 (where the
 * `pid << 16 + counter` tenant-id scheme overflowed u32). Fix on the
 * caller side: keep tenant ids ≤ `u32::MAX` (≈ 4.29 × 10⁹).
 */
export class TenantIdTooLargeError extends KimberliteError {
  constructor(message: string) {
    super(message, 'TenantIdTooLarge');
    this.name = 'TenantIdTooLargeError';
    Object.setPrototypeOf(this, TenantIdTooLargeError.prototype);
  }
}

/**
 * A single row's MVCC version chain has grown beyond the page byte
 * budget, so the B+tree cannot store further versions of this key.
 *
 * Every overwrite of a primary key appends a version to that key's
 * MVCC chain. A hot row updated dozens of times can outgrow the page
 * (4 KiB). Splitting can't help — both halves of a single-entry
 * "split" still contain the same fat entry. v0.9.1 added this typed
 * error to surface the offending key + size; v0.9.0 returned a
 * generic `StorageError` ("page overflow: need N bytes, have M").
 *
 * Mitigation paths until v0.10.0 ships retention-horizon compaction:
 *  - **Rate-limit writes** on the hot key (combine many small
 *    upserts into one).
 *  - **Rotate keys** (e.g. `patient_current_v{N}` where N flips
 *    every K writes) so version chains stay bounded per key.
 *  - **Use the event stream** as the source of truth and rebuild
 *    projections from a checkpoint when chains get large.
 */
export class RowVersionChainTooLargeError extends KimberliteError {
  constructor(message: string) {
    super(message, 'RowVersionChainTooLarge');
    this.name = 'RowVersionChainTooLargeError';
    Object.setPrototypeOf(this, RowVersionChainTooLargeError.prototype);
  }
}

/**
 * A generic server-side error that doesn't map to a more specific subclass.
 * The `code` property exposes the wire error-code tag for inspection.
 */
export class ServerError extends KimberliteError {
  constructor(message: string, code: ErrorCode) {
    super(message, code);
    this.name = 'ServerError';
    Object.setPrototypeOf(this, ServerError.prototype);
  }
}

const ERROR_PREFIX_RE = /^\[KMB_ERR_([A-Za-z]+)\]\s*(.*)$/s;

/**
 * Wrap an error thrown by the native addon in the appropriate subclass.
 *
 * If `err` is already a KimberliteError, returns it unchanged. Otherwise
 * parses the `[KMB_ERR_<code>]` prefix emitted by the native layer and
 * dispatches to a typed subclass.
 */
export function wrapNativeError(err: unknown): KimberliteError {
  if (err instanceof KimberliteError) return err;
  const raw = err instanceof Error ? err.message : String(err);
  const match = raw.match(ERROR_PREFIX_RE);

  if (match) {
    const [, codeTag, inner] = match;
    return constructTypedError(codeTag as ErrorCode, inner);
  }

  // Fallback: legacy string-matching for native builds that pre-date the
  // KMB_ERR_ prefix. Covers the same heuristics as the 0.4.x wrapper.
  return legacyWrap(raw);
}

function constructTypedError(code: ErrorCode, message: string): KimberliteError {
  switch (code) {
    case 'Connection':
    case 'NotConnected':
      // v0.6.2 — the framing-limit error carries a distinctive prefix.
      // Surface it as a typed subclass so callers can branch on
      // `instanceof ResponseTooLargeError` without parsing strings.
      if (code === 'Connection' && message.startsWith('response too large:')) {
        return new ResponseTooLargeError(message);
      }
      return new ConnectionError(message, code);
    case 'Timeout':
      return new TimeoutError(message);
    case 'HandshakeFailed':
    case 'AuthenticationFailed':
      return new AuthenticationError(message, code);
    case 'StreamNotFound':
      return new StreamNotFoundError(message);
    case 'OffsetMismatch':
      return new OffsetMismatchError(message);
    case 'RateLimited':
      return new RateLimitedError(message);
    case 'NotLeader':
      return new NotLeaderError(message);
    case 'UniqueConstraintViolation':
      return new UniqueConstraintViolationError(message);
    case 'TenantIdTooLarge':
      return new TenantIdTooLargeError(message);
    case 'RowVersionChainTooLarge':
      return new RowVersionChainTooLargeError(message);
    case 'TenantNotFound':
    case 'TableNotFound':
    case 'StreamAlreadyExists':
    case 'InvalidOffset':
    case 'PositionAhead':
    case 'QueryParseError':
    case 'QueryExecutionError':
    case 'StorageError':
    case 'ProjectionLag':
    case 'InvalidRequest':
    case 'Wire':
    case 'ResponseMismatch':
    case 'UnexpectedResponse':
    case 'SubscriptionNotFound':
    case 'SubscriptionClosed':
    case 'SubscriptionBackpressure':
    case 'ApiKeyNotFound':
    case 'TenantAlreadyExists':
      return new ServerError(message, code);
    case 'InternalError':
    case 'Unknown':
    default:
      return new InternalError(message, code);
  }
}

function legacyWrap(msg: string): KimberliteError {
  if (msg.includes('connection timeout') || msg.includes('timed out')) {
    return new TimeoutError(msg);
  }
  if (msg.includes('handshake failed')) {
    return new AuthenticationError(msg);
  }
  if (msg.includes('response too large')) {
    return new ResponseTooLargeError(msg);
  }
  if (msg.includes('connection error') || msg.includes('not connected')) {
    return new ConnectionError(msg);
  }
  if (msg.includes('server error')) {
    if (msg.includes('StreamNotFound') || msg.includes('stream not found')) {
      return new StreamNotFoundError(msg);
    }
    if (msg.includes('PermissionDenied') || msg.includes('permission')) {
      return new PermissionDeniedError(msg);
    }
    if (msg.includes('AuthFailed') || msg.includes('Unauthorized')) {
      return new AuthenticationError(msg);
    }
    if (msg.includes('ClusterUnavailable') || msg.includes('cluster unavailable')) {
      return new ClusterUnavailableError(msg);
    }
    return new InternalError(msg);
  }
  if (msg.includes('wire protocol error') || msg.includes('response ID')) {
    return new InternalError(msg);
  }
  return new KimberliteError(msg);
}
