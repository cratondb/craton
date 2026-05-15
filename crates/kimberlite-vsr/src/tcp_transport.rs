//! TCP transport implementation for VSR multi-node clusters.
//!
//! This module provides a non-blocking TCP transport using mio for network I/O.
//! It handles:
//!
//! - Connection management (connect, reconnect, disconnect)
//! - Message sending and receiving with framing
//! - Connection pooling with automatic reconnection
//!
//! # Design
//!
//! - Uses mio for non-blocking I/O (not tokio, per project guidelines)
//! - Connections are lazy: established on first send
//! - Automatic reconnection on connection failures
//! - Fire-and-forget semantics (VSR handles retransmission)

use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};
use tracing::{debug, trace, warn};

use crate::framing::{FrameDecoder, FrameEncoder};
use crate::message::{Message, MessagePayload};
use crate::transport::Transport;
use crate::types::ReplicaId;

// ============================================================================
// Constants
// ============================================================================

/// Token for the listener socket.
const LISTENER_TOKEN: Token = Token(0);

/// Base token for peer connections (peer ID added to this).
const PEER_TOKEN_BASE: usize = 1000;

/// Default read buffer size.
const READ_BUFFER_SIZE: usize = 8 * 1024; // 8KB - reasonable for socket reads

/// Maximum number of events to process per poll iteration.
const MAX_EVENTS: usize = 128;

// ============================================================================
// Peer Address Configuration
// ============================================================================

/// Network addresses for all replicas in the cluster.
#[derive(Debug, Clone)]
pub struct ClusterAddresses {
    /// Map from replica ID to its network address.
    addresses: HashMap<ReplicaId, SocketAddr>,
}

impl ClusterAddresses {
    /// Creates a new cluster address configuration.
    pub fn new(addresses: HashMap<ReplicaId, SocketAddr>) -> Self {
        debug_assert!(
            !addresses.is_empty(),
            "cluster must have at least one member"
        );
        Self { addresses }
    }

    /// Creates from a list of (`ReplicaId`, `SocketAddr`) pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (ReplicaId, SocketAddr)>) -> Self {
        Self::new(pairs.into_iter().collect())
    }

    /// Returns the address for a replica.
    pub fn get(&self, id: ReplicaId) -> Option<SocketAddr> {
        self.addresses.get(&id).copied()
    }

    /// Returns an iterator over all replica IDs.
    pub fn replicas(&self) -> impl Iterator<Item = ReplicaId> + '_ {
        self.addresses.keys().copied()
    }

    /// Returns the number of replicas in the cluster.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns true if there are no addresses.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Computes a 64-bit BLAKE3-derived hash of the cluster membership.
    ///
    /// Membership is sorted by `ReplicaId` before hashing to make the
    /// result independent of `HashMap` iteration order. Used as the
    /// `cluster_hash` field of [`crate::message::Hello`] so a misrouted
    /// connection (different cluster, dev/prod mix-up, scrambled config)
    /// is rejected at handshake time before it can settle and pollute
    /// VSR state.
    ///
    /// Two replicas with identical `ClusterAddresses` produce the same
    /// hash; any difference in membership (added/removed replica,
    /// changed address, changed port) yields a different hash.
    pub fn membership_hash(&self) -> u64 {
        let mut entries: Vec<_> = self
            .addresses
            .iter()
            .map(|(id, addr)| (id.as_u8(), *addr))
            .collect();
        entries.sort_by_key(|(id, _)| *id);

        // Build a canonical byte buffer: [id][addr-string][\0] per entry.
        // Use the crypto crate's BLAKE3 wrapper rather than depending on
        // the raw `blake3` crate directly — keeps the cryptographic
        // dependency centralised.
        let mut buf = Vec::with_capacity(entries.len() * 32);
        for (id, addr) in entries {
            buf.push(id);
            buf.extend_from_slice(addr.to_string().as_bytes());
            buf.push(0);
        }
        let digest = kimberlite_crypto::hash::internal_hash(&buf);
        let bytes = digest.as_bytes();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

// ============================================================================
// Peer Connection State
// ============================================================================

/// State of a connection to a peer replica.
#[derive(Debug)]
enum PeerState {
    /// Not connected, will attempt connection on next send.
    Disconnected,
    /// Connection in progress.
    Connecting(TcpStream),
    /// Connected and ready for I/O.
    Connected {
        stream: TcpStream,
        encoder: FrameEncoder,
        decoder: FrameDecoder,
        write_buffer: Vec<u8>,
    },
}

/// A connection to a peer replica.
#[derive(Debug)]
struct PeerConnection {
    /// The peer's replica ID.
    id: ReplicaId,
    /// The peer's network address.
    addr: SocketAddr,
    /// Current connection state.
    state: PeerState,
}

impl PeerConnection {
    /// Creates a new peer connection (starts disconnected).
    fn new(id: ReplicaId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            state: PeerState::Disconnected,
        }
    }

    /// Returns the mio Token for this peer.
    fn token(&self) -> Token {
        Token(PEER_TOKEN_BASE + self.id.as_u8() as usize)
    }

    /// Returns true if connected and ready for I/O.
    fn is_connected(&self) -> bool {
        matches!(self.state, PeerState::Connected { .. })
    }

    /// Attempts to connect to the peer.
    fn connect(&mut self, registry: &Registry) -> io::Result<()> {
        match &self.state {
            PeerState::Connected { .. } | PeerState::Connecting(_) => {
                return Ok(()); // Already connected or connecting
            }
            PeerState::Disconnected => {}
        }

        debug!(peer = %self.id, addr = %self.addr, "connecting to peer");

        // Create non-blocking socket
        let mut stream = TcpStream::connect(self.addr)?;

        // Disable Nagle's algorithm for low-latency messaging.
        // VSR protocol messages are small and latency-sensitive.
        stream.set_nodelay(true)?;

        // Register for write readiness (to detect connection completion)
        registry.register(&mut stream, self.token(), Interest::WRITABLE)?;

        self.state = PeerState::Connecting(stream);
        Ok(())
    }

    /// Called when the socket becomes writable (connection may be complete).
    fn on_writable(&mut self, registry: &Registry) -> io::Result<()> {
        match std::mem::replace(&mut self.state, PeerState::Disconnected) {
            PeerState::Connecting(mut stream) => {
                // Check if connection succeeded
                match stream.peer_addr() {
                    Ok(_) => {
                        debug!(peer = %self.id, "connected to peer");

                        // Re-register for read/write
                        registry.reregister(
                            &mut stream,
                            self.token(),
                            Interest::READABLE | Interest::WRITABLE,
                        )?;

                        self.state = PeerState::Connected {
                            stream,
                            encoder: FrameEncoder::new(),
                            decoder: FrameDecoder::new(),
                            write_buffer: Vec::new(),
                        };
                    }
                    Err(e) => {
                        warn!(peer = %self.id, error = %e, "connection failed");
                        self.state = PeerState::Disconnected;
                    }
                }
            }
            PeerState::Connected {
                stream,
                encoder,
                decoder,
                write_buffer,
            } => {
                // Already connected, restore state
                self.state = PeerState::Connected {
                    stream,
                    encoder,
                    decoder,
                    write_buffer,
                };
            }
            PeerState::Disconnected => {}
        }
        Ok(())
    }

    /// Queues a message for sending.
    fn queue_send(&mut self, message: &Message) -> Result<(), io::Error> {
        match &mut self.state {
            PeerState::Connected {
                encoder,
                write_buffer,
                ..
            } => {
                let frame = encoder.encode_into(message).map_err(|e| {
                    io::Error::new(ErrorKind::InvalidData, format!("encode error: {e}"))
                })?;
                write_buffer.extend_from_slice(frame);
                Ok(())
            }
            _ => Err(io::Error::new(
                ErrorKind::NotConnected,
                "peer not connected",
            )),
        }
    }

    /// Attempts to flush the write buffer.
    fn flush(&mut self) -> io::Result<usize> {
        match &mut self.state {
            PeerState::Connected {
                stream,
                write_buffer,
                ..
            } => {
                if write_buffer.is_empty() {
                    return Ok(0);
                }

                match stream.write(write_buffer) {
                    Ok(n) => {
                        write_buffer.drain(..n);
                        trace!(peer = %self.id, bytes = n, remaining = write_buffer.len(), "flushed");
                        Ok(n)
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
                    Err(e) => {
                        warn!(peer = %self.id, error = %e, "write error, disconnecting");
                        self.disconnect();
                        Err(e)
                    }
                }
            }
            _ => Ok(0),
        }
    }

    /// Reads available data and returns decoded messages.
    fn read_messages(&mut self) -> io::Result<Vec<Message>> {
        let mut messages = Vec::new();

        if let PeerState::Connected {
            stream, decoder, ..
        } = &mut self.state
        {
            let mut buf = [0u8; READ_BUFFER_SIZE];

            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        // EOF - peer closed connection
                        debug!(peer = %self.id, "peer closed connection");
                        self.state = PeerState::Disconnected;
                        break;
                    }
                    Ok(n) => {
                        decoder.extend(&buf[..n]);

                        // Decode all complete messages
                        loop {
                            match decoder.decode() {
                                Ok(Some(msg)) => messages.push(msg),
                                Ok(None) => break, // Need more data
                                Err(e) => {
                                    warn!(peer = %self.id, error = %e, "decode error");
                                    if e.is_fatal() {
                                        self.disconnect();
                                        return Err(io::Error::new(
                                            ErrorKind::InvalidData,
                                            e.to_string(),
                                        ));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!(peer = %self.id, error = %e, "read error, disconnecting");
                        self.disconnect();
                        return Err(e);
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Disconnects from the peer.
    fn disconnect(&mut self) {
        debug!(peer = %self.id, "disconnecting");
        self.state = PeerState::Disconnected;
    }

    /// Returns true if there's data waiting to be written.
    fn has_pending_writes(&self) -> bool {
        matches!(
            &self.state,
            PeerState::Connected { write_buffer, .. } if !write_buffer.is_empty()
        )
    }
}

// ============================================================================
// Inbound Connection
// ============================================================================

/// An inbound connection from another replica.
///
/// `bound_id` is `None` until the inbound socket sends a valid `Hello`
/// frame; the transport rejects every other frame on an unbound socket.
/// Once bound, every subsequent message must satisfy `msg.from ==
/// bound_id` — that turns the previously trust-the-`from`-field model
/// into a transport-verified identity check, so a peer can no longer
/// spoof another replica's id by setting the field on a forged
/// payload.
struct InboundConnection {
    stream: TcpStream,
    decoder: FrameDecoder,
    bound_id: Option<ReplicaId>,
}

/// Outcome of routing a single inbound frame through the Hello
/// handshake state machine.
enum InboundFate {
    /// Frame is post-handshake VSR traffic — forward upstream.
    Forward(Message),
    /// Frame is part of the handshake (a valid Hello). Don't forward.
    Consumed,
    /// Frame violates the handshake contract — drop the connection.
    Reject(InboundRejection),
}

/// Why an inbound connection was rejected. Logged at warn for operator
/// visibility; the actual remediation (drop the connection) happens in
/// the caller.
#[derive(Debug)]
#[allow(dead_code)] // fields read via Debug formatting in warn! sites
enum InboundRejection {
    /// Hello.cluster_hash didn't match ours — different cluster.
    ClusterMismatch { sender: ReplicaId },
    /// Hello.sender_id != msg.from — Hello envelope is internally
    /// inconsistent and can't be trusted to identify the peer.
    HelloSenderMismatch { from: ReplicaId, claimed: ReplicaId },
    /// First frame on the connection was not a Hello.
    FirstFrameNotHello {
        from: ReplicaId,
        payload: &'static str,
    },
    /// Unsolicited Hello after the connection was already bound.
    DuplicateHello { from: ReplicaId },
    /// Post-handshake message had a `from` field that doesn't match
    /// the transport-verified bound identity. Likely a spoof attempt
    /// or a serious bug.
    FromSpoof { from: ReplicaId, bound: ReplicaId },
}

// ============================================================================
// TCP Transport
// ============================================================================

/// Internal state for the TCP transport.
struct TransportState {
    /// This replica's ID.
    local_id: ReplicaId,
    /// BLAKE3-derived hash of `addresses`, computed once at construction.
    /// Sent in every outbound `Hello` and validated against inbound
    /// `Hello`s — mismatch means misrouted connection (different
    /// cluster, dev/prod mix-up) and the connection is dropped.
    cluster_hash: u64,
    /// Connections to peer replicas.
    peers: HashMap<ReplicaId, PeerConnection>,
    /// mio Poll instance for event notification.
    poll: Poll,
    /// TCP listener for inbound connections.
    listener: Option<TcpListener>,
    /// Cluster addresses (retained for reconnection).
    #[allow(dead_code)]
    addresses: ClusterAddresses,
    /// Inbound connections (from other replicas connecting to us).
    inbound: HashMap<Token, InboundConnection>,
    /// Next token for inbound connections.
    next_inbound_token: usize,
}

/// TCP transport for VSR multi-node clusters.
///
/// This transport handles all network communication between replicas
/// in a VSR cluster. It is thread-safe via internal locking.
///
/// # Example
///
/// ```ignore
/// use kimberlite_vsr::{TcpTransport, ClusterAddresses, ReplicaId};
/// use std::collections::HashMap;
///
/// let mut addrs = HashMap::new();
/// addrs.insert(ReplicaId::new(0), "127.0.0.1:5000".parse().unwrap());
/// addrs.insert(ReplicaId::new(1), "127.0.0.1:5001".parse().unwrap());
/// addrs.insert(ReplicaId::new(2), "127.0.0.1:5002".parse().unwrap());
///
/// let addresses = ClusterAddresses::new(addrs);
/// let transport = TcpTransport::new(ReplicaId::new(0), addresses)?;
/// ```
pub struct TcpTransport {
    state: Arc<Mutex<TransportState>>,
}

impl TcpTransport {
    /// Creates a new TCP transport.
    ///
    /// This starts listening on the address configured for this replica.
    pub fn new(local_id: ReplicaId, addresses: ClusterAddresses) -> io::Result<Self> {
        let poll = Poll::new()?;

        // Get our listen address
        let local_addr = addresses
            .get(local_id)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "local_id not in addresses"))?;

        // Create listener
        let mut listener = TcpListener::bind(local_addr)?;

        // Register listener
        poll.registry()
            .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)?;

        debug!(replica = %local_id, addr = %local_addr, "transport listening");

        // Initialize peer connections
        let mut peers = HashMap::new();
        for peer_id in addresses.replicas() {
            if peer_id != local_id {
                if let Some(addr) = addresses.get(peer_id) {
                    peers.insert(peer_id, PeerConnection::new(peer_id, addr));
                }
            }
        }

        let cluster_hash = addresses.membership_hash();

        let state = TransportState {
            local_id,
            cluster_hash,
            peers,
            poll,
            listener: Some(listener),
            addresses,
            inbound: HashMap::new(),
            next_inbound_token: 10000, // Start high to avoid conflicts
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Creates a transport without binding to a local address.
    ///
    /// Useful for testing where you don't need to accept incoming connections.
    pub fn new_without_listener(
        local_id: ReplicaId,
        addresses: ClusterAddresses,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;

        // Initialize peer connections
        let mut peers = HashMap::new();
        for peer_id in addresses.replicas() {
            if peer_id != local_id {
                if let Some(addr) = addresses.get(peer_id) {
                    peers.insert(peer_id, PeerConnection::new(peer_id, addr));
                }
            }
        }

        let cluster_hash = addresses.membership_hash();

        let state = TransportState {
            local_id,
            cluster_hash,
            peers,
            poll,
            listener: None,
            addresses,
            inbound: HashMap::new(),
            next_inbound_token: 10000,
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Polls for network events and returns received messages.
    ///
    /// This should be called regularly from the event loop.
    pub fn poll(&self, timeout: Option<std::time::Duration>) -> io::Result<Vec<Message>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?;

        let mut events = Events::with_capacity(MAX_EVENTS);
        state.poll.poll(&mut events, timeout)?;

        let mut messages = Vec::new();

        // Collect events to process
        let event_data: Vec<_> = events
            .iter()
            .map(|e| (e.token(), e.is_readable(), e.is_writable()))
            .collect();

        // Snapshot identity values needed inside the per-event match —
        // we can't read `state.local_id` / `state.cluster_hash` while
        // also holding a `&mut state.peers` borrow.
        let local_id = state.local_id;
        let cluster_hash = state.cluster_hash;

        for (token, is_readable, is_writable) in event_data {
            match token {
                LISTENER_TOKEN => {
                    // Accept new connections
                    Self::accept_connections(&mut state)?;
                }
                t if t.0 >= PEER_TOKEN_BASE && t.0 < 10000 => {
                    // Outbound peer connection
                    let peer_id = ReplicaId::new((t.0 - PEER_TOKEN_BASE) as u8);
                    // Clone registry before borrowing peers mutably
                    let registry = state.poll.registry().try_clone()?;
                    if let Some(peer) = state.peers.get_mut(&peer_id) {
                        if is_writable {
                            let was_connecting =
                                matches!(peer.state, PeerState::Connecting(_));
                            peer.on_writable(&registry)?;
                            // The dialer (us) introduces itself with a
                            // Hello as the very first frame on every
                            // freshly-opened connection. Sequencing is
                            // safe because `queue_send` only succeeds
                            // when the peer is Connected and nothing
                            // else writes between Connecting → Connected
                            // and this hook within the same poll
                            // iteration — so Hello always lands first.
                            let just_connected = was_connecting
                                && matches!(peer.state, PeerState::Connected { .. });
                            if just_connected {
                                let hello = Message::broadcast(
                                    local_id,
                                    MessagePayload::Hello(crate::message::Hello {
                                        sender_id: local_id,
                                        cluster_hash,
                                    }),
                                );
                                if let Err(e) = peer.queue_send(&hello) {
                                    warn!(peer = %peer_id, error = %e, "failed to queue Hello");
                                }
                            }
                            let _ = peer.flush();
                        }
                        if is_readable {
                            messages.extend(peer.read_messages()?);
                        }
                    }
                }
                t => {
                    // Inbound connection
                    if is_readable {
                        let should_remove = Self::handle_inbound_read(
                            &mut state.inbound,
                            t,
                            cluster_hash,
                            &mut messages,
                        );
                        if should_remove {
                            state.inbound.remove(&t);
                        }
                    }
                }
            }
        }

        // Flush all pending writes
        for peer in state.peers.values_mut() {
            if peer.has_pending_writes() {
                let _ = peer.flush();
            }
        }

        Ok(messages)
    }

    /// Handles reading from an inbound connection.
    /// Returns true if the connection should be removed.
    ///
    /// Enforces the Hello-handshake contract:
    /// 1. Until `bound_id` is set, the only acceptable frame is a
    ///    `Hello` whose `cluster_hash` matches ours. Anything else (a
    ///    valid VSR message before introduction, a Hello with the wrong
    ///    cluster, a malformed frame) drops the connection.
    /// 2. Once bound, every subsequent frame must satisfy
    ///    `msg.from == bound_id` — the transport now provides verified
    ///    sender identity rather than trusting the spoofable `from`
    ///    field.
    /// 3. `Hello` frames are stripped before forwarding upstream; the
    ///    replica state machine never observes them.
    fn handle_inbound_read(
        inbound: &mut HashMap<Token, InboundConnection>,
        token: Token,
        local_cluster_hash: u64,
        messages: &mut Vec<Message>,
    ) -> bool {
        let Some(conn) = inbound.get_mut(&token) else {
            return false;
        };

        let mut buf = [0u8; READ_BUFFER_SIZE];
        loop {
            match conn.stream.read(&mut buf) {
                Ok(0) => {
                    // Connection closed
                    return true;
                }
                Ok(n) => {
                    conn.decoder.extend(&buf[..n]);
                    loop {
                        match conn.decoder.decode() {
                            Ok(Some(msg)) => {
                                match Self::route_inbound_frame(
                                    &mut conn.bound_id,
                                    local_cluster_hash,
                                    msg,
                                ) {
                                    InboundFate::Forward(m) => messages.push(m),
                                    InboundFate::Consumed => {}
                                    InboundFate::Reject(reason) => {
                                        warn!(
                                            ?reason,
                                            "rejecting inbound connection during handshake"
                                        );
                                        return true;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                warn!(error = %e, "decode error on inbound");
                                if e.is_fatal() {
                                    return true;
                                }
                                break;
                            }
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!(error = %e, "read error on inbound");
                    return true;
                }
            }
        }
        false
    }

    /// Decides what happens to a single decoded inbound frame.
    ///
    /// Pulled out of [`Self::handle_inbound_read`] so the binding
    /// state-machine is testable in isolation (no `TcpStream` needed)
    /// and the read loop body stays scannable.
    fn route_inbound_frame(
        bound_id: &mut Option<ReplicaId>,
        local_cluster_hash: u64,
        msg: Message,
    ) -> InboundFate {
        match (*bound_id, &msg.payload) {
            (None, MessagePayload::Hello(hello)) => {
                if hello.cluster_hash != local_cluster_hash {
                    return InboundFate::Reject(InboundRejection::ClusterMismatch {
                        sender: hello.sender_id,
                    });
                }
                if hello.sender_id != msg.from {
                    return InboundFate::Reject(InboundRejection::HelloSenderMismatch {
                        from: msg.from,
                        claimed: hello.sender_id,
                    });
                }
                *bound_id = Some(hello.sender_id);
                debug!(
                    bound = %hello.sender_id,
                    "inbound connection bound to replica via Hello"
                );
                InboundFate::Consumed
            }
            (None, _) => InboundFate::Reject(InboundRejection::FirstFrameNotHello {
                from: msg.from,
                payload: msg.payload.name(),
            }),
            (Some(_), MessagePayload::Hello(_)) => {
                // A second Hello on an already-bound connection is
                // protocol noise (or a peer attempting to re-bind to a
                // different identity). Treat as a violation.
                InboundFate::Reject(InboundRejection::DuplicateHello { from: msg.from })
            }
            (Some(bound), _) => {
                if msg.from != bound {
                    crate::instrumentation::METRICS.increment_signature_failures();
                    return InboundFate::Reject(InboundRejection::FromSpoof {
                        from: msg.from,
                        bound,
                    });
                }
                InboundFate::Forward(msg)
            }
        }
    }

    /// Accepts pending inbound connections.
    fn accept_connections(state: &mut TransportState) -> io::Result<()> {
        let Some(listener) = &state.listener else {
            return Ok(());
        };

        loop {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    debug!(addr = %addr, "accepted inbound connection");

                    // Disable Nagle's algorithm for low-latency messaging
                    if let Err(e) = stream.set_nodelay(true) {
                        tracing::warn!(addr = %addr, error = %e, "failed to set TCP_NODELAY");
                    }

                    let token = Token(state.next_inbound_token);
                    state.next_inbound_token += 1;

                    state
                        .poll
                        .registry()
                        .register(&mut stream, token, Interest::READABLE)?;

                    state.inbound.insert(
                        token,
                        InboundConnection {
                            stream,
                            decoder: FrameDecoder::new(),
                            bound_id: None,
                        },
                    );
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Connects to all peers (proactively).
    pub fn connect_all(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?;

        let registry = state.poll.registry().try_clone()?;
        for peer in state.peers.values_mut() {
            let _ = peer.connect(&registry);
        }

        Ok(())
    }

    /// Re-attempts connection to any peer currently in `Disconnected` state.
    ///
    /// Used by the event loop's periodic reconnect tick to repair the
    /// mesh after a peer comes online late, recovers from a crash, or
    /// drops a connection mid-run. Peers in `Connecting` or `Connected`
    /// states are left alone — they're either making progress or already
    /// good. Returns the number of peers a reconnect was attempted on.
    ///
    /// Errors during individual reconnects are logged at `debug` (the
    /// peer just stays `Disconnected`); only registry-clone failure
    /// surfaces as `Err` because it indicates a deeper poll-thread
    /// problem we shouldn't paper over.
    pub fn reconnect_disconnected(&self) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?;

        let registry = state.poll.registry().try_clone()?;
        let mut attempts = 0;
        for peer in state.peers.values_mut() {
            if matches!(peer.state, PeerState::Disconnected) {
                if let Err(e) = peer.connect(&registry) {
                    debug!(peer = %peer.id, error = %e, "reconnect attempt failed");
                }
                attempts += 1;
            }
        }
        Ok(attempts)
    }

    /// Returns true if connected to the specified peer.
    pub fn is_connected(&self, peer: ReplicaId) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.peers.get(&peer).map(PeerConnection::is_connected))
            .unwrap_or(false)
    }

    /// Returns the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.state
            .lock()
            .ok()
            .map_or(0, |s| s.peers.values().filter(|p| p.is_connected()).count())
    }

    /// Returns the IDs of peers currently in `Disconnected` state. Used
    /// by bootstrap and the reconnect tick to log which specific peers
    /// haven't come up yet — `connected_count()` alone hides identity.
    pub fn disconnected_peer_ids(&self) -> Vec<ReplicaId> {
        self.state
            .lock()
            .ok()
            .map(|s| {
                let mut ids: Vec<_> = s
                    .peers
                    .iter()
                    .filter(|(_, p)| matches!(p.state, PeerState::Disconnected))
                    .map(|(id, _)| *id)
                    .collect();
                ids.sort_by_key(ReplicaId::as_u8);
                ids
            })
            .unwrap_or_default()
    }

    /// Returns the local replica ID.
    pub fn local_id(&self) -> ReplicaId {
        self.state
            .lock()
            .map(|s| s.local_id)
            .unwrap_or(ReplicaId::new(0))
    }
}

impl Transport for TcpTransport {
    fn send(&self, to: ReplicaId, message: Message) {
        let Ok(mut state) = self.state.lock() else {
            warn!("transport lock poisoned");
            return;
        };

        // Clone registry before borrowing peers mutably
        let registry = match state.poll.registry().try_clone() {
            Ok(r) => r,
            Err(e) => {
                debug!(error = %e, "failed to clone registry");
                return;
            }
        };

        // Get or create peer connection
        if let Some(peer) = state.peers.get_mut(&to) {
            // Ensure connected
            if !peer.is_connected() {
                if let Err(e) = peer.connect(&registry) {
                    debug!(peer = %to, error = %e, "failed to connect");
                    return;
                }
            }

            // Queue the message
            if let Err(e) = peer.queue_send(&message) {
                debug!(peer = %to, error = %e, "failed to queue message");
                return;
            }

            // Try to flush immediately
            let _ = peer.flush();
        } else {
            debug!(peer = %to, "unknown peer");
        }
    }

    fn local_id(&self) -> ReplicaId {
        TcpTransport::local_id(self)
    }
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (local_id, peer_count, inbound_count) = self
            .state
            .lock()
            .map(|s| (s.local_id, s.peers.len(), s.inbound.len()))
            .unwrap_or((ReplicaId::new(0), 0, 0));

        f.debug_struct("TcpTransport")
            .field("local_id", &local_id)
            .field("peers", &peer_count)
            .field("inbound", &inbound_count)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addresses() -> ClusterAddresses {
        let mut addrs = HashMap::new();
        addrs.insert(ReplicaId::new(0), "127.0.0.1:19500".parse().unwrap());
        addrs.insert(ReplicaId::new(1), "127.0.0.1:19501".parse().unwrap());
        addrs.insert(ReplicaId::new(2), "127.0.0.1:19502".parse().unwrap());
        ClusterAddresses::new(addrs)
    }

    #[test]
    fn cluster_addresses_creation() {
        let addrs = test_addresses();
        assert_eq!(addrs.len(), 3);
        assert!(!addrs.is_empty());
        assert!(addrs.get(ReplicaId::new(0)).is_some());
        assert!(addrs.get(ReplicaId::new(3)).is_none());
    }

    #[test]
    fn transport_without_listener() {
        let addrs = test_addresses();
        let transport = TcpTransport::new_without_listener(ReplicaId::new(0), addrs);
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.local_id(), ReplicaId::new(0));
        assert_eq!(transport.connected_count(), 0);
    }

    #[test]
    fn peer_connection_state() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let peer = PeerConnection::new(ReplicaId::new(1), addr);

        assert!(!peer.is_connected());
        assert!(!peer.has_pending_writes());
        assert_eq!(peer.token(), Token(PEER_TOKEN_BASE + 1));
    }

    #[test]
    fn membership_hash_is_order_independent() {
        let mut a = HashMap::new();
        a.insert(ReplicaId::new(0), "127.0.0.1:6000".parse().unwrap());
        a.insert(ReplicaId::new(1), "127.0.0.1:6001".parse().unwrap());
        a.insert(ReplicaId::new(2), "127.0.0.1:6002".parse().unwrap());

        let mut b = HashMap::new();
        // Insert in reverse — ensures HashMap ordering doesn't matter.
        b.insert(ReplicaId::new(2), "127.0.0.1:6002".parse().unwrap());
        b.insert(ReplicaId::new(1), "127.0.0.1:6001".parse().unwrap());
        b.insert(ReplicaId::new(0), "127.0.0.1:6000".parse().unwrap());

        assert_eq!(
            ClusterAddresses::new(a).membership_hash(),
            ClusterAddresses::new(b).membership_hash()
        );
    }

    #[test]
    fn membership_hash_changes_when_membership_changes() {
        let mut base = HashMap::new();
        base.insert(ReplicaId::new(0), "127.0.0.1:6000".parse().unwrap());
        base.insert(ReplicaId::new(1), "127.0.0.1:6001".parse().unwrap());
        base.insert(ReplicaId::new(2), "127.0.0.1:6002".parse().unwrap());
        let h0 = ClusterAddresses::new(base.clone()).membership_hash();

        // Change a port → different hash.
        let mut variant = base.clone();
        variant.insert(ReplicaId::new(2), "127.0.0.1:6999".parse().unwrap());
        assert_ne!(h0, ClusterAddresses::new(variant).membership_hash());

        // Drop a replica → different hash.
        let mut shorter = base;
        shorter.remove(&ReplicaId::new(2));
        assert_ne!(h0, ClusterAddresses::new(shorter).membership_hash());
    }

    /// Builds a Hello message with the specified sender id and hash.
    fn hello_msg(sender: ReplicaId, cluster_hash: u64) -> Message {
        Message::broadcast(
            sender,
            MessagePayload::Hello(crate::message::Hello {
                sender_id: sender,
                cluster_hash,
            }),
        )
    }

    /// Builds a stubbed-out Heartbeat message for handshake tests.
    /// Content doesn't matter — only `from` and the variant are
    /// inspected by the routing helper.
    fn fake_heartbeat(from: ReplicaId) -> Message {
        use crate::message::Heartbeat;
        use crate::types::{CommitNumber, ViewNumber};
        Message::broadcast(
            from,
            MessagePayload::Heartbeat(Heartbeat::without_clock(
                ViewNumber::new(0),
                CommitNumber::ZERO,
            )),
        )
    }

    #[test]
    fn handshake_binds_on_matching_hello_then_forwards_traffic() {
        let mut bound = None;
        let hash = 0xCAFE_BABE_u64;

        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            hash,
            hello_msg(ReplicaId::new(2), hash),
        );
        assert!(matches!(fate, InboundFate::Consumed));
        assert_eq!(bound, Some(ReplicaId::new(2)));

        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            hash,
            fake_heartbeat(ReplicaId::new(2)),
        );
        assert!(matches!(fate, InboundFate::Forward(_)));
    }

    #[test]
    fn handshake_rejects_first_frame_when_not_hello() {
        let mut bound = None;
        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            0,
            fake_heartbeat(ReplicaId::new(1)),
        );
        assert!(matches!(
            fate,
            InboundFate::Reject(InboundRejection::FirstFrameNotHello { .. })
        ));
        assert!(bound.is_none(), "binding should not occur on rejection");
    }

    #[test]
    fn handshake_rejects_hello_with_wrong_cluster_hash() {
        let mut bound = None;
        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            0xAAAA,
            hello_msg(ReplicaId::new(1), 0xBBBB),
        );
        assert!(matches!(
            fate,
            InboundFate::Reject(InboundRejection::ClusterMismatch { .. })
        ));
        assert!(bound.is_none());
    }

    #[test]
    fn handshake_rejects_hello_when_sender_id_mismatches_envelope_from() {
        let mut bound = None;
        let hash = 0x1234;
        let mut hello = hello_msg(ReplicaId::new(1), hash);
        // Tamper: envelope from claims R1 but Hello says R2.
        if let MessagePayload::Hello(ref mut h) = hello.payload {
            h.sender_id = ReplicaId::new(2);
        }
        let fate = TcpTransport::route_inbound_frame(&mut bound, hash, hello);
        assert!(matches!(
            fate,
            InboundFate::Reject(InboundRejection::HelloSenderMismatch { .. })
        ));
    }

    #[test]
    fn handshake_rejects_post_bind_message_with_spoofed_from() {
        let mut bound = Some(ReplicaId::new(1));
        // Bound to R1 but the heartbeat claims to be from R2.
        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            0,
            fake_heartbeat(ReplicaId::new(2)),
        );
        assert!(matches!(
            fate,
            InboundFate::Reject(InboundRejection::FromSpoof { .. })
        ));
    }

    #[test]
    fn handshake_rejects_duplicate_hello_after_bind() {
        let mut bound = Some(ReplicaId::new(1));
        let fate = TcpTransport::route_inbound_frame(
            &mut bound,
            0,
            hello_msg(ReplicaId::new(1), 0),
        );
        assert!(matches!(
            fate,
            InboundFate::Reject(InboundRejection::DuplicateHello { .. })
        ));
    }
}
