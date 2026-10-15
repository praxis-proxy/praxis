// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The connection contract a backend implements: open, send, receive, release.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Version};

use super::PeerSpec;

// -----------------------------------------------------------------------------
// Exchange Types
// -----------------------------------------------------------------------------

/// The request line and headers of an outbound request.
#[derive(Clone, Debug)]
pub struct RequestHead {
    /// Request headers, already sanitized by the caller.
    pub headers: HeaderMap,

    /// HTTP method.
    pub method: Method,

    /// Request target in origin form (`/path?query`).
    pub target: String,
}

/// A borrowed view of the status line and headers of a received response.
#[derive(Clone, Copy, Debug)]
pub struct ResponseHead<'response> {
    /// Response headers as received, retained by the transport for framing.
    pub headers: &'response HeaderMap,

    /// HTTP status code.
    pub status: u16,

    /// Protocol version the peer answered with.
    pub version: Version,
}

/// How far a response body got, as far as the transport can tell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// The body ended cleanly; the connection may be reused.
    Finished,

    /// The body is not complete; the connection must not be reused.
    Incomplete,
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// A transport failure, classified so callers can map it to a status.
///
/// ```
/// use praxis_core::egress::EgressError;
///
/// let err = EgressError::Connect("connection refused".to_owned());
/// assert_eq!(err.to_string(), "connect failed: connection refused");
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EgressError {
    /// The request could not be encoded for the wire.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// No connection to the peer could be established.
    #[error("connect failed: {0}")]
    Connect(String),

    /// The exchange failed after the connection was established.
    #[error("exchange failed: {0}")]
    Io(String),

    /// This build carries no network backend.
    #[error("no network backend is compiled into this build")]
    Unavailable,
}

// -----------------------------------------------------------------------------
// Connector
// -----------------------------------------------------------------------------

/// Opens pooled connections to peers.
///
/// Clones share one pool, so every holder dials through the same idle
/// connections. A backend keys its pool however its transport needs;
/// callers only see [`PeerSpec`] in and [`Session`] out.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::egress::{Connector as _, EgressError, PeerSpec, Unavailable};
///
/// let connector = Unavailable::new(16);
/// let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
/// let result = tokio::runtime::Runtime::new()
///     .expect("runtime")
///     .block_on(connector.connect(&peer, Duration::from_secs(1)));
/// assert!(matches!(result, Err(EgressError::Unavailable)));
/// ```
pub trait Connector: Clone + Send + Sync + 'static {
    /// The live connection type this connector hands out.
    type Session: Session;

    /// Build a connector keeping up to `keepalive_pool_size` idle connections.
    fn new(keepalive_pool_size: usize) -> Self;

    /// Open or reuse a connection to `peer`.
    ///
    /// `timeout` is the whole exchange's deadline: the backend bounds its own
    /// connection-setup timers (TCP, TLS, protocol handshake) to it. A caller
    /// that wants a tighter per-attempt cap wraps the returned future in its
    /// own timer, so the two expiries stay distinguishable.
    fn connect(
        &self,
        peer: &PeerSpec,
        timeout: Duration,
    ) -> impl Future<Output = Result<Self::Session, EgressError>> + Send;

    /// Give a session back. With `keepalive` the connection returns to the
    /// pool; without it the connection is shut down, except that a stream of
    /// a multiplexed connection only releases its share of that connection.
    fn release(&self, session: Self::Session, keepalive: bool) -> impl Future<Output = ()> + Send;
}

// -----------------------------------------------------------------------------
// Session
// -----------------------------------------------------------------------------

/// One HTTP exchange on a connection a [`Connector`] opened.
///
/// Methods run in order: request head, body chunks, finish, then the
/// response head (repeated past any `1xx` interim response), then body
/// chunks until [`read_response_body`] returns `None`. Reads respect the
/// peer's configured read timeout until [`clear_read_timeout`] hands
/// pacing to the caller.
///
/// [`clear_read_timeout`]: Self::clear_read_timeout
/// [`read_response_body`]: Self::read_response_body
pub trait Session: Send + 'static {
    /// Whether this exchange rides a connection that served a request before.
    fn reused(&self) -> bool;

    /// Send the request line and headers.
    fn send_request_head(&mut self, head: RequestHead) -> impl Future<Output = Result<(), EgressError>> + Send;

    /// Send one body chunk; `end_of_stream` marks it as the last.
    fn send_request_body(
        &mut self,
        chunk: Bytes,
        end_of_stream: bool,
    ) -> impl Future<Output = Result<(), EgressError>> + Send;

    /// Mark the request complete when no body chunk carried `end_of_stream`.
    fn finish_request(&mut self) -> impl Future<Output = Result<(), EgressError>> + Send;

    /// Read the next response head into the session, replacing the previous
    /// head. Inspect it with [`response_head`](Self::response_head) before
    /// reading again: callers skip interim `1xx` statuses, except final `101`.
    fn read_response_head(&mut self) -> impl Future<Output = Result<(), EgressError>> + Send;

    /// Borrow the most recently read response head without copying its headers.
    /// The transport retains the original headers for body framing and reuse;
    /// callers sanitize this view into their own map before advancing the
    /// session.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::Io`] when no response head is available.
    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError>;

    /// Whether the response ended with its head (no body follows).
    fn response_done(&mut self) -> bool;

    /// Read the next body chunk; `None` at the end of the body.
    fn read_response_body(&mut self) -> impl Future<Output = Result<Option<Bytes>, EgressError>> + Send;

    /// Whether the body so far ended cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::Io`] when the peer reset or errored the stream.
    fn completion(&mut self) -> Result<Completion, EgressError>;

    /// Stop the transport's own per-read timer; the caller paces reads from
    /// here on.
    fn clear_read_timeout(&mut self);

    /// Tear the connection down without returning it to the pool.
    fn shutdown(&mut self) -> impl Future<Output = ()> + Send;
}
