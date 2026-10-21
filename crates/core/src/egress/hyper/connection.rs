// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! One upstream connection: dialing it (TCP, TLS, the HTTP handshake), the
//! task that drives it, and the handle the pool and its sessions share.

use std::{
    io,
    net::SocketAddr,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response, Version};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::AbortHandle,
    time::Instant,
};
use tokio_rustls::{TlsConnector, client::TlsStream, rustls::ProtocolVersion};
use tracing::debug;

use super::{
    body::RequestBody,
    describe,
    tls::{TlsConfigs, server_name},
};
use crate::{
    config::UpstreamHttpVersion,
    connectivity::ConnectionOptions,
    egress::{EgressError, PeerSpec},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// ALPN protocol ID for HTTP/2.
const ALPN_H2: &[u8] = b"h2";

/// ALPN protocol ID for HTTP/1.1.
const ALPN_HTTP1: &[u8] = b"http/1.1";

/// Most response header fields accepted, as the Pingora HTTP/1 client allows.
const HTTP1_MAX_HEADERS: usize = 256; // header lines

/// Largest HTTP/2 frame the upstream is invited to send.
const HTTP2_MAX_FRAME: u32 = 65_536; // 64 KiB

/// HTTP/2 stream and connection receive windows, as Pingora opens them.
const HTTP2_WINDOW: u32 = 8_388_608; // 8 MiB

// -----------------------------------------------------------------------------
// HttpVersions
// -----------------------------------------------------------------------------

/// Which HTTP versions a peer's connections may speak, from its config.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum HttpVersions {
    /// HTTP/1.1 only.
    Http1,

    /// HTTP/2 only: ALPN `h2` over TLS, prior knowledge over plain TCP.
    Http2,

    /// HTTP/2 when TLS negotiates it, HTTP/1.1 otherwise.
    Either,
}

impl HttpVersions {
    /// The ALPN protocol IDs to offer, most preferred first.
    pub(super) fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http1 => vec![ALPN_HTTP1.to_vec()],
            Self::Http2 => vec![ALPN_H2.to_vec()],
            Self::Either => vec![ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()],
        }
    }

    /// The protocol to speak once the transport is up.
    ///
    /// `negotiated` is the ALPN result. A TLS server that picks nothing gets
    /// HTTP/1.1, as with Pingora; over plain TCP only an HTTP/2-only peer
    /// speaks HTTP/2, with prior knowledge.
    pub(super) fn select(self, tls: bool, negotiated: Option<&[u8]>) -> Protocol {
        let http2 = match negotiated {
            Some(protocol) => protocol == ALPN_H2,
            None => !tls && self == Self::Http2,
        };
        if http2 { Protocol::Http2 } else { Protocol::Http1 }
    }
}

impl From<UpstreamHttpVersion> for HttpVersions {
    fn from(version: UpstreamHttpVersion) -> Self {
        match version {
            UpstreamHttpVersion::H1 => Self::Http1,
            UpstreamHttpVersion::H2 => Self::Http2,
            UpstreamHttpVersion::Auto => Self::Either,
        }
    }
}

/// The HTTP version a connection speaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Protocol {
    /// HTTP/1.1: one exchange at a time.
    Http1,

    /// HTTP/2: exchanges multiplexed as streams.
    Http2,
}

impl Protocol {
    /// The version as [`http`] names it.
    ///
    /// [`http`]: http
    pub(super) const fn version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
        }
    }
}

// -----------------------------------------------------------------------------
// SetupTimeouts
// -----------------------------------------------------------------------------

/// Connection-setup limits for one dial, never longer than the exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SetupTimeouts {
    /// Bounds the TCP connect.
    connect: Duration,

    /// Bounds TCP, TLS and the HTTP handshake together.
    total: Duration,
}

impl SetupTimeouts {
    /// The peer's configured setup timeouts, each cut to `exchange` when
    /// looser, and `exchange` itself where none is configured.
    pub(super) fn new(options: &ConnectionOptions, exchange: Duration) -> Self {
        Self {
            connect: bounded(options.connection_timeout, exchange),
            total: bounded(options.total_connection_timeout, exchange),
        }
    }
}

// -----------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------

/// The response half of an exchange hyper has accepted.
pub(super) type ResponseFuture = Pin<Box<dyn Future<Output = hyper::Result<Response<Incoming>>> + Send>>;

/// A live upstream connection: its request half plus the state the pool
/// and every session on it share.
///
/// An HTTP/1 connection has one handle, which moves between the pool and
/// the session using it. An HTTP/2 connection has a handle per stream and
/// one in the pool.
#[derive(Debug)]
pub(super) struct Connection {
    /// State shared by every handle on the connection.
    info: Arc<ConnectionInfo>,

    /// The request half.
    sender: Sender,
}

impl Connection {
    /// Open an exchange on the connection. It stays open, holding off the
    /// idle timer, until the returned [`Exchange`] drops; `idle_timeout`
    /// is how long the connection may then sit unused.
    ///
    /// [`Exchange`]: Exchange
    pub(super) fn begin_exchange(&self, idle_timeout: Option<Duration>) -> Exchange {
        self.info.idle.send_if_modified(|state| {
            state.open = state.open.saturating_add(1);
            state.deadline.take().is_some()
        });

        let earlier = self.info.exchanges.fetch_add(1, Ordering::Relaxed);
        Exchange {
            idle_timeout,
            info: Arc::clone(&self.info),
            reused: earlier > 0,
        }
    }

    /// Close the connection under every handle.
    pub(super) fn close(&self) {
        self.info.driver.abort();
    }

    /// Let go of this handle when the pool drops it: an HTTP/1 connection
    /// closes, an HTTP/2 one stays up for any stream still using it.
    pub(super) fn discard(self) {
        if self.protocol() == Protocol::Http1 {
            self.close();
        }
    }

    /// Whether the connection has sat idle past its idle timeout.
    pub(super) fn is_idle_expired(&self, now: Instant) -> bool {
        self.info.idle.borrow().deadline.is_some_and(|deadline| deadline <= now)
    }

    /// Whether `other` is a handle on the same connection.
    pub(super) fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.info, &other.info)
    }

    /// Whether the connection can take a new exchange: it is still open, and
    /// an HTTP/1 connection is not busy with an earlier one.
    pub(super) fn is_usable(&self) -> bool {
        match &self.sender {
            Sender::Http1(sender) => !sender.is_closed() && sender.is_ready(),
            Sender::Http2(sender) => !sender.is_closed(),
        }
    }

    /// The address the connection reached.
    pub(super) fn peer_address(&self) -> SocketAddr {
        self.info.peer_address
    }

    /// The HTTP version the connection speaks.
    pub(super) const fn protocol(&self) -> Protocol {
        match self.sender {
            Sender::Http1(_) => Protocol::Http1,
            Sender::Http2(_) => Protocol::Http2,
        }
    }

    /// Wait until the connection can take a request.
    ///
    /// # Errors
    ///
    /// The hyper error when the connection closed.
    pub(super) async fn ready(&mut self) -> hyper::Result<()> {
        match &mut self.sender {
            Sender::Http1(sender) => sender.ready().await,
            Sender::Http2(sender) => sender.ready().await,
        }
    }

    /// Hand `request` to the connection; the future resolves to the
    /// final response head.
    pub(super) fn send(&mut self, request: Request<RequestBody>) -> ResponseFuture {
        match &mut self.sender {
            Sender::Http1(sender) => Box::pin(sender.send_request(request)),
            Sender::Http2(sender) => Box::pin(sender.send_request(request)),
        }
    }

    /// Another handle on a multiplexed connection; `None` for HTTP/1.
    pub(super) fn share(&self) -> Option<Self> {
        match &self.sender {
            Sender::Http1(_) => None,
            Sender::Http2(sender) => Some(Self {
                info: Arc::clone(&self.info),
                sender: Sender::Http2(sender.clone()),
            }),
        }
    }

    /// The negotiated TLS version; `None` over plain TCP.
    pub(super) fn tls_version(&self) -> Option<ProtocolVersion> {
        self.info.tls_version
    }
}

/// One exchange held open on a connection. Dropping it ends the exchange
/// and, when it was the last one open, starts the connection's idle timer.
#[derive(Debug)]
pub(super) struct Exchange {
    /// How long the connection may sit unused once this was its last exchange.
    idle_timeout: Option<Duration>,

    /// The connection the exchange runs on.
    info: Arc<ConnectionInfo>,

    /// Whether the connection carried an exchange before this one.
    reused: bool,
}

impl Exchange {
    /// Whether the connection carried an exchange before this one.
    pub(super) const fn reused(&self) -> bool {
        self.reused
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        let idle_timeout = self.idle_timeout;
        self.info.idle.send_if_modified(|state| {
            state.open = state.open.saturating_sub(1);
            if state.open > 0 {
                return false;
            }
            state.deadline = idle_timeout.and_then(|timeout| Instant::now().checked_add(timeout));
            state.deadline.is_some()
        });
    }
}

/// The request half of a connection.
#[derive(Debug)]
enum Sender {
    /// An HTTP/1 connection.
    Http1(http1::SendRequest<RequestBody>),

    /// An HTTP/2 connection.
    Http2(http2::SendRequest<RequestBody>),
}

/// What every handle on one connection shares.
#[derive(Debug)]
struct ConnectionInfo {
    /// Cancels the task driving the connection, which closes it.
    driver: AbortHandle,

    /// Exchanges started on the connection so far.
    exchanges: AtomicU64,

    /// Open exchanges and the idle deadline the driver enforces.
    idle: watch::Sender<IdleState>,

    /// The address the connection reached.
    peer_address: SocketAddr,

    /// The negotiated TLS version; `None` over plain TCP.
    tls_version: Option<ProtocolVersion>,
}

/// Whether a connection is in use, and when it closes if it is not.
#[derive(Clone, Copy, Debug, Default)]
struct IdleState {
    /// When the idle connection closes; `None` while in use or with no
    /// idle timeout.
    deadline: Option<Instant>,

    /// Exchanges currently open.
    open: usize,
}

// -----------------------------------------------------------------------------
// Dialing
// -----------------------------------------------------------------------------

/// Open a new connection to `peer`.
///
/// # Errors
///
/// [`EgressError::Connect`] when the TCP connect, the TLS handshake or the
/// HTTP handshake fails, or a setup timeout expires first; the message names
/// the timeout.
///
/// [`EgressError::Connect`]: EgressError::Connect
pub(super) async fn dial(
    peer: &PeerSpec,
    tls: &TlsConfigs,
    timeouts: SetupTimeouts,
) -> Result<Connection, EgressError> {
    tokio::time::timeout(timeouts.total, establish(peer, tls, timeouts.connect))
        .await
        .map_err(|_elapsed| {
            EgressError::Connect(format!(
                "total connection timeout ({} ms) expired dialing {}",
                timeouts.total.as_millis(),
                peer.address
            ))
        })?
}

/// Run the TCP connect, the TLS handshake when the peer wants it, and the
/// HTTP handshake.
async fn establish(peer: &PeerSpec, tls: &TlsConfigs, connect_timeout: Duration) -> Result<Connection, EgressError> {
    let versions = HttpVersions::from(peer.connection.http_version);
    let tls_setup = peer
        .tls
        .then(|| Ok::<_, EgressError>((tls.client_config(peer, versions)?, server_name(peer)?)))
        .transpose()?;
    let stream = connect_tcp(peer.address, connect_timeout).await?;
    let Some((config, name)) = tls_setup else {
        let protocol = versions.select(false, None);
        return Box::pin(handshake(Transport::Plain(stream), protocol, peer.address, None)).await;
    };

    let stream = Box::pin(TlsConnector::from(config).connect(name, stream))
        .await
        .map_err(|err| EgressError::Connect(format!("TLS handshake with {} failed: {err}", peer.address)))?;
    let (_, session) = stream.get_ref();
    let protocol = versions.select(true, session.alpn_protocol());
    let tls_version = session.protocol_version();
    Box::pin(handshake(
        Transport::Tls(Box::new(stream)),
        protocol,
        peer.address,
        tls_version,
    ))
    .await
}

/// Connect to `address` within `limit`.
async fn connect_tcp(address: SocketAddr, limit: Duration) -> Result<TcpStream, EgressError> {
    let stream = tokio::time::timeout(limit, TcpStream::connect(address))
        .await
        .map_err(|_elapsed| {
            EgressError::Connect(format!(
                "connection timeout ({} ms) expired connecting to {address}",
                limit.as_millis()
            ))
        })?
        .map_err(|err| EgressError::Connect(format!("connecting to {address} failed: {err}")))?;

    if let Err(err) = stream.set_nodelay(true) {
        debug!(peer = %address, error = %err, "could not set TCP_NODELAY on the upstream socket");
    }
    Ok(stream)
}

/// Run the HTTP handshake for `protocol` over `transport` and start the
/// task that drives the connection.
async fn handshake(
    transport: Transport,
    protocol: Protocol,
    peer_address: SocketAddr,
    tls_version: Option<ProtocolVersion>,
) -> Result<Connection, EgressError> {
    let io = TokioIo::new(transport);
    let (idle, idle_changes) = watch::channel(IdleState::default());
    let (sender, driver) = match protocol {
        Protocol::Http1 => Box::pin(handshake_http1(io, idle_changes, peer_address)).await?,
        Protocol::Http2 => Box::pin(handshake_http2(io, idle_changes, peer_address)).await?,
    };

    debug!(peer = %peer_address, ?protocol, tls = tls_version.is_some(), "opened an upstream connection");
    let info = ConnectionInfo {
        driver,
        exchanges: AtomicU64::new(0),
        idle,
        peer_address,
        tls_version,
    };
    Ok(Connection {
        info: Arc::new(info),
        sender,
    })
}

/// The HTTP/1 handshake, and the connection's driver task.
async fn handshake_http1(
    io: TokioIo<Transport>,
    idle: watch::Receiver<IdleState>,
    peer_address: SocketAddr,
) -> Result<(Sender, AbortHandle), EgressError> {
    // Obsolete line folding in an upstream response is unfolded into spaces
    // rather than refused, which is what Pingora's parser does with it.
    let (sender, connection) = http1::Builder::new()
        .max_headers(HTTP1_MAX_HEADERS)
        .allow_obsolete_multiline_headers_in_responses(true)
        .handshake(io)
        .await
        .map_err(|err| handshake_failed(&err, peer_address))?;
    Ok((Sender::Http1(sender), spawn_driver(connection, idle, peer_address)))
}

/// The HTTP/2 handshake, and the connection's driver task.
async fn handshake_http2(
    io: TokioIo<Transport>,
    idle: watch::Receiver<IdleState>,
    peer_address: SocketAddr,
) -> Result<(Sender, AbortHandle), EgressError> {
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .initial_stream_window_size(HTTP2_WINDOW)
        .initial_connection_window_size(HTTP2_WINDOW)
        .max_frame_size(HTTP2_MAX_FRAME)
        .handshake(io)
        .await
        .map_err(|err| handshake_failed(&err, peer_address))?;
    Ok((Sender::Http2(sender), spawn_driver(connection, idle, peer_address)))
}

/// Spawn the task that drives `connection` until it ends or idles out.
fn spawn_driver<C>(connection: C, idle: watch::Receiver<IdleState>, peer_address: SocketAddr) -> AbortHandle
where
    C: Future<Output = hyper::Result<()>> + Send + 'static,
{
    tokio::spawn(drive(connection, idle, peer_address)).abort_handle()
}

/// Drive `connection`, closing it when it sits idle past its deadline.
///
/// The connection also ends on its own once every request handle is gone
/// and nothing is in flight, so a dropped session cannot strand the task.
async fn drive<C>(connection: C, mut idle: watch::Receiver<IdleState>, peer_address: SocketAddr)
where
    C: Future<Output = hyper::Result<()>>,
{
    let mut connection = pin!(connection);
    loop {
        let deadline = idle.borrow_and_update().deadline;
        tokio::select! {
            result = &mut connection => {
                log_end(result, peer_address);
                return;
            },
            () = idle_expiry(deadline) => {
                debug!(peer = %peer_address, "closing an idle upstream connection");
                return;
            },
            changed = idle.changed() => {
                if changed.is_err() {
                    break;
                }
            },
        }
    }

    log_end(connection.await, peer_address);
}

// -----------------------------------------------------------------------------
// Transport
// -----------------------------------------------------------------------------

/// The byte stream under one HTTP connection.
#[derive(Debug)]
enum Transport {
    /// Plain TCP.
    Plain(TcpStream),

    /// TLS over TCP.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Transport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Keep an operator-configured timeout when it is stricter than the exchange's.
fn bounded(configured: Option<Duration>, exchange: Duration) -> Duration {
    configured.map_or(exchange, |configured| configured.min(exchange))
}

/// A failed HTTP handshake as a connect error.
fn handshake_failed(err: &hyper::Error, peer_address: SocketAddr) -> EgressError {
    EgressError::Connect(format!("HTTP handshake with {peer_address} failed: {}", describe(err)))
}

/// Resolve when `deadline` passes; never without one.
async fn idle_expiry(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Record how a connection ended.
fn log_end(result: hyper::Result<()>, peer_address: SocketAddr) {
    match result {
        Ok(()) => debug!(peer = %peer_address, "upstream connection closed"),
        Err(err) => debug!(peer = %peer_address, error = %describe(&err), "upstream connection ended with an error"),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn setup_timeouts_never_outlive_the_exchange() {
        let options = ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(1)),
            total_connection_timeout: Some(Duration::from_secs(20)),
            ..ConnectionOptions::default()
        };

        let timeouts = SetupTimeouts::new(&options, Duration::from_secs(10));

        assert_eq!(
            timeouts.connect,
            Duration::from_secs(1),
            "a stricter operator timeout is kept"
        );
        assert_eq!(
            timeouts.total,
            Duration::from_secs(10),
            "a looser operator timeout is cut to the exchange timeout"
        );
        assert_eq!(
            SetupTimeouts::new(&ConnectionOptions::default(), Duration::from_secs(3)),
            SetupTimeouts {
                connect: Duration::from_secs(3),
                total: Duration::from_secs(3),
            },
            "unconfigured setup timeouts take the exchange timeout"
        );
    }

    #[test]
    fn versions_map_from_the_cluster_setting() {
        assert_eq!(HttpVersions::from(UpstreamHttpVersion::H1), HttpVersions::Http1, "h1");
        assert_eq!(HttpVersions::from(UpstreamHttpVersion::H2), HttpVersions::Http2, "h2");
        assert_eq!(
            HttpVersions::from(UpstreamHttpVersion::Auto),
            HttpVersions::Either,
            "auto"
        );
    }

    #[test]
    fn versions_offer_alpn_in_preference_order() {
        assert_eq!(HttpVersions::Http1.alpn(), vec![b"http/1.1".to_vec()], "HTTP/1 only");
        assert_eq!(HttpVersions::Http2.alpn(), vec![b"h2".to_vec()], "HTTP/2 only");
        assert_eq!(
            HttpVersions::Either.alpn(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "either version prefers h2"
        );
    }

    #[test]
    fn negotiated_alpn_picks_the_protocol() {
        assert_eq!(
            HttpVersions::Either.select(true, Some(b"h2")),
            Protocol::Http2,
            "a server choosing h2 gets HTTP/2"
        );
        assert_eq!(
            HttpVersions::Either.select(true, Some(b"http/1.1")),
            Protocol::Http1,
            "a server choosing http/1.1 gets HTTP/1.1"
        );
        assert_eq!(
            HttpVersions::Http2.select(true, None),
            Protocol::Http1,
            "a TLS server that negotiates nothing falls back to HTTP/1.1"
        );
    }

    #[test]
    fn plain_tcp_speaks_http2_only_when_told_to() {
        assert_eq!(
            HttpVersions::Http2.select(false, None),
            Protocol::Http2,
            "an HTTP/2-only peer gets prior knowledge"
        );
        assert_eq!(
            HttpVersions::Either.select(false, None),
            Protocol::Http1,
            "with nothing to negotiate, either version means HTTP/1.1"
        );
        assert_eq!(HttpVersions::Http1.select(false, None), Protocol::Http1, "HTTP/1 only");
    }

    #[test]
    fn protocols_name_their_http_version() {
        assert_eq!(Protocol::Http1.version(), Version::HTTP_11, "HTTP/1 speaks 1.1");
        assert_eq!(Protocol::Http2.version(), Version::HTTP_2, "HTTP/2 speaks 2");
    }
}
