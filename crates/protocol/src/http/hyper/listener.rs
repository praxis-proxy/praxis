// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Listener binding, the accept loop and connection serving.
//!
//! A listener's socket is bound when it registers, so bind errors surface
//! at startup; the runtime then starts its service, which listens on the
//! socket, accepts connections until shutdown, terminates TLS where the
//! listener configures it, and serves each connection with hyper-util's
//! auto builder (HTTP/1.1, or HTTP/2 by prior knowledge or ALPN).

use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Once},
    time::Duration,
};

use arc_swap::ArcSwap;
use hyper::{Request, Response, body::Incoming, service::Service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{
        conn::auto,
        graceful::{GracefulShutdown, Watcher},
    },
};
use praxis_core::{
    ProxyError,
    config::Listener,
    egress::hyper::HyperConnector,
    server::{HyperRuntime, hyper::ShutdownWatch},
};
use praxis_filter::FilterPipeline;
use praxis_tls::CachedCaCerts;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
    sync::{Semaphore, watch},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, error, info, warn};

use super::{
    body::ProxyBody,
    service::{self, ResponseAbort},
};
use crate::tcp::hyper::{LISTEN_BACKLOG, bind_listener_socket};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long an accept loop pauses after a failed `accept`, so a process out
/// of file descriptors does not spin on the error.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100); // 100 ms

/// How long a connection waits for its first bytes, and an HTTP/1
/// connection for a request head, between requests included, when the
/// listener sets no keep-alive timeout: Pingora's server default, where
/// hyper alone would wait 30 s.
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(60); // 60 s

/// How much sooner than the runtime's shutdown bound a listener stops
/// waiting for its connections, so its own warning names what was left
/// instead of the runtime aborting the service.
const DRAIN_HEADROOM: Duration = Duration::from_secs(1); // 1 s

/// Most header lines an HTTP/1 request may carry: Pingora parses up to 256,
/// where hyper alone would answer `431` past 100. The egress allows the
/// same number on upstream responses.
const H1_MAX_HEADERS: usize = 256; // header lines

/// Largest header block an HTTP/2 client may send, against HPACK
/// amplification, as on Pingora.
const H2_MAX_HEADER_LIST_SIZE: u32 = 65_536; // 64 KiB

/// Most concurrent streams an HTTP/2 client may open, as on Pingora.
const H2_MAX_CONCURRENT_STREAMS: u32 = 128; // streams

/// Whether this process has logged that client certificates do not reach
/// the filters as a peer identity.
static PEER_IDENTITY_NOTED: Once = Once::new();

/// How long a client may take to complete the TLS handshake, as on Pingora.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60); // 60 s

// -----------------------------------------------------------------------------
// ListenerShared
// -----------------------------------------------------------------------------

/// What every request on one listener shares.
pub(super) struct ListenerShared {
    /// Listener name, as the active-request gauge labels it.
    pub(super) name: ::metrics::SharedString,

    /// The per-listener connection limit (`max_connections`), held per request.
    pub(super) connection_limit: Option<Arc<Semaphore>>,

    /// The upstream connector every listener of the adapter shares.
    pub(super) connector: HyperConnector,

    /// How long a new connection may wait for its first bytes, and an HTTP/1
    /// connection may sit between requests or wait for a request head.
    pub(super) header_timeout: Duration,

    /// The swappable filter pipeline.
    pub(super) pipeline: Arc<ArcSwap<FilterPipeline>>,

    /// Bound on each read of a client request body.
    pub(super) read_timeout: Option<Duration>,

    /// Runtime trust anchors (`runtime.upstream_ca_file`) for upstream TLS.
    pub(super) trust_anchors: Option<Arc<CachedCaCerts>>,
}

impl ListenerShared {
    /// The shared state of `listener`, serving `pipeline` through `connector`.
    pub(super) fn new(
        listener: &Listener,
        pipeline: Arc<ArcSwap<FilterPipeline>>,
        connector: HyperConnector,
        trust_anchors: Option<Arc<CachedCaCerts>>,
    ) -> Self {
        // Pingora applies the keep-alive timeout in whole seconds, rounded up;
        // the read timeout bounds body reads only, as there.
        let keepalive = listener
            .downstream_keepalive_timeout_ms
            .map(|millis| Duration::from_secs(millis.div_ceil(1_000)));
        Self {
            name: ::metrics::SharedString::from_shared(Arc::from(listener.name.as_str())),
            connection_limit: listener
                .max_connections
                .map(|max| Arc::new(Semaphore::new(usize::try_from(max).unwrap_or(usize::MAX)))),
            connector,
            header_timeout: keepalive.unwrap_or(DEFAULT_HEADER_TIMEOUT),
            pipeline,
            read_timeout: listener.downstream_read_timeout_ms.map(Duration::from_millis),
            trust_anchors,
        }
    }
}

impl fmt::Debug for ListenerShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerShared")
            .field("name", &self.name)
            .field("read_timeout", &self.read_timeout)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// ConnectionFacts
// -----------------------------------------------------------------------------

/// What a request knows about the connection it arrived on.
#[derive(Debug)]
pub(super) struct ConnectionFacts {
    /// The client's address.
    pub(super) peer: SocketAddr,

    /// Whether the connection is TLS.
    pub(super) tls: bool,
}

// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

/// Bind `listener` and register the service that serves it on `runtime`.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] naming the address when it cannot be
/// parsed or bound, or when its TLS settings cannot be built.
pub(super) fn register(
    runtime: &mut HyperRuntime,
    listener: &Listener,
    shared: ListenerShared,
    cert_watcher_shutdowns: &mut Vec<watch::Sender<bool>>,
) -> Result<(), ProxyError> {
    let socket = bind_listener_socket(&listener.address).map_err(|err| {
        ProxyError::Config(format!(
            "failed to bind HTTP listener {address}: {err}",
            address = listener.address
        ))
    })?;
    let acceptor = match &listener.tls {
        Some(tls) => {
            let (config, watcher) = crate::tls_setup::build_listener_tls(tls, &listener.address, "HTTP", true)?;
            cert_watcher_shutdowns.extend(watcher);
            Some(TlsAcceptor::from(config))
        },
        None => None,
    };

    info!(
        name = %listener.name,
        address = %listener.address,
        tls = acceptor.is_some(),
        "HTTP listener registered"
    );
    let accept = AcceptLoop {
        acceptor,
        builder: Arc::new(connection_builder(&shared)),
        drain_bound: runtime.shutdown_timeout().saturating_sub(DRAIN_HEADROOM),
        shared: Arc::new(shared),
    };
    runtime.add_service(&format!("http-proxy:{name}", name = listener.name), move |shutdown| {
        accept.run(socket, shutdown)
    });
    Ok(())
}

/// The hyper connection builder, configured like Pingora's HTTP server.
fn connection_builder(shared: &ListenerShared) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    let mut http1 = builder.http1();
    // A client may shut its write side down and still read the response,
    // as Pingora allows.
    http1
        .keep_alive(true)
        .half_close(true)
        .max_headers(H1_MAX_HEADERS)
        .header_read_timeout(shared.header_timeout)
        .timer(TokioTimer::new());
    builder
        .http2()
        .max_header_list_size(H2_MAX_HEADER_LIST_SIZE)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .timer(TokioTimer::new());
    builder
}

// -----------------------------------------------------------------------------
// AcceptLoop
// -----------------------------------------------------------------------------

/// One listener's service: accept, hand off, and drain on shutdown.
struct AcceptLoop {
    /// TLS acceptor for a TLS listener.
    acceptor: Option<TlsAcceptor>,

    /// The connection builder every connection of the listener uses.
    builder: Arc<auto::Builder<TokioExecutor>>,

    /// How long connections may take to finish once shutdown starts: less
    /// than the runtime gives the service.
    drain_bound: Duration,

    /// What every request on the listener shares.
    shared: Arc<ListenerShared>,
}

impl AcceptLoop {
    /// Hand an accepted connection to its own task, or back off on an
    /// accept error.
    async fn accepted(
        &self,
        accepted: io::Result<(TcpStream, SocketAddr)>,
        watcher: Watcher,
        shutdown: &ShutdownWatch,
    ) {
        match accepted {
            Ok((stream, peer)) => {
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(%peer, error = %err, "could not set TCP_NODELAY on the client socket");
                }
                let connection = Connection {
                    acceptor: self.acceptor.clone(),
                    builder: Arc::clone(&self.builder),
                    peer,
                    shared: Arc::clone(&self.shared),
                    shutdown: shutdown.clone(),
                };
                drop(tokio::spawn(connection.serve(stream, watcher)));
            },
            Err(err) => {
                warn!(name = %self.shared.name, error = %err, "failed to accept an HTTP connection");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            },
        }
    }

    /// Ask every open connection to finish and wait for them, up to the
    /// shutdown bound.
    async fn drain(&self, graceful: GracefulShutdown) {
        let open = graceful.count();
        if tokio::time::timeout(self.drain_bound, graceful.shutdown())
            .await
            .is_err()
        {
            warn!(name = %self.shared.name, open, "HTTP connections outlived the shutdown bound");
        } else {
            debug!(name = %self.shared.name, open, "HTTP connections drained");
        }
    }

    /// Listen on `socket` and serve connections until `shutdown` flips,
    /// then let open connections finish within the shutdown bound.
    async fn run(self, socket: TcpSocket, mut shutdown: ShutdownWatch) {
        let listener = match socket.listen(LISTEN_BACKLOG) {
            Ok(listener) => listener,
            Err(err) => {
                error!(name = %self.shared.name, error = %err, "failed to listen on the HTTP listener socket");
                return;
            },
        };
        let graceful = GracefulShutdown::new();
        let connections = shutdown.clone();
        while !*shutdown.borrow_and_update() {
            tokio::select! {
                changed = shutdown.changed() => if changed.is_err() { break },
                accepted = listener.accept() => self.accepted(accepted, graceful.watcher(), &connections).await,
            }
        }
        drop(listener);
        self.drain(graceful).await;
    }
}

// -----------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------

/// One accepted client connection.
struct Connection {
    /// TLS acceptor for a TLS listener.
    acceptor: Option<TlsAcceptor>,

    /// The listener's connection builder.
    builder: Arc<auto::Builder<TokioExecutor>>,

    /// The client's address.
    peer: SocketAddr,

    /// What every request on the listener shares.
    shared: Arc<ListenerShared>,

    /// Flips once the listener starts shutting down.
    shutdown: ShutdownWatch,
}

impl Connection {
    /// Wait, up to the header timeout, for the client's first bytes on
    /// `socket` without taking them; `false` when the connection should
    /// close instead: the client sent nothing, hung up, or shutdown began.
    ///
    /// hyper-util's auto builder waits for the first bytes with no timer,
    /// and hyper's HTTP/1 head timer starts at the first byte, so this
    /// bounds a silent connection as Pingora's read timeout does. It runs
    /// once, before the first request: between requests, the connection's
    /// keep-alive handling applies.
    async fn first_bytes(&mut self, socket: &TcpStream) -> bool {
        let mut probe = [0_u8; 1];
        let peeked = tokio::select! {
            peeked = tokio::time::timeout(self.shared.header_timeout, socket.peek(&mut probe)) => peeked,
            _stopping = self.shutdown.wait_for(|stopping| *stopping) => return false,
        };
        match peeked {
            Ok(Ok(read)) => read > 0,
            Ok(Err(err)) => {
                debug!(peer = %self.peer, error = %err, "client connection failed before its first request");
                false
            },
            Err(_elapsed) => {
                debug!(peer = %self.peer, "client sent nothing before the header timeout");
                false
            },
        }
    }

    /// Terminate TLS when the listener asks for it, then serve HTTP once the
    /// client sends something.
    async fn serve(mut self, stream: TcpStream, watcher: Watcher) {
        let Some(acceptor) = self.acceptor.clone() else {
            if self.first_bytes(&stream).await {
                self.serve_http(stream, false, watcher).await;
            }
            return;
        };
        let handshake = Box::pin(tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)));
        match handshake.await {
            Ok(Ok(mut tls)) => {
                if tls.get_ref().1.peer_certificates().is_some() {
                    note_unmapped_peer_identity();
                }
                if tls_holds_data(&mut tls) || self.first_bytes(tls.get_ref().0).await {
                    self.serve_http(tls, true, watcher).await;
                }
            },
            Ok(Err(err)) if handshake_abandoned(&err) => {
                debug!(peer = %self.peer, error = %err, "Downstream handshake abandoned");
            },
            Ok(Err(err)) => error!(peer = %self.peer, error = %err, "Downstream handshake error"),
            Err(_elapsed) => error!(peer = %self.peer, "Downstream handshake timeout"),
        }
    }

    /// Serve HTTP on `io` until the client closes it or shutdown drains it.
    fn serve_http<I>(self, io: I, tls: bool, watcher: Watcher) -> Pin<Box<dyn Future<Output = ()> + Send>>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = ProxyService {
            connection: Arc::new(ConnectionFacts { peer: self.peer, tls }),
            shared: Arc::clone(&self.shared),
        };
        let connection = self
            .builder
            .serve_connection_with_upgrades(TokioIo::new(io), service)
            .into_owned();
        let peer = self.peer;
        Box::pin(async move {
            if let Err(err) = watcher.watch(connection).await {
                debug!(%peer, error = %err, "HTTP connection ended with an error");
            }
        })
    }
}

// -----------------------------------------------------------------------------
// ProxyService
// -----------------------------------------------------------------------------

/// The hyper service for one connection: every request goes to
/// [`service::handle`].
#[derive(Clone)]
struct ProxyService {
    /// The connection the requests arrive on.
    connection: Arc<ConnectionFacts>,

    /// What every request on the listener shares.
    shared: Arc<ListenerShared>,
}

impl Service<Request<Incoming>> for ProxyService {
    type Error = ResponseAbort;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<ProxyBody>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(service::handle(
            Arc::clone(&self.shared),
            Arc::clone(&self.connection),
            req,
        ))
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Whether a failed handshake is a client that hung up before or during it
/// (a TCP probe, a load balancer health check) rather than one that spoke
/// something other than TLS; the former is not worth an error.
fn handshake_abandoned(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Log, once per process, that client certificates do not reach the filters
/// as a peer identity on this backend yet.
fn note_unmapped_peer_identity() {
    PEER_IDENTITY_NOTED.call_once(|| {
        debug!("the hyper backend does not map client certificates to a TLS peer identity yet; filters see none");
    });
}

/// Whether the TLS session already holds what the client sent with its last
/// handshake flight (a request, or its end), which a peek on the socket
/// would no longer see.
fn tls_holds_data(tls: &mut TlsStream<TcpStream>) -> bool {
    match tls.get_mut().1.process_new_packets() {
        Ok(state) => state.plaintext_bytes_to_read() > 0 || state.peer_has_closed(),
        // A broken record fails the first read, which ends the connection
        // at once.
        Err(_broken) => true,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{
        convert::Infallible,
        io::{Read as _, Write as _},
    };

    use bytes::Bytes;
    use hyper::service::service_fn;
    use praxis_core::{
        config::{Config, DEFAULT_CONFIG},
        egress::Connector as _,
    };
    use praxis_filter::{FilterAction, Rejection};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
        net::TcpListener,
    };
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::http::hyper::test_utils::{Script, empty_pipeline, scripted_pipeline};

    #[test]
    fn keepalive_timeout_is_applied_in_whole_seconds_rounded_up() {
        for (millis, seconds) in [(1, 1), (1_000, 1), (1_500, 2), (30_000, 30)] {
            let shared = shared(&format!("downstream_keepalive_timeout_ms: {millis}\n"));

            assert_eq!(
                shared.header_timeout,
                Duration::from_secs(seconds),
                "a keep-alive timeout of {millis} ms waits {seconds} s, as Pingora rounds it"
            );
        }
    }

    #[test]
    fn header_timeout_defaults_to_pingoras_sixty_seconds() {
        assert_eq!(
            shared("").header_timeout,
            Duration::from_secs(60),
            "an unset keep-alive timeout waits as long as Pingora does, not hyper's 30 s"
        );
    }

    #[test]
    fn read_timeout_bounds_body_reads_and_not_the_head() {
        let shared = shared("downstream_read_timeout_ms: 250\n");

        assert_eq!(
            shared.read_timeout,
            Some(Duration::from_millis(250)),
            "the read timeout bounds each body read"
        );
        assert_eq!(
            shared.header_timeout,
            Duration::from_secs(60),
            "and leaves the wait for a request head alone"
        );
    }

    #[test]
    fn max_connections_becomes_the_listeners_limit() {
        let limited = shared("max_connections: 3\n");

        assert_eq!(
            limited.connection_limit.as_ref().map(|limit| limit.available_permits()),
            Some(3),
            "the listener admits that many requests at once"
        );
        assert!(
            shared("").connection_limit.is_none(),
            "an unset limit admits any number"
        );
        assert_eq!(&*limited.name, "web", "the listener's name labels its requests");
    }

    #[test]
    fn hung_up_handshakes_are_told_apart_from_bad_ones() {
        for (kind, abandoned) in [
            (io::ErrorKind::UnexpectedEof, true),
            (io::ErrorKind::ConnectionReset, true),
            (io::ErrorKind::ConnectionAborted, true),
            (io::ErrorKind::BrokenPipe, true),
            (io::ErrorKind::InvalidData, false),
            (io::ErrorKind::TimedOut, false),
            (io::ErrorKind::Other, false),
        ] {
            assert_eq!(
                handshake_abandoned(&io::Error::from(kind)),
                abandoned,
                "{kind:?} abandoned is {abandoned}"
            );
        }
    }

    #[tokio::test]
    async fn unfinished_http1_head_times_out() {
        let mut shared = shared("");
        shared.header_timeout = Duration::from_millis(100);
        let (addr, _stop) = listen_once(shared, None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(b"GET / HTTP/1.1\r\nhost: a\r\n").await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), read_to_close(&mut client)).await;

        assert!(
            closed.is_ok_and(|response| !response.starts_with(b"HTTP/1.1 200")),
            "a client that never finishes its request head is disconnected"
        );
    }

    #[tokio::test]
    async fn silent_connection_times_out() {
        let mut shared = shared("");
        shared.header_timeout = Duration::from_millis(100);
        let (addr, _stop) = listen_once(shared, None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(5), read_to_close(&mut client)).await;

        assert!(
            closed.is_ok(),
            "a client that sends nothing is disconnected once the header timeout passes"
        );
    }

    #[tokio::test]
    async fn silent_connection_is_let_go_once_shutdown_begins() {
        let (addr, stop) = listen_once(shared(""), None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        stop.send(true).unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), read_to_close(&mut client)).await;

        assert!(
            closed.is_ok(),
            "a client that sends nothing does not hold shutdown up for the 60 s header timeout"
        );
    }

    #[tokio::test]
    async fn silent_tls_connection_times_out() {
        let tls = TestTls::new();
        let mut shared = shared("");
        shared.header_timeout = Duration::from_millis(100);
        let (addr, _stop) = listen_once(shared, Some(tls.acceptor())).await;
        let mut client = tls.connect(addr).await;

        let closed = tokio::time::timeout(Duration::from_secs(5), read_to_close(&mut client)).await;

        assert!(
            closed.is_ok(),
            "a client that completes the handshake and sends nothing is disconnected"
        );
    }

    #[tokio::test]
    async fn tls_request_sent_with_the_handshake_is_served() {
        let tls = TestTls::new();
        let mut shared = shared("");
        shared.header_timeout = Duration::from_millis(200);
        let (addr, _stop) = listen_once(shared, Some(tls.acceptor())).await;
        let socket = TcpStream::connect(addr).await.unwrap();

        let request = b"GET / HTTP/1.1\r\nhost: a\r\n\r\n";
        let answer = tokio::time::timeout(Duration::from_secs(5), tls.handshake_with_request(socket, request))
            .await
            .expect("the request is answered");

        assert!(
            answer.starts_with(b"HTTP/1.1 "),
            "a request read along with the handshake is served, not waited on: {}",
            String::from_utf8_lossy(&answer)
        );
    }

    #[tokio::test]
    async fn keepalive_client_may_pause_between_requests() {
        let mut shared = shared("");
        shared.header_timeout = Duration::from_millis(400);
        let (addr, _stop) = listen_once(shared, None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        for request in 0..3 {
            client.write_all(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await.unwrap();
            let response = tokio::time::timeout(Duration::from_secs(5), read_response(&mut client))
                .await
                .expect("each request is answered");
            assert!(
                response.starts_with(b"HTTP/1.1 "),
                "request {request} on the kept-alive connection is answered: {}",
                String::from_utf8_lossy(&response)
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    #[tokio::test]
    async fn http1_request_with_many_headers_is_served() {
        let mut client = serve(&shared(""));
        let headers: String = (0..200).map(|index| format!("x-header-{index}: v\r\n")).collect();
        let request = format!("GET / HTTP/1.1\r\nhost: a\r\n{headers}connection: close\r\n\r\n");

        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .expect("the request is answered")
            .unwrap();

        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "200 header lines are within Pingora's limit: {}",
            String::from_utf8_lossy(&response)
        );
    }

    #[tokio::test]
    async fn half_closed_client_still_gets_its_response() {
        let (addr, _stop) = listen_once(shared(""), None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();

        client.write_all(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = vec![0_u8; 1024];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
            .await
            .expect("the request is answered")
            .unwrap();

        assert!(
            response
                .get(..read)
                .is_some_and(|bytes| bytes.starts_with(b"HTTP/1.1 200")),
            "a client that shut its write side still reads the response"
        );
    }

    #[tokio::test]
    async fn http2_clients_may_open_pingoras_stream_limit() {
        let client = serve(&shared(""));
        let (mut sender, mut connection) = h2::client::handshake(client).await.unwrap();

        let request = Request::get("http://a/").body(()).unwrap();
        let (response, _body) = sender.send_request(request, true).unwrap();
        let answered = tokio::select! {
            response = response => Some(response.unwrap()),
            _ended = &mut connection => None,
        }
        .expect("the connection outlives its response");

        assert_eq!(answered.status(), 200, "a prior-knowledge HTTP/2 client is served");
        assert_eq!(
            connection.max_concurrent_send_streams(),
            128,
            "the server advertises Pingora's concurrent stream limit"
        );
    }

    #[tokio::test]
    async fn address_already_in_use_is_a_config_error_naming_it() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = taken.local_addr().unwrap().to_string();

        let registered = register_listener(&format!("name: web\naddress: \"{address}\"\n"));

        assert!(
            matches!(&registered, Err(ProxyError::Config(message)) if message.contains(&address)),
            "a bind failure is a configuration error that names the address: {registered:?}"
        );
    }

    #[test]
    fn unresolvable_address_is_a_config_error_naming_it() {
        let registered = register_listener("name: web\naddress: \"not an address\"\n");

        assert!(
            matches!(&registered, Err(ProxyError::Config(message)) if message.contains("not an address")),
            "an address that does not parse is a configuration error: {registered:?}"
        );
    }

    #[test]
    fn missing_tls_material_is_a_config_error() {
        let registered = register_listener(
            "name: web\naddress: \"127.0.0.1:0\"\ntls:\n  certificates:\n    - cert_path: /nonexistent/cert.pem\n      key_path: /nonexistent/key.pem\n",
        );

        assert!(
            matches!(registered, Err(ProxyError::Config(_))),
            "TLS settings that cannot be built fail registration: {registered:?}"
        );
    }

    #[test]
    fn registered_listener_adds_its_service() {
        let registered = register_listener("name: web\naddress: \"127.0.0.1:0\"\n");

        let services = registered.unwrap();
        assert!(
            services.contains("http-proxy:web"),
            "the listener is served by a runtime service named after it: {services}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Read TLS records from `socket` into `session`; the bytes read, zero
    /// once the server closed the connection.
    async fn feed_tls(session: &mut ClientConnection, socket: &mut TcpStream) -> usize {
        let mut buffer = vec![0_u8; 16_384]; // 16 KiB
        let read = socket.read(&mut buffer).await.unwrap_or(0);
        let mut records = buffer.get(..read).unwrap_or_default();
        while !records.is_empty() {
            session.read_tls(&mut records).unwrap();
        }
        session.process_new_packets().unwrap();
        read
    }

    /// Send everything `session` has queued in a single write.
    async fn flush_tls(session: &mut ClientConnection, socket: &mut TcpStream) {
        let mut records = Vec::new();
        while session.wants_write() {
            session.write_tls(&mut records).unwrap();
        }
        socket.write_all(&records).await.unwrap();
    }

    /// Accept one connection on a fresh local port and serve it as the
    /// listener does, terminating TLS with `acceptor` when set; the address
    /// to dial and the switch that starts shutdown.
    async fn listen_once(shared: ListenerShared, acceptor: Option<TlsAcceptor>) -> (SocketAddr, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let builder = Arc::new(connection_builder(&shared));
        drop(tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let graceful = GracefulShutdown::new();
            let connection = Connection {
                acceptor,
                builder,
                peer,
                shared: Arc::new(shared),
                shutdown,
            };
            connection.serve(stream, graceful.watcher()).await;
            drop(graceful);
        }));
        (addr, stop)
    }

    /// Read one length-delimited response from `client`.
    async fn read_response(client: &mut TcpStream) -> Vec<u8> {
        let mut received = Vec::new();
        loop {
            if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(received.get(..end).unwrap_or_default()).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if received.len() >= end + 4 + length {
                    return received;
                }
            }
            if client.read_buf(&mut received).await.unwrap_or(0) == 0 {
                return received;
            }
        }
    }

    /// Read from `client` until the server closes the connection.
    async fn read_to_close<R: AsyncRead + Unpin>(client: &mut R) -> Vec<u8> {
        let mut received = Vec::new();
        drop(client.read_to_end(&mut received).await);
        received
    }

    /// Register a listener from `yaml` on a fresh runtime; the runtime's
    /// description, which names its services, or why registration failed.
    fn register_listener(yaml: &str) -> Result<String, ProxyError> {
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
        let mut runtime = HyperRuntime::new(&config);
        let shared = ListenerShared::new(
            &listener,
            Arc::new(ArcSwap::from_pointee(empty_pipeline())),
            HyperConnector::new(4),
            None,
        );
        let mut watchers = Vec::new();
        register(&mut runtime, &listener, shared, &mut watchers)?;
        Ok(format!("{runtime:?}"))
    }

    /// Serve one in-memory connection with the listener's connection
    /// builder and a service answering every request with `200 ok`; the
    /// client's end.
    fn serve(shared: &ListenerShared) -> DuplexStream {
        let (client, server) = tokio::io::duplex(1_048_576); // 1 MiB
        let service = service_fn(|_request: Request<Incoming>| async {
            Ok::<_, Infallible>(Response::new(ProxyBody::full(Bytes::from_static(b"ok"))))
        });
        let builder = connection_builder(shared);
        drop(tokio::spawn(async move {
            drop(
                builder
                    .serve_connection_with_upgrades(TokioIo::new(server), service)
                    .await,
            );
        }));
        client
    }

    /// The shared state of a listener named `web` with `settings`, YAML
    /// fields of the listener, whose chain answers every request with a
    /// `200` that keeps the connection.
    fn shared(settings: &str) -> ListenerShared {
        let listener: Listener =
            serde_yaml::from_str(&format!("name: web\naddress: \"127.0.0.1:0\"\n{settings}")).unwrap();
        let pipeline = scripted_pipeline(Script {
            request: Some(Arc::new(|| {
                Ok(FilterAction::Reject(Rejection::status(200).preserving_keepalive()))
            })),
            ..Script::default()
        });
        ListenerShared::new(
            &listener,
            Arc::new(ArcSwap::from_pointee(pipeline)),
            HyperConnector::new(4),
            None,
        )
    }

    /// A self-signed `localhost` certificate: a server serving it and a
    /// client trusting it.
    struct TestTls {
        /// Trusts the certificate.
        client: Arc<ClientConfig>,

        /// Serves the certificate.
        server: Arc<ServerConfig>,
    }

    impl TestTls {
        /// Mint the certificate, with the crypto provider installed as
        /// startup installs it.
        fn new() -> Self {
            praxis_tls::provider::install();
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
                .unwrap()
                .self_signed(&key_pair)
                .unwrap();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            let server = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let client = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Self {
                client: Arc::new(client),
                server: Arc::new(server),
            }
        }

        /// The listener side.
        fn acceptor(&self) -> TlsAcceptor {
            TlsAcceptor::from(Arc::clone(&self.server))
        }

        /// A client connection to `addr` that completed its handshake.
        async fn connect(&self, addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
            let socket = TcpStream::connect(addr).await.unwrap();
            TlsConnector::from(Arc::clone(&self.client))
                .connect(ServerName::try_from("localhost").unwrap(), socket)
                .await
                .unwrap()
        }

        /// Complete a handshake on `socket`, sending `request` in the same
        /// write as the client's last handshake flight, so the server reads
        /// both at once; the plaintext answer, up to its head.
        async fn handshake_with_request(&self, mut socket: TcpStream, request: &[u8]) -> Vec<u8> {
            let name = ServerName::try_from("localhost").unwrap();
            let mut session = ClientConnection::new(Arc::clone(&self.client), name).unwrap();
            while session.is_handshaking() {
                flush_tls(&mut session, &mut socket).await;
                assert!(
                    feed_tls(&mut session, &mut socket).await > 0,
                    "the server answers the hello"
                );
            }
            session.writer().write_all(request).unwrap();
            flush_tls(&mut session, &mut socket).await;
            let mut answer = Vec::new();
            while !answer.windows(4).any(|window| window == b"\r\n\r\n") {
                if feed_tls(&mut session, &mut socket).await == 0 {
                    break;
                }
                drop(session.reader().read_to_end(&mut answer));
            }
            answer
        }
    }
}
