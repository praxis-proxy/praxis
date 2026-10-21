// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The hyper backend's raw TCP/L4 protocol adapter.
//!
//! Everything a connection goes through once it is accepted (admission,
//! the SNI peek, the connect and disconnect filters, the upstream connect
//! and forwarding) is the backend-neutral [`PingoraTcpProxy`] that the
//! Pingora service runs as well. This adapter groups the listeners the same
//! way, binds their sockets, terminates TLS where a listener configures it,
//! and hands each accepted connection to the group's proxy.
//!
//! [`PingoraTcpProxy`]: crate::tcp::proxy::PingoraTcpProxy

use std::{
    collections::BTreeMap,
    io,
    net::{SocketAddr, ToSocketAddrs as _},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use praxis_core::{
    ProxyError,
    config::{Config, Listener},
    server::{HyperRuntime, hyper::ShutdownWatch},
};
use praxis_filter::{FilterPipeline, FilterRegistry};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
    sync::watch,
    task::{JoinError, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use super::{
    groups::{self, TcpGroupKey},
    proxy::{self, PingoraTcpProxy},
};
use crate::{ListenerPipelines, Protocol};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long an accept loop pauses after a failed `accept`, so a process out
/// of file descriptors does not spin on the error.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100); // 100 ms

/// Pending connections the kernel may queue on each hyper listener, as on
/// Pingora; the kernel caps it at `net.core.somaxconn`.
pub(crate) const LISTEN_BACKLOG: u32 = 65_535; // connections

/// How long a client may take to complete the TLS handshake, as on Pingora.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60); // 60 s

/// Address label for a socket that cannot report its own address.
const UNKNOWN_ADDR: &str = "unknown";

// -----------------------------------------------------------------------------
// HyperTcp
// -----------------------------------------------------------------------------

/// hyper-backed raw TCP/L4 protocol implementation.
///
/// Groups TCP listeners by `(upstream, cluster, idle timeout, max duration)`
/// the way the Pingora adapter does and registers one runtime service per
/// group, accepting on every socket of the group.
pub struct HyperTcp;

impl HyperTcp {
    /// Bind every TCP listener in `config` onto `runtime`.
    ///
    /// Each listener's address is bound here, so an address that cannot be
    /// bound fails registration rather than the running server; the socket
    /// starts listening when the runtime starts. Returns the
    /// shutdown senders of the certificate watchers that hot-reloading TLS
    /// listeners start; the caller keeps them for the server's lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when grouped listeners disagree on
    /// their filter chains or connection limit, or when a listener's address
    /// cannot be bound or its TLS settings cannot be built.
    pub fn register_on(
        runtime: &mut HyperRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        let grouped = groups::group_tcp_listeners(config);
        groups::validate_tcp_group_consistency(&grouped)?;
        let fallback_pipeline = FilterPipeline::build(&mut [], &FilterRegistry::with_builtins())
            .map_err(|err| ProxyError::Config(format!("TCP fallback pipeline: {err}")))?;
        let group = GroupContext {
            config,
            fallback_pipeline: Arc::new(ArcSwap::from_pointee(fallback_pipeline)),
            pipelines,
        };

        let mut cert_watcher_shutdowns = Vec::new();
        let ordered: BTreeMap<_, _> = grouped.into_iter().collect();
        for (group_key, listeners) in &ordered {
            group.register(runtime, group_key, listeners, &mut cert_watcher_shutdowns)?;
        }

        Ok(cert_watcher_shutdowns)
    }
}

impl Protocol for HyperTcp {
    fn register(
        self: Box<Self>,
        server: &mut HyperRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        Self::register_on(server, config, pipelines)
    }
}

// -----------------------------------------------------------------------------
// Listener Sockets
// -----------------------------------------------------------------------------

/// Bind the socket for a hyper listener at `address`, trying each address it
/// resolves to in turn.
///
/// Called at registration so an address in use fails before the server
/// starts; the service calls `listen` with [`LISTEN_BACKLOG`] once the
/// runtime runs, since a tokio listener needs the runtime.
///
/// # Errors
///
/// Returns the resolution error, or the last bind error when no resolved
/// address can be bound.
pub(crate) fn bind_listener_socket(address: &str) -> io::Result<TcpSocket> {
    let mut last_err = None;
    for addr in address.to_socket_addrs()? {
        match bind_one(addr) {
            Ok(socket) => return Ok(socket),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address resolved to nothing")))
}

/// Bind one socket at `addr`, reusing the address as std's `bind` does.
fn bind_one(addr: SocketAddr) -> io::Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket)
}

// -----------------------------------------------------------------------------
// Group Registration
// -----------------------------------------------------------------------------

/// What every TCP group in one registration shares.
struct GroupContext<'reg> {
    /// The configuration being registered.
    config: &'reg Config,

    /// Pipeline for a group whose first listener has none.
    fallback_pipeline: Arc<ArcSwap<FilterPipeline>>,

    /// Each listener's pipeline.
    pipelines: &'reg ListenerPipelines,
}

impl GroupContext<'_> {
    /// Bind one group's listeners and register the service that serves them.
    fn register(
        &self,
        runtime: &mut HyperRuntime,
        group_key: &TcpGroupKey,
        listeners: &[&Listener],
        cert_watcher_shutdowns: &mut Vec<watch::Sender<bool>>,
    ) -> Result<(), ProxyError> {
        let (upstream, cluster, ..) = group_key;
        let mut sockets = Vec::with_capacity(listeners.len());
        for listener in listeners {
            sockets.push(BoundListener::bind(
                listener,
                upstream.as_deref(),
                cert_watcher_shutdowns,
            )?);
        }

        let proxy = Arc::new(proxy::build_group_proxy(
            group_key,
            listeners,
            self.pipelines,
            &self.fallback_pipeline,
            self.config,
        ));
        let name = proxy::tcp_service_name(upstream.as_deref(), cluster.as_deref());
        runtime.add_service(&name, move |shutdown| serve_group(proxy, sockets, shutdown));
        Ok(())
    }
}

/// One bound listener of a TCP group.
struct BoundListener {
    /// The configured address, for logs.
    address: String,

    /// The bound socket; it starts listening when the service starts.
    socket: TcpSocket,

    /// Terminates TLS before forwarding; `None` forwards the client's bytes.
    tls: Option<TlsAcceptor>,
}

impl BoundListener {
    /// Bind `listener`'s address and build its TLS acceptor, adding the
    /// certificate watcher's shutdown sender to `cert_watcher_shutdowns`.
    fn bind(
        listener: &Listener,
        upstream: Option<&str>,
        cert_watcher_shutdowns: &mut Vec<watch::Sender<bool>>,
    ) -> Result<Self, ProxyError> {
        let socket = bind_listener_socket(&listener.address).map_err(|err| {
            ProxyError::Config(format!(
                "failed to bind TCP listener {address}: {err}",
                address = listener.address
            ))
        })?;
        let tls = match &listener.tls {
            Some(tls) => {
                let (server_config, watcher) =
                    crate::tls_setup::build_listener_tls(tls, &listener.address, "TCP", false)?;
                cert_watcher_shutdowns.extend(watcher);
                Some(TlsAcceptor::from(server_config))
            },
            None => None,
        };

        info!(
            name = %listener.name,
            address = %listener.address,
            upstream = %upstream.unwrap_or("filter-routed"),
            "TCP listener registered"
        );
        Ok(Self {
            address: listener.address.clone(),
            socket,
            tls,
        })
    }
}

// -----------------------------------------------------------------------------
// Serving
// -----------------------------------------------------------------------------

/// Accept on every socket of a group until `shutdown` flips, then wait for
/// the group's connections to finish.
async fn serve_group(proxy: Arc<PingoraTcpProxy>, sockets: Vec<BoundListener>, shutdown: ShutdownWatch) {
    let accept_loops = sockets
        .into_iter()
        .map(|bound| accept_until_shutdown(Arc::clone(&proxy), bound, shutdown.clone()));
    futures::future::join_all(accept_loops).await;
}

/// Accept connections on `bound`, serving each on its own task, until
/// `shutdown` flips; then stop accepting and wait for those tasks.
///
/// Connections already forwarding watch `shutdown` too and close on the
/// flip, so waiting for them only covers their disconnect filters, metrics
/// and logs.
async fn accept_until_shutdown(proxy: Arc<PingoraTcpProxy>, bound: BoundListener, mut shutdown: ShutdownWatch) {
    let BoundListener { address, socket, tls } = bound;
    let listener = match socket.listen(LISTEN_BACKLOG) {
        Ok(listener) => listener,
        Err(err) => {
            error!(address = %address, error = %err, "TCP listener could not listen; it will not accept");
            return;
        },
    };
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(joined) = connections.join_next(), if !connections.is_empty() => log_connection_end(&joined),
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let connection = handle_connection(Arc::clone(&proxy), stream, peer, tls.clone(), shutdown.clone());
                    connections.spawn(connection);
                },
                Err(err) => accept_failed(&address, &err).await,
            },
        }
    }

    drop(listener);
    info!(address = %address, connections = connections.len(), "TCP listener stopped accepting");
    while let Some(joined) = connections.join_next().await {
        log_connection_end(&joined);
    }
}

/// Serve one accepted connection through `proxy`, completing the TLS
/// handshake first when the listener terminates TLS.
async fn handle_connection(
    proxy: Arc<PingoraTcpProxy>,
    stream: TcpStream,
    peer: SocketAddr,
    tls: Option<TlsAcceptor>,
    shutdown: ShutdownWatch,
) {
    // Pingora disables Nagle on every accepted socket; a proxy forwards
    // bytes as they arrive.
    if let Err(err) = stream.set_nodelay(true) {
        debug!(error = %err, "could not set TCP_NODELAY on the client socket");
    }
    let connection = Connection {
        local_addr: stream
            .local_addr()
            .map_or_else(|_| UNKNOWN_ADDR.to_owned(), |addr| addr.to_string()),
        proxy,
        remote_addr: peer.to_string(),
        shutdown,
    };

    match tls {
        Some(acceptor) => connection.terminate_tls(&acceptor, stream).await,
        None => connection.serve(stream).await,
    }
}

/// An accepted connection and what serving it needs.
struct Connection {
    /// The listener address the client reached, for metrics labels.
    local_addr: String,

    /// The group's proxy.
    proxy: Arc<PingoraTcpProxy>,

    /// The client's address.
    remote_addr: String,

    /// Flips when the runtime shuts down; forwarding stops on it.
    shutdown: ShutdownWatch,
}

impl Connection {
    /// Hand `session` to the proxy.
    ///
    /// The proxy's connection future is large, so it lives on the heap
    /// rather than in the caller's frame.
    async fn serve<S>(&self, session: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        Box::pin(
            self.proxy
                .serve_connection(session, &self.remote_addr, &self.local_addr, &self.shutdown),
        )
        .await;
    }

    /// Complete the TLS handshake on `stream`, then serve the decrypted
    /// session; a failed or stalled handshake ends the connection.
    async fn terminate_tls(&self, acceptor: &TlsAcceptor, stream: TcpStream) {
        // Boxed like the connection future in `serve`: the handshake holds a
        // whole TLS session.
        let handshake = Box::pin(tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)));
        match handshake.await {
            Ok(Ok(session)) => self.serve(session).await,
            Ok(Err(err)) if handshake_was_abandoned(&err) => {
                debug!(remote = %self.remote_addr, error = %err, "downstream TLS handshake abandoned");
            },
            Ok(Err(err)) => warn!(remote = %self.remote_addr, error = %err, "downstream TLS handshake failed"),
            Err(_) => warn!(
                remote = %self.remote_addr,
                timeout_secs = TLS_HANDSHAKE_TIMEOUT.as_secs(),
                "downstream TLS handshake timed out"
            ),
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Log a failed `accept` and pause before the next one: running out of file
/// descriptors fails every retry until a connection closes.
async fn accept_failed(address: &str, err: &io::Error) {
    error!(address, error = %err, "TCP accept failed");
    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
}

/// Whether a failed TLS handshake only means the client went away before
/// finishing it, as a TCP health probe does; Pingora logs those quietly too.
fn handshake_was_abandoned(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Log a connection task that panicked; one that finished needs no log.
fn log_connection_end(joined: &Result<(), JoinError>) {
    if let Err(err) = joined
        && err.is_panic()
    {
        error!(error = %err, "TCP connection task panicked");
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::{
        collections::HashMap,
        io::{Read as _, Write as _},
        net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
        thread,
        time::Instant,
    };

    use praxis_core::server::ServerRuntime as _;
    use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn grouped_listeners_forward_to_the_static_upstream() {
        let echo = echo_backend();
        let (first, second) = (free_addr(), free_addr());
        let config = tcp_config(&format!(
            "{}{}",
            tcp_listener("db-a", &first, &echo, ""),
            tcp_listener("db-b", &second, &echo, "")
        ));
        let _running = start(&config);

        for addr in [&first, &second] {
            let mut client = connect(addr);
            client.write_all(b"hello").unwrap();
            assert_eq!(
                read_exactly(&mut client, 5),
                b"hello",
                "{addr} must forward to the group's upstream and back"
            );
        }
    }

    #[test]
    fn max_duration_closes_a_live_session() {
        let echo = echo_backend();
        let addr = free_addr();
        let config = tcp_config(&tcp_listener("capped", &addr, &echo, "    tcp_max_duration_secs: 1\n"));
        let _running = start(&config);

        let mut client = connect(&addr);
        client.write_all(b"ping").unwrap();
        assert_eq!(read_exactly(&mut client, 4), b"ping", "the session must forward first");
        let started = Instant::now();
        let closed = closed_by_peer(&mut client);

        assert!(closed, "the proxy must close a session at its max duration");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the cut must come from the 1 s max duration, not a later timeout"
        );
    }

    #[test]
    fn shutdown_closes_sessions_in_flight() {
        let echo = echo_backend();
        let addr = free_addr();
        let config = tcp_config(&tcp_listener("draining", &addr, &echo, ""));
        let running = start(&config);

        let mut client = connect(&addr);
        client.write_all(b"ping").unwrap();
        assert_eq!(read_exactly(&mut client, 4), b"ping", "the session must forward first");
        let stopping = Instant::now();
        drop(running);

        assert!(
            stopping.elapsed() < Duration::from_secs(5),
            "the runtime must stop within its fast shutdown bound"
        );
        assert!(
            closed_by_peer(&mut client),
            "a forwarding session must close when the server shuts down"
        );
    }

    #[test]
    fn tls_listener_terminates_before_forwarding() {
        praxis_tls::provider::install();
        let certs = TestCerts::generate();
        let echo = echo_backend();
        let addr = free_addr();
        let config = tcp_config(&tcp_listener("secure", &addr, &echo, &certs.listener_yaml()));
        let _running = start(&config);

        let mut client = certs.connect(&addr);
        client.write_all(b"over tls").unwrap();
        let mut echoed = [0_u8; 8];
        client.read_exact(&mut echoed).unwrap();

        assert_eq!(
            &echoed, b"over tls",
            "TLS payload must reach the upstream decrypted and come back"
        );
    }

    #[test]
    fn tls_listener_survives_clients_that_skip_the_handshake() {
        praxis_tls::provider::install();
        let certs = TestCerts::generate();
        let echo = echo_backend();
        let addr = free_addr();
        let config = tcp_config(&tcp_listener("secure", &addr, &echo, &certs.listener_yaml()));
        let _running = start(&config);

        drop(connect(&addr));
        let mut plaintext = connect(&addr);
        plaintext.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut reply = Vec::new();
        drop(plaintext.read_to_end(&mut reply));
        let mut client = certs.connect(&addr);
        client.write_all(b"still up").unwrap();

        assert!(
            !reply.starts_with(b"GET"),
            "plaintext on a TLS listener must not be forwarded"
        );
        assert_eq!(
            read_exactly(&mut client, 8),
            b"still up",
            "failed handshakes must not stop the listener"
        );
    }

    #[test]
    fn register_fails_naming_an_address_in_use() {
        let occupied = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap().to_string();
        let config = tcp_config(&tcp_listener("taken", &addr, "127.0.0.1:9", ""));
        let mut runtime = HyperRuntime::new(&config);

        let result = HyperTcp::register_on(&mut runtime, &config, &no_pipelines());

        assert!(
            matches!(&result, Err(ProxyError::Config(msg)) if msg.contains(&addr)),
            "a bind failure must name the address, got {result:?}"
        );
    }

    #[test]
    fn register_rejects_inconsistent_groups() {
        let (first, second) = (free_addr(), free_addr());
        let config = tcp_config(&format!(
            "{}{}",
            tcp_listener("db-a", &first, "127.0.0.1:9", "    max_connections: 1\n"),
            tcp_listener("db-b", &second, "127.0.0.1:9", "    max_connections: 2\n")
        ));
        let mut runtime = HyperRuntime::new(&config);

        let result = HyperTcp::register_on(&mut runtime, &config, &no_pipelines());

        assert!(
            matches!(&result, Err(ProxyError::Config(msg)) if msg.contains("max_connections")),
            "grouped listeners with different limits must be rejected, got {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A `HyperRuntime` serving on its own thread until dropped.
    struct Running {
        /// Resolves the runtime's shutdown future.
        stop: Option<oneshot::Sender<()>>,

        /// The thread `run_with_shutdown` blocks.
        thread: Option<thread::JoinHandle<()>>,

        /// Stop the certificate watchers hot-reloading listeners started.
        watchers: Vec<watch::Sender<bool>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
            for watcher in &self.watchers {
                _ = watcher.send(true);
            }
        }
    }

    /// Certificates for a `localhost` TLS listener, signed by a test CA.
    struct TestCerts {
        /// The CA certificate clients trust.
        ca: rustls::pki_types::CertificateDer<'static>,

        /// Path of the server certificate PEM.
        cert_path: String,

        /// Keeps the PEM files alive for the test.
        _dir: tempfile::TempDir,

        /// Path of the server key PEM.
        key_path: String,
    }

    impl TestCerts {
        /// Open a TLS session to `addr` that trusts only the test CA.
        fn connect(&self, addr: &str) -> rustls::StreamOwned<rustls::ClientConnection, StdTcpStream> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.ca.clone()).unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let session = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            rustls::StreamOwned::new(session, connect(addr))
        }

        /// Mint a CA and a `localhost` server certificate it signs.
        fn generate() -> Self {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::from_params(&ca_params, &ca_key);
            let server_key = KeyPair::generate().unwrap();
            let server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
            let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

            let dir = tempfile::TempDir::new().unwrap();
            let cert_path = dir.path().join("server.pem");
            let key_path = dir.path().join("server-key.pem");
            std::fs::write(&cert_path, server_cert.pem()).unwrap();
            std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
            Self {
                ca: ca_cert.der().clone(),
                cert_path: cert_path.to_str().unwrap().to_owned(),
                _dir: dir,
                key_path: key_path.to_str().unwrap().to_owned(),
            }
        }

        /// The listener `tls` YAML serving these certificates.
        fn listener_yaml(&self) -> String {
            format!(
                "    tls:\n      certificates:\n        - cert_path: \"{}\"\n          key_path: \"{}\"\n",
                self.cert_path, self.key_path
            )
        }
    }

    /// Whether the peer closed `stream`: a read sees the end of the stream or
    /// a reset, not data or the read timeout.
    fn closed_by_peer<R: io::Read>(stream: &mut R) -> bool {
        match stream.read(&mut [0_u8; 16]) {
            Ok(read) => read == 0,
            Err(err) => !matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        }
    }

    /// Connect to `addr` once its listener is up, with a read timeout so a
    /// broken proxy fails the test instead of hanging it.
    #[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
    fn connect(addr: &str) -> StdTcpStream {
        let started = Instant::now();
        let stream = loop {
            match StdTcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(err) => {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "{addr} never started listening: {err}"
                    );
                    thread::sleep(Duration::from_millis(10));
                },
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    /// Start a loopback echo server and return its address.
    fn echo_backend() -> String {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut writer) = stream else { break };
                let mut reader = writer.try_clone().unwrap();
                thread::spawn(move || io::copy(&mut reader, &mut writer));
            }
        });
        addr
    }

    /// A loopback address with a port nothing is listening on right now.
    fn free_addr() -> String {
        let probe = StdTcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().to_string()
    }

    /// Pipelines with no listener entries, so every group runs the fallback.
    fn no_pipelines() -> ListenerPipelines {
        ListenerPipelines::new(HashMap::new())
    }

    /// Read exactly `len` bytes from `stream`.
    fn read_exactly<R: io::Read>(stream: &mut R, len: usize) -> Vec<u8> {
        let mut buf = vec![0_u8; len];
        stream.read_exact(&mut buf).unwrap();
        buf
    }

    /// Register `config`'s TCP listeners on a fresh runtime and start it.
    fn start(config: &Config) -> Running {
        let mut runtime = HyperRuntime::new(config);
        let watchers = HyperTcp::register_on(&mut runtime, config, &no_pipelines()).unwrap();

        let (stop, stopped) = oneshot::channel::<()>();
        let thread = thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = stopped.await;
            }));
        });
        Running {
            stop: Some(stop),
            thread: Some(thread),
            watchers,
        }
    }

    /// A config of `listeners` YAML on a small runtime that may dial loopback.
    fn tcp_config(listeners: &str) -> Config {
        Config::from_yaml(&format!(
            "runtime:\n  threads: 2\ninsecure_options:\n  allow_private_upstreams: true\nlisteners:\n{listeners}"
        ))
        .unwrap()
    }

    /// One static-upstream TCP listener entry, with `extra` YAML appended.
    fn tcp_listener(name: &str, addr: &str, upstream: &str, extra: &str) -> String {
        format!("  - name: {name}\n    address: \"{addr}\"\n    protocol: tcp\n    upstream: \"{upstream}\"\n{extra}")
    }
}
