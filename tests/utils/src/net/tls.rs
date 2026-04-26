// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! TLS certificate generation and client utilities for integration tests.

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::ClientConfig;
use tempfile::TempDir;

// -----------------------------------------------------------------------------
// TestCertificates
// -----------------------------------------------------------------------------

/// Self-signed test CA and server certificate files.
pub struct TestCertificates {
    /// Path to the PEM-encoded server certificate file.
    pub cert_path: PathBuf,

    /// Path to the PEM-encoded server private key file.
    pub key_path: PathBuf,

    /// Path to the PEM-encoded CA certificate file.
    pub ca_cert_path: PathBuf,

    /// DER-encoded CA certificate for client trust configuration.
    pub ca_cert_der: Vec<u8>,

    /// DER-encoded server certificate for identity comparison.
    pub server_cert_der: Vec<u8>,

    /// The rcgen CA certificate for signing additional certificates.
    ca_cert: rcgen::Certificate,

    /// The rcgen CA key pair for signing additional certificates.
    ca_key: KeyPair,

    /// Temporary directory holding cert files; cleaned up on drop.
    temp_dir: TempDir,
}

impl TestCertificates {
    /// Generate a self-signed CA and server certificate pair.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    pub fn generate() -> Self {
        let (ca_key, ca_cert) = generate_ca("Praxis Test CA");

        let server_key = KeyPair::generate().expect("server key generation");
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert sign");

        let temp_dir = TempDir::new().expect("tempdir creation");
        let cert_path = temp_dir.path().join("server.pem");
        let key_path = temp_dir.path().join("server-key.pem");
        let ca_cert_path = temp_dir.path().join("ca.pem");

        std::fs::write(&cert_path, server_cert.pem()).expect("write cert PEM");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("write key PEM");
        std::fs::write(&ca_cert_path, ca_cert.pem()).expect("write CA PEM");

        let server_cert_der = server_cert.der().to_vec();

        Self {
            cert_path,
            key_path,
            ca_cert_path,
            ca_cert_der: ca_cert.der().to_vec(),
            server_cert_der,
            ca_cert,
            ca_key,
            temp_dir,
        }
    }

    /// Generate a self-signed CA and server certificate with a custom SAN hostname.
    ///
    /// The server certificate includes both the given `san` as a DNS SAN and
    /// `127.0.0.1` as an IP SAN, so it is reachable on loopback.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    #[allow(clippy::too_many_lines, reason = "cert generation steps")]
    pub fn generate_for_san(san: &str) -> Self {
        let (ca_key, ca_cert) = generate_ca(&format!("Praxis Test CA ({san})"));

        let server_key = KeyPair::generate().expect("server key generation");
        let mut server_params = CertificateParams::new(vec![san.to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, san);
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert sign");

        let temp_dir = TempDir::new().expect("tempdir creation");
        let cert_path = temp_dir.path().join("server.pem");
        let key_path = temp_dir.path().join("server-key.pem");
        let ca_cert_path = temp_dir.path().join("ca.pem");

        std::fs::write(&cert_path, server_cert.pem()).expect("write cert PEM");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("write key PEM");
        std::fs::write(&ca_cert_path, ca_cert.pem()).expect("write CA PEM");

        let server_cert_der = server_cert.der().to_vec();

        Self {
            cert_path,
            key_path,
            ca_cert_path,
            ca_cert_der: ca_cert.der().to_vec(),
            server_cert_der,
            ca_cert,
            ca_key,
            temp_dir,
        }
    }

    /// Build a [`rustls::ClientConfig`] that trusts this test CA.
    ///
    /// # Panics
    ///
    /// Panics if the CA certificate cannot be added to the root store.
    ///
    /// [`rustls::ClientConfig`]: rustls::ClientConfig
    pub fn client_config(&self) -> Arc<ClientConfig> {
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        Arc::new(config)
    }

    /// Build a [`rustls::ClientConfig`] without ALPN for raw TLS connections (TCP TLS tests, not HTTP).
    ///
    /// # Panics
    ///
    /// Panics if the CA certificate cannot be added to the root store.
    ///
    /// [`rustls::ClientConfig`]: rustls::ClientConfig
    pub fn raw_tls_client_config(&self) -> Arc<ClientConfig> {
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    /// Generate a client certificate signed by this test CA.
    ///
    /// Returns a [`ClientCert`] with paths written into the same temp directory.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    ///
    /// [`ClientCert`]: ClientCert
    pub fn generate_client_cert(&self) -> ClientCert {
        let client_key = KeyPair::generate().expect("client key generation");
        let mut client_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("client cert params");
        client_params.distinguished_name.push(DnType::CommonName, "Test Client");
        let client_cert = client_params
            .signed_by(&client_key, &self.ca_cert, &self.ca_key)
            .expect("client cert sign");

        let cert_path = self.temp_dir.path().join("client.pem");
        let key_path = self.temp_dir.path().join("client-key.pem");

        std::fs::write(&cert_path, client_cert.pem()).expect("write client cert PEM");
        std::fs::write(&key_path, client_key.serialize_pem()).expect("write client key PEM");

        ClientCert { cert_path, key_path }
    }

    /// Build a [`rustls::ClientConfig`] that presents a client certificate (for mTLS).
    ///
    /// Includes HTTP/2 ALPN negotiation. For raw TCP mTLS, use
    /// [`raw_tls_client_config_with_cert`] instead.
    ///
    /// # Panics
    ///
    /// Panics if the CA certificate or client cert/key cannot be loaded.
    ///
    /// [`rustls::ClientConfig`]: rustls::ClientConfig
    /// [`raw_tls_client_config_with_cert`]: Self::raw_tls_client_config_with_cert
    pub fn client_config_with_cert(&self, client_cert: &ClientCert) -> Arc<ClientConfig> {
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
        let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client cert PEM");
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("parse client key PEM")
            .expect("no client private key found");

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .expect("build client auth config");
        config.alpn_protocols = vec![b"h2".to_vec()];

        Arc::new(config)
    }

    /// Build a [`rustls::ClientConfig`] with a client certificate but without ALPN.
    ///
    /// Suitable for raw TCP mTLS connections (not HTTP).
    ///
    /// # Panics
    ///
    /// Panics if the CA certificate or client cert/key cannot be loaded.
    ///
    /// [`rustls::ClientConfig`]: rustls::ClientConfig
    pub fn raw_tls_client_config_with_cert(&self, client_cert: &ClientCert) -> Arc<ClientConfig> {
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
        let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client cert PEM");
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("parse client key PEM")
            .expect("no client private key found");

        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .expect("build raw mTLS client config"),
        )
    }
}

/// A generated client certificate and key for mTLS testing.
pub struct ClientCert {
    /// Path to the PEM-encoded client certificate file.
    pub cert_path: PathBuf,

    /// Path to the PEM-encoded client private key file.
    pub key_path: PathBuf,
}

// -----------------------------------------------------------------------------
// CA Generation
// -----------------------------------------------------------------------------

/// Generate a self-signed CA certificate and key pair.
fn generate_ca(cn: &str) -> (KeyPair, rcgen::Certificate) {
    let ca_key = KeyPair::generate().expect("CA key generation");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, cn);
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
    (ca_key, ca_cert)
}

// -----------------------------------------------------------------------------
// HTTPS Client (HTTP/2 over TLS)
// -----------------------------------------------------------------------------

/// Send an HTTP GET over TLS and return `(status, body)`.
///
/// # Panics
///
/// Panics if the TLS connection or HTTP/2 handshake fails.
pub fn https_get(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> (u16, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async { h2_get(addr, path, client_config).await })
}

/// Perform an HTTP/2 GET over TLS.
async fn h2_get(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> (u16, String) {
    let tls = tls_connect(addr, client_config).await;

    let (mut client, h2_conn) = h2::client::handshake(tls).await.expect("H2 handshake");
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::debug!(error = %e, "H2 connection closed");
        }
    });

    let request = http::Request::get(path)
        .header("host", "localhost")
        .body(())
        .expect("build H2 request");

    let (response_fut, _) = client.send_request(request, true).expect("send H2 request");
    let response = response_fut.await.expect("H2 response");
    let status = response.status().as_u16();
    let mut body_stream = response.into_body();

    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let data = chunk.expect("H2 body chunk");
        body.extend_from_slice(&data);
        body_stream.flow_control().release_capacity(data.len()).ok();
    }

    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Establish a TLS connection to `addr` using the given client config.
async fn tls_connect(
    addr: &str,
    client_config: &Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
    connector.connect(server_name, tcp).await.expect("TLS handshake")
}

// -----------------------------------------------------------------------------
// Raw TLS (for TCP proxy tests)
// -----------------------------------------------------------------------------

/// Send raw data over TLS and return the response bytes.
///
/// Used for TCP TLS tests where the payload is not HTTP.
///
/// # Panics
///
/// Panics if the TLS connection or data transfer fails.
pub fn tls_send_recv(addr: &str, data: &[u8], client_config: &Arc<ClientConfig>) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let mut tls = connector.connect(server_name, tcp).await.expect("TLS handshake");

        tokio::io::AsyncWriteExt::write_all(&mut tls, data)
            .await
            .expect("TLS write");
        tokio::io::AsyncWriteExt::shutdown(&mut tls)
            .await
            .expect("TLS shutdown");

        let mut buf = Vec::new();
        let _bytes = tokio::io::AsyncReadExt::read_to_end(&mut tls, &mut buf).await;
        buf
    })
}

/// Attempt a TLS connection, send data, and return `true` if the
/// connection is rejected at any stage (handshake, write, or empty
/// response).
///
/// Used for negative mTLS tests where the server should refuse
/// the connection (e.g. missing client certificate).
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created.
pub fn tls_connection_rejected(addr: &str, data: &[u8], client_config: &Arc<ClientConfig>) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

        let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
            return true;
        };
        let Ok(mut tls) = connector.connect(server_name, tcp).await else {
            return true;
        };

        if tokio::io::AsyncWriteExt::write_all(&mut tls, data).await.is_err() {
            return true;
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;

        let mut buf = Vec::new();
        match tokio::io::AsyncReadExt::read_to_end(&mut tls, &mut buf).await {
            Ok(0) | Err(_) => true,
            Ok(_) => buf.is_empty(),
        }
    })
}

// -----------------------------------------------------------------------------
// TLS Readiness
// -----------------------------------------------------------------------------

/// Block until a TLS handshake to `addr` succeeds, or panic
/// after 5 seconds.
///
/// # Panics
///
/// Panics if the server does not become ready within 5 seconds.
pub fn wait_for_tls(addr: &str, client_config: &Arc<ClientConfig>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    for _ in 0..500 {
        let result = rt.block_on(async {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
            let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

            let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                return false;
            };
            connector.connect(server_name, tcp).await.is_ok()
        });
        if result {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("TLS server at {addr} did not become ready within 5s");
}

/// Block until an HTTPS (HTTP/2 over TLS) request to `addr`
/// gets a valid response, or panic after 5 seconds.
///
/// # Panics
///
/// Panics if the server does not return valid HTTP within 5 seconds.
pub fn wait_for_https(addr: &str, client_config: &Arc<ClientConfig>) {
    for _ in 0..500 {
        if let Some((status, _)) = try_h2_get(addr, "/", client_config)
            && status > 0
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("HTTPS server at {addr} did not return valid HTTP within 5s");
}

/// Attempt an H2-over-TLS GET, returning `None` on any failure.
fn try_h2_get(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> Option<(u16, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async {
        let result = tokio::time::timeout(Duration::from_secs(2), try_h2_get_inner(addr, path, client_config)).await;
        result.ok().flatten()
    })
}

/// Inner fallible H2 GET that returns `None` instead of panicking.
#[allow(clippy::cognitive_complexity, reason = "handshake sequence")]
async fn try_h2_get_inner(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> Option<(u16, String)> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").ok()?;

    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let tls = connector.connect(server_name, tcp).await.ok()?;

    let (mut client, h2_conn) = h2::client::handshake(tls).await.ok()?;
    tokio::spawn(async move {
        let _conn = h2_conn.await;
    });

    let request = http::Request::get(path).header("host", "localhost").body(()).ok()?;

    let (response_fut, _) = client.send_request(request, true).ok()?;
    let response = response_fut.await.ok()?;
    let status = response.status().as_u16();
    let mut body_stream = response.into_body();

    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let Ok(data) = chunk else { break };
        body.extend_from_slice(&data);
        body_stream.flow_control().release_capacity(data.len()).ok();
    }

    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

// -----------------------------------------------------------------------------
// TLS HTTP Backend
// -----------------------------------------------------------------------------

/// Start an HTTP backend that speaks TLS (HTTPS). Returns a fixed
/// response body to any request.
///
/// # Panics
///
/// Panics if TLS server setup or binding fails.
pub fn start_tls_backend(certs: &TestCertificates, body: &str) -> u16 {
    let acceptor = build_tls_acceptor(certs);
    let body = body.to_owned();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TLS backend");
    let port = listener.local_addr().expect("TLS backend port").port();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for TLS backend");
        rt.block_on(tls_accept_loop(listener, acceptor, body));
    });

    port
}

/// Build a [`TlsAcceptor`] from test certificate files.
///
/// [`TlsAcceptor`]: tokio_rustls::TlsAcceptor
fn build_tls_acceptor(certs: &TestCertificates) -> tokio_rustls::TlsAcceptor {
    let certs_pem = std::fs::read(&certs.cert_path).expect("read cert PEM");
    let key_pem = std::fs::read(&certs.key_path).expect("read key PEM");

    let certs = rustls_pemfile::certs(&mut &certs_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert PEM");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse key PEM")
        .expect("no private key found");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build TLS server config");

    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

/// Start an HTTP backend that requires mTLS (client cert verification).
///
/// # Panics
///
/// Panics if TLS server setup or binding fails.
pub fn start_mtls_backend(certs: &TestCertificates, body: &str) -> u16 {
    let acceptor = build_mtls_acceptor(certs);
    let body = body.to_owned();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mTLS backend");
    let port = listener.local_addr().expect("mTLS backend port").port();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for mTLS backend");
        rt.block_on(tls_accept_loop(listener, acceptor, body));
    });

    port
}

/// Build a [`TlsAcceptor`] that requires client certificates.
///
/// [`TlsAcceptor`]: tokio_rustls::TlsAcceptor
fn build_mtls_acceptor(certs: &TestCertificates) -> tokio_rustls::TlsAcceptor {
    let certs_pem = std::fs::read(&certs.cert_path).expect("read cert PEM");
    let key_pem = std::fs::read(&certs.key_path).expect("read key PEM");

    let server_certs = rustls_pemfile::certs(&mut &certs_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert PEM");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("parse key PEM")
        .expect("no private key found");

    let ca_der = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_der).expect("add CA to mTLS root store");

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .expect("build mTLS client verifier");

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .expect("build mTLS server config");

    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
}

/// Accept TLS connections and serve fixed HTTP responses.
async fn tls_accept_loop(listener: std::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor, body: String) {
    listener.set_nonblocking(true).expect("set non-blocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(tls_stream) = acceptor.accept(stream).await else {
            continue;
        };
        let body = body.clone();
        tokio::spawn(async move {
            handle_tls_http(tls_stream, &body).await;
        });
    }
}

/// Handle a single TLS HTTP connection: read headers, write response.
async fn handle_tls_http(mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, body: &str) {
    let mut buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        match tokio::io::AsyncReadExt::read(&mut stream, &mut buf[total..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
}

// -----------------------------------------------------------------------------
// TLS TCP Backend
// -----------------------------------------------------------------------------

/// Start a raw TCP echo server that speaks plain TCP (no TLS).
///
/// Echoes back whatever data the client sends. Used as an
/// upstream backend for TLS-terminating proxy tests.
///
/// # Panics
///
/// Panics if binding to the loopback address fails.
pub fn start_tcp_echo_backend() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo backend");
    let port = listener.local_addr().expect("echo backend port").port();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_echo(stream);
            });
        }
    });

    port
}

/// Echo handler for a single TCP connection.
fn handle_echo(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            },
        }
    }
}

/// Start a raw TCP backend that reads one message and responds with
/// `tag` followed by the received data. Used to identify which
/// backend handled a connection in load balancing tests.
///
/// # Panics
///
/// Panics if binding to the loopback address fails.
pub fn start_tcp_tagged_backend(tag: &str) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tagged backend");
    let port = listener.local_addr().expect("tagged backend port").port();
    let tag = tag.to_owned();

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tag = tag.clone();
            std::thread::spawn(move || {
                handle_tagged(stream, &tag);
            });
        }
    });

    port
}

/// Tagged handler: read one chunk, respond with `tag:data`.
fn handle_tagged(mut stream: TcpStream, tag: &str) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) => {},
        Ok(n) => {
            let mut resp = Vec::with_capacity(tag.len() + 1 + n);
            resp.extend_from_slice(tag.as_bytes());
            resp.push(b':');
            resp.extend_from_slice(&buf[..n]);
            let _ = stream.write_all(&resp);
        },
    }
}
