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
///
/// Certificates are written to a temporary directory that is
/// cleaned up on drop. The cert is valid for `localhost` and
/// `127.0.0.1`.
pub struct TestCertificates {
    /// Path to the PEM-encoded server certificate file.
    pub cert_path: PathBuf,

    /// Path to the PEM-encoded server private key file.
    pub key_path: PathBuf,

    /// DER-encoded CA certificate for client trust configuration.
    pub ca_cert_der: Vec<u8>,

    /// Temporary directory holding the cert files. Cleaned up on drop.
    _temp_dir: TempDir,
}

impl TestCertificates {
    /// Generate a self-signed CA and server certificate pair.
    ///
    /// The server cert is signed by the CA and is valid for
    /// `localhost` and `127.0.0.1`.
    pub fn generate() -> Self {
        let ca_key = KeyPair::generate().expect("CA key generation");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Praxis Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

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

        std::fs::write(&cert_path, server_cert.pem()).expect("write cert PEM");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("write key PEM");

        Self {
            cert_path,
            key_path,
            ca_cert_der: ca_cert.der().to_vec(),
            _temp_dir: temp_dir,
        }
    }

    /// Build a [`rustls::ClientConfig`] that trusts this test CA.
    ///
    /// Configures ALPN with `h2` since Pingora always negotiates
    /// HTTP/2 over TLS via its `TlsSettings::intermediate` profile.
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

    /// Build a [`rustls::ClientConfig`] without ALPN for raw TLS
    /// connections (TCP TLS tests, not HTTP).
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
}

// -----------------------------------------------------------------------------
// HTTPS Client (HTTP/2 over TLS)
// -----------------------------------------------------------------------------

/// Send an HTTP GET over TLS (HTTP/2) and return `(status, body)`.
///
/// Pingora negotiates HTTP/2 via ALPN on TLS listeners, so this
/// function uses the [`h2`] crate for proper framing.
///
/// Uses a blocking [`tokio::runtime::Runtime`] internally so it
/// can be called from synchronous test functions.
///
/// [`h2`]: h2
/// [`tokio::runtime::Runtime`]: tokio::runtime::Runtime
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
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut tls, &mut buf).await;
        buf
    })
}

// -----------------------------------------------------------------------------
// TLS Readiness
// -----------------------------------------------------------------------------

/// Block until a TLS handshake to `addr` succeeds, or panic
/// after 5 seconds.
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
async fn try_h2_get_inner(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> Option<(u16, String)> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").ok()?;

    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let tls = connector.connect(server_name, tcp).await.ok()?;

    let (mut client, h2_conn) = h2::client::handshake(tls).await.ok()?;
    tokio::spawn(async move {
        let _ = h2_conn.await;
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
// TLS TCP Backend
// -----------------------------------------------------------------------------

/// Start a raw TCP echo server that speaks plain TCP (no TLS).
///
/// Echoes back whatever data the client sends. Used as an
/// upstream backend for TLS-terminating proxy tests.
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
