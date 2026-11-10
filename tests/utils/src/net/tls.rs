// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS certificate generation and client utilities for integration tests.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls::{ClientConfig, pki_types::pem::PemObject as _};
use tempfile::TempDir;
use tokio::net::TcpStream as AsyncTcpStream;

use crate::net::wait::{DEFAULT_HTTP_TIMEOUT, poll_until_ready, ready_timeout};

// -----------------------------------------------------------------------------
// TestCertificates
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// CryptoProvider
// -----------------------------------------------------------------------------

/// Install the rustls [`CryptoProvider`] for test environments.
///
/// Delegates to [`praxis_tls::provider::install`] so tests exercise whichever
/// provider the build selected, rather than pinning one of their own. rustls
/// has no implicit fallback — the Pingora fork enables `custom-provider` — so
/// a test that builds any config must install one first. Safe to call
/// multiple times; subsequent calls are no-ops.
///
/// Previously this installed `ring` directly, on the basis that "both `ring`
/// and `aws-lc-rs` features are enabled transitively via Pingora". That
/// stopped being true when ring was removed from the fork, and it meant the
/// integration suite had been running on a provider nobody selected.
///
/// When `PRAXIS_FIPS_HOST` declares the host to be in FIPS mode, this also
/// fails closed unless the process is: see [`crate::fips`].
///
/// # Panics
///
/// Panics when `PRAXIS_FIPS_HOST` is set on a host that is not in FIPS mode.
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
pub fn ensure_crypto_provider() {
    praxis_tls::provider::install();
    crate::fips::assert_fips_host_if_declared();
}

/// Parse a PEM certificate chain and private key into rustls DER types.
///
/// # Panics
///
/// Panics if either input fails to parse or contains no matching PEM
/// sections.
pub fn parse_cert_chain_and_key(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    use rustls::pki_types::pem::PemObject as _;

    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert PEM");
    assert!(!certs.is_empty(), "no certificates found in PEM");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem).expect("parse key PEM");
    (certs, key)
}

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

    /// The rcgen CA certificate parameters for building issuers.
    ca_params: CertificateParams,

    /// The rcgen CA key pair for signing additional certificates.
    ca_key: KeyPair,

    /// Counter for generating unique client certificate filenames.
    client_cert_counter: AtomicUsize,

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
        Self::generate_with(|_server_params| {})
    }

    /// Like [`generate`], except the server certificate was only valid
    /// during the year 2000, so verifying it fails on its dates alone.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    ///
    /// [`generate`]: TestCertificates::generate
    pub fn generate_expired() -> Self {
        Self::generate_with(|server_params| {
            server_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            server_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        })
    }

    /// Generate a CA and a `localhost` server certificate, letting
    /// `customize` adjust the server certificate before it is signed.
    fn generate_with<F: FnOnce(&mut CertificateParams)>(customize: F) -> Self {
        let (ca_key, ca_params, ca_cert) = generate_ca("Praxis Test CA");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().expect("server key generation");
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        customize(&mut server_params);
        let server_cert = server_params.signed_by(&server_key, &issuer).expect("server cert sign");

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
            ca_params,
            ca_key,
            client_cert_counter: AtomicUsize::new(0),
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
    pub fn generate_for_san(san: &str) -> Self {
        let (ca_key, ca_params, ca_cert) = generate_ca(&format!("Praxis Test CA ({san})"));
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().expect("server key generation");
        let mut server_params = CertificateParams::new(vec![san.to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, san);
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let server_cert = server_params.signed_by(&server_key, &issuer).expect("server cert sign");

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
            ca_params,
            ca_key,
            client_cert_counter: AtomicUsize::new(0),
            temp_dir,
        }
    }

    /// Generate a self-signed CA and server certificate with ONLY a DNS SAN and
    /// NO loopback IP SAN, so IP-literal SNI validation fails against it.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    pub fn generate_dns_only(san: &str) -> Self {
        let (ca_key, ca_params, ca_cert) = generate_ca(&format!("Praxis Test CA (dns-only {san})"));
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key = KeyPair::generate().expect("server key generation");
        let mut server_params = CertificateParams::new(vec![san.to_owned()]).expect("server params");
        server_params.distinguished_name.push(DnType::CommonName, san);
        // Deliberately NO IP SAN.
        let server_cert = server_params.signed_by(&server_key, &issuer).expect("server cert sign");

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
            ca_params,
            ca_key,
            client_cert_counter: AtomicUsize::new(0),
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
        ensure_crypto_provider();
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
        ensure_crypto_provider();
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    /// Generate a client certificate with a specific `OrganizationName` (O= field).
    ///
    /// The cert is signed by this test CA so the TLS handshake succeeds.
    /// Setting a custom org is useful for testing org-based access decisions.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    pub fn generate_client_cert_with_org(&self, org: &str) -> ClientCert {
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let client_key = KeyPair::generate().expect("client key generation");
        let mut client_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("client cert params");
        client_params.distinguished_name.push(DnType::CommonName, "Test Client");
        client_params.distinguished_name.push(DnType::OrganizationName, org);
        let client_cert = client_params.signed_by(&client_key, &issuer).expect("client cert sign");

        let n = self.client_cert_counter.fetch_add(1, Ordering::Relaxed);
        let cert_path = self.temp_dir.path().join(format!("client-org-{n}.pem"));
        let key_path = self.temp_dir.path().join(format!("client-org-{n}-key.pem"));

        std::fs::write(&cert_path, client_cert.pem()).expect("write client cert PEM");
        std::fs::write(&key_path, client_key.serialize_pem()).expect("write client key PEM");

        ClientCert { cert_path, key_path }
    }

    /// Generate a client certificate carrying `spiffe_id` as its sole URI SAN,
    /// signed by this test CA. Useful for exercising `RequireNamed` listeners.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation or file I/O fails.
    pub fn generate_client_cert_with_spiffe_id(&self, spiffe_id: &str) -> ClientCert {
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let client_key = KeyPair::generate().expect("client key generation");
        // A conforming X.509-SVID leaf: sole URI SAN, no DNS SAN, critical keyUsage
        // with digitalSignature, and an EKU with both serverAuth and clientAuth.
        let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client cert params");
        client_params.distinguished_name.push(DnType::CommonName, "Test Client");
        client_params
            .subject_alt_names
            .push(SanType::URI(spiffe_id.try_into().expect("spiffe uri san")));
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &issuer).expect("client cert sign");

        let n = self.client_cert_counter.fetch_add(1, Ordering::Relaxed);
        let cert_path = self.temp_dir.path().join(format!("client-svid-{n}.pem"));
        let key_path = self.temp_dir.path().join(format!("client-svid-{n}-key.pem"));

        std::fs::write(&cert_path, client_cert.pem()).expect("write client cert PEM");
        std::fs::write(&key_path, client_key.serialize_pem()).expect("write client key PEM");

        ClientCert { cert_path, key_path }
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
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);
        let client_key = KeyPair::generate().expect("client key generation");
        let mut client_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("client cert params");
        client_params.distinguished_name.push(DnType::CommonName, "Test Client");
        let client_cert = client_params.signed_by(&client_key, &issuer).expect("client cert sign");

        let n = self.client_cert_counter.fetch_add(1, Ordering::Relaxed);
        let cert_path = self.temp_dir.path().join(format!("client-{n}.pem"));
        let key_path = self.temp_dir.path().join(format!("client-{n}-key.pem"));

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
        ensure_crypto_provider();
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
        let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

        let (certs, key) = parse_cert_chain_and_key(&cert_pem, &key_pem);

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
        ensure_crypto_provider();
        let ca = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca).expect("add CA to root store");

        let cert_pem = std::fs::read(&client_cert.cert_path).expect("read client cert PEM");
        let key_pem = std::fs::read(&client_cert.key_path).expect("read client key PEM");

        let (certs, key) = parse_cert_chain_and_key(&cert_pem, &key_pem);

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

/// Generate a self-signed CA certificate, parameters, and key pair.
///
/// Also installs the crypto provider: tests build rustls client configs
/// from these certificates, often before any proxy has started.
fn generate_ca(cn: &str) -> (KeyPair, CertificateParams, rcgen::Certificate) {
    ensure_crypto_provider();
    let ca_key = KeyPair::generate().expect("CA key generation");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, cn);
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
    (ca_key, ca_params, ca_cert)
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
    https_get_attempt(addr, path, client_config).expect("HTTPS request")
}

/// Perform one HTTPS GET and return transport errors to the caller.
///
/// # Errors
///
/// Returns an error when the runtime, TLS connection, or HTTP/2 exchange fails.
pub fn https_get_attempt(
    addr: &str,
    path: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let request = runtime.block_on(async {
        Box::pin(tokio::time::timeout(
            DEFAULT_HTTP_TIMEOUT,
            h2_get(addr, path, client_config, usize::MAX),
        ))
        .await
    });
    request.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?
}

/// Perform one HTTPS GET on a caller-owned runtime.
///
/// Continuous load drivers own a single runtime so per-request setup does not
/// dominate the load they generate. Health responses are capped at a small
/// body so a misbehaving peer cannot exhaust the test runner.
///
/// # Errors
///
/// Returns an error when the TLS connection or HTTP/2 exchange fails.
pub fn https_get_attempt_on(
    runtime: &tokio::runtime::Runtime,
    addr: &str,
    path: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let request = runtime.block_on(async {
        Box::pin(tokio::time::timeout(
            DEFAULT_HTTP_TIMEOUT,
            h2_get(addr, path, client_config, HEALTH_BODY_LIMIT),
        ))
        .await
    });
    request.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?
}

/// Largest health response body the continuous HTTPS worker retains.
const HEALTH_BODY_LIMIT: usize = 64;

/// Perform an HTTP/2 GET over TLS.
#[expect(clippy::large_stack_frames, reason = "test utility with H2 handshake structs")]
async fn h2_get(
    addr: &str,
    path: &str,
    client_config: &Arc<ClientConfig>,
    max_body: usize,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let tls = tls_connect(addr, client_config).await?;

    let (mut client, h2_conn) = h2::client::handshake(tls).await?;
    tokio::spawn(async move {
        if let Err(e) = h2_conn.await {
            tracing::debug!(error = %e, "H2 connection closed");
        }
    });

    let port = addr.rsplit_once(':').map_or("443", |(_, port)| port);
    let mut request = http::Request::get(format!("https://localhost:{port}{path}")).body(())?;
    *request.version_mut() = http::Version::HTTP_2;

    let (response_fut, _) = client.send_request(request, true)?;
    let response = response_fut.await?;
    let status = response.status().as_u16();
    let mut body_stream = response.into_body();

    let mut body = Vec::new();
    while body.len() < max_body {
        let Some(chunk) = body_stream.data().await else { break };
        let data = chunk?;
        let keep = (max_body - body.len()).min(data.len());
        body.extend_from_slice(&data[..keep]);
        drop(body_stream.flow_control().release_capacity(data.len()));
    }

    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// Establish a TLS connection to `addr` using the given client config.
async fn tls_connect(
    addr: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    Ok(connector.connect(server_name, tcp).await?)
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

/// Block until a TLS handshake to `addr` succeeds, or panic once the
/// readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `PRAXIS_TEST_READY_TIMEOUT_MS`.
///
/// # Panics
///
/// Panics if the server does not become ready before the deadline.
pub fn wait_for_tls(addr: &str, client_config: &Arc<ClientConfig>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);

    let ready = poll_until_ready(timeout, || {
        rt.block_on(async {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
            let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

            let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                return false;
            };
            connector.connect(server_name, tcp).await.is_ok()
        })
    });

    assert!(ready, "TLS server at {addr} did not become ready within {timeout:?}");
}

/// Block until an HTTPS (HTTP/2 over TLS) request to `addr` gets a valid
/// response, or panic once the readiness deadline (default 5 seconds) passes.
///
/// Override the deadline with `PRAXIS_TEST_READY_TIMEOUT_MS`.
///
/// # Panics
///
/// Panics if the server does not return valid HTTP before the deadline.
pub fn wait_for_https(addr: &str, client_config: &Arc<ClientConfig>) {
    let timeout = ready_timeout(DEFAULT_HTTP_TIMEOUT);

    let ready = poll_until_ready(
        timeout,
        || matches!(try_h2_get(addr, "/", client_config), Some((status, _)) if status > 0),
    );

    assert!(
        ready,
        "HTTPS server at {addr} did not return valid HTTP within {timeout:?}"
    );
}

/// Attempt an H2-over-TLS GET, returning `None` on any failure.
fn try_h2_get(addr: &str, path: &str, client_config: &Arc<ClientConfig>) -> Option<(u16, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    rt.block_on(async {
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            Box::pin(try_h2_get_inner(addr, path, client_config)),
        )
        .await;
        result.ok().flatten()
    })
}

/// Inner fallible H2 GET that returns `None` instead of panicking.
#[expect(clippy::large_stack_frames, reason = "test utility with H2 handshake structs")]
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
        drop(body_stream.flow_control().release_capacity(data.len()));
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
    let cert_pem = std::fs::read(&certs.cert_path).expect("read cert PEM");
    let key_pem = std::fs::read(&certs.key_path).expect("read key PEM");
    start_tls_backend_from_pem(&cert_pem, &key_pem, body)
}

/// Start an HTTPS backend presenting the given PEM certificate chain and
/// key, for tests that need a backend with a particular certificate (a
/// fixture with a weak key or a legacy signature, say).
///
/// # Panics
///
/// Panics if TLS server setup or binding fails.
pub fn start_tls_backend_from_pem(cert_pem: &[u8], key_pem: &[u8], body: &str) -> u16 {
    let acceptor = build_tls_acceptor(cert_pem, key_pem);
    let body = body.to_owned();

    let (listener, port) = crate::net::port::bind_unique_port();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for TLS backend");
        rt.block_on(tls_accept_loop(listener, acceptor, body));
    });

    port
}

/// Build a [`TlsAcceptor`] from a PEM certificate chain and key.
///
/// [`TlsAcceptor`]: tokio_rustls::TlsAcceptor
fn build_tls_acceptor(certs_pem: &[u8], key_pem: &[u8]) -> tokio_rustls::TlsAcceptor {
    ensure_crypto_provider();
    let (certs, key) = parse_cert_chain_and_key(certs_pem, key_pem);

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

    let (listener, port) = crate::net::port::bind_unique_port();

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
    ensure_crypto_provider();
    let certs_pem = std::fs::read(&certs.cert_path).expect("read cert PEM");
    let key_pem = std::fs::read(&certs.key_path).expect("read key PEM");

    let (server_certs, key) = parse_cert_chain_and_key(&certs_pem, &key_pem);

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
#[expect(clippy::infinite_loop, reason = "server accept loop runs until task cancellation")]
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
    let mut buf = vec![0_u8; 4096];
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
    let (listener, port) = crate::net::port::bind_unique_port();

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
    let mut buf = [0_u8; 4096];
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
    let (listener, port) = crate::net::port::bind_unique_port();
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

/// Reads the serial number of the certificate served over TLS.
///
/// # Errors
///
/// Returns an error when the TLS connection, certificate extraction, or
/// certificate parsing fails.
pub fn tls_serial(endpoint: &str, trusted_certificates: &[PathBuf]) -> Result<String, String> {
    let connector = tokio_rustls::TlsConnector::from(https_client_config(trusted_certificates)?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build TLS probe runtime: {error}"))?;
    let handshake = tls_peer_serial(endpoint, connector);
    runtime.block_on(async {
        match tokio::time::timeout(Duration::from_secs(5), handshake).await {
            Ok(result) => result,
            Err(error) => Err(format!("TLS probe timed out: {error}")),
        }
    })
}

/// Reads the serial number from the certificate presented by one TLS peer.
async fn tls_peer_serial(endpoint: &str, connector: tokio_rustls::TlsConnector) -> Result<String, String> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|error| format!("build TLS server name: {error}"))?;
    let stream = AsyncTcpStream::connect(endpoint)
        .await
        .map_err(|error| format!("connect over TLS: {error}"))?;
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("complete TLS handshake: {error}"))?;
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| "TLS peer omitted its certificate".to_owned())?;
    let parsed =
        openssl::x509::X509::from_der(certificate.as_ref()).map_err(|error| format!("parse certificate: {error}"))?;
    let serial = parsed
        .serial_number()
        .to_bn()
        .map_err(|error| format!("read certificate serial: {error}"))?;
    let serial = serial
        .to_hex_str()
        .map_err(|error| format!("format certificate serial: {error}"))?;
    Ok(canonical_hex_serial(&serial))
}

/// Normalizes OpenSSL serial text so decimal and hexadecimal probes agree.
fn canonical_hex_serial(serial: &str) -> String {
    let digits = serial.trim().trim_start_matches('0');
    if digits.is_empty() {
        "0".to_owned()
    } else {
        digits.to_uppercase()
    }
}

/// Extensions required for a self-signed leaf certificate accepted by rustls.
const TEST_CERTIFICATE_EXTENSIONS: [&str; 4] = [
    "subjectAltName=DNS:localhost",
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
];

/// Writes a self-signed localhost certificate and key with the given prefix.
///
/// # Errors
///
/// Returns an error when `openssl` cannot generate the certificate.
pub fn write_test_certificate(temp_dir: &TempDir, prefix: &str) -> Result<(), String> {
    let certificate = temp_dir.path().join(format!("{prefix}.crt"));
    let key = temp_dir.path().join(format!("{prefix}.key"));
    let mut command = std::process::Command::new("openssl");
    command.args([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key.to_string_lossy().as_ref(),
        "-out",
        certificate.to_string_lossy().as_ref(),
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
    ]);
    for extension in TEST_CERTIFICATE_EXTENSIONS {
        command.args(["-addext", extension]);
    }
    let status = command
        .status()
        .map_err(|error| format!("generate {prefix} certificate: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("generate {prefix} certificate: openssl failed"))
    }
}

/// Builds an HTTPS client configuration trusting the supplied certificates.
///
/// The rollout suite rotates between self-signed certificates, so its client
/// must trust both the original and replacement certificate.
///
/// # Errors
///
/// Returns an error when a certificate cannot be parsed or added to the root
/// store.
pub fn https_client_config(certificates: &[PathBuf]) -> Result<Arc<ClientConfig>, String> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        let pem = std::fs::read(certificate).map_err(|error| format!("read certificate: {error}"))?;
        for der in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            let der = der.map_err(|error| format!("parse certificate PEM: {error}"))?;
            roots
                .add(der)
                .map_err(|error| format!("add certificate root: {error}"))?;
        }
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// Tagged handler: read one chunk, respond with `tag:data`.
fn handle_tagged(mut stream: TcpStream, tag: &str) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut buf = [0_u8; 4096];
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

#[cfg(test)]
mod serial_tests {
    use super::*;

    #[test]
    fn certificate_serial_is_canonical_hexadecimal() {
        assert_eq!(canonical_hex_serial("00ABCDEF"), "ABCDEF");
        assert_eq!(canonical_hex_serial("abcdef"), "ABCDEF");
        assert_eq!(canonical_hex_serial("000"), "0");
    }
}
