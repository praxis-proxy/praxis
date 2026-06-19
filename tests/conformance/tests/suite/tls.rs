// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! TLS conformance tests.
//!
//! Verifies TLS protocol enforcement behavior against
//! [RFC 8446] (TLS 1.3) requirements. Praxis uses rustls,
//! which only supports TLS 1.2 and 1.3 with strong cipher
//! suites.
//!
//! [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, https_get, start_backend, start_tls_proxy, start_tls_proxy_no_wait,
    tls_connection_rejected, wait_for_https,
};

// -----------------------------------------------------------------------------
// Tests - RFC 8446 - TLS 1.3
// -----------------------------------------------------------------------------

/// [RFC 8446 Section 4.2.1]: TLS 1.2 connections must be
/// accepted (rustls supports TLS 1.2 and 1.3).
///
/// [RFC 8446 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
#[test]
fn rfc8446_tls_12_connection_accepted() {
    let certs = TestCertificates::generate();
    let client_config = build_tls12_client_config(&certs);

    let backend_port = start_backend("tls12-ok");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &certs.client_config());

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "TLS 1.2 connection must be accepted");
    assert_eq!(body, "tls12-ok", "TLS 1.2 response body must match");
}

/// [RFC 8446 Section 4.2.1]: TLS 1.3 connections must be
/// accepted.
///
/// [RFC 8446 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
#[test]
fn rfc8446_tls_13_connection_accepted() {
    let certs = TestCertificates::generate();
    let client_config = build_tls13_client_config(&certs);

    let backend_port = start_backend("tls13-ok");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &certs.client_config());

    let (status, body) = https_get(proxy.addr(), "/", &client_config);
    assert_eq!(status, 200, "TLS 1.3 connection must be accepted");
    assert_eq!(body, "tls13-ok", "TLS 1.3 response body must match");
}

/// [RFC 8446]: rustls does not support TLS 1.0 or 1.1. A client
/// attempting TLS 1.0/1.1 must be rejected.
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446
#[test]
fn rfc8446_tls_10_connection_rejected() {
    let certs = TestCertificates::generate();
    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &certs.client_config());

    let rejected = attempt_legacy_tls(proxy.addr(), 0x0301);
    assert!(rejected, "TLS 1.0 (0x0301) connection must be rejected by rustls");
}

/// [RFC 8446]: TLS 1.1 connections must be rejected.
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446
#[test]
fn rfc8446_tls_11_connection_rejected() {
    let certs = TestCertificates::generate();
    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &certs.client_config());

    let rejected = attempt_legacy_tls(proxy.addr(), 0x0302);
    assert!(rejected, "TLS 1.1 (0x0302) connection must be rejected by rustls");
}

/// [RFC 8446 Section 4.2]: when the client offers `h2` via ALPN,
/// the proxy must accept the connection and serve H2 responses.
/// Verified end-to-end by performing an HTTPS/H2 GET.
///
/// [RFC 8446 Section 4.2]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
#[test]
fn rfc8446_alpn_h2_accepted() {
    let certs = TestCertificates::generate();
    let backend_port = start_backend("alpn-h2");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &certs.client_config());

    let (status, body) = https_get(proxy.addr(), "/", &certs.client_config());
    assert_eq!(status, 200, "H2 over TLS (via ALPN) must succeed");
    assert_eq!(body, "alpn-h2", "H2 response body must match");
}

/// [RFC 8446 Section 4.2]: when the client offers only
/// `http/1.1` via ALPN, the TLS handshake must still succeed.
///
/// [RFC 8446 Section 4.2]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
#[test]
fn rfc8446_alpn_http11_tls_handshake_accepted() {
    let certs = TestCertificates::generate();
    let backend_port = start_backend("alpn-h1");
    let proxy_port = free_port();
    let yaml = tls_proxy_yaml(proxy_port, backend_port, &certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy(&config, &certs.client_config());

    let handshake_ok = tls_handshake_succeeds(proxy.addr(), &certs, &[b"http/1.1"]);
    assert!(
        handshake_ok,
        "TLS handshake with http/1.1 ALPN must succeed (server should not reject based on ALPN alone)"
    );
}

/// [RFC 8446]: a client without a valid certificate must be
/// rejected when mTLS is required.
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446
#[test]
fn rfc8446_invalid_client_cert_rejected_with_mtls() {
    let server_certs = TestCertificates::generate();
    let other_ca_certs = TestCertificates::generate();
    let wrong_client_cert = other_ca_certs.generate_client_cert();
    let wrong_client_config = server_certs.client_config_with_cert(&wrong_client_cert);
    let valid_client_cert = server_certs.generate_client_cert();
    let valid_client_config = server_certs.client_config_with_cert(&valid_client_cert);

    let backend_port = start_backend("should-not-reach");
    let proxy_port = free_port();
    let yaml = mtls_proxy_yaml(proxy_port, backend_port, &server_certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &valid_client_config);

    let rejected = tls_connection_rejected(
        proxy.addr(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &wrong_client_config,
    );
    assert!(rejected, "client cert signed by wrong CA must be rejected in mTLS mode");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a proxy YAML config with a TLS listener.
fn tls_proxy_yaml(proxy_port: u16, backend_port: u16, certs: &TestCertificates) -> String {
    format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    )
}

/// Build a proxy YAML config with mTLS required.
fn mtls_proxy_yaml(proxy_port: u16, backend_port: u16, certs: &TestCertificates) -> String {
    format!(
        r#"
listeners:
  - name: secure
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
      client_ca:
        ca_path: "{ca}"
      client_cert_mode: require
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
        ca = certs.ca_cert_path.display(),
    )
}

/// Build a TLS 1.2-only client config.
fn build_tls12_client_config(certs: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let versions = vec![&rustls::version::TLS12];
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Build a TLS 1.3-only client config.
fn build_tls13_client_config(certs: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let versions = vec![&rustls::version::TLS13];
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    Arc::new(config)
}

/// Attempt a TLS connection with a crafted legacy ClientHello
/// (TLS 1.0 or 1.1 record version). Returns `true` if the
/// connection was rejected.
fn attempt_legacy_tls(addr: &str, version: u16) -> bool {
    use std::{
        io::{Read as _, Write as _},
        net::TcpStream,
        time::Duration,
    };

    let version_major = (version >> 8) as u8;
    let version_minor = (version & 0xFF) as u8;

    #[rustfmt::skip]
    let client_hello: Vec<u8> = vec![
        0x16,                                   // ContentType: Handshake
        version_major, version_minor,           // ProtocolVersion
        0x00, 0x2f,                             // Length of payload
        0x01,                                   // HandshakeType: ClientHello
        0x00, 0x00, 0x2b,                       // Length
        version_major, version_minor,           // ClientVersion
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                                   // SessionID length: 0
        0x00, 0x02,                             // CipherSuites length: 2
        0x00, 0x2f,                             // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01,                                   // CompressionMethods length: 1
        0x00,                                   // null compression
    ];

    let Ok(mut stream) = TcpStream::connect(addr) else {
        return true;
    };
    drop(stream.set_read_timeout(Some(Duration::from_secs(2))));
    drop(stream.set_write_timeout(Some(Duration::from_secs(2))));

    if stream.write_all(&client_hello).is_err() {
        return true;
    }

    let mut buf = [0_u8; 256];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) => true,
        Ok(n) => n >= 1 && buf[0] == 0x15,
    }
}

/// Attempt a TLS handshake with the given ALPN protocols and
/// return `true` if the handshake succeeds.
fn tls_handshake_succeeds(addr: &str, certs: &TestCertificates, protocols: &[&[u8]]) -> bool {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
    let config = Arc::new(config);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(config);
        let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
            return false;
        };
        connector.connect(server_name, tcp).await.is_ok()
    })
}
