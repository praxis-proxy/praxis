// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS conformance tests.
//!
//! Verifies TLS protocol enforcement behavior against
//! [RFC 8446] (TLS 1.3) requirements. Praxis uses rustls,
//! which only supports TLS 1.2 and 1.3 with strong cipher
//! suites. Upstream certificate identity checks follow
//! [RFC 9110 Section 4.3.4] and [RFC 9525 Section 6.4].
//!
//! [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446
//! [RFC 9110 Section 4.3.4]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.3.4
//! [RFC 9525 Section 6.4]: https://datatracker.ietf.org/doc/html/rfc9525#section-6.4

use std::sync::{Arc, atomic::Ordering};

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, TlsProbeOutcome, free_port, http_get, https_get, start_backend, start_proxy,
    start_request_counting_backend, start_tls_backend, start_tls_proxy, start_tls_proxy_no_wait, tls_negative_probe,
    tls_probe::{self, ClientHello, Offer, Reply},
    wait_for_https,
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

    assert_tls12_probe_control(proxy.addr());
    attempt_legacy_tls(proxy.addr(), 0x0301).expect("TLS 1.0 must receive fatal protocol_version");
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

    assert_tls12_probe_control(proxy.addr());
    attempt_legacy_tls(proxy.addr(), 0x0302).expect("TLS 1.1 must receive fatal protocol_version");
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
    let valid_client_cert = server_certs.generate_client_cert();
    let valid_client_config = server_certs.client_config_with_cert(&valid_client_cert);

    let (backend, hits) = start_request_counting_backend("mtls-ok");
    let proxy_port = free_port();
    let yaml = mtls_proxy_yaml(proxy_port, backend.port(), &server_certs);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_https(proxy.addr(), &valid_client_config);
    let (status, body) = https_get(proxy.addr(), "/", &valid_client_config);
    assert_eq!(
        (status, body.as_str()),
        (200, "mtls-ok"),
        "trusted client reaches backend"
    );
    let accepted_hits = hits.load(Ordering::SeqCst);
    assert!(accepted_hits > 0, "trusted client must reach backend");

    for (issuer, expected_alert) in [
        (TestCertificates::generate(), rustls::AlertDescription::DecryptError),
        (
            TestCertificates::generate_for_san("other.invalid"),
            rustls::AlertDescription::UnknownCA,
        ),
    ] {
        let client_cert = issuer.generate_client_cert();
        let client_config = server_certs.client_config_with_cert(&client_cert);
        let outcome = tls_negative_probe(
            proxy.addr(),
            "localhost",
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            &client_config,
        );
        assert!(
            matches!(&outcome, TlsProbeOutcome::PeerAlert(alert) if *alert == expected_alert),
            "untrusted client certificate must receive {expected_alert:?} before application data: {outcome:?}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            accepted_hits,
            "untrusted client certificate must not reach backend"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests - RFC 9110 and RFC 9525 - https Certificate Verification
// -----------------------------------------------------------------------------

/// [RFC 9110 Section 4.3.4]: when the upstream host is a literal IP
/// address, the reference identity is an IP-ID ([RFC 9110 Section 4.3.5]),
/// which matches an `iPAddress` SAN holding the same address, octet for
/// octet ([RFC 9525 Section 6.4]). An IP endpoint with no `tls.sni` must
/// verify against the backend certificate's `127.0.0.1` IP SAN, whatever
/// `Host` the client sends.
///
/// [RFC 9110 Section 4.3.4]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.3.4
/// [RFC 9110 Section 4.3.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.3.5
/// [RFC 9525 Section 6.4]: https://datatracker.ietf.org/doc/html/rfc9525#section-6.4
#[test]
fn rfc9110_ip_endpoint_verified_against_ip_san() {
    let certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&certs, "ip-san-ok");
    let config = Config::from_yaml(&ip_endpoint_tls_yaml(backend_port, &certs)).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", Some("client.example.com"));
    assert_eq!(status, 200, "a certificate carrying the endpoint's IP SAN must verify");
    assert_eq!(body, "ip-san-ok", "the verified upstream should answer");
}

/// [RFC 9110 Section 4.3.5]: an IP-ID reference identity matches only
/// an `iPAddress` SAN ([RFC 9525 Section 6.4]), so a certificate that
/// names the backend by DNS name alone must fail verification for an IP
/// endpoint, even when the client's `Host` is that DNS name.
///
/// [RFC 9110 Section 4.3.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.3.5
/// [RFC 9525 Section 6.4]: https://datatracker.ietf.org/doc/html/rfc9525#section-6.4
#[test]
fn rfc9110_ip_endpoint_rejects_cert_without_ip_san() {
    let certs = TestCertificates::generate_dns_only("localhost");
    let backend_port = start_tls_backend(&certs, "should-not-reach");
    let config = Config::from_yaml(&ip_endpoint_tls_yaml(backend_port, &certs)).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", Some("localhost"));
    assert_eq!(
        status, 502,
        "a certificate without the endpoint's IP SAN must fail verification"
    );
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
insecure_options:
  allow_private_endpoints: true
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display(),
    )
}

/// Build a proxy YAML config with a plain listener in front of one
/// verifying TLS cluster: a single `127.0.0.1` endpoint, the authority
/// following the endpoint, no `tls.sni`, and the test CA trusted.
fn ip_endpoint_tls_yaml(backend_port: u16, certs: &TestCertificates) -> String {
    format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
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
            http:
              authority: {{ from: endpoint }}
            tls:
              ca:
                ca_path: "{ca}"
insecure_options:
  allow_private_endpoints: true
"#,
        proxy_port = free_port(),
        ca = certs.ca_cert_path.display(),
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
insecure_options:
  allow_private_endpoints: true
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

/// Require the same listener to accept a comparable TLS 1.2 offer.
fn assert_tls12_probe_control(addr: &str) {
    let reply = tls_probe::probe(addr, &ClientHello::tls12("localhost", true));
    assert!(
        matches!(
            reply,
            Reply::ServerHello {
                version: tls_probe::TLS12,
                ..
            }
        ),
        "TLS 1.2 control: {reply:?}"
    );
}

/// Serialize a complete pre-1.3 ClientHello with the requested legacy version.
fn legacy_hello(version: u16) -> Vec<u8> {
    let mut record = ClientHello::tls12("localhost", true).to_record();
    record.get_mut(1..3).unwrap().copy_from_slice(&version.to_be_bytes());
    record.get_mut(9..11).unwrap().copy_from_slice(&version.to_be_bytes());
    record
}

/// Send a legacy offer and require an exact fatal `protocol_version` record.
fn attempt_legacy_tls(addr: &str, version: u16) -> Result<(), String> {
    use std::{io::Write as _, net::TcpStream, time::Duration};
    let mut stream = TcpStream::connect(addr).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&legacy_hello(version))
        .map_err(|error| error.to_string())?;
    require_protocol_version_alert(&mut stream)
}

/// Read a whole TLS record and accept only fatal `protocol_version`.
fn require_protocol_version_alert(reader: &mut impl std::io::Read) -> Result<(), String> {
    let mut header = [0_u8; 5];
    reader
        .read_exact(&mut header)
        .map_err(|error| format!("alert header: {error}"))?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if header[0] != 0x15 || len != 2 {
        return Err(format!("expected a two-byte alert record, got {header:?}"));
    }
    let mut alert = [0_u8; 2];
    reader
        .read_exact(&mut alert)
        .map_err(|error| format!("alert payload: {error}"))?;
    if alert != [2, tls_probe::alerts::PROTOCOL_VERSION] {
        return Err(format!("expected fatal protocol_version, got {alert:?}"));
    }
    Ok(())
}

#[test]
fn legacy_probe_lengths_match_payload() {
    for version in [0x0301, 0x0302] {
        let record = legacy_hello(version);
        assert_eq!(
            usize::from(u16::from_be_bytes([record[3], record[4]])),
            record.len() - 5
        );
        let handshake_len = u32::from_be_bytes([0, record[6], record[7], record[8]]);
        assert_eq!(usize::try_from(handshake_len).unwrap(), record.len() - 9);
        assert_eq!(&record[1..3], &version.to_be_bytes());
        assert_eq!(&record[9..11], &version.to_be_bytes());
        let offer = Offer::parse(&record);
        assert_eq!(offer.versions, [version]);
        assert!(!offer.signature_algorithms.is_empty());
        assert!(!offer.cipher_suites.is_empty());
    }
}

#[test]
fn legacy_probe_requires_protocol_version_alert() {
    use std::io;
    struct OneByte<R>(R);
    impl<R: io::Read> io::Read for OneByte<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let length = buf.len().min(1);
            self.0.read(&mut buf[..length])
        }
    }
    struct Timeout;
    impl io::Read for Timeout {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
        }
    }
    let alert = [0x15, 3, 3, 0, 2, 2, tls_probe::alerts::PROTOCOL_VERSION];
    require_protocol_version_alert(&mut OneByte(&alert[..])).unwrap();
    for bad in [
        &[][..],
        &[0x15, 3, 3, 0, 2, 2][..],
        &[0x15, 3, 3, 0, 2, 2, 40][..],
        &[0x16, 3, 3, 0, 2, 2, 70][..],
    ] {
        let mut input = bad;
        assert!(require_protocol_version_alert(&mut input).is_err(), "accepted {bad:?}");
    }
    assert!(require_protocol_version_alert(&mut Timeout).is_err());
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
