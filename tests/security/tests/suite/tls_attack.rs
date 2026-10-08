// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Cipher policy and ALPN failures are observed at the TLS handshake boundary.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::{Arc, mpsc},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, parse_body, parse_cert_chain_and_key, parse_status, simple_proxy_yaml,
    start_backend_with_shutdown, start_full_proxy, start_tls_proxy_no_wait, wait_for_tcp,
};
use rustls::{CipherSuite, ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use super::test_utils::{IO_TIMEOUT, connect, send_text};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Legacy `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` suite, matching the control certificate.
const RC4_SUITE: u16 = 0xC007;

#[test]
fn tls12_cipher_policy_accepts_allowed_and_rejects_excluded_suite() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("cipher-ok");
    let mut config = listener_config(&certs, backend.port());
    config.listeners[0].tls.as_mut().unwrap().cipher_suites =
        serde_yaml::from_str("[tls12_ecdhe_ecdsa_with_aes_128_gcm_sha256]").unwrap();
    let proxy = start_tls_proxy_no_wait(&config);
    wait_for_tcp(proxy.addr());
    let allowed = cipher_client(&certs, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    let connection = handshake(proxy.addr(), allowed).expect("allowed TLS 1.2 suite must negotiate");
    assert_eq!(
        connection.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2),
        "control must use TLS 1.2"
    );
    assert_eq!(
        connection.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "exact allowed suite must negotiate"
    );
    let excluded = cipher_client(&certs, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    assert_tls_alert(
        &handshake(proxy.addr(), excluded).unwrap_err(),
        rustls::AlertDescription::HandshakeFailure,
    );
}

#[test]
fn legacy_rc4_cipher_is_rejected_during_handshake() {
    use praxis_test_utils::tls_probe::{ClientHello, Reply, TLS12, alerts, probe, suites};
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("weak-suite");
    let proxy = start_tls_proxy_no_wait(&listener_config(&certs, backend.port()));
    wait_for_tcp(proxy.addr());
    let mut hello = ClientHello::approved("localhost");
    hello.versions = vec![TLS12];
    hello.cipher_suites = vec![suites::ECDHE_ECDSA_AES_128_GCM_SHA256];
    assert!(
        matches!(
            probe(proxy.addr(), &hello),
            Reply::ServerHello {
                version: TLS12,
                cipher_suite: suites::ECDHE_ECDSA_AES_128_GCM_SHA256
            }
        ),
        "modern TLS 1.2 control must reach ServerHello"
    );
    hello.cipher_suites = vec![RC4_SUITE];
    assert_eq!(
        probe(proxy.addr(), &hello),
        Reply::Alert {
            description: alerts::HANDSHAKE_FAILURE
        },
        "legacy RC4 offer must fail at handshake"
    );
}

#[test]
fn listener_alpn_without_a_common_protocol_rejected_at_handshake() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("alpn-ok");
    let proxy = start_tls_proxy_no_wait(&listener_config(&certs, backend.port()));
    wait_for_tcp(proxy.addr());
    let mut matching = (*certs.client_config()).clone();
    matching.alpn_protocols = vec![b"http/1.1".to_vec()];
    let accepted = handshake(proxy.addr(), Arc::new(matching.clone())).expect("supported ALPN must negotiate");
    assert_eq!(
        accepted.alpn_protocol(),
        Some(b"http/1.1".as_slice()),
        "positive control must negotiate HTTP/1.1"
    );
    matching.alpn_protocols = vec![b"unsupported-protocol".to_vec()];
    assert_tls_alert(
        &handshake(proxy.addr(), Arc::new(matching)).unwrap_err(),
        rustls::AlertDescription::NoApplicationProtocol,
    );
}

#[test]
fn upstream_alpn_mismatch_returns_502_without_protocol_fallback() {
    let certs = TestCertificates::generate();
    let (status, body, negotiated) = upstream_exchange(&certs, "h1");
    assert_eq!(status, 200, "matching upstream ALPN must succeed");
    assert_eq!(body, "upstream-alpn", "positive control must reach TLS backend");
    assert_eq!(
        negotiated,
        vec![Ok(Some(b"http/1.1".to_vec()))],
        "upstream must negotiate HTTP/1.1"
    );
    let (status, body, mismatch) = upstream_exchange(&certs, "h2");
    assert_eq!(status, 502, "h2-only cluster must reject h1-only TLS backend");
    assert!(
        !body.contains("upstream-alpn"),
        "failed ALPN must not forward application data"
    );
    assert!(!mismatch.is_empty(), "backend must observe the failed TLS negotiation");
    for outcome in mismatch {
        assert_eq!(
            outcome,
            Err(rustls::Error::NoApplicationProtocol),
            "every attempt must fail ALPN without fallback to HTTP/1.1"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build an HTTP TLS listener with its normal advertised protocols.
fn listener_config(certs: &TestCertificates, backend: u16) -> Config {
    let yaml = simple_proxy_yaml(free_port(), backend);
    let mut config = Config::from_yaml(&yaml).unwrap();
    let tls = format!(
        "certificates:\n  - cert_path: \"{}\"\n    key_path: \"{}\"\n",
        certs.cert_path.display(),
        certs.key_path.display()
    );
    config.listeners[0].tls = Some(serde_yaml::from_str(&tls).unwrap());
    config
}

/// Offer exactly one TLS 1.2 suite using the project's selected provider.
fn cipher_client(certs: &TestCertificates, suite: CipherSuite) -> Arc<ClientConfig> {
    let mut provider = rustls::crypto::CryptoProvider::get_default().unwrap().as_ref().clone();
    provider.cipher_suites.retain(|candidate| candidate.suite() == suite);
    assert_eq!(
        provider.cipher_suites.len(),
        1,
        "provider must expose the requested suite"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca_cert_der.clone().into()).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Complete only the handshake; application read errors cannot count as rejection.
fn handshake(addr: &str, config: Arc<ClientConfig>) -> std::io::Result<ClientConnection> {
    let mut stream = connect(addr);
    let mut connection = ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    while connection.is_handshaking() {
        connection.complete_io(&mut stream)?;
    }
    Ok(connection)
}

/// Require a TLS alert rather than accepting transport or timeout errors.
fn assert_tls_alert(error: &std::io::Error, expected: rustls::AlertDescription) {
    let cause = error.get_ref().and_then(|cause| cause.downcast_ref::<rustls::Error>());
    assert_eq!(
        cause,
        Some(&rustls::Error::AlertReceived(expected)),
        "rejection must be the expected TLS alert: {error}"
    );
}

/// One connection's observed ALPN negotiation result.
type AlpnOutcome = Result<Option<Vec<u8>>, rustls::Error>;

/// Exchange through a verified TLS upstream that advertises HTTP/1.1 only.
fn upstream_exchange(certs: &TestCertificates, version: &str) -> (u16, String, Vec<AlpnOutcome>) {
    let (chain, key) = parse_cert_chain_and_key(
        &std::fs::read(&certs.cert_path).unwrap(),
        &std::fs::read(&certs.key_path).unwrap(),
    );
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = Arc::new(server);
    let (observed, observations) = mpsc::channel();
    let (stop, stopping) = mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepting = listener.try_clone().unwrap();
    let worker = std::thread::spawn(move || {
        serve_alpn_connections(&accepting, &server, &observed, &stopping);
    });
    let yaml = format!(
        r#"
listeners:
  - name: plain
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
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
            endpoints: ["127.0.0.1:{port}"]
            http:
              version: {version}
            tls:
              sni: localhost
              ca:
                ca_path: "{ca}"
insecure_options:
  allow_private_endpoints: true
"#,
        proxy_port = free_port(),
        ca = certs.ca_cert_path.display()
    );
    let proxy = start_full_proxy(&Config::from_yaml(&yaml).unwrap());
    wait_for_tcp(proxy.addr());
    let raw = send_text(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    stop.send(()).unwrap();
    worker.join().expect("ALPN backend must finish");
    assert_eq!(
        listener
            .accept()
            .expect_err("all upstream attempts must be observed")
            .kind(),
        std::io::ErrorKind::WouldBlock,
        "no unobserved upstream attempt may remain queued"
    );
    (parse_status(&raw), parse_body(&raw), observations.try_iter().collect())
}

/// Serve every retry and record its TLS outcome until the completed request releases the fixture.
fn serve_alpn_connections(
    listener: &TcpListener,
    config: &Arc<ServerConfig>,
    observed: &mpsc::Sender<AlpnOutcome>,
    stopping: &mpsc::Receiver<()>,
) {
    loop {
        match listener.accept() {
            Ok((stream, _address)) => serve_alpn(stream, Arc::clone(config), observed),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                match stopping.recv_timeout(std::time::Duration::from_millis(10)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                }
            },
            Err(error) => panic!("accept TLS fixture connection: {error}"),
        }
    }
}

/// Observe the server's handshake result and send application bytes only on success.
fn serve_alpn(mut stream: std::net::TcpStream, config: Arc<ServerConfig>, observed: &mpsc::Sender<AlpnOutcome>) {
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut connection = ServerConnection::new(config).unwrap();
    while connection.is_handshaking() {
        if let Err(error) = connection.complete_io(&mut stream) {
            let cause = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<rustls::Error>())
                .expect("handshake must fail for a TLS reason")
                .clone();
            observed.send(Err(cause)).unwrap();
            return;
        }
    }
    observed
        .send(Ok(connection.alpn_protocol().map(<[u8]>::to_vec)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut request = Vec::new();
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut buffer = [0_u8; 512];
        let count = tls.read(&mut buffer).expect("TLS HTTP request");
        assert_ne!(count, 0, "request must complete after successful ALPN");
        request.extend_from_slice(&buffer[..count]);
        assert!(request.len() < 8192, "fixture request must stay bounded");
    }
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nupstream-alpn")
        .unwrap();
    tls.conn.send_close_notify();
    tls.flush().unwrap();
}
