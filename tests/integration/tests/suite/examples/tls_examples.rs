// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional handshakes and requests using the shipped TLS example YAML.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{
    ClientCert, TestCertificates, example_config_path, free_port, http_get, https_get, https_get_attempt, patch_yaml,
    start_backend_with_shutdown, start_full_proxy, start_mtls_backend, start_tls_backend, start_tls_proxy,
    tls_handshake_probe, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cipher_suite_example_accepts_matching_and_rejects_excluded_client() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("cipher-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-cipher-suites.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:3000", backend.port())]),
        Some(&certs),
        None,
        &[],
    );
    let client = version_client(&certs, &rustls::version::TLS13);
    let proxy = start_tls_proxy(&config, &client);
    let (status, body) = https_get(proxy.addr(), "/", &client);
    assert_eq!(
        (status, body.as_str()),
        (200, "cipher-example"),
        "listed suites must forward traffic"
    );

    let excluded = version_client(&certs, &rustls::version::TLS12);
    assert!(
        https_get_attempt(proxy.addr(), "/", &excluded).is_err(),
        "a TLS 1.2 client has no suite from the example's TLS 1.3-only list"
    );
}

#[test]
fn version_constraint_example_accepts_tls13_and_rejects_tls12() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("tls13-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-version-constraint.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:3000", backend.port())]),
        Some(&certs),
        None,
        &[],
    );
    let client = version_client(&certs, &rustls::version::TLS13);
    let proxy = start_tls_proxy(&config, &client);
    assert_eq!(https_get(proxy.addr(), "/", &client).0, 200, "TLS 1.3 must succeed");
    assert!(
        https_get_attempt(proxy.addr(), "/", &version_client(&certs, &rustls::version::TLS12)).is_err(),
        "TLS 1.2-only negotiation must fail"
    );
}

#[test]
fn upstream_tls_example_verifies_configured_sni() {
    let backend_certs = TestCertificates::generate_for_san("api.example.com");
    let backend_port = start_tls_backend(&backend_certs, "upstream-tls-example");
    let port = free_port();
    let trusted_sni = format!(
        "sni: \"api.example.com\"\n              ca:\n                ca_path: {}",
        backend_certs.ca_cert_path.display()
    );
    let config = load_tls_example(
        "upstream-tls.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", backend_port)]),
        None,
        None,
        &[("sni: \"api.example.com\"", trusted_sni)],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);
    assert_eq!(
        http_get(&addr, "/", None),
        (200, "upstream-tls-example".to_owned()),
        "the example's explicit SNI must authenticate the backend"
    );
}

#[test]
fn reencrypt_example_uses_tls_on_both_legs() {
    let listener_certs = TestCertificates::generate();
    let backend_certs = TestCertificates::generate_for_san("backend.example.com");
    let backend_port = start_tls_backend(&backend_certs, "reencrypt-example");
    let port = free_port();
    let trusted_sni = format!(
        "sni: \"backend.example.com\"\n              ca:\n                ca_path: {}",
        backend_certs.ca_cert_path.display()
    );
    let config = load_tls_example(
        "tls-http-reencrypt.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:9443", backend_port)]),
        Some(&listener_certs),
        None,
        &[("sni: \"backend.example.com\"", trusted_sni)],
    );
    let client = listener_certs.client_config();
    let proxy = start_tls_proxy(&config, &client);
    assert_eq!(
        https_get(proxy.addr(), "/", &client),
        (200, "reencrypt-example".to_owned()),
        "the actual example must terminate and originate verified TLS"
    );
}

#[test]
fn verify_disabled_example_reaches_untrusted_backend() {
    let backend_certs = TestCertificates::generate();
    let backend_port = start_tls_backend(&backend_certs, "unverified-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-verify-disabled.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", backend_port)]),
        None,
        None,
        &[],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);
    assert_eq!(
        http_get(&addr, "/", None),
        (200, "unverified-example".to_owned()),
        "the example's explicit verification opt-out must permit this test CA"
    );
}

#[test]
fn upstream_mtls_example_presents_proxy_identity() {
    let certs = TestCertificates::generate();
    let proxy_identity = certs.generate_client_cert();
    let backend_port = start_mtls_backend(&certs, "upstream-mtls-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-mtls-upstream.yaml",
        port,
        &HashMap::from([("127.0.0.1:9443", backend_port)]),
        None,
        Some(&proxy_identity),
        &[],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);
    assert_eq!(
        http_get(&addr, "/", None),
        (200, "upstream-mtls-example".to_owned()),
        "the upstream must accept the proxy's configured client certificate"
    );
}

#[test]
fn listener_mtls_examples_enforce_required_and_optional_modes() {
    let certs = TestCertificates::generate();
    let client_identity = certs.generate_client_cert();
    let with_cert = certs.client_config_with_cert(&client_identity);
    let anonymous = certs.client_config();

    for (filename, required) in [
        ("tls-mtls-listener.yaml", true),
        ("tls-mtls-listener-request.yaml", false),
    ] {
        let backend = start_backend_with_shutdown(filename);
        let port = free_port();
        let config = load_tls_example(
            filename,
            port,
            &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:3000", backend.port())]),
            Some(&certs),
            None,
            &[],
        );
        let proxy = start_tls_proxy(&config, if required { &with_cert } else { &anonymous });
        assert_eq!(
            https_get(proxy.addr(), "/", &with_cert).0,
            200,
            "a CA-signed client must pass either listener mode"
        );
        if required {
            let outcome = tls_handshake_probe(proxy.addr(), "localhost", &anonymous);
            assert!(
                outcome.is_client_auth_alert(),
                "required mode must reject anonymous clients: {outcome:?}"
            );
            assert!(
                https_get_attempt(proxy.addr(), "/", &anonymous).is_err(),
                "required mode must reject the anonymous request"
            );
        } else {
            assert_eq!(
                https_get(proxy.addr(), "/", &anonymous).0,
                200,
                "request mode must permit no cert"
            );
        }
    }
}

#[test]
fn both_directions_mtls_example_authenticates_each_peer() {
    let certs = TestCertificates::generate();
    let client_identity = certs.generate_client_cert();
    let proxy_identity = certs.generate_client_cert();
    let backend_port = start_mtls_backend(&certs, "both-mtls-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-mtls-both.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:9443", backend_port)]),
        Some(&certs),
        Some(&proxy_identity),
        &[],
    );
    let client = certs.client_config_with_cert(&client_identity);
    let proxy = start_tls_proxy(&config, &client);
    assert_eq!(
        https_get(proxy.addr(), "/", &client),
        (200, "both-mtls-example".to_owned()),
        "both handshakes must use the configured client identities"
    );
    let anonymous = certs.client_config();
    let outcome = tls_handshake_probe(proxy.addr(), "localhost", &anonymous);
    assert!(
        outcome.is_client_auth_alert(),
        "the listener must reject missing client identity: {outcome:?}"
    );
    assert!(
        https_get_attempt(proxy.addr(), "/", &anonymous).is_err(),
        "the anonymous request must fail"
    );
}

#[cfg(feature = "spiffe")]
#[test]
fn spiffe_example_checks_the_configured_allowlist() {
    let certs = TestCertificates::generate();
    let allowed = certs.generate_client_cert_with_spiffe_id("spiffe://grid.internal/signals");
    let denied = certs.generate_client_cert_with_spiffe_id("spiffe://grid.internal/other");
    let backend = start_backend_with_shutdown("spiffe-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-mtls-spiffe.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:3000", backend.port())]),
        Some(&certs),
        None,
        &[],
    );
    let allowed_client = certs.client_config_with_cert(&allowed);
    let proxy = start_tls_proxy(&config, &allowed_client);
    assert_eq!(
        https_get(proxy.addr(), "/", &allowed_client).0,
        200,
        "allowlisted SVID must pass"
    );
    let denied_client = certs.client_config_with_cert(&denied);
    let outcome = tls_handshake_probe(proxy.addr(), "localhost", &denied_client);
    assert!(
        matches!(
            &outcome,
            praxis_test_utils::TlsProbeOutcome::PeerAlert(rustls::AlertDescription::AccessDenied)
        ),
        "unlisted SVID must fail at the handshake: {outcome:?}"
    );
    assert!(
        https_get_attempt(proxy.addr(), "/", &denied_client).is_err(),
        "unlisted SVID must also fail a real HTTPS request"
    );
}

#[test]
fn multi_cert_example_selects_named_and_default_certificates() {
    let api = TestCertificates::generate_for_san("api.example.com");
    let web = TestCertificates::generate_for_san("web.example.com");
    let default = TestCertificates::generate_for_san("other.example.com");
    let backend = start_backend_with_shutdown("multi-cert-example");
    let port = free_port();
    let config = load_tls_example(
        "tls-multi-cert.yaml",
        port,
        &HashMap::from([("127.0.0.1:8443", port), ("127.0.0.1:3000", backend.port())]),
        None,
        None,
        &[
            ("/etc/ssl/certs/api.pem", api.cert_path.display().to_string()),
            ("/etc/ssl/private/api-key.pem", api.key_path.display().to_string()),
            ("/etc/ssl/certs/web.pem", web.cert_path.display().to_string()),
            ("/etc/ssl/private/web-key.pem", web.key_path.display().to_string()),
            ("/etc/ssl/certs/default.pem", default.cert_path.display().to_string()),
            (
                "/etc/ssl/private/default-key.pem",
                default.key_path.display().to_string(),
            ),
        ],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);
    for (name, expected) in [
        ("api.example.com", &api.server_cert_der),
        ("web.example.com", &web.server_cert_der),
        ("other.example.com", &default.server_cert_der),
    ] {
        assert_eq!(
            peer_cert_der(&addr, name, &[&api, &web, &default]),
            *expected,
            "the actual example must select the named or default certificate for {name}"
        );
    }
}

#[test]
fn sni_routing_example_selects_exact_wildcard_and_default_backends() {
    let api = TestCertificates::generate_for_san("api.example.com");
    let wildcard = TestCertificates::generate_for_san("shop.example.com");
    let default = TestCertificates::generate_for_san("other.example.net");
    let api_port = start_tls_backend(&api, "api-route");
    let wildcard_port = start_tls_backend(&wildcard, "wildcard-route");
    let default_port = start_tls_backend(&default, "default-route");
    let port = free_port();
    let config = load_tls_example(
        "tls-sni-routing.yaml",
        port,
        &HashMap::from([
            ("0.0.0.0:8443", port),
            ("127.0.0.1:9001", api_port),
            ("127.0.0.1:9002", wildcard_port),
            ("127.0.0.1:9003", default_port),
        ]),
        None,
        None,
        &[],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);
    for (name, certs, expected) in [
        ("api.example.com", &api, "api-route"),
        ("shop.example.com", &wildcard, "wildcard-route"),
        ("other.example.net", &default, "default-route"),
    ] {
        assert_eq!(
            http1_over_tls_sni(&addr, name, certs),
            expected,
            "the example's SNI route must reach the selected TLS backend for {name}"
        );
    }
}

#[test]
fn upstream_hot_reload_example_presents_rotated_identity() {
    let certs = TestCertificates::generate();
    let first_identity = certs.generate_client_cert();
    let second_identity = certs.generate_client_cert();
    let backend = RecordingMtlsBackend::new(&certs);
    let port = free_port();
    let config = load_tls_example(
        "upstream-tls-hot-reload.yaml",
        port,
        &HashMap::from([("127.0.0.1:9443", backend.port)]),
        None,
        Some(&first_identity),
        &[],
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr);

    assert_eq!(
        http_get(&addr, "/", None).0,
        200,
        "the upstream must accept the proxy's initial client certificate"
    );
    let first_leaf = read_pem_cert(&first_identity.cert_path);
    assert!(
        backend.presented_leaves().iter().any(|leaf| leaf == &first_leaf),
        "the initial handshake must present the first identity"
    );

    // Rotate the files the proxy's hot-reload watcher monitors.
    std::fs::copy(&second_identity.cert_path, &first_identity.cert_path).expect("rotate cert file");
    std::fs::copy(&second_identity.key_path, &first_identity.key_path).expect("rotate key file");

    let second_leaf = read_pem_cert(&second_identity.cert_path);
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut rotated = false;
    while Instant::now() < deadline {
        assert_eq!(
            http_get(&addr, "/", None).0,
            200,
            "requests must keep succeeding across the rotation"
        );
        if backend.presented_leaves().iter().any(|leaf| leaf == &second_leaf) {
            rotated = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        rotated,
        "a new upstream connection must present the rotated identity without a restart"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// DER-decode the first certificate in a PEM file.
fn read_pem_cert(path: &std::path::Path) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject as _;
    let pem = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .expect("one PEM certificate")
        .expect("parse PEM certificate")
        .to_vec()
}

/// A local mTLS backend that records the client leaf every connection
/// presents, answering each request over its own connection.
struct RecordingMtlsBackend {
    /// The port the backend listens on.
    port: u16,

    /// The DER leaf of every client certificate presented so far.
    presented: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingMtlsBackend {
    /// Start a backend that requires client certificates signed by `certs`.
    fn new(certs: &TestCertificates) -> Self {
        let acceptor = build_recording_acceptor(certs);
        let presented = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&presented);
        let (listener, port) = praxis_test_utils::bind_unique_port();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime for the recording backend");
            runtime.block_on(async move {
                listener.set_nonblocking(true).expect("nonblocking recording listener");
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio recording listener");
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    };
                    let acceptor = acceptor.clone();
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        serve_recording_connection(stream, acceptor, recorded).await;
                    });
                }
            });
        });
        Self { port, presented }
    }

    /// The client leaves presented so far, in connection order.
    fn presented_leaves(&self) -> Vec<Vec<u8>> {
        self.presented.lock().expect("presented leaves").clone()
    }
}

/// Build the backend's mTLS acceptor from the test CA.
fn build_recording_acceptor(certs: &TestCertificates) -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::pem::PemObject as _;
    let server_pem = std::fs::read_to_string(&certs.cert_path).expect("server PEM");
    let key_pem = std::fs::read_to_string(&certs.key_path).expect("key PEM");
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(server_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("server chain");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("server key");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone()))
        .expect("recording backend root");
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("recording backend verifier");

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("recording backend cert");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// Handshake, record the presented leaf, and answer one request per connection.
async fn serve_recording_connection(
    stream: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    recorded: Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let mut tls = match acceptor.accept(stream).await {
        Ok(stream) => stream,
        Err(_) => return,
    };
    if let Some(certificates) = tls.get_ref().1.peer_certificates()
        && let Some(leaf) = certificates.first()
    {
        recorded.lock().expect("presented leaves").push(leaf.to_vec());
    }
    let request = read_http_request(&mut tls).await;
    if request.is_none() {
        return;
    }
    let body = "upstream-hot-reload-example";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if tokio::io::AsyncWriteExt::write_all(&mut tls, response.as_bytes())
        .await
        .is_err()
    {
        return;
    }
    let _shutdown_result = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
}

/// Read one HTTP/1.1 request head, returning it when complete.
async fn read_http_request(stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let read = tokio::io::AsyncReadExt::read(stream, &mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(chunk.get(..read)?);
        if let Ok(text) = std::str::from_utf8(&buffer)
            && text.contains("\r\n\r\n")
        {
            return Some(text.to_owned());
        }
    }
}

/// Load an actual shipped example with only local fixture substitutions.
#[expect(
    clippy::too_many_arguments,
    reason = "independent fixture paths, ports, and TLS identities"
)]
fn load_tls_example(
    filename: &str,
    listener_port: u16,
    ports: &HashMap<&str, u16>,
    server: Option<&TestCertificates>,
    proxy_client: Option<&ClientCert>,
    replacements: &[(&str, String)],
) -> Config {
    let path = example_config_path(&format!("protocols/{filename}"));
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let mut yaml = patch_yaml(&yaml, listener_port, ports);
    if let Some(certs) = server {
        for (name, path) in [
            ("./localhost+1.pem", &certs.cert_path),
            ("./localhost+1-key.pem", &certs.key_path),
            ("/etc/ssl/certs/server.pem", &certs.cert_path),
            ("/etc/ssl/private/server-key.pem", &certs.key_path),
            ("/etc/ssl/certs/client-ca.pem", &certs.ca_cert_path),
        ] {
            yaml = yaml.replace(name, &path.display().to_string());
        }
    }
    if let Some(client) = proxy_client {
        yaml = yaml.replace(
            "/etc/ssl/certs/proxy-client.pem",
            &client.cert_path.display().to_string(),
        );
        yaml = yaml.replace(
            "/etc/ssl/private/proxy-client-key.pem",
            &client.key_path.display().to_string(),
        );
    }
    for (name, replacement) in replacements {
        assert!(yaml.contains(name), "{filename} must contain fixture token {name}");
        yaml = yaml.replace(name, replacement);
    }
    Config::from_yaml(&yaml).unwrap_or_else(|error| panic!("parse {filename}: {error}"))
}

/// Limit a trusted test client to one TLS version for negotiation assertions.
fn version_client(
    certs: &TestCertificates,
    version: &'static rustls::SupportedProtocolVersion,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone()))
        .expect("test CA root");
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// Return the certificate selected during a real SNI handshake.
fn peer_cert_der(addr: &str, name: &str, certs: &[&TestCertificates]) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    for certs in certs {
        roots
            .add(rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone()))
            .expect("test root");
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(config);
        let socket = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let name = rustls::pki_types::ServerName::try_from(name.to_owned()).expect("SNI");
        let stream = connector.connect(name, socket).await.expect("TLS handshake");
        stream.get_ref().1.peer_certificates().expect("peer certificate")[0].to_vec()
    })
}

/// Send HTTP/1.1 through the passthrough example with an explicit SNI name.
fn http1_over_tls_sni(addr: &str, name: &str, certs: &TestCertificates) -> String {
    let client = certs.raw_tls_client_config();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(client);
        let socket = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).expect("SNI");
        let mut stream = connector.connect(server_name, socket).await.expect("TLS handshake");
        let request = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .expect("HTTP request");
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("HTTP response");
        let response = String::from_utf8(response).expect("UTF-8 backend response");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "the selected backend must return HTTP 200"
        );
        response
            .split_once("\r\n\r\n")
            .expect("HTTP head/body boundary")
            .1
            .to_owned()
    })
}
