// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional handshakes and requests using the shipped TLS example YAML.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::Config;
use praxis_test_utils::{
    ClientCert, TestCertificates, example_config_path, free_port, http_get, https_get, https_get_attempt, patch_yaml,
    start_backend_with_shutdown, start_full_proxy, start_mtls_backend, start_tls_backend, start_tls_proxy,
    tls_negative_probe, wait_for_tcp,
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
            let outcome = tls_negative_probe(proxy.addr(), "localhost", b"GET / HTTP/1.1\r\n\r\n", &anonymous);
            assert!(
                outcome.is_client_auth_alert(),
                "required mode must reject anonymous clients: {outcome:?}"
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
    let outcome = tls_negative_probe(proxy.addr(), "localhost", b"GET / HTTP/1.1\r\n\r\n", &anonymous);
    assert!(
        outcome.is_client_auth_alert(),
        "the listener must reject missing client identity: {outcome:?}"
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
    let outcome = tls_negative_probe(proxy.addr(), "localhost", b"GET / HTTP/1.1\r\n\r\n", &denied_client);
    assert!(
        matches!(
            &outcome,
            praxis_test_utils::TlsProbeOutcome::PeerAlert(rustls::AlertDescription::AccessDenied)
        ),
        "unlisted SVID must fail at the handshake: {outcome:?}"
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

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

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
