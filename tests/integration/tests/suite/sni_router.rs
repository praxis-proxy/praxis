// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `sni_router` TCP filter.

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_test_utils::{
    TestCertificates, free_port, start_full_proxy, start_tls_backend, tls_connection_rejected, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn sni_router_routes_by_hostname() {
    let api_certs = TestCertificates::generate_for_san("api.localhost");
    let web_certs = TestCertificates::generate_for_san("web.localhost");

    let api_port = start_tls_backend(&api_certs, "api-response");
    let web_port = start_tls_backend(&web_certs, "web-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_upstreams: true

listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    filter_chains:
      - sni
filter_chains:
  - name: sni
    filters:
      - filter: sni_router
        routes:
          - server_names: ["api.localhost"]
            upstream: "127.0.0.1:{api_port}"
          - server_names: ["web.localhost"]
            upstream: "127.0.0.1:{web_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let api_client = no_alpn_client_config(&api_certs);
    let (status, body) = http1_over_tls(&format!("127.0.0.1:{proxy_port}"), "/", &api_client, "api.localhost");
    assert_eq!(status, 200, "SNI api.localhost should route to api backend");
    assert_eq!(body, "api-response", "api backend should return api-response");

    let web_client = no_alpn_client_config(&web_certs);
    let (status, body) = http1_over_tls(&format!("127.0.0.1:{proxy_port}"), "/", &web_client, "web.localhost");
    assert_eq!(status, 200, "SNI web.localhost should route to web backend");
    assert_eq!(body, "web-response", "web backend should return web-response");
}

#[test]
fn sni_router_default_upstream_fallback() {
    let default_certs = TestCertificates::generate_for_san("default.localhost");
    let default_port = start_tls_backend(&default_certs, "default-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_upstreams: true

listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    filter_chains:
      - sni
filter_chains:
  - name: sni
    filters:
      - filter: sni_router
        routes:
          - server_names: ["known.localhost"]
            upstream: "127.0.0.1:1"
        default_upstream: "127.0.0.1:{default_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let client = no_alpn_client_config(&default_certs);
    let (status, body) = http1_over_tls(&format!("127.0.0.1:{proxy_port}"), "/", &client, "default.localhost");
    assert_eq!(status, 200, "unmatched SNI should fall back to default upstream");
    assert_eq!(
        body, "default-response",
        "default backend should return default-response"
    );
}

#[test]
fn sni_router_rejects_when_no_match_and_no_default() {
    let certs = TestCertificates::generate_for_san("known.localhost");
    let known_port = start_tls_backend(&certs, "known-response");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
insecure_options:
  allow_private_upstreams: true

listeners:
  - name: gateway
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    filter_chains:
      - sni
filter_chains:
  - name: sni
    filters:
      - filter: sni_router
        routes:
          - server_names: ["known.localhost"]
            upstream: "127.0.0.1:{known_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let unknown_certs = TestCertificates::generate_for_san("unknown.localhost");
    let unknown_client = unknown_certs.raw_tls_client_config();
    let addr = format!("127.0.0.1:{proxy_port}");
    let rejected = tls_connection_rejected(&addr, b"should not echo", &unknown_client);
    assert!(rejected, "unmatched SNI without default should reject the connection");
}

#[test]
fn sni_router_config_validates_example() {
    let config = praxis_test_utils::load_example_config(
        "protocols/tls-sni-routing.yaml",
        free_port(),
        std::collections::HashMap::new(),
    );
    assert!(
        !config.filter_chains.is_empty(),
        "SNI routing example should have filter chains"
    );
}

#[test]
fn sni_router_rejects_invalid_config_empty_routes_no_default() {
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let config = serde_yaml::from_str::<serde_yaml::Value>("routes: []").unwrap();
    let result = registry.create("sni_router", &config);
    assert!(result.is_err(), "empty routes without default should fail validation");
}

#[test]
fn sni_router_rejects_invalid_config_empty_server_names() {
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
routes:
  - server_names: []
    upstream: "127.0.0.1:443"
"#,
    )
    .unwrap();
    let result = registry.create("sni_router", &config);
    assert!(result.is_err(), "empty server_names should fail validation");
}

#[test]
fn sni_router_rejects_duplicate_wildcard() {
    let registry = praxis_filter::FilterRegistry::with_builtins();
    let config: serde_yaml::Value = serde_yaml::from_str(
        r#"
routes:
  - server_names: ["*.example.com"]
    upstream: "127.0.0.1:1"
  - server_names: ["*.example.com"]
    upstream: "127.0.0.1:2"
"#,
    )
    .unwrap();
    let result = registry.create("sni_router", &config);
    assert!(result.is_err(), "duplicate wildcard patterns should fail validation");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a TLS client config without ALPN for L4 passthrough tests.
fn no_alpn_client_config(certs: &TestCertificates) -> Arc<rustls::ClientConfig> {
    let ca = rustls::pki_types::CertificateDer::from(certs.ca_cert_der.clone());
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca).expect("add CA to root store");

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Send an HTTP/1.1 GET over TLS through a passthrough proxy.
fn http1_over_tls(addr: &str, path: &str, client_config: &Arc<rustls::ClientConfig>, sni: &str) -> (u16, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("valid SNI");

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect");
        let mut tls = connector.connect(server_name, tcp).await.expect("TLS handshake");

        let request = format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut tls, request.as_bytes())
            .await
            .expect("write request");

        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut tls, &mut buf)
            .await
            .expect("read response");

        let raw = String::from_utf8_lossy(&buf);
        let status = parse_http1_status(&raw);
        let body = parse_http1_body(&raw);
        (status, body)
    })
}

/// Extract the status code from a raw HTTP/1.1 response.
fn parse_http1_status(raw: &str) -> u16 {
    raw.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Extract the body from a raw HTTP/1.1 response.
fn parse_http1_body(raw: &str) -> String {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default()
}
