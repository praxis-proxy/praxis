// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Praxis Contributors

//! Functional integration tests for protocol example configurations.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    ProxyGuard, TestCertificates, example_config_path, free_port, http_get, https_get, patch_yaml,
    start_backend_with_shutdown, start_full_proxy, start_proxy, start_tcp_tagged_backend, tls_send_recv, wait_for_tcp,
    wait_for_tls,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tcp_proxy_example_forwards_traffic() {
    let backend_port = start_tcp_tagged_backend("tcp");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/tcp-proxy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:5432", proxy_port), ("127.0.0.1:15432", backend_port)]),
    );
    let _proxy = start_tcp_proxy(&config, proxy_port);

    let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"hello");
    assert!(
        resp.contains("tcp"),
        "tcp-proxy example should forward to tagged backend, got: {resp}"
    );
    assert!(
        resp.contains("hello"),
        "tcp-proxy example should echo payload, got: {resp}"
    );
}

#[test]
fn tcp_timeouts_example_forwards_within_limit() {
    let backend_port = start_tcp_tagged_backend("db");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/tcp-timeouts.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:5432", proxy_port), ("127.0.0.1:15432", backend_port)]),
    );
    let _proxy = start_tcp_proxy(&config, proxy_port);

    let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"query");
    assert!(
        resp.contains("db"),
        "tcp-timeouts example should forward to backend, got: {resp}"
    );
    assert!(
        resp.contains("query"),
        "tcp-timeouts example should echo payload, got: {resp}"
    );
}

#[test]
fn mixed_protocol_example_proxies_http_and_tcp() {
    let http_backend = start_backend_with_shutdown("web-ok");
    let tcp_backend_port = start_tcp_tagged_backend("db");
    let http_port = free_port();
    let tcp_port = free_port();
    let config = super::load_example_config(
        "protocols/mixed-protocol.yaml",
        http_port,
        HashMap::from([
            ("127.0.0.1:5432", tcp_port),
            ("10.0.0.1:5432", tcp_backend_port),
            ("10.0.0.1:8080", http_backend.port()),
        ]),
    );
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{tcp_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{http_port}"), "/", None);
    assert_eq!(status, 200, "mixed-protocol HTTP listener should return 200");
    assert_eq!(body, "web-ok", "mixed-protocol HTTP should forward to backend");

    let resp = tcp_send_recv(&format!("127.0.0.1:{tcp_port}"), b"data");
    assert!(
        resp.contains("db"),
        "mixed-protocol TCP listener should forward to tagged backend, got: {resp}"
    );
}

#[test]
fn websocket_example_proxies_plain_http() {
    let backend = start_backend_with_shutdown("ws-ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/websocket.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "websocket config should proxy normal HTTP");
    assert_eq!(body, "ws-ok", "response should come from backend");
}

#[test]
fn tls_termination_example_serves_https() {
    let certs = TestCertificates::generate();
    let backend = start_backend_with_shutdown("tls-ok");
    let proxy_port = free_port();
    let config = load_tls_example(
        "protocols/tls-termination.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8443", proxy_port), ("127.0.0.1:3000", backend.port())]),
        &certs,
    );
    let client_cfg = certs.client_config();
    let _proxy = praxis_test_utils::start_tls_proxy(&config, &client_cfg);

    let (status, body) = https_get(&format!("127.0.0.1:{proxy_port}"), "/", &client_cfg);
    assert_eq!(status, 200, "tls-termination example should serve HTTPS");
    assert_eq!(
        body, "tls-ok",
        "tls-termination example should forward to plaintext backend"
    );
}

#[test]
fn tcp_tls_termination_example_forwards_over_tls() {
    let certs = TestCertificates::generate();
    let backend_port = start_tcp_tagged_backend("secure-db");
    let proxy_port = free_port();
    let config = load_tls_example(
        "protocols/tcp-tls-termination.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:5432", proxy_port), ("127.0.0.1:15432", backend_port)]),
        &certs,
    );
    let _proxy = start_full_proxy(&config);
    let client_cfg = certs.raw_tls_client_config();
    wait_for_tls(&format!("127.0.0.1:{proxy_port}"), &client_cfg);

    let resp = tls_send_recv(&format!("127.0.0.1:{proxy_port}"), b"secret", &client_cfg);
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("secure-db"),
        "tcp-tls-termination should forward to tagged backend, got: {text}"
    );
    assert!(
        text.contains("secret"),
        "tcp-tls-termination should echo payload, got: {text}"
    );
}

#[test]
fn tcp_tls_mtls_example_parses() {
    let certs = TestCertificates::generate();
    let proxy_port = free_port();
    let backend_port = free_port();
    let config = load_mtls_example("protocols/tcp-tls-mtls.yaml", proxy_port, backend_port, &certs);
    assert_eq!(config.listeners.len(), 1, "tcp-tls-mtls should have 1 listener");
    assert_eq!(
        &*config.listeners[0].name, "secure-db",
        "tcp-tls-mtls listener name should be secure-db"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Start a full Praxis TCP proxy and wait for readiness.
fn start_tcp_proxy(config: &Config, proxy_port: u16) -> ProxyGuard {
    let guard = start_full_proxy(config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    guard
}

/// Send data over TCP and return the response as a string.
fn tcp_send_recv(addr: &str, data: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    stream.write_all(data).expect("TCP write failed");
    stream.shutdown(std::net::Shutdown::Write).expect("TCP shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read failed");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Load a TLS example config, substituting generated cert paths.
#[expect(clippy::needless_pass_by_value, reason = "callers construct inline")]
fn load_tls_example(
    filename: &str,
    listener_port: u16,
    port_map: HashMap<&str, u16>,
    certs: &TestCertificates,
) -> Config {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let patched = patch_yaml(&yaml, listener_port, &port_map)
        .replace("./localhost+1.pem", &certs.cert_path.display().to_string())
        .replace("./localhost+1-key.pem", &certs.key_path.display().to_string());
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

/// Load a TCP mTLS example config, substituting generated cert and CA paths.
fn load_mtls_example(filename: &str, listener_port: u16, backend_port: u16, certs: &TestCertificates) -> Config {
    let path = example_config_path(filename);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let port_map = HashMap::from([("127.0.0.1:5432", listener_port), ("127.0.0.1:15432", backend_port)]);
    let patched = patch_yaml(&yaml, listener_port, &port_map)
        .replace("/etc/ssl/certs/server.pem", &certs.cert_path.display().to_string())
        .replace("/etc/ssl/private/server-key.pem", &certs.key_path.display().to_string())
        .replace(
            "/etc/ssl/certs/client-ca.pem",
            &certs.ca_cert_path.display().to_string(),
        );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}
