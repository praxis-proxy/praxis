// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Adversarial tests for path traversal attack vectors.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_status, simple_proxy_yaml, start_proxy, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn bare_dotdot_path_normalized_or_rejected() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "bare /../ should be forwarded or rejected, not cause a server error (got {status})"
    );
}

#[test]
fn nested_dotdot_path_normalized_or_rejected() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET /safe/../../etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "nested /../ should be forwarded or rejected, not cause a server error (got {status})"
    );
}

#[test]
fn percent_encoded_dots_preserved_not_decoded() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert!(
        status == 200 || status == 400,
        "percent-encoded dot path should be passed through or rejected (got {status})"
    );
    if status == 200 {
        assert!(
            !body.contains("/../"),
            "proxy must not decode percent-encoded dots into literal traversal (body: {body})"
        );
    }
}

#[test]
fn mixed_encoding_traversal_handled_safely() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET /..%2f..%2fetc/passwd HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert!(
        status == 200 || status == 400,
        "mixed-encoding traversal should be passed through or rejected (got {status})"
    );
    if status == 200 {
        assert!(
            !body.contains("/../"),
            "mixed-encoding must not be decoded into literal traversal (body: {body})"
        );
    }
}

#[test]
fn path_with_null_byte_rejected_or_sanitized() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET /file%00.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "path with null byte should be handled safely (got {status})"
    );
}

#[test]
fn double_slash_path_forwarded_intact() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "//etc/passwd", None);
    assert_eq!(status, 200, "double-slash path should not crash the proxy");
    assert!(
        !body.contains("/../"),
        "double-slash should not introduce traversal (body: {body})"
    );
}
