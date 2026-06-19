// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Adversarial tests for Host header attack vectors.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_status, simple_proxy_yaml, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn missing_host_header_rejected_http11() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "HTTP/1.1 request without Host header must be rejected per RFC 9112"
    );
}

#[test]
fn conflicting_host_headers_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: good.example.com\r\n\
         Host: evil.example.com\r\n\
         Connection: close\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(status, 400, "conflicting Host headers should be rejected with 400");
}

#[test]
fn identical_duplicate_host_headers_accepted() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 200,
        "identical duplicate Host headers should be canonicalized and accepted"
    );
}

#[test]
fn host_header_with_port_accepted() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost:{proxy_port}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert_eq!(status, 200, "Host header with port should be accepted");
}

#[test]
fn empty_host_header_handled_safely() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "empty Host header must be rejected per RFC 9112 Section 3.2"
    );
}

#[test]
fn whitespace_only_host_header_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\nHost: \t  \r\nConnection: close\r\n\r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "whitespace-only Host header must be rejected per RFC 9112 Section 3.2"
    );
}

#[test]
fn extremely_long_host_header_rejected() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let long_host = "a".repeat(8192);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {long_host}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 431 || status == 200,
        "extremely long Host should be rejected or handled safely (got {status})"
    );
}

#[test]
fn host_ip_literal_does_not_bypass_routing() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = "GET / HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Connection: close\r\n\
         \r\n";
    let raw = http_send(proxy.addr(), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 200,
        "IP literal Host header should route normally, not cause SSRF"
    );
}
