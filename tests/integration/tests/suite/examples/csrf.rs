// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Functional integration test for the CSRF example config.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn csrf_example_get_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/csrf.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "GET should bypass CSRF protection");
}

#[test]
fn csrf_example_post_trusted_origin() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/csrf.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "POST with trusted origin should be allowed");
}

#[test]
fn csrf_example_post_untrusted_origin() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/csrf.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "POST with untrusted origin should be rejected");
}

#[test]
fn csrf_example_post_no_origin() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/csrf.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "POST without origin should be rejected");
}

#[test]
fn csrf_example_sec_fetch_cross_site() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/csrf.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /api/data HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example.com\r\nSec-Fetch-Site: cross-site\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "Sec-Fetch-Site: cross-site should be rejected");
}
