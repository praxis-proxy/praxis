// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the header presence condition example configuration.

use std::collections::HashMap;

use praxis_test_utils::{
    Backend, BackendGuard, free_port, http_send, parse_body, parse_header, parse_status, start_header_echo_backend,
    start_proxy,
};

/// Load the example config in front of `backend`.
fn load(proxy_port: u16, backend: &BackendGuard) -> praxis_core::config::Config {
    super::load_example_config(
        "pipeline/header-presence-condition.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend.port())]),
    )
}

#[test]
fn request_without_tenant_gets_the_default() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load(proxy_port, &backend));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "request should be proxied");
    let body = parse_body(&raw).to_lowercase();
    assert!(
        body.contains("x-tenant: public"),
        "a request without X-Tenant should reach the backend with the default, got:\n{body}"
    );
}

#[test]
fn client_tenant_passes_through_untouched() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load(proxy_port, &backend));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nx-tenant: acme\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "request should be proxied");
    let body = parse_body(&raw).to_lowercase();
    assert!(
        body.contains("x-tenant: acme"),
        "the client's X-Tenant should reach the backend, got:\n{body}"
    );
    assert!(
        !body.contains("x-tenant: public"),
        "unless headers_present should skip the default when the client sent X-Tenant, got:\n{body}"
    );
}

#[test]
fn response_without_cache_control_gets_no_store() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let proxy = start_proxy(&load(proxy_port, &backend));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "request should be proxied");
    assert_eq!(
        parse_header(&raw, "cache-control").as_deref(),
        Some("no-store"),
        "a response without Cache-Control should get the default"
    );
}

#[test]
fn backend_cache_control_passes_through_untouched() {
    let backend = Backend::fixed("cached")
        .header("Cache-Control", "max-age=60")
        .start_with_shutdown();
    let proxy_port = free_port();
    let proxy = start_proxy(&load(proxy_port, &backend));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "request should be proxied");
    assert_eq!(parse_body(&raw), "cached", "the backend body should come through");
    assert_eq!(
        parse_header(&raw, "cache-control").as_deref(),
        Some("max-age=60"),
        "unless headers_present should leave the backend's Cache-Control alone"
    );
}
