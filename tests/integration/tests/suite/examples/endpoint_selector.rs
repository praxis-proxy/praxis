// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the `endpoint_selector` example config.
//!
//! The endpoint selector only reads from trusted mutation sources (e.g.
//! ext_proc), deliberately ignoring client-supplied headers to prevent
//! SSRF. In non-required mode, the filter passes through when no trusted
//! value is present, allowing normal router/load_balancer routing.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, http_send, parse_status, start_backend_with_shutdown, start_proxy};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn endpoint_selector_falls_through_without_trusted_header() {
    let backend_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();
    let config = load_example_config(
        "traffic-management/endpoint-selector.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "without trusted header, non-required endpoint_selector should fall through"
    );
    assert_eq!(
        body, "default-backend",
        "request should reach default backend via normal routing"
    );
}

#[test]
fn endpoint_selector_ignores_client_supplied_header() {
    let backend_guard = start_backend_with_shutdown("default-backend");
    let proxy_port = free_port();
    let config = load_example_config(
        "traffic-management/endpoint-selector.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         x-gateway-destination: 10.0.0.1:9999\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "client-supplied destination header should be ignored (SSRF prevention)"
    );
}
