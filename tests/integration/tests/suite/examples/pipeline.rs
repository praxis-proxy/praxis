// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for pipeline example configurations.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, start_backend_with_shutdown, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn composed_chains() {
    let api_port_guard = start_backend_with_shutdown("api");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web");
    let web_port = web_port_guard.port();
    let public_port = free_port();
    let internal_port = free_port();

    let config = super::load_example_config(
        "pipeline/composed-chains.yaml",
        public_port,
        HashMap::from([
            ("127.0.0.1:9090", internal_port),
            ("10.0.0.1:8080", api_port),
            ("10.0.0.2:8080", web_port),
        ]),
    );
    let _proxy = start_proxy(&config);
    let public_addr = format!("127.0.0.1:{public_port}");
    let internal_addr = format!("127.0.0.1:{internal_port}");
    wait_for_tcp(&internal_addr);

    let (status, body) = http_get(&public_addr, "/api/test", None);
    assert_eq!(status, 200, "public /api/ should return 200");
    assert_eq!(body, "api", "public /api/ should route to api backend");

    let (status, body) = http_get(&public_addr, "/", None);
    assert_eq!(status, 200, "public root should return 200");
    assert_eq!(body, "web", "public root should route to web backend");

    let (status, body) = http_get(&internal_addr, "/api/test", None);
    assert_eq!(status, 200, "internal /api/ should return 200");
    assert_eq!(body, "api", "internal /api/ should route to api backend");

    let (status, body) = http_get(&internal_addr, "/", None);
    assert_eq!(status, 200, "internal root should return 200");
    assert_eq!(body, "web", "internal root should route to web backend");

    let raw = http_send(
        &public_addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-content-type-options"),
        Some("nosniff".to_owned()),
        "public listener should have X-Content-Type-Options from security chain"
    );

    let raw = http_send(
        &internal_addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        parse_header(&raw, "x-content-type-options").is_none(),
        "internal listener should not have security headers"
    );
}

#[test]
fn failure_mode() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/failure-mode.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "failure mode should return 200");
    assert_eq!(body, "ok", "response should come from backend");
}
