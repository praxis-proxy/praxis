// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Praxis Contributors

//! Functional integration tests for traffic-management example configurations.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn timeout_example_fast_request_succeeds() {
    let backend_guard = start_backend_with_shutdown("fast");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/timeout.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "fast request should succeed within 5s timeout");
    assert_eq!(body, "fast", "response body should match backend");
}

#[test]
fn redirect_example_returns_301_with_location() {
    let proxy_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /old-page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 301, "redirect example should return 301");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://example.com/old-page"),
        "redirect Location should expand path template"
    );
}

#[test]
fn rate_limiting_example_allows_then_rejects() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let (first_status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(first_status, 200, "first request within burst should succeed");

    let mut got_429 = false;
    for _ in 0..50 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 429 {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "rate limiter should return 429 after exhausting burst");
}

#[test]
fn rate_limiting_example_returns_rate_limit_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    for _ in 0..50 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if parse_status(&raw) == 429 {
            assert!(
                parse_header(&raw, "Retry-After").is_some(),
                "429 response should include Retry-After header"
            );
            return;
        }
    }
    panic!("rate limiter should have returned 429 within 50 requests");
}
