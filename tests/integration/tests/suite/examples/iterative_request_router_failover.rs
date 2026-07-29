// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the iterative request router failover example.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_stateful_backend};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn failover_on_503() {
    let primary = start_stateful_backend(vec![(503, "down".to_owned())]);
    let fallback = start_backend_with_shutdown("fallback-ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/iterative-request-router-failover.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", primary.port()), ("127.0.0.1:3001", fallback.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "failover should produce 200");
    assert_eq!(body, "fallback-ok", "should get fallback response");
}

#[test]
fn primary_succeeds_no_failover() {
    let primary = start_backend_with_shutdown("primary-ok");
    let fallback = start_backend_with_shutdown("fallback-ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/iterative-request-router-failover.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", primary.port()), ("127.0.0.1:3001", fallback.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "primary success should return 200");
    assert_eq!(body, "primary-ok", "should get primary response");
}
