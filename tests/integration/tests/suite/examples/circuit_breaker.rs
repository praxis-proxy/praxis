// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the circuit breaker example config.

use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn circuit_breaker_config_parses() {
    let config = super::load_example_config(
        "traffic-management/circuit-breaker.yaml",
        29800,
        HashMap::from([("127.0.0.1:3001", 29801_u16), ("127.0.0.1:3002", 29802_u16)]),
    );

    assert_eq!(config.listeners.len(), 1, "should have 1 listener");
    assert_eq!(&*config.listeners[0].name, "http", "listener name should be http");
}

#[test]
fn circuit_breaker_functional() {
    let backend_guard = praxis_test_utils::start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = praxis_test_utils::free_port();

    let config = super::load_example_config(
        "traffic-management/circuit-breaker.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", backend_port), ("127.0.0.1:3002", backend_port)]),
    );

    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = praxis_test_utils::http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "healthy backend should return 200");
    assert_eq!(body, "ok", "response body should match backend");
}
