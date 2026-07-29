// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the iterative request router circuit breaker example.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn circuit_open_triggers_failover() {
    // Grab a port for primary but start no backend on it.
    // Connection attempts will get ECONNREFUSED, which the
    // sub-request executor classifies as Connect errors.
    // After consecutive_failures (2) such errors the circuit
    // opens and subsequent requests fail fast via CircuitOpen.
    let dead_primary_port = free_port();
    let fallback = start_backend_with_shutdown("fallback-ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/iterative-request-router-circuit-breaker.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", dead_primary_port),
            ("127.0.0.1:3001", fallback.port()),
        ]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);

    // First two requests trip the circuit via connect errors
    // (matched by the status: [502, 503, 504] rule) and
    // failover to the error-fallback step.
    for i in 0..2 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "request {i}: connect-error should failover");
        assert_eq!(body, "fallback-ok", "request {i}: should get error-fallback body");
    }

    // Third request: circuit is open, matched by the
    // transport_error: circuit_open rule and routed to the
    // circuit-fallback step which returns a distinct 503.
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "circuit-open should get static 503 from circuit-fallback");
    assert_eq!(
        body, "circuit breaker open",
        "circuit-open body should prove the circuit_open path was taken"
    );
}

#[test]
fn primary_healthy_no_failover() {
    let primary = start_backend_with_shutdown("primary-ok");
    let fallback = start_backend_with_shutdown("fallback-ok");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/iterative-request-router-circuit-breaker.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", primary.port()), ("127.0.0.1:3001", fallback.port())]),
    );
    let proxy = praxis_test_utils::start_full_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "healthy primary should return 200");
    assert_eq!(body, "primary-ok", "should get primary response");
}
