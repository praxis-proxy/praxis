// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Multiple branches example config tests.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_backend, start_header_echo_backend, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn blocked_request_gets_403() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/multiple-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Danger: true\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "request with X-Danger: true should get 403");
}

#[test]
fn passed_request_gets_tagged() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/multiple-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "clean request should reach backend");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-guardrails: passed"),
        "clean request should have X-Guardrails: passed header; got body:\n{body}"
    );
}
