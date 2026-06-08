// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Named chain reference example config tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, start_header_echo_backend, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn named_chain_ref_injects_headers() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/named-chain-ref.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = praxis_test_utils::http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = praxis_test_utils::parse_status(&raw);
    assert_eq!(status, 200, "named chain ref request should return 200");
    let body = praxis_test_utils::parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-guardrail: applied"),
        "named chain ref should inject X-Guardrail header; got body:\n{body}"
    );
    assert!(
        lower.contains("x-entry: checked"),
        "main pipeline should inject X-Entry header; got body:\n{body}"
    );
}
