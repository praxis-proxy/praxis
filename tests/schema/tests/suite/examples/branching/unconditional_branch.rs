// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Unconditional branch example config tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, start_header_echo_backend, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn unconditional_branch_injects_headers() {
    let _backend = start_header_echo_backend();
    let backend_port = _backend.port();
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/unconditional-branch.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = praxis_test_utils::http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = praxis_test_utils::parse_status(&raw);
    assert_eq!(status, 200, "unconditional branch request should return 200");
    let body = praxis_test_utils::parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-audit: applied"),
        "unconditional branch should inject X-Audit header; got body:\n{body}"
    );
    assert!(
        lower.contains("x-pipeline: main"),
        "main pipeline should inject X-Pipeline header; got body:\n{body}"
    );
}
