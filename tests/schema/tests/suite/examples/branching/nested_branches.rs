// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Nested branches example config tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, http_send, parse_status, start_backend, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn nested_branch_blocks_dangerous_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/nested-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Danger: true\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 403, "nested branch should block dangerous request");
}

#[test]
fn nested_branch_allows_clean_request() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/nested-branches.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "clean request should reach backend");
    assert_eq!(body, "ok", "clean request should return backend body");
}
