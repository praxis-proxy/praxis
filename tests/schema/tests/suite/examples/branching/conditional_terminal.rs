// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Conditional terminal branch example config tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, http_send, parse_status, start_backend, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn dangerous_request_gets_403() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/conditional-terminal.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Danger: true\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        403,
        "request with X-Danger: true should be blocked with 403"
    );
}

#[test]
fn clean_request_reaches_backend() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "branching/conditional-terminal.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "clean request should reach backend");
    assert_eq!(body, "ok", "clean request should return backend body");
}
