// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the conditional filters example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn conditional_filters() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/conditional-filters.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST /api/items HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "POST with conditional filters should return 200"
    );
    assert_eq!(parse_body(&raw), "ok", "POST response body should match backend");
    let raw_get = http_send(
        proxy.addr(),
        "GET /api/items HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw_get),
        200,
        "GET with conditional filters should return 200"
    );
    assert_eq!(parse_body(&raw_get), "ok", "GET response body should match backend");
}
