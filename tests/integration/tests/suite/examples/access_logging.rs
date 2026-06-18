// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access logging example configuration.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_logging() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/access-logging.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "basic request should return 200");
    assert_eq!(parse_body(&raw), "logged", "response body should match backend");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: trace-abc\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Request-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("trace-abc".to_owned()),
        "proxy should echo back the X-Request-Id"
    );
}
