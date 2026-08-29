// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log field selection example configuration.

use std::collections::HashMap;

use praxis_test_utils::{Backend, free_port, http_send, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_fields() {
    let ok_backend = start_backend_with_shutdown("ok");
    let error_port = Backend::status(500, "error").start();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/access-log-fields.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", ok_backend.port()), ("127.0.0.1:3001", error_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "successful route should return 200");

    let raw = http_send(
        proxy.addr(),
        "GET /error HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 500, "error route should return 500");
}
