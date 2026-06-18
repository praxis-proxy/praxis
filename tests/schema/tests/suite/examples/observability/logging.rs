// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Logging example tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn logging() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
        "observability/logging.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request without X-Trace-Id should succeed");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Trace-Id: my-trace-42\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Trace-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-trace-id"),
        Some("my-trace-42".to_owned()),
        "proxy should echo back X-Trace-Id"
    );

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Trace-Id: other-99\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_header(&raw, "x-trace-id"),
        Some("other-99".to_owned()),
        "proxy should echo back different X-Trace-Id"
    );
}
