// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log text template example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_template() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/access-log-template.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    // The access_log filter renders the configured text template
    // (`{method} {path} {status} {duration_ms}ms id={request_id}`) through the
    // tracing subscriber, which the in-process harness does not capture. This
    // test therefore only asserts that the template config loads and does not
    // disrupt proxying; the exact rendered output is covered by the unit tests
    // (`render_text_template_*`). The `{request_id}` token
    // is backed by the request_id filter in the chain, so the echoed id below
    // confirms that token's source ran.
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "templated access log should not disrupt proxying"
    );

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: tmpl-abc\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Request-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("tmpl-abc".to_owned()),
        "request_id filter backing the {{request_id}} template token should echo the id"
    );
}
