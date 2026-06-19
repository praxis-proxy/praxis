// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for token usage headers filter behavior.
//!
//! Only the no-op path is tested here because no filter in the example
//! pipeline writes token metadata, and it cannot be injected externally
//! via HTTP. The happy path (headers present) is covered by unit tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn token_usage_headers_no_metadata_is_noop() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "ai/token-usage-headers.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");
    assert_eq!(
        parse_header(&raw, "praxis-token-input"),
        None,
        "no token headers without upstream metadata"
    );
    assert_eq!(
        parse_header(&raw, "praxis-token-output"),
        None,
        "no token headers without upstream metadata"
    );
    assert_eq!(
        parse_header(&raw, "praxis-token-total"),
        None,
        "no token headers without upstream metadata"
    );
}
