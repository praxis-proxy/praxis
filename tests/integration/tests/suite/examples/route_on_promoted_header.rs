// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the route-on-promoted-header example configuration.

use std::collections::HashMap;

use praxis_test_utils::{
    BackendGuard, ProxyGuard, free_port, http_get, http_send, parse_body, parse_status, start_backend_with_shutdown,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reads_fall_through_to_the_replica() {
    let (_backends, proxy) = start();

    let (status, body) = http_get(proxy.addr(), "/orders", None);

    assert_eq!(status, 200, "a read should be proxied");
    assert_eq!(
        body, "replica",
        "a read carries no promoted header and should reach the replica"
    );
}

#[test]
fn writes_route_on_the_promoted_header_to_the_primary() {
    let (_backends, proxy) = start();

    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "{method} /orders HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            ),
        );

        assert_eq!(parse_status(&raw), 200, "{method} should be proxied");
        assert_eq!(
            parse_body(&raw),
            "primary",
            "{method} should be tagged by the headers filter and routed to the primary"
        );
    }
}

#[test]
fn client_cannot_spoof_the_promoted_header() {
    let (_backends, proxy) = start();

    let raw = http_send(
        proxy.addr(),
        "GET /orders HTTP/1.1\r\n\
         Host: localhost\r\n\
         x-praxis-traffic: write\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(
        parse_status(&raw),
        400,
        "a client-sent x-praxis-traffic header should be rejected before routing"
    );
    assert_ne!(
        parse_body(&raw),
        "primary",
        "a spoofed promoted header must never reach the primary"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start the primary and replica backends and the example proxy in front of them.
fn start() -> ([BackendGuard; 2], ProxyGuard) {
    let primary = start_backend_with_shutdown("primary");
    let replica = start_backend_with_shutdown("replica");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "pipeline/route-on-promoted-header.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", primary.port()), ("127.0.0.1:3001", replica.port())]),
    );
    let proxy = start_proxy(&config);
    ([primary, replica], proxy)
}
