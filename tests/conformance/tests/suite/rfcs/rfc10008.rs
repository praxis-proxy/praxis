// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! [RFC 10008] QUERY resource discovery and redirect forwarding.
//!
//! [RFC 10008]: https://datatracker.ietf.org/doc/html/rfc10008

use praxis_core::config::Config;
use praxis_test_utils::{Backend, free_port, http_send, parse_header, parse_status, simple_proxy_yaml, start_proxy};

// -----------------------------------------------------------------------------
// RFC 10008 Section 3 - Accept-Query
// -----------------------------------------------------------------------------

/// [RFC 10008 Section 3]: a resource advertises its query formats with
/// `Accept-Query`. A proxy must preserve that discovery response.
///
/// [RFC 10008 Section 3]: https://datatracker.ietf.org/doc/html/rfc10008#section-3
#[test]
fn query_resource_discovery_preserves_allow_and_accept_query() {
    let backend = Backend::fixed("")
        .header("Allow", "OPTIONS, QUERY")
        .header("Accept-Query", "application/json, application/sql;charset=\"UTF-8\"")
        .start_with_shutdown();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /products HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200);
    assert_eq!(parse_header(&raw, "allow"), Some("OPTIONS, QUERY".to_owned()));
    assert_eq!(
        parse_header(&raw, "accept-query"),
        Some("application/json, application/sql;charset=\"UTF-8\"".to_owned())
    );
}

// -----------------------------------------------------------------------------
// RFC 10008 Section 2.5 - Redirection
// -----------------------------------------------------------------------------

/// [RFC 10008 Section 2.5]: the origin's QUERY redirect reaches the client
/// with its status and Location intact, for the client to handle.
///
/// [RFC 10008 Section 2.5]: https://datatracker.ietf.org/doc/html/rfc10008#section-2.5
#[test]
fn query_redirects_preserve_status_and_location() {
    for status in [301, 302, 303, 307, 308] {
        let backend = Backend::status(status, "redirect")
            .header("Location", "/results/123")
            .start_with_shutdown();
        let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
        let proxy = start_proxy(&config);

        let raw = http_send(
            proxy.addr(),
            "QUERY /products HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );

        assert_eq!(
            parse_status(&raw),
            status,
            "QUERY redirect should reach the client: {raw}"
        );
        assert_eq!(parse_header(&raw, "location"), Some("/results/123".to_owned()));
    }
}
