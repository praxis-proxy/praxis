// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! URL / path encoding attack-vector tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, parse_body, parse_status, simple_proxy_yaml, start_backend_with_shutdown, start_proxy,
    start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn fragment_identifier_does_not_influence_routing() {
    let allowed = start_backend_with_shutdown("allowed");
    let denied = start_backend_with_shutdown("denied");
    let proxy_port = free_port();
    let yaml = two_route_yaml(proxy_port, allowed.port(), denied.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let without = super::test_utils::send_text(
        proxy.addr(),
        "GET /allowed/resource HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let with_fragment = super::test_utils::send_text(
        proxy.addr(),
        "GET /allowed/resource#/denied/secret HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );

    assert_eq!(parse_status(&without), 200, "unmodified route must succeed");
    assert_eq!(parse_body(&without), "allowed", "positive control must select /allowed");
    assert_eq!(
        parse_status(&with_fragment),
        200,
        "fragment target must retain its route"
    );
    assert_eq!(
        parse_body(&with_fragment),
        "allowed",
        "fragment must not route to /denied"
    );
}

#[test]
fn null_byte_in_query_string_handled_safely() {
    let backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = super::test_utils::send_text(
        proxy.addr(),
        "GET /search?q=hello%00world HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    assert_eq!(parse_status(&raw), 200, "escaped NUL is a valid query octet");
    assert_eq!(
        parse_body(&raw),
        "/search?q=hello%00world",
        "query must not be decoded, truncated or re-encoded"
    );
}

#[test]
fn double_encoded_path_segments_do_not_bypass_matching() {
    let allowed = start_uri_echo_backend();
    let denied = start_backend_with_shutdown("denied");
    let proxy_port = free_port();
    let yaml = two_route_yaml(proxy_port, allowed.port(), denied.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = super::test_utils::send_text(
        proxy.addr(),
        "GET /allowed/%252e%252e/%252e%252e/denied/secret HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "double-encoded path must reach its configured route"
    );
    assert_eq!(
        parse_body(&raw),
        "/allowed/%252e%252e/%252e%252e/denied/secret",
        "double encoding must not redirect to /denied"
    );
    let control = super::test_utils::send_text(
        proxy.addr(),
        "GET /denied/secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&control), 200, "the alternate route must be reachable");
    assert_eq!(
        parse_body(&control),
        "denied",
        "the route markers must be distinguishable"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build distinguishable routes for URI matching assertions.
fn two_route_yaml(proxy_port: u16, allowed_port: u16, denied_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/allowed"
            cluster: allowed
          - path_prefix: "/denied"
            cluster: denied
          - path_prefix: "/"
            cluster: denied
      - filter: load_balancer
        clusters:
          - name: allowed
            endpoints:
              - "127.0.0.1:{allowed_port}"
          - name: denied
            endpoints:
              - "127.0.0.1:{denied_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}
