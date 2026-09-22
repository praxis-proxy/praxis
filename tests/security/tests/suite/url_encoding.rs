// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! URL / path encoding attack-vector tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_status, start_backend, start_proxy, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn fragment_identifier_does_not_influence_routing() {
    let allowed = start_backend("allowed");
    let denied = start_backend("denied");
    let proxy_port = free_port();
    let yaml = two_route_yaml(proxy_port, allowed, denied);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let without = http_send(
        proxy.addr(),
        "GET /allowed/resource HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let with_fragment = http_send(
        proxy.addr(),
        "GET /allowed/resource#/denied/secret HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );

    let status_a = parse_status(&without);
    let status_b = parse_status(&with_fragment);

    // Fragment is not sent by browsers over the wire normally; if accepted,
    // routing must still match `/allowed` and not divert to `/denied`.
    if status_b == 200 {
        let body = parse_body(&with_fragment);
        assert_eq!(
            body, "allowed",
            "fragment must not change routing away from /allowed (body={body})"
        );
    } else {
        assert!(
            status_b == 400 || status_b == 0 || status_b == status_a,
            "fragment URI must be rejected or match non-fragment routing (got {status_b})"
        );
    }
}

#[test]
fn null_byte_in_query_string_handled_safely() {
    let backend = start_uri_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_catch_all_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /search?q=hello%00world HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || status == 0,
        "null byte in query must be accepted or cleanly rejected (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");
}

#[test]
fn double_encoded_path_segments_do_not_bypass_matching() {
    let allowed = start_backend("allowed");
    let denied = start_backend("denied");
    let proxy_port = free_port();
    let yaml = two_route_yaml(proxy_port, allowed, denied);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // `%252e%252e` decodes once to `%2e%2e`, not `..`. Must not reach /denied
    // by traversing out of /allowed.
    let raw = http_send(
        proxy.addr(),
        "GET /allowed/%252e%252e/%252e%252e/denied/secret HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_ne!(status, 500, "double-encoded path must not crash");
    if status == 200 {
        assert_ne!(
            body, "denied",
            "double-encoded traversal must not bypass path matching into /denied"
        );
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn simple_catch_all_yaml(proxy_port: u16, backend_port: u16) -> String {
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
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

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
