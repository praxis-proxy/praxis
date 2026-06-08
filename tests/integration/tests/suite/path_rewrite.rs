// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for the path_rewrite filter.

use praxis_test_utils::{free_port, http_get, start_proxy, start_uri_echo_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn strip_prefix_rewrites_upstream_path() {
    let backend_guard = start_uri_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: path_rewrite
        strip_prefix: "/api/v1"
        conditions:
          - when:
              path_prefix: "/api/v1"
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/v1/users", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(body, "/users", "upstream should see stripped path");
}

#[test]
fn strip_prefix_preserves_query_string() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: path_rewrite
        strip_prefix: "/api"
        conditions:
          - when:
              path_prefix: "/api"
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/items?sort=name&limit=10", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(
        body, "/items?sort=name&limit=10",
        "upstream should see stripped path with preserved query"
    );
}

#[test]
fn add_prefix_prepends_to_upstream_path() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: path_rewrite
        add_prefix: "/api/v2"
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/users", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(body, "/api/v2/users", "upstream should see prefixed path");
}

#[test]
fn replace_rewrites_upstream_path_with_regex() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: path_rewrite
        replace:
          pattern: "^/old/(.*)"
          replacement: "/new/$1"
        conditions:
          - when:
              path_prefix: "/old/"
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/old/resource/42", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(body, "/new/resource/42", "upstream should see regex-rewritten path");
}

#[test]
fn rewrite_then_route_uses_rewritten_path() {
    let backend_a_port_guard = start_uri_echo_backend();
    let backend_a_port = backend_a_port_guard.port();
    let backend_b_port_guard = start_uri_echo_backend();
    let backend_b_port = backend_b_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        strip_prefix: "/api/v1"
        conditions:
          - when:
              path_prefix: "/api/v1"
      - filter: router
        routes:
          - path_prefix: "/users/"
            cluster: users_backend
          - path_prefix: "/"
            cluster: default_backend
      - filter: load_balancer
        clusters:
          - name: users_backend
            endpoints:
              - "127.0.0.1:{backend_a_port}"
          - name: default_backend
            endpoints:
              - "127.0.0.1:{backend_b_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/api/v1/users/42", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(
        body, "/users/42",
        "router should match rewritten path /users/42 to users_backend"
    );
}

#[test]
fn no_rewrite_when_prefix_does_not_match() {
    let backend_port_guard = start_uri_echo_backend();
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: path_rewrite
        strip_prefix: "/api/v1"
        conditions:
          - when:
              path_prefix: "/api/v1"
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/other/path", None);
    assert_eq!(status, 200, "request should succeed");
    assert_eq!(
        body, "/other/path",
        "upstream should see original path when condition does not match"
    );
}
