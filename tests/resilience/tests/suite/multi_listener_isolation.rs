// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests verifying that multiple listeners have independent
//! failure domains: a backend failure on one listener does
//! not affect traffic on another.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend, start_proxy, wait_for_http, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn dead_backend_on_one_listener_does_not_affect_other() {
    let live_port = start_backend("listener-b-ok");
    let dead_port = free_port();
    let port_a = free_port();
    let port_b = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: listener_a
    address: "127.0.0.1:{port_a}"
    filter_chains: [chain_a]
  - name: listener_b
    address: "127.0.0.1:{port_b}"
    filter_chains: [chain_b]
filter_chains:
  - name: chain_a
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: dead_cluster
      - filter: load_balancer
        clusters:
          - name: dead_cluster
            endpoints:
              - "127.0.0.1:{dead_port}"
  - name: chain_b
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: live_cluster
      - filter: load_balancer
        clusters:
          - name: live_cluster
            endpoints:
              - "127.0.0.1:{live_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{port_b}"));

    let (status_a, _) = http_get(&format!("127.0.0.1:{port_a}"), "/", None);
    assert_eq!(status_a, 502, "listener A with dead backend should return 502");

    let (status_b, body_b) = http_get(&format!("127.0.0.1:{port_b}"), "/", None);
    assert_eq!(
        status_b, 200,
        "listener B should be unaffected by listener A's dead backend"
    );
    assert_eq!(body_b, "listener-b-ok", "listener B should serve its own backend");
}

#[test]
fn independent_pipelines_per_listener() {
    let backend_port = start_backend("shared-backend");
    let port_a = free_port();
    let port_b = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: alpha
    address: "127.0.0.1:{port_a}"
    filter_chains: [shared, headers_alpha]
  - name: beta
    address: "127.0.0.1:{port_b}"
    filter_chains: [shared, headers_beta]
filter_chains:
  - name: shared
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
  - name: headers_alpha
    filters:
      - filter: headers
        response_add:
          - name: X-Listener
            value: alpha
  - name: headers_beta
    filters:
      - filter: headers
        response_add:
          - name: X-Listener
            value: beta
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{port_b}"));

    let raw_a = praxis_test_utils::http_send(
        &format!("127.0.0.1:{port_a}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        raw_a.contains("x-listener: alpha"),
        "listener alpha should add its own header, got:\n{raw_a}"
    );
    assert!(
        !raw_a.contains("x-listener: beta"),
        "listener alpha should not have beta's header"
    );

    let raw_b = praxis_test_utils::http_send(
        &format!("127.0.0.1:{port_b}"),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        raw_b.contains("x-listener: beta"),
        "listener beta should add its own header, got:\n{raw_b}"
    );
    assert!(
        !raw_b.contains("x-listener: alpha"),
        "listener beta should not have alpha's header"
    );
}

#[test]
fn three_listeners_independent_routing() {
    let api_port = start_backend("api-data");
    let web_port = start_backend("web-page");
    let internal_port = start_backend("internal-service");
    let listen_a = free_port();
    let listen_b = free_port();
    let listen_c = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: api
    address: "127.0.0.1:{listen_a}"
    filter_chains: [api_chain]
  - name: web
    address: "127.0.0.1:{listen_b}"
    filter_chains: [web_chain]
  - name: internal
    address: "127.0.0.1:{listen_c}"
    filter_chains: [internal_chain]
filter_chains:
  - name: api_chain
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: api_backend
      - filter: load_balancer
        clusters:
          - name: api_backend
            endpoints:
              - "127.0.0.1:{api_port}"
  - name: web_chain
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: web_backend
      - filter: load_balancer
        clusters:
          - name: web_backend
            endpoints:
              - "127.0.0.1:{web_port}"
  - name: internal_chain
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: internal_backend
      - filter: load_balancer
        clusters:
          - name: internal_backend
            endpoints:
              - "127.0.0.1:{internal_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{listen_b}"));
    wait_for_http(&format!("127.0.0.1:{listen_c}"));

    let (status, body) = http_get(&format!("127.0.0.1:{listen_a}"), "/", None);
    assert_eq!(status, 200, "API listener should return 200");
    assert_eq!(body, "api-data", "API listener should route to API backend");

    let (status, body) = http_get(&format!("127.0.0.1:{listen_b}"), "/", None);
    assert_eq!(status, 200, "web listener should return 200");
    assert_eq!(body, "web-page", "web listener should route to web backend");

    let (status, body) = http_get(&format!("127.0.0.1:{listen_c}"), "/", None);
    assert_eq!(status, 200, "internal listener should return 200");
    assert_eq!(
        body, "internal-service",
        "internal listener should route to internal backend"
    );
}

#[test]
fn listener_with_dead_backend_does_not_stall_other_listeners() {
    let live_port = start_backend("fast-response");
    let dead_port = free_port();
    let port_fast = free_port();
    let port_dead = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: fast
    address: "127.0.0.1:{port_fast}"
    filter_chains: [fast_chain]
  - name: dead
    address: "127.0.0.1:{port_dead}"
    filter_chains: [dead_chain]
filter_chains:
  - name: fast_chain
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: live
      - filter: load_balancer
        clusters:
          - name: live
            endpoints:
              - "127.0.0.1:{live_port}"
  - name: dead_chain
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: dead
      - filter: load_balancer
        clusters:
          - name: dead
            endpoints:
              - "127.0.0.1:{dead_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{port_dead}"));

    let (status_dead, _) = http_get(&format!("127.0.0.1:{port_dead}"), "/", None);
    assert_eq!(status_dead, 502, "dead listener should return 502");

    for i in 0..5 {
        let (status, body) = http_get(&format!("127.0.0.1:{port_fast}"), "/", None);
        assert_eq!(
            status, 200,
            "fast listener request {i} should succeed despite dead listener"
        );
        assert_eq!(body, "fast-response", "fast listener request {i} body mismatch");
    }
}
