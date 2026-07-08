// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for operations example configurations.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_send, parse_header, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn container_default() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "operations/container-default.yaml",
        proxy_port,
        HashMap::from([("0.0.0.0:9901", admin_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "container default root should return 200");
    assert!(
        body.contains(r#""status": "ok""#),
        "response should contain status ok, got: {body}"
    );

    let (status, body) = http_get(proxy.addr(), "/nonexistent", None);
    assert_eq!(status, 404, "container default unknown path should return 404");
    assert!(
        body.contains(r#""error": "not found""#),
        "404 response should contain error message, got: {body}"
    );
}

#[test]
fn log_overrides() {
    let proxy_port = free_port();
    let config = super::load_example_config("operations/log-overrides.yaml", proxy_port, HashMap::new());
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "log overrides should return 200");
    assert!(
        body.contains(r#""status": "ok""#),
        "response should contain status ok, got: {body}"
    );
}

#[test]
fn production_gateway() {
    let api_port_guard = start_backend_with_shutdown("api-ok");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web-ok");
    let web_port = web_port_guard.port();
    let http_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: http
    address: "127.0.0.1:{http_port}"
    filter_chains:
      - observability
      - security
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: security
    filters:
      - filter: timeout
        timeout_ms: 10000
      - filter: headers
        request_add:
          - name: "X-Forwarded-By"
            value: "praxis"
        response_set:
          - name: "X-Frame-Options"
            value: "DENY"
          - name: "X-Content-Type-Options"
            value: "nosniff"
          - name: "Referrer-Policy"
            value: "strict-origin-when-cross-origin"
        response_remove:
          - "Server"
          - "X-Powered-By"

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            load_balancer_strategy: least_connections
            connection_timeout_ms: 2000
            read_timeout_ms: 10000
            idle_timeout_ms: 60000
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: web
            load_balancer_strategy: round_robin
            connection_timeout_ms: 2000
            read_timeout_ms: 10000
            idle_timeout_ms: 60000
            endpoints:
              - "127.0.0.1:{web_port}"

runtime:
  threads: 0
  work_stealing: true

shutdown_timeout_secs: 30
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = format!("127.0.0.1:{http_port}");
    let _proxy = start_proxy(&config);

    let (status, body) = http_get(&addr, "/api/v1/users", None);
    assert_eq!(status, 200, "production gateway /api/ should return 200");
    assert_eq!(body, "api-ok", "/api/ should route to api backend");

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "production gateway root should return 200");
    assert_eq!(body, "web-ok", "root should route to web backend");

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(
        parse_header(&raw, "x-frame-options"),
        Some("DENY".to_owned()),
        "X-Frame-Options should be DENY"
    );
    assert_eq!(
        parse_header(&raw, "x-content-type-options"),
        Some("nosniff".to_owned()),
        "X-Content-Type-Options should be nosniff"
    );
}
