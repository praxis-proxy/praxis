// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Basic proxy and dead backend tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_status, simple_proxy_yaml, start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn get_to_dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 502, "expected 502 for dead backend, got: {raw}");
}

#[test]
fn post_to_dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 502, "expected 502 for dead backend, got: {raw}");
}

#[test]
fn basic_proxy() {
    let backend_port_guard = start_backend_with_shutdown("hello from backend");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&simple_proxy_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "basic proxy should return 200");
    assert_eq!(body, "hello from backend", "proxy should forward backend response");
}

#[test]
fn round_robin_distribution() {
    let port_a_guard = start_backend_with_shutdown("backend-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("backend-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("backend-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
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
            cluster: "backends"
      - filter: load_balancer
        clusters:
          - name: "backends"
            endpoints:
              - "127.0.0.1:{port_a}"
              - "127.0.0.1:{port_b}"
              - "127.0.0.1:{port_c}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut count_a = 0_u32;
    let mut count_b = 0_u32;
    let mut count_c = 0_u32;
    for _ in 0..15 {
        let (_status, body) = http_get(proxy.addr(), "/", None);
        match body.as_str() {
            "backend-a" => count_a += 1,
            "backend-b" => count_b += 1,
            "backend-c" => count_c += 1,
            other => panic!("unexpected backend body: {other}"),
        }
    }

    assert_eq!(count_a, 5, "expected exactly 5 for backend-a, got {count_a}");
    assert_eq!(count_b, 5, "expected exactly 5 for backend-b, got {count_b}");
    assert_eq!(count_c, 5, "expected exactly 5 for backend-c, got {count_c}");
}
