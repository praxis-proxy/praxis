// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the per-cluster `max_connections` concurrency ceiling.
//!
//! The listener-level cap is covered by `super::max_connections`. These tests
//! keep the listener uncapped so every rejection they observe can only come
//! from the cluster's own ceiling.

use std::{io::Write as _, net::TcpStream, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown, start_proxy,
    start_slow_backend,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open `count` connections to `addr` and write a request on each without
/// reading the response, leaving them in flight at the upstream.
fn hold_in_flight(addr: &str, path: &str, count: usize) -> Vec<TcpStream> {
    let mut held = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = TcpStream::connect(addr).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
            .expect("write request");
        held.push(stream);
    }
    // Let the proxy admit each held request before the probe that follows.
    std::thread::sleep(Duration::from_millis(200));
    held
}

/// Single-cluster config with the listener uncapped and the cluster capped
/// at `max_connections`.
fn single_cluster_yaml(proxy_port: u16, backend_port: u16, max_connections: u32) -> String {
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
            max_connections: {max_connections}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cluster_max_connections_rejects_excess_with_503() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_cluster_yaml(proxy_port, slow_port, 2)).unwrap();
    let proxy = start_proxy(&config);

    let held = hold_in_flight(proxy.addr(), "/", 2);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "a request past the cluster's max_connections should be shed with 503"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "cluster shedding should carry Retry-After: 1 like the listener cap"
    );

    drop(held);
}

#[test]
fn cluster_max_connections_allows_after_release() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_cluster_yaml(proxy_port, backend_guard.port(), 1)).unwrap();
    let proxy = start_proxy(&config);

    for attempt in 0..3 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "sequential request {attempt} should reuse the one slot");
        assert_eq!(body, "ok", "request {attempt} should reach the backend");
    }
}

#[test]
fn cluster_max_connections_is_per_cluster_not_per_listener() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let fast_guard = start_backend_with_shutdown("fast");
    let fast_port = fast_guard.port();
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
          - path_prefix: "/slow/"
            cluster: slow-model
          - path_prefix: "/"
            cluster: fast-api
      - filter: load_balancer
        clusters:
          - name: slow-model
            endpoints:
              - "127.0.0.1:{slow_port}"
            max_connections: 1
          - name: fast-api
            endpoints:
              - "127.0.0.1:{fast_port}"
            max_connections: 64
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let held = hold_in_flight(proxy.addr(), "/slow/one", 1);

    let raw = http_send(
        proxy.addr(),
        "GET /slow/two HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "the saturated cluster should shed its own excess"
    );

    let (status, body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(
        status, 200,
        "a cluster under its own ceiling must keep serving while another is saturated"
    );
    assert_eq!(body, "fast", "the unsaturated cluster should reach its backend");

    drop(held);
}

#[test]
fn cluster_max_connections_example_config_parses() {
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/cluster-max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:9000", free_port()), ("127.0.0.1:9001", free_port())]),
    );
    let clusters = config.filter_chains[0].filters[1]
        .config
        .get("clusters")
        .and_then(serde_yaml::Value::as_sequence)
        .expect("load_balancer should declare clusters");
    let caps: Vec<Option<u64>> = clusters
        .iter()
        .map(|cluster| cluster.get("max_connections").and_then(serde_yaml::Value::as_u64))
        .collect();
    assert_eq!(
        caps,
        vec![Some(2), Some(64)],
        "both example clusters should carry their own ceiling"
    );
}

#[test]
fn cluster_max_connections_example_functional() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let fast_guard = start_backend_with_shutdown("fast");
    let proxy_port = free_port();

    let config = super::load_example_config(
        "traffic-management/cluster-max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:9000", slow_port), ("127.0.0.1:9001", fast_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // The example caps slow-model at 2; fill it, then prove the third is shed
    // while the uncapped-in-practice fast-api cluster still answers.
    let held = hold_in_flight(proxy.addr(), "/slow/one", 2);

    let raw = http_send(
        proxy.addr(),
        "GET /slow/three HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "the example's slow-model ceiling of 2 should shed the third request"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "the example's shed response should carry Retry-After: 1"
    );

    let (status, body) = http_get(proxy.addr(), "/anything", None);
    assert_eq!(status, 200, "the example's fast-api cluster should stay available");
    assert_eq!(body, "fast", "fast-api should reach its own backend");

    drop(held);
}
