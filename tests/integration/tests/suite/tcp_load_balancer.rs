// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for TCP load balancing via the `tcp_load_balancer` filter.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tcp_round_robin_distributes_across_backends() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp_rr
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [lb]

clusters:
  - name: pool
    endpoints:
      - "127.0.0.1:{port_a}"
      - "127.0.0.1:{port_b}"
      - "127.0.0.1:{port_c}"

filter_chains:
  - name: lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - "127.0.0.1:{port_a}"
              - "127.0.0.1:{port_b}"
              - "127.0.0.1:{port_c}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_tcp_proxy(config, proxy_port);

    let total = 30u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let tag = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"ping");
        let backend = tag.split(':').next().unwrap_or("").to_owned();
        *counts.entry(backend).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "round-robin should hit all 3 backends");
    for (backend, count) in &counts {
        assert!(
            (9..=11).contains(count),
            "round-robin backend {backend} expected ~10 of 30, got {count}"
        );
    }
}

#[test]
fn tcp_weighted_distribution() {
    let port_light = start_tcp_tagged_backend("light");
    let port_heavy = start_tcp_tagged_backend("heavy");
    let port_medium = start_tcp_tagged_backend("medium");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp_weighted
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [lb]

clusters:
  - name: pool
    endpoints:
      - address: "127.0.0.1:{port_light}"
        weight: 1
      - address: "127.0.0.1:{port_heavy}"
        weight: 2
      - address: "127.0.0.1:{port_medium}"
        weight: 1

filter_chains:
  - name: lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - address: "127.0.0.1:{port_light}"
                weight: 1
              - address: "127.0.0.1:{port_heavy}"
                weight: 2
              - address: "127.0.0.1:{port_medium}"
                weight: 1
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_tcp_proxy(config, proxy_port);

    let total = 200u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let tag = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"ping");
        let backend = tag.split(':').next().unwrap_or("").to_owned();
        *counts.entry(backend).or_default() += 1;
    }

    let light = *counts.get("light").unwrap_or(&0);
    let heavy = *counts.get("heavy").unwrap_or(&0);
    let medium = *counts.get("medium").unwrap_or(&0);
    assert_eq!(light + heavy + medium, total, "all connections should reach a backend");

    let ratio = heavy as f64 / light.max(1) as f64;
    assert!(
        (1.5..=2.5).contains(&ratio),
        "heavy/light ratio should be ~2.0, got {ratio} (heavy={heavy}, light={light})"
    );

    assert!(
        (35..=65).contains(&light),
        "weight-1 'light' expected ~50 of 200, got {light}"
    );
    assert!(
        (80..=120).contains(&heavy),
        "weight-2 'heavy' expected ~100 of 200, got {heavy}"
    );
    assert!(
        (35..=65).contains(&medium),
        "weight-1 'medium' expected ~50 of 200, got {medium}"
    );
}

#[test]
fn tcp_consistent_hash_client_affinity() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp_ch
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [lb]

clusters:
  - name: pool
    endpoints:
      - "127.0.0.1:{port_a}"
      - "127.0.0.1:{port_b}"
      - "127.0.0.1:{port_c}"
    load_balancer_strategy:
      consistent_hash: {{}}

filter_chains:
  - name: lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - "127.0.0.1:{port_a}"
              - "127.0.0.1:{port_b}"
              - "127.0.0.1:{port_c}"
            load_balancer_strategy:
              consistent_hash: {{}}
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_tcp_proxy(config, proxy_port);

    let mut first_backend = String::new();
    for i in 0..5 {
        let tag = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"ping");
        let backend = tag.split(':').next().unwrap_or("").to_owned();
        if i == 0 {
            first_backend = backend.clone();
        }
        assert_eq!(
            backend, first_backend,
            "consistent-hash should route same client IP to same backend on attempt {i}"
        );
    }
}

#[test]
fn tcp_backward_compat_upstream_still_works() {
    let port_a = start_tcp_tagged_backend("legacy");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp_legacy
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{port_a}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_tcp_proxy(config, proxy_port);

    let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"hello");
    assert!(
        resp.starts_with("legacy:"),
        "plain upstream should forward to the single backend, got: {resp}"
    );
    assert!(
        resp.ends_with("hello"),
        "upstream response should contain original payload, got: {resp}"
    );
}

#[test]
fn tcp_least_connections_forwards_correctly() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: tcp_lc
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: pool
    filter_chains: [lb]

clusters:
  - name: pool
    endpoints:
      - "127.0.0.1:{port_a}"
      - "127.0.0.1:{port_b}"
      - "127.0.0.1:{port_c}"
    load_balancer_strategy:
      least_connections: ~

filter_chains:
  - name: lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: pool
            endpoints:
              - "127.0.0.1:{port_a}"
              - "127.0.0.1:{port_b}"
              - "127.0.0.1:{port_c}"
            load_balancer_strategy:
              least_connections: ~
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    start_tcp_proxy(config, proxy_port);

    for _ in 0..5 {
        let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"data");
        assert!(
            resp.contains(':'),
            "least-connections should forward and return tagged response, got: {resp}"
        );
        assert!(
            resp.ends_with("data"),
            "least-connections response should contain original payload, got: {resp}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Start a full Praxis TCP proxy in a background thread and wait for readiness.
fn start_tcp_proxy(config: Config, proxy_port: u16) {
    start_full_proxy(config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
}

/// Send data over TCP and return the response as a string.
fn tcp_send_recv(addr: &str, data: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("TCP connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    stream.write_all(data).expect("TCP write failed");
    stream.shutdown(std::net::Shutdown::Write).expect("TCP shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read failed");
    String::from_utf8_lossy(&buf).into_owned()
}
