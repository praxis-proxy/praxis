// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Functional integration tests for TCP protocol example configurations.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use praxis_test_utils::{free_port, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn tcp_round_robin_example_distributes_traffic() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/tcp-round-robin.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", port_a),
            ("127.0.0.1:15433", port_b),
            ("127.0.0.1:15434", port_c),
        ]),
    );
    start_tcp_proxy(config, proxy_port);

    let total = 30u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let tag = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"ping");
        let backend = tag.split(':').next().unwrap_or("").to_owned();
        *counts.entry(backend).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "round-robin example should hit all 3 backends");
    for (backend, count) in &counts {
        assert!(
            (9..=11).contains(count),
            "round-robin backend {backend} expected ~10 of 30, got {count}"
        );
    }
}

#[test]
fn tcp_least_connections_example_forwards_correctly() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/tcp-least-connections.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", port_a),
            ("127.0.0.1:15433", port_b),
            ("127.0.0.1:15434", port_c),
        ]),
    );
    start_tcp_proxy(config, proxy_port);

    for _ in 0..5 {
        let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"data");
        assert!(
            resp.contains(':'),
            "least-connections example should forward and return tagged response, got: {resp}"
        );
        assert!(
            resp.ends_with("data"),
            "least-connections response should contain original payload, got: {resp}"
        );
    }
}

#[test]
fn tcp_consistent_hash_example_maintains_affinity() {
    let port_a = start_tcp_tagged_backend("a");
    let port_b = start_tcp_tagged_backend("b");
    let port_c = start_tcp_tagged_backend("c");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "protocols/tcp-consistent-hash.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:6379", proxy_port),
            ("127.0.0.1:16379", port_a),
            ("127.0.0.1:16380", port_b),
            ("127.0.0.1:16381", port_c),
        ]),
    );
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
            "consistent-hash example should route same client to same backend on attempt {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Start a full Praxis TCP proxy in a background thread and wait for readiness.
fn start_tcp_proxy(config: praxis_core::config::Config, proxy_port: u16) {
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
