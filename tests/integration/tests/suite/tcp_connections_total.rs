// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for TCP connections total counter.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_connections_total_increments_on_each_connection() {
    let backend_port = start_tcp_tagged_backend("counter-test");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"

insecure_options:
  allow_private_upstreams: true

listeners:
  - name: tcp-counter-test
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    for i in 0..3 {
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap_or_else(|e| panic!("connect {i}: {e}"));
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        stream.write_all(b"ping").expect("write");
        stream.shutdown(std::net::Shutdown::Write).expect("shutdown");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read");
    }

    std::thread::sleep(Duration::from_millis(100));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    assert!(
        body.contains("praxis_tcp_connections_total"),
        "/metrics should contain praxis_tcp_connections_total: {body}"
    );
    assert!(
        body.contains("listener=\"tcp-counter-test\""),
        "/metrics should contain listener=tcp-counter-test label: {body}"
    );

    let count_line = body
        .lines()
        .find(|l| l.contains("praxis_tcp_connections_total") && l.contains("tcp-counter-test") && !l.starts_with('#'))
        .expect("should find counter line");
    let count: f64 = count_line
        .split_whitespace()
        .last()
        .expect("counter should have a value")
        .parse()
        .expect("counter value should parse as f64");
    assert!(
        count >= 3.0,
        "counter should be at least 3 after 3 connections, got: {count}"
    );
}
