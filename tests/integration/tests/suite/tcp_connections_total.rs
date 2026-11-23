// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for TCP connections total counter.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::{Duration, Instant},
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
    let listener = format!("tcp-counter-{proxy_port}");
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    let admin_addr = format!("127.0.0.1:{admin_port}");

    let yaml = format!(
        r#"
admin:
  metrics_address: "127.0.0.1:{admin_port}"

insecure_options:
  allow_private_upstreams: true

listeners:
  - name: {listener}
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&admin_addr);

    exchange(connect_when_ready(&proxy_addr));
    let baseline = listener_count(&admin_addr, &listener);
    let expected = baseline.checked_add(3).expect("three connections fit the counter");

    for _ in 0..3 {
        exchange(TcpStream::connect(&proxy_addr).expect("connect to TCP listener"));
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let count = listener_count(&admin_addr, &listener);
        if count == expected {
            break;
        }
        assert!(count < expected, "counter overshot exact delta: {baseline} -> {count}");
        assert!(
            Instant::now() < deadline,
            "counter did not reach exact delta: {baseline} -> {count}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn connect_when_ready(proxy_addr: &str) -> TcpStream {
    let address = proxy_addr.parse().expect("TCP listener socket address");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
            Ok(stream) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            },
            Err(error) => panic!("TCP listener did not become ready: {error}"),
        }
    }
}

fn exchange(mut stream: TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"ping").expect("write ping");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write half");
    let mut echo = Vec::new();
    stream.read_to_end(&mut echo).expect("read tagged echo");
    assert_eq!(
        echo, b"counter-test:ping",
        "exchange must complete through tagged backend"
    );
}

fn listener_count(admin_addr: &str, listener: &str) -> u64 {
    let (status, body) = http_get(admin_addr, "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    let count_line = body
        .lines()
        .find(|line| {
            line.starts_with("praxis_tcp_connections_total{") && line.contains(&format!("listener=\"{listener}\""))
        })
        .unwrap_or_else(|| panic!("missing listener counter for {listener}: {body}"));
    count_line
        .split_whitespace()
        .last()
        .expect("counter should have a value")
        .parse()
        .expect("counter value should parse as u64")
}
