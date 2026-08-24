// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for TCP connection duration metrics.

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
fn tcp_connection_duration_histogram_emitted_after_connection_close() {
    let backend_port = start_tcp_tagged_backend("metrics-test");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"

insecure_options:
  allow_private_upstreams: true

listeners:
  - name: tcp-metrics-test
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"hello").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    drop(stream);

    std::thread::sleep(Duration::from_millis(100));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    assert!(
        body.contains("praxis_tcp_connection_duration_seconds"),
        "/metrics should contain praxis_tcp_connection_duration_seconds: {body}"
    );
    assert!(
        body.contains("listener=\"tcp-metrics-test\""),
        "/metrics should contain listener=tcp-metrics-test label: {body}"
    );
    assert!(
        body.contains("reason=\"completed\""),
        "/metrics should contain reason=completed label for normal close: {body}"
    );
}

#[test]
fn tcp_connection_duration_uses_correct_listener_label() {
    let backend_port = start_tcp_tagged_backend("label-test");
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"

insecure_options:
  allow_private_upstreams: true

listeners:
  - name: custom-label
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"data").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    drop(stream);

    std::thread::sleep(Duration::from_millis(100));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    assert!(
        body.contains("listener=\"custom-label\""),
        "metric should use the configured listener name as label: {body}"
    );
    assert!(
        body.contains("reason=\"completed\""),
        "metric should contain the reason label: {body}"
    );
}

#[test]
fn tcp_connection_duration_records_connect_failure_reason() {
    let unreachable_port = free_port();
    let proxy_port = free_port();
    let admin_port = free_port();

    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"

insecure_options:
  allow_private_upstreams: true

listeners:
  - name: tcp-fail-test
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    upstream: "127.0.0.1:{unreachable_port}"
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    drop(stream);

    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    assert!(
        body.contains("reason=\"connect_failure\""),
        "/metrics should contain reason=connect_failure for unreachable upstream: {body}"
    );
}
