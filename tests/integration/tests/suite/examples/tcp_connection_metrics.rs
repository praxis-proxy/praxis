// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the tcp-connection-metrics example
//! configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_test_utils::{free_port, http_get, start_full_proxy, start_tcp_tagged_backend, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn tcp_connection_metrics_example_emits_histogram() {
    let backend_port = start_tcp_tagged_backend("pg");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-connection-metrics.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9901", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"SELECT 1").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    drop(stream);

    std::thread::sleep(Duration::from_millis(100));

    let (status, body) = http_get(&format!("127.0.0.1:{admin_port}"), "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    assert!(
        body.contains("praxis_tcp_connection_duration_seconds"),
        "metrics should contain praxis_tcp_connection_duration_seconds histogram: {body}"
    );
    assert!(
        body.contains("listener=\"postgres\""),
        "metrics should contain listener=postgres label: {body}"
    );
    assert!(
        body.contains("reason=\"completed\""),
        "metrics should contain reason=completed label: {body}"
    );
}

#[test]
fn tcp_connection_metrics_example_forwards_traffic() {
    let backend_port = start_tcp_tagged_backend("dbdata");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-connection-metrics.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9901", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let resp = tcp_send_recv(&format!("127.0.0.1:{proxy_port}"), b"hello");
    assert!(
        resp.contains("dbdata"),
        "tcp-connection-metrics example should forward to tagged backend, got: {resp}"
    );
    assert!(
        resp.contains("hello"),
        "tcp-connection-metrics example should echo payload, got: {resp}"
    );
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn tcp_send_recv(addr: &str, data: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("TCP connect failed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(data).expect("TCP write failed");
    stream.shutdown(std::net::Shutdown::Write).expect("TCP shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read failed");
    String::from_utf8_lossy(&buf).into_owned()
}
