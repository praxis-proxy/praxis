// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the tcp-connections-total example
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
fn tcp_connections_total_example_emits_counter() {
    let backend_port = start_tcp_tagged_backend("pg");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-connections-total.yaml",
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
        body.contains("praxis_tcp_connections_total"),
        "metrics should contain praxis_tcp_connections_total counter: {body}"
    );
    assert!(
        body.contains("listener=\"postgres\""),
        "metrics should contain listener=postgres label: {body}"
    );
}

#[test]
fn tcp_connections_total_example_forwards_traffic() {
    let backend_port = start_tcp_tagged_backend("dbdata");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-connections-total.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9901", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(b"hello").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    let resp = String::from_utf8_lossy(&buf);
    assert!(
        resp.contains("dbdata"),
        "tcp-connections-total example should forward to tagged backend, got: {resp}"
    );
}
