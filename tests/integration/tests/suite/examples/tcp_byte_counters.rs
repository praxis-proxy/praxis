// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the tcp-byte-counters example
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
fn tcp_byte_counters_example_emits_counters() {
    let backend_port = start_tcp_tagged_backend("pg");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-byte-counters.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    send_and_close(proxy_port, b"SELECT 1");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (status, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(status, 200, "/metrics should return 200");
        body = scrape;
        if body.contains("praxis_tcp_bytes_received_total") && body.contains("praxis_tcp_bytes_sent_total") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for needle in [
        "praxis_tcp_bytes_received_total",
        "praxis_tcp_bytes_sent_total",
        "listener=\"postgres\"",
    ] {
        assert!(body.contains(needle), "metrics should contain `{needle}`: {body}");
    }
}

#[test]
fn tcp_byte_counters_example_forwards_traffic() {
    let backend_port = start_tcp_tagged_backend("dbdata");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-byte-counters.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:5432", proxy_port),
            ("127.0.0.1:15432", backend_port),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let resp = send_and_close(proxy_port, b"hello");
    assert!(
        resp.contains("dbdata"),
        "tcp-byte-counters example should forward to tagged backend, got: {resp}"
    );
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn send_and_close(proxy_port: u16, payload: &[u8]) -> String {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).expect("TCP connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(payload).expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    String::from_utf8_lossy(&buf).into_owned()
}
