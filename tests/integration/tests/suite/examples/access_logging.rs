// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access logging example configuration.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown, start_full_proxy,
    start_proxy, start_tcp_tagged_backend, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_logging() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/access-logging.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "basic request should return 200");
    assert_eq!(parse_body(&raw), "logged", "response body should match backend");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Request-Id: trace-abc\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request with X-Request-Id should return 200");
    assert_eq!(
        parse_header(&raw, "x-request-id"),
        Some("trace-abc".to_owned()),
        "proxy should echo back the X-Request-Id"
    );
}

#[test]
fn tcp_access_log_example_forwards_tcp_traffic() {
    let backend_port = start_tcp_tagged_backend("db");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "observability/tcp-access-log.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:5432", proxy_port), ("127.0.0.1:15432", backend_port)]),
    );
    let _proxy = start_full_proxy(&config);
    let addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&addr);

    // Exercise the logged connect/forward/disconnect lifecycle: the
    // tcp_access_log pipeline must forward payloads unchanged.
    let mut stream = TcpStream::connect(&addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream.write_all(b"select 1").expect("TCP write");
    stream.shutdown(std::net::Shutdown::Write).expect("shutdown write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("TCP read");
    let text = String::from_utf8_lossy(&buf);

    assert!(
        text.contains("db"),
        "tcp-access-log example should forward to the tagged backend, got: {text}"
    );
    assert!(
        text.contains("select 1"),
        "tcp-access-log example should echo the payload, got: {text}"
    );
}
