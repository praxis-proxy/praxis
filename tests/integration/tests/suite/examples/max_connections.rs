// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for max connections limiting behavior.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_get_retry, http_send, parse_header, parse_status, read_full_response,
    start_backend_with_shutdown, start_full_proxy, start_proxy, start_slow_backend, start_tcp_echo_backend,
    wait_for_tcp,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn max_connections_rejects_excess_http() {
    // The backend only needs to hold the two slots open past the 200ms probe
    // below; a shorter delay keeps the proxy from waiting it out at teardown.
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 2
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
              - "127.0.0.1:{slow_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).expect("write request");
        held.push(stream);
    }

    std::thread::sleep(Duration::from_millis(200));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 503, "third request should be rejected with 503");
    let retry_after = parse_header(&raw, "Retry-After");
    assert_eq!(
        retry_after.as_deref(),
        Some("1"),
        "503 response should include Retry-After: 1"
    );

    drop(held);
}

#[test]
fn max_connections_allows_after_release() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 1
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
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request should succeed");
    assert_eq!(body, "ok", "first request body should match");

    let (status2, body2) = http_get(proxy.addr(), "/", None);
    assert_eq!(status2, 200, "second request after release should succeed");
    assert_eq!(body2, "ok", "second request body should match");
}

#[test]
fn max_connections_holds_permit_across_keepalive_idle() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_slot_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    // Request A completes but leaves its connection open and idle. The
    // listener's single slot belongs to that connection, not to the finished
    // request, so it must stay taken.
    let mut idle = TcpStream::connect(proxy.addr()).expect("TCP connect");
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    idle.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    let raw = read_full_response(&mut idle);
    assert_eq!(parse_status(&raw), 200, "keep-alive request should succeed");

    // Give the proxy time to finish the request and go idle: a request-scoped
    // permit would have been released by now.
    std::thread::sleep(Duration::from_millis(200));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "second connection should be rejected while an idle keep-alive connection holds the only slot"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "503 response should include Retry-After: 1"
    );

    // Closing the idle connection must hand the slot back.
    drop(idle);
    let (status, body) = http_get_retry(proxy.addr(), "/", None);
    assert_eq!(status, 200, "slot should be released when the connection closes");
    assert_eq!(body, "ok", "released slot should serve a normal response");
}

#[test]
fn max_connections_keepalive_reuse_takes_one_slot() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_slot_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    let mut conn = TcpStream::connect(proxy.addr()).expect("TCP connect");
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");

    for attempt in 1..=3 {
        conn.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("write request");
        let raw = read_full_response(&mut conn);
        assert_eq!(
            parse_status(&raw),
            200,
            "request {attempt} on one keep-alive connection should reuse that connection's single slot"
        );
    }
}

#[test]
fn max_connections_rejections_neither_take_nor_park_a_slot() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_slot_yaml(proxy_port, backend_port)).unwrap();
    let proxy = start_proxy(&config);

    // One idle keep-alive connection owns the listener's only slot.
    let mut idle = TcpStream::connect(proxy.addr()).expect("TCP connect");
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    idle.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    assert_eq!(
        parse_status(&read_full_response(&mut idle)),
        200,
        "keep-alive request should succeed"
    );

    // Repeated rejections must not park a permit bundle of their own: a
    // rejected request never acquired one, so there is nothing to persist.
    for attempt in 1..=3 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&raw), 503, "rejected attempt {attempt} should return 503");
    }

    // The only slot still belongs to the idle connection, so closing it must
    // hand the slot back even after those rejections.
    drop(idle);
    let (status, body) = http_get_retry(proxy.addr(), "/", None);
    assert_eq!(status, 200, "slot should be free once the holder closes");
    assert_eq!(body, "ok", "released slot should serve a normal response");
}

#[test]
fn max_connections_h2c_counts_streams_not_transport_connections() {
    // Pins the HTTP/2 limitation documented in
    // docs/operating/configuration.md: Pingora exposes no per-connection hook
    // on HTTP/2, so each concurrent stream is admitted separately and a single
    // transport connection can consume every slot. h2c is enabled on every
    // praxis HTTP listener, so the client alone chooses this path.
    //
    // The backend is slow so the first stream is still in flight when the
    // second arrives on the same connection.
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_slot_yaml(proxy_port, slow_port)).unwrap();
    let proxy = start_proxy(&config);
    let addr = proxy.addr().to_owned();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for h2c");

    let (first, second) = runtime.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("TCP connect for h2c");
        let (client, connection) = h2::client::handshake(tcp).await.expect("h2c handshake");
        let driver = tokio::spawn(async move {
            let _result = connection.await;
        });

        let build = |path: &str| {
            http::Request::get(path)
                .header("host", "localhost")
                .body(())
                .expect("build h2c request")
        };

        let mut client = client.ready().await.expect("client ready for first stream");
        let (first_fut, _) = client.send_request(build("/first"), true).expect("send first stream");

        // Let the first stream reach early_request_filter and take the slot.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut client = client.ready().await.expect("client ready for second stream");
        let (second_fut, _) = client.send_request(build("/second"), true).expect("send second stream");

        let second = second_fut.await.expect("second stream response").status().as_u16();
        let first = first_fut.await.expect("first stream response").status().as_u16();
        driver.abort();
        (first, second)
    });

    assert_eq!(first, 200, "first h2c stream should be admitted");
    assert_eq!(
        second, 503,
        "a second concurrent h2c stream on the same transport connection consumes a second slot"
    );
}

#[test]
fn max_connections_example_config_parses() {
    let proxy_port = free_port();
    let config = super::load_example_config(
        "operations/max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:3001", free_port())]),
    );
    assert_eq!(
        config.listeners[0].max_connections,
        Some(100),
        "max_connections should be 100"
    );
}

#[test]
fn max_connections_example_functional() {
    // Only needs to outlast the 200ms probe below; kept short so the proxy does
    // not wait the backend out at teardown.
    let slow_port = start_slow_backend("slow", Duration::from_secs(1));
    let proxy_port = free_port();

    let mut config = super::load_example_config(
        "operations/max-connections.yaml",
        proxy_port,
        std::collections::HashMap::from([("127.0.0.1:3001", slow_port)]),
    );
    config.listeners[0].max_connections = Some(2);
    let proxy = start_proxy(&config);

    let mut held: Vec<TcpStream> = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(proxy.addr()).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).expect("write request");
        held.push(stream);
    }

    std::thread::sleep(Duration::from_millis(200));

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        503,
        "request beyond max_connections limit should be rejected with 503"
    );
    assert_eq!(
        parse_header(&raw, "Retry-After").as_deref(),
        Some("1"),
        "503 response should include Retry-After: 1"
    );

    drop(held);
}

#[test]
fn max_connections_rejects_excess_tcp() {
    let backend_port = start_tcp_echo_backend();
    let proxy_port = free_port();
    let addr = format!("127.0.0.1:{proxy_port}");
    let yaml = format!(
        r#"
listeners:
  - name: tcp
    address: "{addr}"
    protocol: tcp
    upstream: "127.0.0.1:{backend_port}"
    max_connections: 1
filter_chains: []
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&addr);

    let held = TcpStream::connect(&addr).expect("first TCP connect should succeed");

    std::thread::sleep(Duration::from_millis(200));

    if let Ok(mut stream) = TcpStream::connect(&addr) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut buf = [0_u8; 1];
        let n = stream.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "second TCP connection should be closed");
    }

    drop(held);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a proxy config whose listener admits a single connection.
fn single_slot_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    max_connections: 1
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
insecure_options:
  allow_private_endpoints: true
"#
    )
}
