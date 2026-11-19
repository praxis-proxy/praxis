// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `rate_limit` filter.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, free_port_v6, http_get, http_get_v6, http_send, ipv6_available, parse_header, parse_status,
    start_backend_v6, start_backend_with_shutdown, start_full_proxy, start_proxy, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn rate_limit_allows_within_burst() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 6);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..5 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "request {i} within burst should return 200");
        assert_eq!(body, "ok", "request {i} within burst should return backend response");
    }

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request past burst should return 429");
}

#[test]
fn rate_limit_rejects_over_burst() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 4);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for _ in 0..3 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "requests within burst should return 200");
    }

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request over burst should return 429");

    let retry_after = parse_header(&raw, "retry-after");
    assert!(retry_after.is_some(), "429 should include Retry-After header");
}

#[test]
fn rate_limit_global_shared() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 4);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/a", None);
    assert_eq!(status, 200, "first request should succeed");

    let (status, _) = http_get(proxy.addr(), "/b", None);
    assert_eq!(status, 200, "second request should succeed");

    let (status, _) = http_get(proxy.addr(), "/c", None);
    assert_eq!(status, 200, "third request should succeed");

    let (status, _) = http_get(proxy.addr(), "/d", None);
    assert_eq!(
        status, 429,
        "fourth request should be rate limited (global shares one bucket)"
    );
}

#[test]
fn rate_limit_response_headers_present() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 10);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request should succeed");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "response should contain X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "response should contain X-RateLimit-Remaining"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-reset").is_some(),
        "response should contain X-RateLimit-Reset"
    );
}

#[test]
fn rate_limit_429_includes_rate_limit_headers() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "global", 1.0, 2);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    http_get(proxy.addr(), "/", None);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 429, "second request should be 429");

    assert!(
        parse_header(&raw, "x-ratelimit-limit").is_some(),
        "429 should include X-RateLimit-Limit"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-remaining").is_some(),
        "429 should include X-RateLimit-Remaining"
    );
    assert!(
        parse_header(&raw, "x-ratelimit-reset").is_some(),
        "429 should include X-RateLimit-Reset"
    );
}

#[test]
fn rate_limit_with_conditions() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: global
        rate: 1
        burst: 1
        conditions:
          - when:
              path_prefix: "/api/"
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

    let (status, _) = http_get(proxy.addr(), "/api/data", None);
    assert_eq!(status, 200, "first /api/ request should succeed");

    let (status, _) = http_get(proxy.addr(), "/api/data", None);
    assert_eq!(status, 429, "second /api/ request should be rate limited");

    let (status, body) = http_get(proxy.addr(), "/public", None);
    assert_eq!(status, 200, "non-API path should bypass rate limiter");
    assert_eq!(body, "ok", "non-API path should return backend response");
}

#[test]
fn rate_limit_per_ip_isolates_clients() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "first request within burst should return 200");
    assert_eq!(body, "ok", "first request should return backend response");

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "second request within burst should return 200");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 429, "request exceeding per-IP burst should be rate limited");
}

/// Distinct bound loopback sockets must receive independent limiter buckets.
#[cfg(target_os = "linux")]
#[test]
fn per_ip_distinct_socket_sources_have_independent_buckets() {
    use std::{net::Ipv4Addr, sync::mpsc::TryRecvError};

    use praxis_test_utils::{PayloadSpec, parse_body, start_counting_backend};

    let empty = PayloadSpec::binary(0, 7);
    let a1 = start_counting_backend(empty.clone(), "a1", 0);
    let a2 = start_counting_backend(empty.clone(), "a2", 0);
    let b1 = start_counting_backend(empty.clone(), "b1", 0);
    let b2 = start_counting_backend(empty, "b2", 0);
    let proxy_port = free_port();
    let yaml = per_ip_socket_source_yaml(proxy_port, [a1.port, a2.port, b1.port, b2.port]);
    let config = Config::from_yaml(&yaml).expect("valid two-source rate-limit config");
    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("source-socket runtime");
    let responses = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(12), async {
                let source_a = Ipv4Addr::new(127, 0, 0, 2);
                let source_b = Ipv4Addr::new(127, 0, 0, 3);
                let a1 = bound_source_get(proxy_port, source_a, "/a1", "a1").await;
                let a2 = bound_source_get(proxy_port, source_a, "/a2", "a2").await;
                let b1 = bound_source_get(proxy_port, source_b, "/b1", "b1").await;
                let b2 = bound_source_get(proxy_port, source_b, "/b2", "b2").await;
                [a1, a2, b1, b2]
            })
            .await
        })
        .expect("four-source exchange must complete before rate refill");

    for (response, id) in [(&responses[0], "a1"), (&responses[2], "b1")] {
        assert_eq!(parse_status(response), 200, "permitted {id}: {response}");
        assert_eq!(parse_body(response), "", "exact zero-byte backend response: {response}");
        assert!(response.ends_with("\r\n\r\n"), "complete backend response: {response}");
    }
    for (response, id) in [(&responses[1], "a2"), (&responses[3], "b2")] {
        assert_eq!(parse_status(response), 429, "repeat {id} must be limited: {response}");
    }
    let a1_receipt = a1
        .receipt
        .recv_timeout(Duration::from_secs(3))
        .expect("a1 backend receipt");
    let b1_receipt = b1
        .receipt
        .recv_timeout(Duration::from_secs(3))
        .expect("b1 backend receipt");
    assert_eq!(
        a1_receipt.backend_id, "a1",
        "source A's first request must reach its backend"
    );
    assert_eq!(
        a1_receipt.request_id.as_deref(),
        Some("a1"),
        "source A receipt must identify the allowed request"
    );
    assert_eq!(
        a1_receipt.request_line, "GET /a1 HTTP/1.1",
        "source A receipt must match the measured path"
    );
    assert_eq!(
        b1_receipt.backend_id, "b1",
        "source B's first request must reach its backend"
    );
    assert_eq!(
        b1_receipt.request_id.as_deref(),
        Some("b1"),
        "source B receipt must identify the allowed request"
    );
    assert_eq!(
        b1_receipt.request_line, "GET /b1 HTTP/1.1",
        "source B receipt must match the measured path"
    );
    for receipt in [&a1_receipt, &b1_receipt] {
        assert_eq!(receipt.bytes, 0, "{receipt:?}");
        assert_eq!(receipt.verified_bytes, 0, "{receipt:?}");
        assert_eq!(receipt.mismatch, None, "{receipt:?}");
        assert!(receipt.completion.is_some(), "{receipt:?}");
        assert_eq!(receipt.abort, None, "{receipt:?}");
    }
    assert!(
        matches!(a2.accepted.try_recv(), Err(TryRecvError::Empty)),
        "source A's second request must not reach a backend"
    );
    assert!(
        matches!(b2.accepted.try_recv(), Err(TryRecvError::Empty)),
        "source B's second request must not reach a backend"
    );
    a1.join();
    a2.join();
    b1.join();
    b2.join();
}

/// Make one bounded HTTP request from a verified local source address.
#[cfg(target_os = "linux")]
async fn bound_source_get(proxy_port: u16, source: std::net::Ipv4Addr, path: &str, id: &str) -> String {
    use std::net::{IpAddr, SocketAddr};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpSocket,
        time::timeout,
    };

    let socket = TcpSocket::new_v4().expect("create source socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(source), 0))
        .expect("bind distinct 127/8 source");
    let destination = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let mut stream = timeout(Duration::from_secs(3), socket.connect(destination))
        .await
        .expect("bounded source connect")
        .expect("connect bound source");
    assert_eq!(
        stream.local_addr().expect("local socket address").ip(),
        IpAddr::V4(source),
        "measured connection must use its assigned transport source IP"
    );
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {id}\r\nConnection: close\r\n\r\n");
    timeout(Duration::from_secs(3), stream.write_all(request.as_bytes()))
        .await
        .expect("bounded source write")
        .expect("send bound-source request");
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("bounded source read")
        .expect("read complete bound-source response");
    assert!(response.len() < 4096, "bounded response exceeded 4 KiB");
    String::from_utf8(response).expect("ASCII response")
}

/// Give each measured request identity its own one-request observing backend.
#[cfg(target_os = "linux")]
fn per_ip_socket_source_yaml(proxy_port: u16, ports: [u16; 4]) -> String {
    let [a1, a2, b1, b2] = ports;
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: per_ip
        rate: 0.001
        burst: 1
      - filter: router
        routes:
          - path_prefix: "/a1"
            cluster: a1
          - path_prefix: "/a2"
            cluster: a2
          - path_prefix: "/b1"
            cluster: b1
          - path_prefix: "/b2"
            cluster: b2
      - filter: load_balancer
        clusters:
          - name: a1
            endpoints: ["127.0.0.1:{a1}"]
          - name: a2
            endpoints: ["127.0.0.1:{a2}"]
          - name: b1
            endpoints: ["127.0.0.1:{b1}"]
          - name: b2
            endpoints: ["127.0.0.1:{b2}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// End-to-end IPv6 per-prefix keying through the proxy.
///
/// The loopback interface only offers `::1`, so the harness cannot open
/// connections from distinct addresses in one /64; grouping across
/// addresses is covered by the filter's unit tests. This proves the
/// option parses through the full config path and that an IPv6 client
/// is limited by its masked bucket and reported in response headers.
#[test]
fn rate_limit_per_ip_ipv6_prefix_len() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_port = start_backend_v6("ok");
    let proxy_port = free_port_v6();
    let yaml = rate_limit_yaml(proxy_port, backend_port, "per_ip", 1.0, 3)
        .replace("127.0.0.1:", "[::1]:")
        .replace("        burst: 3\n", "        burst: 3\n        ipv6_prefix_len: 64\n");
    assert!(
        yaml.contains("ipv6_prefix_len: 64"),
        "test config should set ipv6_prefix_len"
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get_v6(proxy.addr(), "/");
    assert_eq!(status, 200, "first IPv6 request within burst should return 200");
    assert_eq!(body, "ok", "first IPv6 request should return backend response");

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "second IPv6 request within burst should return 200"
    );
    assert_eq!(
        parse_header(&raw, "x-ratelimit-remaining").as_deref(),
        Some("0"),
        "response should report the IPv6 prefix bucket as drained"
    );

    let (status, _) = http_get_v6(proxy.addr(), "/");
    assert_eq!(status, 429, "IPv6 request past the prefix burst should be rate limited");
}

#[test]
fn rate_limit_shadow_allows_over_burst_and_reports_headers() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = rate_limit_yaml(proxy_port, backend_port_guard.port(), "global", 1.0, 2)
        .replace("        burst: 2\n", "        burst: 2\n        shadow: true\n");
    assert!(yaml.contains("shadow: true"), "test config should enable shadow mode");
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut drained = false;
    for i in 0..6 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            parse_status(&raw),
            200,
            "shadow request {i} should be allowed past the burst"
        );
        assert!(
            parse_header(&raw, "retry-after").is_none(),
            "shadow response {i} should carry no Retry-After"
        );
        drained |= parse_header(&raw, "x-ratelimit-remaining").as_deref() == Some("0");
    }
    assert!(
        drained,
        "shadow responses should report the drained bucket in X-RateLimit-Remaining"
    );
}

#[test]
fn rate_limit_shadow_does_not_suppress_enforced_limit() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: global
        rate: 1
        burst: 1
        shadow: true
      - filter: rate_limit
        scope: local
        mode: global
        rate: 1
        burst: 4
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

    let statuses: Vec<u16> = (0..10).map(|_| http_get(proxy.addr(), "/", None).0).collect();
    assert_eq!(statuses[0], 200, "first request is within both limits");
    assert_eq!(
        statuses[1], 200,
        "second request exceeds only the shadow limit and must pass through"
    );
    assert!(
        statuses.contains(&429),
        "the enforced limit behind the shadow limit should still reject: {statuses:?}"
    );
}

#[test]
fn rate_limit_shadow_counts_would_be_rejections() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let metrics_port = free_port();
    let yaml = format!(
        r#"
admin:
  metrics_address: "127.0.0.1:{metrics_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: global
        rate: 1
        burst: 1
        shadow: true
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
    let _proxy = start_full_proxy(&config);
    let proxy = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy);
    let metrics = format!("127.0.0.1:{metrics_port}");
    wait_for_tcp(&metrics);

    let series = "praxis_rate_limit_limited_total{shadow=\"true\"} ";
    let limited_total = || {
        let (status, body) = http_get(&metrics, "/metrics", None);
        assert_eq!(status, 200, "/metrics should return 200");
        body.lines()
            .find_map(|line| line.strip_prefix(series))
            .map_or(0, |value| value.trim().parse::<u64>().unwrap())
    };
    let before = limited_total();

    for i in 0..4 {
        let (status, _) = http_get(&proxy, "/", None);
        assert_eq!(status, 200, "shadow request {i} should be allowed");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut after = limited_total();
    while after < before + 3 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        after = limited_total();
    }
    assert!(
        after >= before + 3,
        "three of four requests exceeded a burst of one and should be counted as shadow limited, before={before}, after={after}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a rate-limited proxy YAML config.
fn rate_limit_yaml(proxy_port: u16, backend_port: u16, mode: &str, rate: f64, burst: u32) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: {mode}
        rate: {rate}
        burst: {burst}
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
