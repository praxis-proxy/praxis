// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration scrape coverage for the expanded Prometheus metrics surface (#794).

use std::{io::Write as _, net::TcpStream, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, free_port, http_get, http_send, parse_status, start_backend_with_shutdown, start_full_proxy, start_proxy,
    start_reloadable_proxy, start_slow_backend, wait_for_http, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn scrape_metrics(admin_addr: &str) -> String {
    let (status, body) = http_get(admin_addr, "/metrics", None);
    assert_eq!(status, 200, "/metrics should return 200");
    body
}

fn wait_for_metric(admin_addr: &str, needle: &str, timeout: Duration) -> String {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        last = scrape_metrics(admin_addr);
        if last.contains(needle) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("metric `{needle}` not found within {timeout:?}; last scrape:\n{last}");
}

fn proxy_with_admin(
    proxy_port: u16,
    admin_port: u16,
    backend_port: u16,
    extra_listener: &str,
    filters: &str,
) -> String {
    format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    {extra_listener}
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
{filters}
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

fn router_and_optional(extra_filters: &str) -> String {
    format!(
        r#"
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: backend
{extra_filters}"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn metrics_happy_path_emits_baseline_series_with_real_labels() {
    let backend = start_backend_with_shutdown("metrics-ok");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = proxy_with_admin(proxy_port, admin_port, backend.port(), "", &router_and_optional(""));
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, body) = http_get(proxy.addr(), "/api/hello", None);
    assert_eq!(status, 200, "proxy request should succeed");
    assert_eq!(body, "metrics-ok");

    let metrics = scrape_metrics(&admin);
    for needle in [
        "praxis_http_requests_total",
        "praxis_http_request_duration_seconds",
        "praxis_http_request_body_bytes",
        "praxis_http_response_body_bytes",
        "praxis_connections_active",
        "praxis_upstream_connect_duration_seconds",
        "route=\"/api/*\"",
        "cluster=\"backend\"",
        "method=\"GET\"",
        "status_class=\"2xx\"",
        "listener=\"default\"",
    ] {
        assert!(metrics.contains(needle), "expected `{needle}` in scrape:\n{metrics}");
    }
}

#[test]
fn metrics_overload_rejects_listener_connections() {
    let slow_port = start_slow_backend("slow", Duration::from_secs(3));
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = proxy_with_admin(
        proxy_port,
        admin_port,
        slow_port,
        "max_connections: 1",
        &router_and_optional(""),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let mut held = TcpStream::connect(proxy.addr()).expect("hold connection");
    held.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    held.write_all(b"GET /api/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    let raw = http_send(
        proxy.addr(),
        "GET /api/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 503, "excess connection should be rejected");

    let metrics = wait_for_metric(
        &admin,
        "praxis_overload_rejects_total{reason=\"listener_connections\"}",
        Duration::from_secs(2),
    );
    assert!(
        metrics.contains("praxis_overload_rejects_total{reason=\"listener_connections\"}"),
        "expected listener overload reject counter:\n{metrics}"
    );
    drop(held);
}

// Memory and global-connection overload reasons share the same
// `early_request_filter` call sites as `listener_connections`, but cannot
// be exercised safely end-to-end in this suite: both use process-wide
// `OnceLock` limits that would poison later tests. Label emission for
// `reason=memory` and `reason=global_connections` is covered by
// `overload_reject_reasons_appear_in_scrape` in `protocol` metrics unit tests.

#[test]
fn metrics_upstream_connect_failure_and_retry_exhausted() {
    // Serialize against the retry-success gate test (shared process-global gate).
    let _gate_lock = praxis_protocol::http::pingora::handler::lock_upstream_retry_gate_tests();

    let dead = free_port();
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = proxy_with_admin(proxy_port, admin_port, dead, "", &router_and_optional(""));
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(proxy.addr(), "/api/", None);
    assert_eq!(status, 502, "dead upstream should fail the request");

    let metrics = scrape_metrics(&admin);
    assert!(
        metrics.contains("praxis_upstream_connect_failures_total{cluster=\"backend\"}"),
        "expected connect failure counter:\n{metrics}"
    );
    assert!(
        metrics.contains("praxis_upstream_retries_total{cluster=\"backend\",result=\"exhausted\"}"),
        "expected exhausted retry counter for idempotent GET:\n{metrics}"
    );
}

#[test]
fn metrics_upstream_retry_success_after_transient_connect_failure() {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    let (held, backend_port) = praxis_test_utils::bind_unique_port();
    drop(held);

    // Unique cluster label so wait_for_metric is not satisfied by parallel
    // prometheus tests that share the process-wide recorder under cluster=backend.
    const CLUSTER: &str = "retry_ok_backend";

    // Block retries until this test releases the gate, so the backend can
    // bind without relying on production reconnect backoff.
    let (_gate_lock, release_retry) = praxis_protocol::http::pingora::handler::arm_upstream_retry_gate();

    let (start_bind_tx, start_bind_rx) = mpsc::channel();
    let (bound_tx, bound_rx) = mpsc::channel();
    thread::spawn(move || {
        start_bind_rx.recv().expect("wait to start backend bind");
        let listener = TcpListener::bind(format!("127.0.0.1:{backend_port}")).expect("bind backend");
        bound_tx.send(()).expect("signal backend bound");
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut stream = stream;
                drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
                let mut buf = [0_u8; 4096];
                drop(stream.read(&mut buf));
                let body = b"retry-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                drop(stream.write_all(resp.as_bytes()));
                drop(stream.write_all(body));
            });
        }
    });

    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: {CLUSTER}
      - filter: load_balancer
        clusters:
          - name: {CLUSTER}
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let addr = proxy.addr().to_owned();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(http_get(&addr, "/api/", None)).expect("send result");
    });

    // Wait for the first refused connect, bind the backend, then release
    // the retry gate so the blocked retry can succeed.
    drop(wait_for_metric(
        &admin,
        &format!("praxis_upstream_connect_failures_total{{cluster=\"{CLUSTER}\"}}"),
        Duration::from_secs(5),
    ));
    start_bind_tx.send(()).expect("start backend bind");
    bound_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("backend should bind");
    release_retry.release();

    let (status, body) = rx.recv_timeout(Duration::from_secs(10)).expect("request should finish");
    assert_eq!(status, 200, "request should succeed after backend comes up");
    assert_eq!(body, "retry-ok");

    let success = format!("praxis_upstream_retries_total{{cluster=\"{CLUSTER}\",result=\"success\"}}");
    let metrics = wait_for_metric(&admin, &success, Duration::from_secs(2));
    assert!(
        metrics.contains(&success),
        "expected successful retry counter:\n{metrics}"
    );
}

#[test]
fn metrics_circuit_breaker_open_gauge() {
    // Unique cluster label: the open gauge is process-global and other CB
    // tests would otherwise stomp cluster=backend via new()/Drop seeding 0.
    const CLUSTER: &str = "cb_open_backend";

    let failing = Backend::status(503, "down").start_with_shutdown();
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: {CLUSTER}
      - filter: circuit_breaker
        clusters:
          - name: {CLUSTER}
            consecutive_failures: 1
            recovery_window_secs: 60
      - filter: load_balancer
        clusters:
          - name: {CLUSTER}
            endpoints:
              - "127.0.0.1:{}"
"#,
        failing.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // First request records failure and opens the breaker.
    drop(http_get(proxy.addr(), "/api/", None));
    // Second request should hit open circuit (503 from filter).
    let (status, _) = http_get(proxy.addr(), "/api/", None);
    assert_eq!(status, 503, "open circuit should reject with 503");

    let open = format!("praxis_circuit_breaker_open{{cluster=\"{CLUSTER}\"}} 1");
    let metrics = wait_for_metric(&admin, &open, Duration::from_secs(2));
    assert!(metrics.contains(&open), "expected open circuit gauge:\n{metrics}");
}

#[test]
fn metrics_circuit_breaker_gauge_recovers_to_zero() {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicU16, Ordering},
        },
        thread,
    };

    // Unique cluster label — see metrics_circuit_breaker_open_gauge.
    const CLUSTER: &str = "cb_recover_backend";

    let (held, backend_port) = praxis_test_utils::bind_unique_port();
    drop(held);
    let status_code = Arc::new(AtomicU16::new(503));
    let status_for_server = Arc::clone(&status_code);
    thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{backend_port}")).expect("bind backend");
        for stream in listener.incoming().flatten() {
            let code = status_for_server.load(Ordering::SeqCst);
            thread::spawn(move || {
                let mut stream = stream;
                drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
                let mut buf = [0_u8; 4096];
                drop(stream.read(&mut buf));
                let body = b"cb";
                let reason = if code == 200 { "OK" } else { "Service Unavailable" };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                drop(stream.write_all(resp.as_bytes()));
                drop(stream.write_all(body));
            });
        }
    });

    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: {CLUSTER}
      - filter: circuit_breaker
        clusters:
          - name: {CLUSTER}
            consecutive_failures: 1
            recovery_window_secs: 1
      - filter: load_balancer
        clusters:
          - name: {CLUSTER}
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    drop(http_get(proxy.addr(), "/api/", None));
    let (status, _) = http_get(proxy.addr(), "/api/", None);
    assert_eq!(status, 503, "open circuit should reject with 503");
    let open = format!("praxis_circuit_breaker_open{{cluster=\"{CLUSTER}\"}} 1");
    drop(wait_for_metric(&admin, &open, Duration::from_secs(2)));

    status_code.store(200, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(1100));

    let (status, _) = http_get(proxy.addr(), "/api/", None);
    assert_eq!(status, 200, "half-open probe should succeed after recovery window");

    let closed = format!("praxis_circuit_breaker_open{{cluster=\"{CLUSTER}\"}} 0");
    let metrics = wait_for_metric(&admin, &closed, Duration::from_secs(2));
    assert!(
        metrics.contains(&closed),
        "expected recovered circuit gauge:\n{metrics}"
    );
}

#[test]
fn metrics_circuit_breaker_drop_clears_gauge_on_reload() {
    // Unique cluster label — see metrics_circuit_breaker_open_gauge.
    const CLUSTER: &str = "cb_drop_backend";

    let failing = Backend::status(503, "down").start_with_shutdown();
    let healthy = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let admin_port = free_port();

    let with_cb = |backend_port: u16| {
        format!(
            r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_root: true
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: {CLUSTER}
      - filter: circuit_breaker
        clusters:
          - name: {CLUSTER}
            consecutive_failures: 1
            recovery_window_secs: 60
      - filter: load_balancer
        clusters:
          - name: {CLUSTER}
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
        )
    };
    let without_cb = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_root: true
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: {CLUSTER}
      - filter: load_balancer
        clusters:
          - name: {CLUSTER}
            endpoints:
              - "127.0.0.1:{}"
"#,
        healthy.port()
    );

    let proxy = start_reloadable_proxy(&with_cb(failing.port()));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    drop(http_get(proxy.addr(), "/api/", None));
    let (status, _) = http_get(proxy.addr(), "/api/", None);
    assert_eq!(status, 503, "open circuit should reject with 503");
    let open = format!("praxis_circuit_breaker_open{{cluster=\"{CLUSTER}\"}} 1");
    drop(wait_for_metric(&admin, &open, Duration::from_secs(2)));

    // Removing the circuit_breaker filter drops the old breaker; Drop must
    // clear the gauge so a stale open=1 series does not linger.
    proxy.reload(&without_cb);
    let closed = format!("praxis_circuit_breaker_open{{cluster=\"{CLUSTER}\"}} 0");
    let metrics = wait_for_metric(&admin, &closed, Duration::from_secs(5));
    assert!(
        metrics.contains(&closed),
        "expected Drop cleanup to clear open gauge after reload:\n{metrics}"
    );
}

#[test]
fn metrics_health_transitions_and_endpoint_gauges() {
    let dead = free_port();
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_private_health_checks: true
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{dead}"
    health_check:
      type: tcp
      interval_ms: 100
      timeout_ms: 50
      healthy_threshold: 1
      unhealthy_threshold: 1
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
              - "127.0.0.1:{dead}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    wait_for_http(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let metrics = wait_for_metric(
        &admin,
        "praxis_upstream_health_transitions_total{cluster=\"backend\",result=\"unhealthy\"}",
        Duration::from_secs(5),
    );
    assert!(
        metrics.contains("praxis_upstream_healthy_endpoints{cluster=\"backend\"}"),
        "expected healthy endpoints gauge:\n{metrics}"
    );
    assert!(
        metrics.contains("praxis_upstream_total_endpoints{cluster=\"backend\"}"),
        "expected total endpoints gauge:\n{metrics}"
    );
}

#[test]
fn metrics_lb_panic_mode_when_all_unhealthy() {
    let dead = free_port();
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_private_health_checks: true
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{dead}"
    health_check:
      type: tcp
      interval_ms: 100
      timeout_ms: 50
      healthy_threshold: 1
      unhealthy_threshold: 1
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
              - "127.0.0.1:{dead}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_full_proxy(&config);
    wait_for_http(proxy.addr());
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // Wait until health marks the endpoint unhealthy, then send traffic.
    drop(wait_for_metric(
        &admin,
        "praxis_upstream_health_transitions_total{cluster=\"backend\",result=\"unhealthy\"}",
        Duration::from_secs(5),
    ));
    drop(http_get(proxy.addr(), "/", None));

    let metrics = wait_for_metric(
        &admin,
        "praxis_lb_panic_mode_total{cluster=\"backend\"}",
        Duration::from_secs(2),
    );
    assert!(
        metrics.contains("praxis_lb_panic_mode_total{cluster=\"backend\"}"),
        "expected LB panic counter:\n{metrics}"
    );
}

#[test]
fn metrics_tcp_lb_panic_mode_when_all_unhealthy() {
    let dead = free_port();
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: tcp_default
    address: "127.0.0.1:{proxy_port}"
    protocol: tcp
    cluster: backend
    filter_chains: [main]
insecure_options:
  allow_private_endpoints: true
  allow_private_upstreams: true
  allow_private_health_checks: true
  allow_root: true
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:{dead}"
    health_check:
      type: tcp
      interval_ms: 100
      timeout_ms: 50
      healthy_threshold: 1
      unhealthy_threshold: 1
filter_chains:
  - name: main
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{dead}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_full_proxy(&config);
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy_addr);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    drop(wait_for_metric(
        &admin,
        "praxis_upstream_health_transitions_total{cluster=\"backend\",result=\"unhealthy\"}",
        Duration::from_secs(5),
    ));

    drop(TcpStream::connect_timeout(
        &proxy_addr.parse().expect("proxy addr"),
        Duration::from_secs(2),
    ));

    let metrics = wait_for_metric(
        &admin,
        "praxis_lb_panic_mode_total{cluster=\"backend\"}",
        Duration::from_secs(2),
    );
    assert!(
        metrics.contains("praxis_lb_panic_mode_total{cluster=\"backend\"}"),
        "expected TCP LB panic counter:\n{metrics}"
    );
}

#[test]
fn metrics_config_reload_success_and_failure() {
    let backend = start_backend_with_shutdown("v1");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_root: true
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
              - "127.0.0.1:{}"
"#,
        backend.port()
    );
    let proxy = start_reloadable_proxy(&yaml);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // Successful reload (endpoint swap keeps same shape).
    let backend2 = start_backend_with_shutdown("v2");
    let good = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
insecure_options:
  allow_root: true
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
              - "127.0.0.1:{}"
"#,
        backend2.port()
    );
    proxy.reload(&good);
    let metrics = wait_for_metric(
        &admin,
        "praxis_config_reload_total{result=\"success\"}",
        Duration::from_secs(5),
    );
    assert!(
        metrics.contains("praxis_config_reload_last_success_timestamp"),
        "expected last success timestamp gauge:\n{metrics}"
    );

    proxy.reload("invalid: [[[yaml");
    let metrics = wait_for_metric(
        &admin,
        "praxis_config_reload_total{result=\"failure\"}",
        Duration::from_secs(5),
    );
    assert!(
        metrics.contains("praxis_config_reload_total{result=\"failure\"}"),
        "expected reload failure counter:\n{metrics}"
    );
}
