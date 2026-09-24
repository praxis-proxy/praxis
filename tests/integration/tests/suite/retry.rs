// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for policy-driven retry behavior.

use std::time::{Duration, Instant};

use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, free_port, http_get, http_send, parse_status, simple_proxy_yaml, start_backend_with_shutdown, start_proxy,
    start_reused_connection_kill_backend,
};

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn cluster_yaml(proxy_port: u16, endpoints: &str, retry_policy: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
{endpoints}
{retry_policy}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn no_retry_policy() -> &'static str {
    r#"
            retry_policy:
              max_retries: 0
"#
}

fn status5xx_retry_policy() -> &'static str {
    r#"
            retry_policy:
              max_retries: 3
              retriable_conditions: [connect_failure, status_5xx]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
"#
}

// -----------------------------------------------------------------------------
// Tests — disabled retries (max_retries: 0)
// -----------------------------------------------------------------------------

#[test]
fn disabled_retry_on_dead_backend_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{dead_port}\""),
        no_retry_policy(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 502, "dead backend with retries disabled should return 502");
}

#[test]
fn disabled_retry_on_dead_backend_post_returns_502() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{dead_port}\""),
        no_retry_policy(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 502, "POST to dead backend should return 502");
}

#[test]
fn disabled_retry_mixed_endpoints_can_return_502() {
    let dead_port = free_port();
    let live_port_guard = start_backend_with_shutdown("live-backend");
    let live_port = live_port_guard.port();
    let proxy_port = free_port();

    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{dead_port}\"\n              - \"127.0.0.1:{live_port}\""),
        no_retry_policy(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut saw_live = false;
    let mut saw_502 = false;
    for _ in 0..10 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        match status {
            200 => {
                assert_eq!(body, "live-backend", "healthy endpoint should serve response");
                saw_live = true;
            },
            502 => saw_502 = true,
            other => panic!("unexpected status {other} from mixed cluster"),
        }
    }

    assert!(saw_live, "at least one request should reach the healthy endpoint");
    assert!(
        saw_502,
        "with retries disabled, at least one request should hit the dead endpoint and return 502"
    );
}

// -----------------------------------------------------------------------------
// Tests — connect-failure alternate-host retry (legacy / default policy)
// -----------------------------------------------------------------------------

#[test]
fn connect_retry_reaches_healthy_endpoint() {
    let dead_port = free_port();
    let live_port_guard = start_backend_with_shutdown("recovered");
    let live_port = live_port_guard.port();
    let proxy_port = free_port();

    // Default (unset) retry policy: connect_failure only, max_retries 3.
    // Prefer the dead endpoint first so the initial attempt fails and retries.
    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{dead_port}\"\n              - \"127.0.0.1:{live_port}\""),
        r#"
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 3
              retriable_conditions: [connect_failure]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
"#,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "connect failure should retry onto the healthy alternate host"
    );
    assert_eq!(body, "recovered");
}

#[test]
fn all_endpoints_down_still_returns_502_after_retries() {
    let dead_a = free_port();
    let dead_b = free_port();
    let proxy_port = free_port();

    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{dead_a}\"\n              - \"127.0.0.1:{dead_b}\""),
        r#"
            retry_policy:
              max_retries: 2
              retriable_conditions: [connect_failure]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
"#,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "all-dead cluster should return 502 after exhausting retries"
    );
}

#[test]
fn non_idempotent_post_does_not_retry_onto_alternate_host() {
    // Port 9 is the discard service; connecting fails immediately and is
    // never bound by other tests (unlike free_port races).
    let live_port_guard = start_backend_with_shutdown("should-not-reach");
    let live_port = live_port_guard.port();
    let proxy_port = free_port();

    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:9\"\n              - \"127.0.0.1:{live_port}\""),
        r#"
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 3
              retriable_conditions: [connect_failure]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
"#,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 502,
        "POST must not retry onto the healthy host without allow_non_idempotent"
    );
}

#[test]
fn allow_non_idempotent_post_retries_onto_alternate_host() {
    let live_port_guard = start_backend_with_shutdown("post-ok");
    let live_port = live_port_guard.port();
    let proxy_port = free_port();

    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:9\"\n              - \"127.0.0.1:{live_port}\""),
        r#"
            load_balancer_strategy: round_robin
            retry_policy:
              max_retries: 3
              allow_non_idempotent: true
              retriable_conditions: [connect_failure]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
"#,
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    );
    let status = parse_status(&raw);
    assert_eq!(
        status, 200,
        "POST with allow_non_idempotent should retry onto the healthy host"
    );
}

// -----------------------------------------------------------------------------
// Tests — HTTP status retry
// -----------------------------------------------------------------------------

#[test]
fn status_5xx_retry_reaches_healthy_backend() {
    let failing = Backend::status(503, "unavailable").start();
    let healthy = Backend::fixed("ok").start();
    let proxy_port = free_port();

    let yaml = cluster_yaml(
        proxy_port,
        &format!("              - \"127.0.0.1:{failing}\"\n              - \"127.0.0.1:{healthy}\""),
        status5xx_retry_policy(),
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "503 should retry onto a healthy alternate host");
    assert_eq!(body, "ok");
}

#[cfg(feature = "upstream-binding")]
#[test]
fn status_5xx_retry_reaches_healthy_backend_through_bound_load_balancer() {
    let failing = Backend::status(503, "unavailable").start();
    let healthy = Backend::fixed("ok").start();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: headers
        branch_chains:
          - name: dispatch
            rejoin: terminal
            chains:
              - name: bound-dispatch
                filters:
                  - filter: load_balancer
                    cluster_source: bound_upstream
                    clusters:
                      - name: "backend"
                        endpoints:
                          - "127.0.0.1:{failing}"
                          - "127.0.0.1:{healthy}"
                        retry_policy:
                          max_retries: 3
                          retriable_conditions: [connect_failure, status_5xx]
                          backoff:
                            base_interval_ms: 1
                            max_interval_ms: 5
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = praxis_test_utils::start_full_proxy(&config);
    praxis_test_utils::wait_for_tcp(proxy.addr());

    for attempt in 0..2 {
        let (status, body) = http_get(proxy.addr(), "/", None);

        assert_eq!(
            status, 200,
            "request {attempt}: a 503 from the bound cluster should retry onto its healthy endpoint"
        );
        assert_eq!(
            body, "ok",
            "request {attempt}: the retry must land on the healthy endpoint"
        );
    }
}

#[test]
fn status_5xx_without_policy_is_forwarded() {
    let failing = Backend::status(503, "unavailable").start();
    let proxy_port = free_port();

    // Legacy / default: connect_failure only — 503 must be forwarded.
    let yaml = simple_proxy_yaml(proxy_port, failing);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 503, "without Status5xx, upstream 503 is forwarded");
}

#[test]
fn reused_connection_failure_retries_replayable_post() {
    let (backend, log) = start_reused_connection_kill_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Connection pooling and reuse are timing-sensitive: under the heavy
    // concurrency of the coverage / full-suite run the probe does not always
    // land on the pooled connection that gets killed, so retry the
    // warmup+probe exchange until we observe the intended reused-connection
    // failure and its transparent retry.
    //
    // The guarantee under test holds on every successful attempt: a POST whose
    // reused upstream connection dies before responding (Pingora ReusedOnly)
    // is replayed on a fresh connection and still returns the pooled backend's
    // 200 to the client, even though POST is non-idempotent — the peer closed
    // the pooled keepalive before processing the request, so replay is safe.
    // A regression that drops the replay keeps surfacing the failure as a 502
    // until the deadline.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (warmup_status, _body) = http_get(proxy.addr(), "/warmup", None);
        assert_eq!(
            warmup_status, 200,
            "warmup request should succeed and pool the connection"
        );

        let logged_before = log.lock().unwrap().len();
        let raw = http_send(
            proxy.addr(),
            "POST /probe HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
        );
        let last_status = parse_status(&raw);
        let attempt = log.lock().unwrap()[logged_before..].to_vec();

        // Did this probe reach the killed, reused connection? The backend
        // records the doomed attempt with request_num > 0 before closing
        // without a response.
        let probe_hit_reused = attempt
            .iter()
            .any(|(_, request_num, method, path)| *request_num > 0 && method == "POST" && path == "/probe");

        // Success: the probe hit the reused connection, and because the killed
        // connection never answers, the client's 200 can only come from the
        // transparent replay on a fresh connection.
        if probe_hit_reused {
            assert_eq!(
                last_status, 200,
                "a replayable POST whose reused upstream connection dies before responding must be \
                 retried on a fresh connection, got {last_status} (attempt: {attempt:?})"
            );
            assert!(
                raw.contains("pooled-ok"),
                "the retried POST should return the pooled backend body, got: {raw:?}"
            );
            return;
        }

        assert!(
            Instant::now() < deadline,
            "a replayable POST on a reused, killed connection should be retried on a fresh \
             connection within the retry window (last status {last_status}, attempt: {attempt:?})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn reused_connection_failure_retries_idempotent_get() {
    let (backend, log) = start_reused_connection_kill_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Connection pooling and reuse are timing-sensitive: under the heavy
    // concurrency of the coverage / full-suite run the probe does not always
    // land on the pooled connection that gets killed, so retry the
    // warmup+probe exchange until we observe the intended reused-connection
    // failure and its transparent retry.
    //
    // The guarantee under test holds on every successful attempt: an idempotent
    // GET whose reused upstream connection dies mid-request is retried on a
    // fresh connection and still returns the pooled backend's 200 to the
    // client. A regression that drops the retry keeps surfacing the failure as
    // a 502 until the deadline; one that simply never reuses a connection keeps
    // retrying the exchange. The exact replay count is left unchecked on
    // purpose: a retry can chain through more than one pooled, kill-on-reuse
    // connection before landing on a fresh one, so the count is timing-derived.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (warmup_status, _body) = http_get(proxy.addr(), "/warmup", None);
        assert_eq!(
            warmup_status, 200,
            "warmup request should succeed and pool the connection"
        );

        let logged_before = log.lock().unwrap().len();
        let (status, body) = http_get(proxy.addr(), "/probe", None);
        let attempt = log.lock().unwrap()[logged_before..].to_vec();

        // Did this probe reach the killed, reused connection? The backend
        // records the doomed attempt with request_num > 0 before closing
        // without a response.
        let probe_hit_reused = attempt
            .iter()
            .any(|(_, request_num, method, path)| *request_num > 0 && method == "GET" && path == "/probe");

        // Success: the probe hit the reused connection, and because the killed
        // connection never answers, the client's 200 can only come from the
        // transparent retry on a fresh connection.
        if probe_hit_reused {
            assert_eq!(
                status, 200,
                "reused-connection failure on an idempotent GET should be retried to success, \
                 got {status} (attempt: {attempt:?})"
            );
            assert_eq!(body, "pooled-ok");
            return;
        }

        assert!(
            Instant::now() < deadline,
            "an idempotent GET on a reused, killed connection should be retried on a fresh \
             connection within the retry window (last status {status}, attempt: {attempt:?})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn sequential_requests_to_dead_backend_all_fail() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    for i in 0..3 {
        let (status, _body) = http_get(proxy.addr(), "/", None);
        assert_eq!(
            status, 502,
            "request {i} to sole dead backend should return 502 after retries"
        );
    }
}
