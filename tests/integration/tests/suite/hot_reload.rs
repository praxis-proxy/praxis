// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration tests for hot config reload.

use std::time::Duration;

use praxis_test_utils::{
    net::{
        backend::{start_backend_with_shutdown, start_slow_backend},
        http_client::http_get,
        port::free_port,
    },
    start_reloadable_proxy,
};

// ---------------------------------------------------------------------------
// Core Reload
// ---------------------------------------------------------------------------

#[test]
fn reload_route_change_shifts_traffic() {
    let backend1 = start_backend_with_shutdown("backend1");
    let backend2 = start_backend_with_shutdown("backend2");
    let proxy_port = free_port();

    let yaml = proxy_yaml(proxy_port, backend1.port());
    let proxy = start_reloadable_proxy(&yaml);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "initial request should succeed");
    assert_eq!(body, "backend1", "should route to backend1 initially");

    proxy.reload(&proxy_yaml(proxy_port, backend2.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "reloaded request should succeed");
    assert_eq!(body, "backend2", "should route to backend2 after reload");
}

#[test]
fn reload_endpoint_swap_shifts_traffic() {
    let backend1 = start_backend_with_shutdown("endpoint-a");
    let backend2 = start_backend_with_shutdown("endpoint-b");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend1.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "endpoint-a", "should hit endpoint-a initially");

    proxy.reload(&proxy_yaml(proxy_port, backend2.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "endpoint-b", "should hit endpoint-b after reload");
}

#[test]
fn reload_adds_filter() {
    let backend = start_backend_with_shutdown("proxied");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);
    assert_eq!(body, "proxied", "should proxy to backend initially");

    proxy.reload(&static_yaml(proxy_port, "intercepted"));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);
    assert_eq!(
        body, "intercepted",
        "static_response filter should intercept after reload"
    );
}

#[test]
fn reload_removes_filter() {
    let backend = start_backend_with_shutdown("backend-response");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&static_yaml(proxy_port, "static-body"));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);
    assert_eq!(body, "static-body", "static_response should serve initially");

    proxy.reload(&proxy_yaml(proxy_port, backend.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);
    assert_eq!(
        body, "backend-response",
        "should proxy to backend after removing static_response"
    );
}

// ---------------------------------------------------------------------------
// Error Resilience
// ---------------------------------------------------------------------------

#[test]
fn reload_invalid_yaml_keeps_old_config() {
    let backend = start_backend_with_shutdown("original");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "original", "initial request works");

    proxy.reload("invalid: [[[yaml syntax");

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "should still serve after invalid config");
    assert_eq!(body, "original", "should use old pipeline after invalid config");
}

#[test]
fn reload_unknown_filter_keeps_old_config() {
    let backend = start_backend_with_shutdown("still-here");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend.port()));

    let bad_yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_xyz
"#
    );

    proxy.reload(&bad_yaml);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "should still serve after bad filter config");
    assert_eq!(body, "still-here", "old pipeline preserved");
}

#[test]
fn reload_recovers_after_invalid_then_valid() {
    let backend1 = start_backend_with_shutdown("v1");
    let backend2 = start_backend_with_shutdown("v2");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend1.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "v1");

    proxy.reload("garbage");

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "v1", "still serving v1 after garbage config");

    proxy.reload(&proxy_yaml(proxy_port, backend2.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "v2", "should recover and serve v2 after valid config");
}

// ---------------------------------------------------------------------------
// In-Flight Safety
// ---------------------------------------------------------------------------

#[test]
fn reload_mid_flight_old_request_completes_with_old_pipeline() {
    let slow_port = start_slow_backend("slow-response", Duration::from_secs(2));
    let fast_backend = start_backend_with_shutdown("fast-response");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, slow_port));
    let proxy_addr = proxy.addr().to_owned();

    let in_flight = std::thread::spawn(move || http_get(&proxy_addr, "/", None));

    std::thread::sleep(Duration::from_millis(200));

    proxy.write_config(&proxy_yaml(proxy_port, fast_backend.port()));
    std::thread::sleep(Duration::from_millis(1500));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200);
    assert_eq!(body, "fast-response", "new request should use new pipeline");

    let (old_status, old_body) = in_flight.join().expect("in-flight thread panicked");
    assert_eq!(old_status, 200);
    assert_eq!(
        old_body, "slow-response",
        "in-flight request should complete with old pipeline"
    );
}

// ---------------------------------------------------------------------------
// Stateful Filter Reset
// ---------------------------------------------------------------------------

#[test]
fn reload_resets_rate_limit_bucket() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();

    let yaml = rate_limit_yaml(proxy_port, backend.port(), 5);
    let proxy = start_reloadable_proxy(&yaml);

    for i in 0..4 {
        let (s, _) = http_get(proxy.addr(), "/", None);
        assert_eq!(s, 200, "request {i} should be within burst");
    }

    let (s_limited, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(s_limited, 429, "should be rate limited after burst exhausted");

    proxy.reload(&rate_limit_yaml(proxy_port, backend.port(), 5));

    let (s_after, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(s_after, 200, "after reload, rate limit bucket should be fresh");
}

#[test]
fn reload_swaps_backend_with_circuit_breaker() {
    let backend1 = start_backend_with_shutdown("cb-v1");
    let backend2 = start_backend_with_shutdown("cb-v2");
    let proxy_port = free_port();

    let cb_yaml = |endpoint_port: u16| {
        format!(
            r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: circuit_breaker
        clusters:
          - name: backend
            consecutive_failures: 3
            recovery_window_secs: 300
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{endpoint_port}"
"#
        )
    };

    let proxy = start_reloadable_proxy(&cb_yaml(backend1.port()));

    let (s1, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(s1, 200, "initial request should succeed");
    assert_eq!(body, "cb-v1");

    proxy.reload(&cb_yaml(backend2.port()));

    let (s2, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(s2, 200, "reloaded circuit breaker should be closed (fresh state)");
    assert_eq!(body, "cb-v2", "should route to new backend after reload");
}

// ---------------------------------------------------------------------------
// Restart-Required Detection
// ---------------------------------------------------------------------------

#[test]
fn reload_listener_address_change_keeps_old_address() {
    let backend = start_backend_with_shutdown("served");
    let proxy_port = free_port();
    let new_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, backend.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "served");

    proxy.reload(&proxy_yaml(new_port, backend.port()));

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "old address should still serve after address change");
    assert_eq!(body, "served", "old pipeline still active on old address");
}

// ---------------------------------------------------------------------------
// Operational Scenarios
// ---------------------------------------------------------------------------

#[test]
fn reload_rolling_deploy_v1_to_v2() {
    let v1 = start_backend_with_shutdown("v1");
    let v2 = start_backend_with_shutdown("v2");
    let proxy_port = free_port();

    let both_yaml = |p1: u16, p2: u16| {
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
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{p1}"
              - "127.0.0.1:{p2}"
"#
        )
    };

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, v1.port()));

    for _ in 0..3 {
        let (s, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(s, 200);
        assert_eq!(body, "v1", "all traffic should go to v1 initially");
    }

    proxy.reload(&both_yaml(v1.port(), v2.port()));

    let mut saw_v1 = false;
    let mut saw_v2 = false;
    for _ in 0..20 {
        let (s, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(s, 200);
        match body.as_str() {
            "v1" => saw_v1 = true,
            "v2" => saw_v2 = true,
            other => panic!("unexpected response: {other}"),
        }
    }
    assert!(
        saw_v1 && saw_v2,
        "both v1 and v2 should receive traffic during canary phase"
    );

    proxy.reload(&proxy_yaml(proxy_port, v2.port()));

    for _ in 0..3 {
        let (s, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(s, 200);
        assert_eq!(body, "v2", "all traffic should go to v2 after completing rollout");
    }
}

#[test]
fn reload_multiple_successive_changes() {
    let b1 = start_backend_with_shutdown("iteration-1");
    let b2 = start_backend_with_shutdown("iteration-2");
    let b3 = start_backend_with_shutdown("iteration-3");
    let b4 = start_backend_with_shutdown("iteration-4");
    let proxy_port = free_port();

    let proxy = start_reloadable_proxy(&proxy_yaml(proxy_port, b1.port()));

    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "iteration-1");

    proxy.reload(&proxy_yaml(proxy_port, b2.port()));
    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "iteration-2", "second config should take effect");

    proxy.reload(&proxy_yaml(proxy_port, b3.port()));
    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "iteration-3", "third config should take effect");

    proxy.reload("broken yaml [[[");
    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "iteration-3", "invalid reload should keep iteration-3");

    proxy.reload(&proxy_yaml(proxy_port, b4.port()));
    let (_, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(body, "iteration-4", "fourth config should take effect after recovery");
}

#[test]
fn reload_adds_new_route() {
    let api_backend = start_backend_with_shutdown("api-response");
    let health_backend = start_backend_with_shutdown("health-ok");
    let proxy_port = free_port();

    let single_route = format!(
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
          - path_prefix: "/api/"
            cluster: api
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
"#,
        api_port = api_backend.port()
    );

    let proxy = start_reloadable_proxy(&single_route);

    let (s, body) = http_get(proxy.addr(), "/api/data", None);
    assert_eq!(s, 200);
    assert_eq!(body, "api-response", "api route should work");

    let (s, _) = http_get(proxy.addr(), "/health/check", None);
    assert!(s == 404 || s == 502, "health route should not exist yet: {s}");

    let two_routes = format!(
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
          - path_prefix: "/api/"
            cluster: api
          - path_prefix: "/health/"
            cluster: health
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "127.0.0.1:{api_port}"
          - name: health
            endpoints:
              - "127.0.0.1:{health_port}"
"#,
        api_port = api_backend.port(),
        health_port = health_backend.port()
    );

    proxy.reload(&two_routes);

    let (s, body) = http_get(proxy.addr(), "/api/data", None);
    assert_eq!(s, 200);
    assert_eq!(
        body, "api-response",
        "api route should still work after adding health route"
    );

    let (s, body) = http_get(proxy.addr(), "/health/check", None);
    assert_eq!(s, 200);
    assert_eq!(body, "health-ok", "new health route should work after reload");
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

fn proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
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
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

fn static_yaml(proxy_port: u16, body: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: "{body}"
"#
    )
}

fn rate_limit_yaml(proxy_port: u16, backend_port: u16, burst: u32) -> String {
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
        rate: 1
        burst: {burst}
        mode: global
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}
