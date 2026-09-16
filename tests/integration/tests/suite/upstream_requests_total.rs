// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the upstream request counter.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn wait_for_metric(admin: &str, needle: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        last = http_get(admin, "/metrics", None).1;
        if last.contains(needle) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

fn counter_value(body: &str, endpoint: &str) -> Option<f64> {
    body.lines()
        .find(|line| {
            line.starts_with("praxis_upstream_requests_total{") && line.contains(&format!("endpoint=\"{endpoint}\""))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

/// Poll `/metrics` until the upstream counter for `endpoint` reaches
/// `at_least`, returning the final value and the last scrape body.
///
/// The counter is recorded from the proxy's `logging` hook, which runs after
/// the client has already received its response, so a scrape taken immediately
/// after the requests can observe fewer increments than were issued. Waiting
/// for the value (not merely the series' presence) removes that race.
fn wait_for_counter(admin: &str, endpoint: &str, at_least: f64) -> (f64, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut value = 0.0;
    while std::time::Instant::now() < deadline {
        body = http_get(admin, "/metrics", None).1;
        value = counter_value(&body, endpoint).unwrap_or(0.0);
        if value >= at_least {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (value, body)
}

fn proxy_yaml(proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
    format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: upstream-counter
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_requests_total_carries_cluster_endpoint_and_status_class() {
    let backend = start_backend_with_shutdown("upstream-counted");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, admin_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(proxy.addr(), "/api/hello", None);
    assert_eq!(status, 200, "proxy request should succeed");

    let endpoint = format!("127.0.0.1:{}", backend.port());
    let body = wait_for_metric(&admin, &format!("endpoint=\"{endpoint}\""));
    for needle in [
        "cluster=\"backend\"",
        &format!("endpoint=\"{endpoint}\""),
        "status_class=\"2xx\"",
    ] {
        assert!(
            body.contains(needle),
            "upstream counter should carry `{needle}`:\n{body}"
        );
    }
}

#[test]
fn upstream_requests_total_counts_once_per_request() {
    let backend = start_backend_with_shutdown("upstream-once");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, admin_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // The counter is recorded from the proxy's `logging` hook, which runs after
    // the client already has its response, so a scrape taken right after the
    // requests can still be short a count. Wait for the value to catch up
    // rather than for the series to merely appear. The before/after delta is
    // defensive: this test's backend port is unique, so `before` is normally
    // zero.
    let endpoint = format!("127.0.0.1:{}", backend.port());
    let before = counter_value(&http_get(&admin, "/metrics", None).1, &endpoint).unwrap_or(0.0);

    for _ in 0..4 {
        let (status, _) = http_get(proxy.addr(), "/api/hello", None);
        assert_eq!(status, 200, "proxy request should succeed");
    }

    let (after, body) = wait_for_counter(&admin, &endpoint, before + 4.0);
    assert!(
        (after - before - 4.0).abs() < f64::EPSILON,
        "four requests must count exactly four, not once per upstream attempt:\n{body}"
    );
}

#[test]
fn upstream_requests_total_excludes_proxy_generated_responses() {
    let backend = start_backend_with_shutdown("upstream-excluded");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, admin_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // The endpoint port may have been used by an earlier test's backend, so
    // assert that this request added nothing rather than that the series is
    // absent.
    let endpoint = format!("127.0.0.1:{}", backend.port());
    let before = counter_value(&http_get(&admin, "/metrics", None).1, &endpoint).unwrap_or(0.0);

    let (unrouted, _) = http_get(proxy.addr(), "/not-routed", None);
    assert_ne!(unrouted, 200, "an unrouted path should not reach the backend");

    let body = http_get(&admin, "/metrics", None).1;
    let after = counter_value(&body, &endpoint).unwrap_or(0.0);
    assert!(
        (after - before).abs() < f64::EPSILON,
        "a request the proxy answered itself must not appear in the upstream counter:\n{body}"
    );
}
