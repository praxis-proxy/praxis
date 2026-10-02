// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Integration tests for the HTTP in-flight request gauge.

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn series_value(body: &str, metric: &str, listener: &str) -> f64 {
    body.lines()
        .find(|line| line.starts_with(&format!("{metric}{{")) && line.contains(&format!("listener=\"{listener}\"")))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or_else(|| panic!("no {metric} series for listener {listener}:\n{body}"))
}

fn gauge_value(body: &str, listener: &str) -> f64 {
    series_value(body, "praxis_http_active_requests", listener)
}

fn proxy_yaml(proxy_port: u16, admin_port: u16, backend_port: u16) -> String {
    format!(
        r#"
admin:
  metrics_address: "127.0.0.1:{admin_port}"
listeners:
  - name: inflight
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
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn http_active_requests_is_labeled_by_listener() {
    let backend = start_backend_with_shutdown("inflight-ok");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, admin_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(proxy.addr(), "/hello", None);
    assert_eq!(status, 200, "proxy request should succeed");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        body = http_get(&admin, "/metrics", None).1;
        if body.contains("praxis_http_active_requests{") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains("praxis_http_active_requests{listener=\"inflight\"}"),
        "gauge should carry the listener label:\n{body}"
    );
}

#[test]
fn http_active_requests_returns_to_zero_when_idle() {
    let backend = start_backend_with_shutdown("inflight-drain");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = Config::from_yaml(&proxy_yaml(proxy_port, admin_port, backend.port())).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    for _ in 0..5 {
        let (status, _) = http_get(proxy.addr(), "/hello", None);
        assert_eq!(status, 200, "proxy request should succeed");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut value = f64::NAN;
    while std::time::Instant::now() < deadline {
        body = http_get(&admin, "/metrics", None).1;
        if body.contains("praxis_http_active_requests{") {
            value = gauge_value(&body, "inflight");
            if value == 0.0 {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        value.abs() < f64::EPSILON,
        "gauge must drain to zero after every request completes; a leak here means the guard is not dropped:\n{body}"
    );
}
