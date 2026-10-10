// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Route validation tests (routes within router filter configs).

use praxis_core::config::{Config, HedgePolicy};
use praxis_filter::RouterFilter;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn accept_route_with_host() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            host: "api.example.com"
            cluster: api
          - path_prefix: "/"
            cluster: web
      - filter: load_balancer
        clusters:
          - name: api
            endpoints: ["10.0.0.1:8080"]
          - name: web
            endpoints: ["10.0.0.2:8080"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(config.filter_chains.len(), 1, "should have 1 filter chain");
}

#[test]
fn accept_route_with_headers() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-version: "v2"
            cluster: v2
          - path_prefix: "/"
            cluster: v1
      - filter: load_balancer
        clusters:
          - name: v1
            endpoints: ["10.0.0.1:80"]
          - name: v2
            endpoints: ["10.0.0.2:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(config.filter_chains.len(), 1, "should have 1 filter chain");
}

#[test]
fn accept_route_without_hedge_policy() {
    Config::from_yaml(&proxy_yaml("")).unwrap();
    assert!(
        RouterFilter::from_config(&router_value("")).is_ok(),
        "a route without hedge_policy should build"
    );
}

#[test]
fn accept_hedge_fan_out_and_timeout_trigger() {
    accept_policy(
        "
initial_requests: 2
max_attempts: 2
budget_percent: 10",
    );
    accept_policy(
        "
initial_requests: 1
max_attempts: 2
per_try_timeout_ms: 50
budget_percent: 0.01",
    );
}

#[test]
fn reject_invalid_hedge_policy_shapes() {
    expect_hedge_error(
        "
initial_requests: 0
max_attempts: 1
budget_percent: 10",
        "initial_requests",
    );
    expect_hedge_error(
        "
initial_requests: 3
max_attempts: 2
budget_percent: 10",
        "max_attempts",
    );
    expect_hedge_error(
        "
initial_requests: 1
max_attempts: 2
budget_percent: 10",
        "per_try_timeout_ms",
    );
    expect_hedge_error(
        "
initial_requests: 2
max_attempts: 2
per_try_timeout_ms: 50
budget_percent: 10",
        "per_try_timeout_ms",
    );
    expect_hedge_error(
        "
initial_requests: 1
max_attempts: 1
budget_percent: 101",
        "budget_percent",
    );
    expect_hedge_error(
        "
initial_requests: 1
max_attempts: 1
budget_percent: 0.005",
        "0.01",
    );
    expect_hedge_error(
        "
initial_requests: 1
max_attempts: 1
budget_percent: 10
extra: 1",
        "unknown field",
    );
}

/// Full proxy document. Filter bodies stay opaque until the router is built.
fn proxy_yaml(route_extra: &str) -> String {
    format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: api
{route_extra}
      - filter: load_balancer
        clusters:
          - name: api
            endpoints: ["10.0.0.1:8080", "10.0.0.2:8080"]
"#
    )
}

/// Router filter document for `route_extra` fields under the one route.
fn router_value(route_extra: &str) -> serde_yaml::Value {
    let yaml = format!(
        r#"
routes:
  - path_prefix: "/"
    cluster: api
{route_extra}
"#
    );
    serde_yaml::from_str(&yaml).unwrap()
}

/// Accept `policy_fields` as a route policy and as a standalone document.
fn accept_policy(policy_fields: &str) {
    Config::from_yaml(&proxy_yaml(&hedge_block(12, policy_fields))).unwrap();
    assert!(
        RouterFilter::from_config(&router_value(&hedge_block(4, policy_fields))).is_ok(),
        "router should accept the hedge policy"
    );
    let policy: HedgePolicy = serde_yaml::from_str(&policy_document(policy_fields)).unwrap();
    assert!(policy.max_attempts() >= 1, "a valid policy keeps its attempt cap");
}

/// Reject `policy_fields` when the router filter is built.
fn expect_hedge_error(policy_fields: &str, expected: &str) {
    let Err(error) = RouterFilter::from_config(&router_value(&hedge_block(4, policy_fields))) else {
        panic!("invalid hedge policy was accepted");
    };
    assert!(error.to_string().contains(expected), "{error}");
}

/// `hedge_policy` nested under the route, at the same indent as `cluster`.
fn hedge_block(indent: usize, policy_fields: &str) -> String {
    let key_pad = " ".repeat(indent);
    let field_pad = " ".repeat(indent.saturating_add(2));
    let fields = policy_fields
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("{field_pad}{}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    format!("\n{key_pad}hedge_policy:\n{fields}")
}

/// Policy fields as their own YAML document.
fn policy_document(policy_fields: &str) -> String {
    policy_fields
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n")
}
