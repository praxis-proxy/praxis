// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Cluster validation tests.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_empty_endpoints() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: empty
    endpoints: []
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("has no endpoints"), "got: {err}");
}

#[test]
fn reject_zero_weight() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints:
      - address: "10.0.0.1:80"
        weight: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("weight 0"), "got: {err}");
}

#[test]
fn accept_valid_weights() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints:
      - address: "10.0.0.1:80"
        weight: 1
      - address: "10.0.0.2:80"
        weight: 5
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.clusters[0].endpoints[0].weight(),
        1,
        "first endpoint weight should be 1"
    );
    assert_eq!(
        config.clusters[0].endpoints[1].weight(),
        5,
        "second endpoint weight should be 5"
    );
}

#[test]
fn reject_empty_sni() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: ""
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("sni must be a valid DNS hostname"),
        "got: {err}"
    );
}

#[test]
fn reject_sni_over_253_chars() {
    let long_label = "a".repeat(250);
    let sni = format!("{long_label}.com");
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "{sni}"
"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sni must be a valid DNS hostname"),
        "got: {err}"
    );
}

#[test]
fn reject_sni_label_over_63() {
    let long_label = "a".repeat(64);
    let sni = format!("{long_label}.example.com");
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "{sni}"
"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("sni must be a valid DNS hostname"),
        "got: {err}"
    );
}

#[test]
fn reject_sni_double_dot() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "api..example.com"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("sni must be a valid DNS hostname"),
        "got: {err}"
    );
}

#[test]
fn reject_sni_invalid_chars() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "api.exam ple.com"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("sni must be a valid DNS hostname"),
        "got: {err}"
    );
}

#[test]
fn accept_valid_sni() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "api.example.com"
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reject_zero_connection_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("connection_timeout_ms is 0"), "got: {err}");
}

#[test]
fn reject_zero_total_connection_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    total_connection_timeout_ms: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("total_connection_timeout_ms is 0"),
        "got: {err}"
    );
}

#[test]
fn reject_zero_idle_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    idle_timeout_ms: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("idle_timeout_ms is 0"), "got: {err}");
}

#[test]
fn reject_zero_read_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    read_timeout_ms: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("read_timeout_ms is 0"), "got: {err}");
}

#[test]
fn reject_zero_write_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    write_timeout_ms: 0
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("write_timeout_ms is 0"), "got: {err}");
}

#[test]
fn reject_connection_exceeds_total() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 10000
    total_connection_timeout_ms: 5000
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "got: {err}");
}

#[test]
fn accept_connection_equals_total() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 5000
    total_connection_timeout_ms: 5000
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reject_too_many_endpoints() {
    let mut endpoints = String::from("[");
    for i in 0..10_001 {
        if i > 0 {
            endpoints.push(',');
        }
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        endpoints.push_str(&format!("\"10.{a}.{b}.{c}:80\""));
    }
    endpoints.push(']');

    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: big
    endpoints: {endpoints}
"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many endpoints"), "got: {err}");
}

#[test]
fn reject_too_many_clusters() {
    let mut clusters = String::from("clusters:\n");
    for i in 0..10_001 {
        clusters.push_str(&format!("  - name: c{i}\n    endpoints: [\"10.0.0.1:80\"]\n"));
    }
    let yaml = format!(
        "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n{clusters}"
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many"), "got: {err}");
}

#[test]
fn reject_duplicate_cluster_names() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
  - name: backend
    endpoints: ["10.0.0.2:80"]
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate cluster name"),
        "duplicate cluster names should be rejected: {err}"
    );
}

#[test]
fn accept_tls_with_sni() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    tls:
      sni: "api.example.com"
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(config.clusters[0].tls.is_some(), "tls should be present");
    assert_eq!(
        config.clusters[0].tls.as_ref().unwrap().sni.as_deref(),
        Some("api.example.com"),
        "sni should match configured value"
    );
}

#[test]
fn accept_round_robin_strategy() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    load_balancer_strategy: round_robin
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn accept_least_connections_strategy() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    load_balancer_strategy: least_connections
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn accept_consistent_hash_strategy() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    load_balancer_strategy:
      consistent_hash:
        header: "X-User-Id"
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn accept_consistent_hash_without_header() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    load_balancer_strategy:
      consistent_hash: {}
"#;
    Config::from_yaml(yaml).unwrap();
}
