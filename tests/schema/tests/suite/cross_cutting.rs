// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Cross-cutting validation tests.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_http_no_filter_chains() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("at least one filter chain"), "got: {err}");
}

#[test]
fn accept_tcp_only_without_filter_chains() {
    let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(
        config.filter_chains.is_empty(),
        "TCP-only config should have empty filter chains"
    );
}

#[test]
fn reject_invalid_admin_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
admin:
  address: "not-valid"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid admin_address"), "got: {err}");
}

#[test]
fn accept_valid_admin_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
admin:
  address: "127.0.0.1:9901"
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["1.2.3.4:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.admin.address.as_deref(),
        Some("127.0.0.1:9901"),
        "admin address should be preserved"
    );
}

#[test]
fn accept_no_admin_address() {
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
            cluster: b
      - filter: load_balancer
        clusters:
          - name: b
            endpoints: ["1.2.3.4:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(config.admin.address.is_none(), "admin address should default to None");
}

#[test]
fn tcp_listener_keeps_empty_filter_chains() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
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
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();

    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["main"],
        "HTTP listener should reference main chain"
    );
    assert!(
        config.listeners[1].filter_chains.is_empty(),
        "TCP listener should have no filter chains"
    );
}
