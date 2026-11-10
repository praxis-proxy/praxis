// SPDX-License-Identifier: Apache-2.0
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
    assert!(err.to_string().contains("invalid admin.address"), "got: {err}");
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
insecure_options:
  allow_private_endpoints: true
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

#[test]
fn reject_superseded_metrics_label_lists() {
    // `disabled` shipped and was replaced by per-dimension settings; `enabled`
    // is the obvious wrong guess at its counterpart. Neither names a dimension,
    // so the whole config must fail to load rather than silently ignore them.
    for key in ["disabled", "enabled"] {
        let yaml = format!(
            r#"
metrics:
  labels:
    {key}: [route, status_code]
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#
        );
        assert!(
            Config::from_yaml(&yaml).is_err(),
            "metrics.labels.{key} names no dimension, so the config must not load"
        );
    }
}

#[test]
fn accept_per_dimension_metrics_labels() {
    let yaml = r#"
metrics:
  labels:
    route: false
    status_code: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(
        !config
            .metrics
            .labels
            .is_enabled(praxis_core::config::MetricLabel::Route),
        "route should be turned off"
    );
    assert!(
        config
            .metrics
            .labels
            .is_enabled(praxis_core::config::MetricLabel::StatusCode),
        "status_code should be turned on"
    );
}

#[test]
fn reject_repeated_metrics_label_dimension() {
    for (first, second) in [("true", "false"), ("false", "true"), ("true", "true")] {
        let yaml = format!(
            r#"
metrics:
  labels:
    status_code: {first}
    status_code: {second}
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#
        );
        let err = Config::from_yaml(&yaml)
            .err()
            .unwrap_or_else(|| panic!("status_code: {first} then {second} must not load"));
        assert!(
            err.to_string().contains("status_code"),
            "the error should name the repeated dimension, got: {err}"
        );
    }
}

#[test]
fn accept_every_dimension_set_once() {
    let yaml = r#"
metrics:
  labels:
    cluster: false
    endpoint: false
    listener: false
    method: false
    route: false
    status_class: false
    status_code: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let config = Config::from_yaml(yaml).unwrap();
    for label in [
        praxis_core::config::MetricLabel::Cluster,
        praxis_core::config::MetricLabel::Endpoint,
        praxis_core::config::MetricLabel::Listener,
        praxis_core::config::MetricLabel::Method,
        praxis_core::config::MetricLabel::Route,
        praxis_core::config::MetricLabel::StatusClass,
    ] {
        assert!(
            !config.metrics.labels.is_enabled(label),
            "{label:?} was set to false and should be off"
        );
    }
    assert!(
        config
            .metrics
            .labels
            .is_enabled(praxis_core::config::MetricLabel::StatusCode),
        "status_code was set to true and should be on"
    );
}
