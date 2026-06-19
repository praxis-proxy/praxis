// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Listener validation tests.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_empty_listeners() {
    let yaml = "listeners: []\n";
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("at least one listener"), "got: {err}");
}

#[test]
fn reject_empty_listener_name() {
    let yaml = r#"
listeners:
  - name: ""
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("name must not be empty"),
        "empty listener name should be rejected: {err}"
    );
}

#[test]
fn reject_invalid_socket_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "not-valid"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid socket address"), "got: {err}");
}

#[test]
fn reject_address_missing_port() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid socket address"), "got: {err}");
}

#[test]
fn accept_ipv4_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn accept_ipv6_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "[::1]:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reject_tcp_without_upstream() {
    let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("requires an upstream address"), "got: {err}");
}

#[test]
fn accept_tcp_with_upstream() {
    let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reject_tls_cert_path_traversal() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:443"
    tls:
      certificates:
        - cert_path: "/etc/../../tmp/evil.pem"
          key_path: "/etc/ssl/key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("path traversal"), "got: {err}");
}

#[test]
fn reject_tls_key_path_traversal() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:443"
    tls:
      certificates:
        - cert_path: "/etc/ssl/cert.pem"
          key_path: "../secret/key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("path traversal"), "got: {err}");
}

#[test]
fn reject_tls_missing_key_path() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:443"
    tls:
      cert_path: "/etc/ssl/cert.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid YAML"), "got: {err}");
}

#[test]
fn reject_duplicate_listener_names() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: web
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("duplicate listener name"), "got: {err}");
}

#[test]
fn reject_too_many_listeners() {
    let mut yaml = String::from("listeners:\n");
    for i in 0..1001 {
        let port = 10_000 + i;
        yaml.push_str(&format!(
            "  - name: l{i}\n    address: \"127.0.0.1:{port}\"\n    protocol: tcp\n    upstream: \"10.0.0.1:80\"\n"
        ));
    }

    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many listeners"), "got: {err}");
}

#[test]
fn accept_max_listeners() {
    let mut yaml = String::from("listeners:\n");
    for i in 0..1000 {
        let port = 10_000 + i;
        yaml.push_str(&format!(
            "  - name: l{i}\n    address: \"127.0.0.1:{port}\"\n    protocol: tcp\n    upstream: \"10.0.0.1:80\"\n"
        ));
    }

    Config::from_yaml(&yaml).unwrap();
}
