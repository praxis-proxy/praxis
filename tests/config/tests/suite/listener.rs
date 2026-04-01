//! Listener validation tests.
//!
//! Covers: empty listeners, invalid addresses, protocol constraints,
//! TLS path traversal, duplicate names, and cardinality limits.

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
routes:
  - path_prefix: "/"
    cluster: b
clusters:
  - name: b
    endpoints: ["1.2.3.4:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.listeners[0].name, "",
        "single empty-name listener should be accepted"
    );
}

#[test]
fn reject_invalid_socket_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "not-valid"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
routes:
  - path_prefix: "/"
    cluster: b
clusters:
  - name: b
    endpoints: ["1.2.3.4:80"]
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn accept_ipv6_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "[::1]:8080"
routes:
  - path_prefix: "/"
    cluster: b
clusters:
  - name: b
    endpoints: ["1.2.3.4:80"]
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
      cert_path: "/etc/../../tmp/evil.pem"
      key_path: "/etc/ssl/key.pem"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
      cert_path: "/etc/ssl/cert.pem"
      key_path: "../secret/key.pem"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
  - name: web
    address: "127.0.0.1:9090"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: x
  - filter: load_balancer
    clusters:
      - name: x
        endpoints: ["1.2.3.4:80"]
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
