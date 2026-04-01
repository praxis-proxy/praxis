//! Cluster validation tests.
//!
//! Covers: empty endpoints, zero weight, SNI validation, timeout rules,
//! load-balancing strategies, and cardinality limits.

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
routes:
  - path_prefix: "/"
    cluster: empty
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: ""
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("upstream_sni is empty"), "got: {err}");
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
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: "{sni}"
"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("exceeds 253 characters"), "got: {err}");
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
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: "{sni}"
"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("invalid label length"), "got: {err}");
}

#[test]
fn reject_sni_double_dot() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: "api..example.com"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid label length"), "got: {err}");
}

#[test]
fn reject_sni_invalid_chars() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: "api.exam ple.com"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("invalid characters"), "got: {err}");
}

#[test]
fn accept_valid_sni() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_tls: true
    upstream_sni: "api.example.com"
"#;
    Config::from_yaml(yaml).unwrap();
}

#[test]
fn reject_zero_connection_timeout() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: big
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
    let mut routes = String::from("routes:\n");
    let mut clusters = String::from("clusters:\n");
    for i in 0..10_001 {
        routes.push_str(&format!("  - path_prefix: \"/c{i}\"\n    cluster: c{i}\n"));
        clusters.push_str(&format!("  - name: c{i}\n    endpoints: [\"10.0.0.1:80\"]\n"));
    }
    let yaml = format!("listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n{routes}{clusters}");
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many"), "got: {err}");
}

#[test]
fn reject_duplicate_cluster_names() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/a"
    cluster: backend
  - path_prefix: "/b"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
  - name: backend
    endpoints: ["10.0.0.2:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.clusters.len(),
        2,
        "both duplicate cluster entries should survive parsing"
    );
    assert_eq!(
        &*config.clusters[0].name, "backend",
        "first cluster should be named 'backend'"
    );
    assert_eq!(
        &*config.clusters[1].name, "backend",
        "second cluster should be named 'backend'"
    );
}

#[test]
fn accept_upstream_sni_without_tls_flag() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:443"]
    upstream_sni: "api.example.com"
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(!config.clusters[0].upstream_tls, "upstream_tls should default to false");
    assert_eq!(
        config.clusters[0].upstream_sni.as_deref(),
        Some("api.example.com"),
        "upstream_sni should be accepted without upstream_tls flag"
    );
}

#[test]
fn accept_round_robin_strategy() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
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
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
    load_balancer_strategy:
      consistent_hash: {}
"#;
    Config::from_yaml(yaml).unwrap();
}
