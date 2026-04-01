//! Cross-cutting validation tests.
//!
//! Tests that span multiple config sections: HTTP pipeline requirements,
//! TCP-only bypass, admin address validation, and shorthand config promotion.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_http_no_pipeline_routes_or_chains() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string()
            .contains("at least one pipeline filter, route, or filter chain"),
        "got: {err}"
    );
}

#[test]
fn accept_tcp_only_without_pipeline() {
    let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(config.pipeline.is_empty(), "TCP-only config should have empty pipeline");
    assert!(config.routes.is_empty(), "TCP-only config should have no routes");
}

#[test]
fn reject_invalid_admin_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
admin_address: "not-valid"
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
    assert!(err.to_string().contains("invalid admin_address"), "got: {err}");
}

#[test]
fn accept_valid_admin_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
admin_address: "127.0.0.1:9901"
routes:
  - path_prefix: "/"
    cluster: b
clusters:
  - name: b
    endpoints: ["1.2.3.4:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.admin_address.as_deref(),
        Some("127.0.0.1:9901"),
        "admin_address should be preserved"
    );
}

#[test]
fn accept_no_admin_address() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: b
clusters:
  - name: b
    endpoints: ["1.2.3.4:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(config.admin_address.is_none(), "admin_address should default to None");
}

#[test]
fn accept_shorthand_routes_generate_default_pipeline() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.pipeline.len(),
        2,
        "shorthand routes should generate 2-filter pipeline"
    );
    assert_eq!(
        config.pipeline[0].filter_type, "router",
        "first promoted filter should be router"
    );
    assert_eq!(
        config.pipeline[1].filter_type, "load_balancer",
        "second promoted filter should be load_balancer"
    );

    let routes = config.pipeline[0]
        .config
        .get("routes")
        .expect("router entry must contain routes");
    let routes_seq = routes.as_sequence().expect("routes must be a sequence");
    assert_eq!(routes_seq.len(), 1, "promoted router should have 1 route");
    let first_route = &routes_seq[0];
    assert_eq!(
        first_route.get("path_prefix").and_then(|v| v.as_str()),
        Some("/"),
        "promoted route path_prefix should be '/'"
    );
    assert_eq!(
        first_route.get("cluster").and_then(|v| v.as_str()),
        Some("backend"),
        "promoted route cluster should be 'backend'"
    );

    let clusters = config.pipeline[1]
        .config
        .get("clusters")
        .expect("load_balancer entry must contain clusters");
    let clusters_seq = clusters.as_sequence().expect("clusters must be a sequence");
    assert_eq!(clusters_seq.len(), 1, "promoted load_balancer should have 1 cluster");
    let first_cluster = &clusters_seq[0];
    assert_eq!(
        first_cluster.get("name").and_then(|v| v.as_str()),
        Some("backend"),
        "promoted cluster name should be 'backend'"
    );
}

#[test]
fn verify_apply_defaults_assigns_default_chain() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();

    assert_eq!(
        config.filter_chains.len(),
        1,
        "apply_defaults should create one filter chain"
    );
    assert_eq!(
        config.filter_chains[0].name, "default",
        "auto-created chain should be named 'default'"
    );
    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["default"],
        "HTTP listener should reference the default chain"
    );
}

#[test]
fn tcp_listener_not_assigned_default_chain() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();

    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["default"],
        "HTTP listener should get the default chain"
    );
    assert!(
        config.listeners[1].filter_chains.is_empty(),
        "TCP listener should not be assigned a default chain"
    );
}

#[test]
fn explicit_pipeline_generates_default_chain() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: web
  - filter: load_balancer
    clusters:
      - name: web
        endpoints: ["10.0.0.1:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();

    assert_eq!(
        config.filter_chains.len(),
        1,
        "explicit pipeline should produce one chain"
    );
    assert_eq!(
        config.filter_chains[0].name, "default",
        "promoted chain should be named 'default'"
    );
    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["default"],
        "listener should reference the promoted default chain"
    );
}
