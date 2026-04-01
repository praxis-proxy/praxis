//! Route validation tests.
//!
//! Covers: unknown cluster references, empty clusters requirement,
//! route-with-host/headers acceptance, and cardinality limits.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_route_unknown_cluster() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: nonexistent
clusters:
  - name: backend
    endpoints: ["1.2.3.4:80"]
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("unknown cluster 'nonexistent'"), "got: {err}");
}

#[test]
fn reject_routes_with_no_clusters() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: missing
clusters: []
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("at least one cluster"), "got: {err}");
}

#[test]
fn accept_matching_route_cluster() {
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
        &*config.routes[0].cluster, "backend",
        "route should reference 'backend' cluster"
    );
}

#[test]
fn accept_empty_path_prefix() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: ""
    cluster: backend
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(config.routes[0].path_prefix, "", "empty path_prefix should be accepted");
}

#[test]
fn reject_empty_cluster_name_in_route() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: ""
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("unknown cluster"), "got: {err}");
}

#[test]
fn accept_route_with_host() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    host: "api.example.com"
    cluster: api
  - path_prefix: "/"
    cluster: web
clusters:
  - name: api
    endpoints: ["10.0.0.1:8080"]
  - name: web
    endpoints: ["10.0.0.2:8080"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.routes[0].host.as_deref(),
        Some("api.example.com"),
        "first route should have host 'api.example.com'"
    );
    assert!(config.routes[1].host.is_none(), "second route should have no host");
}

#[test]
fn accept_route_with_headers() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    headers:
      x-version: "v2"
    cluster: v2
  - path_prefix: "/"
    cluster: v1
clusters:
  - name: v1
    endpoints: ["10.0.0.1:80"]
  - name: v2
    endpoints: ["10.0.0.2:80"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    let h = config.routes[0].headers.as_ref().unwrap();
    assert_eq!(h.get("x-version").unwrap(), "v2", "x-version header should be 'v2'");
}

#[test]
fn reject_too_many_routes() {
    let mut routes = String::from("routes:\n");
    for i in 0..10_001 {
        routes.push_str(&format!("  - path_prefix: \"/r{i}\"\n    cluster: backend\n"));
    }
    let yaml = format!(
        "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n\
         {routes}\
         clusters:\n  - name: backend\n    endpoints: [\"10.0.0.1:80\"]\n"
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many routes"), "got: {err}");
}
