//! YAML builder test utilities to reduce duplication across test modules.
//!
//! Each function produces a complete, parseable YAML string that
//! [`Config::from_yaml`] will accept (unless the test intentionally
//! breaks it).
//!
//! [`Config::from_yaml`]: praxis_core::config::Config::from_yaml

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Smallest valid HTTP config: one listener, one route, one cluster.
pub(crate) fn minimal_valid_yaml() -> String {
    r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: backend
clusters:
  - name: backend
    endpoints: ["127.0.0.1:3000"]
"#
    .to_string()
}

/// Valid config using named filter chains instead of shorthand routes/clusters.
pub(crate) fn valid_filter_chain_yaml() -> String {
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
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#
    .to_string()
}
