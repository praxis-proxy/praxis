// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Route validation tests (routes within router filter configs).

use praxis_core::config::Config;

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
