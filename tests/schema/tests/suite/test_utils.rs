// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! YAML builder test utilities to reduce duplication across test modules.

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Smallest valid HTTP config: one listener, one filter chain.
pub(crate) fn minimal_valid_yaml() -> String {
    valid_filter_chain_yaml()
}

/// Valid config using named filter chains.
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
    .to_owned()
}
