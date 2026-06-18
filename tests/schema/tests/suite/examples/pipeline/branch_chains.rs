// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Branch chains example config tests.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::build_pipeline;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn branch_chains_pipeline_builds() {
    let config = crate::example_utils::load_example_config(
        "pipeline/branch-chains.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let pipeline = build_pipeline(&config);
    assert!(pipeline.len() > 0, "branch-chains pipeline should have filters");
}

#[test]
fn cross_chain_rejoin_via_flat_pipeline() {
    let config = crate::example_utils::load_example_config(
        "pipeline/branch-chains.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let pipeline = build_pipeline(&config);
    assert!(
        pipeline.len() > 5,
        "pipeline should contain filters from both preprocessing and main chains"
    );
}

#[test]
fn cross_chain_colon_syntax_rejected() {
    let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: bad_rejoin
            rejoin: "other:routing"
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(
        err.to_string().contains("cross-chain rejoin"),
        "colon syntax should be rejected with clear message: {err}"
    );
    assert!(
        err.to_string().contains("use the filter's name directly"),
        "error should explain the alternative: {err}"
    );
}
