// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Access log text template example schema tests.

use praxis_core::config::Config;
use praxis_filter::{FilterPipeline, FilterRegistry};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn build_pipeline(config: &Config) -> Result<FilterPipeline, praxis_filter::FilterError> {
    let registry = FilterRegistry::with_builtins();
    let chains: std::collections::HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();
    let listener = config.listeners.first().expect("listener");
    let mut entries = Vec::new();
    for chain_name in &listener.filter_chains {
        let filters = chains
            .get(chain_name.as_str())
            .unwrap_or_else(|| panic!("unknown chain {chain_name}"));
        entries.extend_from_slice(filters);
    }
    FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &chains,
        &praxis_core::config::InsecureOptions::default(),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_template_example_parses() {
    let yaml = include_str!("../../../../../../examples/configs/observability/access-log-template.yaml");
    let config = Config::from_yaml(yaml).expect("example config should parse");
    assert!(
        config
            .filter_chains
            .iter()
            .any(|chain| chain.filters.iter().any(|entry| entry.filter_type == "access_log")),
        "example should include access_log filter"
    );
}

#[test]
fn access_log_template_example_builds_pipeline() {
    let yaml = include_str!("../../../../../../examples/configs/observability/access-log-template.yaml");
    let config = Config::from_yaml(yaml).expect("example config should parse");
    build_pipeline(&config).expect("pipeline should build");
}

#[test]
fn reject_literal_only_template() {
    // A template with no `{field}` tokens would log a constant string with no
    // request data, so the access_log filter rejects it at build time.
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        template: "just a literal"
"#;
    let config = Config::from_yaml(yaml).expect("config should parse");
    let err = match build_pipeline(&config) {
        Ok(_) => panic!("literal-only template should be rejected"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("must contain at least one {field} token"),
        "got: {err}"
    );
}
