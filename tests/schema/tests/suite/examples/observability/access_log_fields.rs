// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Access log field selection example schema tests.

use praxis_core::config::Config;
use praxis_filter::{FilterPipeline, FilterRegistry};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_fields_example_parses() {
    let yaml = include_str!("../../../../../../examples/configs/observability/access-log-fields.yaml");
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
fn access_log_fields_example_builds_pipeline() {
    let yaml = include_str!("../../../../../../examples/configs/observability/access-log-fields.yaml");
    let config = Config::from_yaml(yaml).expect("example config should parse");
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
    FilterPipeline::build_with_chains(&mut entries, &registry, &chains).expect("pipeline should build");
}
