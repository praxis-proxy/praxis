// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Additional schema parse-validation tests for example configs
//! that lack dedicated structural assertions.

use std::{collections::HashMap, path::Path};

use praxis_core::config::{Config, ProtocolKind};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn branching_configs_parse_with_branch_chains() {
    let configs = [
        "branching/conditional-terminal.yaml",
        "branching/multiple-branches.yaml",
    ];
    for filename in configs {
        let config =
            crate::example_utils::load_example_config(filename, 8080, HashMap::from([("127.0.0.1:3000", 3000)]));
        assert!(
            !config.filter_chains.is_empty(),
            "{filename}: should have at least one filter chain"
        );
        let has_branch = config.filter_chains.iter().any(|chain| {
            chain
                .filters
                .iter()
                .any(|f| f.branch_chains.as_ref().is_some_and(|b| !b.is_empty()))
        });
        assert!(
            has_branch,
            "{filename}: at least one filter entry should have branch_chains"
        );
    }
}

#[test]
fn conditional_terminal_branch_has_terminal_rejoin() {
    let config = crate::example_utils::load_example_config(
        "branching/conditional-terminal.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let branches: Vec<_> = config
        .filter_chains
        .iter()
        .flat_map(|c| &c.filters)
        .filter_map(|f| f.branch_chains.as_ref())
        .flatten()
        .collect();
    assert!(
        !branches.is_empty(),
        "conditional-terminal should define at least one branch chain"
    );
    let terminal = branches.iter().any(|b| b.rejoin == "terminal");
    assert!(
        terminal,
        "conditional-terminal should have a branch with rejoin: terminal"
    );
}

#[test]
fn multiple_branches_has_two_branch_chains() {
    let config = crate::example_utils::load_example_config(
        "branching/multiple-branches.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    let branches: Vec<_> = config
        .filter_chains
        .iter()
        .flat_map(|c| &c.filters)
        .filter_map(|f| f.branch_chains.as_ref())
        .flatten()
        .collect();
    assert_eq!(
        branches.len(),
        2,
        "multiple-branches should define exactly two branch chains"
    );
}

#[test]
fn payload_configs_parse_compression() {
    let config = crate::example_utils::load_example_config(
        "payload-processing/compression.yaml",
        8080,
        HashMap::from([("127.0.0.1:3000", 3000)]),
    );
    assert_eq!(config.listeners.len(), 1, "compression config should have one listener");
    assert!(
        !config.filter_chains.is_empty(),
        "compression config should have filter chains"
    );
    let has_compression = config
        .filter_chains
        .iter()
        .any(|chain| chain.filters.iter().any(|f| f.filter_type == "compression"));
    assert!(
        has_compression,
        "compression config should contain a compression filter"
    );
}

#[test]
fn pipeline_configs_parse_composed_chains() {
    let config = crate::example_utils::load_example_config("pipeline/composed-chains.yaml", 8080, HashMap::new());
    assert_eq!(config.listeners.len(), 2, "composed-chains should have two listeners");
    assert_eq!(config.listeners[0].name, "public", "first listener should be 'public'");
    assert_eq!(
        config.listeners[1].name, "internal",
        "second listener should be 'internal'"
    );
    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["security", "observability", "routing"],
        "public listener should reference three chains"
    );
    assert_eq!(
        config.listeners[1].filter_chains,
        vec!["observability", "routing"],
        "internal listener should reference two chains"
    );
    assert_eq!(
        config.filter_chains.len(),
        3,
        "composed-chains should define three filter chains"
    );
    let chain_names: Vec<&str> = config.filter_chains.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        chain_names,
        vec!["security", "observability", "routing"],
        "filter chain names should match config"
    );
}

#[test]
fn protocol_tcp_config_parses_from_example() {
    let path = praxis_test_utils::example_config_path("protocols/tcp-proxy.yaml");
    let config = Config::from_file(Path::new(&path)).unwrap_or_else(|e| panic!("parse tcp-proxy.yaml: {e}"));
    assert_eq!(config.listeners.len(), 1, "tcp-proxy should have one listener");
    let listener = &config.listeners[0];
    assert_eq!(listener.name, "postgres", "listener name should be 'postgres'");
    assert_eq!(listener.protocol, ProtocolKind::Tcp, "protocol should be Tcp");
    assert_eq!(
        listener.upstream.as_deref(),
        Some("127.0.0.1:15432"),
        "upstream should point to the postgres backend"
    );
    assert!(
        listener.filter_chains.is_empty(),
        "tcp-proxy example should have no filter chains"
    );
    assert!(listener.tls.is_none(), "tcp-proxy example should have no TLS");
}
