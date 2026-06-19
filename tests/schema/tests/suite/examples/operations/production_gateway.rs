// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Production gateway example configuration tests.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn production_gateway_parses() {
    let path = praxis_test_utils::example_config_path("operations/production-gateway.yaml");
    let config =
        Config::from_file(std::path::Path::new(&path)).unwrap_or_else(|e| panic!("parse production-gateway: {e}"));
    assert_eq!(config.listeners.len(), 2, "expected https and http listeners");
    assert_eq!(
        config.listeners[0].name, "https",
        "first listener should be named https"
    );
    assert_eq!(config.listeners[1].name, "http", "second listener should be named http");
    assert!(
        config.listeners[0].tls.is_some(),
        "https listener should have TLS config"
    );
    assert!(
        config.listeners[1].tls.is_none(),
        "http listener should not have TLS config"
    );
    assert_eq!(
        config.filter_chains.len(),
        3,
        "expected observability, security, and routing chains"
    );
    assert_eq!(config.shutdown_timeout_secs, 30, "shutdown timeout should be 30s");
}

#[test]
fn production_gateway_has_expected_filter_chains() {
    let path = praxis_test_utils::example_config_path("operations/production-gateway.yaml");
    let config = Config::from_file(std::path::Path::new(&path)).unwrap();
    let chain_names: Vec<&str> = config.filter_chains.iter().map(|c| c.name.as_str()).collect();
    assert!(
        chain_names.contains(&"observability"),
        "expected observability chain, got: {chain_names:?}"
    );
    assert!(
        chain_names.contains(&"security"),
        "expected security chain, got: {chain_names:?}"
    );
    assert!(
        chain_names.contains(&"routing"),
        "expected routing chain, got: {chain_names:?}"
    );
}

#[test]
fn production_gateway_listeners_reference_all_chains() {
    let path = praxis_test_utils::example_config_path("operations/production-gateway.yaml");
    let config = Config::from_file(std::path::Path::new(&path)).unwrap();
    for listener in &config.listeners {
        assert_eq!(
            listener.filter_chains.len(),
            3,
            "listener {name} should reference 3 filter chains",
            name = listener.name
        );
        assert!(
            listener.filter_chains.contains(&"observability".to_owned()),
            "listener {name} should reference observability chain",
            name = listener.name
        );
        assert!(
            listener.filter_chains.contains(&"security".to_owned()),
            "listener {name} should reference security chain",
            name = listener.name
        );
        assert!(
            listener.filter_chains.contains(&"routing".to_owned()),
            "listener {name} should reference routing chain",
            name = listener.name
        );
    }
}
