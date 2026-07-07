// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Admin interface example configuration tests.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn admin_interface_parses() {
    let path = praxis_test_utils::example_config_path("operations/admin-interface.yaml");
    let config =
        Config::from_file(std::path::Path::new(&path)).unwrap_or_else(|e| panic!("parse admin-interface: {e}"));
    assert_eq!(config.listeners.len(), 1, "expected one listener");
    assert_eq!(config.listeners[0].name, "default", "listener should be named default");
    assert_eq!(
        config.admin.address,
        Some("127.0.0.1:9901".to_owned()),
        "admin address should be 127.0.0.1:9901"
    );
    assert!(config.admin.verbose, "admin verbose should be true");
    assert!(
        config.metrics.filter_duration,
        "filter_duration should be enabled in example"
    );
    assert_eq!(config.filter_chains.len(), 1, "expected one filter chain");
}
