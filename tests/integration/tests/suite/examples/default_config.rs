// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the default example configuration.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, patch_yaml, start_proxy};
use serde_json::Value;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default example config loaded at compile time.
const DEFAULT_CONFIG: &str = praxis_core::config::DEFAULT_CONFIG;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn default_config_root_returns_200() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = default_config_with_test_ports(proxy_port, admin_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "default config root should return 200");
    let json: Value = serde_json::from_str(&body).expect("response body should be valid JSON");
    assert_eq!(json["status"], "ok", "status field should be 'ok'");
    assert_eq!(json["server"], "praxis", "server field should be 'praxis'");
}

#[test]
fn default_config_other_path_returns_404() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = default_config_with_test_ports(proxy_port, admin_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/anything", None);
    assert_eq!(status, 404, "non-root path should return 404");
    assert!(body.contains("not found"), "404 body should contain 'not found'");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Return the embedded default config with per-test listener and admin ports.
///
/// `patch_yaml` handles known default listener forms. The admin listener is
/// patched separately because it is not an endpoint.
fn default_config_with_test_ports(proxy_port: u16, admin_port: u16) -> String {
    patch_yaml(DEFAULT_CONFIG, proxy_port, &HashMap::new())
        .replace("127.0.0.1:9901", &format!("127.0.0.1:{admin_port}"))
}
