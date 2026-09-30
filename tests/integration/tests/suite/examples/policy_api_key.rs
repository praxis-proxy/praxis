// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the API key authentication example
//! (`examples/configs/security/policy-api-key.yaml`).
//!
//! Drives the `policy` filter end to end with `identity/api-key` as its only
//! identity resolver. A known key reaches the backend, while an unknown key and
//! a missing key are both rejected at the identity gate with HTTP 401.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_backend_with_shutdown, start_proxy,
};

/// Key the fixture directory maps to subject `alice`.
const KNOWN_KEY: &str = "sk-test-alice";

/// Load the example with its `config_path` pointed at a copy of the fixture
/// policy whose directory path points at the fixture key file.
fn load_example(policy_dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let fixtures = format!("{}/fixtures", env!("CARGO_MANIFEST_DIR"));
    let policy = std::fs::read_to_string(format!("{fixtures}/api-key-policy.yaml")).expect("read fixture policy");
    let policy = policy.replace("/etc/praxis/api-keys.yaml", &format!("{fixtures}/api-keys.yaml"));
    let policy_path = policy_dir.path().join("api-key-policy.yaml");
    std::fs::write(&policy_path, policy).expect("write policy");

    let example_path = example_config_path("security/policy-api-key.yaml");
    let raw = std::fs::read_to_string(&example_path).unwrap_or_else(|e| panic!("read {example_path}: {e}"));
    let with_policy = raw.replace(
        "/etc/praxis/api-key-policy.yaml",
        policy_path.to_str().expect("utf8 path"),
    );
    let patched = patch_yaml(
        &with_policy,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-api-key.yaml: {e}"))
}

/// Send `GET /widgets` through a proxy built from the example, with
/// `authorization` as the `Authorization` header when present.
fn send(authorization: Option<&str>) -> String {
    let backend = start_backend_with_shutdown("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&policy_dir, free_port(), backend.port());
    let proxy = start_proxy(&config);
    let header = authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
    http_send(
        proxy.addr(),
        &format!("GET /widgets HTTP/1.1\r\nHost: localhost\r\n{header}Connection: close\r\n\r\n"),
    )
}

#[test]
fn policy_api_key_known_key_passes_through() {
    let raw = send(Some(&format!("Bearer {KNOWN_KEY}")));
    assert_eq!(parse_status(&raw), 200, "a known key should reach the backend");
    assert!(raw.contains("ok"), "backend body should reach the client");
}

#[test]
fn policy_api_key_unknown_key_is_rejected() {
    let raw = send(Some("Bearer sk-test-mallory"));
    assert_eq!(parse_status(&raw), 401, "an unknown key should be rejected");
}

#[test]
fn policy_api_key_missing_key_is_rejected() {
    let raw = send(None);
    assert_eq!(parse_status(&raw), 401, "a request with no key should be rejected");
}
