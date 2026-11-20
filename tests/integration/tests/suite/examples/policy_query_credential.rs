// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the query-parameter API key example
//! (`examples/configs/security/policy-query-credential.yaml`).
//!
//! Drives the `policy` filter end to end with an `identity/api-key` resolver
//! reading `?api_key=`. A known key reaches the backend with its query intact;
//! a missing, unknown or repeated key is rejected with HTTP 401, and no
//! rejection echoes the key.

use std::collections::HashMap;

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_proxy, start_uri_echo_backend,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Key the fixture directory maps to subject `alice`.
const KNOWN_KEY: &str = "sk-test-alice";

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn policy_query_credential_known_key_passes_through() {
    let target = format!("/events?api_key={KNOWN_KEY}&stream=1");
    let raw = send(&target);
    assert_eq!(
        parse_status(&raw),
        200,
        "a known key in the query should reach the backend"
    );
    assert!(
        raw.ends_with(&target),
        "the filter does not rewrite the URL, so the backend sees the query: {raw}"
    );
}

#[test]
fn policy_query_credential_unknown_key_is_rejected() {
    let raw = send("/events?api_key=sk-test-mallory");
    assert_eq!(parse_status(&raw), 401, "an unknown key should be rejected");
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.key_unknown"),
        "got: {raw}"
    );
    assert!(
        !raw.contains("sk-test-mallory"),
        "the rejection must not echo the key: {raw}"
    );
}

#[test]
fn policy_query_credential_missing_key_is_rejected() {
    for target in ["/events", "/events?", "/events?stream=1"] {
        let raw = send(target);
        assert_eq!(parse_status(&raw), 401, "{target} carries no key");
        assert!(
            raw.to_ascii_lowercase()
                .contains("x-policy-violation: auth.missing_credential"),
            "{target}: got {raw}"
        );
    }
}

#[test]
fn policy_query_credential_repeated_key_is_rejected() {
    for target in [
        format!("/events?api_key={KNOWN_KEY}&api_key=sk-test-bob"),
        format!("/events?api_key={KNOWN_KEY}&api%5Fkey=sk-test-bob"),
    ] {
        let raw = send(&target);
        assert_eq!(parse_status(&raw), 401, "{target} names the key twice");
        assert!(
            raw.to_ascii_lowercase()
                .contains("x-policy-violation: auth.ambiguous_credential"),
            "{target}: got {raw}"
        );
        assert!(!raw.contains(KNOWN_KEY), "the rejection must not echo the key: {raw}");
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example with its `config_path` pointed at a copy of the fixture
/// policy whose directory path points at the fixture key file.
fn load_example(policy_dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let fixtures = format!("{}/fixtures", env!("CARGO_MANIFEST_DIR"));
    let policy =
        std::fs::read_to_string(format!("{fixtures}/query-credential-policy.yaml")).expect("read fixture policy");
    let policy = policy.replace("/etc/praxis/api-keys.yaml", &format!("{fixtures}/api-keys.yaml"));
    let policy_path = policy_dir.path().join("query-credential-policy.yaml");
    std::fs::write(&policy_path, policy).expect("write policy");

    let example_path = example_config_path("security/policy-query-credential.yaml");
    let raw = std::fs::read_to_string(&example_path).unwrap_or_else(|e| panic!("read {example_path}: {e}"));
    let with_policy = raw.replace(
        "/etc/praxis/query-credential-policy.yaml",
        policy_path.to_str().expect("utf8 path"),
    );
    let patched = patch_yaml(
        &with_policy,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-query-credential.yaml: {e}"))
}

/// Send `GET target` through a proxy built from the example; the backend
/// answers with the request-target it received.
fn send(target: &str) -> String {
    let backend = start_uri_echo_backend();
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&policy_dir, free_port(), backend.port());
    let proxy = start_proxy(&config);
    http_send(
        proxy.addr(),
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}
