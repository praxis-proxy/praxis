// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the API key authentication example
//! (`examples/configs/security/policy-api-key.yaml`).
//!
//! Drives the `policy` filter end to end with `identity/api-key` as its only
//! identity resolver. A known key reaches the backend, while an unknown key, a
//! credential without the key prefix, and a missing key are rejected with HTTP 401.
//!
//! In a FIPS build (`policy-crypto-fips`) the key digests go through the
//! OpenSSL FIPS provider, so these cases run only where one is active
//! (`make test-fips-provider`, `make test-fips-host`); elsewhere the filter
//! must refuse to build, which the last test checks.

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

/// Whether this build can load the policy: always, except a FIPS build
/// without a FIPS provider.
fn provider_ready() -> bool {
    !cfg!(feature = "policy-crypto-fips") || praxis_test_utils::expect_approved_mode()
}

/// Send `GET /widgets` through a proxy built from the example, with
/// `authorization` as the `Authorization` header when present; `None` when
/// the build cannot load the policy here.
fn send(authorization: Option<&str>) -> Option<String> {
    if !provider_ready() {
        eprintln!("policy_api_key: skipped, FIPS build without a FIPS provider (run make test-fips-provider)");
        return None;
    }
    let backend = start_backend_with_shutdown("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&policy_dir, free_port(), backend.port());
    let proxy = start_proxy(&config);
    let header = authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
    Some(http_send(
        proxy.addr(),
        &format!("GET /widgets HTTP/1.1\r\nHost: localhost\r\n{header}Connection: close\r\n\r\n"),
    ))
}

#[test]
fn policy_api_key_known_key_passes_through() {
    let Some(raw) = send(Some(&format!("Bearer {KNOWN_KEY}"))) else {
        return;
    };
    assert_eq!(parse_status(&raw), 200, "a known key should reach the backend");
    assert!(raw.contains("ok"), "backend body should reach the client");
}

#[test]
fn policy_api_key_unknown_key_is_rejected() {
    let Some(raw) = send(Some("Bearer sk-test-mallory")) else {
        return;
    };
    assert_eq!(parse_status(&raw), 401, "an unknown key should be rejected");
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.key_unknown"),
        "got: {raw}"
    );
}

#[test]
fn policy_api_key_unrecognized_credential_is_rejected() {
    let Some(raw) = send(Some("Bearer unrelated-test-credential")) else {
        return;
    };
    assert_eq!(
        parse_status(&raw),
        401,
        "a credential without the key prefix should be rejected"
    );
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.unrecognized_credential"),
        "got: {raw}"
    );
}

#[test]
fn policy_api_key_missing_key_is_rejected() {
    let Some(raw) = send(None) else { return };
    assert_eq!(parse_status(&raw), 401, "a request with no key should be rejected");
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-policy-violation: auth.missing_credential"),
        "got: {raw}"
    );
}

#[cfg(feature = "policy-crypto-fips")]
#[test]
fn policy_api_key_fips_build_without_a_fips_provider_refuses_the_policy() {
    if provider_ready() {
        return;
    }
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&policy_dir, free_port(), free_port());
    let error = praxis::resolve_pipelines(
        &config,
        &praxis::build_full_registry(),
        &praxis_core::health::build_health_registry(&config.clusters),
        &praxis_core::kv::KvStoreRegistry::new(),
        &std::sync::Arc::new(praxis_filter::SessionStoreRegistry::new()),
        &praxis::build_subrequest_client(&config).expect("sub-request client"),
    )
    .map(drop)
    .expect_err("without the FIPS provider the API-key policy must not load")
    .to_string();
    assert!(
        error.contains("policy.crypto_failed"),
        "the refusal names the crypto failure: {error}"
    );
}
