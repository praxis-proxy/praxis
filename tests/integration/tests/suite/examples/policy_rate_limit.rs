// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration test for the Policy rate limiting example
//! (`examples/configs/security/policy-rate-limit.yaml`).
//!
//! Drives both limiter stages through a real proxy on the default build: the
//! per-subject limit after identity, the per-address limit before identity
//! (which stops a bad key before it is checked), and the 429 wire form. A
//! counting backend proves no denied request reaches it.

use std::{collections::HashMap, sync::atomic::Ordering};

use praxis_core::config::Config;
use praxis_test_utils::{
    example_config_path, free_port, http_send, parse_status, patch_yaml, start_proxy, start_request_counting_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn policy_rate_limit_enforces_both_stages_end_to_end() {
    let (backend, hits) = start_request_counting_backend("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let config = load_example(&policy_dir, free_port(), backend.port());
    let proxy = start_proxy(&config);

    for attempt in 1..=3 {
        let raw = send(proxy.addr(), "sk-test-alice");
        assert_eq!(parse_status(&raw), 200, "attempt {attempt} is under the limit: {raw}");
    }
    let denied = send(proxy.addr(), "sk-test-alice");
    assert_eq!(parse_status(&denied), 429, "the fourth request is over: {denied}");
    assert_eq!(header(&denied, "X-Policy-Violation"), Some("ratelimit.exceeded"));
    let retry: u64 = header(&denied, "Retry-After")
        .and_then(|value| value.parse().ok())
        .expect("a positive Retry-After");
    assert!(retry >= 1);
    let body: serde_json::Value =
        serde_json::from_str(denied.split("\r\n\r\n").nth(1).unwrap_or_default()).expect("JSON body");
    let mut keys: Vec<&str> = body.as_object().expect("object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "code",
            "limit",
            "message",
            "remaining",
            "retry_after_seconds",
            "window_seconds"
        ]
    );
    assert!(!denied.contains("per-user"), "the namespace never reaches the client");

    let mut statuses = Vec::new();
    while statuses.last() != Some(&429) && statuses.len() < 20 {
        statuses.push(parse_status(&send(proxy.addr(), "sk-test-mallory")));
    }
    assert_eq!(
        statuses.first(),
        Some(&401),
        "identity still runs under the limit: {statuses:?}"
    );
    assert_eq!(
        statuses.last(),
        Some(&429),
        "the address runs out within its limit: {statuses:?}"
    );
    assert!(
        statuses.iter().rev().skip(1).all(|status| *status == 401),
        "every request under the limit reaches identity: {statuses:?}"
    );
    let edge = send(proxy.addr(), "sk-test-mallory");
    assert_eq!(
        header(&edge, "X-Policy-Violation"),
        Some("ratelimit.exceeded"),
        "{edge}"
    );

    assert_eq!(hits.load(Ordering::SeqCst), 3, "no denied request reached the backend");
}

#[test]
fn a_malformed_hop_from_a_trusted_proxy_is_denied_not_pooled() {
    let (backend, hits) = start_request_counting_backend("ok");
    let policy_dir = tempfile::TempDir::new().expect("create tempdir");
    let mut config = load_example(&policy_dir, free_port(), backend.port());
    let policy = config
        .filter_chains
        .iter_mut()
        .flat_map(|chain| chain.filters.iter_mut())
        .find(|entry| entry.filter_type == "policy")
        .expect("the example's policy filter");
    policy.config.as_mapping_mut().expect("policy config mapping").insert(
        "trusted_proxies".into(),
        serde_yaml::Value::Sequence(vec!["127.0.0.0/8".into()]),
    );
    let proxy = start_proxy(&config);

    for forwarded in ["not-an-ip", "198.51.100.7, garbage"] {
        let raw = send_forwarded(proxy.addr(), forwarded);
        assert_eq!(
            parse_status(&raw),
            400,
            "{forwarded}: an unattributable request is denied: {raw}"
        );
        assert_eq!(
            header(&raw, "X-Policy-Violation"),
            Some("ratelimit.missing_attribute"),
            "{forwarded}: {raw}"
        );
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no unattributable request reached the backend"
    );

    let raw = send_forwarded(proxy.addr(), "198.51.100.7");
    assert_eq!(
        parse_status(&raw),
        200,
        "a well-formed chain is attributed and admitted: {raw}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Load the example with its policy pointed at a copy of the fixture whose key
/// directory points at the fixture key file.
fn load_example(policy_dir: &tempfile::TempDir, proxy_port: u16, backend_port: u16) -> Config {
    let fixtures = format!("{}/fixtures", env!("CARGO_MANIFEST_DIR"));
    let policy = std::fs::read_to_string(format!("{fixtures}/rate-limit-policy.yaml")).expect("read fixture policy");
    let policy = policy.replace("/etc/praxis/api-keys.yaml", &format!("{fixtures}/api-keys.yaml"));
    let policy_path = policy_dir.path().join("rate-limit-policy.yaml");
    std::fs::write(&policy_path, policy).expect("write policy");

    let example_path = example_config_path("security/policy-rate-limit.yaml");
    let raw = std::fs::read_to_string(&example_path).unwrap_or_else(|e| panic!("read {example_path}: {e}"));
    let with_policy = raw.replace(
        "/etc/praxis/rate-limit-policy.yaml",
        policy_path.to_str().expect("utf8 path"),
    );
    let patched = patch_yaml(
        &with_policy,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    );
    Config::from_yaml(&patched).unwrap_or_else(|e| panic!("parse security/policy-rate-limit.yaml: {e}"))
}

/// Send `GET /widgets` with `key` as the bearer key.
fn send(addr: &str, key: &str) -> String {
    http_send(
        addr,
        &format!(
            "GET /widgets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\nConnection: close\r\n\r\n"
        ),
    )
}

/// The value of response header `name`, if present.
fn header<'r>(raw: &'r str, name: &str) -> Option<&'r str> {
    raw.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Send `GET /widgets` for alice carrying `forwarded` as `X-Forwarded-For`.
fn send_forwarded(addr: &str, forwarded: &str) -> String {
    http_send(
        addr,
        &format!(
            "GET /widgets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer sk-test-alice\r\nX-Forwarded-For: \
             {forwarded}\r\nConnection: close\r\n\r\n"
        ),
    )
}
