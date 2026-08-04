// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the basic auth filter.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use praxis_core::kv::KvStoreRegistry;

use super::filter::BasicAuthFilter;
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

#[test]
fn from_config_parses_valid_inline() {
    let yaml = yaml(
        "
credentials:
  - username: admin
    password: secret
",
    );
    let filter = BasicAuthFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "basic_auth");
}

#[test]
fn from_config_parses_valid_kv_store() {
    let yaml = yaml("kv_store: auth_credentials");
    let filter = BasicAuthFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "basic_auth");
}

#[test]
fn rejects_both_credentials_and_kv_store() {
    let yaml = yaml(
        "
credentials:
  - username: admin
    password: secret
kv_store: auth_credentials
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("both"),
        "should reject both credential sources: {err}"
    );
}

#[test]
fn rejects_neither_credentials_nor_kv_store() {
    let yaml = yaml("realm: Test");
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("one of"),
        "should reject missing credential source: {err}"
    );
}

#[test]
fn rejects_both_password_and_env_var() {
    let yaml = yaml(
        "
credentials:
  - username: admin
    password: secret
    env_var: SECRET_VAR
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("both 'password' and 'env_var'"),
        "should reject both password sources: {err}"
    );
}

#[test]
fn rejects_neither_password_nor_env_var() {
    let yaml = yaml(
        "
credentials:
  - username: admin
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must have either"),
        "should reject missing password source: {err}"
    );
}

#[test]
fn rejects_duplicate_usernames() {
    let yaml = yaml(
        "
credentials:
  - username: admin
    password: one
  - username: admin
    password: two
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("duplicate username"),
        "should reject duplicate usernames: {err}"
    );
}

#[test]
fn rejects_empty_username() {
    let yaml = yaml(
        "
credentials:
  - username: ''
    password: secret
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("username must not be empty"),
        "should reject empty username: {err}"
    );
}

#[test]
fn rejects_whitespace_only_username() {
    let yaml = yaml(
        "
credentials:
  - username: '  '
    password: secret
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("username must not be empty"),
        "should reject whitespace-only username: {err}"
    );
}

#[test]
fn rejects_realm_with_double_quote() {
    let yaml = yaml(
        r#"
realm: 'has"quote'
credentials:
  - username: admin
    password: secret
"#,
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("realm must not contain"),
        "should reject realm with double-quote: {err}"
    );
}

#[test]
fn rejects_realm_with_backslash() {
    let yaml = yaml("realm: 'has\\\\slash'\ncredentials:\n  - username: admin\n    password: secret\n");
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("realm must not contain"),
        "should reject realm with backslash: {err}"
    );
}

#[test]
fn rejects_realm_with_control_character() {
    let yaml = yaml("realm: \"has\\x00null\"\ncredentials:\n  - username: admin\n    password: secret\n");
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("realm must not contain"),
        "should reject realm with control character: {err}"
    );
}

#[test]
fn rejects_missing_env_var() {
    let yaml = yaml(
        "
credentials:
  - username: deploy
    env_var: PRAXIS_TEST_MISSING_VAR_THAT_DOES_NOT_EXIST
",
    );
    let err = BasicAuthFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not set"),
        "should reject missing env var: {err}"
    );
}

// -----------------------------------------------------------------------------
// Request-Phase Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn authenticates_valid_credentials() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid credentials should continue"
    );
}

#[tokio::test]
async fn rejects_missing_authorization_header() {
    let f = make_filter(&[("admin", "fakecreds")], "TestRealm");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert_rejection_with_challenge(&action, "TestRealm");
}

#[tokio::test]
async fn rejects_invalid_base64() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Basic !!!not-base64!!!"),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "invalid base64 should return 401"
    );
}

#[tokio::test]
async fn rejects_non_utf8_base64() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Basic gP8="),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "non-UTF-8 decoded payload should return 401"
    );
}

#[tokio::test]
async fn rejects_credentials_without_colon() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    let encoded = STANDARD.encode("usernameonly");
    req.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "credentials without colon separator should return 401"
    );
}

#[tokio::test]
async fn rejects_wrong_password() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "wrong"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "wrong password should return 401"
    );
}

#[tokio::test]
async fn rejects_unknown_username() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("unknown", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "unknown username should return 401"
    );
}

#[tokio::test]
async fn rejects_non_basic_scheme() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer some-token"),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "non-Basic scheme should return 401"
    );
}

#[tokio::test]
async fn strips_authorization_header_by_default() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert!(
        ctx.request_headers_to_remove.contains(&http::header::AUTHORIZATION),
        "should queue Authorization header for removal"
    );
}

#[tokio::test]
async fn preserves_authorization_header_when_strip_disabled() {
    let yaml = yaml(
        "
credentials:
  - username: admin
    password: fakecreds
strip_authorization: false
",
    );
    let f = BasicAuthFilter::from_config(&yaml).unwrap();
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert!(
        ctx.request_headers_to_remove.is_empty(),
        "should not queue header removal when strip_authorization is false"
    );
}

#[tokio::test]
async fn password_may_contain_colons() {
    let f = make_filter(&[("admin", "a:b:c")], "Restricted");
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "a:b:c"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "password with colons should authenticate successfully"
    );
}

#[tokio::test]
async fn basic_scheme_case_insensitive() {
    let f = make_filter(&[("admin", "fakecreds")], "Restricted");
    let encoded = STANDARD.encode("admin:fakecreds");

    for scheme in &["BASIC", "basic", "bAsIc"] {
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        let value = format!("{scheme} {encoded}");
        req.headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&value).unwrap(),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "scheme '{scheme}' should be accepted"
        );
    }
}

#[tokio::test]
async fn realm_appears_in_challenge() {
    let f = make_filter(&[("admin", "fakecreds")], "My Custom Realm");
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert_rejection_with_challenge(&action, "My Custom Realm");
}

#[tokio::test]
async fn kv_store_lookup_valid_credentials() {
    let yaml = yaml("kv_store: auth_users");
    let f = BasicAuthFilter::from_config(&yaml).unwrap();

    let registry = KvStoreRegistry::new();
    let store = registry.get_or_create("auth_users");
    store.set("admin", Arc::from("fakecreds"));

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.kv_stores = Some(&registry);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "valid KV store credentials should continue"
    );
}

#[tokio::test]
async fn kv_store_missing_store_rejects() {
    let yaml = yaml("kv_store: nonexistent_store");
    let f = BasicAuthFilter::from_config(&yaml).unwrap();

    let registry = KvStoreRegistry::new();
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.kv_stores = Some(&registry);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "missing KV store should reject with 401"
    );
}

#[tokio::test]
async fn kv_store_missing_registry_rejects() {
    let yaml = yaml("kv_store: auth_users");
    let f = BasicAuthFilter::from_config(&yaml).unwrap();

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert(http::header::AUTHORIZATION, basic_header("admin", "fakecreds"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 401),
        "missing KV registry should reject with 401"
    );
}

#[tokio::test]
async fn multiple_inline_credentials() {
    let f = make_filter(&[("admin", "fakecreds"), ("readonly", "viewer")], "Restricted");

    for (user, pass) in &[("admin", "fakecreds"), ("readonly", "viewer")] {
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers
            .insert(http::header::AUTHORIZATION, basic_header(user, pass));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "user '{user}' should authenticate successfully"
        );
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Parse a YAML string into a `serde_yaml::Value`.
fn yaml(s: &str) -> serde_yaml::Value {
    serde_yaml::from_str(s).expect("test YAML should parse")
}

/// Build a `BasicAuthFilter` with inline credentials.
fn make_filter(users: &[(&str, &str)], realm: &str) -> Box<dyn HttpFilter> {
    let creds: String = users
        .iter()
        .map(|(u, p)| format!("  - username: {u}\n    password: {p}\n"))
        .collect();
    let config = format!("realm: \"{realm}\"\ncredentials:\n{creds}");
    BasicAuthFilter::from_config(&yaml(&config)).expect("test filter should construct")
}

/// Encode credentials as a `Basic` Authorization header value.
fn basic_header(username: &str, password: &str) -> http::HeaderValue {
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    http::HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header value")
}

/// Assert that an action is a 401 rejection with a matching realm challenge.
fn assert_rejection_with_challenge(action: &FilterAction, realm: &str) {
    let FilterAction::Reject(rejection) = action else {
        panic!("expected Reject, got {action:?}");
    };
    assert_eq!(rejection.status, 401, "should reject with 401");
    let challenge = rejection
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("WWW-Authenticate"))
        .map(|(_, v)| v.as_str());
    let expected = format!("Basic realm=\"{realm}\"");
    assert_eq!(
        challenge,
        Some(expected.as_str()),
        "WWW-Authenticate should contain realm"
    );
}
