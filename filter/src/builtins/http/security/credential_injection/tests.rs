// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the credential injection filter.

use std::sync::Arc;

use super::CredentialInjectionFilter;
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn injects_credential_for_matching_cluster() {
    let f = from_yaml(
        r#"
clusters:
  - name: openai
    header: Authorization
    value: "sk-test-key"
    header_prefix: "Bearer "
"#,
    );
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("openai"));

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "credential injection should continue"
    );

    let injected = find_header(&ctx.extra_request_headers, "Authorization");
    assert_eq!(
        injected,
        Some("Bearer sk-test-key"),
        "Authorization header should have Bearer prefix and key"
    );
}

#[tokio::test]
async fn skips_when_no_cluster_selected() {
    let f = from_yaml(
        r#"
clusters:
  - name: openai
    header: Authorization
    value: "sk-test-key"
"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when no cluster selected"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be injected without a cluster"
    );
}

#[tokio::test]
async fn skips_when_cluster_has_no_credentials() {
    let f = from_yaml(
        r#"
clusters:
  - name: openai
    header: Authorization
    value: "sk-test-key"
"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("other-cluster"));

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "should continue for unconfigured cluster"
    );
    assert!(
        ctx.extra_request_headers.is_empty(),
        "no headers should be injected for unconfigured cluster"
    );
}

#[tokio::test]
async fn injects_without_prefix() {
    let f = from_yaml(
        r#"
clusters:
  - name: internal
    header: x-api-key
    value: "raw-token-123"
"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("internal"));

    let _action = f.on_request(&mut ctx).await.unwrap();

    let injected = find_header(&ctx.extra_request_headers, "x-api-key");
    assert_eq!(
        injected,
        Some("raw-token-123"),
        "x-api-key should contain raw token without prefix"
    );
}

#[tokio::test]
async fn strips_client_credential_by_default() {
    let f = from_yaml(
        r#"
clusters:
  - name: backend
    header: Authorization
    value: "server-secret"
"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("authorization", "client-spoofed".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));

    let _action = f.on_request(&mut ctx).await.unwrap();

    let auth_headers: Vec<_> = ctx
        .extra_request_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
        .collect();
    assert_eq!(auth_headers.len(), 2, "should have strip (empty) + inject entries");
    assert_eq!(auth_headers[0].1, "", "first entry should be empty (strip)");
    assert_eq!(
        auth_headers[1].1, "server-secret",
        "second entry should be the injected credential"
    );
}

#[tokio::test]
async fn no_strip_when_disabled() {
    let f = from_yaml(
        r#"
clusters:
  - name: backend
    header: Authorization
    value: "server-secret"
    strip_client_credential: false
"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));

    let _action = f.on_request(&mut ctx).await.unwrap();

    let auth_headers: Vec<_> = ctx
        .extra_request_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
        .collect();
    assert_eq!(
        auth_headers.len(),
        1,
        "should only have inject entry when strip is disabled"
    );
    assert_eq!(
        auth_headers[0].1, "server-secret",
        "single entry should be the injected credential"
    );
}

#[tokio::test]
async fn multiple_clusters() {
    let f = from_yaml(
        r#"
clusters:
  - name: openai
    header: Authorization
    value: "sk-openai"
    header_prefix: "Bearer "
  - name: anthropic
    header: x-api-key
    value: "sk-anthropic"
"#,
    );

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("openai"));
    let _action = f.on_request(&mut ctx).await.unwrap();
    let auth = find_header(&ctx.extra_request_headers, "Authorization");
    assert_eq!(auth, Some("Bearer sk-openai"), "openai cluster should get Bearer token");

    let req2 = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
    let mut ctx2 = crate::test_utils::make_filter_context(&req2);
    ctx2.cluster = Some(Arc::from("anthropic"));
    let _action = f.on_request(&mut ctx2).await.unwrap();
    let key = find_header(&ctx2.extra_request_headers, "x-api-key");
    assert_eq!(key, Some("sk-anthropic"), "anthropic cluster should get x-api-key");
}

#[test]
fn rejects_empty_clusters() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("clusters: []").unwrap();
    let err = CredentialInjectionFilter::from_config(&yaml)
        .err()
        .expect("should fail for empty clusters");
    assert!(
        err.to_string().contains("must not be empty"),
        "empty clusters should fail: {err}"
    );
}

#[test]
fn rejects_both_value_and_env_var() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
clusters:
  - name: bad
    header: Authorization
    value: "inline"
    env_var: "SOME_VAR"
"#,
    )
    .unwrap();
    let err = CredentialInjectionFilter::from_config(&yaml)
        .err()
        .expect("should fail with both value and env_var");
    assert!(
        err.to_string().contains("both 'value' and 'env_var'"),
        "both value and env_var should fail: {err}"
    );
}

#[test]
fn rejects_neither_value_nor_env_var() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "
clusters:
  - name: bad
    header: Authorization
",
    )
    .unwrap();
    let err = CredentialInjectionFilter::from_config(&yaml)
        .err()
        .expect("should fail with neither value nor env_var");
    assert!(
        err.to_string().contains("must have either 'value' or 'env_var'"),
        "missing both value and env_var should fail: {err}"
    );
}

#[test]
fn rejects_missing_env_var() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
clusters:
  - name: bad
    header: Authorization
    env_var: "DEFINITELY_NOT_SET_PRAXIS_TEST_XYZ"
"#,
    )
    .unwrap();
    let err = CredentialInjectionFilter::from_config(&yaml)
        .err()
        .expect("should fail with missing env var");
    assert!(err.to_string().contains("not set"), "unset env var should fail: {err}");
}

#[test]
fn from_config_parses_valid_yaml() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
clusters:
  - name: openai
    header: Authorization
    value: "sk-test"
    header_prefix: "Bearer "
    strip_client_credential: true
  - name: internal
    header: x-api-key
    value: "internal-key"
    strip_client_credential: false
"#,
    )
    .unwrap();
    let filter = CredentialInjectionFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "credential_injection",
        "filter name should be credential_injection"
    );
}

#[tokio::test]
async fn strips_case_insensitive_client_header() {
    let f = from_yaml(
        r#"
clusters:
  - name: backend
    header: Authorization
    value: "server-secret"
"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("authorization", "client-spoofed".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.cluster = Some(Arc::from("backend"));

    let _action = f.on_request(&mut ctx).await.unwrap();

    let strip_entries: Vec<_> = ctx
        .extra_request_headers
        .iter()
        .filter(|(k, v)| k.eq_ignore_ascii_case("Authorization") && v.is_empty())
        .collect();
    assert_eq!(
        strip_entries.len(),
        1,
        "should strip client header even when client sends lowercase 'authorization'"
    );

    let injected = find_header(&ctx.extra_request_headers, "Authorization");
    assert_eq!(
        injected,
        Some("server-secret"),
        "server credential should still be injected after stripping"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Parse YAML and construct a boxed [`CredentialInjectionFilter`].
fn from_yaml(yaml: &str) -> Box<dyn HttpFilter> {
    let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    CredentialInjectionFilter::from_config(&val).unwrap()
}

/// Find the last non-empty header value by name (case-insensitive).
fn find_header<'a>(headers: &'a [(std::borrow::Cow<'static, str>, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(k, v)| k.eq_ignore_ascii_case(name) && !v.is_empty())
        .map(|(_, v)| v.as_str())
}
