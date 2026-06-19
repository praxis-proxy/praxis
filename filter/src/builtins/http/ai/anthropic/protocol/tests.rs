// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the `anthropic_messages_protocol` filter.

use super::*;

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

#[test]
fn default_config_parses() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = AnthropicMessagesProtocolFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "anthropic_messages_protocol",
        "filter name should be anthropic_messages_protocol"
    );
}

#[test]
fn empty_version_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("default_version: \"\"").unwrap();
    let result = AnthropicMessagesProtocolFilter::from_config(&yaml);
    assert!(result.is_err(), "empty default_version should be rejected");
}

#[test]
fn invalid_header_value_rejected() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("default_version: \"2023-06-01\\nmalformed\"").unwrap();
    let result = AnthropicMessagesProtocolFilter::from_config(&yaml);
    assert!(
        result.is_err(),
        "invalid default_version header value should be rejected"
    );
}

// -----------------------------------------------------------------------------
// Header Injection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn injects_anthropic_version_when_absent() {
    let filter = make_filter("{}");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);

    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "filter should continue");

    let headers: std::collections::HashMap<&str, &str> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("anthropic-version"),
        Some(&"2023-06-01"),
        "should inject default anthropic-version"
    );
}

#[tokio::test]
async fn does_not_inject_when_header_present() {
    let filter = make_filter("{}");
    let mut req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
    req.headers.insert("anthropic-version", "2024-01-01".parse().unwrap());

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);

    let _action = filter.on_request(&mut ctx).await.unwrap();

    assert!(
        ctx.extra_request_headers.is_empty(),
        "should not inject when header already present"
    );
}

#[tokio::test]
async fn custom_default_version() {
    let filter = make_filter("default_version: \"2024-06-01\"");
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");

    let req: &'static crate::context::Request = Box::leak(Box::new(req));
    let mut ctx = crate::test_utils::make_filter_context(req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    let headers: std::collections::HashMap<&str, &str> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("anthropic-version"),
        Some(&"2024-06-01"),
        "should inject configured version"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a filter from a YAML snippet.
fn make_filter(yaml_str: &str) -> Box<dyn HttpFilter> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(yaml_str).unwrap();
    AnthropicMessagesProtocolFilter::from_config(&yaml).unwrap()
}
