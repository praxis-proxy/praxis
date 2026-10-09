// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the head classifier filter.

use super::HeadClassifierFilter;
use crate::{
    FilterAction, TrustedHeaderMutation,
    test_utils::{make_filter_context, make_request},
};

/// Parse a YAML snippet into a filter, panicking on error.
fn build(yaml: &str) -> Box<dyn crate::filter::HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    HeadClassifierFilter::from_config(&value).unwrap()
}

/// Return the value of the first `x-praxis-head-class` set mutation, if any.
fn promoted_class(ctx: &crate::filter::HttpFilterContext<'_>) -> Option<String> {
    ctx.pre_read_mutations.iter().find_map(|mutation| match mutation {
        TrustedHeaderMutation::Set(name, value) if name.as_str() == "x-praxis-head-class" => {
            Some(value.to_str().unwrap().to_owned())
        },
        _ => None,
    })
}

const RULES: &str = "rules:\n  - path_prefix: /api/\n    class: api\n  - path_prefix: /assets/\n    class: assets\n";

#[test]
fn from_config_succeeds() {
    let filter = build(&format!("{RULES}default_class: other\n"));
    assert_eq!(filter.name(), "head_classifier", "name should be head_classifier");
    assert!(
        filter.runs_request_head(),
        "filter must opt into the request-head phase"
    );
}

#[test]
fn from_config_rejects_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!("{RULES}bogus: true\n")).unwrap();
    assert!(
        HeadClassifierFilter::from_config(&yaml).is_err(),
        "unknown fields should be rejected"
    );
}

#[test]
fn from_config_rejects_empty_path_prefix() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("rules:\n  - path_prefix: ''\n    class: api\n").unwrap();
    assert!(
        HeadClassifierFilter::from_config(&yaml).is_err(),
        "empty path_prefix should be rejected"
    );
}

#[test]
fn from_config_rejects_unsafe_class() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("rules:\n  - path_prefix: /api/\n    class: \"a\\nb\"\n").unwrap();
    assert!(
        HeadClassifierFilter::from_config(&yaml).is_err(),
        "class with control bytes should be rejected"
    );
}

#[tokio::test]
async fn matched_rule_promotes_class() {
    let req = make_request(http::Method::GET, "/api/users");
    let mut ctx = make_filter_context(&req);
    let filter = build(&format!("{RULES}default_class: other\n"));
    let action = filter
        .on_request_head(&mut ctx)
        .await
        .expect("head phase should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        promoted_class(&ctx).as_deref(),
        Some("api"),
        "should promote the api class"
    );
    assert_eq!(ctx.get_metadata("head_classifier.class"), Some("api"), "metadata set");
    assert_eq!(
        ctx.filter_results.get("head_classifier").unwrap().get("class").unwrap(),
        "api",
        "filter result class should be api"
    );
}

#[tokio::test]
async fn default_class_used_when_no_rule_matches() {
    let req = make_request(http::Method::GET, "/home");
    let mut ctx = make_filter_context(&req);
    let filter = build(&format!("{RULES}default_class: other\n"));
    let _action = filter
        .on_request_head(&mut ctx)
        .await
        .expect("head phase should not error");
    assert_eq!(
        promoted_class(&ctx).as_deref(),
        Some("other"),
        "should fall back to default"
    );
}

#[tokio::test]
async fn no_class_without_match_or_default() {
    let req = make_request(http::Method::GET, "/home");
    let mut ctx = make_filter_context(&req);
    let filter = build(RULES);
    let action = filter
        .on_request_head(&mut ctx)
        .await
        .expect("head phase should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue unclassified");
    assert!(promoted_class(&ctx).is_none(), "no header should be promoted");
    assert!(
        ctx.get_metadata("head_classifier.class").is_none(),
        "no metadata should be set"
    );
}

#[tokio::test]
async fn on_request_is_a_noop() {
    let req = make_request(http::Method::GET, "/api/users");
    let mut ctx = make_filter_context(&req);
    let filter = build(&format!("{RULES}default_class: other\n"));
    let action = filter
        .on_request(&mut ctx)
        .await
        .expect("request phase should not error");
    assert!(matches!(action, FilterAction::Continue), "on_request is a no-op");
    assert!(promoted_class(&ctx).is_none(), "on_request must not promote anything");
}
