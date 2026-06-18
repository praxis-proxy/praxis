// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the path rewrite filter.

use std::borrow::Cow;

use http::Method;
use regex::Regex;

use super::{
    PathRewriteFilter,
    config::PathRewriteConfig,
    ops::{PathRewriteOp, add_prefix, append_query, build_op, rewrite_path, strip_prefix},
};
use crate::{FilterAction, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn strip_prefix_removes_matching_prefix() {
    let filter = make_filter("strip_prefix: \"/api/v1\"");
    let req = crate::test_utils::make_request(Method::GET, "/api/v1/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "should return Continue");
    assert_eq!(ctx.rewritten_path.as_deref(), Some("/users"), "should strip the prefix");
}

#[tokio::test]
async fn strip_prefix_exact_match_yields_root() {
    let filter = make_filter("strip_prefix: \"/api\"");
    let req = crate::test_utils::make_request(Method::GET, "/api");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/"),
        "stripping entire path should yield root"
    );
}

#[tokio::test]
async fn strip_prefix_no_match_leaves_path_unchanged() {
    let filter = make_filter("strip_prefix: \"/api/v1\"");
    let req = crate::test_utils::make_request(Method::GET, "/other/path");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert!(ctx.rewritten_path.is_none(), "non-matching prefix should not rewrite");
}

#[tokio::test]
async fn strip_prefix_preserves_query_string() {
    let filter = make_filter("strip_prefix: \"/api\"");
    let req = crate::test_utils::make_request(Method::GET, "/api/users?page=2&limit=10");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/users?page=2&limit=10"),
        "query string should be preserved"
    );
}

#[tokio::test]
async fn add_prefix_prepends_to_path() {
    let filter = make_filter("add_prefix: \"/api/v2\"");
    let req = crate::test_utils::make_request(Method::GET, "/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/api/v2/users"),
        "should prepend the prefix"
    );
}

#[tokio::test]
async fn add_prefix_avoids_double_slash() {
    let filter = make_filter("add_prefix: \"/api/v2/\"");
    let req = crate::test_utils::make_request(Method::GET, "/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/api/v2/users"),
        "trailing slash on prefix should not cause double slash"
    );
}

#[tokio::test]
async fn add_prefix_preserves_query_string() {
    let filter = make_filter("add_prefix: \"/v2\"");
    let req = crate::test_utils::make_request(Method::GET, "/items?sort=name");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/v2/items?sort=name"),
        "query string should be preserved when adding prefix"
    );
}

#[tokio::test]
async fn replace_rewrites_with_regex() {
    let filter = make_filter("replace:\n  pattern: \"^/old/(.*)\"\n  replacement: \"/new/$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/old/resource/42");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/new/resource/42"),
        "regex replacement should rewrite path"
    );
}

#[tokio::test]
async fn replace_no_match_leaves_path_unchanged() {
    let filter = make_filter("replace:\n  pattern: \"^/old/(.*)\"\n  replacement: \"/new/$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/other/path");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert!(ctx.rewritten_path.is_none(), "non-matching regex should not rewrite");
}

#[tokio::test]
async fn replace_preserves_query_string() {
    let filter = make_filter("replace:\n  pattern: \"^/v1/(.*)\"\n  replacement: \"/v2/$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/v1/data?key=val");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/v2/data?key=val"),
        "query string should be preserved with regex replace"
    );
}

#[test]
fn from_config_rejects_no_operation() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let err = PathRewriteFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("exactly one"),
        "should reject config with no operation: {err}"
    );
}

#[test]
fn from_config_rejects_multiple_operations() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("strip_prefix: \"/a\"\nadd_prefix: \"/b\"").unwrap();
    let err = PathRewriteFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("only one"),
        "should reject config with multiple operations: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_regex() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("replace:\n  pattern: \"[invalid\"\n  replacement: \"x\"").unwrap();
    let err = PathRewriteFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("invalid regex"),
        "should reject invalid regex: {err}"
    );
}

#[test]
fn strip_prefix_root_path() {
    let result = strip_prefix("/", "/");
    assert_eq!(result, "/", "stripping root from root should yield root");
}

#[test]
fn strip_prefix_non_segment_boundary_leaves_path_unchanged() {
    let result = strip_prefix("/api/v1foo", "/api/v1");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "non-boundary match should return borrowed"
    );
    assert_eq!(&*result, "/api/v1foo", "non-boundary prefix should not strip");
}

#[test]
fn add_prefix_to_root() {
    let result = add_prefix("/", "/api");
    assert_eq!(result, "/api/", "adding prefix to root should work");
}

#[test]
fn append_query_with_none() {
    let result = append_query("/path", None);
    assert_eq!(result, "/path", "no query should return path only");
}

#[test]
fn append_query_with_value() {
    let result = append_query("/path", Some("a=1"));
    assert_eq!(result, "/path?a=1", "query should be appended");
}

#[test]
fn filter_name_is_path_rewrite() {
    let filter = make_filter("strip_prefix: \"/x\"");
    assert_eq!(filter.name(), "path_rewrite");
}

#[test]
fn strip_prefix_at_segment_boundary() {
    let result = strip_prefix("/api/users", "/api");
    assert_eq!(&*result, "/users", "should strip prefix at segment boundary");
    assert!(matches!(result, Cow::Owned(_)), "rewrite should allocate");
}

#[test]
fn strip_prefix_not_at_segment_boundary() {
    let result = strip_prefix("/api-gateway/resource", "/api");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "non-boundary should return borrowed"
    );
    assert_eq!(
        &*result, "/api-gateway/resource",
        "non-boundary prefix should leave path unchanged"
    );
}

#[tokio::test]
async fn strip_prefix_not_at_segment_boundary_via_filter() {
    let filter = make_filter("strip_prefix: \"/api\"");
    let req = crate::test_utils::make_request(Method::GET, "/api-gateway/resource");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert!(ctx.rewritten_path.is_none(), "non-boundary prefix should not rewrite");
}

#[tokio::test]
async fn rewrite_normalizes_dot_dot_traversal() {
    let filter = make_filter("replace:\n  pattern: \"^/api/(.*)\"\n  replacement: \"/internal/$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/api/../etc/passwd");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/etc/passwd"),
        "/../ traversal should be normalized after rewrite"
    );
}

#[tokio::test]
async fn rewrite_normalizes_dot_segments() {
    let filter = make_filter("replace:\n  pattern: \"^/app/(.*)\"\n  replacement: \"/svc/$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/app/./config");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/svc/config"),
        "/./ segments should be normalized after rewrite"
    );
}

#[tokio::test]
async fn rewrite_normalizes_double_slashes() {
    let filter = make_filter("replace:\n  pattern: \"^/api/(.*)\"\n  replacement: \"/v2//$1\"");
    let req = crate::test_utils::make_request(Method::GET, "/api/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/v2/data"),
        "double slashes introduced by rewrite should be collapsed"
    );
}

#[tokio::test]
async fn add_prefix_normalizes_traversal_in_result() {
    let filter = make_filter("add_prefix: \"/base\"");
    let req = crate::test_utils::make_request(Method::GET, "/../etc/passwd");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    let rewritten = ctx.rewritten_path.as_deref().expect("should rewrite");
    assert!(
        !rewritten.contains(".."),
        "traversal in add_prefix result should be normalized: {rewritten}"
    );
}

#[test]
fn add_prefix_to_path_without_leading_slash() {
    let result = add_prefix("users", "/api");
    assert_eq!(&*result, "/api/users", "should insert slash between prefix and path");
}

#[test]
fn regex_with_named_capture_groups() {
    let pattern = Regex::new(r"^/(?P<version>v\d+)/(?P<resource>.+)$").unwrap();
    let op = PathRewriteOp::Replace {
        pattern,
        replacement: "/api/$version/$resource".to_owned(),
    };
    let result = rewrite_path(&op, "/v2/items");
    assert_eq!(&*result, "/api/v2/items", "named captures should expand");
}

#[test]
fn regex_producing_empty_path_yields_root() {
    let pattern = Regex::new(r"^/remove-me$").unwrap();
    let op = PathRewriteOp::Replace {
        pattern,
        replacement: String::new(),
    };
    let result = rewrite_path(&op, "/remove-me");
    assert_eq!(&*result, "", "regex can produce empty path");
}

#[tokio::test]
async fn regex_producing_empty_path_sets_root_via_filter() {
    let filter = make_filter("replace:\n  pattern: \"^/remove-me$\"\n  replacement: \"/\"");
    let req = crate::test_utils::make_request(Method::GET, "/remove-me");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert_eq!(
        ctx.rewritten_path.as_deref(),
        Some("/"),
        "empty regex result should produce root"
    );
}

#[tokio::test]
async fn strip_prefix_with_query_no_match() {
    let filter = make_filter("strip_prefix: \"/missing\"");
    let req = crate::test_utils::make_request(Method::GET, "/other/path?key=val");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(filter.on_request(&mut ctx).await.unwrap());

    assert!(
        ctx.rewritten_path.is_none(),
        "non-matching prefix with query string should not rewrite"
    );
}

#[test]
fn strip_prefix_returns_borrowed_on_no_match() {
    let result = strip_prefix("/other/path", "/api");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "no-match should return borrowed (no allocation)"
    );
}

#[test]
fn add_prefix_returns_owned() {
    let result = add_prefix("/users", "/api");
    assert!(matches!(result, Cow::Owned(_)), "add_prefix always allocates");
}

#[test]
fn regex_no_match_returns_borrowed() {
    let pattern = Regex::new(r"^/old/(.*)").unwrap();
    let op = PathRewriteOp::Replace {
        pattern,
        replacement: "/new/$1".to_owned(),
    };
    let result = rewrite_path(&op, "/other/path");
    assert!(
        matches!(result, Cow::Borrowed(_)),
        "regex no-match should return borrowed (no allocation)"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`PathRewriteFilter`] from a YAML string for testing.
fn make_filter(yaml: &str) -> PathRewriteFilter {
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    let cfg: PathRewriteConfig = serde_yaml::from_value(config).unwrap();
    let op = build_op(cfg.into_operation().unwrap()).unwrap();
    PathRewriteFilter { op }
}
