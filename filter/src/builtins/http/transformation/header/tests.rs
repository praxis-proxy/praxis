// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the header manipulation filter.

use super::{
    HeaderFilter, HeaderFilterConfig,
    ops::{append_headers, remove_headers, set_headers},
};
use crate::filter::HttpFilter as _;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn request_add_populates_extra_headers() {
    let filter = make_header_filter(
        r#"request_add:
  - name: X-Forwarded-By
    value: praxis"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "should add exactly one request header"
    );
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "X-Forwarded-By", "header name should match");
    assert_eq!(value, "praxis", "header value should match");
}

#[tokio::test]
async fn response_set_overwrites_header() {
    let filter = make_header_filter(
        r#"response_set:
  - name: server
    value: praxis"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut resp = crate::test_utils::make_response();
    resp.headers.insert("server", "nginx".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());
    assert_eq!(
        resp.headers["server"], "praxis",
        "response_set should overwrite existing header"
    );
}

#[tokio::test]
async fn response_remove_deletes_header() {
    let filter = make_header_filter(
        r#"response_remove:
  - x-backend-server"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut resp = crate::test_utils::make_response();
    resp.headers.insert("x-backend-server", "internal".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());
    assert!(
        !resp.headers.contains_key("x-backend-server"),
        "response_remove should delete header"
    );
}

#[tokio::test]
async fn response_add_appends_without_overwriting() {
    let filter = make_header_filter(
        r#"response_add:
  - name: x-custom
    value: second"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut resp = crate::test_utils::make_response();
    resp.headers.insert("x-custom", "first".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    drop(filter.on_response(&mut ctx).await.unwrap());
    let values: Vec<&str> = resp
        .headers
        .get_all("x-custom")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(
        values,
        vec!["first", "second"],
        "response_add should append without overwriting"
    );
}

#[tokio::test]
async fn from_config_empty_is_noop() {
    let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let filter = HeaderFilter::from_config(&config).unwrap();
    assert_eq!(filter.name(), "headers", "empty config should produce valid filter");
}

#[test]
fn from_config_rejects_invalid_header_name_in_response_add() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
response_add:
  - name: "invalid header"
    value: "value"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid header name at config time: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_header_value() {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("response_add:\n  - name: x-good-name\n    value: \"bad\\x00value\"\n").unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header value"),
        "should reject invalid header value at config time: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_set_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
response_set:
  - name: "bad name!"
    value: "value"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid set header name at config time: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_request_add_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
request_add:
  - name: "bad name"
    value: "value"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid request_add header name at config time: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_response_remove_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
response_remove:
  - "bad name!"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid response_remove header name at config time: {err}"
    );
}

#[test]
fn remove_headers_idempotent() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-remove", "val".parse().unwrap());
    let names = vec![hdr_name("x-remove")];
    remove_headers(&mut headers, &names);
    remove_headers(&mut headers, &names);
    assert!(!headers.contains_key("x-remove"), "double removal should be idempotent");
}

#[test]
fn remove_headers_missing_is_noop() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-keep", "val".parse().unwrap());
    remove_headers(&mut headers, &[hdr_name("x-absent")]);
    assert_eq!(
        headers.len(),
        1,
        "removing absent header should not affect existing ones"
    );
    assert_eq!(headers["x-keep"], "val", "existing header should remain");
}

#[test]
fn append_headers_preserves_existing() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-existing", "first".parse().unwrap());
    append_headers(&mut headers, &[hdr_pair("x-existing", "second")]);
    let values: Vec<&str> = headers
        .get_all("x-existing")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(
        values,
        vec!["first", "second"],
        "append should preserve existing and add new"
    );
}

#[test]
fn append_headers_to_empty_map() {
    let mut headers = http::HeaderMap::new();
    append_headers(&mut headers, &[hdr_pair("x-new", "value")]);
    assert_eq!(headers["x-new"], "value", "append to empty map should work");
}

#[test]
fn set_headers_overwrites_existing() {
    let mut headers = http::HeaderMap::new();
    headers.insert("server", "nginx".parse().unwrap());
    set_headers(&mut headers, &[hdr_pair("server", "praxis")]);
    assert_eq!(headers["server"], "praxis", "set should overwrite existing value");
    assert_eq!(
        headers.get_all("server").iter().count(),
        1,
        "set should result in exactly one value"
    );
}

#[test]
fn set_headers_creates_new() {
    let mut headers = http::HeaderMap::new();
    set_headers(&mut headers, &[hdr_pair("x-new", "value")]);
    assert_eq!(headers["x-new"], "value", "set should create header when absent");
}

#[test]
fn remove_headers_empty_list_is_noop() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-keep", "val".parse().unwrap());
    remove_headers(&mut headers, &[]);
    assert_eq!(headers.len(), 1, "empty remove list should not affect headers");
}


#[tokio::test]
async fn request_set_populates_headers_to_set() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-custom
    value: overwritten"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.request_headers_to_set.len(),
        1,
        "should queue exactly one header set operation"
    );
    let (name, value) = &ctx.request_headers_to_set[0];
    assert_eq!(name.as_str(), "x-custom", "set header name should match");
    assert_eq!(value.to_str().unwrap(), "overwritten", "set header value should match");
}

#[tokio::test]
async fn request_remove_populates_headers_to_remove() {
    let filter = make_header_filter(
        r#"request_remove:
  - x-internal"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.request_headers_to_remove.len(),
        1,
        "should queue exactly one header remove operation"
    );
    assert_eq!(
        ctx.request_headers_to_remove[0].as_str(),
        "x-internal",
        "remove header name should match"
    );
}

#[tokio::test]
async fn request_set_and_remove_combined() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-replaced
    value: new-value
request_remove:
  - x-unwanted"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(ctx.request_headers_to_remove.len(), 1, "should queue one remove");
    assert_eq!(ctx.request_headers_to_set.len(), 1, "should queue one set");
    assert_eq!(
        ctx.request_headers_to_remove[0].as_str(),
        "x-unwanted",
        "remove target should be x-unwanted"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].0.as_str(),
        "x-replaced",
        "set target should be x-replaced"
    );
}

#[tokio::test]
async fn request_set_and_add_combined() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-mode
    value: override
request_add:
  - name: x-extra
    value: appended"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(ctx.request_headers_to_set.len(), 1, "should queue one set");
    assert_eq!(ctx.extra_request_headers.len(), 1, "should queue one add");
}

#[tokio::test]
async fn request_remove_nonexistent_continues() {
    let filter = make_header_filter(
        r#"request_remove:
  - x-nonexistent"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, crate::FilterAction::Continue),
        "removing nonexistent header should still continue"
    );
    assert_eq!(
        ctx.request_headers_to_remove.len(),
        1,
        "removal should still be queued for the protocol layer"
    );
}

#[test]
fn from_config_rejects_invalid_request_set_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
request_set:
  - name: "bad name!"
    value: "value"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid request_set header name: {err}"
    );
}

#[test]
fn from_config_rejects_invalid_request_remove_header_name() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
request_remove:
  - "bad name!"
"#,
    )
    .unwrap();
    let err = expect_config_err(&yaml);
    assert!(
        err.contains("invalid header name"),
        "should reject invalid request_remove header name: {err}"
    );
}

#[tokio::test]
async fn request_set_multiple_headers() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-first
    value: one
  - name: x-second
    value: two"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(ctx.request_headers_to_set.len(), 2, "should queue two set operations");
}

#[tokio::test]
async fn request_remove_multiple_headers() {
    let filter = make_header_filter(
        r#"request_remove:
  - x-first
  - x-second"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.request_headers_to_remove.len(),
        2,
        "should queue two remove operations"
    );
}

#[tokio::test]
async fn request_all_operations_combined() {
    let filter = make_header_filter(
        r#"request_add:
  - name: x-added
    value: new
request_set:
  - name: x-set
    value: overridden
request_remove:
  - x-removed"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(ctx.extra_request_headers.len(), 1, "should add one header");
    assert_eq!(ctx.request_headers_to_set.len(), 1, "should set one header");
    assert_eq!(ctx.request_headers_to_remove.len(), 1, "should remove one header");
}

#[tokio::test]
async fn request_set_empty_value() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-empty
    value: """#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(ctx.request_headers_to_set.len(), 1, "should accept empty header value");
    assert_eq!(
        ctx.request_headers_to_set[0].1.to_str().unwrap(),
        "",
        "empty value should be preserved"
    );
}

#[tokio::test]
async fn from_config_empty_accepts_request_set_and_remove() {
    let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let filter = HeaderFilter::from_config(&config).unwrap();
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert!(
        ctx.request_headers_to_set.is_empty(),
        "empty config should produce no set ops"
    );
    assert!(
        ctx.request_headers_to_remove.is_empty(),
        "empty config should produce no remove ops"
    );
}

#[tokio::test]
async fn request_add_stacks_with_existing_header() {
    let filter = make_header_filter(
        r#"request_add:
  - name: x-trace-id
    value: hop-2"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-trace-id", http::HeaderValue::from_static("hop-1"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert!(
        ctx.extra_request_headers.is_empty(),
        "stacking should use request_headers_to_set, not extra_request_headers"
    );
    assert_eq!(
        ctx.request_headers_to_set.len(),
        1,
        "should produce exactly one set operation for the combined value"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].0.as_str(),
        "x-trace-id",
        "set header name should match"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].1.to_str().unwrap(),
        "hop-1,hop-2",
        "stacked value should be existing,new with comma separator"
    );
}

#[tokio::test]
async fn request_add_stacks_existing_but_not_fresh() {
    let filter = make_header_filter(
        r#"request_add:
  - name: x-existing
    value: appended
  - name: x-fresh
    value: brand-new"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-existing", http::HeaderValue::from_static("original"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.request_headers_to_set.len(),
        1,
        "only the stacked header should be in request_headers_to_set"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].1.to_str().unwrap(),
        "original,appended",
        "existing header should be comma-combined"
    );
}

#[tokio::test]
async fn request_add_fresh_header_uses_extra_headers() {
    let filter = make_header_filter(
        r#"request_add:
  - name: x-fresh
    value: brand-new"#,
    );
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert!(
        ctx.request_headers_to_set.is_empty(),
        "non-existing header should not stack"
    );
    assert_eq!(ctx.extra_request_headers.len(), 1, "should go to extra_request_headers");
    assert_eq!(ctx.extra_request_headers[0].0, "x-fresh", "header name should match");
    assert_eq!(ctx.extra_request_headers[0].1, "brand-new", "header value should match");
}

#[tokio::test]
async fn request_add_non_visible_ascii_existing_falls_back() {
    let filter = make_header_filter(
        r#"request_add:
  - name: x-opaque
    value: appended"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("x-opaque", http::HeaderValue::from_bytes(b"\x80\x81binary").unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert!(
        ctx.request_headers_to_set.is_empty(),
        "non-visible-ASCII existing value should prevent stacking"
    );
    assert_eq!(
        ctx.extra_request_headers.len(),
        1,
        "should fall back to extra_request_headers when existing value is not valid str"
    );
}

#[tokio::test]
async fn request_add_set_order_preserved_with_stacking() {
    let filter = make_header_filter(
        r#"request_set:
  - name: x-mode
    value: override
request_add:
  - name: x-trace
    value: second"#,
    );
    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("x-trace", http::HeaderValue::from_static("first"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(filter.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.request_headers_to_set.len(),
        2,
        "should have one set and one stacked add"
    );
    assert_eq!(
        ctx.request_headers_to_set[0].0.as_str(),
        "x-mode",
        "set operation should come first (set runs before add)"
    );
    assert_eq!(
        ctx.request_headers_to_set[1].1.to_str().unwrap(),
        "first,second",
        "stacked add should come second with combined value"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`HeaderFilter`] from a YAML string for testing.
fn make_header_filter(yaml: &str) -> HeaderFilter {
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    drop(HeaderFilter::from_config(&config).unwrap());
    let cfg: HeaderFilterConfig = serde_yaml::from_value(config).unwrap();
    HeaderFilter {
        request_add: cfg.request_add.into_iter().map(|p| (p.name, p.value)).collect(),
        request_remove: cfg.request_remove.into_iter().map(|n| hdr_name(&n)).collect(),
        request_set: cfg
            .request_set
            .into_iter()
            .map(|p| hdr_pair(&p.name, &p.value))
            .collect(),
        response_add: cfg
            .response_add
            .into_iter()
            .map(|p| hdr_pair(&p.name, &p.value))
            .collect(),
        response_remove: cfg.response_remove.into_iter().map(|n| hdr_name(&n)).collect(),
        response_set: cfg
            .response_set
            .into_iter()
            .map(|p| hdr_pair(&p.name, &p.value))
            .collect(),
    }
}

/// Call `from_config` and assert it returns an error, returning the error string.
fn expect_config_err(yaml: &serde_yaml::Value) -> String {
    match HeaderFilter::from_config(yaml) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected from_config to return an error"),
    }
}

/// Parse a header name string for tests.
fn hdr_name(name: &str) -> http::header::HeaderName {
    http::header::HeaderName::from_bytes(name.as_bytes()).unwrap()
}

/// Parse a header name/value pair for tests.
fn hdr_pair(name: &str, value: &str) -> (http::header::HeaderName, http::header::HeaderValue) {
    (
        http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
        http::header::HeaderValue::from_str(value).unwrap(),
    )
}
