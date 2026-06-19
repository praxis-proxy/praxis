// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the CORS filter.

use http::HeaderValue;

use super::{
    CorsFilter, VARY_ORIGIN,
    origin::{OriginPolicy, build_origin_policy},
};
use crate::{FilterAction, Rejection, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_parses_basic() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins:
  - "https://example.com"
"#,
    )
    .unwrap();
    let filter = CorsFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "cors", "basic config should parse");
}

#[test]
fn from_config_rejects_empty_origins() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("allow_origins: []").unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("must not be empty"),
        "empty origins should fail: {err}"
    );
}

#[test]
fn from_config_rejects_credentials_with_wildcard_origin() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["*"]
allow_credentials: true
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("incompatible with wildcard allow_origins"),
        "credentials + wildcard origin should fail: {err}"
    );
}

#[test]
fn from_config_rejects_credentials_with_wildcard_methods() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://example.com"]
allow_methods: ["*"]
allow_credentials: true
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("incompatible with wildcard allow_methods"),
        "credentials + wildcard methods should fail: {err}"
    );
}

#[test]
fn from_config_rejects_credentials_with_wildcard_headers() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://example.com"]
allow_headers: ["*"]
allow_credentials: true
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("incompatible with wildcard allow_headers"),
        "credentials + wildcard headers should fail: {err}"
    );
}

#[test]
fn from_config_rejects_wildcard_mixed_with_other_origins() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["*", "https://example.com"]
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("cannot be mixed"),
        "wildcard mixed with other origins should fail: {err}"
    );
}

#[test]
fn from_config_rejects_scheme_wildcard() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["*://example.com"]
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("scheme wildcard"),
        "scheme wildcard should fail: {err}"
    );
}

#[test]
fn from_config_allows_lone_wildcard() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["*"]
"#,
    )
    .unwrap();
    assert!(
        CorsFilter::from_config(&yaml).is_ok(),
        "lone wildcard should be accepted"
    );
}

#[test]
fn from_config_rejects_invalid_disallowed_mode() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://example.com"]
disallowed_origin_mode: "block"
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("cors"),
        "invalid disallowed mode should fail: {err}"
    );
}

#[test]
fn from_config_rejects_zero_max_age() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://example.com"]
max_age: 0
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("max_age must be greater than 0"),
        "zero max_age should fail: {err}"
    );
}

#[tokio::test]
async fn from_config_defaults_methods() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://example.com"]
"#,
    )
    .unwrap();
    let filter = CorsFilter::from_config(&yaml).unwrap();

    let req = make_preflight_request("https://example.com", "HEAD", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(&r, "Access-Control-Allow-Methods", "GET, HEAD, POST");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[test]
fn from_config_wildcard_subdomain_valid() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://*.example.com"]
"#,
    )
    .unwrap();
    assert!(
        CorsFilter::from_config(&yaml).is_ok(),
        "valid wildcard subdomain should parse"
    );
}

#[test]
fn from_config_wildcard_subdomain_invalid() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://foo.*.com"]
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("must be at the start"),
        "mid-host wildcard should fail: {err}"
    );
}

#[test]
fn from_config_rejects_multiple_wildcards_in_origin() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
allow_origins: ["https://*.*.example.com"]
"#,
    )
    .unwrap();
    let err = CorsFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("multiple wildcards"),
        "double wildcard should fail: {err}"
    );
}

#[test]
fn origin_policy_any_matches_all() {
    let policy = OriginPolicy::Any;
    assert!(
        policy.is_allowed("https://anything.example.com"),
        "Any policy should match any origin"
    );
}

#[test]
fn origin_policy_exact_match() {
    let policy = build_origin_policy(&["https://example.com".to_owned()]);
    assert!(policy.is_allowed("https://example.com"), "exact origin should match");
}

#[test]
fn origin_policy_exact_no_match() {
    let policy = build_origin_policy(&["https://example.com".to_owned()]);
    assert!(
        !policy.is_allowed("https://evil.com"),
        "non-listed origin should not match"
    );
}

#[test]
fn origin_policy_wildcard_subdomain_match() {
    let policy = build_origin_policy(&["https://*.example.com".to_owned()]);
    assert!(
        policy.is_allowed("https://app.example.com"),
        "wildcard subdomain should match"
    );
}

#[test]
fn origin_policy_wildcard_subdomain_no_match() {
    let policy = build_origin_policy(&["https://*.example.com".to_owned()]);
    assert!(
        !policy.is_allowed("https://example.com"),
        "bare domain should not match wildcard subdomain"
    );
    assert!(
        !policy.is_allowed("https://evil.com"),
        "unrelated domain should not match wildcard subdomain"
    );
}

#[test]
fn origin_null_rejected_by_default() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);
    assert!(
        f.resolve_origin("null").is_none(),
        "null origin should be rejected by default"
    );
}

#[test]
fn origin_null_allowed_when_opted_in() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, true, false, false);
    assert_eq!(
        f.resolve_origin("null"),
        Some("null"),
        "null origin should be allowed when opted in"
    );
}

#[test]
fn origin_null_not_matched_by_wildcard() {
    let f = make_filter(&["*"], &["GET"], &[], &[], false, false, false, false);
    assert!(
        f.resolve_origin("null").is_none(),
        "wildcard should not match null unless allow_null_origin is true"
    );
}

#[tokio::test]
async fn preflight_returns_204_with_cors_headers() {
    let f = make_filter(
        &["https://example.com"],
        &["GET", "POST"],
        &["Content-Type"],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "POST", Some("Content-Type"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "preflight should return 204");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
            assert_header(&r, "Access-Control-Allow-Methods", "GET, POST");
            assert_header(&r, "Access-Control-Allow-Headers", "Content-Type");
            assert_header(&r, "Access-Control-Max-Age", "86400");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_requires_request_method_header() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::OPTIONS, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());

    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "OPTIONS without Access-Control-Request-Method should continue to upstream"
    );
}

#[tokio::test]
async fn preflight_rejects_disallowed_method() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "DELETE", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "disallowed method should return 204 in omit mode");
            assert!(
                !has_header(&r, "Access-Control-Allow-Origin"),
                "disallowed method should not include CORS headers"
            );
        },
        _ => panic!("expected Reject for disallowed preflight method"),
    }
}

#[tokio::test]
async fn preflight_validates_request_headers() {
    let f = make_filter(
        &["https://example.com"],
        &["GET"],
        &["Content-Type"],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "GET", Some("X-Custom"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "disallowed header should return 204 in omit mode");
            assert!(
                !has_header(&r, "Access-Control-Allow-Origin"),
                "disallowed header should not include CORS headers"
            );
        },
        _ => panic!("expected Reject for disallowed preflight headers"),
    }
}

#[tokio::test]
async fn preflight_includes_max_age() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(&r, "Access-Control-Max-Age", "86400");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_includes_credentials() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], true, false, false, false);

    let req = make_preflight_request("https://example.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(&r, "Access-Control-Allow-Credentials", "true");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_private_network() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, true, false);

    let mut req = make_preflight_request("https://example.com", "GET", None);
    req.headers
        .insert("access-control-request-private-network", "true".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(&r, "Access-Control-Allow-Private-Network", "true");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_disallowed_origin_omit_mode() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://evil.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "omit mode should return 204");
            assert!(
                !has_header(&r, "Access-Control-Allow-Origin"),
                "omit mode should not include CORS headers"
            );
        },
        _ => panic!("expected Reject for disallowed preflight origin"),
    }
}

#[tokio::test]
async fn preflight_disallowed_origin_reject_mode() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, true);

    let req = make_preflight_request("https://evil.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 403, "reject mode should return 403");
        },
        _ => panic!("expected Reject for disallowed preflight origin"),
    }
}

#[tokio::test]
async fn on_response_injects_cors_headers() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    let action = f.on_response(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "on_response should continue");
    assert_eq!(
        resp.headers.get("access-control-allow-origin").unwrap(),
        "https://example.com",
        "should inject Access-Control-Allow-Origin"
    );
}

#[tokio::test]
async fn on_response_injects_vary_origin() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert_eq!(
        resp.headers.get("vary").unwrap(),
        "Origin",
        "dynamic origin list should inject Vary: Origin"
    );
}

#[tokio::test]
async fn on_response_no_vary_for_static_wildcard() {
    let f = make_filter(&["*"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://anything.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert!(
        resp.headers.get("vary").is_none(),
        "static wildcard without credentials should not add Vary: Origin"
    );
}

#[tokio::test]
async fn on_response_omits_cors_for_disallowed_origin() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert!(
        resp.headers.get("access-control-allow-origin").is_none(),
        "disallowed origin should not get ACAO header"
    );
    assert_eq!(
        resp.headers.get("vary").unwrap(),
        "Origin",
        "disallowed origin should still get Vary: Origin"
    );
}

#[tokio::test]
async fn on_response_expose_headers() {
    let f = make_filter(
        &["https://example.com"],
        &["GET"],
        &[],
        &["X-Request-ID", "X-RateLimit-Remaining"],
        false,
        false,
        false,
        false,
    );

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert_eq!(
        resp.headers.get("access-control-expose-headers").unwrap(),
        "X-Request-ID, X-RateLimit-Remaining",
        "should inject Access-Control-Expose-Headers"
    );
}

#[tokio::test]
async fn on_response_no_origin_header_adds_vary() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert_eq!(
        resp.headers.get("vary").unwrap(),
        "Origin",
        "non-CORS request should still get Vary: Origin when origin is dynamic"
    );
}

#[tokio::test]
async fn on_response_credentials_reflects_origin() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], true, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut resp = crate::test_utils::make_response();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);

    drop(f.on_response(&mut ctx).await.unwrap());
    assert_eq!(
        resp.headers.get("access-control-allow-origin").unwrap(),
        "https://example.com",
        "credentials mode should reflect exact origin, not *"
    );
    assert_eq!(
        resp.headers.get("access-control-allow-credentials").unwrap(),
        "true",
        "credentials mode should set Access-Control-Allow-Credentials"
    );
}

#[tokio::test]
async fn preflight_wildcard_methods_allows_any_method() {
    let f = make_filter(&["https://example.com"], &["*"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "PUT", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "wildcard methods preflight should return 204");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
        },
        _ => panic!("expected Reject for preflight with wildcard methods"),
    }
}

#[tokio::test]
async fn preflight_wildcard_headers_allows_any_header() {
    let f = make_filter(
        &["https://example.com"],
        &["GET"],
        &["*"],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "GET", Some("X-Arbitrary, X-Custom"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "wildcard headers preflight should return 204");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
        },
        _ => panic!("expected Reject for preflight with wildcard headers"),
    }
}

#[test]
fn multiple_exact_origins_match_and_reject() {
    let policy = build_origin_policy(&[
        "https://alpha.example.com".to_owned(),
        "https://beta.example.com".to_owned(),
    ]);
    assert!(
        policy.is_allowed("https://alpha.example.com"),
        "first origin should match"
    );
    assert!(
        policy.is_allowed("https://beta.example.com"),
        "second origin should match"
    );
    assert!(
        !policy.is_allowed("https://gamma.example.com"),
        "unlisted origin should not match"
    );
}

#[test]
fn deep_nested_subdomain_not_matched_by_wildcard() {
    let policy = build_origin_policy(&["https://*.example.com".to_owned()]);
    assert!(
        !policy.is_allowed("https://a.b.example.com"),
        "deep nested subdomain should not match single-level wildcard"
    );
}

#[tokio::test]
async fn disallowed_preflight_includes_vary() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://evil.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "omit mode should return 204");
            assert_header(
                &r,
                "Vary",
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            );
        },
        _ => panic!("expected Reject for disallowed preflight"),
    }
}

#[tokio::test]
async fn successful_preflight_vary_includes_all_fields() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(
                &r,
                "Vary",
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            );
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_empty_allow_headers_rejects_nonempty_request_headers() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "GET", Some("X-Custom"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(
                r.status, 204,
                "empty allow_headers should reject non-empty request headers"
            );
            assert!(
                !has_header(&r, "Access-Control-Allow-Origin"),
                "empty allow_headers should not allow non-empty request headers"
            );
        },
        _ => panic!("expected Reject for disallowed preflight headers"),
    }
}

#[tokio::test]
async fn preflight_empty_allow_headers_allows_empty_request_headers() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, false, false);

    let req = make_preflight_request("https://example.com", "GET", Some(""));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "empty allow_headers should accept empty request headers");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_case_insensitive_header_match() {
    let f = make_filter(
        &["https://example.com"],
        &["GET"],
        &["Content-Type"],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "GET", Some("content-type"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "case-insensitive header match should succeed");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_case_sensitive_method_match() {
    let f = make_filter(
        &["https://example.com"],
        &["POST"],
        &[],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "POST", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "exact method match should succeed");
            assert_header(&r, "Access-Control-Allow-Origin", "https://example.com");
        },
        _ => panic!("expected Reject for preflight"),
    }
}

#[tokio::test]
async fn preflight_case_mismatch_method_rejected() {
    let f = make_filter(
        &["https://example.com"],
        &["post"],
        &[],
        &[],
        false,
        false,
        false,
        false,
    );

    let req = make_preflight_request("https://example.com", "POST", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(
                r.status, 204,
                "case mismatch should be rejected (methods are case-sensitive per RFC 9110)"
            );
            assert!(
                !has_header(&r, "Access-Control-Allow-Origin"),
                "case-mismatched method should not include CORS headers"
            );
        },
        _ => panic!("expected Reject for disallowed preflight method"),
    }
}

#[test]
fn wildcard_does_not_cross_scheme_boundary() {
    let policy = build_origin_policy(&["https://*.example.com".to_owned()]);
    assert!(
        !policy.is_allowed("https://sub.example.org"),
        "wildcard *.example.com should not match example.org"
    );
    assert!(
        !policy.is_allowed("http://sub.example.com"),
        "wildcard https://*.example.com should not match http scheme"
    );
}

#[test]
fn origin_with_port_matches_exact() {
    let policy = build_origin_policy(&["https://example.com:8080".to_owned()]);
    assert!(
        policy.is_allowed("https://example.com:8080"),
        "exact origin with port should match"
    );
    assert!(
        !policy.is_allowed("https://example.com"),
        "origin without port should not match origin with port"
    );
    assert!(
        !policy.is_allowed("https://example.com:9090"),
        "origin with different port should not match"
    );
}

#[tokio::test]
async fn pna_vary_includes_private_network_field() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, true, false);

    let mut req = make_preflight_request("https://example.com", "GET", None);
    req.headers
        .insert("access-control-request-private-network", "true".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_header(
                &r,
                "Vary",
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
            );
        },
        _ => panic!("expected Reject for PNA preflight"),
    }
}

#[tokio::test]
async fn disallowed_preflight_with_pna_includes_private_network_in_vary() {
    let f = make_filter(&["https://example.com"], &["GET"], &[], &[], false, false, true, false);

    let req = make_preflight_request("https://evil.com", "GET", None);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(r.status, 204, "omit mode should return 204");
            assert_header(
                &r,
                "Vary",
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network",
            );
        },
        _ => panic!("expected Reject for disallowed PNA preflight"),
    }
}

#[test]
fn origin_policy_case_insensitive_match() {
    let policy = build_origin_policy(&["https://example.com".to_owned()]);
    assert!(
        policy.is_allowed("HTTPS://EXAMPLE.COM"),
        "case-insensitive origin should match"
    );
    assert!(
        policy.is_allowed("Https://Example.Com"),
        "mixed-case origin should match"
    );
}

#[test]
fn origin_policy_default_port_normalization() {
    let policy = build_origin_policy(&["https://example.com".to_owned()]);
    assert!(
        policy.is_allowed("https://example.com:443"),
        "https with :443 should match without port"
    );

    let policy_http = build_origin_policy(&["http://example.com".to_owned()]);
    assert!(
        policy_http.is_allowed("http://example.com:80"),
        "http with :80 should match without port"
    );
}

#[test]
fn origin_policy_configured_with_default_port_matches_without() {
    let policy = build_origin_policy(&["https://example.com:443".to_owned()]);
    assert!(
        policy.is_allowed("https://example.com"),
        "configured :443 should match request without port"
    );
}

#[test]
fn origin_policy_wildcard_case_insensitive() {
    let policy = build_origin_policy(&["https://*.example.com".to_owned()]);
    assert!(
        policy.is_allowed("HTTPS://APP.EXAMPLE.COM"),
        "wildcard should match case-insensitive subdomain"
    );
}

#[test]
fn origin_policy_websocket_scheme_normalization() {
    let policy = build_origin_policy(&["https://example.com".to_owned()]);
    assert!(
        policy.is_allowed("wss://example.com"),
        "wss should normalize to https and match"
    );

    let policy_http = build_origin_policy(&["http://example.com".to_owned()]);
    assert!(
        policy_http.is_allowed("ws://example.com"),
        "ws should normalize to http and match"
    );
}

#[tokio::test]
async fn non_utf8_origin_rejected_with_400() {
    let f = make_filter(&["*"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers
        .insert("origin", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(
                r.status, 400,
                "non-UTF-8 Origin should be rejected with 400 (valid Origin is always ASCII)"
            );
        },
        _ => panic!("expected Reject for non-UTF-8 Origin"),
    }
}

#[tokio::test]
async fn non_utf8_origin_preflight_rejected_with_400() {
    let f = make_filter(&["*"], &["GET"], &[], &[], false, false, false, false);

    let mut req = crate::test_utils::make_request(http::Method::OPTIONS, "/");
    req.headers
        .insert("origin", HeaderValue::from_bytes(&[0x80, 0xFF]).unwrap());
    req.headers
        .insert("access-control-request-method", "GET".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = f.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(r) => {
            assert_eq!(
                r.status, 400,
                "preflight with non-UTF-8 Origin should be rejected with 400"
            );
        },
        _ => panic!("expected Reject for non-UTF-8 Origin on preflight"),
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

#[expect(clippy::too_many_arguments, reason = "exhaustive test config")]
fn make_filter(
    origins: &[&str],
    methods: &[&str],
    headers: &[&str],
    expose: &[&str],
    credentials: bool,
    allow_null: bool,
    private_network: bool,
    reject_mode: bool,
) -> CorsFilter {
    let origin_strings: Vec<String> = origins.iter().map(|s| (*s).to_owned()).collect();
    let policy = build_origin_policy(&origin_strings);
    CorsFilter {
        policy,
        allow_credentials: credentials,
        allow_null_origin: allow_null,
        allow_private_network: private_network,
        reject_mode,
        methods_header: if methods.is_empty() {
            "GET, HEAD, POST".to_owned()
        } else {
            methods.join(", ")
        },
        headers_header: headers.join(", "),
        expose_header: expose.join(", "),
        max_age_header: "86400".to_owned(),
        vary_origin: HeaderValue::from_static(VARY_ORIGIN),
    }
}

fn make_preflight_request(origin: &str, method: &str, request_headers: Option<&str>) -> crate::context::Request {
    let mut req = crate::test_utils::make_request(http::Method::OPTIONS, "/");
    req.headers.insert("origin", origin.parse().unwrap());
    req.headers
        .insert("access-control-request-method", method.parse().unwrap());
    if let Some(h) = request_headers {
        req.headers.insert("access-control-request-headers", h.parse().unwrap());
    }
    req
}

fn find_header<'a>(r: &'a Rejection, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn assert_header(r: &Rejection, name: &str, expected: &str) {
    let value = find_header(r, name);
    assert_eq!(value, Some(expected), "header {name} should be \"{expected}\"");
}

fn has_header(r: &Rejection, name: &str) -> bool {
    find_header(r, name).is_some()
}
