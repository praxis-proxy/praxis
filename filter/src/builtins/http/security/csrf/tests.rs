// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the CSRF filter.

use praxis_core::config::InsecureOptions;

use super::{
    CsrfFilter,
    origin::{build_trusted_origins, extract_origin},
};
use crate::{FilterAction, filter::HttpFilter as _};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_parses_basic() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins:
  - "https://example.com"
"#,
    )
    .unwrap();
    let filter = CsrfFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "csrf", "basic config should parse");
}

#[test]
fn from_config_rejects_empty_origins() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("trusted_origins: []").unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("must not be empty"),
        "empty origins should fail: {err}"
    );
}

#[test]
fn from_config_rejects_percentage_over_100() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://example.com"]
enforce_percentage: 101
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("enforce_percentage"),
        "percentage > 100 should fail: {err}"
    );
}

#[test]
fn from_config_rejects_origin_without_scheme() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["example.com"]
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("must include scheme"),
        "origin without scheme should fail: {err}"
    );
}

#[test]
fn from_config_accepts_wildcard_subdomain() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://*.example.com"]
"#,
    )
    .unwrap();
    assert!(
        CsrfFilter::from_config(&yaml).is_ok(),
        "valid wildcard subdomain should parse"
    );
}

#[test]
fn from_config_rejects_invalid_wildcard() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://foo.*.com"]
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("must be at the start"),
        "mid-host wildcard should fail: {err}"
    );
}

#[test]
fn from_config_rejects_wildcard_mixed_with_other_origins() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["*", "https://example.com"]
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("cannot be mixed"),
        "wildcard mixed with other origins should fail: {err}"
    );
}

#[test]
fn from_config_rejects_scheme_wildcard() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["*://example.com"]
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("scheme wildcard"),
        "scheme wildcard should fail: {err}"
    );
}

#[test]
fn from_config_rejects_multiple_wildcards() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://*.*.example.com"]
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("multiple wildcards"),
        "multiple wildcards should fail: {err}"
    );
}

#[test]
fn websocket_scheme_normalized_to_https() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(
        origins.is_trusted("wss://example.com"),
        "wss:// origin should match https:// trusted origin"
    );
}

#[test]
fn websocket_scheme_normalized_to_http() {
    let origins = build_trusted_origins(&["http://example.com".to_owned()]);
    assert!(
        origins.is_trusted("ws://example.com"),
        "ws:// origin should match http:// trusted origin"
    );
}

#[test]
fn websocket_scheme_with_default_port_normalized() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(
        origins.is_trusted("wss://example.com:443"),
        "wss:// with :443 should match https:// trusted origin"
    );
}

#[test]
fn from_config_rejects_empty_safe_methods() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://example.com"]
safe_methods: []
"#,
    )
    .unwrap();
    let err = CsrfFilter::from_config(&yaml).err().unwrap();
    assert!(
        err.to_string().contains("safe_methods must not be empty"),
        "empty safe_methods should fail: {err}"
    );
}

#[test]
fn from_config_accepts_zero_enforcement() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://example.com"]
enforce_percentage: 0
"#,
    )
    .unwrap();
    assert!(CsrfFilter::from_config(&yaml).is_ok(), "0% enforcement should parse");
}

#[test]
fn trusted_origins_any_matches_all() {
    let origins = build_trusted_origins(&["*".to_owned()]);
    assert!(
        origins.is_trusted("https://anything.example.com"),
        "Any policy should match any origin"
    );
}

#[test]
fn trusted_origins_exact_match() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(origins.is_trusted("https://example.com"), "exact origin should match");
}

#[test]
fn trusted_origins_exact_no_match() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(
        !origins.is_trusted("https://evil.com"),
        "non-listed origin should not match"
    );
}

#[test]
fn trusted_origins_wildcard_subdomain() {
    let origins = build_trusted_origins(&["https://*.example.com".to_owned()]);
    assert!(
        origins.is_trusted("https://app.example.com"),
        "wildcard subdomain should match"
    );
    assert!(
        !origins.is_trusted("https://example.com"),
        "bare domain should not match wildcard"
    );
    assert!(
        !origins.is_trusted("https://a.b.example.com"),
        "nested subdomain should not match"
    );
}

#[test]
fn extract_origin_from_origin_header() {
    let mut headers = http::HeaderMap::new();
    headers.insert("origin", "https://example.com".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("https://example.com".to_owned()),
        "should extract from Origin header"
    );
}

#[test]
fn extract_origin_from_referer_fallback() {
    let mut headers = http::HeaderMap::new();
    headers.insert("referer", "https://example.com/path?q=1".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("https://example.com".to_owned()),
        "should extract scheme+host from Referer"
    );
}

#[test]
fn extract_origin_referer_with_port() {
    let mut headers = http::HeaderMap::new();
    headers.insert("referer", "https://example.com:8443/path".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("https://example.com:8443".to_owned()),
        "should preserve port from Referer"
    );
}

#[test]
fn extract_origin_null_origin_header() {
    let mut headers = http::HeaderMap::new();
    headers.insert("origin", "null".parse().unwrap());
    assert!(extract_origin(&headers).is_none(), "null Origin should return None");
}

#[test]
fn extract_origin_prefers_origin_over_referer() {
    let mut headers = http::HeaderMap::new();
    headers.insert("origin", "https://origin.example.com".parse().unwrap());
    headers.insert("referer", "https://referer.example.com/path".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("https://origin.example.com".to_owned()),
        "Origin header should take precedence over Referer"
    );
}

#[test]
fn extract_origin_missing_both() {
    let headers = http::HeaderMap::new();
    assert!(
        extract_origin(&headers).is_none(),
        "missing both headers should return None"
    );
}

#[tokio::test]
async fn safe_method_get_continues() {
    let f = make_filter(&["https://example.com"], 100, true);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue), "GET should bypass CSRF check");
}

#[tokio::test]
async fn safe_method_head_continues() {
    let f = make_filter(&["https://example.com"], 100, true);
    let req = crate::test_utils::make_request(http::Method::HEAD, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "HEAD should bypass CSRF check"
    );
}

#[tokio::test]
async fn safe_method_options_continues() {
    let f = make_filter(&["https://example.com"], 100, true);
    let req = crate::test_utils::make_request(http::Method::OPTIONS, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "OPTIONS should bypass CSRF check"
    );
}

#[tokio::test]
async fn post_with_trusted_origin_continues() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST with trusted origin should continue"
    );
}

#[tokio::test]
async fn post_with_untrusted_origin_rejects() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "POST with untrusted origin should reject 403"
    );
}

#[tokio::test]
async fn post_without_origin_or_referer_rejects() {
    let f = make_filter(&["https://example.com"], 100, false);
    let req = crate::test_utils::make_request(http::Method::POST, "/submit");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "POST without origin should reject 403"
    );
}

#[tokio::test]
async fn post_with_trusted_referer_continues() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers
        .insert("referer", "https://example.com/form".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "POST with trusted Referer should continue"
    );
}

#[tokio::test]
async fn sec_fetch_site_cross_site_rejects() {
    let f = make_filter(&["https://example.com"], 100, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "cross-site Sec-Fetch-Site should reject"
    );
}

#[tokio::test]
async fn sec_fetch_site_same_origin_continues() {
    let f = make_filter(&["https://example.com"], 100, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "same-origin Sec-Fetch-Site should continue"
    );
}

#[tokio::test]
async fn sec_fetch_site_disabled_ignores_cross_site() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "disabled sec_fetch_site should ignore cross-site"
    );
}

#[tokio::test]
async fn zero_enforcement_skips_origin_check() {
    let f = make_filter(&["https://example.com"], 0, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "0% enforcement should skip origin validation"
    );
}

#[tokio::test]
async fn zero_enforcement_still_rejects_null_origin() {
    let f = make_filter(&["https://example.com"], 0, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "null".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "null origin should be rejected regardless of enforce_percentage"
    );
}

#[tokio::test]
async fn zero_enforcement_still_rejects_cross_site_sec_fetch() {
    let f = make_filter(&["https://example.com"], 0, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "sec-fetch-site cross-site should be rejected regardless of enforce_percentage"
    );
}

#[tokio::test]
async fn partial_enforcement_samples_statistically() {
    let f = make_filter(&["https://example.com"], 50, false);
    let mut enforced = 0_u32;
    let total = 2000_u32;

    for _ in 0..total {
        let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
        req.headers.insert("origin", "https://evil.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        if matches!(action, FilterAction::Reject(_)) {
            enforced += 1;
        }
    }

    assert!(
        (900..1100).contains(&enforced),
        "50% enforcement over 2000 requests should reject ~1000 (got {enforced})"
    );
}

#[tokio::test]
async fn wildcard_trusted_origin_allows_any() {
    let f = make_filter(&["*"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "wildcard trusted origins should allow any origin"
    );
}

#[tokio::test]
async fn delete_with_untrusted_origin_rejects() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::DELETE, "/resource/123");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "DELETE with untrusted origin should reject"
    );
}

#[tokio::test]
async fn put_with_wildcard_subdomain_continues() {
    let f = make_filter(&["https://*.example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::PUT, "/update");
    req.headers.insert("origin", "https://app.example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "PUT with wildcard subdomain match should continue"
    );
}

#[test]
fn trusted_origin_normalizes_https_default_port() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(
        origins.is_trusted("https://example.com:443"),
        "https with explicit :443 should match bare origin"
    );
}

#[test]
fn trusted_origin_configured_with_default_port_matches_bare() {
    let origins = build_trusted_origins(&["https://example.com:443".to_owned()]);
    assert!(
        origins.is_trusted("https://example.com"),
        "bare origin should match configured :443"
    );
}

#[test]
fn trusted_origin_normalizes_http_default_port() {
    let origins = build_trusted_origins(&["http://example.com".to_owned()]);
    assert!(
        origins.is_trusted("http://example.com:80"),
        "http with explicit :80 should match bare origin"
    );
}

#[test]
fn trusted_origin_preserves_non_default_port() {
    let origins = build_trusted_origins(&["https://example.com".to_owned()]);
    assert!(
        !origins.is_trusted("https://example.com:8443"),
        "non-default port should not match bare origin"
    );
}

#[test]
fn extract_origin_normalizes_default_port_in_origin_header() {
    let mut headers = http::HeaderMap::new();
    headers.insert("origin", "https://example.com:443".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("https://example.com".to_owned()),
        "Origin header with :443 should normalize"
    );
}

#[test]
fn extract_origin_normalizes_default_port_in_referer() {
    let mut headers = http::HeaderMap::new();
    headers.insert("referer", "http://example.com:80/path".parse().unwrap());
    assert_eq!(
        extract_origin(&headers),
        Some("http://example.com".to_owned()),
        "Referer with :80 should normalize"
    );
}

#[test]
fn extract_origin_referer_fragment_no_path() {
    let mut headers = http::HeaderMap::new();
    headers.insert("referer", "https://example.com#section".parse().unwrap());
    let origin = extract_origin(&headers);
    assert!(
        origin.is_some(),
        "Referer with fragment but no path should still extract an origin"
    );
    assert_eq!(
        origin.as_deref(),
        Some("https://example.com#section"),
        "fragment leaks when no path separates it (split('/') misses '#')"
    );
}

#[tokio::test]
async fn log_only_allows_untrusted_origin() {
    let f = make_log_only_filter(&["https://example.com"]);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "log-only mode should allow untrusted origin"
    );
}

#[tokio::test]
async fn log_only_allows_missing_origin() {
    let f = make_log_only_filter(&["https://example.com"]);
    let req = crate::test_utils::make_request(http::Method::POST, "/submit");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "log-only mode should allow request without origin"
    );
}

#[tokio::test]
async fn log_only_allows_cross_site_sec_fetch() {
    let f = make_filter(&["https://example.com"], 100, true);
    let opts = InsecureOptions {
        csrf_log_only: true,
        ..InsecureOptions::default()
    };
    f.apply_insecure_options(&opts);

    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "log-only mode should allow cross-site sec-fetch-site"
    );
}

#[tokio::test]
async fn log_only_still_allows_trusted_origin() {
    let f = make_log_only_filter(&["https://example.com"]);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "log-only mode should still allow trusted origins"
    );
}

#[tokio::test]
async fn log_only_still_skips_safe_methods() {
    let f = make_log_only_filter(&["https://example.com"]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "log-only mode should still skip safe methods"
    );
}

#[test]
fn log_only_default_is_false() {
    let f = make_filter(&["https://example.com"], 100, false);
    assert!(!f.is_log_only(), "log_only should default to false");
}

#[test]
fn log_only_set_by_insecure_options() {
    let f = make_filter(&["https://example.com"], 100, false);
    let opts = InsecureOptions {
        csrf_log_only: true,
        ..InsecureOptions::default()
    };
    f.apply_insecure_options(&opts);
    assert!(f.is_log_only(), "apply_insecure_options should set log_only");
}

#[test]
fn log_only_cleared_by_insecure_options() {
    let f = make_filter(&["https://example.com"], 100, false);
    let enable = InsecureOptions {
        csrf_log_only: true,
        ..InsecureOptions::default()
    };
    f.apply_insecure_options(&enable);
    assert!(f.is_log_only(), "log_only should be set");

    let disable = InsecureOptions::default();
    f.apply_insecure_options(&disable);
    assert!(!f.is_log_only(), "log_only should be cleared");
}

#[tokio::test]
async fn patch_with_untrusted_origin_rejected() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::PATCH, "/api");
    req.headers.insert("origin", "https://evil.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "PATCH with untrusted origin should be rejected"
    );
}

#[tokio::test]
async fn trace_is_not_safe_by_default() {
    let f = make_filter(&["https://example.com"], 100, false);
    let req = crate::test_utils::make_request(http::Method::TRACE, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "TRACE should not bypass CSRF by default (XST risk)"
    );
}

#[tokio::test]
async fn enforcement_percentage_one_enforces_rarely() {
    let f = make_filter(&["https://example.com"], 1, false);
    let mut enforced = 0_u32;

    for _ in 0..1000 {
        let mut req = crate::test_utils::make_request(http::Method::POST, "/");
        req.headers.insert("origin", "https://evil.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        if matches!(f.on_request(&mut ctx).await.unwrap(), FilterAction::Reject(_)) {
            enforced += 1;
        }
    }

    assert!(
        (1..30).contains(&enforced),
        "1% enforcement over 1000 requests should enforce ~10 (got {enforced})"
    );
}

#[tokio::test]
async fn enforcement_percentage_ninety_nine_enforces_almost_all() {
    let f = make_filter(&["https://example.com"], 99, false);
    let mut enforced = 0_u32;

    for _ in 0..1000 {
        let mut req = crate::test_utils::make_request(http::Method::POST, "/");
        req.headers.insert("origin", "https://evil.com".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        if matches!(f.on_request(&mut ctx).await.unwrap(), FilterAction::Reject(_)) {
            enforced += 1;
        }
    }

    assert!(
        (970..1000).contains(&enforced),
        "99% enforcement over 1000 requests should enforce ~990 (got {enforced})"
    );
}

#[tokio::test]
async fn sec_fetch_site_none_allowed() {
    let f = make_filter(&["https://example.com"], 100, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "none".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "Sec-Fetch-Site: none should be allowed"
    );
}

#[tokio::test]
async fn sec_fetch_site_absent_with_feature_enabled() {
    let f = make_filter(&["https://example.com"], 100, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "absent Sec-Fetch-Site should fall through to origin check"
    );
}

#[tokio::test]
async fn sec_fetch_site_same_site_allowed() {
    let f = make_filter(&["https://example.com"], 100, true);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "https://example.com".parse().unwrap());
    req.headers.insert("sec-fetch-site", "same-site".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "Sec-Fetch-Site: same-site should be allowed"
    );
}

#[tokio::test]
async fn wildcard_with_non_default_port() {
    let f = make_filter(&["https://*.example.com:8443"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers
        .insert("origin", "https://app.example.com:8443".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "wildcard with non-default port should match"
    );
}

#[tokio::test]
async fn cross_scheme_rejected() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "http://example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "http:// should not match trusted https:// origin"
    );
}

#[tokio::test]
async fn case_insensitive_origin_match() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "HTTPS://EXAMPLE.COM".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "origin comparison should be case-insensitive per RFC 6454"
    );
}

#[tokio::test]
async fn empty_origin_header_rejected() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(_)),
        "empty origin header should be rejected"
    );
}

#[test]
fn config_rejects_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
trusted_origins: ["https://example.com"]
bogus_field: true
"#,
    )
    .unwrap();
    let result = CsrfFilter::from_config(&yaml);
    assert!(result.is_err(), "unknown fields should be rejected");
}

#[tokio::test]
async fn http_wildcard_subdomain_matches() {
    let f = make_filter(&["http://*.example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/");
    req.headers.insert("origin", "http://app.example.com".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "http:// wildcard subdomain should match"
    );
}

#[tokio::test]
async fn null_origin_rejected_with_distinct_reason() {
    let f = make_filter(&["https://example.com"], 100, false);
    let mut req = crate::test_utils::make_request(http::Method::POST, "/submit");
    req.headers.insert("origin", "null".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "null origin should be rejected"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`CsrfFilter`] with the given config.
fn make_filter(origins: &[&str], enforce_pct: u8, sec_fetch: bool) -> CsrfFilter {
    let origin_strings: Vec<String> = origins.iter().map(|s| (*s).to_owned()).collect();
    let trusted = build_trusted_origins(&origin_strings);
    CsrfFilter {
        enable_sec_fetch_site: sec_fetch,
        enforce_percentage: enforce_pct,
        log_only: std::sync::atomic::AtomicBool::new(false),
        safe_methods: vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()],
        trusted,
    }
}

/// Build a [`CsrfFilter`] in log-only mode.
fn make_log_only_filter(origins: &[&str]) -> CsrfFilter {
    let f = make_filter(origins, 100, false);
    let opts = InsecureOptions {
        csrf_log_only: true,
        ..InsecureOptions::default()
    };
    f.apply_insecure_options(&opts);
    f
}
