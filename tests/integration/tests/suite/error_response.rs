// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for structured error responses on upstream failures.

use http::HeaderValue;
use praxis_core::config::Config;
use praxis_filter::{
    ErrorResponseContext, ErrorResponseFormatter, ErrorResponseFormatterHandle, FilterAction, FilterError,
    FormattedErrorResponse, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_get, http_send, parse_body, parse_header, parse_status, registry_with,
    simple_proxy_yaml, start_proxy, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn dead_backend_returns_problem_details_body() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 502, "dead backend should return 502");
    assert!(
        body.contains(r#""type":"about:blank""#),
        "body should contain RFC 9457 type field, got: {body}"
    );
    assert!(
        body.contains(r#""title":"Bad Gateway""#),
        "body should contain RFC 9457 title, got: {body}"
    );
    assert!(
        body.contains(r#""status":502"#),
        "body should contain RFC 9457 status, got: {body}"
    );
    assert!(
        body.contains(r#""detail":"Upstream connection refused""#),
        "body should contain human-readable detail, got: {body}"
    );
}

#[test]
fn dead_backend_returns_problem_json_content_type() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_eq!(status, 502, "dead backend should return 502");

    let ct = parse_header(&raw, "content-type");
    assert_eq!(
        ct.as_deref(),
        Some("application/problem+json"),
        "error response should have application/problem+json content-type"
    );
}

#[test]
fn dead_backend_head_request_has_no_body() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_eq!(status, 502, "HEAD to dead backend should return 502");

    let body = parse_body(&raw);
    assert!(body.is_empty(), "HEAD response should have no body, got: {body}");

    let ct = parse_header(&raw, "content-type");
    assert_eq!(
        ct.as_deref(),
        Some("application/problem+json"),
        "HEAD error response should still have content-type header"
    );
}

#[test]
fn dead_backend_post_returns_problem_details_body() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST /v1/responses HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 2\r\n\
         Connection: close\r\n\r\n\
         {}",
    );

    let status = parse_status(&raw);
    assert_eq!(status, 502, "POST to dead backend should return 502");

    let body = parse_body(&raw);
    assert!(
        body.contains(r#""type":"about:blank""#),
        "POST error body should contain RFC 9457 type, got: {body}"
    );
}

#[test]
fn error_response_is_valid_json() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, dead_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (_status, body) = http_get(proxy.addr(), "/", None);

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        panic!("error response body should be valid JSON: {e}\nbody: {body}");
    });

    assert!(parsed.get("type").is_some(), "should have 'type' field");
    assert!(parsed.get("title").is_some(), "should have 'title' field");
    assert!(parsed.get("status").is_some(), "should have 'status' field");
    assert!(parsed.get("detail").is_some(), "should have 'detail' field");
}

#[test]
fn external_filter_controls_error_response_envelope() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, dead_port, "test_error_formatter");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("test_error_formatter", || Box::new(InstallErrorFormatterFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 502, "dead backend should return 502");
    assert_eq!(
        parse_header(&raw, "content-type").as_deref(),
        Some("application/vnd.praxis.test+json")
    );
    assert_eq!(
        parse_body(&raw),
        r#"{"error":{"code":"upstream_connect_refused","status":502}}"#
    );
}

#[test]
fn error_response_bypasses_compression_module() {
    let dead_port = free_port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
        min_size_bytes: 1
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{dead_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 502, "dead backend should return 502");
    assert!(
        parse_header(&raw, "content-encoding").is_none(),
        "synthetic error response must not be compressed"
    );
    assert_eq!(
        parse_header(&raw, "cache-control").as_deref(),
        Some("no-transform"),
        "synthetic error response should include no-transform cache directive"
    );
    let body = parse_body(&raw);
    assert!(
        body.contains(r#""status":502"#),
        "body should remain plain JSON: {body}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Filter that installs a test-owned error response formatter.
struct InstallErrorFormatterFilter;

#[async_trait::async_trait]
impl HttpFilter for InstallErrorFormatterFilter {
    fn name(&self) -> &'static str {
        "test_error_formatter"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.extensions
            .insert(ErrorResponseFormatterHandle::new(TestErrorFormatter));
        Ok(FilterAction::Continue)
    }
}

/// Test formatter standing in for a provider-specific external filter.
struct TestErrorFormatter;

impl ErrorResponseFormatter for TestErrorFormatter {
    fn format(&self, context: &ErrorResponseContext<'_>) -> FormattedErrorResponse {
        FormattedErrorResponse::new(
            format!(
                r#"{{"error":{{"code":"{}","status":{}}}}}"#,
                context.code, context.status
            ),
            HeaderValue::from_static("application/vnd.praxis.test+json"),
        )
    }
}
