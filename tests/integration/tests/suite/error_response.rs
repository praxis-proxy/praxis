// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for structured error responses on upstream failures.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_proxy,
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
