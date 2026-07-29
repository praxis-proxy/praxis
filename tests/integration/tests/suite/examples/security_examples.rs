// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for security example configurations.

use std::collections::HashMap;

use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, start_backend_with_shutdown,
    start_header_echo_backend, start_proxy,
};

use super::load_example_config;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cors_preflight_returns_cors_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/cors.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "OPTIONS /api/data HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://app.example.com\r\n\
         Access-Control-Request-Method: PUT\r\n\
         Access-Control-Request-Headers: Content-Type\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 204, "preflight should return 204");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "preflight should reflect allowed origin"
    );
    assert!(
        parse_header(&raw, "access-control-allow-methods").is_some_and(|v| v.contains("PUT")),
        "preflight should include PUT in allowed methods"
    );
    assert!(
        parse_header(&raw, "access-control-allow-headers").is_some_and(|v| v.contains("Content-Type")),
        "preflight should include Content-Type in allowed headers"
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-credentials"),
        Some("true".to_owned()),
        "preflight should include credentials header"
    );
    assert_eq!(
        parse_header(&raw, "access-control-max-age"),
        Some("3600".to_owned()),
        "preflight should include max-age"
    );
}

#[test]
fn cors_actual_request_includes_response_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/cors.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://app.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "actual CORS request should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://app.example.com".to_owned()),
        "response should include Access-Control-Allow-Origin"
    );
    assert_eq!(
        parse_header(&raw, "access-control-allow-credentials"),
        Some("true".to_owned()),
        "response should include Access-Control-Allow-Credentials"
    );
    assert!(
        parse_header(&raw, "access-control-expose-headers").is_some_and(|v| v.contains("X-Request-ID")),
        "response should expose X-Request-ID header"
    );
}

#[test]
fn cors_disallowed_origin_omits_cors_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/cors.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /api/data HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://evil.com\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "disallowed origin should still proxy");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        None,
        "disallowed origin should not get ACAO header"
    );
}

#[test]
fn cors_wildcard_subdomain_origin_allowed() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/cors.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Origin: https://sub.example.com\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "wildcard subdomain should return 200");
    assert_eq!(
        parse_header(&raw, "access-control-allow-origin"),
        Some("https://sub.example.com".to_owned()),
        "wildcard subdomain should be reflected as allowed origin"
    );
}

#[test]
fn forwarded_headers_sets_xff() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "security/forwarded-headers.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "forwarded headers request should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("x-forwarded-for:"),
        "backend should receive X-Forwarded-For, got:\n{body}"
    );
}

#[test]
fn forwarded_headers_sets_standard_forwarded() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "security/forwarded-headers.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "request should return 200");
    let body = parse_body(&raw);
    let lower = body.to_lowercase();
    assert!(
        lower.contains("forwarded:"),
        "use_standard_header: true should set RFC 7239 Forwarded header, got:\n{body}"
    );
}

#[test]
fn ip_acl_allows_loopback() {
    let backend_guard = start_backend_with_shutdown("allowed");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/ip-acl.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "loopback address should be allowed by ip_acl");
    assert_eq!(body, "allowed", "response should come from backend");
}

#[test]
fn downstream_read_timeout_normal_request() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/downstream-read-timeout.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "normal GET within timeout should return 200");
    assert_eq!(body, "ok", "response body should match backend");
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn basic_auth_rejects_unauthenticated() {
    let backend_guard = start_backend_with_shutdown("protected");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/basic-auth.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 401, "unauthenticated request should return 401");
    assert!(
        parse_header(&raw, "www-authenticate").is_some_and(|v| v.contains("Basic")),
        "401 response should include WWW-Authenticate: Basic header"
    );
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn basic_auth_allows_valid_credentials() {
    let backend_guard = start_backend_with_shutdown("protected");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/basic-auth.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // "admin:secret" base64-encoded
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Basic YWRtaW46c2VjcmV0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "valid credentials should return 200");
    assert_eq!(parse_body(&raw), "protected", "response should come from backend");
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn basic_auth_strips_authorization_header() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let config = load_example_config(
        "security/basic-auth.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // "admin:secret" base64-encoded
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Basic YWRtaW46c2VjcmV0\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "valid credentials should return 200");

    let body = parse_body(&raw);
    assert!(
        !body.to_lowercase().contains("authorization:"),
        "Authorization header should be stripped before forwarding"
    );
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn basic_auth_allows_second_credential() {
    let backend_guard = start_backend_with_shutdown("protected");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/basic-auth.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Basic cmVhZG9ubHk6dmlld2Vy\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "second credential (readonly:viewer) should return 200"
    );
    assert_eq!(parse_body(&raw), "protected", "response should come from backend");
}

#[cfg(feature = "basic-auth-filter")]
#[test]
fn basic_auth_rejects_wrong_password() {
    let backend_guard = start_backend_with_shutdown("protected");
    let proxy_port = free_port();
    let config = load_example_config(
        "security/basic-auth.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    // "admin:wrong" base64-encoded
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Basic YWRtaW46d3Jvbmc=\r\n\
         Connection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 401, "wrong password should return 401");
}
