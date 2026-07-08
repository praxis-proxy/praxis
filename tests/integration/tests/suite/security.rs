// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for secure HTTP behavior.

use praxis_core::config::Config;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_backend_with_shutdown,
    start_header_echo_backend, start_hop_by_hop_response_backend, start_proxy, start_proxy_with_registry,
    start_reserved_header_response_backend,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn hop_by_hop_headers_stripped_before_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive, X-Secret\r\n\
         Keep-Alive: timeout=300\r\n\
         X-Secret: should-be-stripped\r\n\
         X-Safe: should-remain\r\n\
         Accept: text/html\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("keep-alive"),
        "Keep-Alive forwarded upstream: {body}"
    );
    assert!(
        !body_lower.contains("x-secret"),
        "Connection-declared header forwarded: {body}"
    );
    assert!(
        !body_lower.contains("\nconnection:"),
        "Connection header forwarded: {body}"
    );
    assert!(body_lower.contains("x-safe"), "Safe header stripped: {body}");
    assert!(body_lower.contains("accept"), "Accept header stripped: {body}");
}

#[test]
fn hop_by_hop_preserves_all_end_to_end_headers() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         Accept: application/json\r\n\
         Authorization: Bearer token123\r\n\
         X-Request-ID: abc-def\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(body_lower.contains("accept"), "Accept lost: {body}");
    assert!(body_lower.contains("authorization"), "Authorization lost: {body}");
    assert!(body_lower.contains("x-request-id"), "X-Request-ID lost: {body}");
}

#[test]
fn forwarded_headers_injected_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: forwarded_headers
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-forwarded-for"),
        "X-Forwarded-For missing: {body}"
    );
    assert!(
        body_lower.contains("x-forwarded-proto"),
        "X-Forwarded-Proto missing: {body}"
    );
    assert!(
        body.contains("example.com"),
        "X-Forwarded-Host missing original host: {body}"
    );
}

#[test]
fn forwarded_headers_untrusted_overwrites_spoofed_xff() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: proxy
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: forwarded_headers
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 1.1.1.1\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);

    assert!(
        !body.contains("1.1.1.1"),
        "Spoofed X-Forwarded-For was preserved: {body}"
    );

    assert!(
        body.contains("127.0.0.1"),
        "Real client IP missing from X-Forwarded-For: {body}"
    );
}

#[test]
fn hop_by_hop_headers_stripped_from_response() {
    let backend_port = start_hop_by_hop_response_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert!(
        parse_header(&raw, "keep-alive").is_none(),
        "Keep-Alive should be stripped from response: {raw}"
    );
    assert!(
        parse_header(&raw, "upgrade").is_none(),
        "Upgrade should be stripped from response: {raw}"
    );
    assert!(
        parse_header(&raw, "proxy-authenticate").is_none(),
        "Proxy-Authenticate should be stripped from response: {raw}"
    );
    assert!(
        parse_header(&raw, "trailer").is_none(),
        "Trailer should be stripped from response: {raw}"
    );
    assert!(
        parse_header(&raw, "x-internal-token").is_none(),
        "Connection-declared header should be stripped from response: {raw}"
    );
}

#[test]
fn hop_by_hop_response_preserves_end_to_end_headers() {
    let backend_port = start_hop_by_hop_response_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert!(
        parse_header(&raw, "x-safe-header").is_some(),
        "X-Safe-Header should be preserved in response: {raw}"
    );
    assert!(
        parse_header(&raw, "server").is_some(),
        "Server should be preserved in response: {raw}"
    );
    let body = parse_body(&raw);
    assert_eq!(body, "hop-by-hop-test", "response body should be forwarded intact");
}

#[test]
fn filter_injected_headers_do_not_leak_to_client_or_reserved_upstream() {
    let backend_guard = start_header_echo_backend();
    let backend_port = backend_guard.port();
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
      - filter: test_inject_internal
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    registry
        .register(
            "test_inject_internal",
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(|_| Ok(Box::new(InjectInternalFilter)))),
        )
        .expect("duplicate filter name");
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert!(
        parse_header(&raw, "x-internal-praxis").is_none(),
        "filter-injected request header should not appear in client response: {raw}"
    );
    assert!(
        parse_header(&raw, "x-praxis-secret").is_none(),
        "filter-injected request header should not appear in client response: {raw}"
    );

    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(
        body_lower.contains("x-internal-praxis"),
        "injected header X-Internal-Praxis should reach upstream: {body}"
    );
    assert!(
        !body_lower.contains("x-praxis-secret"),
        "x-praxis-* headers should be stripped before upstream even when filter-injected: {body}"
    );
}

#[test]
fn conflicting_content_length_rejected() {
    let backend_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Content-Length: 5\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "conflicting Content-Length values should be rejected with 400: {raw}"
    );
}

#[test]
fn reserved_internal_headers_stripped_from_upstream_response() {
    let backend_port = start_reserved_header_response_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert!(
        parse_header(&raw, "x-praxis-filter-action").is_none(),
        "x-praxis-* headers should be stripped from upstream response: {raw}"
    );
    assert!(
        parse_header(&raw, "x-ext-protocol-servername").is_none(),
        "x-ext-protocol-* headers should be stripped from upstream response: {raw}"
    );
    assert!(
        parse_header(&raw, "x-ext-agent-method").is_none(),
        "x-ext-agent-* headers should be stripped from upstream response: {raw}"
    );
    assert!(
        parse_header(&raw, "x-request-id").is_some(),
        "non-reserved x- headers should be preserved in response: {raw}"
    );
    assert!(
        parse_header(&raw, "server").is_some(),
        "standard headers should be preserved in response: {raw}"
    );
    let body = parse_body(&raw);
    assert_eq!(body, "reserved-header-test", "response body should be forwarded intact");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A filter that injects request headers via `extra_request_headers`.
///
/// Used to verify that filter-injected request headers do not leak into
/// client responses, and that reserved internal prefixes are stripped
/// before upstream forwarding.
struct InjectInternalFilter;

#[async_trait::async_trait]
impl HttpFilter for InjectInternalFilter {
    fn name(&self) -> &'static str {
        "test_inject_internal"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.extra_request_headers.push((
            std::borrow::Cow::Borrowed("X-Internal-Praxis"),
            "secret-value".to_owned(),
        ));
        ctx.extra_request_headers
            .push((std::borrow::Cow::Borrowed("X-Praxis-Secret"), "do-not-leak".to_owned()));
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Reserved Internal Header Hygiene — Acceptance Tests
// -----------------------------------------------------------------------------

#[test]
fn body_derived_internal_header_routes_request() {
    let tools_call_guard = start_backend_with_shutdown("tools-call-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
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
      - filter: json_rpc
        max_body_bytes: 65536
        headers:
          method: x-praxis-rpc-method
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-praxis-rpc-method: "service/invoke"
            cluster: "tools-call"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "tools-call"
            endpoints:
              - "127.0.0.1:{}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{}"
"#,
        tools_call_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"get_weather"}}"#;
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    );

    let raw = http_send(proxy.addr(), &request);
    let response_body = parse_body(&raw);

    assert_eq!(
        response_body, "tools-call-backend",
        "router should use body-derived service/invoke header: {response_body}"
    );
}

#[test]
fn spoofed_internal_header_rejected_before_routing() {
    let tools_call_guard = start_backend_with_shutdown("tools-call-backend");
    let default_guard = start_backend_with_shutdown("default-backend");
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
      - filter: json_rpc
        max_body_bytes: 65536
        headers:
          method: x-praxis-rpc-method
      - filter: router
        routes:
          - path_prefix: "/"
            headers:
              x-praxis-rpc-method: "service/invoke"
            cluster: "tools-call"
          - path_prefix: "/"
            cluster: "default"
      - filter: load_balancer
        clusters:
          - name: "tools-call"
            endpoints:
              - "127.0.0.1:{}"
          - name: "default"
            endpoints:
              - "127.0.0.1:{}"
"#,
        tools_call_guard.port(),
        default_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"get_weather"}}"#;
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Praxis-Ext-Method: initialize\r\n\
         \r\n\
         {body}",
        body.len(),
    );

    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 400,
        "client-supplied x-praxis-* internal headers should be rejected before routing: {raw}"
    );
}

#[test]
fn filter_generated_internal_header_does_not_reach_backend() {
    let backend_guard = start_header_echo_backend();
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
      - filter: json_rpc
        max_body_bytes: 65536
        headers:
          method: x-praxis-rpc-method
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{}"
"#,
        backend_guard.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"service/invoke","params":{"name":"get_weather"}}"#;
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    );

    let raw = http_send(proxy.addr(), &request);
    let echoed = parse_body(&raw);
    let echoed_lower = echoed.to_lowercase();

    assert!(
        !echoed_lower.contains("x-praxis-rpc-method"),
        "filter-generated x-praxis-rpc-method should be stripped before upstream: {echoed}"
    );
}

// -----------------------------------------------------------------------------
// Reserved Internal Header Hygiene — Prefix Rejection Tests
// -----------------------------------------------------------------------------

#[test]
fn reserved_x_praxis_headers_rejected_from_client() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Praxis-Ext-Method: spoofed\r\n\
         X-Praxis-Rpc-Name: spoofed-tool\r\n\
         X-Praxis-Ext-Method: spoofed-ext\r\n\
         X-Safe-Header: should-remain\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "x-praxis-* headers supplied by clients should be rejected: {raw}"
    );
}

#[test]
fn reserved_x_ext_protocol_headers_rejected_from_client() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Ext-Protocol-Server: evil-server\r\n\
         X-Ext-Protocol-Tool: evil-tool\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "x-ext-protocol-* headers supplied by clients should be rejected: {raw}"
    );
}

#[test]
fn reserved_x_ext_agent_headers_rejected_from_client() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Ext-Agent-Method: spoofed\r\n\
         X-Ext-Agent-Family: spoofed\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);

    assert_eq!(
        parse_status(&raw),
        400,
        "x-ext-agent-* headers supplied by clients should be rejected: {raw}"
    );
}

#[test]
fn standard_ext_protocol_headers_preserved() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Ext-Session-Id: session-123\r\n\
         Ext-Method: process\r\n\
         Ext-Name: get_weather\r\n\
         Ext-Protocol-Version: 2025-03-26\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        body_lower.contains("ext-session-id: session-123"),
        "Ext-Session-Id should be preserved: {body}"
    );
    assert!(
        body_lower.contains("ext-method: process"),
        "Ext-Method should be preserved: {body}"
    );
    assert!(
        body_lower.contains("ext-name: get_weather"),
        "Ext-Name should be preserved: {body}"
    );
    assert!(
        body_lower.contains("ext-protocol-version: 2025-03-26"),
        "Ext-Protocol-Version should be preserved: {body}"
    );
}
