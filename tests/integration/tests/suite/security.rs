//! Integration tests for secure HTTP behavior.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_send, parse_body, parse_header, simple_proxy_yaml, start_header_echo_backend,
    start_hop_by_hop_response_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn hop_by_hop_headers_stripped_before_upstream() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive, X-Secret\r\n\
         Keep-Alive: timeout=300\r\n\
         Upgrade: websocket\r\n\
         X-Secret: should-be-stripped\r\n\
         X-Safe: should-remain\r\n\
         Accept: text/html\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("keep-alive"),
        "Keep-Alive forwarded upstream: {body}"
    );
    assert!(!body_lower.contains("upgrade"), "Upgrade forwarded upstream: {body}");
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
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         Accept: application/json\r\n\
         Authorization: Bearer token123\r\n\
         X-Request-ID: abc-def\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    assert!(body_lower.contains("accept"), "Accept lost: {body}");
    assert!(body_lower.contains("authorization"), "Authorization lost: {body}");
    assert!(body_lower.contains("x-request-id"), "X-Request-ID lost: {body}");
}

#[test]
fn forwarded_headers_injected_upstream() {
    let backend_port = start_header_echo_backend();
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
    let addr = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);
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
    let backend_port = start_header_echo_backend();
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
    let addr = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 1.1.1.1\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);
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
    let addr = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);

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
    let addr = start_proxy(&config);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);

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
