//! Forwarded headers adversarial tests.
//!
//! Verifies that `X-Forwarded-For`, `X-Forwarded-Proto`,
//! and `X-Forwarded-Host` cannot be spoofed by untrusted
//! clients, and that trusted proxy chains are preserved.

use praxis_core::config::Config;

use crate::common::{free_port, http_send, parse_body, start_header_echo_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn untrusted_client_cannot_spoof_xff() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 10.0.0.99\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    assert!(xff.is_some(), "X-Forwarded-For must be present; body: {body}");
    let xff = xff.unwrap();
    assert!(
        !xff.contains("10.0.0.99"),
        "spoofed XFF value must be overwritten; got: {xff}"
    );
    assert!(
        xff.contains("127.0.0.1"),
        "real client IP must appear in XFF; got: {xff}"
    );
}

#[test]
fn untrusted_cannot_spoof_x_forwarded_proto() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-Proto: https\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let proto = body_header(&body, "x-forwarded-proto");
    assert!(proto.is_some(), "X-Forwarded-Proto must be present; body: {body}");
    let proto = proto.unwrap();
    assert_eq!(
        proto, "http",
        "X-Forwarded-Proto must reflect actual scheme, not spoofed value"
    );
}

#[test]
fn untrusted_cannot_spoof_x_forwarded_host() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: real-host.com\r\n\
         X-Forwarded-Host: evil-host.com\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let host = body_header(&body, "x-forwarded-host");
    assert!(host.is_some(), "X-Forwarded-Host must be present; body: {body}");
    let host = host.unwrap();
    assert_eq!(
        host, "real-host.com",
        "X-Forwarded-Host must reflect the actual Host header, not the spoofed value"
    );
}

#[test]
fn xff_chain_injection_prevented() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 10.0.0.1, 192.168.1.1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        !xff.contains("10.0.0.1"),
        "injected chain IP must not survive; got: {xff}"
    );
    assert!(
        !xff.contains("192.168.1.1"),
        "injected chain IP must not survive; got: {xff}"
    );
    assert_eq!(xff, "127.0.0.1", "XFF must contain only the real client IP; got: {xff}");
}

#[test]
fn trusted_proxy_preserves_chain() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 203.0.113.50\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        xff.contains("203.0.113.50"),
        "trusted proxy must preserve existing XFF; got: {xff}"
    );
    assert!(
        xff.contains("127.0.0.1"),
        "trusted proxy must append its own IP; got: {xff}"
    );
    assert_eq!(
        xff, "203.0.113.50, 127.0.0.1",
        "XFF must be existing + appended; got: {xff}"
    );
}

#[test]
fn trusted_proxy_with_long_xff_chain() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 203.0.113.1, 10.1.1.1, 10.2.2.2\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert_eq!(
        xff, "203.0.113.1, 10.1.1.1, 10.2.2.2, 127.0.0.1",
        "full chain must be preserved with our IP appended; got: {xff}"
    );
}

#[test]
fn multiple_xff_headers_from_untrusted_overwritten() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 10.0.0.1\r\n\
         X-Forwarded-For: 192.168.1.1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);
    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        xff.contains("127.0.0.1"),
        "real client IP must appear in XFF; got: {xff}"
    );
}

#[test]
fn multiple_xfp_headers_from_untrusted_overwritten() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-Proto: https\r\n\
         X-Forwarded-Proto: wss\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let proto = body_header(&body, "x-forwarded-proto");
    let proto = proto.unwrap_or_default();
    assert_eq!(
        proto, "http",
        "spoofed proto headers must be overwritten with actual scheme; got: {proto}"
    );
}

#[test]
fn multiple_xfh_headers_from_untrusted_overwritten() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: real-host.com\r\n\
         X-Forwarded-Host: evil1.com\r\n\
         X-Forwarded-Host: evil2.com\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let host = body_header(&body, "x-forwarded-host");
    let host = host.unwrap_or_default();
    assert_eq!(
        host, "real-host.com",
        "spoofed host headers must be overwritten with actual Host; got: {host}"
    );
}

#[test]
fn empty_xff_from_untrusted_replaced() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: \r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert_eq!(
        xff, "127.0.0.1",
        "empty XFF must be replaced with real client IP; got: {xff}"
    );
}

#[test]
fn ipv6_xff_from_untrusted_overwritten() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &[]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: ::1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(!xff.contains("::1"), "spoofed IPv6 XFF must be overwritten; got: {xff}");
    assert_eq!(xff, "127.0.0.1", "XFF must contain only the real client IP; got: {xff}");
}

#[test]
fn ipv6_loopback_in_xff_chain_from_trusted_proxy_preserved() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: ::1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        xff.contains("::1"),
        "trusted proxy must preserve IPv6 loopback in XFF chain; got: {xff}"
    );
    assert!(
        xff.contains("127.0.0.1"),
        "trusted proxy must append real client IP; got: {xff}"
    );
    assert_eq!(
        xff, "::1, 127.0.0.1",
        "XFF must be preserved IPv6 loopback followed by appended real IP; got: {xff}"
    );
}

#[test]
fn ipv6_full_address_in_xff_from_trusted_proxy_preserved() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 2001:db8::1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        xff.contains("2001:db8::1"),
        "trusted proxy must preserve full IPv6 address in XFF; got: {xff}"
    );
    assert_eq!(
        xff, "2001:db8::1, 127.0.0.1",
        "XFF must be preserved IPv6 address followed by appended real IP; got: {xff}"
    );
}

#[test]
fn mixed_ipv4_and_ipv6_in_xff_from_trusted_proxy_preserved() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 192.168.1.1, 2001:db8::1\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let xff = body_header(&body, "x-forwarded-for");
    let xff = xff.unwrap_or_default();
    assert!(
        xff.contains("192.168.1.1"),
        "trusted proxy must preserve IPv4 address in mixed chain; got: {xff}"
    );
    assert!(
        xff.contains("2001:db8::1"),
        "trusted proxy must preserve IPv6 address in mixed chain; got: {xff}"
    );
    assert_eq!(
        xff, "192.168.1.1, 2001:db8::1, 127.0.0.1",
        "XFF must preserve full mixed chain with real IP appended; got: {xff}"
    );
}

#[test]
fn trusted_proxy_proto_reflects_actual_scheme() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-Proto: https\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let proto = body_header(&body, "x-forwarded-proto");
    let proto = proto.unwrap_or_default();
    assert_eq!(
        proto, "http",
        "X-Forwarded-Proto must reflect actual scheme (http), not forwarded value; got: {proto}"
    );
}

#[test]
fn trusted_proxy_host_reflects_actual_host_header() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = fwd_yaml(proxy_port, backend_port, &["127.0.0.0/8"]);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: proxy-host.com\r\n\
         X-Forwarded-Host: original-host.com\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);

    let host = body_header(&body, "x-forwarded-host");
    let host = host.unwrap_or_default();
    assert_eq!(
        host, "proxy-host.com",
        "X-Forwarded-Host must reflect actual Host header; got: {host}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build proxy YAML with forwarded_headers filter.
fn fwd_yaml(proxy_port: u16, backend_port: u16, trusted: &[&str]) -> String {
    let trusted_yaml = if trusted.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = trusted.iter().map(|t| format!("          - \"{t}\"")).collect();
        format!("        trusted_proxies:\n{}", entries.join("\n"))
    };

    format!(
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
{trusted_yaml}
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
    )
}

/// Extract a header value from the echo body (key: value format).
fn body_header(body: &str, name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    body.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().to_lowercase() == lower {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}
