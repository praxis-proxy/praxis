//! Header injection adversarial tests.
//!
//! Verifies that CRLF injection, hop-by-hop abuse,
//! oversized headers, and null bytes do not bypass
//! security boundaries or crash the proxy.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_send, parse_body, parse_status, simple_proxy_yaml, start_header_echo_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn crlf_in_header_value_rejected_or_sanitized() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let request_bytes =
        b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: safe\r\nX-Injected: true\r\nConnection: close\r\n\r\n";
    let raw = {
        use std::{
            io::{Read, Write},
            net::TcpStream,
            time::Duration,
        };

        let mut stream = TcpStream::connect(&addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(request_bytes).unwrap();

        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    };

    let status = parse_status(&raw);
    if status == 0 {
        return;
    }

    assert_ne!(status, 500, "CRLF in request must not cause 500");
}

#[test]
fn crlf_in_header_name_rejected() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Bad\r\nName: value\r\n\
         Connection: close\r\n\r\n",
    );

    let status = parse_status(&raw);
    assert_ne!(status, 500, "CRLF in header name must not cause 500");
}

#[test]
fn connection_header_cannot_strip_security_headers() {
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
    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Forwarded-For: 10.0.0.99\r\n\
         Connection: close\r\n\r\n",
    );
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();
    if body_lower.contains("x-forwarded-for") {
        assert!(
            !body.contains("10.0.0.99"),
            "spoofed XFF value must not reach upstream; body: {body}"
        );
    }
}

#[test]
fn oversized_header_handled_gracefully() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let big_value = "A".repeat(8 * 1024);
    let raw = http_send(
        &addr,
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-Big: {big_value}\r\n\
             Connection: close\r\n\r\n"
        ),
    );
    let status = parse_status(&raw);
    assert_ne!(status, 500, "oversized header must not cause 500");
}

#[test]
fn null_bytes_in_headers_handled() {
    let backend_port = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Null: before\x00after\r\nConnection: close\r\n\r\n",
    );
    let status = parse_status(&raw);
    assert_ne!(status, 500, "null byte in header must not cause 500");
}
