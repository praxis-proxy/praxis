//! HTTP conformance tests.
//!
//! Verify the proxy handles edge cases and malformed traffic
//! without crashing, leaking connections, or returning
//! incorrect responses.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_get, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn nonsense_method_does_not_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "XYZZY / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || status == 405,
        "expected 200, 400, or 405 for unknown method, got {status}"
    );
}

#[test]
fn missing_host_header_does_not_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400 || status == 0,
        "expected 200, 400, or connection close for missing Host, got: {status}"
    );
}

#[test]
fn empty_request_line_no_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "\r\n\r\n");
    let status = parse_status(&raw);
    assert!(
        status == 400 || status == 0,
        "expected 400 or connection close for empty request line, got {status}"
    );
}

#[test]
fn garbage_bytes_no_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let garbage = b"\x00\x01\x02\x7f\x03\r\n";
    {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(&addr).unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
        let _ = stream.write_all(garbage);
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
    }

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "proxy should still serve requests after garbage bytes");
    assert_eq!(body, "ok", "response body should be intact after garbage bytes");
}

#[test]
fn very_long_uri_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let long_path = "/".to_string() + &"a".repeat(8000);
    let request = format!("GET {long_path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let raw = http_send(&addr, &request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 414,
        "expected 200 or 414 for long URI, got: {status}"
    );
}

#[test]
fn very_long_header_value_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let long_value = "x".repeat(16_000);
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Big: {long_value}\r\n\
         \r\n"
    );
    let raw = http_send(&addr, &request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 431,
        "expected 200 or 431 for large header, got: {status}"
    );
}

#[test]
fn many_headers_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let mut request = "GET / HTTP/1.1\r\nHost: localhost\r\n".to_string();
    for i in 0..200 {
        request.push_str(&format!("X-Header-{i}: value-{i}\r\n"));
    }
    request.push_str("\r\n");

    let raw = http_send(&addr, &request);
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 431,
        "expected 200 or 431 for many headers, got: {status}"
    );
}

#[test]
fn content_length_zero_with_no_body() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    let status = parse_status(&raw);
    assert_eq!(status, 200, "Content-Length: 0 with no body should succeed");
}

#[test]
fn negative_content_length_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n");
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 0,
        "expected 400 or connection close for negative CL, got {status}"
    );
}

#[test]
fn duplicate_content_length_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 5\r\n\
         Content-Length: 10\r\n\
         \r\n\
         hello",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 0,
        "expected 400 or connection close for \
         conflicting Content-Length, got {status}"
    );
}

#[test]
fn proxy_recovers_after_malformed_request() {
    let backend_port = start_backend("recovered");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let _ = http_send(&addr, "NOT HTTP\r\n\r\n");

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "proxy should recover after malformed request");
    assert_eq!(body, "recovered", "response body should be correct after recovery");
}

#[test]
fn proxy_recovers_after_connection_reset() {
    let backend_port = start_backend("alive");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    {
        let stream = std::net::TcpStream::connect(&addr).unwrap();
        drop(stream);
    }

    let (status, body) = http_get(&addr, "/", None);
    assert_eq!(status, 200, "proxy should recover after connection reset");
    assert_eq!(body, "alive", "response body should be correct after reset recovery");
}

#[test]
fn head_request_returns_no_body() {
    let backend_port = start_backend("should-not-appear");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(&addr, "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let status = parse_status(&raw);

    assert_eq!(status, 200, "HEAD request should return 200");
    let body = parse_body(&raw);
    assert!(body.is_empty(), "HEAD response should have no body, got: {body}");
}

#[test]
fn options_request_handled() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let raw = http_send(&addr, "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let status = parse_status(&raw);
    assert!(
        status == 200 || status == 405,
        "expected 200 or 405 for OPTIONS, got: {status}"
    );
}

#[test]
fn handles_concurrent_requests() {
    let backend_port = start_backend("concurrent");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let addr = addr.clone();
            std::thread::spawn(move || http_get(&addr, "/", None))
        })
        .collect();
    for handle in handles {
        let (status, body) = handle.join().unwrap();
        assert_eq!(status, 200, "concurrent request should return 200");
        assert_eq!(body, "concurrent", "concurrent request body mismatch");
    }
}
