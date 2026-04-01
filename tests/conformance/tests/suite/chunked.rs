//! Chunked transfer encoding conformance tests.
//!
//! Verify the proxy correctly handles HTTP/1.1 chunked
//! request bodies.

use praxis_core::config::Config;

use crate::common::{
    free_port, http_get, http_send, parse_body, parse_status, simple_proxy_yaml, start_backend, start_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn single_chunk_body_proxied() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert_eq!(status, 200, "single-chunk POST should be proxied successfully");
}

#[test]
fn multiple_chunks_proxied() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         1\r\n\
         ,\r\n\
         6\r\n\
         world!\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "multi-chunk POST should be proxied successfully");
    assert_eq!(
        body, "ok",
        "backend should respond normally after receiving multi-chunk body"
    );
}

#[test]
fn empty_chunked_body_returns_200() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(
        status, 200,
        "empty chunked body (zero-length terminator only) should return 200"
    );
    assert!(
        body.is_empty(),
        "empty chunked body should produce an empty echo, got: {body:?}"
    );
}

#[test]
fn chunked_body_with_trailers_does_not_crash() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Trailer: X-Checksum\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\n\
         hello\r\n\
         0\r\n\
         X-Checksum: abc123\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 400,
        "chunked body with trailers should return 200 or 400, got {status}"
    );
}

#[test]
fn recovery_after_chunked_request() {
    let backend_port = start_backend("alive");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);

    let raw = http_send(
        &addr,
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         3\r\n\
         abc\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);
    assert_eq!(status, 200, "chunked POST should return 200");

    let (status2, body2) = http_get(&addr, "/", None);
    assert_eq!(status2, 200, "normal GET after chunked POST should return 200");
    assert_eq!(
        body2, "alive",
        "proxy should serve normal requests correctly after chunked request"
    );
}
