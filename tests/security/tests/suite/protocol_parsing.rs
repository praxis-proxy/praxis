// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Protocol parsing attack-vector tests (chunked encoding, URI form, length).

use std::io::{Read as _, Write as _};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_status, simple_proxy_yaml, start_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn chunked_encoding_non_hex_size_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         xyz\r\n\
         data\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 0,
        "non-hex chunk size must be rejected or connection closed (got {status})"
    );
}

#[test]
fn chunked_encoding_overflow_size_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Absurd hex length that would overflow if parsed as usize unsafely.
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         ffffffffffffffff\r\n\
         x\r\n\
         0\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 413 || status == 0,
        "overflow chunk size must be rejected or connection closed (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");
}

#[test]
fn mixed_chunked_and_content_length_does_not_poison_connection() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let mut stream = std::net::TcpStream::connect(proxy.addr()).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    // Ambiguous TE + CL request on a keep-alive connection.
    let ambiguous = "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Transfer-Encoding: chunked\r\n\
         Content-Length: 4\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         0\r\n\
         \r\n";
    stream.write_all(ambiguous.as_bytes()).unwrap();

    let mut buf = vec![0_u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let first = String::from_utf8_lossy(&buf[..n]);
    let first_status = parse_status(&first);

    // Either rejected, or handled consistently — then a follow-up must be isolated.
    let follow_up = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n";
    drop(stream.write_all(follow_up.as_bytes()));
    let mut buf2 = vec![0_u8; 4096];
    let n2 = stream.read(&mut buf2).unwrap_or(0);
    let second = String::from_utf8_lossy(&buf2[..n2]);
    let second_status = parse_status(&second);

    assert_ne!(first_status, 500, "TE+CL must not cause 500 on first request");
    if n2 > 0 {
        assert_ne!(
            second_status, 500,
            "follow-up after TE+CL must not be poisoned into 500"
        );
        assert!(
            second_status == 200 || second_status == 400 || second_status == 0,
            "follow-up must be isolated (got {second_status})"
        );
    }
}

#[test]
fn request_line_exceeding_max_length_rejected() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Oversized request-target (well beyond typical URI limits).
    let long_path = format!("/{}", "a".repeat(65_536));
    let request = format!(
        "GET {long_path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let status = parse_status(&raw);

    // Prefer 414 URI Too Long; accept other safe rejections.
    assert!(
        status == 414 || status == 400 || status == 431 || status == 0,
        "oversized request-target must be rejected safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");
}

#[test]
fn absolute_form_request_uri_does_not_ssrf() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    // Absolute-form URI pointing at an unrelated host must not open that host.
    let raw = http_send(
        proxy.addr(),
        "GET http://evil.example/secret HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 400 || status == 200 || status == 0,
        "absolute-form URI must be rejected or rewritten safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    // If accepted, body must come from the configured backend, not evil.example.
    if status == 200 {
        assert!(
            raw.contains("ok"),
            "absolute-form must not SSRF to evil.example; expected configured backend body"
        );
    }
}
