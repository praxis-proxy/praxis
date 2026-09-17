// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the `compression` filter.

use pingora_core::protocols::http::compression::Algorithm;
use praxis_core::config::Config;
use praxis_test_utils::{
    Backend, bind_unique_port, free_port, http_send, parse_header, parse_status, start_backend_with_shutdown,
    start_proxy, start_reloadable_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn compression_filter_is_accepted_in_pipeline() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
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
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter in pipeline should not break basic proxying"
    );
}

#[test]
fn compression_with_custom_level() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
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
        level: 3
        min_size_bytes: 1
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter with custom level should proxy successfully"
    );
}

#[test]
fn compression_with_algorithm_config() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
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
        level: 4
        gzip:
          enabled: true
          level: 6
        brotli:
          enabled: false
        zstd:
          enabled: true
          level: 3
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter with per-algorithm config should proxy successfully"
    );
}

#[test]
fn compression_in_filter_chain() {
    let backend_port_guard = start_backend_with_shutdown("ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: compression
        level: 6
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        parse_status(&raw),
        200,
        "compression filter in filter_chain should work"
    );
}

#[test]
fn no_compression_without_accept_encoding() {
    let backend_port_guard = start_backend_with_shutdown("uncompressed-response");
    let backend_port = backend_port_guard.port();
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
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "should return 200 without Accept-Encoding");
    let encoding = parse_header(&raw, "content-encoding");
    assert!(
        encoding.is_none(),
        "response should not be compressed without Accept-Encoding header"
    );
}

#[test]
fn compression_with_accept_encoding_gzip() {
    let body = "a".repeat(1024);
    let backend_port = Backend::fixed(body.leak()).header("Content-Type", "text/plain").start();
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
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );

    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let headers = send_and_read_headers(
        proxy.addr(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert!(
        headers.starts_with("HTTP/1.1 200"),
        "should return 200 with Accept-Encoding: gzip, got: {headers}"
    );
    let encoding = parse_header(&headers, "content-encoding");
    assert_eq!(
        encoding.as_deref(),
        Some("gzip"),
        "response should have Content-Encoding: gzip when client accepts gzip"
    );
}

#[test]
fn high_shared_levels_round_trip_gzip_for_upstream_and_static_responses() {
    let body = "gzip regression: preserve every byte, including Unicode: café 🦀. ".repeat(128);
    let backend = Backend::fixed(&body)
        .header("Content-Type", "text/plain")
        .start_with_shutdown();
    for level in [10, 11, 22] {
        let yaml = regression_yaml(free_port(), backend.port(), &body, &format!("level: {level}"));
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
        for path in ["/upstream", "/static"] {
            assert_gzip_response(proxy.addr(), path, &body, true);
        }
    }
}

#[test]
fn gzip_overrides_and_disablement_apply_before_negotiation_on_both_paths() {
    let body = "gzip algorithm settings must apply to the entire response. ".repeat(128);
    let backend = Backend::fixed(&body)
        .header("Content-Type", "text/plain")
        .start_with_shutdown();
    for (settings, compressed) in [
        ("level: 22\n        gzip: {level: 1}", true),
        ("level: 22\n        gzip: {enabled: false, level: 9}", false),
        ("level: 22\n        gzip: {level: 0}", false),
        ("level: 0\n        gzip: {level: 6}", true),
        ("level: 0", false),
    ] {
        let yaml = regression_yaml(free_port(), backend.port(), &body, settings);
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
        for path in ["/upstream", "/static"] {
            assert_gzip_response(proxy.addr(), path, &body, compressed);
        }
    }
}

#[test]
fn high_shared_level_round_trips_a_chunked_upstream_body() {
    let chunks = vec![
        "first chunk 🦀 ".repeat(128),
        "second chunk café ".repeat(256),
        "tail".into(),
    ];
    let body = chunks.concat();
    let backend = Backend::chunked(chunks)
        .header("Content-Type", "text/plain")
        .start_with_shutdown();
    let yaml = regression_yaml(free_port(), backend.port(), &body, "level: 22");
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    assert_gzip_response(proxy.addr(), "/upstream", &body, true);
}

#[test]
fn gzip_compresses_the_final_response_after_early_hints() {
    use std::{
        io::{BufRead as _, BufReader, Write as _},
        time::Duration,
    };

    let body = "final response following early hints ".repeat(64);
    for settings in ["level: 22", "level: 22\n        gzip: {level: 1}"] {
        let (listener, backend_port) = bind_unique_port();
        let response = format!(
            "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
             HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let backend = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(&mut stream);
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let yaml = regression_yaml(free_port(), backend_port, &body, settings);
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
        assert_gzip_response(proxy.addr(), "/upstream", &body, true);
        backend.join().unwrap();
    }
}

#[test]
fn high_shared_level_keeps_ineligible_upstream_responses_uncompressed() {
    let body = "compression policy remains in force. ".repeat(32);
    for (content_type, settings) in [
        ("text/plain", "level: 22\n        min_size_bytes: 100000"),
        ("image/png", "level: 22"),
        ("text/plain", "level: 22\n        content_types: [application/json]"),
    ] {
        let backend = Backend::fixed(&body)
            .header("Content-Type", content_type)
            .start_with_shutdown();
        let yaml = regression_yaml(free_port(), backend.port(), &body, settings);
        let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
        assert_gzip_response(proxy.addr(), "/upstream", &body, false);
    }
}

#[test]
fn high_shared_level_does_not_compress_without_accept_encoding() {
    let body = "clients that do not request gzip must receive the original bytes. ".repeat(32);
    let backend = Backend::fixed(&body)
        .header("Content-Type", "text/plain")
        .start_with_shutdown();
    let yaml = regression_yaml(free_port(), backend.port(), &body, "level: 22");
    let proxy = start_proxy(&Config::from_yaml(&yaml).unwrap());
    for path in ["/upstream", "/static"] {
        let (headers, received) = send_and_read_body(proxy.addr(), path, None);
        assert_eq!(parse_status(&headers), 200);
        assert!(parse_header(&headers, "content-encoding").is_none());
        assert_eq!(received, body.as_bytes());
    }
}

#[test]
fn gzip_configuration_reload_uses_current_levels_and_honors_removal() {
    let proxy_port = free_port();
    let backend = start_backend_with_shutdown("unused");
    let body = "startup generation ".repeat(64);
    let yaml = regression_yaml(proxy_port, backend.port(), &body, "level: 0");
    let proxy = start_reloadable_proxy(&yaml);
    assert_gzip_response(proxy.addr(), "/static", &body, false);

    let body = "high compression generation ".repeat(64);
    let yaml = regression_yaml(proxy_port, backend.port(), &body, "level: 22");
    proxy.reload(&yaml);
    assert_gzip_response(proxy.addr(), "/static", &body, true);

    let body = "removed compression generation ".repeat(64);
    let yaml = regression_yaml(proxy_port, backend.port(), &body, "level: 22")
        .replace("      - filter: compression\n        level: 22\n", "");
    proxy.reload(&yaml);
    assert_gzip_response(proxy.addr(), "/static", &body, false);
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn regression_yaml(proxy_port: u16, backend_port: u16, body: &str, settings: &str) -> String {
    let body = serde_json::to_string(body).unwrap();
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
        {settings}
      - filter: static_response
        conditions:
          - when:
              path_prefix: /static
        status: 200
        body: {body}
        headers:
          - name: Content-Type
            value: text/plain
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn assert_gzip_response(addr: &str, path: &str, expected: &str, compressed: bool) {
    let (headers, body) = send_and_read_body(addr, path, Some("gzip"));
    assert_eq!(parse_status(&headers), 200, "{path}: {headers}");
    let encoding = parse_header(&headers, "content-encoding");
    if compressed {
        assert_eq!(encoding.as_deref(), Some("gzip"), "{path}: {headers}");
        assert!(
            parse_header(&headers, "content-length").is_none(),
            "gzip must replace the original length"
        );
        assert!(
            parse_header(&headers, "vary")
                .unwrap()
                .to_ascii_lowercase()
                .contains("accept-encoding"),
            "compressed responses must vary on the client's accepted encodings"
        );
        let decoded = Algorithm::Gzip
            .decompressor(true)
            .unwrap()
            .encode(&body, true)
            .expect("complete gzip stream must decode, including its checksum and trailer");
        assert_eq!(
            decoded.as_ref(),
            expected.as_bytes(),
            "{path}: gzip must preserve the complete body"
        );
    } else {
        assert!(encoding.is_none(), "{path}: {headers}");
        assert_eq!(
            body,
            expected.as_bytes(),
            "{path}: disabled compression must preserve the body"
        );
    }
}

/// Read framed bytes without UTF-8 loss or mistaking compressed bytes for a chunk terminator.
fn send_and_read_body(addr: &str, path: &str, accept_encoding: Option<&str>) -> (String, Vec<u8>) {
    use std::{
        io::{BufRead as _, BufReader, Read as _, Write as _},
        net::TcpStream,
        time::Duration,
    };

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    )
    .unwrap();
    if let Some(encoding) = accept_encoding {
        write!(stream, "Accept-Encoding: {encoding}\r\n").unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "response headers must be complete"
        );
        headers.push_str(&line);
        if line == "\r\n" {
            if (100..200).contains(&parse_status(&headers)) {
                headers.clear();
                continue;
            }
            break;
        }
    }

    let mut body = Vec::new();
    if parse_header(&headers, "transfer-encoding").as_deref() == Some("chunked") {
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0, "chunk size must be present");
            let size = usize::from_str_radix(line.trim(), 16).expect("valid chunk size");
            if size == 0 {
                line.clear();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "\r\n", "chunked response must have its final terminator");
                break;
            }
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).expect("complete chunk body");
            body.extend_from_slice(&chunk);
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).unwrap();
            assert_eq!(&crlf, b"\r\n", "each chunk must end with CRLF");
        }
    } else {
        let size = parse_header(&headers, "content-length")
            .expect("response must be framed")
            .parse()
            .unwrap();
        body.resize(size, 0);
        reader.read_exact(&mut body).expect("complete fixed-length body");
    }
    (headers, body)
}

/// Send an HTTP request and read only the response headers.
fn send_and_read_headers(addr: &str, request: &str) -> String {
    use std::{
        io::{Read as _, Write as _},
        net::TcpStream,
        time::Duration,
    };

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();

    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(data.len(), |p| p + 4);
    String::from_utf8_lossy(&data[..header_end]).into_owned()
}
