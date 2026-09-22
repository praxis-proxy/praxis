// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Connection lifecycle attack-vector tests.

use std::io::{Read as _, Write as _};

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_backend,
    start_keepalive_poison_backend, start_mid_response_drop_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn keepalive_poisoning_does_not_leak_to_client() {
    let backend = start_keepalive_poison_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 200 || status == 502 || status == 0,
        "keep-alive poison upstream must be handled safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    let poisoned = parse_header(&raw, "x-poisoned");
    assert!(
        poisoned.is_none(),
        "forged second upstream response must not reach the client: {raw}"
    );

    if status == 200 {
        let body = parse_body(&raw);
        assert!(
            !body.contains("poison"),
            "poison body must not be appended to the client response: {body}"
        );
    }
}

#[test]
fn http11_pipelining_responses_do_not_mix() {
    let backend_port = start_backend("pipe-ok");
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

    // Two requests pipelined on one connection.
    let pipeline = "GET /a HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         GET /b HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n";
    stream.write_all(pipeline.as_bytes()).unwrap();

    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.windows(4).filter(|w| *w == b"\r\n\r\n").count() >= 2 || buf.len() > 16_384 {
            break;
        }
    }
    let raw = String::from_utf8_lossy(&buf);

    // Count distinct HTTP/1.1 status lines; they must not interleave mid-message.
    let status_lines: Vec<_> = raw
        .lines()
        .filter(|l| l.starts_with("HTTP/1."))
        .collect();
    assert!(
        !status_lines.is_empty(),
        "pipelined requests must produce at least one response"
    );
    for line in &status_lines {
        assert!(
            line.starts_with("HTTP/1.1 ") || line.starts_with("HTTP/1.0 "),
            "status lines must stay on message boundaries, got {line}"
        );
    }

    // Bodies (if present) should not contain mixed status framing.
    assert!(
        !raw.contains("HTTP/1.1 200 OKHTTP/1.1"),
        "responses must not be concatenated without separators: {raw}"
    );
}

#[test]
fn premature_backend_close_mid_response_returns_502() {
    let backend_port = start_mid_response_drop_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 502,
        "backend dropping mid-response should produce 502 (got {status})"
    );
}
