// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Response-side header injection and response-splitting tests.

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, simple_proxy_yaml,
    start_malicious_response_header_backend, start_proxy,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_response_crlf_header_value_not_injected() {
    // Double-CRLF response splitting: embedded blank line + forged status.
    let malformed = b"X-Safe: ok\r\n\r\nHTTP/1.1 200 OK\r\nX-Injected: evil".to_vec();
    let backend = start_malicious_response_header_backend(malformed);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 502 || status == 400 || status == 200 || status == 0,
        "CRLF response splitting must be handled safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    // Injected material must not appear as a client-visible *header*
    // (it may appear in a rejected/chunked body if the proxy treats the
    // split as opaque payload — still not a second response frame).
    assert!(
        parse_header(&raw, "x-injected").is_none(),
        "response splitting must not inject X-Injected as a response header: {raw}"
    );
}

#[test]
fn upstream_set_cookie_crlf_injection_rejected() {
    // Bare CR inside a Set-Cookie value — classic cookie injection vector.
    let malformed = b"Set-Cookie: session=abc\rSet-Cookie: injected=1".to_vec();
    let backend = start_malicious_response_header_backend(malformed);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let status = parse_status(&raw);

    assert!(
        status == 502 || status == 400 || status == 200 || status == 0,
        "Set-Cookie CRLF injection must be handled safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    let lower = raw.to_lowercase();
    assert!(
        !lower.contains("set-cookie: injected=1"),
        "injected Set-Cookie must not reach the client: {raw}"
    );
}

#[test]
fn upstream_response_control_characters_in_headers_rejected() {
    // Literal CTL bytes (excluding HTAB/CR/LF) in a response header value.
    let mut malformed = b"X-Ctl: before".to_vec();
    for b in [0x01_u8, 0x07, 0x0e, 0x1f] {
        malformed.push(b);
    }
    malformed.extend_from_slice(b"after");

    let backend = start_malicious_response_header_backend(malformed);
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let (status, _) = http_get(proxy.addr(), "/", None);

    assert!(
        status == 502 || status == 400 || status == 200 || status == 0,
        "CTL bytes in upstream response headers must be handled safely (got {status})"
    );
    assert_ne!(status, 500, "must not crash with 500");

    if status == 200 {
        // Re-fetch raw to inspect header bytes if the proxy sanitized rather than rejected.
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        let value = parse_header(&raw, "x-ctl").unwrap_or_default();
        assert!(
            !value.bytes().any(|b| (0x01..=0x08).contains(&b) || (0x0e..=0x1f).contains(&b)),
            "CTL bytes must not be forwarded unmodified in X-Ctl: {value:?}"
        );
    }
}
