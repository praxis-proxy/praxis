// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! [RFC 6455] WebSocket Protocol conformance tests.
//!
//! Verifies proxy behavior for WebSocket upgrade handshakes.
//! A conforming proxy must transparently forward all handshake
//! headers between client and server without modification.
//!
//! [RFC 6455]: https://datatracker.ietf.org/doc/html/rfc6455

use std::time::Duration;

use praxis_core::config::Config;
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, simple_proxy_yaml, start_header_echo_backend,
    start_proxy,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// RFC 6455 Section 4.2.2 example key (base64-encoded nonce).
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Sec-WebSocket-Accept value corresponding to [`WS_KEY`],
/// computed per RFC 6455 Section 4.2.2.
const WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// -----------------------------------------------------------------------------
// RFC 6455 Section 4.1 - Client-Side Requirements
// -----------------------------------------------------------------------------

/// [RFC 6455 Section 4.1]: the proxy MUST forward the
/// `Upgrade: websocket` header to the upstream server.
/// Without it the server cannot recognize the request as
/// a WebSocket opening handshake.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
#[test]
fn rfc6455_upgrade_header_forwarded() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let status = parse_status(&raw);
    let body = parse_body(&raw);

    assert_eq!(status, 200, "header echo backend should return 200");
    assert!(
        body.to_lowercase().contains("upgrade: websocket"),
        "Upgrade: websocket must be forwarded to upstream (RFC 6455 S4.1); echoed: {body}"
    );
}

/// [RFC 6455 Section 4.1]: the proxy MUST forward the
/// `Connection: Upgrade` header. Although `Connection` is
/// normally hop-by-hop, an upgrade request requires it to
/// reach the upstream so the protocol switch can proceed.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
#[test]
fn rfc6455_connection_upgrade_forwarded() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let body = parse_body(&raw);
    let lower = body.to_lowercase();

    assert!(
        lower.contains("upgrade"),
        "Connection: Upgrade must be forwarded for WebSocket requests (RFC 6455 S4.1); echoed: {body}"
    );
}

/// [RFC 6455 Section 4.1]: the `Sec-WebSocket-Key` nonce
/// MUST be forwarded verbatim. The server uses this exact
/// value to compute `Sec-WebSocket-Accept`; any modification
/// breaks the handshake.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
#[test]
fn rfc6455_sec_websocket_key_forwarded_unchanged() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let body = parse_body(&raw);

    assert!(
        body.contains(WS_KEY),
        "Sec-WebSocket-Key must be forwarded unchanged (RFC 6455 S4.1); echoed: {body}"
    );
}

/// [RFC 6455 Section 4.1]: the `Sec-WebSocket-Version: 13`
/// header MUST be forwarded so the upstream knows which
/// protocol version the client requests.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
#[test]
fn rfc6455_sec_websocket_version_forwarded() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let body = parse_body(&raw);

    assert!(
        body.to_lowercase().contains("sec-websocket-version: 13"),
        "Sec-WebSocket-Version: 13 must be forwarded to upstream (RFC 6455 S4.1); echoed: {body}"
    );
}

// -----------------------------------------------------------------------------
// RFC 6455 Section 4.2.1 - Server-Side Requirements
// -----------------------------------------------------------------------------

/// [RFC 6455 Section 4.2.1]: the proxy MUST forward the
/// server's `101 Switching Protocols` response to the client
/// with `Upgrade: websocket` and `Connection: Upgrade`
/// headers intact.
///
/// [RFC 6455 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.1
#[test]
fn rfc6455_101_response_forwarded() {
    let backend_port = start_ws_handshake_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let status = parse_status(&raw);
    let upgrade = parse_header(&raw, "upgrade");
    let connection = parse_header(&raw, "connection");

    assert_eq!(
        status, 101,
        "proxy must forward 101 Switching Protocols (RFC 6455 S4.2.1), got {status}"
    );
    assert!(
        upgrade.is_some_and(|u| u.to_lowercase() == "websocket"),
        "response must include Upgrade: websocket (RFC 6455 S4.2.1)"
    );
    assert!(
        connection.is_some_and(|c| c.to_lowercase().contains("upgrade")),
        "response must include Connection: Upgrade (RFC 6455 S4.2.1)"
    );
}

/// [RFC 6455 Section 4.2.1]: the proxy MUST forward the
/// `Sec-WebSocket-Accept` header unchanged. The client uses
/// this value to verify the server received the correct
/// `Sec-WebSocket-Key`.
///
/// [RFC 6455 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.1
#[test]
fn rfc6455_sec_websocket_accept_forwarded_unchanged() {
    let backend_port = start_ws_handshake_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        &format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {WS_KEY}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        ),
    );
    let accept = parse_header(&raw, "sec-websocket-accept");

    assert_eq!(
        accept.as_deref(),
        Some(WS_ACCEPT),
        "Sec-WebSocket-Accept must be forwarded unchanged (RFC 6455 S4.2.1)"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Start a backend that performs a minimal WebSocket handshake:
/// responds with `101 Switching Protocols` and the required
/// upgrade headers, then closes the connection.
fn start_ws_handshake_backend() -> u16 {
    let (listener, port) = praxis_test_utils::net::port::bind_unique_port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                handle_ws_handshake(stream);
            });
        }
    });
    port
}

/// Handle a single WebSocket handshake connection: read the
/// request headers, respond with 101 and known accept value,
/// then close.
fn handle_ws_handshake(mut stream: std::net::TcpStream) {
    use std::io::{Read as _, Write as _};

    drop(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut buf = [0_u8; 4096];
    let _bytes = stream.read(&mut buf);

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {WS_ACCEPT}\r\n\
         \r\n"
    );
    let _sent = stream.write_all(response.as_bytes());
    let _flushed = stream.flush();
}
