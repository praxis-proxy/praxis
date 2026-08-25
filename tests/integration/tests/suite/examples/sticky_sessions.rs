// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for cookie-based sticky sessions.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_send, parse_body, parse_header_all, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn sticky_sessions_cookie_pins_to_same_backend() {
    let port_a_guard = start_backend_with_shutdown("ss-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("ss-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("ss-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            // The example config declares three listeners; remap the two this
            // test does not exercise to free ports so the proxy does not bind
            // the literal 8081/8082 (an EADDRINUSE flake under concurrency).
            ("127.0.0.1:8081", free_port()),
            ("127.0.0.1:8082", free_port()),
        ]),
    );
    let proxy = start_proxy(&config);

    // First request — should get a Set-Cookie header.
    let raw = http_send(
        proxy.addr(),
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    let set_cookies = parse_header_all(&raw, "set-cookie");
    let set_cookie = set_cookies
        .first()
        .expect("first response should contain Set-Cookie header");
    assert!(
        set_cookie.contains("_praxis_sticky="),
        "Set-Cookie should contain the configured cookie name, got: {set_cookie}"
    );

    // Extract cookie value for subsequent requests.
    let cookie_val = set_cookie.split(';').next().unwrap_or_default().trim();

    // Subsequent requests with the cookie should always reach the same backend.
    for _ in 0..5 {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Cookie: {cookie_val}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        let body = parse_body(&raw);
        assert_eq!(
            body, first_body,
            "cookie-pinned requests must always route to the same backend"
        );
    }
}

#[test]
fn sticky_sessions_header_pins_to_same_backend() {
    let port_a_guard = start_backend_with_shutdown("hdr-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("hdr-b");
    let port_b = port_b_guard.port();
    let proxy_port = free_port();
    let header_port = free_port();
    let learn_a = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8081", header_port),
            ("127.0.0.1:8082", free_port()),
            ("127.0.0.1:3011", port_a),
            ("127.0.0.1:3012", port_b),
            ("127.0.0.1:3021", learn_a),
            ("127.0.0.1:3022", learn_a),
        ]),
    );
    let proxy = start_proxy(&config);
    let header_addr = format!("127.0.0.1:{header_port}");

    // First request with a session header establishes the binding.
    let raw = http_send(
        &header_addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         X-Session-Id: user-42\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    assert!(
        first_body == "hdr-a" || first_body == "hdr-b",
        "request should reach a backend, got: {first_body}"
    );

    for _ in 0..5 {
        let raw = http_send(
            &header_addr,
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-Session-Id: user-42\r\n\
             Connection: close\r\n\r\n",
        );
        assert_eq!(
            parse_body(&raw),
            first_body,
            "header-keyed requests must always route to the same backend"
        );
    }

    drop(proxy);
}

/// Minimal backend that tags responses with `body` and sets a session cookie,
/// as an application server with server-side sessions would.
fn start_cookie_setting_backend(body: &'static str, session_id: &'static str) -> u16 {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0_u8; 4096];
            let _read = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Set-Cookie: JSESSIONID={session_id}; Path=/\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _sent = stream.write_all(response.as_bytes());
        }
    });
    port
}

#[test]
fn sticky_sessions_learn_mode_adopts_backend_cookie() {
    let port_a = start_cookie_setting_backend("learn-a", "sess-from-a");
    let port_b = start_cookie_setting_backend("learn-b", "sess-from-b");
    let proxy_port = free_port();
    let learn_port = free_port();
    let config = super::load_example_config(
        "traffic-management/sticky-sessions.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8081", free_port()),
            ("127.0.0.1:8082", learn_port),
            ("127.0.0.1:3011", port_a),
            ("127.0.0.1:3012", port_b),
            ("127.0.0.1:3021", port_a),
            ("127.0.0.1:3022", port_b),
        ]),
    );
    let proxy = start_proxy(&config);
    let learn_addr = format!("127.0.0.1:{learn_port}");

    // First request: backend issues its session cookie and the proxy learns
    // the binding.
    let raw = http_send(
        &learn_addr,
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\r\n",
    );
    let first_body = parse_body(&raw);
    let set_cookie = parse_header_all(&raw, "set-cookie")
        .into_iter()
        .find(|v| v.contains("JSESSIONID="))
        .expect("backend Set-Cookie should pass through");
    let cookie_val = set_cookie.split(';').next().unwrap_or_default().trim().to_owned();

    // Replaying the learned cookie must keep hitting the same backend.
    for _ in 0..5 {
        let raw = http_send(
            &learn_addr,
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Cookie: {cookie_val}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        assert_eq!(
            parse_body(&raw),
            first_body,
            "learned session must pin to the backend that issued the cookie"
        );
    }

    drop(proxy);
}
