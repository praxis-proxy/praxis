// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the Maglev load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{free_port, http_send, parse_body, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn maglev() {
    let port_a_guard = start_backend_with_shutdown("mg-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("mg-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("mg-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/maglev.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    // Affinity: the same header value pins to the same backend.
    let mut first_body = None;
    for _ in 0..6 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-User-Id: user-42\r\n\
             Connection: close\r\n\r\n",
        );
        let body = parse_body(&raw);
        match &first_body {
            None => first_body = Some(body),
            Some(expected) => assert_eq!(&body, expected, "Maglev should pin user-42 to the same backend"),
        }
    }

    // Distribution: distinct header values reach all backends.
    let mut backends_seen = HashSet::new();
    for i in 0..30 {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "GET / HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 X-User-Id: user-{i}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        backends_seen.insert(parse_body(&raw));
    }
    assert_eq!(
        backends_seen.len(),
        3,
        "30 distinct user IDs should reach all 3 backends, got {}: {:?}",
        backends_seen.len(),
        backends_seen
    );

    // Fallback: with no X-User-Id header, Maglev hashes on the URI path, so
    // repeated requests to the same path still pin to a single backend.
    let mut path_body = None;
    for _ in 0..6 {
        let raw = http_send(
            proxy.addr(),
            "GET /catalog HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n",
        );
        let body = parse_body(&raw);
        match &path_body {
            None => path_body = Some(body),
            Some(expected) => assert_eq!(&body, expected, "absent header should pin by URI path to one backend"),
        }
    }
}
