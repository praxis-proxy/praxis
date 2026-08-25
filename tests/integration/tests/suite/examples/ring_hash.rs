// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the ring-hash load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{free_port, http_send, parse_body, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn ring_hash() {
    let port_a_guard = start_backend_with_shutdown("rh-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("rh-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("rh-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/ring-hash.yaml",
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
             X-Session-Id: sess-42\r\n\
             Connection: close\r\n\r\n",
        );
        let body = parse_body(&raw);
        match &first_body {
            None => first_body = Some(body),
            Some(expected) => assert_eq!(&body, expected, "ring-hash should pin sess-42 to the same backend"),
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
                 X-Session-Id: sess-{i}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        backends_seen.insert(parse_body(&raw));
    }
    // Backends map to random free ports each run, so ring placement varies;
    // requiring all 3 of 3 has a small but nonzero miss chance. Assert the ring
    // spreads across multiple backends (not all pinned to one); the exact
    // per-key pinning is covered deterministically above.
    assert!(
        backends_seen.len() >= 2,
        "30 distinct session IDs should spread across multiple backends, got {}: {:?}",
        backends_seen.len(),
        backends_seen
    );
}
