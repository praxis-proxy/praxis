// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the subset load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{free_port, http_send, parse_body, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn subset_lb() {
    let port_a_guard = start_backend_with_shutdown("sub-stable");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("sub-canary-1");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("sub-canary-2");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/subset-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    // Subset routing: only canary endpoints should receive traffic.
    let mut backends_seen = HashSet::new();
    for _ in 0..20 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Connection: close\r\n\r\n",
        );
        backends_seen.insert(parse_body(&raw));
    }

    assert!(
        !backends_seen.contains("sub-stable"),
        "stable endpoint should not receive traffic when subset selector matches canary"
    );
    assert!(
        backends_seen.contains("sub-canary-1") || backends_seen.contains("sub-canary-2"),
        "at least one canary endpoint should receive traffic"
    );
}
