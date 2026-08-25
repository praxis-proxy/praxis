// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for the priority-level load-balancing example config.

use std::collections::{HashMap, HashSet};

use praxis_test_utils::{free_port, http_send, parse_body, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn priority_lb() {
    let port_a_guard = start_backend_with_shutdown("pri-primary-1");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("pri-primary-2");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("pri-failover-1");
    let port_c = port_c_guard.port();
    let port_d_guard = start_backend_with_shutdown("pri-failover-2");
    let port_d = port_d_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/priority-lb.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
            ("127.0.0.1:3004", port_d),
        ]),
    );
    let proxy = start_proxy(&config);

    // Without health issues, only primary-tier endpoints should be used.
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
        backends_seen.contains("pri-primary-1") || backends_seen.contains("pri-primary-2"),
        "primary-tier endpoints should receive traffic"
    );
    assert!(
        !backends_seen.contains("pri-failover-1") && !backends_seen.contains("pri-failover-2"),
        "failover-tier endpoints should not receive traffic when primary is healthy"
    );
}
