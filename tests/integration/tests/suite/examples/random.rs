// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for random load balancing behavior.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn random_distributes_across_backends() {
    let port_a_guard = start_backend_with_shutdown("random-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("random-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("random-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/random.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    let total = 30_u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "random request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "random should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (4..=16).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}
