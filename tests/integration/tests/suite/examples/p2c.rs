// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for P2C (power-of-two-choices) load balancing behavior.

use std::{collections::HashMap, thread, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, start_slow_backend};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn p2c_distributes_across_backends() {
    let port_a_guard = start_backend_with_shutdown("p2c-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("p2c-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("p2c-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/p2c.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    let total = 30u32;
    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..total {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "p2c request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "p2c should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (4..=16).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}

#[test]
fn p2c_prefers_less_loaded_under_concurrency() {
    let delay = Duration::from_millis(200);
    let port_a = start_slow_backend("p2c-a", delay);
    let port_b = start_slow_backend("p2c-b", delay);
    let port_c = start_slow_backend("p2c-c", delay);
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/p2c.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", port_a),
            ("127.0.0.1:3002", port_b),
            ("127.0.0.1:3003", port_c),
        ]),
    );
    let proxy = start_proxy(&config);

    let total = 30;
    let addr = proxy.addr().to_owned();
    let handles: Vec<_> = (0..total)
        .map(|_| {
            let addr = addr.clone();
            thread::spawn(move || http_get(&addr, "/", None))
        })
        .collect();

    let mut counts: HashMap<String, u32> = HashMap::new();
    for handle in handles {
        let (status, body) = handle.join().expect("request thread panicked");
        assert_eq!(status, 200, "concurrent p2c request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "concurrent p2c should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (4..=16).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}
