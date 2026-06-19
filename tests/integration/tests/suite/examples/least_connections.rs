// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for least-connections load balancing behavior.

use std::{collections::HashMap, thread, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy, start_slow_backend};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn least_connections() {
    let port_a_guard = start_backend_with_shutdown("lc-a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("lc-b");
    let port_b = port_b_guard.port();
    let port_c_guard = start_backend_with_shutdown("lc-c");
    let port_c = port_c_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/least-connections.yaml",
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
        assert_eq!(status, 200, "least-conn request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "least-conn should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (7..=13).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}

#[test]
fn least_connections_concurrent() {
    let delay = Duration::from_millis(200);
    let port_a = start_slow_backend("lc-a", delay);
    let port_b = start_slow_backend("lc-b", delay);
    let port_c = start_slow_backend("lc-c", delay);
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/least-connections.yaml",
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
        assert_eq!(status, 200, "concurrent least-conn request should return 200");
        *counts.entry(body).or_default() += 1;
    }

    assert_eq!(counts.len(), 3, "concurrent least-conn should use all 3 backends");

    for (backend, count) in &counts {
        assert!(
            (7..=13).contains(count),
            "expected ~10 for backend {backend}, got {count}"
        );
    }
}
