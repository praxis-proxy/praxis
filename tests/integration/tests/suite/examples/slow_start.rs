// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Slow start example: the config is accepted and baseline endpoints still serve.

#[cfg(feature = "slow-start")]
use std::collections::HashMap;

#[cfg(feature = "slow-start")]
use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(feature = "slow-start")]
#[test]
fn slow_start_config_serves_the_baseline_endpoints() {
    let port_a_guard = start_backend_with_shutdown("a");
    let port_a = port_a_guard.port();
    let port_b_guard = start_backend_with_shutdown("b");
    let port_b = port_b_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/slow-start.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", port_a), ("127.0.0.1:3002", port_b)]),
    );
    let proxy = start_proxy(&config);

    let mut seen: HashMap<String, u32> = HashMap::new();
    for _ in 0..4 {
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "slow start config should proxy the request");
        *seen.entry(body).or_default() += 1;
    }
    assert_eq!(seen.len(), 2, "baseline endpoints stay in rotation");
}
