// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the hedged-requests example configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, start_slow_backend};

#[test]
fn hedged_request_returns_the_faster_endpoint() {
    let slow_port = start_slow_backend("slow", Duration::from_millis(800));
    let fast = start_backend_with_shutdown("fast");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/hedged-requests.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", slow_port), ("127.0.0.1:3002", fast.port())]),
    );
    let proxy = start_full_proxy(&config);

    for _ in 0..2 {
        let started = std::time::Instant::now();
        let (status, body) = http_get(proxy.addr(), "/", None);
        assert_eq!(status, 200, "the hedged request should succeed");
        assert_eq!(
            body, "fast",
            "the faster endpoint should win whichever endpoint is primary"
        );
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "the copy should answer before the slow primary"
        );
    }
}
