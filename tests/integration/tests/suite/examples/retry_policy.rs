// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for retry-policy example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

#[test]
fn retry_policy() {
    let healthy_guard = start_backend_with_shutdown("healthy");
    let healthy_port = healthy_guard.port();
    let proxy_port = free_port();
    let dead_port = free_port();

    let config = super::load_example_config(
        "traffic-management/retry-policy.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", dead_port), ("127.0.0.1:3002", healthy_port)]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "retry should recover from dead backend");
    assert_eq!(body, "healthy", "response should come from healthy backend");
}
