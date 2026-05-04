// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the hostname upstream example configuration.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn hostname_upstream_routes_to_backend() {
    let backend_port_guard = start_backend_with_shutdown("hostname-backend");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/hostname-upstream.yaml",
        proxy_port,
        HashMap::from([("localhost:9000", backend_port)]),
    );
    let proxy = praxis_test_utils::start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "hostname upstream example should return 200");
    assert_eq!(body, "hostname-backend", "proxy should forward to hostname upstream");
}
