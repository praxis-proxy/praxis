// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for path-based routing behavior.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn path_based_routing() {
    let api_port_guard = start_backend_with_shutdown("api");
    let api_port = api_port_guard.port();
    let static_port_guard = start_backend_with_shutdown("static");
    let static_port = static_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/path-based-routing.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api_port),
            ("127.0.0.1:3002", api_port),
            ("127.0.0.1:3003", api_port),
            ("127.0.0.1:4000", static_port),
            ("127.0.0.1:5000", default_port),
        ]),
    );
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/api/users", None);
    assert_eq!(status, 200, "/api/ path should return 200");
    assert_eq!(body, "api", "/api/ should route to api backend");
    let (status, body) = http_get(proxy.addr(), "/static/index.html", None);
    assert_eq!(status, 200, "/static/ path should return 200");
    assert_eq!(body, "static", "/static/ should route to static backend");
    let (status, body) = http_get(proxy.addr(), "/other", None);
    assert_eq!(status, 200, "default path should return 200");
    assert_eq!(body, "default", "unmatched path should route to default backend");
}
