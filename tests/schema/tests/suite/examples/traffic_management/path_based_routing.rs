// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Path-based routing example tests.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get_retry, start_backend, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn path_based_routing() {
    let api_port = start_backend("api");
    let static_port = start_backend("static");
    let default_port = start_backend("default");
    let proxy_port = free_port();
    let config = crate::example_utils::load_example_config(
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
    let (status, body) = http_get_retry(proxy.addr(), "/api/users", None);
    assert_eq!(status, 200, "/api/ path should return 200");
    assert_eq!(body, "api", "/api/ should route to api backend");
    let (status, body) = http_get_retry(proxy.addr(), "/static/index.html", None);
    assert_eq!(status, 200, "/static/ path should return 200");
    assert_eq!(body, "static", "/static/ should route to static backend");
    let (status, body) = http_get_retry(proxy.addr(), "/other", None);
    assert_eq!(status, 200, "default path should return 200");
    assert_eq!(body, "default", "unmatched path should route to default backend");
}
