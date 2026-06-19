// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tests for virtual host behavior.

use std::collections::HashMap;

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn virtual_hosts() {
    let api_port_guard = start_backend_with_shutdown("api-host");
    let api_port = api_port_guard.port();
    let web_port_guard = start_backend_with_shutdown("web-host");
    let web_port = web_port_guard.port();
    let default_port_guard = start_backend_with_shutdown("default-host");
    let default_port = default_port_guard.port();
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/hosts.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3001", api_port),
            ("127.0.0.1:3002", api_port),
            ("127.0.0.1:4000", web_port),
            ("127.0.0.1:5000", default_port),
        ]),
    );
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", Some("api.example.com"));
    assert_eq!(status, 200, "api.example.com should return 200");
    assert_eq!(body, "api-host", "api.example.com should route to api backend");
    let (status, body) = http_get(proxy.addr(), "/", Some("www.example.com"));
    assert_eq!(status, 200, "www.example.com should return 200");
    assert_eq!(body, "web-host", "www.example.com should route to web backend");
    let (status, body) = http_get(proxy.addr(), "/", Some("unknown.example.com"));
    assert_eq!(status, 200, "unknown host should return 200");
    assert_eq!(body, "default-host", "unknown host should route to default backend");
}
