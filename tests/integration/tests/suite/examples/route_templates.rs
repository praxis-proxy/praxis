// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the route-templates example
//! configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn route_templates_example_collapses_dynamic_segments() {
    let backend = start_backend_with_shutdown("templated-example");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/route-templates.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    for id in ["42", "99"] {
        let (status, _) = http_get(&format!("127.0.0.1:{proxy_port}"), &format!("/users/{id}/orders"), None);
        assert_eq!(status, 200, "example config should proxy successfully");
    }

    let needle = "route=\"/users/{id}/orders\"";
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (code, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(code, 200, "/metrics should return 200");
        body = scrape;
        if body.contains(needle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains(needle),
        "metrics should carry the templated route label: {body}"
    );
    for id in ["42", "99"] {
        assert!(
            !body.contains(&format!("route=\"/users/{id}/orders\"")),
            "raw path for id {id} must not appear as a label value: {body}"
        );
    }
}

#[test]
fn route_templates_example_forwards_traffic() {
    let backend = start_backend_with_shutdown("templated-payload");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/route-templates.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{proxy_port}"), "/users/7", None);
    assert_eq!(status, 200, "example config should proxy successfully");
    assert_eq!(
        body, "templated-payload",
        "route-templates example should forward to the backend"
    );
}
