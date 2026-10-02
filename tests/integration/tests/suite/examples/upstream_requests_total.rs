// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the upstream-requests-total example
//! configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn upstream_requests_total_example_emits_counter() {
    let backend = start_backend_with_shutdown("upstream-example");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/upstream-requests-total.yaml",
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

    let (status, _) = http_get(&format!("127.0.0.1:{proxy_port}"), "/api/hello", None);
    assert_eq!(status, 200, "example config should proxy successfully");

    let endpoint = format!("endpoint=\"127.0.0.1:{}\"", backend.port());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (code, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(code, 200, "/metrics should return 200");
        body = scrape;
        if body.contains(&endpoint) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for needle in [
        "praxis_upstream_requests_total",
        "cluster=\"backend\"",
        "status_class=\"2xx\"",
        endpoint.as_str(),
    ] {
        assert!(body.contains(needle), "metrics should contain `{needle}`: {body}");
    }
}

#[test]
fn upstream_requests_total_example_forwards_traffic() {
    let backend = start_backend_with_shutdown("upstream-payload");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/upstream-requests-total.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{proxy_port}"), "/api/hello", None);
    assert_eq!(status, 200, "example config should proxy successfully");
    assert_eq!(
        body, "upstream-payload",
        "upstream-requests-total example should forward to the backend"
    );
}
