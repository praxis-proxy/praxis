// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the http-active-requests example
//! configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn http_active_requests_example_emits_gauge() {
    let backend = start_backend_with_shutdown("inflight-example");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/http-active-requests.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    wait_for_tcp(&format!("127.0.0.1:{admin_port}"));

    let (status, _) = http_get(&format!("127.0.0.1:{proxy_port}"), "/", None);
    assert_eq!(status, 200, "example config should proxy successfully");

    let admin = format!("127.0.0.1:{admin_port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (code, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(code, 200, "/metrics should return 200");
        body = scrape;
        if body.contains("praxis_http_active_requests{") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains("praxis_http_active_requests"),
        "metrics should contain praxis_http_active_requests gauge: {body}"
    );
    assert!(
        body.contains("listener=\"web\""),
        "metrics should contain listener=web label: {body}"
    );
}

#[test]
fn http_active_requests_example_forwards_traffic() {
    let backend = start_backend_with_shutdown("inflight-payload");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/http-active-requests.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9902", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));

    let (status, body) = http_get(&format!("127.0.0.1:{proxy_port}"), "/", None);
    assert_eq!(status, 200, "example config should proxy successfully");
    assert_eq!(
        body, "inflight-payload",
        "http-active-requests example should forward to the backend"
    );
}
