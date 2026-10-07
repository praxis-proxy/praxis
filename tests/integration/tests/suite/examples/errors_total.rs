// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the errors-total example
//! configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{free_port, http_get, start_backend_with_shutdown, start_full_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn errors_total_example_counts_unreachable_upstreams() {
    let backend = start_backend_with_shutdown("errors-example");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/errors-total.yaml",
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

    let (status, _) = http_get(&format!("127.0.0.1:{proxy_port}"), "/broken/thing", None);
    assert_ne!(status, 200, "the unreachable cluster should not return 200");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (code, scrape) = http_get(&admin, "/metrics", None);
        assert_eq!(code, 200, "/metrics should return 200");
        body = scrape;
        if body.contains("praxis_errors_total{type=\"upstream_unavailable\"}") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains("praxis_errors_total{type=\"upstream_unavailable\"}"),
        "metrics should contain an upstream_unavailable error: {body}"
    );
}

#[test]
fn errors_total_example_forwards_traffic() {
    let backend = start_backend_with_shutdown("errors-allowed");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = super::load_example_config(
        "observability/errors-total.yaml",
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
    assert_eq!(status, 200, "traffic outside /broken/ should proxy normally");
    assert_eq!(
        body, "errors-allowed",
        "errors-total example should forward healthy traffic"
    );
}
