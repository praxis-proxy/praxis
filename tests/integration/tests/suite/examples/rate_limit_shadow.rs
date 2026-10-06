// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional integration tests for the rate-limiting-shadow example
//! configuration.

use std::{collections::HashMap, time::Duration};

use praxis_test_utils::{
    free_port, http_get, http_send, parse_header, parse_status, start_backend_with_shutdown, start_full_proxy,
    wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn rate_limiting_shadow_example_allows_everything_and_counts_would_be_rejections() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let metrics_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting-shadow.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9901", metrics_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    let proxy = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy);
    let metrics = format!("127.0.0.1:{metrics_port}");
    wait_for_tcp(&metrics);

    let mut drained = false;
    for i in 0..10 {
        let raw = http_send(&proxy, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert_eq!(
            parse_status(&raw),
            200,
            "shadow example should never reject (request {i})"
        );
        drained |= parse_header(&raw, "x-ratelimit-remaining").as_deref() == Some("0");
    }
    assert!(
        drained,
        "responses should report the drained bucket in X-RateLimit-Remaining"
    );

    let series = "praxis_rate_limit_limited_total{shadow=\"true\"}";
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    while std::time::Instant::now() < deadline {
        let (status, scrape) = http_get(&metrics, "/metrics", None);
        assert_eq!(status, 200, "/metrics should return 200");
        body = scrape;
        if body.contains(series) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains(series),
        "metrics should count the would-be rejections under shadow=\"true\": {body}"
    );
}
