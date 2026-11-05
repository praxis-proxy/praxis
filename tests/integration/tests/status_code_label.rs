// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Functional test for the `status-code-label.yaml` example (#1350).
//!
//! The opt-in `status_code` dimension is installed once into a process-global
//! `OnceLock`, for the same reason the rest of the label set is: a gauge guard
//! acquired before a change and released after it would increment one series
//! and decrement another. That makes it untestable inside the shared `suite`
//! process, where every other test expects the default label set, so this
//! example's functional test runs as its own test binary alongside
//! `metric_labels.rs`.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::panic,
    clippy::print_stderr,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "test code"
)]

use std::{collections::HashMap, time::Duration};

use praxis_core::config::{MetricLabel, MetricLabelsConfig};
use praxis_test_utils::{free_port, http_get, load_example_config, start_full_proxy, wait_for_tcp};

/// The example config under test.
const EXAMPLE: &str = "observability/status-code-label.yaml";

/// Scrape `/metrics` until `needle` shows up, or the deadline passes.
fn scrape(admin: &str, needle: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (status, body) = http_get(admin, "/metrics", None);
        assert_eq!(status, 200, "/metrics should return 200");
        last = body;
        if last.contains(needle) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

/// Every `praxis_http_requests_total` sample line in a scrape.
fn request_counter_lines(scraped: &str) -> Vec<&str> {
    scraped
        .lines()
        .filter(|line| line.starts_with("praxis_http_requests_total{"))
        .collect()
}

#[test]
fn opt_in_status_code_splits_the_4xx_series() {
    // Installed before any metric is recorded, and only once per process.
    praxis_protocol::http::pingora::metrics::install_metric_labels(MetricLabelsConfig {
        disabled: vec![],
        enabled: vec![MetricLabel::StatusCode],
    });

    let backend = praxis_test_utils::start_backend_with_shutdown("status-code");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = load_example_config(
        EXAMPLE,
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9903", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    let proxy = format!("127.0.0.1:{proxy_port}");
    wait_for_tcp(&proxy);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    // A routed request the backend answers.
    let (status, body) = http_get(&proxy, "/api/hello", None);
    assert_eq!(status, 200, "the routed path should reach the backend");
    assert_eq!(body, "status-code", "the backend response should be forwarded");

    // A path no route matches: the router rejects it with 404.
    let (status, _) = http_get(&proxy, "/missing", None);
    assert_eq!(status, 404, "an unmatched path should be rejected with 404");

    // Drain the token bucket until the rate limiter answers 429. Both this
    // and the 404 above are 4xx, which is exactly the pair that shares one
    // series without the new dimension.
    let mut saw_rate_limit = false;
    for _ in 0..20 {
        let (status, _) = http_get(&proxy, "/api/hello", None);
        if status == 429 {
            saw_rate_limit = true;
            break;
        }
    }
    assert!(saw_rate_limit, "the example's rate limit should produce a 429");

    let scraped = scrape(&admin, r#"status_code="429""#);
    let counters = request_counter_lines(&scraped);
    assert!(
        !counters.is_empty(),
        "the request counter should be emitted:\n{scraped}"
    );

    for code in ["404", "429"] {
        assert!(
            counters
                .iter()
                .any(|line| line.contains(&format!(r#"status_code="{code}""#))),
            "each allowlisted code should get its own series, {code} is missing:\n{scraped}"
        );
    }

    // 200 is not on the allowlist: a success carries no filter-level detail
    // worth a series of its own, so it collapses to its class.
    assert!(
        counters.iter().any(|line| line.contains(r#"status_code="2xx""#)),
        "an unlisted code should collapse to its class rather than mint a series:\n{scraped}"
    );
    assert!(
        !counters.iter().any(|line| line.contains(r#"status_code="200""#)),
        "200 is off the allowlist and must not appear verbatim:\n{scraped}"
    );

    // The aggregated dimension is untouched, so existing 4xx queries still work.
    assert!(
        counters.iter().any(|line| line.contains(r#"status_class="4xx""#)),
        "status_class must stay alongside the exact code:\n{scraped}"
    );
    assert!(
        counters.iter().any(|line| line.contains(r#"status_class="2xx""#)),
        "the success series keeps its class too:\n{scraped}"
    );

    // The 404 and the 429 are now distinct series rather than one 4xx tally.
    let four_xx: Vec<&&str> = counters
        .iter()
        .filter(|line| line.contains(r#"status_class="4xx""#))
        .collect();
    assert!(
        four_xx.len() >= 2,
        "the 4xx class should span more than one series once split by code:\n{scraped}"
    );

    // The duration distribution renders as a summary, whose quantiles cannot
    // be aggregated back across a label, so it must not carry the dimension.
    for line in scraped
        .lines()
        .filter(|line| line.starts_with("praxis_http_request_duration_seconds"))
    {
        assert!(
            !line.contains("status_code="),
            "the duration summary must not be split by status code:\n{line}"
        );
    }
}
