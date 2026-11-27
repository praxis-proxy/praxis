// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Status code label example: the opt-in `status_code` dimension splits the
//! `4xx` series that a rate limit and a missing route used to share (#1350).
//!
//! The label set is installed once per process, from `metrics.labels`, by the
//! server's own startup path. So this runs the real binary on the example
//! config rather than building a runtime in-process and installing the labels
//! itself: the example YAML is the only thing that turns the dimension on, and
//! a test that reaches past the startup path could not prove that.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use praxis_core::config::{Config, MetricLabel};
use praxis_test_utils::{
    PraxisProcess, allow_loopback_endpoints, example_config_path, free_port, http_get, patch_yaml,
    start_backend_with_shutdown, wait_for_tcp,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The example under test.
const EXAMPLE: &str = "observability/status-code-label.yaml";

/// How long a scrape may take to show a newly recorded series.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
#[cfg_attr(
    coverage,
    ignore = "spawns the praxis binary; deadlocks on exit under llvm-cov instrumentation"
)]
fn status_code_label_example_splits_the_4xx_series() {
    let backend = start_backend_with_shutdown("status-code");
    let (port, admin) = (free_port(), free_port());
    let proxy = PraxisProcess::spawn(&example_yaml(port, admin, backend.port()), &addr(port));
    let admin_addr = addr(admin);
    wait_for_tcp(&admin_addr);

    // A routed request the backend answers.
    let (status, body) = http_get(&addr(port), "/api/hello", None);
    assert_eq!(status, 200, "the routed path should reach the backend");
    assert_eq!(body, "status-code", "the backend response should be forwarded");

    // A path no route matches: the router rejects it with 404.
    let (status, _) = http_get(&addr(port), "/missing", None);
    assert_eq!(status, 404, "an unmatched path should be rejected with 404");

    // Drain the token bucket until the rate limiter answers 429. Both this
    // and the 404 above are 4xx, which is exactly the pair that shares one
    // series without the new dimension.
    let saw_rate_limit = (0..20).any(|_| http_get(&addr(port), "/api/hello", None).0 == 429);
    assert!(
        saw_rate_limit,
        "the example's rate limit should produce a 429:\n{}",
        proxy.logs()
    );

    let scraped = scrape_until(&admin_addr, r#"status_code="429""#);
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
    let four_xx = counters
        .iter()
        .filter(|line| line.contains(r#"status_class="4xx""#))
        .count();
    assert!(
        four_xx >= 2,
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

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example on test ports, with a shutdown window short enough for the
/// SIGTERM that ends the test.
///
/// The opt-in is asserted on the parsed config rather than matched as text, so
/// the test fails if the example drops its `enabled` block instead of silently
/// measuring a dimension nothing turned on.
fn example_yaml(port: u16, admin: u16, backend: u16) -> String {
    let yaml = std::fs::read_to_string(example_config_path(EXAMPLE)).expect("read example");
    let ports = HashMap::from([("127.0.0.1:9903", admin), ("127.0.0.1:3000", backend)]);
    let patched = format!(
        "shutdown_timeout_secs: 1\n{}",
        allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports))
    );
    let config = Config::from_yaml(&patched).expect("parse example");
    assert!(
        config.metrics.labels.is_enabled(MetricLabel::StatusCode),
        "the example must opt into the status_code dimension"
    );
    patched
}

/// Loopback address for `port`.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Scrape `/metrics` until `needle` shows up, or the deadline passes.
fn scrape_until(admin: &str, needle: &str) -> String {
    let deadline = Instant::now() + SCRAPE_TIMEOUT;
    let mut last = String::new();
    while Instant::now() < deadline {
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
