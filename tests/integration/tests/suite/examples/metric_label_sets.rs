// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Metric label sets example: a disabled dimension disappears from every
//! metric that carries it, and the metrics themselves stay available (#1033).
//!
//! The label set is installed once per process, from `metrics.labels`, by the
//! server's own startup path, so this runs the real binary on the example
//! config rather than building a runtime in-process and installing the label
//! set itself: the YAML is what drops the dimensions, and a test that reaches
//! past the startup path could not prove that.

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
const EXAMPLE: &str = "observability/metric-label-sets.yaml";

/// The last dimension the example disables, and so where the test appends
/// its own.
const LAST_DISABLED: &str = "      - endpoint\n";

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
fn metric_label_sets_example_drops_the_disabled_dimensions() {
    let backend = start_backend_with_shutdown("label-sets");
    let (port, admin) = (free_port(), free_port());
    let proxy = PraxisProcess::spawn(&example_yaml(port, admin, backend.port()), &addr(port));
    let admin_addr = addr(admin);
    wait_for_tcp(&admin_addr);

    let (status, body) = http_get(&addr(port), "/api/hello", None);
    assert_eq!(status, 200, "example config should proxy successfully");
    assert_eq!(body, "label-sets", "example config should forward to the backend");

    let scraped = scrape_until(&admin_addr, "praxis_http_requests_total");
    assert!(
        !scraped.contains("route="),
        "the disabled route dimension must not appear on any series:\n{scraped}\n{}",
        proxy.logs()
    );
    assert!(
        !scraped.contains("endpoint="),
        "the disabled endpoint dimension must not appear on any series:\n{scraped}"
    );
    assert!(
        !scraped.contains("cluster="),
        "the disabled cluster dimension must not appear on any series, including the additive \
         upstream metrics such as the connect-duration histogram:\n{scraped}"
    );
    assert!(
        scraped.contains("method=\"GET\""),
        "dimensions left enabled must still be emitted:\n{scraped}"
    );
    assert!(
        scraped.contains("listener=\"web\""),
        "the listener dimension was left enabled and must still be emitted:\n{scraped}"
    );
    assert!(
        scraped.contains("praxis_upstream_requests_total"),
        "the metric itself stays available when a dimension is dropped:\n{scraped}"
    );
    assert!(
        scraped.contains("praxis_upstream_connect_duration_seconds"),
        "the additive connect-duration histogram is still emitted, now without the cluster label:\n{scraped}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example on test ports, with `cluster` appended to the dimensions it
/// disables and a shutdown window short enough for the SIGTERM that ends the
/// test.
///
/// The example's own `route` and `endpoint` are asserted on the parsed config
/// rather than matched as text, so dropping them from the YAML fails the test
/// instead of leaving it to assert the absence of labels nothing emitted.
/// `cluster` is the test's addition: the example does not disable it, and it
/// is what proves the additive upstream metrics (here the connect-duration
/// histogram, recorded on the happy path) drop a dimension too.
fn example_yaml(port: u16, admin: u16, backend: u16) -> String {
    let yaml = std::fs::read_to_string(example_config_path(EXAMPLE)).expect("read example");
    assert!(
        yaml.contains(LAST_DISABLED),
        "the example must disable the endpoint dimension the test appends to"
    );
    let ports = HashMap::from([("127.0.0.1:9902", admin), ("127.0.0.1:3000", backend)]);
    let patched = format!(
        "shutdown_timeout_secs: 1\n{}",
        allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports)).replacen(
            LAST_DISABLED,
            &format!("{LAST_DISABLED}      - cluster\n"),
            1
        )
    );
    let labels = Config::from_yaml(&patched).expect("parse example").metrics.labels;
    for label in [MetricLabel::Route, MetricLabel::Endpoint] {
        assert!(
            !labels.is_enabled(label),
            "the example must disable {label:?} for the test to prove it is dropped"
        );
    }
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
