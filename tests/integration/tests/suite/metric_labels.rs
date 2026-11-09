// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Metric label sets on the upstream failure path (#1033).
//!
//! The connect-failure and connect-duration recorders take a different path
//! than the happy one the `metric-label-sets.yaml` example test drives, so a
//! dead upstream proves they honor a disabled dimension too.
//!
//! The label set is installed once per process, from `metrics.labels`, by the
//! server's own startup path. That makes it untestable in-process here, where
//! every other test in this binary expects the default label set, so the
//! config carries the disabled dimensions and the real binary applies them.

use std::time::{Duration, Instant};

use praxis_test_utils::{PraxisProcess, free_port, http_get, wait_for_tcp};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

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
fn disabled_cluster_drops_from_the_failure_path_metrics() {
    let (port, admin, dead) = (free_port(), free_port(), free_port());
    let proxy = PraxisProcess::spawn(&dead_upstream_yaml(port, admin, dead), &addr(port));
    let admin_addr = addr(admin);
    wait_for_tcp(&admin_addr);

    let (status, _) = http_get(&addr(port), "/anything", None);
    assert_ne!(status, 200, "a dead upstream must not return 200");

    let scraped = scrape_until(&admin_addr, "praxis_upstream_connect_failures_total");
    assert!(
        scraped.contains("praxis_upstream_connect_failures_total"),
        "the connect-failure counter must be emitted for a dead upstream:\n{scraped}\n{}",
        proxy.logs()
    );
    assert!(
        !scraped.contains("cluster="),
        "the disabled cluster dimension must be dropped from the failure-path counters too, \
         not just the request metrics:\n{scraped}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A proxy routing every request to `dead`, where nothing listens, with the
/// cardinality-driving dimensions disabled in config so startup installs them.
fn dead_upstream_yaml(port: u16, admin: u16, dead: u16) -> String {
    format!(
        r#"
shutdown_timeout_secs: 1
admin:
  metrics_address: "127.0.0.1:{admin}"
metrics:
  labels:
    route: false
    endpoint: false
    cluster: false
listeners:
  - name: web
    address: "127.0.0.1:{port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: dead
      - filter: load_balancer
        clusters:
          - name: dead
            endpoints:
              - "127.0.0.1:{dead}"
insecure_options:
  allow_private_endpoints: true
"#
    )
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
