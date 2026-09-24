// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Integration tests for configurable metric label sets (#1033).
//!
//! The selected label dimensions are installed once into a process-global
//! `OnceLock`, because a gauge guard acquired before a change and released
//! after it would increment one series and decrement another. That makes the
//! setting untestable inside the shared `suite` process, where every other
//! test expects the default label set, so these tests run as their own test
//! binary.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::doc_nested_refdefs,
    clippy::expect_used,
    clippy::format_push_string,
    clippy::indexing_slicing,
    clippy::iter_over_hash_type,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::map_with_unused_argument_over_ranges,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::string_add,
    clippy::struct_field_names,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    clippy::wildcard_enum_match_arm,
    reason = "test code"
)]

use std::{collections::HashMap, time::Duration};

use praxis_core::config::{MetricLabel, MetricLabelsConfig};
use praxis_test_utils::{free_port, http_get, load_example_config, start_full_proxy, wait_for_tcp};

const EXAMPLE: &str = "observability/metric-label-sets.yaml";

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

#[test]
fn disabled_dimensions_disappear_from_the_scrape() {
    // Installed before any metric is recorded, and only once per process.
    // `cluster` is disabled alongside `route` and `endpoint` to prove the
    // additive cluster metrics (here the connect-duration histogram emitted
    // on the happy path) drop the label too, not just the request metrics.
    praxis_protocol::http::pingora::metrics::install_metric_labels(MetricLabelsConfig {
        disabled: vec![MetricLabel::Route, MetricLabel::Endpoint, MetricLabel::Cluster],
    });

    let backend = praxis_test_utils::start_backend_with_shutdown("label-sets");
    let proxy_port = free_port();
    let admin_port = free_port();
    let config = load_example_config(
        EXAMPLE,
        proxy_port,
        HashMap::from([
            ("127.0.0.1:8080", proxy_port),
            ("127.0.0.1:3000", backend.port()),
            ("127.0.0.1:9901", admin_port),
        ]),
    );

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, body) = http_get(&format!("127.0.0.1:{proxy_port}"), "/api/hello", None);
    assert_eq!(status, 200, "example config should proxy successfully");
    assert_eq!(body, "label-sets", "example config should forward to the backend");

    let scraped = scrape(&admin, "praxis_http_requests_total");
    assert!(
        !scraped.contains("route="),
        "the disabled route dimension must not appear on any series:\n{scraped}"
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

#[test]
fn disabled_cluster_drops_from_the_failure_path_metrics() {
    // Same process-global install: the connect-failure and connect-duration
    // recorders take a different (failure) path than the happy-path test
    // above, so drive a dead upstream to prove they honor the disabled
    // cluster dimension too.
    praxis_protocol::http::pingora::metrics::install_metric_labels(MetricLabelsConfig {
        disabled: vec![MetricLabel::Route, MetricLabel::Endpoint, MetricLabel::Cluster],
    });

    let proxy_port = free_port();
    let admin_port = free_port();
    let dead_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: web
    address: "127.0.0.1:{proxy_port}"
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
              - "127.0.0.1:{dead_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).expect("inline config should parse");

    let _proxy = start_full_proxy(&config);
    wait_for_tcp(&format!("127.0.0.1:{proxy_port}"));
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let (status, _) = http_get(&format!("127.0.0.1:{proxy_port}"), "/anything", None);
    assert_ne!(status, 200, "a dead upstream must not return 200");

    let scraped = scrape(&admin, "praxis_upstream_connect_failures_total");
    assert!(
        scraped.contains("praxis_upstream_connect_failures_total"),
        "the connect-failure counter must be emitted for a dead upstream:\n{scraped}"
    );
    assert!(
        !scraped.contains("cluster="),
        "the disabled cluster dimension must be dropped from the failure-path counters too, \
         not just the request metrics:\n{scraped}"
    );
}
