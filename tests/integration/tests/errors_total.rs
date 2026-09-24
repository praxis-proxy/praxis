// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Integration tests for the unified proxy error counter.
//!
//! `praxis_errors_total` is process-global and labelled only by `type`, so in
//! the shared `suite` process another test's rejection could satisfy a
//! "count went up" assertion. These tests run as their own binary, one at a
//! time.

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

use std::{sync::Mutex, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, http_post, start_backend_with_shutdown, start_proxy, wait_for_tcp};

// -----------------------------------------------------------------------------
// Statics
// -----------------------------------------------------------------------------

/// Held by every test: they read and bump the same counter series.
static SERIAL: Mutex<()> = Mutex::new(());

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn error_count(body: &str, error_type: &str) -> Option<f64> {
    body.lines()
        .find(|line| line.starts_with(&format!("praxis_errors_total{{type=\"{error_type}\"}}")))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

/// Poll `/metrics` until the `error_type` counter rises above `baseline`,
/// returning the scrape that observed the increase (or the last scrape once the
/// deadline passes).
///
/// The series may already be nonzero from an earlier test, and the response
/// can return before the request's increment lands, so wait for a strict
/// increase above the caller's `before` reading rather than for the series to
/// appear. Tests hold [`SERIAL`], so no other request can supply it.
fn wait_for_error(admin: &str, error_type: &str, baseline: f64) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        last = http_get(admin, "/metrics", None).1;
        if error_count(&last, error_type).is_some_and(|count| count > baseline) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn errors_total_counts_filter_rejections() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let backend = start_backend_with_shutdown("errors-reject");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: errors-reject
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny:
          - "127.0.0.0/8"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{}"
insecure_options:
  allow_private_endpoints: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let before = error_count(&http_get(&admin, "/metrics", None).1, "filter_reject").unwrap_or(0.0);

    let (status, _) = http_get(proxy.addr(), "/blocked", None);
    assert_ne!(status, 200, "the ACL should reject the request");

    let body = wait_for_error(&admin, "filter_reject", before);
    assert!(
        error_count(&body, "filter_reject").is_some_and(|count| count > before),
        "a filter rejection should be counted as type=filter_reject:\n{body}"
    );
}

#[test]
fn errors_total_counts_unreachable_upstreams() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let proxy_port = free_port();
    let admin_port = free_port();
    let dead_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: errors-unreachable
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{dead_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let before = error_count(&http_get(&admin, "/metrics", None).1, "upstream_unavailable").unwrap_or(0.0);

    let (status, _) = http_get(proxy.addr(), "/gone", None);
    assert_ne!(status, 200, "a dead upstream should not return 200");

    // praxis_errors_total carries only a `type` label, so this series is
    // shared with every other test in this binary; assert that this request
    // moved it rather than pinning an exact total. The once-per-request
    // guarantee is pinned deterministically by the stamp_error_type unit
    // tests in the protocol crate.
    let body = wait_for_error(&admin, "upstream_unavailable", before);
    let after = error_count(&body, "upstream_unavailable").unwrap_or(0.0);
    assert!(
        after > before,
        "an unreachable upstream should be counted as type=upstream_unavailable:\n{body}"
    );
}

#[test]
fn errors_total_absent_on_the_happy_path() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let backend = start_backend_with_shutdown("errors-none");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: errors-none
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{}"
insecure_options:
  allow_private_endpoints: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let before = error_count(&http_get(&admin, "/metrics", None).1, "internal").unwrap_or(0.0);
    let (status, _) = http_get(proxy.addr(), "/ok", None);
    assert_eq!(status, 200, "proxy request should succeed");

    let after = error_count(&http_get(&admin, "/metrics", None).1, "internal").unwrap_or(0.0);
    assert!(
        (after - before).abs() < f64::EPSILON,
        "a successful request must not record an internal error"
    );
}

#[test]
fn errors_total_counts_request_body_rejections() {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // A rejection raised in the request-body phase (here a body larger than
    // the configured limit) terminates the request just like a header-phase
    // reject and must be counted, not silently dropped.
    let backend = start_backend_with_shutdown("errors-body");
    let proxy_port = free_port();
    let admin_port = free_port();
    let yaml = format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
listeners:
  - name: errors-body
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: json_body_field
        field: model
        header: X-Model
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{}"
body_limits:
  max_request_bytes: 1024
insecure_options:
  allow_private_endpoints: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let admin = format!("127.0.0.1:{admin_port}");
    wait_for_tcp(&admin);

    let before = error_count(&http_get(&admin, "/metrics", None).1, "filter_reject").unwrap_or(0.0);

    let oversized = "x".repeat(4096);
    let (status, _) = http_post(proxy.addr(), "/api", &oversized);
    assert_eq!(
        status, 413,
        "a body over the configured limit should be rejected with 413"
    );

    let body = wait_for_error(&admin, "filter_reject", before);
    assert!(
        error_count(&body, "filter_reject").is_some_and(|count| count > before),
        "a request-body-phase rejection must be counted as type=filter_reject:\n{body}"
    );
}
