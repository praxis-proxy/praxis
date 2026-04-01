//! Filter chain depth benchmarks.
//!
//! Measures how pipeline length affects throughput. Each test
//! builds a chain with `request_id`, N `headers` filters,
//! `router`, and `load_balancer`, then drives GET traffic
//! through it.

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_backend, start_proxy};

use crate::test_utils::{BenchConfig, assert_performance, report_results, run_get_benchmark};

// -----------------------------------------------------------------------------
// YAML Generator
// -----------------------------------------------------------------------------

/// Build a filter_chains YAML with `num_header_filters` headers
/// filters between request_id and router+lb.
fn multi_filter_yaml(proxy_port: u16, backend_port: u16, num_header_filters: usize) -> String {
    let mut headers_block = String::new();
    for i in 0..num_header_filters {
        headers_block.push_str(&format!(
            r#"      - filter: headers
        request_add:
          - name: "X-Bench-{i}"
            value: "value-{i}"
"#
        ));
    }

    format!(
        r#"listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - bench

filter_chains:
  - name: bench
    filters:
      - filter: request_id
{headers_block}      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
"#
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn bench_pipeline_4_filters() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = multi_filter_yaml(proxy_port, backend_port, 1);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let cfg = BenchConfig::new("pipeline_4_filters (rid + 1h + router + lb)");
    let result = run_get_benchmark(&cfg, &addr, "/");
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 500.0, 500.0);
}

#[test]
fn bench_pipeline_8_filters() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = multi_filter_yaml(proxy_port, backend_port, 5);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let cfg = BenchConfig::new("pipeline_8_filters (rid + 5h + router + lb)");
    let result = run_get_benchmark(&cfg, &addr, "/");
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 300.0, 500.0);
}

#[test]
fn bench_pipeline_15_filters() {
    let backend_port = start_backend("ok");
    let proxy_port = free_port();
    let yaml = multi_filter_yaml(proxy_port, backend_port, 12);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let cfg = BenchConfig::new("pipeline_15_filters (rid + 12h + router + lb)");
    let result = run_get_benchmark(&cfg, &addr, "/");
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 200.0, 500.0);
}
