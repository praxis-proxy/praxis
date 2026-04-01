//! Production-simulation pipeline performance tests.

use std::sync::Arc;

use praxis_core::config::Config;
use praxis_test_utils::{free_port, start_echo_backend, start_proxy};

use crate::test_utils::{
    BenchConfig, assert_performance, compute_percentile, report_results, run_benchmark, run_benchmark_with_body,
    run_get_benchmark,
};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Build a YAML config with a production-like filter chain.
fn production_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - security
      - observability
      - transformation
      - routing

filter_chains:
  - name: security
    filters:
      - filter: ip_acl
        allow:
          - "127.0.0.0/8"
      - filter: forwarded_headers

  - name: observability
    filters:
      - filter: request_id
      - filter: access_log
        sample_rate: 0.01

  - name: transformation
    filters:
      - filter: headers
        request_add:
          - name: "X-Proxy"
            value: "praxis"
        response_add:
          - name: "X-Served-By"
            value: "praxis"

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: "backend"
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
fn bench_production_pipeline_get() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = production_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let cfg = BenchConfig::new("production_pipeline_get (7 filters, c=8)")
        .total(3000)
        .concurrency(8);
    let result = run_get_benchmark(&cfg, &addr, "/api/users");
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 300.0, 500.0);
}

#[test]
fn bench_production_pipeline_post() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = production_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let payload = "x".repeat(512);
    let body = format!(r#"{{"user":"bench","action":"create","payload":"{payload}"}}"#);
    let cfg = BenchConfig::new("production_pipeline_post (7 filters, ~600B JSON, c=8)")
        .total(2000)
        .concurrency(8);
    let result = run_benchmark_with_body(&cfg, &addr, "/api/users", &body);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 200.0, 500.0);
}

#[test]
fn bench_production_pipeline_mixed() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = production_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let post_body = "x".repeat(1024);
    let post_body = Arc::new(post_body);
    let cfg = BenchConfig::new("production_pipeline_mixed (GET+POST, c=8)")
        .total(3000)
        .concurrency(8);

    let pb = Arc::clone(&post_body);
    let result = run_benchmark(&cfg, &addr, move |a| {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        if n % 2 == 0 {
            praxis_test_utils::http_get(a, "/api/users", None)
        } else {
            praxis_test_utils::http_post(a, "/api/data", &pb)
        }
    });
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);

    let throughput = result.total_requests as f64 / result.elapsed.as_secs_f64();
    let p99 = compute_percentile(&result.latencies, 99.0);
    let p50 = compute_percentile(&result.latencies, 50.0);
    eprintln!("  mixed ratio: 50% GET / 50% POST (1KB body)");
    eprintln!("  p50/p99 ratio: {:.1}x", p99.as_secs_f64() / p50.as_secs_f64());
    eprintln!("  effective throughput: {throughput:.0} req/s");

    assert_performance(&result, 200.0, 500.0);
}
