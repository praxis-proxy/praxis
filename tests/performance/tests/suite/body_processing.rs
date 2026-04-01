//! Body processing throughput benchmarks.
//!
//! Measures POST throughput at various payload sizes, with and
//! without body-aware filters in the pipeline.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    custom_filter_yaml, free_port, registry_with, simple_proxy_yaml, start_echo_backend, start_proxy,
    start_proxy_with_registry,
};

use crate::test_utils::{BenchConfig, assert_performance, report_results, run_benchmark_with_body};

// -----------------------------------------------------------------------------
// NoopBodyFilter
// -----------------------------------------------------------------------------

/// A body filter that declares ReadOnly + Stream access but
/// performs no transformation. Used to measure the overhead of
/// body interception itself.
struct NoopBodyFilter;

#[async_trait]
impl HttpFilter for NoopBodyFilter {
    fn name(&self) -> &'static str {
        "noop_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn bench_body_passthrough() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let body = "x".repeat(100);
    let cfg = BenchConfig::new("body_passthrough (100B, no body filter)");
    let result = run_benchmark_with_body(&cfg, &addr, "/echo", &body);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 300.0, 500.0);
}

#[test]
fn bench_body_readonly_stream() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, backend_port, "noop_body");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("noop_body", || Box::new(NoopBodyFilter));
    let addr = start_proxy_with_registry(&config, &registry);
    let body = "x".repeat(100);
    let cfg = BenchConfig::new("body_readonly_stream (100B, noop body filter)");
    let result = run_benchmark_with_body(&cfg, &addr, "/echo", &body);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 300.0, 500.0);
}

#[test]
fn bench_body_medium_payload() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let body = "x".repeat(4096);
    let cfg = BenchConfig::new("body_medium_payload (4KB, no body filter)");
    let result = run_benchmark_with_body(&cfg, &addr, "/echo", &body);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 200.0, 500.0);
}

#[test]
fn bench_body_large_payload() {
    let backend_port = start_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_port);
    let config = Config::from_yaml(&yaml).unwrap();
    let addr = start_proxy(&config);
    let body = "x".repeat(65536);
    let cfg = BenchConfig::new("body_large_payload (64KB, no body filter)");
    let result = run_benchmark_with_body(&cfg, &addr, "/echo", &body);
    assert_eq!(result.errors, 0, "all requests should succeed");
    report_results(&result);
    assert_performance(&result, 50.0, 1000.0);
}
