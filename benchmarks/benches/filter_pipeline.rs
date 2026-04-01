//! Criterion benchmarks for filter pipeline construction and execution.
//!
//! Measures [`FilterPipeline::build`] with varying chain sizes and
//! async request execution via [`FilterPipeline::execute_http_request`].
//!
//! [`FilterPipeline::build`]: praxis_filter::FilterPipeline::build
//! [`FilterPipeline::execute_http_request`]: praxis_filter::FilterPipeline

#![deny(unsafe_code)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::Route;
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry, HttpFilter, RouterFilter};

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a vector of `n` filter entries alternating between
/// router (even) and headers (odd).
fn make_entries(n: usize) -> Vec<FilterEntry> {
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                FilterEntry {
                    filter_type: "router".into(),
                    config: serde_yaml::from_str("routes: []").unwrap(),
                    conditions: vec![],
                    response_conditions: vec![],
                }
            } else {
                FilterEntry {
                    filter_type: "headers".into(),
                    config: serde_yaml::from_str("response_add: []").unwrap(),
                    conditions: vec![],
                    response_conditions: vec![],
                }
            }
        })
        .collect()
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

/// Benchmark pipeline construction from filter entries.
fn bench_pipeline_build(c: &mut Criterion) {
    let registry = FilterRegistry::with_builtins();
    let mut group = c.benchmark_group("pipeline_build");

    for size in [1, 5, 20] {
        let entries = make_entries(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &entries, |b, entries| {
            b.iter(|| FilterPipeline::build(black_box(entries), &registry).unwrap());
        });
    }

    group.finish();
}

/// Benchmark async request execution through a realistic pipeline.
fn bench_pipeline_execute_request(c: &mut Criterion) {
    let rt = bench_runtime();

    let routes = vec![
        Route {
            path_prefix: "/api/".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        },
        Route {
            path_prefix: "/".into(),
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ];

    let router = RouterFilter::new(routes).expect("valid routes");
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            filter_type: "router".into(),
            config: serde_yaml::from_str(
                "routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /\n    cluster: default",
            )
            .unwrap(),
            conditions: vec![],
            response_conditions: vec![],
        },
        FilterEntry {
            filter_type: "headers".into(),
            config: serde_yaml::from_str("request_add:\n  - name: X-Via\n    value: praxis").unwrap(),
            conditions: vec![],
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();

    // Also benchmark the router alone for comparison.
    let mut group = c.benchmark_group("pipeline_execute_request");
    group.bench_function("router_only", |b| {
        let router = &router;
        b.to_async(&rt).iter_batched(
            || make_request("/api/v1/users"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                black_box(router.on_request(&mut ctx).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("router_plus_headers", |b| {
        let pipeline = &pipeline;
        b.to_async(&rt).iter_batched(
            || make_request("/api/v1/users"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                black_box(pipeline.execute_http_request(&mut ctx).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_pipeline_build, bench_pipeline_execute_request);
criterion_main!(benches);
