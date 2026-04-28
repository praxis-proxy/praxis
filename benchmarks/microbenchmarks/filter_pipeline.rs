// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Criterion benchmarks for filter pipeline construction and execution.

#![deny(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::Route;
use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry, HttpFilter, RouterFilter};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(benches, bench_pipeline_build, bench_pipeline_execute_request);
criterion_main!(benches);

/// Benchmark pipeline construction from filter entries.
fn bench_pipeline_build(c: &mut Criterion) {
    let registry = FilterRegistry::with_builtins();
    let mut group = c.benchmark_group("pipeline_build");

    for size in [1, 5, 20] {
        let entries = make_entries(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &entries, |b, entries| {
            b.iter_batched(
                || entries.clone(),
                |mut cloned| {
                    let _result = black_box(FilterPipeline::build(black_box(&mut cloned), &registry).unwrap());
                },
                BatchSize::SmallInput,
            );
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
    let mut entries = vec![
        filter_entry(
            "router",
            "routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /\n    cluster: default",
        ),
        filter_entry("headers", "request_add:\n  - name: X-Via\n    value: praxis"),
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();

    // Also benchmark the router alone for comparison.
    let mut group = c.benchmark_group("pipeline_execute_request");
    group.bench_function("router_only", |b| {
        let router = &router;
        b.to_async(&rt).iter_batched(
            || make_request("/api/v1/users"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                let _result = black_box(router.on_request(black_box(&mut ctx)).await.unwrap());
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
                let _result = black_box(pipeline.execute_http_request(black_box(&mut ctx)).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark Utilities
// -----------------------------------------------------------------------------

/// Build a [`FilterEntry`] from a filter type name and YAML config string.
fn filter_entry(filter_type: &str, yaml: &str) -> FilterEntry {
    FilterEntry {
        branch_chains: None,
        filter_type: filter_type.into(),
        config: serde_yaml::from_str(yaml).unwrap(),
        conditions: vec![],
        name: None,
        response_conditions: vec![],
        failure_mode: FailureMode::default(),
    }
}

/// Build a vector of `n` filter entries alternating between
/// router (even) and headers (odd).
fn make_entries(n: usize) -> Vec<FilterEntry> {
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                filter_entry("router", "routes: []")
            } else {
                filter_entry("headers", "response_add: []")
            }
        })
        .collect()
}
