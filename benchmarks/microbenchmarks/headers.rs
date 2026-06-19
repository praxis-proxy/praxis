// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Criterion benchmarks for header manipulation filter.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use http::{HeaderMap, StatusCode};
use praxis_filter::{FilterRegistry, HttpFilter, Response};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(benches, bench_headers_request, bench_headers_response);
criterion_main!(benches);

/// Benchmark request header injection with varying header counts.
fn bench_headers_request(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("headers_on_request");

    for &n in &[1, 5, 20] {
        let yaml = header_filter_yaml(n);
        let filter = make_header_filter(&yaml);

        group.bench_with_input(BenchmarkId::from_parameter(n), &filter, |b, filter| {
            b.to_async(&rt).iter_batched(
                || make_request("/api/data"),
                |req| async move {
                    let mut ctx = make_ctx(&req);
                    let _result = black_box(filter.on_request(black_box(&mut ctx)).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark response header manipulation with varying header counts.
fn bench_headers_response(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("headers_on_response");

    for &n in &[1, 5, 20] {
        let yaml = header_filter_yaml(n);
        let filter = make_header_filter(&yaml);

        group.bench_with_input(BenchmarkId::from_parameter(n), &filter, |b, filter| {
            b.to_async(&rt).iter_batched(
                || {
                    let req = make_request("/api/data");
                    let resp = Response {
                        status: StatusCode::OK,
                        headers: HeaderMap::new(),
                    };
                    (req, resp)
                },
                |(req, mut resp)| async move {
                    let mut ctx = make_ctx(&req);
                    ctx.response_header = Some(&mut resp);
                    let _result = black_box(filter.on_response(black_box(&mut ctx)).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark Utilities
// -----------------------------------------------------------------------------

/// Generate a YAML config for the header filter with `n` `request_add`
/// and `n` `response_set` entries.
fn header_filter_yaml(n: usize) -> String {
    use std::fmt::Write as _;

    let mut yaml = String::from("request_add:\n");
    for i in 0..n {
        _ = write!(yaml, "  - name: x-req-{i}\n    value: value-{i}\n");
    }

    yaml.push_str("response_set:\n");
    for i in 0..n {
        _ = write!(yaml, "  - name: x-resp-{i}\n    value: value-{i}\n");
    }

    yaml.push_str("response_remove:\n  - x-backend-server\n");

    yaml
}

/// Create a header filter from YAML via the registry.
fn make_header_filter(yaml: &str) -> Box<dyn HttpFilter> {
    let registry = FilterRegistry::with_builtins();
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    let filter = registry.create("headers", &config).unwrap();
    match filter {
        praxis_filter::AnyFilter::Http(f) => f,
        praxis_filter::AnyFilter::Tcp(_) => {
            panic!("expected HTTP filter")
        },
    }
}
