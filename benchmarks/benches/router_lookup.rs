//! Criterion benchmarks for router path-prefix matching.
//!
//! Measures [`RouterFilter::on_request`] with route tables of
//! varying sizes (10, 100, 500 routes) and different hit positions
//! (early, middle, late, fallback).
//!
//! [`RouterFilter::on_request`]: praxis_filter::RouterFilter

#![deny(unsafe_code)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::Route;
use praxis_filter::{HttpFilter, RouterFilter};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

/// Benchmark router lookup with varying table sizes and hit positions.
fn bench_router_lookup(c: &mut Criterion) {
    let rt = bench_runtime();

    let mut group = c.benchmark_group("router_lookup");

    for &n in &[10, 100, 500] {
        let router = RouterFilter::new(make_routes(n)).expect("valid routes");

        // Early hit (first route).
        group.bench_with_input(BenchmarkId::new("early_hit", n), &router, |b, router| {
            b.to_async(&rt).iter_batched(
                || make_request("/svc-0/data"),
                |req| async move {
                    let mut ctx = make_ctx(&req);
                    black_box(router.on_request(&mut ctx).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });

        // Mid hit.
        let mid_path = format!("/svc-{}/data", n / 2);
        group.bench_with_input(BenchmarkId::new("mid_hit", n), &router, |b, router| {
            let p = mid_path.clone();
            b.to_async(&rt).iter_batched(
                || make_request(&p),
                |req| async move {
                    let mut ctx = make_ctx(&req);
                    black_box(router.on_request(&mut ctx).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });

        // Fallback (no specific route matched).
        group.bench_with_input(BenchmarkId::new("fallback", n), &router, |b, router| {
            b.to_async(&rt).iter_batched(
                || make_request("/unknown"),
                |req| async move {
                    let mut ctx = make_ctx(&req);
                    black_box(router.on_request(&mut ctx).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a route table with `n` routes plus a catch-all.
fn make_routes(n: usize) -> Vec<Route> {
    let mut routes: Vec<Route> = (0..n)
        .map(|i| Route {
            path_prefix: format!("/svc-{i}/"),
            host: None,
            headers: None,
            cluster: format!("cluster-{i}").into(),
        })
        .collect();

    routes.push(Route {
        path_prefix: "/".into(),
        host: None,
        headers: None,
        cluster: "fallback".into(),
    });

    routes
}

criterion_group!(benches, bench_router_lookup);
criterion_main!(benches);
