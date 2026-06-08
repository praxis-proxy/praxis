// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Criterion benchmarks for load balancer endpoint selection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::{Cluster, ConsistentHashOpts, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy};
use praxis_filter::{HttpFilter, HttpFilterContext, LoadBalancerFilter};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(benches, bench_load_balancer);
criterion_main!(benches);

/// Benchmark endpoint selection across strategies and pool sizes.
fn bench_load_balancer(c: &mut Criterion) {
    let rt = bench_runtime();

    let strategies: Vec<(&str, LoadBalancerStrategy)> = vec![
        ("round_robin", LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin)),
        (
            "least_conn",
            LoadBalancerStrategy::Simple(SimpleStrategy::LeastConnections),
        ),
        (
            "consistent_hash",
            LoadBalancerStrategy::Parameterised(ParameterisedStrategy::ConsistentHash(ConsistentHashOpts {
                header: None,
            })),
        ),
    ];

    let mut group = c.benchmark_group("load_balancer");

    for (label, strategy) in &strategies {
        for &pool_size in &[3, 10, 50] {
            let cluster = make_cluster(strategy.clone(), pool_size);
            let lb = LoadBalancerFilter::new(&[cluster]);

            group.bench_with_input(BenchmarkId::new(*label, pool_size), &lb, |b, lb| {
                b.to_async(&rt).iter_batched(
                    || make_request("/api/v1/users"),
                    |req| async move {
                        let mut ctx = make_ctx_with_cluster(&req, "bench");
                        let _result = black_box(lb.on_request(black_box(&mut ctx)).await.unwrap());
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark Utilities
// -----------------------------------------------------------------------------

/// Build an [`HttpFilterContext`] with a pre-selected cluster.
fn make_ctx_with_cluster<'a>(req: &'a praxis_filter::Request, cluster: &str) -> HttpFilterContext<'a> {
    let mut ctx = common::make_ctx(req);
    ctx.cluster = Some(std::sync::Arc::from(cluster));
    ctx
}

/// Build a cluster with the given strategy and `n` endpoints.
fn make_cluster(strategy: LoadBalancerStrategy, n: usize) -> Cluster {
    let endpoints: Vec<String> = (0..n).map(|i| format!("10.0.{}.{}:8080", i / 256, i % 256)).collect();
    Cluster {
        connection_timeout_ms: None,
        endpoints: endpoints.into_iter().map(Into::into).collect(),
        health_check: None,
        idle_timeout_ms: None,
        load_balancer_strategy: strategy,
        max_connections: None,
        name: "bench".into(),
        read_timeout_ms: None,
        tls: None,
        total_connection_timeout_ms: None,
        write_timeout_ms: None,
    }
}
