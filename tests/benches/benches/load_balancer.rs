// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for load balancer endpoint selection.

#![expect(
    clippy::min_ident_chars,
    clippy::single_char_lifetime_names,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::{Cluster, ConsistentHashOpts, LoadBalancerStrategy, ParameterisedStrategy, SimpleStrategy};
use praxis_filter::{HttpFilter as _, HttpFilterContext, LoadBalancerFilter};

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

    let mut authority_cluster = make_cluster(LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin), 10);
    authority_cluster.http.authority = Some("api.example.com".into());
    let authority_lb = LoadBalancerFilter::new(&[authority_cluster]);
    group.bench_function("round_robin_authority/10", |b| {
        let authority_lb = &authority_lb;
        b.to_async(&rt).iter_batched(
            || make_request("/api/v1/users"),
            |req| async move {
                let mut ctx = make_ctx_with_cluster(&req, "bench");
                let _result = black_box(authority_lb.on_request(black_box(&mut ctx)).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "slow-start")]
    bench_slow_start(&mut group, &rt);

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

/// Settled and in-window slow start, at the same pool sizes as the other cases.
#[cfg(feature = "slow-start")]
fn bench_slow_start(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    rt: &tokio::runtime::Runtime,
) {
    use std::sync::Arc;

    use praxis_core::config::SlowStartConfig;
    use praxis_filter::SlowStartRegistry;

    for &pool_size in &[10_usize, 50] {
        let mut cluster = make_cluster(LoadBalancerStrategy::Simple(SimpleStrategy::RoundRobin), pool_size);
        cluster.slow_start = Some(SlowStartConfig {
            window_ms: 60_000,
            aggression: 1.0,
        });
        let lb = LoadBalancerFilter::new(&[cluster.clone()]);
        lb.bind_slow_start(&Arc::new(SlowStartRegistry::new()));
        let addresses: Vec<Arc<str>> = cluster
            .endpoints
            .iter()
            .map(|endpoint| Arc::from(endpoint.address()))
            .collect();
        let healthy = health_registry(&addresses, None);
        warm_slow_start(rt, &lb, &healthy);
        group.bench_with_input(BenchmarkId::new("slow_start_settled", pool_size), &lb, |b, filter| {
            let healthy = &healthy;
            b.to_async(rt).iter_batched(
                || make_request("/api/v1/users"),
                |req| async move {
                    let mut ctx = make_ctx_with_cluster(&req, "bench");
                    ctx.health_registry = Some(healthy);
                    let _result = black_box(filter.on_request(black_box(&mut ctx)).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });

        let active = LoadBalancerFilter::new(&[cluster]);
        active.bind_slow_start(&Arc::new(SlowStartRegistry::new()));
        let down = health_registry(&addresses, Some(pool_size.saturating_sub(1)));
        let recovered = health_registry(&addresses, None);
        warm_slow_start(rt, &active, &down);
        warm_slow_start(rt, &active, &recovered);
        group.bench_with_input(
            BenchmarkId::new("slow_start_active", pool_size),
            &active,
            |b, filter| {
                let recovered = &recovered;
                b.to_async(rt).iter_batched(
                    || make_request("/api/v1/users"),
                    |req| async move {
                        let mut ctx = make_ctx_with_cluster(&req, "bench");
                        ctx.health_registry = Some(recovered);
                        let _result = black_box(filter.on_request(black_box(&mut ctx)).await.unwrap());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

/// One request so the ramp records membership before the measured loop.
#[cfg(feature = "slow-start")]
fn warm_slow_start(
    rt: &tokio::runtime::Runtime,
    lb: &LoadBalancerFilter,
    health: &praxis_core::health::HealthRegistry,
) {
    rt.block_on(async {
        let req = make_request("/api/v1/users");
        let mut ctx = make_ctx_with_cluster(&req, "bench");
        ctx.health_registry = Some(health);
        let _result = lb.on_request(&mut ctx).await.unwrap();
    });
}

/// Health map for `bench`. `down` is the endpoint index that is unhealthy.
#[cfg(feature = "slow-start")]
fn health_registry(addresses: &[std::sync::Arc<str>], down: Option<usize>) -> praxis_core::health::HealthRegistry {
    use std::{collections::HashMap, sync::Arc};

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    let endpoints: Vec<EndpointHealth> = addresses
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let endpoint = EndpointHealth::new();
            if down == Some(index) {
                endpoint.mark_unhealthy();
            }
            endpoint
        })
        .collect();
    let entry = ClusterHealthEntry::new(endpoints, addresses.to_vec(), None, None);
    let mut map = HashMap::new();
    map.insert(Arc::from("bench"), Arc::new(entry));
    Arc::new(map)
}

/// Build a cluster with the given strategy and `n` endpoints.
fn make_cluster(strategy: LoadBalancerStrategy, n: usize) -> Cluster {
    let endpoints: Vec<String> = (0..n).map(|i| format!("10.0.{}.{}:8080", i / 256, i % 256)).collect();
    let endpoints = endpoints.into_iter().map(Into::into).collect();
    Cluster {
        load_balancer_strategy: strategy,
        ..Cluster::with_defaults("bench", endpoints)
    }
}
