// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Criterion benchmarks for branch chain evaluation and execution.
//!
//! Covers branch condition matching, result set operations, filter
//! execution within branches, and rejoin logic with varying branch
//! counts and nesting levels.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::min_ident_chars,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::hint::black_box;

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::{BranchChainConfig, BranchCondition, ChainRef};
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry, FilterResultSet};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_pipeline_no_branches,
    bench_pipeline_with_branches,
    bench_branch_condition_matching,
    bench_result_set_snapshot
);
criterion_main!(benches);

/// Benchmark pipeline execution without branches (baseline).
fn bench_pipeline_no_branches(c: &mut Criterion) {
    let rt = bench_runtime();
    let registry = FilterRegistry::with_builtins();
    let mut entries = vec![
        filter_entry(
            "router",
            "routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /\n    cluster: default",
        ),
        filter_entry("headers", "request_add:\n  - name: X-Via\n    value: praxis"),
    ];
    let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();

    c.bench_function("branch_chains/no_branches", |b| {
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
}

/// Benchmark pipeline execution with varying numbers of branches.
fn bench_pipeline_with_branches(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("branch_chains/with_branches");

    for &(label, branch_count) in &[("1", 1), ("3", 3), ("5", 5)] {
        let pipeline = build_pipeline_with_branches(branch_count);
        group.bench_with_input(BenchmarkId::from_parameter(label), &pipeline, |b, pipeline| {
            b.to_async(&rt).iter_batched(
                || make_request("/api/data"),
                |req| async move {
                    let mut ctx = make_ctx(&req);
                    let _result = black_box(pipeline.execute_http_request(black_box(&mut ctx)).await.unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark branch condition matching logic.
fn bench_branch_condition_matching(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("branch_chains/condition_matching");

    // Build three different pipelines for different match scenarios
    let pipeline_api = build_pipeline_with_conditional_branches(3, "api");
    let _pipeline_app = build_pipeline_with_conditional_branches(3, "app");
    let pipeline_other = build_pipeline_with_conditional_branches(3, "other");

    // Condition that matches (first branch fires)
    group.bench_function("match_first", |b| {
        let pipeline = &pipeline_api;
        b.to_async(&rt).iter_batched(
            || make_request("/api/data"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                let _result = black_box(pipeline.execute_http_request(black_box(&mut ctx)).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    // Condition that matches last branch
    group.bench_function("match_last", |b| {
        let pipeline = &pipeline_other;
        b.to_async(&rt).iter_batched(
            || make_request("/other/data"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                let _result = black_box(pipeline.execute_http_request(black_box(&mut ctx)).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    // No condition matches (all branches skipped)
    group.bench_function("no_match", |b| {
        let pipeline = &pipeline_api;
        b.to_async(&rt).iter_batched(
            || make_request("/unknown/data"),
            |req| async move {
                let mut ctx = make_ctx(&req);
                let _result = black_box(pipeline.execute_http_request(black_box(&mut ctx)).await.unwrap());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark result set snapshot operation for branch evaluation.
fn bench_result_set_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_chains/result_snapshot");

    for &(label, result_count) in &[("1", 1), ("5", 5), ("10", 10)] {
        let mut results = std::collections::HashMap::new();
        for i in 0..result_count {
            let mut result_set = FilterResultSet::new();
            result_set.set("status", "success").unwrap();
            result_set.set("latency", "100ms").unwrap();
            result_set.set("attempts", i.to_string()).unwrap();
            results.insert(format!("filter_{i}"), result_set);
        }

        group.bench_with_input(BenchmarkId::from_parameter(label), &results, |b, results| {
            b.iter(|| {
                let _snapshot = black_box(results.clone());
            });
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Pipeline Construction
// -----------------------------------------------------------------------------

/// Build a pipeline with `n` branches on a single filter.
fn build_pipeline_with_branches(branch_count: usize) -> FilterPipeline {
    let registry = FilterRegistry::with_builtins();

    let branch_chains: Vec<BranchChainConfig> = (0..branch_count)
        .map(|i| BranchChainConfig {
            name: format!("branch_{i}"),
            on_result: Some(BranchCondition {
                filter: "router".to_owned(),
                key: "cluster".to_owned(),
                value: "api".to_owned(),
            }),
            rejoin: "next".to_owned(),
            max_iterations: None,
            chains: vec![ChainRef::Inline {
                name: format!("chain_{i}"),
                filters: vec![filter_entry(
                    "headers",
                    &format!("request_add:\n  - name: X-Branch\n    value: branch_{i}"),
                )],
            }],
        })
        .collect();

    let mut entries = vec![
        FilterEntry {
            filter_type: "router".into(),
            config: serde_yaml::from_str(
                "routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /\n    cluster: default",
            )
            .unwrap(),
            conditions: vec![],
            response_conditions: vec![],
            name: None,
            failure_mode: praxis_core::config::FailureMode::default(),
            branch_chains: Some(branch_chains),
        },
        filter_entry("headers", "response_add:\n  - name: X-Done\n    value: \"true\""),
    ];

    FilterPipeline::build(&mut entries, &registry).unwrap()
}

/// Build a pipeline with conditional branches that match different cluster values.
fn build_pipeline_with_conditional_branches(branch_count: usize, _target_match: &str) -> FilterPipeline {
    let registry = FilterRegistry::with_builtins();

    let cluster_values = ["api", "app", "other"];
    let branch_chains: Vec<BranchChainConfig> = (0..branch_count)
        .map(|i| {
            let cluster = cluster_values[i % cluster_values.len()];
            BranchChainConfig {
                name: format!("branch_{cluster}"),
                on_result: Some(BranchCondition {
                    filter: "router".to_owned(),
                    key: "cluster".to_owned(),
                    value: cluster.to_owned(),
                }),
                rejoin: "next".to_owned(),
                max_iterations: None,
                chains: vec![ChainRef::Inline {
                    name: format!("chain_{cluster}"),
                    filters: vec![filter_entry(
                        "headers",
                        &format!("request_add:\n  - name: X-Cluster\n    value: {cluster}"),
                    )],
                }],
            }
        })
        .collect();

    let mut entries = vec![
        FilterEntry {
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /app/\n    cluster: app\n  - path_prefix: /other/\n    cluster: other\n  - path_prefix: /\n    cluster: default").unwrap(),
            conditions: vec![],
            response_conditions: vec![],
            name: None,
            failure_mode: praxis_core::config::FailureMode::default(),
            branch_chains: Some(branch_chains),
        },
    ];

    FilterPipeline::build(&mut entries, &registry).unwrap()
}

/// Build a [`FilterEntry`] from a filter type name and YAML config string.
fn filter_entry(filter_type: &str, yaml: &str) -> FilterEntry {
    FilterEntry {
        branch_chains: None,
        filter_type: filter_type.into(),
        config: serde_yaml::from_str(yaml).unwrap(),
        conditions: vec![],
        response_conditions: vec![],
        name: None,
        failure_mode: praxis_core::config::FailureMode::default(),
    }
}
