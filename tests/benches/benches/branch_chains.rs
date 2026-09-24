// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for branch chain evaluation and execution.
//!
//! Covers branch condition matching, result set operations, filter
//! execution within branches, and rejoin logic with varying branch
//! counts and nesting levels.

#![expect(
    clippy::min_ident_chars,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

mod common;

use std::{collections::HashMap, hint::black_box};

use common::{bench_runtime, make_ctx, make_request};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::{BranchChainConfig, BranchCondition, ChainRef, InsecureOptions};
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry, FilterResultSet, Request};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Static filter names, matching the `&'static str` keys of the real
/// result-set map so the snapshot bench clones the same shape.
const FILTER_NAMES: [&str; 10] = [
    "filter_0", "filter_1", "filter_2", "filter_3", "filter_4", "filter_5", "filter_6", "filter_7", "filter_8",
    "filter_9",
];

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

/// Benchmark pipeline execution with varying numbers of unconditional branches.
fn bench_pipeline_with_branches(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("branch_chains/with_branches");

    for &(label, branch_count) in &[("1", 1), ("3", 3), ("5", 5)] {
        let pipeline = build_pipeline_with_branches(branch_count);
        assert_branch_ran(&rt, &pipeline, &make_request("/api/data"), "X-Branch");
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

/// Benchmark `on_result` branch matching against `grpc_detection` results.
fn bench_branch_condition_matching(c: &mut Criterion) {
    let rt = bench_runtime();
    let mut group = c.benchmark_group("branch_chains/condition_matching");
    let pipeline = build_pipeline_with_conditional_branches();

    for (label, content_type) in [
        ("match_first", Some("application/grpc")),
        ("match_last", Some("application/grpc+json")),
        ("no_match", None),
    ] {
        let request = grpc_request(content_type);
        if content_type.is_some() {
            assert_branch_ran(&rt, &pipeline, &request, "X-Kind");
        }
        group.bench_function(label, |b| {
            let pipeline = &pipeline;
            b.to_async(&rt).iter_batched(
                || request.clone(),
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

/// Benchmark result set snapshot operation for branch evaluation.
fn bench_result_set_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("branch_chains/result_snapshot");

    for &(label, result_count) in &[("1", 1), ("5", 5), ("10", 10)] {
        let mut results = HashMap::new();
        for (i, name) in FILTER_NAMES.iter().copied().enumerate().take(result_count) {
            let mut result_set = FilterResultSet::new();
            result_set.set("status", "success").unwrap();
            result_set.set("latency", "100ms").unwrap();
            result_set.set("attempts", i.to_string()).unwrap();
            results.insert(name, result_set);
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

/// Build a pipeline whose router hosts `branch_count` unconditional branches.
fn build_pipeline_with_branches(branch_count: usize) -> FilterPipeline {
    let branch_chains = (0..branch_count)
        .map(|i| branch(&format!("branch_{i}"), None, "X-Branch"))
        .collect();
    let mut entries = vec![
        FilterEntry {
            branch_chains: Some(branch_chains),
            ..filter_entry(
                "router",
                "routes:\n  - path_prefix: /api/\n    cluster: api\n  - path_prefix: /\n    cluster: default",
            )
        },
        filter_entry("headers", "response_add:\n  - name: X-Done\n    value: \"true\""),
    ];
    build_with_chains(&mut entries)
}

/// Build a pipeline whose `grpc_detection` filter hosts one branch per gRPC
/// kind, in the order `grpc`, `grpc+proto`, `grpc+json`.
fn build_pipeline_with_conditional_branches() -> FilterPipeline {
    let branch_chains = ["grpc", "grpc+proto", "grpc+json"]
        .into_iter()
        .enumerate()
        .map(|(i, kind)| {
            let condition = BranchCondition {
                filter: "grpc_detection".to_owned(),
                key: "kind".to_owned(),
                value: kind.to_owned(),
            };
            branch(&format!("branch_{i}"), Some(condition), "X-Kind")
        })
        .collect();
    let mut entries = vec![
        FilterEntry {
            branch_chains: Some(branch_chains),
            ..filter_entry("grpc_detection", "{}")
        },
        filter_entry("router", "routes:\n  - path_prefix: /\n    cluster: default"),
    ];
    build_with_chains(&mut entries)
}

/// A branch that rejoins at the next filter after adding `header`.
fn branch(name: &str, on_result: Option<BranchCondition>, header: &str) -> BranchChainConfig {
    BranchChainConfig {
        name: name.to_owned(),
        on_result,
        rejoin: "next".to_owned(),
        max_iterations: None,
        chains: vec![ChainRef::Inline {
            name: format!("chain_{name}"),
            filters: vec![filter_entry(
                "headers",
                &format!("request_add:\n  - name: {header}\n    value: {name}"),
            )],
        }],
    }
}

/// Build a pipeline with its branch chains resolved.
fn build_with_chains(entries: &mut [FilterEntry]) -> FilterPipeline {
    let registry = FilterRegistry::with_builtins();
    FilterPipeline::build_with_chains(entries, &registry, &HashMap::new(), &InsecureOptions::default()).unwrap()
}

/// Build a POST request with an optional `content-type`.
fn grpc_request(content_type: Option<&str>) -> Request {
    let mut request = make_request("/svc/Method");
    request.method = http::Method::POST;
    if let Some(content_type) = content_type {
        request
            .headers
            .insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    }
    request
}

/// Run `request` once and panic unless a branch added `header`, so a
/// broken config cannot silently time the branch-free path.
fn assert_branch_ran(rt: &tokio::runtime::Runtime, pipeline: &FilterPipeline, request: &Request, header: &str) {
    let mut ctx = make_ctx(request);
    let _action = rt.block_on(pipeline.execute_http_request(&mut ctx)).unwrap();
    assert!(
        ctx.extra_request_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(header)),
        "a branch should have added {header}"
    );
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
