// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Criterion benchmarks for condition evaluation.

#![expect(
    clippy::min_ident_chars,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "benchmarks"
)]

use std::{collections::HashMap, hint::black_box};

#[cfg(feature = "upstream-binding")]
mod common;

#[cfg(feature = "upstream-binding")]
use common::{bench_runtime, make_ctx, make_request as make_get_request};
#[cfg(feature = "upstream-binding")]
use criterion::BatchSize;
use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderMap, HeaderValue, Method, Uri};
use praxis_core::config::{Condition, ConditionMatch};
#[cfg(feature = "upstream-binding")]
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry};
use praxis_filter::{Request, should_execute};

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

#[cfg(feature = "upstream-binding")]
criterion_group!(benches, bench_condition_eval, bench_bound_pipeline_eval);
#[cfg(not(feature = "upstream-binding"))]
criterion_group!(benches, bench_condition_eval);
criterion_main!(benches);

/// Benchmark condition evaluation across a range of scenarios.
fn bench_condition_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("condition_eval");

    // Empty conditions (always passes).
    {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        group.bench_function("empty", |b| {
            b.iter(|| should_execute(black_box(&[]), black_box(&req)));
        });
    }

    // Single path prefix (hit).
    {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        let conditions = [when_path("/api")];
        group.bench_function("path_prefix_hit", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    // Single path prefix (miss).
    {
        let req = make_request(Method::GET, "/health", HeaderMap::new());
        let conditions = [when_path("/api")];
        group.bench_function("path_prefix_miss", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    // Method match (3 allowed methods, hit).
    {
        let req = make_request(Method::POST, "/api/data", HeaderMap::new());
        let conditions = [when_methods(&["GET", "POST", "PUT"])];
        group.bench_function("method_match", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    // Header match (2 required headers, hit).
    {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));
        headers.insert("x-version", HeaderValue::from_static("2"));
        let req = make_request(Method::GET, "/api", headers);
        let conditions = [when_headers(&[("x-tenant", "acme"), ("x-version", "2")])];
        group.bench_function("header_match_2", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    // Compound: path + method + unless.
    {
        let req = make_request(Method::POST, "/api/users", HeaderMap::new());
        let conditions = [
            when_path("/api"),
            when_methods(&["POST", "PUT", "DELETE"]),
            unless_path("/api/internal"),
        ];
        group.bench_function("compound_3", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    // 10 chained conditions (all pass).
    {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        headers.insert("x-b", HeaderValue::from_static("2"));
        let req = make_request(Method::POST, "/api/v2/resource", headers);
        let conditions = [
            when_path("/api"),
            when_path("/api/v2"),
            when_methods(&["POST", "PUT"]),
            unless_path("/api/v2/admin"),
            when_headers(&[("x-a", "1")]),
            when_headers(&[("x-b", "2")]),
            unless_path("/api/v2/internal"),
            when_methods(&["POST", "PUT", "PATCH", "DELETE"]),
            when_path("/api/v2/res"),
            unless_path("/api/v2/resource/private"),
        ];
        group.bench_function("chained_10", |b| {
            b.iter(|| should_execute(black_box(&conditions), black_box(&req)));
        });
    }

    group.finish();
}

/// Benchmark the real router publication and a populated bound-upstream gate.
#[cfg(feature = "upstream-binding")]
fn bench_bound_pipeline_eval(c: &mut Criterion) {
    let runtime = bench_runtime();
    let registry = FilterRegistry::with_builtins();
    let mut entries: Vec<FilterEntry> = serde_yaml::from_str(
        r#"
- filter: router
  routes:
    - path_prefix: "/"
      cluster: inference
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  request_add:
    - name: x-bench
      value: matched
- filter: load_balancer
  conditions:
    - when:
        path: "/never"
  clusters:
    - name: inference
      http:
        application_provider: openai
      endpoints: ["127.0.0.1:9"]
"#,
    )
    .expect("valid benchmark pipeline");
    let pipeline = FilterPipeline::build(&mut entries, &registry).expect("benchmark pipeline builds");
    runtime.block_on(async {
        let request = make_get_request("/api");
        let mut ctx = make_ctx(&request);
        drop(
            pipeline
                .execute_http_request(&mut ctx)
                .await
                .expect("pipeline executes"),
        );
        assert_eq!(
            ctx.bound_application_provider(),
            Some("openai"),
            "the benchmark must measure a bound-provider hit, not a miss"
        );
    });

    c.bench_function("condition_eval/router_bound_provider_hit", |b| {
        b.to_async(&runtime).iter_batched(
            || make_get_request("/api"),
            |request| {
                let pipeline = &pipeline;
                async move {
                    let mut ctx = make_ctx(&request);
                    drop(
                        black_box(pipeline.execute_http_request(black_box(&mut ctx)).await).expect("pipeline executes"),
                    );
                }
            },
            BatchSize::SmallInput,
        );
    });
}

// -----------------------------------------------------------------------------
// Benchmark Utilities
// -----------------------------------------------------------------------------

/// Build a request with the given method, path, and headers.
fn make_request(method: Method, path: &str, headers: HeaderMap) -> Request {
    Request {
        method,
        uri: path.parse::<Uri>().expect("invalid URI"),
        headers,
    }
}

/// Build a path-prefix `When` condition.
fn when_path(prefix: &str) -> Condition {
    Condition::When(ConditionMatch {
        grpc: None,
        bound_upstream: None,
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
        selected_upstream: None,
    })
}

/// Build a method-list `When` condition.
fn when_methods(methods: &[&str]) -> Condition {
    Condition::When(ConditionMatch {
        grpc: None,
        bound_upstream: None,
        path: None,
        path_prefix: None,
        methods: Some(methods.iter().map(|s| (*s).to_owned()).collect()),
        headers: None,
        selected_upstream: None,
    })
}

/// Build a header-match `When` condition.
fn when_headers(pairs: &[(&str, &str)]) -> Condition {
    let map: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    Condition::When(ConditionMatch {
        grpc: None,
        bound_upstream: None,
        path: None,
        path_prefix: None,
        methods: None,
        headers: Some(map),
        selected_upstream: None,
    })
}

/// Build an `Unless` path-prefix condition.
fn unless_path(prefix: &str) -> Condition {
    Condition::Unless(ConditionMatch {
        grpc: None,
        bound_upstream: None,
        path: None,
        path_prefix: Some(prefix.to_owned()),
        methods: None,
        headers: None,
        selected_upstream: None,
    })
}
