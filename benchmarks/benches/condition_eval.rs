//! Criterion benchmarks for condition evaluation.

#![deny(unsafe_code)]

use std::{collections::HashMap, hint::black_box};

use criterion::{Criterion, criterion_group, criterion_main};
use http::{HeaderMap, HeaderValue, Method, Uri};
use praxis_core::config::{Condition, ConditionMatch};
use praxis_filter::{Request, should_execute};

// -----------------------------------------------------------------------------
// Test Utilities
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
        path: None,
        path_prefix: Some(prefix.to_string()),
        methods: None,
        headers: None,
    })
}

/// Build a method-list `When` condition.
fn when_methods(methods: &[&str]) -> Condition {
    Condition::When(ConditionMatch {
        path: None,
        path_prefix: None,
        methods: Some(methods.iter().map(|s| s.to_string()).collect()),
        headers: None,
    })
}

/// Build a header-match `When` condition.
fn when_headers(pairs: &[(&str, &str)]) -> Condition {
    let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Condition::When(ConditionMatch {
        path: None,
        path_prefix: None,
        methods: None,
        headers: Some(map),
    })
}

/// Build an `Unless` path-prefix condition.
fn unless_path(prefix: &str) -> Condition {
    Condition::Unless(ConditionMatch {
        path: None,
        path_prefix: Some(prefix.to_string()),
        methods: None,
        headers: None,
    })
}

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

criterion_group!(benches, bench_condition_eval);
criterion_main!(benches);
