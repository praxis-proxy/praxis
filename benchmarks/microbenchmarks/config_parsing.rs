// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Criterion benchmarks for YAML config deserialization.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "benchmarks")]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(benches, bench_config_parse);
criterion_main!(benches);

/// Benchmark config parsing with varying route/cluster counts.
fn bench_config_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_parse");

    for &n in &[1, 10, 50] {
        let yaml = generate_config_yaml(n);
        group.bench_with_input(BenchmarkId::new("routes", n), &yaml, |b, yaml| {
            b.iter(|| Config::from_yaml(black_box(yaml)).unwrap());
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Benchmark Utilities
// -----------------------------------------------------------------------------

/// Generate a YAML config string with `n` routes and `n` clusters.
fn generate_config_yaml(n: usize) -> String {
    use std::fmt::Write as _;

    let mut yaml = String::from(
        "listeners:\n  - name: default\n    address: \"127.0.0.1:8080\"\n    filter_chains:\n      - main\n\
         filter_chains:\n  - name: main\n    filters:\n      - filter: router\n        routes:\n",
    );

    for i in 0..n {
        _ = write!(
            yaml,
            "          - path_prefix: \"/svc-{i}/\"\n            cluster: \"cluster-{i}\"\n"
        );
    }

    yaml.push_str("      - filter: load_balancer\n        clusters:\n");
    for i in 0..n {
        _ = write!(
            yaml,
            "          - name: \"cluster-{i}\"\n            endpoints:\n              \
             - \"10.0.{}.{}:8080\"\n              - \"10.0.{}.{}:8080\"\n",
            i / 256,
            i % 256,
            i / 256,
            (i + 1) % 256,
        );
    }

    yaml
}
