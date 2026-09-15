// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Criterion benchmarks for `json_body` tokenizer rewrite.
//!
//! Run:
//! ```console
//! cargo bench -p praxis-tests-benches --bench json_body
//! cargo bench -p praxis-tests-benches --bench json_body -- spread/256kiB
//! ```
//!
//! Fixtures are OpenAI-style chat completion request bodies (`model`, `messages`, …).

#![allow(
    clippy::as_conversions,
    clippy::min_ident_chars,
    clippy::missing_docs_in_private_items,
    reason = "benchmarks"
)]

mod json_body_workload;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use json_body_workload::{BODY_SIZES, BodyLayout, body_for_layout, tokenizer_apply};

criterion_group!(benches, bench_json_body_tokenizer, bench_json_body_tokenizer_spread);

fn main() {
    benches();
}

fn bench_json_body_tokenizer(c: &mut Criterion) {
    bench_layout(c, "json_body_tokenizer", BodyLayout::Prefix, tokenizer_apply);
}

fn bench_json_body_tokenizer_spread(c: &mut Criterion) {
    bench_layout(c, "json_body_tokenizer_spread", BodyLayout::Spread, tokenizer_apply);
}

fn bench_layout<F>(c: &mut Criterion, group_name: &str, layout: BodyLayout, mut apply: F)
where
    F: FnMut(&[u8]) -> Vec<u8>,
{
    let mut group = c.benchmark_group(group_name);
    for &(label, _) in BODY_SIZES {
        let body = body_for_layout(layout, label);
        group.throughput(Throughput::Bytes(body.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &body, |b, body| {
            b.iter(|| black_box(apply(black_box(body))));
        });
    }
    group.finish();
}
