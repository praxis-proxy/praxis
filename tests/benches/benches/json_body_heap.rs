// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Heap allocation profiles for extraction, guardrails, tokenizer rewrite, and a DOM reference.
//!
//! Run:
//! ```console
//! cargo bench -p praxis-tests-benches --bench json_body_heap --features dhat-heap
//! PRAXIS_HEAP_STRESS=1 PRAXIS_HEAP_OUTPUT=/tmp/praxis-heaps cargo bench -p praxis-tests-benches --bench json_body_heap --features dhat-heap
//! PRAXIS_HEAP_CYCLES=1 PRAXIS_HEAP_OUTPUT=/tmp/praxis-cycles cargo bench -p praxis-tests-benches --bench json_body_heap --features dhat-heap
//! # Optional smoke run: set PRAXIS_HEAP_MAX_MIB=1.
//! ```

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::panic,
    clippy::unwrap_used,
    reason = "benchmarks"
)]

#[expect(
    clippy::too_many_lines,
    reason = "the shared context fixture enumerates all filter context fields"
)]
mod common;
mod json_body_workload;

use bytes::Bytes;
use common::{bench_runtime, make_ctx, make_request};
use json_body_workload::{BODY_SIZES, BodyLayout, body_for_layout, tokenizer_apply};
use praxis_filter::{
    FilterAction, GuardrailsFilter, HttpFilter, Request,
    builtins::{JsonBodyFieldFilter, JsonBodyFilter},
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const ITERATIONS: usize = 20;

fn main() {
    if std::env::var_os("PRAXIS_HEAP_CYCLES").is_some() {
        warmed_filter_cycles();
        return;
    }
    if std::env::var_os("PRAXIS_HEAP_STRESS").is_some() {
        println!("profile\tshape\tbytes\titerations\ttotal_bytes\tmax_bytes\tretained_bytes\tmax_blocks\tnanoseconds");
        stress_profiles();
        warmed_filter_cycles();
        return;
    }
    println!("layout\tpath\tsize\titerations\ttotal_bytes\tmax_bytes");
    for layout in [BodyLayout::Prefix, BodyLayout::Spread] {
        let layout_name = layout_label(layout);
        for &(label, _) in BODY_SIZES {
            let body = body_for_layout(layout, label);
            bench_path(layout_name, "tokenizer", label, body, tokenizer_apply);
        }
    }
}

/// Compiled filter and prebuilt bodies for repeated success and rejection.
struct CycleFixture {
    runtime: tokio::runtime::Runtime,
    request: Request,
    filter: Box<dyn HttpFilter>,
    valid: Bytes,
    rewritten: Bytes,
    invalid: Bytes,
}

impl CycleFixture {
    /// Construct all inputs before starting the profiler.
    fn new() -> Self {
        const SIZE: usize = 1_048_576; // 1 MiB
        let config = serde_yaml::from_str(
            "max_body_bytes: 1048576\non_invalid: reject\nrequest_replace:\n  - pointer: /model\n    value: new\n",
        )
        .unwrap();
        let valid = stress_body(SIZE, "long");
        assert_eq!(valid.len(), SIZE, "the warmed cycle must exercise exactly 1 MiB");
        let mut rewritten = valid.clone();
        let needle = br#""model":"old""#;
        let position = rewritten.windows(needle.len()).position(|part| part == needle).unwrap();
        rewritten[position..position + needle.len()].copy_from_slice(br#""model":"new""#);
        let mut invalid = valid.clone();
        *invalid.last_mut().unwrap() = b'!';
        Self {
            runtime: bench_runtime(),
            request: make_request("/bulk"),
            filter: JsonBodyFilter::from_config(&config).unwrap(),
            valid: Bytes::from(valid),
            rewritten: Bytes::from(rewritten),
            invalid: Bytes::from(invalid),
        }
    }

    /// Run one actual filter callback and check its full output or rejection.
    fn run(&self, valid: bool) {
        let (original, expected) = if valid {
            (&self.valid, &self.rewritten)
        } else {
            (&self.invalid, &self.invalid)
        };
        let mut context = make_ctx(&self.request);
        let mut body = Some(original.clone());
        let action = self
            .runtime
            .block_on(self.filter.on_request_body(&mut context, &mut body, true))
            .unwrap();
        if valid {
            assert!(
                matches!(action, FilterAction::BodyDone),
                "valid input must be rewritten"
            );
        } else {
            assert!(
                matches!(action, FilterAction::Reject(rejection) if rejection.status == 400),
                "late invalid JSON must be rejected"
            );
        }
        assert_eq!(body.as_ref(), Some(expected), "the entire result must match");
    }
}

/// One stable-point sample of allocations made while profiling is active.
#[derive(Clone, Copy)]
struct CycleSample {
    total: u64,
    current: usize,
    blocks: usize,
    peak: usize,
    peak_blocks: usize,
}

impl From<dhat::HeapStats> for CycleSample {
    fn from(stats: dhat::HeapStats) -> Self {
        Self {
            total: stats.total_bytes,
            current: stats.curr_bytes,
            blocks: stats.curr_blocks,
            peak: stats.max_bytes,
            peak_blocks: stats.max_blocks,
        }
    }
}

/// Alternate warmed success and failure paths and return their stable samples.
fn sample_filter_cycles(fixture: &CycleFixture) -> (usize, [CycleSample; 64]) {
    // Stack storage keeps observations outside the profiled allocations.
    let active = profiler("warmed-json-body-success-invalid-cycles");
    let initial = dhat::HeapStats::get();
    let mut samples = [CycleSample::from(initial.clone()); 64];
    for (index, sample) in samples.iter_mut().enumerate() {
        fixture.run(index % 2 == 0);
        *sample = CycleSample::from(dhat::HeapStats::get());
    }
    drop(active);
    (initial.curr_bytes, samples)
}

/// Report allocator observations, not total process live allocations.
fn warmed_filter_cycles() {
    let fixture = CycleFixture::new();
    for _ in 0..4 {
        fixture.run(true);
        fixture.run(false);
    }
    let (initial, samples) = sample_filter_cycles(&fixture);
    println!("cycle\tcase\ttotal_bytes\tcurrent_bytes\tcurrent_blocks\tpeak_bytes\tpeak_blocks");
    for (index, sample) in samples.iter().enumerate() {
        let case = if index % 2 == 0 { "success" } else { "invalid" };
        println!(
            "{}\t{case}\t{}\t{}\t{}\t{}\t{}",
            index / 2 + 1,
            sample.total,
            sample.current,
            sample.blocks,
            sample.peak,
            sample.peak_blocks
        );
    }
    let final_live = samples.last().unwrap().current;
    assert!(
        final_live <= initial + 65_536,
        "profile live allocations grew by more than the 64 KiB runner envelope: initial={initial} final={final_live}"
    );
}

fn layout_label(layout: BodyLayout) -> &'static str {
    match layout {
        BodyLayout::Prefix => "prefix",
        BodyLayout::Spread => "spread",
    }
}

fn bench_path<F>(layout: &str, path: &str, label: &str, body: &[u8], mut apply: F)
where
    F: FnMut(&[u8]) -> Vec<u8>,
{
    let _profiler = profiler(&format!("{layout}-{path}-{label}"));
    for _ in 0..ITERATIONS {
        drop(apply(body));
    }
    let stats = dhat::HeapStats::get();
    println!(
        "{layout}\t{path}\t{label}\t{ITERATIONS}\t{}\t{}",
        stats.total_bytes, stats.max_bytes
    );
}

/// Resource profiles use one operation per shape to bound peak host load.
/// Input storage, the runtime, and compiled filters are created before each
/// profiler starts, so totals cover the operation rather than fixture setup.
#[expect(
    clippy::too_many_lines,
    reason = "the benchmark compares independent operations against each identical fixture"
)]
fn stress_profiles() {
    let _ops = json_body_workload::request_ops();
    let runtime = bench_runtime();
    let request = make_request("/bulk");
    drop(make_ctx(&request));
    let config = serde_yaml::from_str("field: model\nheader: x-praxis-model\nmax_body_bytes: 67108864\n").unwrap();
    let filter = JsonBodyFieldFilter::from_config(&config).unwrap();
    let guardrail_config = serde_yaml::from_str(
        "reject_oversized: false\nrules:\n  - target: body\n    contains: NEVER-MATCH-THIS\n  - target: body\n    contains: [ssn, credit_card, email, phone]\n",
    ).unwrap();
    let guardrails = GuardrailsFilter::from_config(&guardrail_config).unwrap();
    let mut positive_ctx = make_ctx(&request);
    let mut positive = Some(Bytes::from_static(b"{\"ssn\":\"123-45-6789\"}"));
    assert!(
        matches!(
            runtime
                .block_on(guardrails.on_request_body(&mut positive_ctx, &mut positive, true))
                .unwrap(),
            FilterAction::Reject(_)
        ),
        "PII positive control must reject"
    );
    assert!(
        "İ".to_lowercase().len() > "İ".len(),
        "unicode shape must expand on lowercasing"
    );
    let max_mib = std::env::var("PRAXIS_HEAP_MAX_MIB").map_or(64, |value| value.parse::<usize>().unwrap());
    assert!(max_mib >= 1, "at least the 1 MiB workload must be selected");
    for size in [1_048_576, 10_485_760, 67_108_864] {
        if size > max_mib.saturating_mul(1_048_576) {
            continue;
        }
        for shape in ["long", "fields", "escaped", "unicode"] {
            let body = Bytes::from(stress_body(size, shape));
            for path in [
                "field-extraction",
                "guardrails-inspection",
                "tokenizer-rewrite",
                "serde-dom-reference",
            ] {
                let _profiler = profiler(&format!("stress-{path}-{shape}-{size}"));
                let started = std::time::Instant::now();
                match path {
                    "field-extraction" => {
                        let mut context = make_ctx(&request);
                        let mut input = Some(body.clone());
                        let action = runtime
                            .block_on(filter.on_request_body(&mut context, &mut input, true))
                            .unwrap();
                        assert!(matches!(action, FilterAction::BodyDone), "the field must be extracted");
                        assert_eq!(
                            context.extra_request_headers.len(),
                            1,
                            "one model header must be promoted"
                        );
                        assert_eq!(
                            context.extra_request_headers[0].1, "old",
                            "the extracted model must match"
                        );
                    },
                    "guardrails-inspection" => {
                        let mut context = make_ctx(&request);
                        let mut input = Some(body.clone());
                        let action = runtime
                            .block_on(guardrails.on_request_body(&mut context, &mut input, true))
                            .unwrap();
                        assert!(
                            matches!(action, FilterAction::Continue),
                            "clean body must pass guardrails"
                        );
                    },
                    "tokenizer-rewrite" => {
                        let output = tokenizer_apply(&body);
                        assert!(
                            output
                                .windows(b"forced-model".len())
                                .any(|part| part == b"forced-model"),
                            "the rewrite must replace the model"
                        );
                        drop(output);
                    },
                    "serde-dom-reference" => dom_reference(&body),
                    _ => panic!("invalid profile path"),
                }
                let elapsed = started.elapsed();
                let stats = dhat::HeapStats::get();
                println!(
                    "{path}\t{shape}\t{}\t1\t{}\t{}\t{}\t{}\t{}",
                    body.len(),
                    stats.total_bytes,
                    stats.max_bytes,
                    stats.curr_bytes,
                    stats.max_blocks,
                    elapsed.as_nanos()
                );
            }
        }
    }
}

/// Reference implementation of the same extraction and rewrite operations,
/// using serde's materialized DOM rather than an active proxy filter.
fn dom_reference(body: &[u8]) {
    let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
    let object = value.as_object_mut().unwrap();
    assert_eq!(
        object.get("model").and_then(serde_json::Value::as_str),
        Some("old"),
        "DOM must extract the original model"
    );
    drop(object.insert("model".into(), serde_json::json!("forced-model")));
    drop(object.insert("tenant".into(), serde_json::json!("acme")));
    drop(object.insert("original_model".into(), serde_json::json!("old")));
    drop(object.remove("secret"));
    let output = serde_json::to_vec(&value).unwrap();
    assert!(
        output
            .windows(b"forced-model".len())
            .any(|part| part == b"forced-model"),
        "DOM rewrite must replace the model"
    );
}

/// Keep raw dhat files when an output directory is supplied; otherwise avoid
/// overwriting a file in the checkout while still reporting heap statistics.
fn profiler(label: &str) -> dhat::Profiler {
    let builder = dhat::Profiler::builder();
    match std::env::var_os("PRAXIS_HEAP_OUTPUT") {
        Some(directory) => {
            let path = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&path).unwrap();
            builder.file_name(path.join(format!("{label}.json"))).build()
        },
        None => builder.testing().build(),
    }
}

/// Build legal JSON with distinct fields, escapes, or Unicode expansion input.
/// Wide fields keep the 64 MiB fixture's object count within a host-safe budget.
#[expect(
    clippy::too_many_lines,
    reason = "the workload generator keeps all shape boundaries together"
)]
fn stress_body(size: usize, shape: &str) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(size);
    body.push_str(r#"{"model":"old","secret":"remove","pad":""#);
    if shape == "fields" {
        body.push('"');
        let value = if size >= 67_108_864 {
            "x".repeat(96)
        } else {
            "x".to_owned()
        };
        let mut field = 0;
        loop {
            let member = format!(r#","k{field}":"{value}""#);
            if body.len() + member.len() + 1 > size {
                break;
            }
            write!(body, "{member}").unwrap();
            field += 1;
        }
        body.push('}');
    } else {
        let atom = match shape {
            "long" => "x",
            "escaped" => "\\u0078",
            "unicode" => "İ",
            _ => panic!("invalid workload shape"),
        };
        let repeats = (size - body.len() - 2) / atom.len();
        for _ in 0..repeats {
            body.push_str(atom);
        }
        body.push_str("\"}");
    }
    body.into_bytes()
}
