// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Heap allocation totals for `json_body` tokenizer rewrite.
//!
//! Run:
//! ```console
//! cargo bench -p praxis-tests-benches --bench json_body_heap --features dhat-heap
//! ```

#![allow(
    clippy::min_ident_chars,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    reason = "benchmarks"
)]

mod json_body_workload;

use json_body_workload::{BODY_SIZES, BodyLayout, body_for_layout, tokenizer_apply};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const ITERATIONS: usize = 20;

fn main() {
    println!("layout\tpath\tsize\titerations\ttotal_bytes\tmax_bytes");
    for layout in [BodyLayout::Prefix, BodyLayout::Spread] {
        let layout_name = layout_label(layout);
        for &(label, _) in BODY_SIZES {
            let body = body_for_layout(layout, label);
            bench_path(layout_name, "tokenizer", label, body, tokenizer_apply);
        }
    }
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
    let _profiler = dhat::Profiler::new_heap();
    for _ in 0..ITERATIONS {
        drop(apply(body));
    }
    let stats = dhat::HeapStats::get();
    println!(
        "{layout}\t{path}\t{label}\t{ITERATIONS}\t{}\t{}",
        stats.total_bytes, stats.max_bytes
    );
}
