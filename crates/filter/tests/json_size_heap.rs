// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated allocation regression test for public JSON utilities.


use praxis_filter::json_size::{JsonSizeError, serialized_len, serialized_len_capped, to_vec_capped};

/// Tracks only allocations made while the profiler is active.
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Run the allocation assertions without concurrent libtest allocations.
fn main() -> Result<(), JsonSizeError> {
    let input = "x".repeat(1_048_576);
    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    assert_eq!(serialized_len(input.as_str())?, 1_048_578);
    let measured = dhat::HeapStats::get();
    assert_eq!(measured.total_bytes, before.total_bytes);
    assert!(matches!(
        serialized_len_capped(input.as_str(), 64),
        Err(JsonSizeError::LimitExceeded)
    ));
    assert!(matches!(
        to_vec_capped(input.as_str(), 64),
        Err(JsonSizeError::LimitExceeded)
    ));
    let after = dhat::HeapStats::get();
    assert!(after.max_bytes < 4096, "a megabyte output must never be materialized");
    assert_eq!(after.curr_bytes, 0, "partial output and errors must be dropped");
    drop(profiler);
    Ok(())
}
