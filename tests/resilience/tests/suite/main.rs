// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Resilience, fault-tolerance, and throughput test suite for Praxis.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::doc_nested_refdefs,
    clippy::expect_used,
    clippy::format_push_string,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::string_add,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    reason = "test code"
)]

mod backend_failure;
mod backend_recovery;
mod concurrent_load;
mod large_payload;
mod multi_listener_isolation;
mod rate_limit_burst;
mod throughput_body;
mod throughput_filter_chain;
mod throughput_production;
mod throughput_simple;
mod throughput_tcp;
mod throughput_utils;
