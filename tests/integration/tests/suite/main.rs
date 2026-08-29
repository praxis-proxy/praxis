// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Integration test suite for Praxis.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
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
    clippy::iter_over_hash_type,
    clippy::items_after_statements,
    clippy::len_zero,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::map_with_unused_argument_over_ranges,
    clippy::min_ident_chars,
    clippy::needless_raw_string_hashes,
    clippy::needless_raw_strings,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::string_add,
    clippy::struct_field_names,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    clippy::wildcard_enum_match_arm,
    reason = "test code"
)]

mod adversarial;
mod body;
mod body_filter_failures;
mod body_pipeline;
mod compression;
mod conditions;
mod cors;
mod csrf;
mod downstream_read_timeout;
mod error_response;
mod examples;
mod failure_mode;
mod filter_composition;
mod filter_metadata;
mod guardrails;
mod health_check;
mod hot_reload;
mod ip_acl;
mod iterative_request_router;
mod json_body_field;
mod json_rpc;
mod path_rewrite;
mod payload_processing;
mod per_listener_pipeline;
mod pipelines_admin;
mod process_logging;
mod prometheus_metrics;
mod rate_limit;
mod retry;
mod routing;
mod security;
mod sni_router;
mod stream_buffer_adapter;
mod streaming_terminal_response;
mod tcp_access_log;
mod tcp_connection_metrics;
mod tcp_edge_cases;
mod tcp_load_balancer;
mod tls;
mod url_rewrite;
mod via;
mod websocket;
mod wildcard_routing;
