// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Integration test suite for Praxis.

#![allow(
    clippy::allow_attributes_without_reason,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::doc_nested_refdefs,
    clippy::expect_used,
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
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::used_underscore_binding,
    clippy::useless_format,
    reason = "test code"
)]

mod adversarial;
mod body;
mod body_pipeline;
mod compression;
mod conditions;
mod cors;
mod downstream_read_timeout;
mod examples;
mod failure_mode;
mod filter_composition;
mod guardrails;
mod health_check;
mod ip_acl;
mod json_body_field;
mod path_rewrite;
mod payload_processing;
mod per_listener_pipeline;
mod rate_limit;
mod retry;
mod routing;
mod security;
mod sni_router;
mod tcp_access_log;
mod tcp_load_balancer;
mod tls;
mod url_rewrite;
mod websocket;
mod wildcard_routing;
