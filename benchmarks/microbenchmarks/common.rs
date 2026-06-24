// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared utility functions for Criterion benchmarks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "benchmarks"
)]

use std::sync::LazyLock;

use http::{HeaderMap, Method, Uri};
use praxis_core::id::IdGenerator;
use praxis_filter::{HttpFilterContext, Request};

/// Deterministic ID generator for benchmarks.
static BENCH_ID_GENERATOR: LazyLock<IdGenerator> = LazyLock::new(|| IdGenerator::with_seed(0));

// -----------------------------------------------------------------------------
// Tokio Runtime
// -----------------------------------------------------------------------------

/// Build a single-threaded tokio runtime for async benchmarks.
pub(crate) fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// -----------------------------------------------------------------------------
// Filter Context
// -----------------------------------------------------------------------------

/// Build an [`HttpFilterContext`] with no cluster, upstream,
/// or response header set.
pub(crate) fn make_ctx(req: &Request) -> HttpFilterContext<'_> {
    HttpFilterContext {
        body_done_indices: Vec::new(),
        branch_iterations: std::collections::HashMap::new(),
        client_addr: None,
        cluster: None,
        current_filter_id: None,
        downstream_tls: false,
        extensions: praxis_filter::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        filter_metadata: std::collections::HashMap::new(),
        filter_results: std::collections::HashMap::new(),
        filter_state: std::collections::HashMap::new(),
        health_registry: None,
        id_generator: &BENCH_ID_GENERATOR,
        kv_stores: None,
        request: req,
        request_body_bytes: 0,
        request_body_mode: praxis_filter::BodyMode::Stream,
        request_start: std::time::Instant::now(),
        response_body_bytes: 0,
        response_body_mode: praxis_filter::BodyMode::Stream,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        time_source: &praxis_core::time::SystemTimeSource,
        upstream: None,
    }
}

// -----------------------------------------------------------------------------
// HTTP Requests
// -----------------------------------------------------------------------------

/// Build a GET request targeting the given path.
pub(crate) fn make_request(path: &str) -> Request {
    Request {
        method: Method::GET,
        uri: path.parse::<Uri>().expect("invalid URI"),
        headers: HeaderMap::new(),
    }
}
