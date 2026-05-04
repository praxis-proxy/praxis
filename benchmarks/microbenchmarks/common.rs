// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shared utility functions for Criterion benchmarks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "benchmarks"
)]

use http::{HeaderMap, Method, Uri};
use praxis_filter::{HttpFilterContext, Request};

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
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        filter_results: std::collections::HashMap::new(),
        health_registry: None,
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
