// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Adapter-neutral context construction for the compiled contract example.

use praxis_filter::{FilterPipeline, HttpFilterContext, Request};

/// Build a fresh request context pinned to the supplied pipeline.
#[expect(clippy::too_many_lines, reason = "complete context initialization")]
pub(super) fn context<'request>(
    req: &'request Request,
    pipeline: &'request FilterPipeline,
) -> HttpFilterContext<'request> {
    HttpFilterContext {
        buffered_request_body: None,
        body_done_indices: Vec::new(),
        branch_iterations: std::collections::HashMap::new(),
        grpc_completion: None,
        client_addr: None,
        cluster: None,
        current_filter_id: None,
        downstream_tls: false,
        extensions: praxis_filter::RequestExtensions::default(),
        executed_branch_filters: Vec::new(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        filter_metadata: std::collections::HashMap::new(),
        prior_pre_read_mutations: Vec::new(),
        pre_read_mutations: Vec::new(),
        structured_metadata: std::collections::HashMap::new(),
        filter_results: std::collections::HashMap::new(),
        filter_state: std::collections::HashMap::new(),
        health_registry: None,
        id_generator: pipeline.id_generator(),
        kv_stores: None,
        session_stores: None,
        metrics_route: None,
        peer_identity: None,
        subrequest_client: None,
        subrequest_response_mode: praxis_filter::SubRequestResponseMode::Buffered,
        request: req,
        request_body_bytes: 0,
        request_body_mode: praxis_filter::BodyMode::Stream,
        request_start: std::time::Instant::now(),
        response_body_bytes: 0,
        response_body_mode: praxis_filter::BodyMode::Stream,
        response_header: None,
        response_headers_modified: false,
        upstream_reached: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        attempted_endpoints: Vec::new(),
        retry_policy: None,
        route_retry_policy: None,
        hedge_policy: None,
        cluster_retry_state: None,
        cluster_retry_state_released: false,
        endpoint_reselector: None,
        pinned_endpoint_address: None,
        time_source: pipeline.time_source(),
        upstream: None,
    }
}
