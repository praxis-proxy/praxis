// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Nested filter-context construction for a filtered sub-request.

use std::{collections::HashMap, sync::Arc, time::Instant};

use crate::{FilterPipeline, HttpFilterContext, SubRequestResponseMode};

/// Runtime resources inherited from the pipeline that owns the executor.
///
/// These mirror the server-injected resources on the outer request so a
/// nested step pipeline observes the same identity, health, and timing
/// context as the request that spawned it.
#[derive(Clone, Copy)]
pub(super) struct SubrequestRuntimeResources<'a> {
    /// Original downstream client address.
    pub(super) client_addr: Option<std::net::IpAddr>,

    /// Whether the original downstream connection uses TLS.
    pub(super) downstream_tls: bool,

    /// Shared endpoint-health state.
    pub(super) health_registry: Option<&'a praxis_core::health::HealthRegistry>,

    /// Shared request ID generator.
    pub(super) id_generator: &'a praxis_core::id::IdGenerator,

    /// Named runtime key-value stores.
    pub(super) kv_stores: Option<&'a praxis_core::kv::KvStoreRegistry>,

    /// Shared sticky-session store registry.
    pub(super) session_stores: Option<&'a Arc<crate::SessionStoreRegistry>>,

    /// Verified downstream mTLS identity.
    pub(super) peer_identity: Option<&'a Arc<praxis_tls::TlsPeerIdentity>>,

    /// Start time of the containing client request.
    pub(super) request_start: Instant,

    /// Shared client used for recursive subrequests.
    pub(super) subrequest_client: Option<&'a praxis_core::subrequest::SubRequestClient>,

    /// Server-provided wall-clock source.
    pub(super) time_source: &'a dyn praxis_core::time::TimeSource,
}

/// Build a [`HttpFilterContext`] for running a sub-request's pipeline,
/// inheriting server-injected resources from the containing request.
#[expect(clippy::too_many_lines, reason = "all fields must be initialized")]
pub(super) fn build_sub_filter_context<'a>(
    pipeline: &'a FilterPipeline,
    request: &'a crate::Request,
    runtime: SubrequestRuntimeResources<'a>,
) -> HttpFilterContext<'a> {
    HttpFilterContext {
        buffered_request_body: None,
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: runtime.client_addr,
        cluster: None,
        current_filter_id: None,
        downstream_tls: runtime.downstream_tls,
        extensions: crate::extensions::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
        filter_state: HashMap::new(),
        health_registry: runtime.health_registry,
        id_generator: runtime.id_generator,
        kv_stores: runtime.kv_stores,
        session_stores: runtime.session_stores,
        metrics_route: None,
        peer_identity: runtime.peer_identity.cloned(),
        prior_pre_read_mutations: Vec::new(),
        pre_read_mutations: Vec::new(),
        request,
        request_body_bytes: 0,
        request_body_mode: pipeline.body_capabilities().request_body_mode,
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        request_start: runtime.request_start,
        response_body_bytes: 0,
        response_body_mode: pipeline.body_capabilities().response_body_mode,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        attempted_endpoints: Vec::new(),
        retry_policy: None,
        route_retry_policy: None,
        cluster_retry_state: None,
        cluster_retry_state_released: false,
        endpoint_reselector: None,
        pinned_endpoint_address: None,
        structured_metadata: HashMap::new(),
        subrequest_client: runtime.subrequest_client,
        subrequest_response_mode: SubRequestResponseMode::Buffered,
        time_source: runtime.time_source,
        upstream: None,
    }
}
