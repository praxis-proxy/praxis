// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Streaming response lifecycle types for the iterative request router.
//!
//! The iterative request router runs step pipelines across multiple
//! sub-requests. When a step's pipeline selects streaming mode,
//! `on_request()` returns a terminal streaming response whose body
//! is owned by [`IrrStreamingBody`].
//!
//! [`IrrStreamingBody`] pulls upstream chunks through the step's
//! response-body filters until the stream ends, then runs the step's
//! completion lifecycle exactly once (owned `end_of_stream` hook).
//!
//! [`StepResponseContinuation`] holds all state needed to run body
//! filters after `on_request()` returns: the step pipeline, request
//! and response snapshots, filter extensions, filter state, metadata,
//! and a completion guard. The continuation owns an `Arc<FilterPipeline>`
//! so the pipeline outlives the router filter.

use std::{any::Any, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::subrequest::SubResponseBody;

use crate::{
    FilterError, FilterPipeline, actions::StreamingResponseBody, extensions::RequestExtensions,
    results::FilterResultSet,
};

/// State continuation for streaming a step's response body.
///
/// Owns the step pipeline, request/response snapshots, and all
/// per-filter state needed to run response-body filters after
/// `on_request()` returns. The `Arc<FilterPipeline>` outlives
/// the router filter, enabling body hooks to execute while the
/// router's `on_request` has already completed.
pub(super) struct StepResponseContinuation {
    /// Arc-wrapped step pipeline for executing response-body filters.
    pub(super) pipeline: Arc<FilterPipeline>,
    /// Snapshot of the step's request for filter context reconstruction.
    pub(super) request_snapshot: crate::Request,
    /// Snapshot of the step's response headers for filter context reconstruction.
    pub(super) response_snapshot: crate::Response,
    /// Request extensions that persist across body chunks.
    pub(super) extensions: RequestExtensions,
    /// Per-filter state that persists across body chunks.
    pub(super) filter_state: HashMap<usize, Box<dyn Any + Send + Sync>>,
    /// Filter results that persist across body chunks.
    pub(super) filter_results: HashMap<&'static str, FilterResultSet>,
    /// Filter metadata that persists across body chunks.
    pub(super) filter_metadata: HashMap<String, String>,
    /// Structured metadata that persists across body chunks.
    pub(super) structured_metadata: HashMap<String, serde_json::Value>,
    /// Tracks which filters executed during request phase.
    pub(super) executed_filter_indices: Vec<bool>,
    /// Tracks which filters completed their body hooks.
    pub(super) body_done_indices: Vec<bool>,
    /// Accumulated response body bytes seen so far.
    pub(super) response_body_bytes: u64,
    /// Response body mode from pipeline capabilities.
    pub(super) response_body_mode: crate::body::BodyMode,
    /// Whether the completion lifecycle has run.
    pub(super) completed: bool,
    /// Original downstream client address for body filter context.
    pub(super) client_addr: Option<std::net::IpAddr>,
    /// Whether the original downstream connection uses TLS.
    pub(super) downstream_tls: bool,
    /// Start time of the containing client request.
    pub(super) request_start: std::time::Instant,
    /// Verified downstream mTLS identity.
    pub(super) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
}

/// Streaming body implementation for iterative request router steps.
///
/// Pulls upstream chunks through the step's response-body filters,
/// accumulates state in the owned [`StepResponseContinuation`],
/// and runs the step's completion lifecycle exactly once after
/// upstream EOF.
///
/// The `upstream` field is `Option<SubResponseBody>` because
/// `SubResponseBody::cancel()` consumes `self`. Standard Rust
/// pattern: `.take()` to move it out for cancellation.
pub(super) struct IrrStreamingBody {
    /// Upstream streaming body handle. `None` after cancellation.
    upstream: Option<SubResponseBody>,
    /// Owned state for running step response-body filters.
    continuation: StepResponseContinuation,
    /// Whether the stream has finished (EOF or error).
    finished: bool,
}

impl IrrStreamingBody {
    /// Create a new streaming body for a step's response.
    pub(super) fn new(upstream: SubResponseBody, continuation: StepResponseContinuation) -> Self {
        Self {
            upstream: Some(upstream),
            continuation,
            finished: false,
        }
    }

    /// Run the step's response-body filters on a single chunk.
    ///
    /// Reconstructs a temporary `HttpFilterContext` from the
    /// continuation's owned state, runs the pipeline's body
    /// execution, then writes state changes back to the
    /// continuation for the next chunk.
    #[expect(clippy::too_many_lines, reason = "context reconstruction requires many fields")]
    fn run_step_body_filters(&mut self, body: &mut Option<Bytes>, end_of_stream: bool) -> Result<(), FilterError> {
        let cont = &mut self.continuation;
        let mut ctx = crate::filter::HttpFilterContext {
            buffered_request_body: None,
            body_done_indices: std::mem::take(&mut cont.body_done_indices),
            branch_iterations: HashMap::new(),
            client_addr: cont.client_addr,
            cluster: None,
            current_filter_id: None,
            downstream_tls: cont.downstream_tls,
            extensions: std::mem::take(&mut cont.extensions),
            executed_filter_indices: std::mem::take(&mut cont.executed_filter_indices),
            extra_request_headers: Vec::new(),
            filter_metadata: std::mem::take(&mut cont.filter_metadata),
            filter_results: std::mem::take(&mut cont.filter_results),
            filter_state: std::mem::take(&mut cont.filter_state),
            health_registry: None,
            id_generator: cont.pipeline.id_generator(),
            kv_stores: None,
            metrics_route: None,
            peer_identity: cont.peer_identity.clone(),
            pre_read_mutations: Vec::new(),
            request: &cont.request_snapshot,
            request_body_bytes: 0,
            request_body_mode: cont.pipeline.body_capabilities().request_body_mode,
            request_headers_to_remove: Vec::new(),
            request_headers_to_set: Vec::new(),
            request_start: cont.request_start,
            response_body_bytes: cont.response_body_bytes,
            response_body_mode: cont.response_body_mode,
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
            session_stores: None,
            structured_metadata: std::mem::take(&mut cont.structured_metadata),
            subrequest_client: None,
            subrequest_response_mode: crate::context::SubRequestResponseMode::Buffered,
            time_source: cont.pipeline.time_source(),
            upstream: None,
        };

        let result = cont.pipeline.execute_http_response_body_with_response_header(
            &mut ctx,
            body,
            end_of_stream,
            Some(&cont.response_snapshot),
        );

        cont.body_done_indices = ctx.body_done_indices;
        cont.executed_filter_indices = ctx.executed_filter_indices;
        cont.extensions = ctx.extensions;
        cont.filter_metadata = ctx.filter_metadata;
        cont.filter_results = ctx.filter_results;
        cont.filter_state = ctx.filter_state;
        cont.response_body_bytes = ctx.response_body_bytes;
        cont.structured_metadata = ctx.structured_metadata;

        match result? {
            crate::actions::FilterAction::Reject(_) => {
                Err("iterative_request_router: step body filter rejected during stream"
                    .to_owned()
                    .into())
            },
            _ => Ok(()),
        }
    }

    /// Run the step's completion lifecycle exactly once.
    ///
    /// Called after upstream EOF. Runs body filters with
    /// `end_of_stream: true` to let them emit any buffered
    /// completion chunk (e.g. a closing SSE comment or JSON
    /// array bracket).
    fn complete_step(&mut self) -> Result<Option<Bytes>, FilterError> {
        if self.continuation.completed {
            return Ok(None);
        }
        self.continuation.completed = true;
        let mut body: Option<Bytes> = None;
        self.run_step_body_filters(&mut body, true)?;
        Ok(body)
    }

    /// Handle a chunk received from the upstream.
    fn handle_upstream_chunk(&mut self, chunk: Bytes) -> Result<Option<Bytes>, FilterError> {
        let mut body = Some(chunk);
        self.run_step_body_filters(&mut body, false)?;
        Ok(body)
    }

    /// Handle upstream EOF.
    fn handle_upstream_eof(&mut self) -> Result<Option<Bytes>, FilterError> {
        let completion = self.complete_step()?;
        self.finished = true;
        if completion.as_ref().is_some_and(|b| !b.is_empty()) {
            Ok(completion)
        } else {
            Ok(None)
        }
    }

    /// Handle an upstream error.
    async fn handle_upstream_error(
        &mut self,
        e: praxis_core::subrequest::SubRequestError,
    ) -> Result<Option<Bytes>, FilterError> {
        self.finished = true;
        if let Some(upstream_body) = self.upstream.take() {
            upstream_body.cancel().await;
        }
        Err(format!("iterative_request_router: upstream stream error: {e}").into())
    }
}

#[async_trait]
impl StreamingResponseBody for IrrStreamingBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        if self.finished {
            return Ok(None);
        }

        loop {
            let upstream = self.upstream.as_mut().ok_or_else(|| -> FilterError {
                "iterative_request_router: upstream already consumed".to_owned().into()
            })?;

            match upstream.next_chunk().await {
                Ok(Some(chunk)) => {
                    if let Some(bytes) = self.handle_upstream_chunk(chunk)? {
                        return Ok(Some(bytes));
                    }
                },
                Ok(None) => return self.handle_upstream_eof(),
                Err(e) => return Box::pin(self.handle_upstream_error(e)).await,
            }
        }
    }

    async fn suppress(&mut self) -> Result<(), FilterError> {
        if !self.finished {
            self.finished = true;
            if let Some(upstream_body) = self.upstream.take() {
                upstream_body.cancel().await;
            }
            self.complete_step()?;
        }
        Ok(())
    }

    async fn cancel(&mut self) {
        if !self.finished {
            self.finished = true;
            if let Some(upstream_body) = self.upstream.take() {
                upstream_body.cancel().await;
            }
        }
    }
}
