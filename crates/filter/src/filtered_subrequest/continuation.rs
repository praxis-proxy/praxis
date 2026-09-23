// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Owned response-lifecycle continuation for a filtered sub-request.
//!
//! [`FilteredSubrequestContinuation`] holds all state needed to run
//! response-body filters after the executor's `execute()` returns: the
//! step pipeline, request and response snapshots, filter extensions,
//! filter state, metadata, and a completion guard. The continuation owns
//! an `Arc<FilterPipeline>` so the pipeline outlives the executor's caller.

use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use bytes::Bytes;

use super::restore_parent_upstream_scope;
use crate::{
    FilterPipeline, StreamTermination,
    context::PendingStreamChunks,
    extensions::RequestExtensions,
    results::{FilterResultSet, RetainedFilterResults},
};

/// Generic state made available after a sub-request's completion hook has run.
///
/// The executor extracts only the executor-owned mechanisms
/// (`RetainedFilterResults`, `PendingStreamChunks`, `StreamTermination`) into
/// typed fields. Any caller-injected extension types remain inside
/// [`extensions`](Self::extensions) for the caller to recover.
pub(crate) struct SubrequestCompletion {
    /// Request extensions after completion, still holding caller-owned types.
    pub(crate) extensions: RequestExtensions,
    /// Results retained across all sub-request phases.
    #[cfg_attr(
        not(feature = "iterative-request-router"),
        expect(dead_code, reason = "read only by the iterative_request_router continuation path")
    )]
    pub(crate) filter_results: HashMap<&'static str, FilterResultSet>,
    /// Bounded locally emitted chunks.
    pub(crate) pending_chunks: VecDeque<Bytes>,
    /// Typed abnormal source termination, when present.
    pub(crate) termination: Option<StreamTermination>,
}

/// State continuation for streaming a sub-request's response body.
///
/// Owns the step pipeline, request/response snapshots, and all per-filter
/// state needed to run response-body filters after `execute()` returns. The
/// `Arc<FilterPipeline>` outlives the executor's caller, enabling body hooks
/// to run while the caller's request-phase hook has already completed.
pub(crate) struct FilteredSubrequestContinuation {
    /// Arc-wrapped step pipeline for executing response-body filters.
    pub(super) pipeline: Arc<FilterPipeline>,
    /// Snapshot of the request for filter context reconstruction.
    pub(super) request_snapshot: crate::Request,
    /// Snapshot of the response headers for filter context reconstruction.
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
    /// Absolute deadline shared by header and body processing for this step.
    pub(super) step_deadline: std::time::Instant,
    /// Verified downstream mTLS identity.
    pub(super) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
}

impl FilteredSubrequestContinuation {
    /// Capture all owned step context after response headers have run.
    #[expect(
        clippy::too_many_arguments,
        reason = "capture owns the complete response continuation boundary"
    )]
    pub(super) fn capture(
        pipeline: Arc<FilterPipeline>,
        request_snapshot: crate::Request,
        response_snapshot: crate::Response,
        ctx: &mut crate::filter::HttpFilterContext<'_>,
        completed: bool,
        step_deadline: std::time::Instant,
    ) -> Self {
        Self {
            pipeline,
            request_snapshot,
            response_snapshot,
            extensions: std::mem::take(&mut ctx.extensions),
            filter_state: std::mem::take(&mut ctx.filter_state),
            filter_results: std::mem::take(&mut ctx.filter_results),
            filter_metadata: std::mem::take(&mut ctx.filter_metadata),
            structured_metadata: std::mem::take(&mut ctx.structured_metadata),
            executed_filter_indices: std::mem::take(&mut ctx.executed_filter_indices),
            body_done_indices: std::mem::take(&mut ctx.body_done_indices),
            response_body_bytes: ctx.response_body_bytes,
            response_body_mode: ctx.response_body_mode,
            completed,
            client_addr: ctx.client_addr,
            downstream_tls: ctx.downstream_tls,
            request_start: ctx.request_start,
            step_deadline,
            peer_identity: ctx.peer_identity.clone(),
        }
    }

    /// Recover caller-owned extensions, dropping executor-owned mechanisms.
    ///
    /// Removes the executor's own transient extension types
    /// (`RetainedFilterResults`, `PendingStreamChunks`, `StreamTermination`).
    /// Caller-injected extension types remain for the caller to strip before
    /// returning them to the parent request context.
    pub(crate) fn into_parent_extensions(mut self) -> RequestExtensions {
        restore_parent_upstream_scope(&mut self.extensions);
        self.extensions.remove::<PendingStreamChunks>();
        self.extensions.remove::<RetainedFilterResults>();
        self.extensions.remove::<StreamTermination>();
        self.extensions
    }

    /// Consume the completed continuation into generic completion state.
    ///
    /// Executor-owned mechanisms are lifted into typed fields; caller-injected
    /// extension types remain inside [`SubrequestCompletion::extensions`].
    pub(crate) fn into_completion(mut self) -> SubrequestCompletion {
        restore_parent_upstream_scope(&mut self.extensions);
        let pending_chunks = self
            .extensions
            .remove::<PendingStreamChunks>()
            .map_or_else(VecDeque::new, PendingStreamChunks::into_chunks);
        let termination = self.extensions.remove::<StreamTermination>();
        let mut filter_results = self.extensions.remove::<RetainedFilterResults>().unwrap_or_default().0;
        filter_results.extend(self.filter_results);
        SubrequestCompletion {
            extensions: self.extensions,
            filter_results,
            pending_chunks,
            termination,
        }
    }

    /// Borrow the retained request extensions.
    ///
    /// The caller reads its own injected extension types (for example an
    /// iteration-state marker) without consuming the continuation.
    #[cfg_attr(
        not(feature = "iterative-request-router"),
        expect(dead_code, reason = "used only by the iterative_request_router filter")
    )]
    pub(crate) fn extensions(&self) -> &RequestExtensions {
        &self.extensions
    }
}
