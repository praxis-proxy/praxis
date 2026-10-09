// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Body capabilities computation for filter pipelines.
//!
//! Scans every filter's [`BodyAccess`] and [`BodyMode`] declarations to
//! produce a single [`BodyCapabilities`] that the handler layer uses to
//! decide whether to enable body filter hooks. Mode merging promotes the
//! pipeline to `StreamBuffer` if any filter requests it, keeping the
//! largest buffer limit so every filter gets enough data. A
//! filter-declared `SizeLimit` is ignored by the merge; `SizeLimit` is
//! reserved for the listener body ceiling applied by `apply_body_limits`.
//!
//! Called once at pipeline build time by [`FilterPipeline::from_filters`].
//!
//! [`BodyAccess`]: crate::body::BodyAccess
//! [`BodyMode`]: crate::body::BodyMode
//! [`BodyCapabilities`]: crate::body::BodyCapabilities
//! [`FilterPipeline::from_filters`]: super::FilterPipeline

use praxis_core::config::{ABSOLUTE_MAX_BODY_BYTES, ResponseCondition};

use super::filter::PipelineFilter;
use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
};

// -----------------------------------------------------------------------------
// Body Mode Merging
// -----------------------------------------------------------------------------

/// Merge two optional size limits, keeping the largest value.
///
/// `None` represents unbounded buffering and is treated as larger
/// than any finite limit. When both sides are `Some`, the larger
/// value wins so that every filter in the pipeline gets enough
/// buffer to do its job. The pipeline-level body ceiling (applied
/// separately via [`apply_body_limits`]) remains the hard safety cap.
///
/// [`apply_body_limits`]: super::FilterPipeline::apply_body_limits
pub(super) fn merge_optional_limits(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (None, _) | (_, None) => None,
        // unreachable, but spelled out for clarity — both None is still None
    }
}

/// Merge a filter's body mode into the current accumulated mode.
///
/// Only a filter's `StreamBuffer` changes the accumulated mode: it
/// replaces `Stream` or `SizeLimit`, and when two `StreamBuffer` modes
/// merge, the **largest** limit wins so that every filter gets enough
/// buffer to do its job. A filter-declared `SizeLimit` (and `Stream`) is
/// ignored here; `SizeLimit` is reserved for the listener body ceiling,
/// which `apply_body_limits` applies separately as the hard safety cap.
pub(crate) fn merge_body_mode(current: &mut BodyMode, filter_mode: BodyMode) {
    match filter_mode {
        BodyMode::StreamBuffer { max_bytes } => {
            *current = match *current {
                BodyMode::Stream | BodyMode::SizeLimit { .. } => BodyMode::StreamBuffer { max_bytes },
                BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                    max_bytes: merge_optional_limits(existing, max_bytes),
                },
            };
        },
        BodyMode::SizeLimit { .. } | BodyMode::Stream => {},
    }
}

// -----------------------------------------------------------------------------
// Body Capabilities
// -----------------------------------------------------------------------------

/// Merge all filters' body access declarations into a single capability set.
pub(super) fn compute_body_capabilities(filters: &[PipelineFilter]) -> BodyCapabilities {
    let mut caps = BodyCapabilities::default();
    accumulate_caps(&mut caps, filters);
    caps
}

/// Precompute the pipeline indices of filters that declared body access.
///
/// The body-chunk loops run once per chunk; walking only these indices
/// skips non-body filters without a per-chunk predicate check. The request
/// set holds only filters whose [`effective_request_body_phase`] is
/// [`PreRead`]: a dual-access filter deferred to the binding barrier runs its
/// hook there instead and is excluded here.
///
/// [`PreRead`]: RequestBodyPhase::PreRead
pub(super) fn body_filter_indices(filters: &[PipelineFilter]) -> (Vec<usize>, Vec<usize>) {
    let mut request = Vec::new();
    let mut response = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        if effective_request_body_phase(pf) == RequestBodyPhase::PreRead {
            request.push(idx);
        }
        if let AnyFilter::Http(f) = &pf.filter
            && f.response_body_access() != BodyAccess::None
        {
            response.push(idx);
        }
    }
    (request, response)
}

/// Precompute the pipeline indices of top-level filters that run the
/// request-head phase.
///
/// The head loop runs each of these filters' [`on_request_head`] hook before
/// any `StreamBuffer` request-body pre-read; walking only these indices skips
/// non-participating filters without a per-request predicate check. A filter
/// opts in by overriding [`runs_request_head`].
///
/// Top-level only: branch filters never run the head hook, matching the
/// body-phase precompute helpers.
///
/// [`on_request_head`]: crate::HttpFilter::on_request_head
/// [`runs_request_head`]: crate::HttpFilter::runs_request_head
pub(super) fn request_head_filter_indices(filters: &[PipelineFilter]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        if let AnyFilter::Http(f) = &pf.filter
            && f.runs_request_head()
        {
            indices.push(idx);
        }
    }
    indices
}

/// Precompute the pipeline indices of filters that declared
/// selected-upstream request-body access.
///
/// Top-level only: branch filters never run body hooks, so a
/// selected-upstream declaration inside a branch is rejected at build
/// time rather than collected here.
pub(super) fn selected_upstream_request_body_indices(filters: &[PipelineFilter]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        if let AnyFilter::Http(f) = &pf.filter
            && f.selected_upstream_request_body_access() != BodyAccess::None
        {
            indices.push(idx);
        }
    }
    indices
}

/// Precompute the pipeline indices of filters that run at the bound-upstream
/// request-body barrier.
///
/// A filter runs here when its [`effective_request_body_phase`] is
/// [`BoundUpstream`]: a bound-only declaration, or a dual-access declaration
/// whose `bound_upstream` condition defers it past the binding router. Such
/// dual-access filters are correspondingly excluded from the pre-read set in
/// [`body_filter_indices`], so each hook runs exactly once.
///
/// Top-level only: branch filters never run body hooks, so a bound-upstream
/// declaration inside a branch is rejected at build time rather than
/// collected here.
///
/// [`BoundUpstream`]: RequestBodyPhase::BoundUpstream
#[cfg(feature = "bound-upstream-request-body")]
pub(super) fn bound_upstream_request_body_indices(filters: &[PipelineFilter]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        if effective_request_body_phase(pf) == RequestBodyPhase::BoundUpstream {
            indices.push(idx);
        }
    }
    indices
}

/// Whether the filter declares bound-upstream request-body access.
///
/// Always `false` unless the experimental `bound-upstream-request-body`
/// feature compiles the hook in.
pub(super) fn participates_in_bound_upstream_body(filter: &dyn crate::filter::HttpFilter) -> bool {
    #[cfg(feature = "bound-upstream-request-body")]
    {
        filter.bound_upstream_request_body_access() != BodyAccess::None
    }
    #[cfg(not(feature = "bound-upstream-request-body"))]
    {
        let _ = filter;
        false
    }
}

/// The single request-body phase a filter's hook effectively runs in.
///
/// A filter may declare pre-read access ([`request_body_access`]) and
/// bound-upstream access ([`bound_upstream_request_body_access`]). Declaring
/// both means "defer this operation to the binding barrier when my conditions
/// require it," never "run twice": a `bound_upstream` request condition selects
/// [`BoundUpstream`], its absence selects [`PreRead`]. Core resolves exactly one
/// phase per filter so the hook runs exactly once.
///
/// [`request_body_access`]: crate::HttpFilter::request_body_access
/// [`bound_upstream_request_body_access`]: crate::HttpFilter::bound_upstream_request_body_access
/// [`PreRead`]: RequestBodyPhase::PreRead
/// [`BoundUpstream`]: RequestBodyPhase::BoundUpstream
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum RequestBodyPhase {
    /// The filter runs no request-body hook.
    None,
    /// The pre-read phase, before the request phase selects an upstream.
    PreRead,
    /// The bound-upstream barrier, after the router binds a logical upstream.
    BoundUpstream,
}

/// Resolve the single [`RequestBodyPhase`] a filter's request-body hook runs in.
///
/// Applies the dual-access truth table: a pre-read-only declaration runs
/// [`PreRead`], a bound-only declaration runs [`BoundUpstream`], and a
/// dual-access declaration defers to [`BoundUpstream`] exactly when the filter
/// carries a `bound_upstream` request condition, otherwise [`PreRead`]. Filters
/// that declare neither access (or are not HTTP filters) run no hook.
///
/// [`PreRead`]: RequestBodyPhase::PreRead
/// [`BoundUpstream`]: RequestBodyPhase::BoundUpstream
pub(super) fn effective_request_body_phase(pf: &PipelineFilter) -> RequestBodyPhase {
    let AnyFilter::Http(filter) = &pf.filter else {
        return RequestBodyPhase::None;
    };
    let pre_read = filter.request_body_access() != BodyAccess::None;
    let bound = participates_in_bound_upstream_body(filter.as_ref());
    match (pre_read, bound) {
        (false, false) => RequestBodyPhase::None,
        (true, false) => RequestBodyPhase::PreRead,
        (false, true) => RequestBodyPhase::BoundUpstream,
        // Dual-access: defer to the barrier only when a bound_upstream
        // condition requires the binding, otherwise run pre-read.
        (true, true) => {
            if pf.has_bound_upstream_condition() {
                RequestBodyPhase::BoundUpstream
            } else {
                RequestBodyPhase::PreRead
            }
        },
    }
}

/// Indices of filters declaring response-trailer access.
pub(super) fn response_trailer_filter_indices(filters: &[PipelineFilter]) -> Vec<usize> {
    filters
        .iter()
        .enumerate()
        .filter_map(|(idx, pf)| match &pf.filter {
            AnyFilter::Http(f) if f.response_trailer_access() => Some(idx),
            AnyFilter::Http(_) | AnyFilter::Tcp(_) => None,
        })
        .collect()
}

/// Recursively accumulate body capabilities from a slice of pipeline filters.
pub(super) fn accumulate_caps(caps: &mut BodyCapabilities, filters: &[PipelineFilter]) {
    accumulate_caps_inner(caps, filters, false);
}

/// Recursive worker for [`accumulate_caps`].
///
/// Branch sub-chains run only header hooks: body hooks never execute for
/// filters inside branches, so their body access declarations must not
/// enable pipeline-wide buffering (`in_branch` skips body accumulation).
/// Request-context needs still accumulate because `on_request` runs.
fn accumulate_caps_inner(caps: &mut BodyCapabilities, filters: &[PipelineFilter], in_branch: bool) {
    for pf in filters {
        let http_filter = match &pf.filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };

        if !in_branch {
            // A dual-access filter contributes to exactly one request-body
            // phase, matching where its single hook runs (see
            // `effective_request_body_phase`), so read/write capabilities and
            // the buffered mode are computed for the selected phase only.
            match effective_request_body_phase(pf) {
                RequestBodyPhase::PreRead => accumulate_request_body(caps, http_filter),
                RequestBodyPhase::BoundUpstream => {
                    #[cfg(feature = "bound-upstream-request-body")]
                    accumulate_bound_upstream_request_body(caps, http_filter);
                },
                RequestBodyPhase::None => {},
            }
            accumulate_selected_upstream_request_body(caps, http_filter);
            accumulate_response_body(caps, http_filter, &pf.response_conditions);
            if !caps.any_response_condition_uses_headers {
                caps.any_response_condition_uses_headers = resp_conditions_use_headers(&pf.response_conditions);
            }
        }

        if http_filter.needs_request_context() {
            caps.needs_request_context = true;
        }

        for branch in &pf.branches {
            accumulate_caps_inner(caps, &branch.filters, true);
        }
    }
}

/// Accumulate request body capabilities from a single filter.
fn accumulate_request_body(caps: &mut BodyCapabilities, filter: &dyn crate::filter::HttpFilter) {
    let access = filter.request_body_access();
    if access != BodyAccess::None {
        caps.needs_request_body = true;
        if access == BodyAccess::ReadWrite {
            caps.any_request_body_writer = true;
        }
        merge_body_mode(&mut caps.request_body_mode, filter.request_body_mode());
    }
}

/// Accumulate selected-upstream request body capabilities from a single filter.
///
/// A participating filter contributes to the *global* request-body
/// capabilities (`needs_request_body`, the request-body writer flag, and
/// the effective `request_body_mode`) because the selected-upstream phase
/// operates on the same buffered request body: the pipeline must buffer it
/// (a bounded `StreamBuffer`) for the phase to have anything to run on. It
/// also sets selected-specific flags so downstream layers can skip the
/// phase entirely when no filter participates.
///
/// The contributed mode is promoted defensively: a participant that
/// declared a non-buffering `request_body_mode` (rejected by validation,
/// but not relied on here) still forces a bounded `StreamBuffer` capped at
/// [`ABSOLUTE_MAX_BODY_BYTES`] so the phase never runs against an
/// unbuffered or unbounded body.
///
/// [`ABSOLUTE_MAX_BODY_BYTES`]: praxis_core::config::ABSOLUTE_MAX_BODY_BYTES
fn accumulate_selected_upstream_request_body(caps: &mut BodyCapabilities, filter: &dyn crate::filter::HttpFilter) {
    let access = filter.selected_upstream_request_body_access();
    if access == BodyAccess::None {
        return;
    }
    caps.needs_selected_upstream_request_body = true;
    caps.needs_request_body = true;
    if access == BodyAccess::ReadWrite {
        caps.any_selected_upstream_request_body_writer = true;
        caps.any_request_body_writer = true;
    }
    merge_body_mode(&mut caps.request_body_mode, selected_upstream_body_mode(filter));
}

/// The buffered body mode a selected-upstream participant contributes.
///
/// The phase needs the complete body, so any declaration that is not
/// already a bounded `StreamBuffer` is promoted to one capped at the
/// absolute ceiling. Validation rejects such declarations, but the
/// capability computation stays safe on its own: it never yields an
/// unbuffered or unbounded mode for a selected-upstream participant.
fn selected_upstream_body_mode(filter: &dyn crate::filter::HttpFilter) -> BodyMode {
    buffered_body_mode(filter)
}

/// Accumulate bound-upstream request body capabilities from a single filter.
///
/// A participating filter contributes to the *global* request-body
/// capabilities (`needs_request_body`, the request-body writer flag, and the
/// effective `request_body_mode`) because the bound-upstream barrier operates
/// on the same buffered request body: the pipeline must buffer it (a bounded
/// `StreamBuffer`) so the canonical body is populated before the request
/// phase reaches the binding router.
///
/// The contributed mode is promoted defensively to a bounded `StreamBuffer`
/// capped at [`ABSOLUTE_MAX_BODY_BYTES`], mirroring the selected-upstream
/// phase, so the barrier never runs against an unbuffered or unbounded body.
///
/// [`ABSOLUTE_MAX_BODY_BYTES`]: praxis_core::config::ABSOLUTE_MAX_BODY_BYTES
#[cfg(feature = "bound-upstream-request-body")]
fn accumulate_bound_upstream_request_body(caps: &mut BodyCapabilities, filter: &dyn crate::filter::HttpFilter) {
    let access = filter.bound_upstream_request_body_access();
    if access == BodyAccess::None {
        return;
    }
    caps.needs_request_body = true;
    if access == BodyAccess::ReadWrite {
        caps.any_request_body_writer = true;
    }
    merge_body_mode(&mut caps.request_body_mode, buffered_body_mode(filter));
}

/// The buffered body mode a phase participant contributes.
///
/// A post-header body phase needs the complete body, so any declaration
/// that is not already a bounded `StreamBuffer` is promoted to one capped
/// at the absolute ceiling. Validation rejects such declarations, but the
/// capability computation stays safe on its own: it never yields an
/// unbuffered or unbounded mode for a participant.
fn buffered_body_mode(filter: &dyn crate::filter::HttpFilter) -> BodyMode {
    match filter.request_body_mode() {
        BodyMode::StreamBuffer { max_bytes: Some(limit) } => BodyMode::StreamBuffer { max_bytes: Some(limit) },
        _ => BodyMode::StreamBuffer {
            max_bytes: Some(ABSOLUTE_MAX_BODY_BYTES),
        },
    }
}

/// Accumulate response body capabilities from a single filter.
fn accumulate_response_body(
    caps: &mut BodyCapabilities,
    filter: &dyn crate::filter::HttpFilter,
    response_conditions: &[ResponseCondition],
) {
    let access = filter.response_body_access();
    if access != BodyAccess::None {
        caps.needs_response_body = true;
        if !response_conditions.is_empty() {
            caps.any_response_body_condition = true;
        }
        if access == BodyAccess::ReadWrite {
            caps.any_response_body_writer = true;
        }
        merge_body_mode(&mut caps.response_body_mode, filter.response_body_mode());
    }
    if filter.response_trailer_access() {
        caps.needs_response_trailers = true;
    }
}

/// Check whether any response condition references headers.
fn resp_conditions_use_headers(conditions: &[ResponseCondition]) -> bool {
    conditions.iter().any(|c| {
        let m = match c {
            ResponseCondition::When(m) | ResponseCondition::Unless(m) => m,
        };
        m.headers.is_some() || m.headers_present.is_some()
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::config::{FailureMode, ResponseConditionMatch};

    use super::*;

    #[test]
    fn merge_body_mode_stream_buffer_wins_over_stream() {
        let mut mode = BodyMode::Stream;
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "StreamBuffer should replace Stream"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_wins_over_size_limit() {
        let mut mode = BodyMode::SizeLimit { max_bytes: 4096 };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(2048) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "StreamBuffer should replace SizeLimit"
        );
    }

    #[test]
    fn merge_body_mode_size_limit_is_noop() {
        let mut mode = BodyMode::Stream;
        merge_body_mode(&mut mode, BodyMode::SizeLimit { max_bytes: 4096 });
        assert_eq!(
            mode,
            BodyMode::Stream,
            "SizeLimit should not change Stream (treated as noop in merge)"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_merges_limits() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: Some(2048) };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "larger StreamBuffer limit should win"
        );
    }

    #[test]
    fn merge_body_mode_stream_buffer_none_with_some() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: None };
        merge_body_mode(&mut mode, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: None },
            "None (unbounded) should win over Some"
        );
    }

    #[test]
    fn merge_body_mode_stream_is_noop() {
        let mut mode = BodyMode::StreamBuffer { max_bytes: Some(1024) };
        merge_body_mode(&mut mode, BodyMode::Stream);
        assert_eq!(
            mode,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "Stream should not change existing mode"
        );
    }

    #[test]
    fn merge_optional_limits_both_some_picks_larger() {
        assert_eq!(
            merge_optional_limits(Some(100), Some(50)),
            Some(100),
            "should pick larger of two Some values"
        );
    }

    #[test]
    fn merge_optional_limits_one_none() {
        assert_eq!(
            merge_optional_limits(Some(100), None),
            None,
            "None (unbounded) should win over Some (left)"
        );
        assert_eq!(
            merge_optional_limits(None, Some(200)),
            None,
            "None (unbounded) should win over Some (right)"
        );
    }

    #[test]
    fn merge_optional_limits_both_none() {
        assert_eq!(merge_optional_limits(None, None), None, "both None should yield None");
    }

    #[test]
    fn resp_conditions_use_headers_true_when_headers_present() {
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: None,
            headers: Some(HashMap::from([("x-key".to_owned(), "val".to_owned())])),
            headers_present: None,
        })];
        assert!(
            resp_conditions_use_headers(&conds),
            "should return true when a condition has headers"
        );
    }

    #[test]
    fn resp_conditions_use_headers_counts_the_headers_present_predicate() {
        let conds = vec![ResponseCondition::Unless(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
            headers_present: Some(vec!["cache-control".to_owned()]),
        })];
        assert!(
            resp_conditions_use_headers(&conds),
            "a headers_present predicate reads response headers too"
        );
    }

    #[test]
    fn resp_conditions_use_headers_false_when_status_only() {
        let conds = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
            headers_present: None,
        })];
        assert!(
            !resp_conditions_use_headers(&conds),
            "should return false when conditions only use status"
        );
    }

    #[test]
    fn resp_conditions_use_headers_false_when_empty() {
        assert!(
            !resp_conditions_use_headers(&[]),
            "should return false when no conditions"
        );
    }

    #[test]
    fn resp_conditions_use_headers_unless_variant() {
        let conds = vec![ResponseCondition::Unless(ResponseConditionMatch {
            status: None,
            headers: Some(HashMap::from([("x-skip".to_owned(), "yes".to_owned())])),
            headers_present: None,
        })];
        assert!(
            resp_conditions_use_headers(&conds),
            "should return true for Unless variant with headers"
        );
    }

    #[test]
    fn body_caps_marks_response_body_conditions_for_status_only() {
        use crate::{FilterAction, FilterError};

        /// Minimal response-body filter for capability tests.
        struct ResponseBodyFilter;

        #[async_trait::async_trait]
        impl crate::HttpFilter for ResponseBodyFilter {
            fn name(&self) -> &'static str {
                "response_body"
            }

            async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn response_body_access(&self) -> BodyAccess {
                BodyAccess::ReadOnly
            }
        }

        let conditions = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![200]),
            headers: None,
            headers_present: None,
        })];
        let filter = PipelineFilter::new(0, AnyFilter::Http(Box::new(ResponseBodyFilter)), vec![], conditions);
        let caps = compute_body_capabilities(&[filter]);

        assert!(
            caps.any_response_body_condition,
            "status-only response body conditions should require response header snapshots"
        );
        assert!(
            !caps.any_response_condition_uses_headers,
            "status-only conditions should not set the header-specific flag"
        );
    }

    #[test]
    fn body_caps_ignore_branch_body_filters() {
        use std::sync::Arc;

        use async_trait::async_trait;
        use bytes::Bytes;

        use crate::{
            FilterAction, FilterError,
            filter::HttpFilter,
            pipeline::branch::{RejoinTarget, ResolvedBranch},
        };

        struct BranchBodyFilter;

        #[async_trait]
        impl HttpFilter for BranchBodyFilter {
            fn name(&self) -> &'static str {
                "branch_body"
            }

            async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadWrite
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::StreamBuffer { max_bytes: Some(4096) }
            }

            async fn on_request_body(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
                _body: &mut Option<Bytes>,
                _eos: bool,
            ) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }
        }

        let branch_filter = PipelineFilter {
            filter_id: 100,
            is_security: false,
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(BranchBodyFilter)),
            name: None,
            response_conditions: vec![],
        };
        let branch = ResolvedBranch {
            condition: None,
            filters: vec![branch_filter],
            max_iterations: None,
            name: Arc::from("body_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            filter_id: 0,
            is_security: false,
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);
        assert!(
            !caps.needs_request_body,
            "branch filters run no body hooks; their body access must not enable buffering"
        );
        assert!(
            !caps.any_request_body_writer,
            "ReadWrite filter in branch must not set writer flag"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::Stream,
            "StreamBuffer mode from branch filter must not propagate"
        );
    }

    #[test]
    fn body_caps_branch_filters_still_accumulate_request_context() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        /// Branch filter that needs the request context on `on_request`.
        struct ContextFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for ContextFilter {
            fn name(&self) -> &'static str {
                "context_filter"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn needs_request_context(&self) -> bool {
                true
            }
        }

        let branch = ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                100,
                AnyFilter::Http(Box::new(ContextFilter)),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("context_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            filter_id: 0,
            is_security: false,
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);
        assert!(
            caps.needs_request_context,
            "branch filters run on_request, so request-context needs must accumulate"
        );
    }

    #[test]
    fn body_caps_no_branch_body_filters_has_no_effect() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        let branch = ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                100,
                AnyFilter::Http(Box::new(NoopHttpFilter)),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("noop_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            filter_id: 0,
            is_security: false,
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);
        assert!(
            !caps.needs_request_body,
            "branch without body filters should not enable request body"
        );
    }

    #[test]
    fn body_caps_selected_upstream_read_write_participation() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(SelectedUpstreamCapFilter {
                access: BodyAccess::ReadWrite,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert!(
            caps.needs_selected_upstream_request_body,
            "selected participant should set needs_selected_upstream_request_body"
        );
        assert!(
            caps.needs_request_body,
            "selected participant must contribute to the global request-body need"
        );
        assert!(
            caps.any_selected_upstream_request_body_writer,
            "ReadWrite selected participant should set the selected writer flag"
        );
        assert!(
            caps.any_request_body_writer,
            "ReadWrite selected participant must contribute to the global writer flag"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "selected participant's bounded StreamBuffer should drive the effective mode"
        );
    }

    #[test]
    fn body_caps_selected_upstream_read_only_is_not_writer() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(SelectedUpstreamCapFilter {
                access: BodyAccess::ReadOnly,
                mode: BodyMode::StreamBuffer { max_bytes: Some(2048) },
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert!(
            caps.needs_selected_upstream_request_body,
            "read-only selected participant should still need the phase"
        );
        assert!(
            caps.needs_request_body,
            "read-only selected participant needs request body"
        );
        assert!(
            !caps.any_selected_upstream_request_body_writer,
            "read-only selected participant must not set the selected writer flag"
        );
        assert!(
            !caps.any_request_body_writer,
            "read-only selected participant must not set the global writer flag"
        );
    }

    #[test]
    fn body_caps_selected_upstream_defensive_ceiling() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(SelectedUpstreamCapFilter {
                access: BodyAccess::ReadOnly,
                mode: BodyMode::Stream,
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert_eq!(
            caps.request_body_mode,
            BodyMode::StreamBuffer {
                max_bytes: Some(ABSOLUTE_MAX_BODY_BYTES),
            },
            "a non-bounded selected participant must fall back to the finite absolute ceiling"
        );
    }

    #[test]
    fn body_caps_ignore_branch_selected_upstream_filters() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        let branch = ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                100,
                AnyFilter::Http(Box::new(SelectedUpstreamCapFilter {
                    access: BodyAccess::ReadWrite,
                    mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
                })),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("selected_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            filter_id: 0,
            is_security: false,
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);

        assert!(
            !caps.needs_selected_upstream_request_body,
            "selected participant inside a branch must not enable the phase"
        );
        assert!(
            !caps.needs_request_body,
            "branch selected participant must not enable request buffering"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::Stream,
            "StreamBuffer mode from a branch selected participant must not propagate"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn body_caps_bound_upstream_read_write_participation() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(BoundUpstreamCapFilter {
                access: BodyAccess::ReadWrite,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert!(
            caps.needs_request_body,
            "bound participant must contribute to the global request-body need"
        );
        assert!(
            caps.any_request_body_writer,
            "ReadWrite bound participant must contribute to the global writer flag"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "bound participant's bounded StreamBuffer should drive the effective mode"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn body_caps_bound_upstream_read_only_is_not_writer() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(BoundUpstreamCapFilter {
                access: BodyAccess::ReadOnly,
                mode: BodyMode::StreamBuffer { max_bytes: Some(2048) },
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert!(
            caps.needs_request_body,
            "read-only bound participant needs request body"
        );
        assert!(
            !caps.any_request_body_writer,
            "read-only bound participant must not set the global writer flag"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn body_caps_bound_upstream_defensive_ceiling() {
        let filter = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(BoundUpstreamCapFilter {
                access: BodyAccess::ReadOnly,
                mode: BodyMode::Stream,
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[filter]);

        assert_eq!(
            caps.request_body_mode,
            BodyMode::StreamBuffer {
                max_bytes: Some(ABSOLUTE_MAX_BODY_BYTES),
            },
            "a non-bounded bound participant must fall back to the finite absolute ceiling"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn body_caps_ignore_branch_bound_upstream_filters() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        let branch = ResolvedBranch {
            condition: None,
            filters: vec![PipelineFilter::new(
                100,
                AnyFilter::Http(Box::new(BoundUpstreamCapFilter {
                    access: BodyAccess::ReadWrite,
                    mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
                })),
                vec![],
                vec![],
            )],
            max_iterations: None,
            name: Arc::from("bound_branch"),
            rejoin: RejoinTarget::Next,
        };
        let parent = PipelineFilter {
            filter_id: 0,
            is_security: false,
            branches: vec![branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopHttpFilter)),
            name: None,
            response_conditions: vec![],
        };
        let caps = compute_body_capabilities(&[parent]);

        assert!(
            !caps.any_request_body_writer,
            "a branch read-write participant must not mark the request body as written"
        );
        assert!(
            !caps.needs_request_body,
            "branch bound participant must not enable request buffering"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::Stream,
            "StreamBuffer mode from a branch bound participant must not propagate"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_request_body_indices_top_level_only() {
        let participant = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(BoundUpstreamCapFilter {
                access: BodyAccess::ReadWrite,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![],
            vec![],
        );
        let plain = PipelineFilter::new(1, AnyFilter::Http(Box::new(NoopHttpFilter)), vec![], vec![]);
        let indices = bound_upstream_request_body_indices(&[participant, plain]);
        assert_eq!(indices, vec![0], "only the declaring filter's index is collected");
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn dual_phase_without_bound_condition_runs_pre_read() {
        let pf = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(DualPhaseCapFilter {
                pre_read: BodyAccess::ReadOnly,
                bound: BodyAccess::ReadOnly,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![],
            vec![],
        );
        assert_eq!(
            effective_request_body_phase(&pf),
            RequestBodyPhase::PreRead,
            "a dual-access filter with no bound_upstream condition runs pre-read"
        );
        let filters = vec![pf];
        let (request, _response) = body_filter_indices(&filters);
        assert_eq!(request, vec![0], "it is scheduled in the pre-read set");
        assert!(
            bound_upstream_request_body_indices(&filters).is_empty(),
            "it is not scheduled at the binding barrier"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn dual_phase_with_bound_condition_runs_at_barrier() {
        let pf = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(DualPhaseCapFilter {
                pre_read: BodyAccess::ReadOnly,
                bound: BodyAccess::ReadOnly,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![bound_upstream_condition()],
            vec![],
        );
        assert_eq!(
            effective_request_body_phase(&pf),
            RequestBodyPhase::BoundUpstream,
            "a bound_upstream condition defers a dual-access hook to the barrier"
        );
        let filters = vec![pf];
        let (request, _response) = body_filter_indices(&filters);
        assert!(request.is_empty(), "it is excluded from the pre-read set");
        assert_eq!(
            bound_upstream_request_body_indices(&filters),
            vec![0],
            "it is scheduled at the binding barrier"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn dual_phase_hook_scheduled_in_exactly_one_phase() {
        for conditions in [vec![], vec![bound_upstream_condition()]] {
            let filters = vec![PipelineFilter::new(
                0,
                AnyFilter::Http(Box::new(DualPhaseCapFilter {
                    pre_read: BodyAccess::ReadWrite,
                    bound: BodyAccess::ReadWrite,
                    mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
                })),
                conditions,
                vec![],
            )];
            let (request, _response) = body_filter_indices(&filters);
            let bound = bound_upstream_request_body_indices(&filters);
            assert_eq!(
                request.len() + bound.len(),
                1,
                "a dual-access hook is scheduled exactly once, never twice"
            );
            assert!(
                request.is_empty() != bound.is_empty(),
                "the hook lands in exactly one phase, never both or neither"
            );
        }
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn dual_phase_capabilities_follow_selected_phase() {
        // Pre-read ReadOnly, bound-upstream ReadWrite: the writer flag depends
        // entirely on which phase the single hook is scheduled in.
        let pre_read = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(DualPhaseCapFilter {
                pre_read: BodyAccess::ReadOnly,
                bound: BodyAccess::ReadWrite,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![],
            vec![],
        );
        let caps = compute_body_capabilities(&[pre_read]);
        assert!(
            caps.needs_request_body,
            "the pre-read phase still needs the request body"
        );
        assert!(
            !caps.any_request_body_writer,
            "the pre-read phase declares ReadOnly, so nothing writes the body"
        );

        let bound = PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(DualPhaseCapFilter {
                pre_read: BodyAccess::ReadOnly,
                bound: BodyAccess::ReadWrite,
                mode: BodyMode::StreamBuffer { max_bytes: Some(4096) },
            })),
            vec![bound_upstream_condition()],
            vec![],
        );
        let caps = compute_body_capabilities(&[bound]);
        assert!(caps.needs_request_body, "the bound phase still needs the request body");
        assert!(
            caps.any_request_body_writer,
            "the bound phase declares ReadWrite, so capability calc must mark the body as written"
        );
    }

    #[test]
    fn request_head_filter_indices_collects_opted_in_filters() {
        let head = PipelineFilter::new(0, AnyFilter::Http(Box::new(HeadCapFilter)), vec![], vec![]);
        let plain = PipelineFilter::new(1, AnyFilter::Http(Box::new(NoopHttpFilter)), vec![], vec![]);
        let indices = request_head_filter_indices(&[head, plain]);
        assert_eq!(indices, vec![0], "only the opted-in filter's index is collected");
    }

    #[test]
    fn request_head_filter_indices_empty_without_opt_in() {
        let plain = PipelineFilter::new(0, AnyFilter::Http(Box::new(NoopHttpFilter)), vec![], vec![]);
        assert!(
            request_head_filter_indices(&[plain]).is_empty(),
            "a pipeline with no head participant collects no head indices"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Noop HTTP filter for body capability branch testing.
    struct NoopHttpFilter;

    /// HTTP filter that opts in to the request-head phase.
    struct HeadCapFilter;

    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for HeadCapFilter {
        fn name(&self) -> &'static str {
            "head_cap"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }

        fn runs_request_head(&self) -> bool {
            true
        }
    }

    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for NoopHttpFilter {
        fn name(&self) -> &'static str {
            "noop"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }
    }

    /// Selected-upstream request-body participant for capability tests, with
    /// a configurable declared access and body mode.
    struct SelectedUpstreamCapFilter {
        access: BodyAccess,
        mode: BodyMode,
    }

    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for SelectedUpstreamCapFilter {
        fn name(&self) -> &'static str {
            "selected_upstream_cap"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> BodyAccess {
            self.access
        }

        fn request_body_mode(&self) -> BodyMode {
            self.mode
        }
    }

    /// Bound-upstream request-body participant for capability tests, with a
    /// configurable declared access and body mode.
    #[cfg(feature = "bound-upstream-request-body")]
    struct BoundUpstreamCapFilter {
        access: BodyAccess,
        mode: BodyMode,
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for BoundUpstreamCapFilter {
        fn name(&self) -> &'static str {
            "bound_upstream_cap"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            self.access
        }

        fn request_body_mode(&self) -> BodyMode {
            self.mode
        }
    }

    /// Dual-access request-body participant: declares both a pre-read and a
    /// bound-upstream request-body hook, for phase-inference tests.
    #[cfg(feature = "bound-upstream-request-body")]
    struct DualPhaseCapFilter {
        pre_read: BodyAccess,
        bound: BodyAccess,
        mode: BodyMode,
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for DualPhaseCapFilter {
        fn name(&self) -> &'static str {
            "dual_phase_cap"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            self.pre_read
        }

        fn bound_upstream_request_body_access(&self) -> BodyAccess {
            self.bound
        }

        fn request_body_mode(&self) -> BodyMode {
            self.mode
        }
    }

    /// A request condition gating on `bound_upstream`, for phase-inference tests.
    #[cfg(feature = "bound-upstream-request-body")]
    fn bound_upstream_condition() -> praxis_core::config::Condition {
        use praxis_core::config::{ApplicationMatch, Condition, ConditionMatch};

        Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            headers_present: None,
            bound_upstream: Some(ApplicationMatch {
                application_protocol: None,
                application_provider: Some("openai".to_owned()),
            }),
            selected_upstream: None,
        })
    }
}
