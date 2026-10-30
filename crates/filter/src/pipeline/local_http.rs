// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Linear local policy execution with normal ordering and request pairing.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use praxis_core::config::FailureMode;

use super::{FilterPipeline, check_failure_mode, filter::PipelineFilter, http_utils::skip_by_response_conditions};
use crate::{
    AnyFilter, FilterAction, FilterError, HttpFilterContext, Response,
    condition::should_execute_from,
    context::EffectiveHeaders,
    local_http::{LocalClaim, LocalCompatibility, LocalHttpActive, LocalResponse},
};

/// A local header phase; head hooks precede ordinary request hooks.
#[derive(Clone, Copy)]
enum Phase {
    /// All opted-in head hooks, before request hooks.
    Head,
    /// Normal request-header policies.
    Request,
    /// Paired response-header policies.
    Response,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "pipeline concerns are split across modules"
)]
impl FilterPipeline {
    /// Keep matching and already-claimed requests within the local lifecycle.
    pub(super) fn requires_local_http(&self, ctx: &HttpFilterContext<'_>) -> bool {
        ctx.extensions.get::<LocalHttpActive>().is_some()
            || self.local_routes.iter().any(|(_, route)| {
                route.methods.matches(&ctx.request.method) && route.path.matches(ctx.request.uri.path())
            })
    }

    /// Claim the admitted route once, before hooks, reads, or dispatch.
    pub fn claim_local_http(self: &Arc<Self>, ctx: &mut HttpFilterContext<'_>) -> Option<LocalClaim> {
        if let Some(active) = ctx.extensions.get::<LocalHttpActive>() {
            active.claim.conflict.store(true, Ordering::Release);
            return Some(active.claim.clone());
        }
        let mut matches = self.local_routes.iter().filter(|(_, route)| {
            route.methods.matches(&ctx.request.method) && route.path.matches(ctx.request.uri.path())
        });
        let (owner, route) = matches.next()?;
        let conflict = matches.next().is_some()
            || !self.local_http_valid
            || ctx.buffered_request_body.is_some()
            || ctx.request_body_bytes != 0
            || ctx.upstream_reached;
        let claim = LocalClaim {
            pipeline: Arc::clone(self),
            owner: *owner,
            route: route.clone(),
            conflict: Arc::new(AtomicBool::new(conflict)),
        };
        ctx.extensions.insert(LocalHttpActive { claim: claim.clone() });
        Some(claim)
    }

    /// Execute head policies, then request policies, stopping on first denial.
    pub(crate) async fn approve_local_http(&self, ctx: &mut HttpFilterContext<'_>) -> Option<LocalResponse> {
        ctx.executed_filter_indices = vec![false; self.filters.len()];
        ctx.body_done_indices = vec![false; self.filters.len()];
        for phase in [Phase::Head, Phase::Request] {
            for (index, filter) in self.filters.iter().enumerate() {
                match local_request_eligible(filter, ctx, phase) {
                    Ok(false) => continue,
                    Err(_) => return Some(LocalResponse::internal_error()),
                    Ok(true) => {},
                }
                if let Some(executed) = ctx.executed_filter_indices.get_mut(index) {
                    *executed = true;
                }
                let action = run_hook(filter, ctx, phase, self.records_filter_duration_metrics()).await;
                if let Some(response) = local_action(action).await {
                    return Some(response);
                }
            }
        }
        None
    }

    /// Unwind paired policies once. A replacement never restarts the phase.
    /// `ctx.response_header` must borrow the adapter-owned response slot.
    /// Returns whether any policy replaced the pending response.
    pub async fn filter_local_http_response(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        response: &mut LocalResponse,
    ) -> bool {
        let mut edits = crate::local_http::headers::HeaderEdits::default();
        let mut replaced = false;
        let Some(head) = ctx.response_header.as_deref_mut() else {
            response.replace(LocalResponse::internal_error()).await;
            return true;
        };
        *head = response.head();
        for (index, filter) in self.filters.iter().enumerate().rev() {
            if ctx.executed_filter_indices.get(index) != Some(&true) {
                continue;
            }
            if let Some(replacement) = self.local_response_hook(filter, ctx, &mut edits).await {
                response.replace(replacement).await;
                if let Some(head) = ctx.response_header.as_deref_mut() {
                    *head = response.head();
                    edits.apply(&mut head.headers);
                }
                replaced = true;
            }
        }
        if let Some(head) = ctx.response_header.as_deref() {
            response.set_head(Response {
                status: head.status,
                headers: head.headers.clone(),
            });
        }
        ctx.extensions.insert(edits);
        replaced
    }

    /// Apply a paired response policy exactly once at its reverse position.
    async fn local_response_hook(
        &self,
        filter: &PipelineFilter,
        ctx: &mut HttpFilterContext<'_>,
        edits: &mut crate::local_http::headers::HeaderEdits,
    ) -> Option<LocalResponse> {
        let AnyFilter::Http(http) = &filter.filter else {
            return None;
        };
        if skip_by_response_conditions(http.as_ref(), &filter.response_conditions, ctx) {
            return None;
        }
        let before = ctx
            .response_header
            .as_deref()
            .map(|head| head.headers.clone())
            .unwrap_or_default();
        ctx.extensions
            .insert(crate::local_http::headers::PolicyHeaders::default());
        let replacement =
            local_action(run_hook(filter, ctx, Phase::Response, self.records_filter_duration_metrics()).await).await;
        let explicit = ctx
            .extensions
            .remove::<crate::local_http::headers::PolicyHeaders>()
            .unwrap_or_default();
        if let Some(head) = ctx.response_header.as_deref() {
            edits.record(&before, &head.headers, &explicit.touched);
        }
        replacement
    }

    /// Finish configured access logging once, preserving request eligibility.
    pub fn complete_local_http(&self, ctx: &mut HttpFilterContext<'_>, status: u16) {
        if crate::access_record_already_emitted(ctx) {
            return;
        }
        for filter in &self.filters {
            if local_conditions_match(filter, ctx).unwrap_or(false)
                && let AnyFilter::Http(http) = &filter.filter
                && http.local_http_compatibility() == LocalCompatibility::Policy
            {
                ctx.current_filter_id = Some(filter.filter_id);
                http.complete_local_http(ctx, status);
            }
        }
        ctx.current_filter_id = None;
        // Includes configured sampling/condition suppression: no fallback record.
        crate::mark_access_record_emitted(ctx);
    }
}

/// Local conditions are header-only; construction rejects upstream predicates.
fn local_conditions_match(filter: &PipelineFilter, ctx: &HttpFilterContext<'_>) -> Result<bool, FilterError> {
    should_execute_from(
        &filter.conditions,
        ctx.request,
        &EffectiveHeaders(ctx),
        ctx.bound_upstream_view(),
        super::http_utils::ctx_selected_upstream(ctx),
    )
    .map_err(|error| FilterError::from(error.to_string()))
}

/// Routing-only filters never evaluate policy conditions or execute hooks.
fn local_request_eligible(
    filter: &PipelineFilter,
    ctx: &HttpFilterContext<'_>,
    phase: Phase,
) -> Result<bool, FilterError> {
    let AnyFilter::Http(http) = &filter.filter else {
        return Ok(false);
    };
    if http.local_http_compatibility() != LocalCompatibility::Policy
        || (matches!(phase, Phase::Head) && !http.runs_request_head())
    {
        return Ok(false);
    }
    local_conditions_match(filter, ctx)
}

/// Invoke the real filter hooks with normal failure modes and duration metrics.
async fn run_hook(
    filter: &PipelineFilter,
    ctx: &mut HttpFilterContext<'_>,
    phase: Phase,
    metrics: bool,
) -> Result<FilterAction, FilterError> {
    let AnyFilter::Http(http) = &filter.filter else {
        return Err("incompatible local filter".into());
    };
    ctx.current_filter_id = Some(filter.filter_id);
    let started = std::time::Instant::now();
    let (result, label) = match phase {
        Phase::Head => (http.on_request_head(ctx).await, "request_head"),
        Phase::Request => (http.on_request(ctx).await, "request"),
        Phase::Response => (http.on_response(ctx).await, "response"),
    };
    ctx.current_filter_id = None;
    if metrics {
        crate::metrics::record_filter_duration(http.name(), label, "headers", started.elapsed().as_secs_f64());
    }
    if ctx
        .extensions
        .get::<LocalHttpActive>()
        .is_some_and(|active| active.claim.is_conflicted())
    {
        return Err("conflicting local HTTP claim".into());
    }
    match result {
        Err(error) if filter.failure_mode == FailureMode::Open => {
            check_failure_mode(http.name(), error, label, filter.failure_mode)?;
            Ok(FilterAction::Continue)
        },
        other => other,
    }
}

/// Unexpected terminal/body actions are local contract failures, never claims.
async fn local_action(action: Result<FilterAction, FilterError>) -> Option<LocalResponse> {
    match action {
        Ok(FilterAction::Continue) => None,
        Ok(FilterAction::Reject(rejection)) => {
            Some(LocalResponse::rejection(rejection).unwrap_or_else(|_| LocalResponse::internal_error()))
        },
        Ok(FilterAction::StreamingTerminalResponse(mut response)) => {
            response.body.cancel().await;
            Some(LocalResponse::internal_error())
        },
        Ok(FilterAction::TerminalResponse(_) | FilterAction::Release | FilterAction::BodyDone) | Err(_) => {
            Some(LocalResponse::internal_error())
        },
    }
}
