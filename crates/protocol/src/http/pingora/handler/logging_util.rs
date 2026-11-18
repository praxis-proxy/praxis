// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Terminal filter observers and response filter cleanup.
//!
//! Emits access log records for requests that ended before the
//! `access_log` filter's normal completion hooks could run (early
//! rejections, upstream failures, aborted streams). Runs the response
//! filter pipeline during logging cleanup when the response phase
//! was skipped. Extracted from `mod.rs` to keep the handler module
//! focused on lifecycle hooks.

use praxis_filter::FilterPipeline;

use crate::http::pingora::context::PingoraRequestCtx;

/// Notify request-completion observers and emit an eligible fallback access record.
///
/// Completion observers run for successful and failed requests. The access
/// record fallback covers only requests whose normal access-log completion
/// hook did not run; it bypasses sampling for incomplete requests.
pub(in crate::http) fn emit_completion_observers(pipeline: &FilterPipeline, status: u16, ctx: &mut PingoraRequestCtx) {
    let needs_access_fallback =
        !ctx.response_delivery_complete && !ctx.connection_upgraded && pipeline.contains_filter("access_log");
    if !pipeline.has_request_completion_observer() && !needs_access_fallback {
        return;
    }
    if let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None) {
        pipeline.emit_request_completion(&mut filter_ctx, status);
        if !needs_access_fallback {
            return;
        }
        // The access_log filter already logged this request (e.g. a bodyless
        // response whose on_response emitted before a later filter rejected):
        // no fallback record, or it would duplicate.
        if praxis_filter::access_record_already_emitted(&filter_ctx) {
            return;
        }
        // Honor the entry's request conditions: a scoped access_log (e.g.
        // only /api paths, a `bound_upstream`, or a `selected_upstream`
        // predicate) must not gain fallback records for requests the operator
        // excluded. The binding and the selection restored by `logging_cleanup`
        // are on the context, so a `bound_upstream`- or `selected_upstream`-
        // scoped filter is matched against them rather than silently dropped.
        // Sampling is still deliberately bypassed.
        if !pipeline.filter_request_conditions_match("access_log", &filter_ctx) {
            return;
        }
        // Route through the pipeline so the record honours the filter's
        // configured `fields`, and so late facts — the gRPC completion
        // status captured from the response trailers — reach it. Only
        // fall back to the fixed shape if no filter claimed the record.
        if !pipeline.emit_deferred_access_record(&mut filter_ctx, status) {
            praxis_filter::emit_access_record(&filter_ctx, status);
        }
    }
}

/// Run response filters during the logging phase if the
/// response phase never executed (upstream error, filter
/// rejection, etc.).
pub(in crate::http) async fn logging_cleanup(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    if !ctx.response_phase_done
        && let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None)
    {
        let _result = pipeline.execute_http_response(&mut filter_ctx).await;
        let extensions = filter_ctx.extensions;
        let metadata = filter_ctx.filter_metadata;
        let state = filter_ctx.filter_state;
        let branch_idx = filter_ctx.executed_branch_filters;
        let exec_idx = filter_ctx.executed_filter_indices;
        let body_idx = filter_ctx.body_done_indices;
        // The context macro takes cluster/upstream out of ctx; restore them
        // so the fallback access record that follows can attribute the
        // failure to the routed cluster and selected endpoint.
        let cluster = filter_ctx.cluster;
        let upstream = filter_ctx.upstream;
        ctx.extensions = extensions;
        ctx.filter_metadata = metadata;
        ctx.filter_state = state;
        ctx.cached_executed_branch_filters = branch_idx;
        ctx.cached_executed_filter_indices = exec_idx;
        ctx.cached_body_done_indices = body_idx;
        ctx.cluster = cluster;
        ctx.upstream = upstream;
    }
}
