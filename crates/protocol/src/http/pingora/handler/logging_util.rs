// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Fallback access log emission and response filter cleanup.
//!
//! Emits access log records for requests that ended before the
//! `access_log` filter's normal completion hooks could run (early
//! rejections, upstream failures, aborted streams). Runs the response
//! filter pipeline during logging cleanup when the response phase
//! was skipped. Extracted from `mod.rs` to keep the handler module
//! focused on lifecycle hooks.

use praxis_filter::FilterPipeline;

use crate::http::pingora::context::PingoraRequestCtx;

/// Emit a fallback access record for requests whose lifecycle ended
/// before the access log filter's completion hooks could run.
///
/// Covers pre-upstream rejections, upstream connect and read failures,
/// and streamed responses aborted mid-body: none of these reach the
/// bodyless response phase or body end-of-stream where the filter
/// emits. Only fires when the pipeline configures an `access_log`
/// filter; these records bypass the filter's sampling because
/// incomplete requests are always worth a record.
pub(super) fn maybe_emit_fallback_access_log(pipeline: &FilterPipeline, status: u16, ctx: &mut PingoraRequestCtx) {
    if ctx.response_delivery_complete || ctx.connection_upgraded || !pipeline.contains_filter("access_log") {
        return;
    }
    if let Some(filter_ctx) = ctx.filter_context_for(pipeline, None) {
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
        if !pipeline.emit_deferred_records(&filter_ctx, status) {
            praxis_filter::emit_access_record(&filter_ctx, status);
        }
    }
}

/// Run response filters during the logging phase if the
/// response phase never executed (upstream error, filter
/// rejection, etc.).
pub(super) async fn logging_cleanup(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    if !ctx.response_phase_done
        && let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None)
    {
        let _result = pipeline.execute_http_response(&mut filter_ctx).await;
        let extensions = filter_ctx.extensions;
        let metadata = filter_ctx.filter_metadata;
        let state = filter_ctx.filter_state;
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
        ctx.cached_executed_filter_indices = exec_idx;
        ctx.cached_body_done_indices = body_idx;
        ctx.cluster = cluster;
        ctx.upstream = upstream;
    }
}
