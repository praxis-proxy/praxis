// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request metrics emission utilities.
//!
//! Aggregates and emits Prometheus metrics for completed HTTP requests,
//! including duration, body sizes, status classes, and upstream request
//! attribution. Extracted from `mod.rs` to keep the handler module
//! focused on lifecycle hooks.

#[cfg(feature = "pingora")]
use pingora_proxy::Session;

use super::metrics;
use crate::http::pingora::context::PingoraRequestCtx;

/// Emit Prometheus metrics for a completed HTTP request.
///
/// No-op when the Prometheus recorder has not been installed.
#[cfg(feature = "pingora")]
pub(super) fn emit_request_metrics(session: &Session, ctx: &PingoraRequestCtx) {
    let status_code = session.response_written().map_or(0, |resp| resp.status.as_u16());
    emit_request_metrics_for(status_code, session.req_header().method.as_str(), ctx);
}

/// Emit Prometheus metrics for a completed HTTP request that was answered
/// with `status_code` (0 when nothing was written) for a request whose
/// method reads `request_method` (empty when it is no longer known); the
/// backend-neutral core of `emit_request_metrics`.
///
/// No-op when the Prometheus recorder has not been installed.
pub(in crate::http) fn emit_request_metrics_for(status_code: u16, request_method: &str, ctx: &PingoraRequestCtx) {
    if !metrics::is_recorder_installed() {
        return;
    }

    let status_class = metrics::status_class(status_code);

    let method = request_method_label(request_method, ctx);

    let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);

    let route = ctx.metrics_route.clone().unwrap_or_else(metrics::route_unknown);

    let labels = metrics::RequestMetricLabels {
        cluster: cluster.clone(),
        method,
        route,
        status_class,
    };

    emit_upstream_request_metric(ctx, &cluster);

    if let Some(error_type) = ctx.error_type {
        metrics::record_error(error_type);
    }

    let duration_secs = ctx.request_start.elapsed().as_secs_f64();
    metrics::record_request_metrics(labels, duration_secs);
    metrics::record_body_size_metrics(
        method,
        status_class,
        cluster,
        ctx.request_body_bytes,
        ctx.response_body_bytes,
    );
}

/// Resolve the bounded `method` label for a request.
///
/// Falls back to the request snapshot when the session header has already
/// been consumed, and to `"UNKNOWN"` when neither carries a method.
fn request_method_label(request_method: &str, ctx: &PingoraRequestCtx) -> &'static str {
    let raw_method = if request_method.is_empty() {
        ctx.request_snapshot.as_ref().map_or("UNKNOWN", |r| r.method.as_str())
    } else {
        request_method
    };
    metrics::method_label(raw_method)
}

/// Count a request that reached an upstream endpoint.
///
/// Only requests that actually reached an upstream carry an upstream
/// response status; filter rejections and connect failures never do, and
/// must not inflate the upstream denominator.
fn emit_upstream_request_metric(ctx: &PingoraRequestCtx, cluster: &::metrics::SharedString) {
    if let Some(upstream_status) = ctx.upstream_response_status
        && let Some(upstream) = ctx.upstream_for_retry.as_ref()
    {
        metrics::record_upstream_request(
            cluster.clone(),
            ::metrics::SharedString::from(std::sync::Arc::clone(&upstream.address)),
            metrics::status_class(upstream_status),
        );
    }
}
