// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Passive health checking and observation recording.
//!
//! Records health observations for selected upstream endpoints based on
//! request outcomes (connect failures, response statuses). Applies
//! configured thresholds to mark endpoints healthy or unhealthy.
//! Extracted from `mod.rs` to keep the handler module focused on
//! lifecycle hooks.

use std::sync::Arc;

use praxis_filter::FilterPipeline;

use super::metrics;
use crate::http::pingora::context::PingoraRequestCtx;

/// Record a passive health observation for the selected upstream endpoint.
///
/// Called from the `logging` hook on every completed request. Determines
/// success/failure from the error argument and the stashed upstream
/// response status code.
///
/// No-op when no upstream was selected, no health registry is available,
/// or passive checking is not configured for the cluster.
pub(super) fn record_passive_health(
    pipeline: &FilterPipeline,
    error: Option<&pingora_core::Error>,
    ctx: &PingoraRequestCtx,
) {
    let cluster_name = ctx.cluster.as_ref().or(ctx.metrics_cluster.as_ref());
    let Some(cluster_name) = cluster_name else {
        return;
    };
    let Some(idx) = ctx.selected_endpoint_index else {
        return;
    };
    let Some(registry) = pipeline.health_registry() else {
        return;
    };
    let Some(health) = registry.get(cluster_name) else {
        return;
    };

    // A request that never contacted the upstream carries no signal about the
    // endpoint, so skip it. upstream_contacted is set once a peer is resolved
    // and stays set across retries (unlike upstream_for_retry, which a retry
    // clears to force reselection), so it distinguishes a genuine connect or
    // read failure from a filter reject or a proxy-generated terminal response
    // after endpoint selection, which would otherwise record a spurious
    // observation against the untouched endpoint and skew a real failure
    // streak.
    if !ctx.upstream_contacted {
        return;
    }

    // Classify the observation by the error's origin. A client-sourced
    // (Downstream) error carries no signal about the endpoint, so when it
    // arrives without an upstream response we skip the observation
    // entirely: recording a failure would eject a healthy upstream, and
    // recording a success would clear a real failure streak and mask a
    // failing one. Upstream/Internal/Unset errors and 5xx responses count
    // as failures (Internal/Unset are kept because a real endpoint failure
    // is not always tagged Upstream, and missing one is worse here than an
    // occasional false positive).
    let is_downstream_error = error.is_some_and(|e| matches!(e.esource(), pingora_core::ErrorSource::Downstream));
    if ended_by_client(error, ctx.upstream_response_status) {
        return;
    }
    let is_failure =
        ctx.upstream_response_status.is_some_and(|s| s >= 500) || (error.is_some() && !is_downstream_error);
    apply_passive_threshold(health, idx, cluster_name, is_failure);
}

/// Whether the request ended on the client side before the upstream answered:
/// a downstream-sourced error with no upstream response status. Such a
/// request says nothing about the endpoint, so neither passive health nor the
/// circuit breaker may count it.
pub(super) fn ended_by_client(error: Option<&pingora_core::Error>, upstream_status: Option<u16>) -> bool {
    upstream_status.is_none() && error.is_some_and(|e| matches!(e.esource(), pingora_core::ErrorSource::Downstream))
}

/// Apply passive health threshold for a single endpoint observation.
fn apply_passive_threshold(
    health: &praxis_core::health::ClusterHealthEntry,
    idx: usize,
    cluster_name: &Arc<str>,
    is_failure: bool,
) {
    if is_failure {
        if let Some(threshold) = health.passive_unhealthy_threshold()
            && health
                .endpoints()
                .get(idx)
                .is_some_and(|ep| ep.record_failure(threshold))
        {
            tracing::warn!(
                cluster = %cluster_name,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint marked unhealthy"
            );
            emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_UNHEALTHY);
        }
    } else if let Some(threshold) = health.passive_healthy_threshold()
        && health
            .endpoints()
            .get(idx)
            .is_some_and(|ep| ep.record_success(threshold))
    {
        tracing::info!(
            cluster = %cluster_name,
            endpoint_index = idx,
            threshold,
            "passive health: endpoint recovered"
        );
        emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_HEALTHY);
    }
}

/// Refresh health gauges and increment the transition counter after a passive flip.
fn emit_passive_health_transition(
    health: &praxis_core::health::ClusterHealthEntry,
    cluster_name: &Arc<str>,
    result: &'static str,
) {
    let (healthy, total) = metrics::count_healthy_endpoints(health);
    metrics::record_health_transition(
        ::metrics::SharedString::from(Arc::clone(cluster_name)),
        result,
        healthy,
        total,
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use pingora_core::{Error, ErrorType};

    use super::ended_by_client;

    #[test]
    fn a_client_abort_before_any_upstream_response_ended_by_client() {
        let error = Error::new_down(ErrorType::ConnectionClosed);
        assert!(
            ended_by_client(Some(&error), None),
            "a downstream error with no upstream status must not be charged to the endpoint"
        );
    }

    #[test]
    fn upstream_errors_and_answered_requests_are_not_client_endings() {
        let upstream = Error::new_up(ErrorType::ConnectionClosed);
        let downstream = Error::new_down(ErrorType::ConnectionClosed);
        assert!(
            !ended_by_client(Some(&upstream), None),
            "an upstream error is the endpoint's"
        );
        assert!(
            !ended_by_client(Some(&downstream), Some(502)),
            "once the upstream answered, its status is the signal"
        );
        assert!(!ended_by_client(None, None), "no error is not a client ending");
    }
}
