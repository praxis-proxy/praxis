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

use praxis_core::health::PassiveTransition;
use praxis_filter::FilterPipeline;

use super::metrics;
use crate::http::pingora::context::PingoraRequestCtx;

/// Where the error that ended a request came from, as passive health and
/// the circuit breaker see it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::http) enum ErrorOrigin {
    /// The downstream client; says nothing about the endpoint.
    Downstream,

    /// The upstream, the proxy itself, or an unknown source.
    Other,
}

/// Record a passive health observation for the selected upstream endpoint.
///
/// Called from the `logging` hook on every completed request. Determines
/// success/failure from the error argument and the stashed upstream
/// response status code.
///
/// No-op when no upstream was selected, no health registry is available,
/// or passive checking is not configured for the cluster.
#[cfg(feature = "pingora")]
pub(super) fn record_passive_health(
    pipeline: &FilterPipeline,
    error: Option<&pingora_core::Error>,
    ctx: &PingoraRequestCtx,
) {
    record_passive_health_outcome(pipeline, error_origin(error), ctx);
}

/// Record a passive health observation from the origin of the error that
/// ended the request, if any; the backend-neutral core of
/// `record_passive_health`.
pub(in crate::http) fn record_passive_health_outcome(
    pipeline: &FilterPipeline,
    error: Option<ErrorOrigin>,
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
    let upstream_failed = ctx.upstream_response_status.is_some_and(|status| status >= 500);
    if ctx.response_size_limit_exceeded && !upstream_failed {
        return;
    }
    if ctx.upgrade_failure == Some(crate::http::pingora::context::UpgradeFailure::Local) && !upstream_failed {
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
    let is_downstream_error = error == Some(ErrorOrigin::Downstream);
    if ended_by_client_origin(error, ctx.upstream_response_status) {
        return;
    }
    let is_failure = upstream_failed || (error.is_some() && !is_downstream_error);
    apply_passive_threshold(health, idx, cluster_name, is_failure);
}

/// The logging hook only sees the winner. A copy that failed, or a connect
/// that never produced a status, still has to move this endpoint's passive
/// health.
#[cfg(all(feature = "pingora", feature = "hedged-requests"))]
pub(super) fn record_hedge_attempt(
    health: &praxis_core::health::ClusterHealthEntry,
    cluster_name: &Arc<str>,
    idx: usize,
    is_failure: bool,
) {
    apply_passive_threshold(health, idx, cluster_name, is_failure);
}

/// Whether the request ended on the client side before the upstream answered:
/// a downstream-sourced error with no upstream response status. Such a
/// request says nothing about the endpoint, so neither passive health nor the
/// circuit breaker may count it.
#[cfg(feature = "pingora")]
pub(super) fn ended_by_client(error: Option<&pingora_core::Error>, upstream_status: Option<u16>) -> bool {
    ended_by_client_origin(error_origin(error), upstream_status)
}

/// Whether the request ended on the client side before the upstream
/// answered, from the origin of the error that ended it; the
/// backend-neutral core of `ended_by_client`.
pub(in crate::http) fn ended_by_client_origin(error: Option<ErrorOrigin>, upstream_status: Option<u16>) -> bool {
    upstream_status.is_none() && error == Some(ErrorOrigin::Downstream)
}

/// The origin of a Pingora error, as passive health classifies it.
#[cfg(feature = "pingora")]
fn error_origin(error: Option<&pingora_core::Error>) -> Option<ErrorOrigin> {
    error.map(|e| {
        if matches!(e.esource(), pingora_core::ErrorSource::Downstream) {
            ErrorOrigin::Downstream
        } else {
            ErrorOrigin::Other
        }
    })
}

/// Apply passive health threshold for a single endpoint observation.
fn apply_passive_threshold(
    health: &praxis_core::health::ClusterHealthEntry,
    idx: usize,
    cluster_name: &Arc<str>,
    is_failure: bool,
) {
    match health.observe_passive(idx, is_failure) {
        Some(PassiveTransition::Unhealthy { threshold }) => {
            tracing::warn!(
                cluster = %cluster_name,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint marked unhealthy"
            );
            emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_UNHEALTHY);
        },
        Some(PassiveTransition::Recovered { threshold }) => {
            tracing::info!(
                cluster = %cluster_name,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint recovered"
            );
            emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_HEALTHY);
        },
        None => {},
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
#[cfg(feature = "pingora")]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use pingora_core::{Error, ErrorType};
    use praxis_core::health::{ClusterHealthEntry, EndpointHealth, HealthRegistry};
    use praxis_filter::{FilterPipeline, FilterRegistry};

    use super::{ErrorOrigin, ended_by_client, record_passive_health_outcome};
    use crate::http::pingora::context::PingoraRequestCtx;

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

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one sequence verifies that local policy preserves a health streak"
    )]
    fn local_response_size_rejection_neither_fails_nor_recovers_endpoint_health()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = health_pipeline(2)?;
        let mut ctx = contacted_context(200);
        ctx.response_size_limit_exceeded = true;
        record_passive_health_outcome(&pipeline, Some(ErrorOrigin::Other), &ctx);
        assert_eq!(
            endpoint_healthy(&pipeline),
            Some(true),
            "local policy is not an upstream failure"
        );

        ctx.response_size_limit_exceeded = false;
        record_passive_health_outcome(&pipeline, Some(ErrorOrigin::Other), &ctx);
        assert_eq!(
            endpoint_healthy(&pipeline),
            Some(true),
            "one real failure is below threshold"
        );

        ctx.response_size_limit_exceeded = true;
        record_passive_health_outcome(&pipeline, Some(ErrorOrigin::Other), &ctx);
        assert!(
            endpoint_healthy(&pipeline) == Some(true),
            "local policy must not clear or advance the failure streak"
        );

        ctx.response_size_limit_exceeded = false;
        record_passive_health_outcome(&pipeline, Some(ErrorOrigin::Other), &ctx);
        assert_eq!(
            endpoint_healthy(&pipeline),
            Some(false),
            "the prior failure streak remains intact"
        );
        drop(ctx);
        Ok(())
    }

    #[test]
    fn response_size_rejection_keeps_an_upstream_5xx_health_signal()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = health_pipeline(1)?;
        let mut ctx = contacted_context(503);
        ctx.response_size_limit_exceeded = true;

        record_passive_health_outcome(&pipeline, Some(ErrorOrigin::Other), &ctx);

        assert!(
            endpoint_healthy(&pipeline) == Some(false),
            "an upstream 5xx still counts as a failure"
        );
        drop(ctx);
        Ok(())
    }

    /// Build a one-endpoint pipeline with passive health checking enabled.
    fn health_pipeline(threshold: u32) -> Result<FilterPipeline, Box<dyn std::error::Error + Send + Sync>> {
        let mut pipeline = FilterPipeline::build(&mut [], &FilterRegistry::with_builtins())?;
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("127.0.0.1:8080")],
            Some(threshold),
            Some(1),
        );
        let registry: HealthRegistry = Arc::new(HashMap::from([(Arc::from("backend"), Arc::new(entry))]));
        pipeline.set_health_registry(registry);
        Ok(pipeline)
    }

    /// A request that reached the tracked endpoint and got `status`.
    fn contacted_context(status: u16) -> PingoraRequestCtx {
        PingoraRequestCtx {
            cluster: Some(Arc::from("backend")),
            selected_endpoint_index: Some(0),
            upstream_contacted: true,
            upstream_response_status: Some(status),
            ..PingoraRequestCtx::default()
        }
    }

    /// Whether the pipeline's sole endpoint remains healthy.
    fn endpoint_healthy(pipeline: &FilterPipeline) -> Option<bool> {
        pipeline
            .health_registry()
            .and_then(|registry| registry.get("backend"))
            .and_then(|health| health.endpoints().first())
            .map(EndpointHealth::is_healthy)
    }
}
