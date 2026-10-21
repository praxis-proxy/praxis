// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Retry decision logic and state management.
//!
//! Extracted from `mod.rs` to keep the handler module focused on
//! lifecycle hooks. Implements policy-aware retry decisions for
//! connect failures and response statuses, including backoff,
//! endpoint reselection, and budget exhaustion tracking.

use std::sync::Arc;

use praxis_core::config::RetryPolicy;
use tracing::{debug, warn};

use super::{metrics, retry};
use crate::http::pingora::context::PingoraRequestCtx;

/// Shared legacy-default retry policy for requests that carry none.
pub(super) fn legacy_default_policy() -> Arc<RetryPolicy> {
    static LEGACY_DEFAULT: std::sync::LazyLock<Arc<RetryPolicy>> =
        std::sync::LazyLock::new(|| Arc::new(RetryPolicy::legacy_default()));
    Arc::clone(&LEGACY_DEFAULT)
}

/// Handle upstream connect failures with the policy-aware retry engine.
///
/// Retries are skipped when the effective forwarded body size exceeds
/// the configured replay limit, the method is non-idempotent without
/// opt-in, the budget is exhausted, or the overall deadline has passed.
#[cfg(feature = "pingora")]
pub(super) fn handle_connect_failure(
    ctx: &mut PingoraRequestCtx,
    e: Box<pingora_core::Error>,
) -> Box<pingora_core::Error> {
    let outcome = retry::classify_error(&e);
    let retry = connect_failure_retry(ctx, outcome);
    let mut e = e;
    e.set_retry(retry);
    e
}

/// Record an upstream failure classified as `outcome` and decide, under the
/// request's retry policy, whether to retry it; the backend-neutral core of
/// `handle_connect_failure`.
///
/// A `true` result has already counted the retry, armed its backoff and,
/// under a configured policy, cleared the failed upstream for reselection.
#[expect(clippy::too_many_lines, reason = "sequential guard checks")]
pub(in crate::http) fn connect_failure_retry(ctx: &mut PingoraRequestCtx, outcome: retry::RetryOutcome) -> bool {
    let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);
    if let Some(start) = ctx.upstream_connect_start.take() {
        metrics::record_upstream_connect_duration(cluster.clone(), start.elapsed().as_secs_f64());
    }
    metrics::record_upstream_connect_failure(cluster.clone());

    let policy = ctx.retry_policy.clone().unwrap_or_else(legacy_default_policy);
    let decision = retry::should_retry(ctx, &policy, outcome, ctx.cluster_retry_state.as_deref());

    match decision {
        retry::RetryDecision::Retry { backoff } => {
            ctx.retries += 1;
            ctx.pending_backoff = Some(backoff);
            // Legacy (unconfigured) policies keep the historical
            // retry-same-endpoint behavior; only operator-configured
            // policies opt into endpoint reselection.
            ctx.reselect_on_retry = policy.configured;
            if let Some(upstream) = ctx.upstream_for_retry.as_ref() {
                let addr = Arc::clone(&upstream.address);
                if !ctx.attempted_endpoints.iter().any(|e| e.as_ref() == addr.as_ref()) {
                    ctx.attempted_endpoints.push(addr);
                }
            }
            // Under reselection, release the failed endpoint's in-flight
            // counter and clear the saved upstream so upstream_peer picks an
            // alternate host. Legacy same-endpoint retries keep the saved
            // upstream (and its counter) for the next attempt.
            if policy.configured {
                clear_for_reselection(ctx);
            }
            let upstream_address = ctx
                .upstream_for_retry
                .as_ref()
                .map_or("unknown", |u| u.address.as_ref());
            debug!(
                retries = ctx.retries,
                max = policy.effective_max_retries(),
                ?backoff,
                upstream_address,
                "retrying after connect failure"
            );
            true
        },
        retry::RetryDecision::DoNotRetry => {
            if ctx.retries > 0 {
                warn!(
                    retries = ctx.retries,
                    max = policy.effective_max_retries(),
                    upstream_address = ctx
                        .upstream_for_retry
                        .as_ref()
                        .map_or("unknown", |u| u.address.as_ref()),
                    "retry limit exhausted"
                );
            }
            record_retry_exhausted_if_attempted(ctx, cluster);
            // Pingora may mark some errors retriable by default; the caller
            // clears the flag so the policy decision is authoritative.
            false
        },
    }
}

/// Decide whether an HTTP response status should trigger a retry.
///
/// Returns `Some(error)` marked retriable when the status is retriable
/// and all guards pass; `None` when the response should be forwarded.
#[cfg(feature = "pingora")]
pub(super) fn maybe_retry_response(ctx: &mut PingoraRequestCtx, status: u16) -> Option<Box<pingora_core::Error>> {
    if !response_status_retry(ctx, status) {
        return None;
    }
    let mut e = pingora_core::Error::explain(pingora_core::ErrorType::HTTPStatus(status), "retriable upstream status");
    e.set_retry(true);
    Some(e)
}

/// Decide whether an upstream response `status` should be retried instead
/// of forwarded; the backend-neutral core of `maybe_retry_response`.
///
/// A `true` result has already counted the retry, armed its backoff and,
/// under a configured policy, cleared the failed upstream for reselection.
pub(in crate::http) fn response_status_retry(ctx: &mut PingoraRequestCtx, status: u16) -> bool {
    let policy = ctx.retry_policy.clone().unwrap_or_else(legacy_default_policy);
    let outcome = retry::RetryOutcome::StatusCode(status);
    let decision = retry::should_retry(ctx, &policy, outcome, ctx.cluster_retry_state.as_deref());
    match decision {
        retry::RetryDecision::Retry { backoff } => {
            ctx.retries += 1;
            ctx.pending_backoff = Some(backoff);
            // Legacy (unconfigured) policies keep the historical
            // retry-same-endpoint behavior; only operator-configured
            // policies opt into endpoint reselection.
            ctx.reselect_on_retry = policy.configured;
            if let Some(upstream) = ctx.upstream_for_retry.as_ref() {
                let addr = Arc::clone(&upstream.address);
                if !ctx.attempted_endpoints.iter().any(|e| e.as_ref() == addr.as_ref()) {
                    ctx.attempted_endpoints.push(addr);
                }
            }
            // Under reselection, release the failed endpoint's in-flight
            // counter and clear the saved upstream so upstream_peer picks an
            // alternate host. Legacy same-endpoint retries keep the saved
            // upstream (and its counter) for the next attempt.
            if policy.configured {
                clear_for_reselection(ctx);
            }
            debug!(
                status,
                retries = ctx.retries,
                max = policy.effective_max_retries(),
                ?backoff,
                "retrying after retriable response status"
            );
            true
        },
        retry::RetryDecision::DoNotRetry => false,
    }
}

/// Release the active-request counter if it has not already been released.
pub(in crate::http) fn release_retry_state(ctx: &mut PingoraRequestCtx) {
    if !ctx.cluster_retry_state_released
        && let Some(state) = ctx.cluster_retry_state.take()
    {
        state.leave();
        ctx.cluster_retry_state_released = true;
    }
}

/// Release the failed endpoint's in-flight counter and clear the saved
/// upstream so the next attempt reselects, keeping the SNI that attempt
/// presented for the reselected upstream to reuse.
fn clear_for_reselection(ctx: &mut PingoraRequestCtx) {
    let failed = ctx.upstream_for_retry.take();
    if let Some(upstream) = failed.as_ref()
        && let Some(reselector) = ctx.endpoint_reselector.as_ref()
    {
        reselector.release(&upstream.address);
    }
    ctx.prior_attempt_sni = failed
        .as_ref()
        .and_then(|upstream| upstream.tls.as_ref())
        .and_then(|tls| tls.sni())
        .map(Arc::from);
}

/// Record `result=exhausted` only when at least one retry was already attempted.
fn record_retry_exhausted_if_attempted(ctx: &PingoraRequestCtx, cluster: ::metrics::SharedString) {
    if ctx.retries > 0 {
        metrics::record_upstream_retry(cluster, metrics::RETRY_RESULT_EXHAUSTED);
    }
}
