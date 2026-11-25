// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Transport attempt classification for passive health.
#[cfg(feature = "chain-binding")]
use praxis_core::health::PassiveTransition;
use praxis_core::subrequest::{StreamingSubResponse, SubRequestError};

use super::types::{ResponseOrigin, TransportFailure};
use crate::SubResponse;
#[cfg(feature = "chain-binding")]
use crate::{ClusterRef, HttpFilterContext};

// -----------------------------------------------------------------------------
// Attempt Result
// -----------------------------------------------------------------------------

/// What one transport attempt produced, before the response phase runs.
pub(super) enum AttemptResult {
    /// A streaming dial: response headers with a live body, or the error.
    Streaming(Box<Result<StreamingSubResponse, SubRequestError>>),
    /// A buffered dial: the response (real or synthesized) and its origin.
    Buffered(Box<(SubResponse, ResponseOrigin, Option<TransportFailure>)>),
}

// -----------------------------------------------------------------------------
// Attempt Classification
// -----------------------------------------------------------------------------

/// How one attempt went, as retries and passive health see it.
#[cfg(feature = "chain-binding")]
pub(super) struct AttemptFacts {
    /// Whether the endpoint failed (a transport error or a 5xx).
    pub(super) failure: bool,
    /// Whether the attempt reached the endpoint and its outcome describes
    /// the endpoint (not a caller-side admission, breaker, or size limit).
    pub(super) contacted: bool,
}

/// Classify an attempt. A connect error is a connect failure, an I/O error a
/// reset, and every other transport error is never retried.
#[cfg(feature = "chain-binding")]
pub(super) fn facts(result: &AttemptResult, contacted: bool) -> AttemptFacts {
    let failure = match result {
        AttemptResult::Streaming(response) => response
            .as_ref()
            .as_ref()
            .map_or(true, |response| response.status >= 500),
        AttemptResult::Buffered(response) => response.1 != ResponseOrigin::Upstream || response.0.status >= 500,
    };
    AttemptFacts {
        failure,
        contacted: contacted && !decided_by_caller(result),
    }
}

#[cfg(feature = "chain-binding")]
impl AttemptFacts {
    /// An attempt the step deadline cancelled after it dialed the endpoint.
    ///
    /// The endpoint took the whole remaining budget without answering, so it
    /// counts as an endpoint failure, the same as an attempt that timed out on
    /// its own.
    pub(super) const fn cancelled() -> Self {
        Self {
            failure: true,
            contacted: true,
        }
    }
}

/// Whether the attempt ended on the caller's side: the request could not be
/// built, the client's admission limit or circuit breaker refused to dial, or
/// the response exceeded the caller's own size limit. None of these says anything about the endpoint,
/// so passive health must not count them.
#[cfg(feature = "chain-binding")]
fn decided_by_caller(result: &AttemptResult) -> bool {
    match result {
        AttemptResult::Streaming(response) => matches!(
            response.as_ref(),
            Err(SubRequestError::InvalidRequest(_)
                | SubRequestError::AdmissionTimeout { .. }
                | SubRequestError::CircuitOpen { .. }
                | SubRequestError::ResponseTooLarge { .. })
        ),
        AttemptResult::Buffered(attempt) => matches!(
            attempt.2,
            Some(
                TransportFailure::InvalidRequest
                    | TransportFailure::AdmissionTimeout
                    | TransportFailure::CircuitOpen
                    | TransportFailure::ResponseTooLarge { .. }
            )
        ),
    }
}

// -----------------------------------------------------------------------------
// Passive Health
// -----------------------------------------------------------------------------

/// Report one attempt to the staged cluster's passive health.
///
/// Skipped when the attempt never reached the endpoint, or the cluster has no
/// health entry or passive thresholds.
#[cfg(feature = "chain-binding")]
pub(super) fn record_passive(ctx: &HttpFilterContext<'_>, cluster: &ClusterRef, facts: &AttemptFacts) {
    if !facts.contacted {
        return;
    }
    let Some(idx) = ctx.selected_endpoint_index else {
        return;
    };
    let Some(health) = ctx.health_registry.and_then(|registry| registry.get(cluster.name())) else {
        return;
    };
    match health.observe_passive(idx, facts.failure) {
        Some(PassiveTransition::Unhealthy { threshold }) => tracing::warn!(
            cluster = %cluster.name(),
            endpoint_index = idx,
            threshold,
            "passive health: endpoint marked unhealthy"
        ),
        Some(PassiveTransition::Recovered { threshold }) => tracing::info!(
            cluster = %cluster.name(),
            endpoint_index = idx,
            threshold,
            "passive health: endpoint recovered"
        ),
        None => {},
    }
}
