// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! One transport attempt of a filtered sub-request, and the retry rules for
//! callouts staged at a named cluster.
//!
//! A callout staged with [`StagedCluster`](super::StagedCluster) is retried
//! under its cluster's `retry_policy`, with the same decision the main proxy
//! path makes ([`praxis_core::retry::should_retry`]). Every attempt also
//! reports to the cluster's passive health. Callouts without a staged cluster
//! make exactly one attempt.

#[cfg(feature = "chain-binding")]
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(feature = "chain-binding")]
use praxis_core::subrequest::ExchangeFailure;
use praxis_core::subrequest::{StreamingSubResponse, SubRequestError};
#[cfg(feature = "chain-binding")]
use praxis_core::{
    connectivity::Upstream,
    health::PassiveTransition,
    retry::{RetryAttempt, RetryDecision, RetryOutcome, should_retry},
};

use super::types::{ResponseOrigin, TransportFailure};
use crate::SubResponse;
#[cfg(feature = "chain-binding")]
use crate::{
    ClusterRef, HttpFilterContext,
    credentials::{InjectedSet, PendingCredentials, ResolvedDestination},
};

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

impl AttemptResult {
    /// Release a live streaming body this attempt opened but will not use.
    #[cfg(feature = "chain-binding")]
    pub(super) async fn discard(self) {
        if let Self::Streaming(response) = self
            && let Ok(response) = *response
        {
            response.body.cancel().await;
        }
    }
}

// -----------------------------------------------------------------------------
// Attempt Classification
// -----------------------------------------------------------------------------

/// How one attempt went, as retries and passive health see it.
#[cfg(feature = "chain-binding")]
pub(super) struct AttemptFacts {
    /// The retry classification of the outcome.
    pub(super) outcome: RetryOutcome,
    /// Whether the endpoint failed (a transport error or a 5xx).
    pub(super) failure: bool,
    /// Whether the attempt reached the endpoint and its outcome describes
    /// the endpoint (not a caller-side admission, breaker, or size limit).
    pub(super) contacted: bool,
}

/// Classify an attempt. A connect error is a connect failure, an I/O error a
/// reset, and every other transport error is never retried.
#[cfg(feature = "chain-binding")]
pub(super) fn facts(result: &AttemptResult, contacted: bool, exchange: Option<ExchangeFailure>) -> AttemptFacts {
    // An I/O failure keeps the HTTP/2 class the transport recorded: only a
    // refused stream is known to be unprocessed, and an aborted exchange may
    // have been acted on, as the main proxy path classifies them.
    let io = match exchange {
        None => RetryOutcome::Reset,
        Some(ExchangeFailure::Refused) => RetryOutcome::RefusedStream,
        Some(ExchangeFailure::Aborted) => RetryOutcome::Other,
    };
    let outcome = match result {
        AttemptResult::Streaming(response) => match response.as_ref() {
            Ok(response) => RetryOutcome::StatusCode(response.status),
            Err(SubRequestError::Connect(_)) => RetryOutcome::ConnectFailure,
            Err(SubRequestError::Io(_)) => io,
            Err(_) => RetryOutcome::Other,
        },
        AttemptResult::Buffered(attempt) => match (&attempt.1, &attempt.2) {
            (ResponseOrigin::Upstream, _) => RetryOutcome::StatusCode(attempt.0.status),
            (_, Some(TransportFailure::Connect)) => RetryOutcome::ConnectFailure,
            (_, Some(TransportFailure::Io)) => io,
            (ResponseOrigin::Local | ResponseOrigin::Transport, _) => RetryOutcome::Other,
        },
    };
    let failure = match outcome {
        RetryOutcome::StatusCode(status) => status >= 500,
        RetryOutcome::ConnectFailure | RetryOutcome::Reset | RetryOutcome::RefusedStream | RetryOutcome::Other => true,
    };
    AttemptFacts {
        outcome,
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
            outcome: RetryOutcome::Other,
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
    if facts.contacted
        && let Some(observation) = PassiveObservation::new(ctx, cluster)
    {
        observation.finish(facts.failure);
    }
}

/// Endpoint selected for one transport observation.
#[cfg(feature = "chain-binding")]
pub(super) struct PassiveObservation {
    /// Health state retained across streaming body reads.
    health: praxis_core::health::ClusterHealthState,
    /// Selected endpoint.
    idx: usize,
    /// Cluster name for transition logs.
    cluster: Arc<str>,
}

#[cfg(feature = "chain-binding")]
impl PassiveObservation {
    /// Capture the selected endpoint.
    pub(super) fn new(ctx: &HttpFilterContext<'_>, cluster: &ClusterRef) -> Option<Self> {
        Some(Self {
            health: Arc::clone(ctx.health_registry?.get(cluster.name())?),
            idx: ctx.selected_endpoint_index?,
            cluster: Arc::from(cluster.name()),
        })
    }

    /// Apply the terminal transport outcome once.
    pub(super) fn finish(self, failure: bool) {
        let Self { health, idx, cluster } = self;
        match health.observe_passive(idx, failure) {
            Some(PassiveTransition::Unhealthy { threshold }) => tracing::warn!(
                cluster = %cluster,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint marked unhealthy"
            ),
            Some(PassiveTransition::Recovered { threshold }) => tracing::info!(
                cluster = %cluster,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint recovered"
            ),
            None => {},
        }
    }
}

// -----------------------------------------------------------------------------
// Retry Decision
// -----------------------------------------------------------------------------

/// The request facts a retry decision needs, fixed for the whole callout.
#[cfg(feature = "chain-binding")]
pub(super) struct RetryContext<'a> {
    /// The callout's method, for the idempotency guard.
    pub(super) method: &'a http::Method,
    /// The larger of the step's input body and the body a retry replays, as
    /// the main proxy counts it, so a filter that shrinks an oversized body
    /// cannot make it replayable.
    pub(super) body_len: usize,
    /// When the callout step started, for `request_timeout_ms`.
    pub(super) started: Instant,
    /// Absolute step deadline; no backoff may run past it.
    pub(super) deadline: Instant,
}

/// Decide whether to retry, returning the backoff to wait first.
///
/// Uses the cluster's retry policy (the legacy default when unset). A retry
/// whose backoff would reach the step deadline is not made. The retry budget
/// is charged later, by [`next_endpoint`], once the retry is certain to run.
///
/// An attempt that never reached the endpoint is not retried: a peer that
/// could not be built (a refused private address, a failed lookup, a TLS
/// peer with no name) fails the same way again.
#[cfg(feature = "chain-binding")]
pub(super) fn decide(
    cluster: &ClusterRef,
    facts: &AttemptFacts,
    retries: u32,
    request: &RetryContext<'_>,
) -> Option<Duration> {
    if !facts.contacted {
        return None;
    }
    let attempt = RetryAttempt {
        retries,
        idempotent: praxis_core::retry::replays_without_opt_in(request.method),
        replay_body_bytes: u64::try_from(request.body_len).unwrap_or(u64::MAX),
        replay_safe: true,
        elapsed: request.started.elapsed(),
    };
    let RetryDecision::Retry { backoff } = should_retry(&attempt, cluster.entry().retry_policy(), facts.outcome, None)
    else {
        return None;
    };
    Instant::now()
        .checked_add(backoff)
        .is_some_and(|resume| resume < request.deadline)
        .then_some(backoff)
}

/// What [`next_endpoint`] needs to know about the attempts so far.
#[cfg(feature = "chain-binding")]
pub(super) struct RetryTarget<'a> {
    /// Endpoint addresses already tried.
    pub(super) attempted: &'a [Arc<str>],
    /// The endpoint the failed attempt dialed.
    pub(super) current: &'a Upstream,
    /// The staged credentials and the set the first attempt injected.
    pub(super) credentials: Option<(&'a PendingCredentials, &'a InjectedSet)>,
    /// Whether a selected-upstream body writer adapted the body for `current`.
    pub(super) body_bound: bool,
}

/// Choose the endpoint for the next attempt.
///
/// A configured retry policy prefers an endpoint outside `attempted` and
/// swaps the held lease. It redials `current`, as the main proxy path does,
/// when no such endpoint is available or the one selected would receive a
/// different set of staged credentials than the first attempt did. The
/// legacy default always redials `current`, and so does any policy when the
/// body was adapted for `current`, since that body may carry its
/// credential. The retry is abandoned (`None`) only when the cluster's retry
/// budget is spent; the budget is charged last, so it costs no token then.
#[cfg(feature = "chain-binding")]
pub(super) fn next_endpoint(
    ctx: &mut HttpFilterContext<'_>,
    pinned: &mut super::staged_cluster::PinnedCluster,
    target: &RetryTarget<'_>,
) -> Option<(Upstream, RetryReservation)> {
    let reselect = pinned.cluster.entry().retry_policy().configured && !target.body_bound;
    if let Some((candidate, lease)) = reselect.then(|| alternate(ctx, pinned, target)).flatten() {
        let reservation = admit_retry(&pinned.cluster)?;
        ctx.selected_endpoint_index = Some(lease.index);
        pinned.lease = lease;
        return Some((candidate, reservation));
    }
    admit_retry(&pinned.cluster).map(|reservation| (target.current.clone(), reservation))
}

/// An endpoint outside `target.attempted` that would receive the same staged
/// credentials as the first attempt.
#[cfg(feature = "chain-binding")]
fn alternate(
    ctx: &HttpFilterContext<'_>,
    pinned: &super::staged_cluster::PinnedCluster,
    target: &RetryTarget<'_>,
) -> Option<(Upstream, crate::cluster_ref::ClusterLease)> {
    // A strategy may fall back to an excluded endpoint (ring hash returns its
    // hashed endpoint once every one is excluded); that is a redial.
    let (candidate, lease) = pinned
        .cluster
        .select(ctx, target.attempted, pinned.lease.admission())
        .ok()
        .filter(|(candidate, _)| !target.attempted.contains(&candidate.address))?;
    if let Some((pending, first)) = target.credentials
        && matched_credentials(pending, &candidate) != *first
    {
        tracing::debug!(
            cluster = %pinned.cluster.name(),
            "redialing: the next endpoint would receive different credentials"
        );
        return None;
    }
    Some((candidate, lease))
}

/// Refunds a retry interrupted while releasing a response or awaiting backoff.
#[cfg(feature = "chain-binding")]
pub(super) struct RetryReservation(Option<ClusterRef>);

#[cfg(feature = "chain-binding")]
impl RetryReservation {
    /// Commit the token when the executor starts the next attempt.
    pub(super) fn commit(mut self) {
        self.0 = None;
    }
}

#[cfg(feature = "chain-binding")]
impl Drop for RetryReservation {
    fn drop(&mut self) {
        if let Some(cluster) = &self.0 {
            cluster.entry().retry_state().refund_retry();
        }
    }
}

/// Reserve one token from the cluster's retry budget.
#[cfg(feature = "chain-binding")]
fn admit_retry(cluster: &ClusterRef) -> Option<RetryReservation> {
    let admitted = cluster.entry().retry_state().try_admit_retry();
    if !admitted {
        tracing::debug!(cluster = %cluster.name(), "not retrying: retry budget exhausted");
    }
    admitted.then(|| RetryReservation(Some(cluster.clone())))
}

/// The credentials `pending` would inject for a request to `upstream`.
#[cfg(feature = "chain-binding")]
fn matched_credentials(pending: &PendingCredentials, upstream: &Upstream) -> InjectedSet {
    let (logical, transport) = destination(upstream);
    let destination = ResolvedDestination {
        authority: &logical,
        transport: &transport,
    };
    pending.inject_matching(&destination, &mut http::HeaderMap::new())
}

/// The logical authority (the `authority` override, else the transport
/// address) and the transport address of `upstream`.
#[cfg(feature = "chain-binding")]
pub(super) fn destination(upstream: &Upstream) -> (Arc<str>, Arc<str>) {
    let transport = Arc::clone(&upstream.address);
    let logical = upstream
        .authority
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| Arc::clone(&transport), Arc::from);
    (logical, transport)
}

#[cfg(feature = "chain-binding")]
#[cfg(test)]
mod tests {
    use super::*;

    /// Backoff cancellation refunds the token, while a started retry consumes it.
    #[test]
    fn reservation_is_charged_only_when_committed() -> Result<(), crate::FilterError> {
        let config = serde_yaml::from_str(
            "name: backend\nendpoints: ['127.0.0.1:9']\nretry_policy:\n  retry_budget:\n    percent: 0\n    min_retries_per_second: 1",
        )?;
        let cluster = ClusterRef::resolve(&config)?;
        let budget = cluster.entry().retry_state().budget();
        let reserve = || admit_retry(&cluster).ok_or("expected one available retry token");
        let reservation = reserve()?;
        assert_eq!(budget.available(), 0, "reservation holds the token");
        drop(reservation);
        assert_eq!(budget.available(), 1, "cancellation refunds the token");
        reserve()?.commit();
        assert_eq!(budget.available(), 0, "started retry consumes the token");
        Ok(())
    }
}
