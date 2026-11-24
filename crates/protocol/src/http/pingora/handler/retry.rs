// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Policy-aware retry decision engine.
//!
//! Retry logic lives on the Praxis side of the Pingora boundary: given
//! an upstream failure outcome, this engine decides whether to retry and
//! how long to wait, applying the configured [`RetryPolicy`](praxis_core::config::RetryPolicy) (retriable
//! conditions and backoff) against per-cluster [`ClusterRetryState`](praxis_core::retry::ClusterRetryState) so
//! that retries cannot amplify upstream load without bound.

#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use praxis_core::config::{BackoffConfig, RetriableCondition};
pub(super) use praxis_core::retry::RetryDecision;
pub(in crate::http) use praxis_core::retry::RetryOutcome;
#[cfg(test)]
use praxis_core::retry::{compute_backoff, is_retriable};
use praxis_core::{
    config::RetryPolicy,
    retry::{ClusterRetryState, RetryAttempt},
};

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

/// Classify a Pingora error into a [`RetryOutcome`].
#[cfg(feature = "pingora")]
#[must_use]
pub(super) fn classify_error(e: &pingora_core::Error) -> RetryOutcome {
    use pingora_core::ErrorType;
    match e.etype() {
        ErrorType::ConnectError
        | ErrorType::ConnectTimedout
        | ErrorType::ConnectRefused
        | ErrorType::ConnectNoRoute
        | ErrorType::ConnectProxyFailure
        | ErrorType::TLSHandshakeFailure
        | ErrorType::TLSHandshakeTimedout => RetryOutcome::ConnectFailure,
        ErrorType::ConnectionClosed => RetryOutcome::Reset,
        ErrorType::H2Error => classify_h2_error(e),
        ErrorType::H2Downgrade | ErrorType::InvalidH2 => RetryOutcome::RefusedStream,
        ErrorType::HTTPStatus(code) => RetryOutcome::StatusCode(*code),
        ErrorType::ReadError | ErrorType::ReadTimedout | ErrorType::WriteError | ErrorType::WriteTimedout => {
            RetryOutcome::Reset
        },
        _ => RetryOutcome::Other,
    }
}

/// Classify an `H2Error` by the underlying [`h2::Error`].
///
/// Only a `REFUSED_STREAM` reset guarantees the upstream did not process the
/// request ([RFC 9113 Section 8.7]), so only that maps to
/// [`RetryOutcome::RefusedStream`]. A GOAWAY or I/O failure is treated like a
/// connection reset, and any other stream or connection error (for example
/// `INTERNAL_ERROR` after the backend acted) is never retriable.
///
/// [`h2::Error`]: h2::Error
/// [RFC 9113 Section 8.7]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.7
#[cfg(feature = "pingora")]
fn classify_h2_error(e: &pingora_core::Error) -> RetryOutcome {
    let Some(h2_error) = e.root_cause().downcast_ref::<h2::Error>() else {
        return RetryOutcome::Other;
    };
    if h2_error.reason() == Some(h2::Reason::REFUSED_STREAM) {
        RetryOutcome::RefusedStream
    } else if h2_error.is_go_away() || h2_error.is_io() {
        RetryOutcome::Reset
    } else {
        RetryOutcome::Other
    }
}

// -----------------------------------------------------------------------------
// Decision
// -----------------------------------------------------------------------------

/// A streamed writer's first output has no authoritative Pingora replay copy.
pub(super) fn streaming_writer_cannot_replay(ctx: &PingoraRequestCtx) -> bool {
    ctx.streaming_request_writer_ran
        && ctx.retained_pre_read_body.is_none()
        && ctx.retained_adapted_request_body.is_none()
}

/// Larger of the original input and the final authoritative representation.
///
/// The adapted body, when present, supersedes the earlier canonical body.
pub(super) fn replay_body_size(ctx: &PingoraRequestCtx) -> u64 {
    let transformed = ctx
        .adapted_request_body_len
        .or(ctx.mutated_request_body_len)
        .unwrap_or(0);
    ctx.request_body_bytes
        .max(u64::try_from(transformed).unwrap_or(u64::MAX))
}

/// Retry decision over `ctx` and `policy`. Does not mutate `ctx`, but a
/// passing budget check consumes one token from `budget`; callers must not
/// re-invoke this for the same failure.
///
/// Gathers the attempt facts from `ctx` and delegates to
/// [`praxis_core::retry::should_retry`], which owns the guard sequence.
#[must_use]
pub(super) fn should_retry(
    ctx: &PingoraRequestCtx,
    policy: &RetryPolicy,
    outcome: RetryOutcome,
    budget: Option<&ClusterRetryState>,
) -> RetryDecision {
    let attempt = RetryAttempt {
        retries: ctx.retries,
        idempotent: ctx.request_is_idempotent,
        // Adapted length (selected-upstream phase, #1139) supersedes the
        // pre-read mutated length; retry accounting uses the larger of the
        // original downstream body and the final transformed body.
        replay_body_bytes: replay_body_size(ctx),
        replay_safe: !streaming_writer_cannot_replay(ctx),
        elapsed: ctx.request_start.elapsed(),
    };
    praxis_core::retry::should_retry(&attempt, policy, outcome, budget)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_core::config::HttpStatusCode;

    use super::*;

    fn ctx_idempotent() -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx
    }

    #[test]
    fn status5xx_and_explicit_codes_are_or_combined() {
        let policy = RetryPolicy {
            retriable_status_codes: vec![HttpStatusCode::try_from(429).unwrap()],
            retriable_conditions: vec![RetriableCondition::Status5xx],
            ..RetryPolicy::legacy_default()
        };
        assert!(is_retriable(&policy, RetryOutcome::StatusCode(503)));
        assert!(is_retriable(&policy, RetryOutcome::StatusCode(429)));
        assert!(!is_retriable(&policy, RetryOutcome::StatusCode(404)));
    }

    #[test]
    fn connect_failure_requires_condition() {
        let policy = RetryPolicy {
            retriable_conditions: vec![RetriableCondition::Status5xx],
            ..RetryPolicy::legacy_default()
        };
        assert!(!is_retriable(&policy, RetryOutcome::ConnectFailure));
        assert!(is_retriable(
            &RetryPolicy::legacy_default(),
            RetryOutcome::ConnectFailure
        ));
    }

    #[test]
    fn should_retry_respects_max_retries() {
        let mut ctx = ctx_idempotent();
        ctx.retries = 3;
        let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn should_retry_blocks_non_idempotent() {
        let ctx = PingoraRequestCtx::default();
        let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn should_retry_allows_non_idempotent_with_opt_in() {
        let ctx = PingoraRequestCtx::default();
        let policy = RetryPolicy {
            allow_non_idempotent: Some(true),
            ..RetryPolicy::legacy_default()
        };
        let decision = should_retry(&ctx, &policy, RetryOutcome::ConnectFailure, None);
        assert!(matches!(decision, RetryDecision::Retry { .. }));
    }

    #[test]
    fn should_retry_blocks_oversized_body() {
        let mut ctx = ctx_idempotent();
        ctx.request_body_bytes = 100_000;
        let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    /// Check that a retained representation makes a connection retry safe.
    fn assert_body_retryable(ctx: &PingoraRequestCtx, policy: &RetryPolicy, reason: &str) {
        assert!(
            matches!(
                should_retry(ctx, policy, RetryOutcome::ConnectFailure, None),
                RetryDecision::Retry { .. }
            ),
            "{reason}"
        );
    }

    #[test]
    fn streamed_writer_requires_an_authoritative_replay_body() {
        let policy = RetryPolicy::legacy_default();
        let mut ctx = ctx_idempotent();
        assert_body_retryable(
            &ctx,
            &policy,
            "a writer that has not run does not block a connection retry",
        );
        ctx.streaming_request_writer_ran = true;
        assert_eq!(
            should_retry(&ctx, &policy, RetryOutcome::ConnectFailure, None),
            RetryDecision::DoNotRetry,
            "unretained streamed output cannot be replayed safely"
        );
        ctx.retained_pre_read_body = Some(std::collections::VecDeque::new());
        assert_body_retryable(&ctx, &policy, "a retained canonical body is replayable");
        ctx.retained_pre_read_body = None;
        ctx.retained_adapted_request_body = Some(std::collections::VecDeque::new());
        assert_body_retryable(&ctx, &policy, "a retained adapted body is replayable");
    }

    #[test]
    fn should_retry_blocks_when_budget_exhausted() {
        use praxis_core::{config::RetryBudgetConfig, retry::ClusterRetryState};
        let cfg = RetryBudgetConfig {
            percent: praxis_core::config::BudgetPercent::try_from(0.0).unwrap(),
            min_retries_per_second: 0,
        };
        let state = ClusterRetryState::new(Some(&cfg));
        while state.budget().try_acquire() {}
        let ctx = ctx_idempotent();
        let policy = RetryPolicy {
            retry_budget: Some(cfg),
            ..RetryPolicy::legacy_default()
        };
        let decision = should_retry(&ctx, &policy, RetryOutcome::ConnectFailure, Some(&state));
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn should_retry_blocks_when_request_timeout_exceeded() {
        let mut ctx = ctx_idempotent();
        ctx.request_start = std::time::Instant::now() - Duration::from_secs(10);
        let policy = RetryPolicy {
            request_timeout_ms: Some(1000),
            ..RetryPolicy::legacy_default()
        };
        let decision = should_retry(&ctx, &policy, RetryOutcome::ConnectFailure, None);
        assert_eq!(decision, RetryDecision::DoNotRetry);
    }

    #[test]
    fn compute_backoff_respects_max() {
        let cfg = BackoffConfig {
            base_interval_ms: 100,
            max_interval_ms: 200,
        };
        for attempt in 1..10 {
            let d = compute_backoff(attempt, Some(&cfg));
            assert!(d <= Duration::from_millis(200));
        }
    }

    #[test]
    fn legacy_policy_retries_connect_failure() {
        let ctx = ctx_idempotent();
        let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);
        assert!(matches!(decision, RetryDecision::Retry { .. }));
    }

    #[test]
    fn status5xx_yaml_alias_parses() {
        let cond: RetriableCondition = serde_yaml::from_str("status_5xx").unwrap();
        assert_eq!(cond, RetriableCondition::Status5xx);
        let cond: RetriableCondition = serde_yaml::from_str("status5xx").unwrap();
        assert_eq!(cond, RetriableCondition::Status5xx);
    }
    #[test]
    fn unknown_error_types_are_not_retriable() {
        let policy = RetryPolicy::legacy_default();
        assert!(
            !is_retriable(&policy, RetryOutcome::Other),
            "unclassified errors must never be retried"
        );
        let permissive = RetryPolicy {
            retriable_conditions: vec![
                RetriableCondition::ConnectFailure,
                RetriableCondition::Reset,
                RetriableCondition::RefusedStream,
                RetriableCondition::Status5xx,
            ],
            ..RetryPolicy::legacy_default()
        };
        assert!(
            !is_retriable(&permissive, RetryOutcome::Other),
            "even a fully permissive policy must not retry unclassified errors"
        );
    }

    #[test]
    fn should_retry_blocks_when_adapted_body_exceeds_limit() {
        let mut ctx = ctx_idempotent();
        ctx.request_body_bytes = 10; // small original downstream body
        ctx.adapted_request_body_len = Some(100_000); // adaptation expanded it past the limit

        let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);

        assert!(
            matches!(decision, RetryDecision::DoNotRetry),
            "an adapted body over the replay limit must block the retry"
        );
    }

    #[test]
    fn retry_guard_uses_original_and_final_transformed_lengths() {
        let cap = praxis_core::config::DEFAULT_RETRY_BODY_LIMIT_BYTES;
        for (original, mutated, adapted, allowed) in [
            (cap - 1, None, None, true),
            (cap, None, None, true),
            (cap + 1, Some(1), None, false),
            (1, Some(usize::try_from(cap).unwrap()), None, true),
            (1, Some(usize::try_from(cap + 1).unwrap()), None, false),
            (1, Some(usize::try_from(cap + 1).unwrap()), Some(1), true),
            (1, Some(1), Some(usize::try_from(cap + 1).unwrap()), false),
            (cap + 1, Some(1), Some(1), false),
        ] {
            let mut ctx = ctx_idempotent();
            ctx.request_body_bytes = original;
            ctx.mutated_request_body_len = mutated;
            ctx.adapted_request_body_len = adapted;
            let decision = should_retry(&ctx, &RetryPolicy::legacy_default(), RetryOutcome::ConnectFailure, None);
            assert_eq!(
                matches!(decision, RetryDecision::Retry { .. }),
                allowed,
                "original={original}, mutated={mutated:?}, adapted={adapted:?}"
            );
        }
    }

    #[cfg(feature = "pingora")]
    fn h2_error_with_reason(reason: h2::Reason) -> pingora_core::BError {
        pingora_core::Error::because(
            pingora_core::ErrorType::H2Error,
            "while reading h2 header",
            h2::Error::from(reason),
        )
    }

    #[cfg(feature = "pingora")]
    #[test]
    fn h2_refused_stream_is_refused_stream() {
        assert_eq!(
            classify_error(&h2_error_with_reason(h2::Reason::REFUSED_STREAM)),
            RetryOutcome::RefusedStream,
            "REFUSED_STREAM guarantees no processing and must classify as refused stream"
        );
    }

    #[cfg(feature = "pingora")]
    #[test]
    fn h2_internal_error_is_not_refused_stream() {
        assert_eq!(
            classify_error(&h2_error_with_reason(h2::Reason::INTERNAL_ERROR)),
            RetryOutcome::Other,
            "a generic H2 stream error may follow processing and must not be retriable"
        );
    }

    #[cfg(feature = "pingora")]
    #[test]
    fn h2_error_without_cause_is_other() {
        assert_eq!(
            classify_error(&pingora_core::Error::new(pingora_core::ErrorType::H2Error)),
            RetryOutcome::Other,
            "an H2 error with no h2 cause must not be assumed refused"
        );
    }
}
