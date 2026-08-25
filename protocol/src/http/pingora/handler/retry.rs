// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Policy-aware retry decision engine.
//!
//! Retry logic lives on the Praxis side of the Pingora boundary: given
//! an upstream failure outcome, this engine decides whether to retry and
//! how long to wait, applying the configured [`RetryPolicy`] (retriable
//! conditions and backoff) against per-cluster [`ClusterRetryState`] so
//! that retries cannot amplify upstream load without bound.

use std::time::Duration;

use praxis_core::{
    config::{BackoffConfig, RetriableCondition, RetryPolicy},
    retry::ClusterRetryState,
};
use rand::RngExt as _;
use tracing::debug;

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Classification of an upstream failure outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetryOutcome {
    /// TCP/TLS connect failure.
    ConnectFailure,
    /// Connection reset by peer.
    Reset,
    /// HTTP/2 refused stream.
    RefusedStream,
    /// Upstream returned an HTTP status code.
    StatusCode(u16),
    /// Any error not covered by an explicit classification.
    ///
    /// Never retriable: broadening unknown error types into a retriable
    /// class would silently retry internal errors, proxy bugs, and other
    /// conditions no policy opted into.
    Other,
}

/// Decision returned by [`should_retry`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetryDecision {
    /// Retry is allowed; caller should apply `backoff` then re-attempt.
    Retry {
        /// Delay before the next attempt.
        backoff: Duration,
    },
    /// Retry is not allowed.
    DoNotRetry,
}

// -----------------------------------------------------------------------------
// Classification
// -----------------------------------------------------------------------------

/// Return whether `outcome` is retriable under `policy`.
///
/// `retriable_status_codes` and `Status5xx` are OR-combined: either match
/// independently triggers retriability.
#[must_use]
pub(super) fn is_retriable(policy: &RetryPolicy, outcome: RetryOutcome) -> bool {
    match outcome {
        RetryOutcome::ConnectFailure => policy
            .retriable_conditions
            .contains(&RetriableCondition::ConnectFailure),
        RetryOutcome::Reset => policy.retriable_conditions.contains(&RetriableCondition::Reset),
        RetryOutcome::RefusedStream => policy.retriable_conditions.contains(&RetriableCondition::RefusedStream),
        RetryOutcome::StatusCode(code) => {
            let in_list = policy.retriable_status_codes.iter().any(|c| c.get() == code);
            let is_5xx =
                (500..600).contains(&code) && policy.retriable_conditions.contains(&RetriableCondition::Status5xx);
            in_list || is_5xx
        },
        RetryOutcome::Other => false,
    }
}

/// Classify a Pingora error into a [`RetryOutcome`].
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
        ErrorType::H2Error | ErrorType::H2Downgrade | ErrorType::InvalidH2 => RetryOutcome::RefusedStream,
        ErrorType::HTTPStatus(code) => RetryOutcome::StatusCode(*code),
        ErrorType::ReadError | ErrorType::ReadTimedout | ErrorType::WriteError | ErrorType::WriteTimedout => {
            RetryOutcome::Reset
        },
        _ => RetryOutcome::Other,
    }
}

// -----------------------------------------------------------------------------
// Decision
// -----------------------------------------------------------------------------

/// Retry decision over `ctx` and `policy`. Does not mutate `ctx`, but a
/// passing budget check consumes one token from `budget`; callers must not
/// re-invoke this for the same failure.
///
/// Guards (all must pass):
/// - outcome is retriable under the policy
/// - `ctx.retries < policy.max_retries`
/// - body size ≤ `retry_body_limit_bytes`
/// - method is idempotent OR `allow_non_idempotent`
/// - retry budget has remaining capacity (when `budget` is provided)
/// - `total_elapsed < request_timeout` (when configured)
#[must_use]
#[expect(clippy::too_many_lines, reason = "guard-rail sequence reads clearer as one function")]
pub(super) fn should_retry(
    ctx: &PingoraRequestCtx,
    policy: &RetryPolicy,
    outcome: RetryOutcome,
    budget: Option<&ClusterRetryState>,
) -> RetryDecision {
    if !is_retriable(policy, outcome) {
        debug!(?outcome, "outcome not retriable under policy");
        return RetryDecision::DoNotRetry;
    }

    if ctx.retries >= policy.effective_max_retries() {
        debug!(
            retries = ctx.retries,
            max = policy.effective_max_retries(),
            "retry limit reached"
        );
        return RetryDecision::DoNotRetry;
    }

    let mutated_len = ctx.mutated_request_body_len.unwrap_or(0) as u64;
    let effective_body_size = std::cmp::max(ctx.request_body_bytes, mutated_len);
    let body_limit = policy.body_limit_bytes();
    if effective_body_size > body_limit {
        debug!(
            body_bytes = effective_body_size,
            limit = body_limit,
            "skipping retry: body exceeds replay limit"
        );
        return RetryDecision::DoNotRetry;
    }

    if !ctx.request_is_idempotent && !policy.allow_non_idempotent() {
        debug!("skipping retry: non-idempotent method without opt-in");
        return RetryDecision::DoNotRetry;
    }

    if let Some(timeout_ms) = policy.request_timeout_ms {
        let elapsed = ctx.request_start.elapsed();
        if elapsed >= Duration::from_millis(timeout_ms) {
            debug!(
                elapsed_ms = elapsed.as_millis(),
                timeout_ms, "skipping retry: overall request timeout exceeded"
            );
            return RetryDecision::DoNotRetry;
        }
    }

    if let Some(state) = budget
        && !state.try_admit_retry()
    {
        debug!("skipping retry: budget exhausted");
        return RetryDecision::DoNotRetry;
    }

    let attempt = ctx.retries + 1;
    let backoff = compute_backoff(attempt, policy.backoff.as_ref());
    RetryDecision::Retry { backoff }
}

/// Compute full-jitter exponential backoff for the given 1-based attempt.
///
/// ```text
/// delay = min(base * 2^(attempt-1), max)
/// jittered = random_uniform(0, delay)
/// ```
#[must_use]
pub(super) fn compute_backoff(attempt: u32, config: Option<&BackoffConfig>) -> Duration {
    let cfg = config.cloned().unwrap_or_default();
    if attempt == 0 {
        return Duration::ZERO;
    }

    let exp = attempt.saturating_sub(1).min(63);
    let scaled = cfg.base_interval_ms.saturating_mul(1_u64 << exp);
    let capped = scaled.min(cfg.max_interval_ms);
    if capped == 0 {
        return Duration::ZERO;
    }

    let jittered = rand::rng().random_range(0..=capped);
    Duration::from_millis(jittered)
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

    #[test]
    fn should_retry_blocks_when_budget_exhausted() {
        use praxis_core::{config::RetryBudgetConfig, retry::ClusterRetryState};
        let cfg = RetryBudgetConfig {
            percent: praxis_core::config::BudgetPercent::try_from(0.0).unwrap(),
            min_retries_per_second: 0,
        };
        // min_rps 0 and percent 0 → max_tokens = 0, starts with 0 tokens
        let state = ClusterRetryState::new(Some(&cfg));
        // Force tokens to 0
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
}
