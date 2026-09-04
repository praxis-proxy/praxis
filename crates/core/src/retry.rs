// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared retry budget and per-cluster active-request tracking.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::RetryBudgetConfig;

// -----------------------------------------------------------------------------
// RetryBudget
// -----------------------------------------------------------------------------

/// Token-bucket rate limiter for cluster-wide retry admission.
///
/// Tokens refill at `min_retries_per_second` per second and are capped
/// at a dynamically computed `max_tokens(active_requests)`.
pub struct RetryBudget {
    /// Current available retry tokens.
    tokens: AtomicU64,
    /// Percentage of active requests used to compute the dynamic cap.
    percent: f64,
    /// Floor rate for token refill and minimum cap.
    min_retries_per_second: u32,
    /// Milliseconds since the unix epoch of the last refill.
    last_refill_ms: AtomicU64,
}

impl RetryBudget {
    /// Create a budget from config, pre-filled to the minimum floor.
    #[must_use]
    pub fn new(config: &RetryBudgetConfig) -> Self {
        let floor = u64::from(config.min_retries_per_second);
        Self {
            tokens: AtomicU64::new(floor),
            percent: config.percent.get(),
            min_retries_per_second: config.min_retries_per_second,
            last_refill_ms: AtomicU64::new(now_ms()),
        }
    }

    /// Create an unconstrained budget that always admits retries.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            tokens: AtomicU64::new(u64::MAX / 4),
            percent: 100.0,
            min_retries_per_second: u32::MAX,
            last_refill_ms: AtomicU64::new(now_ms()),
        }
    }

    /// Dynamically computed token cap from current traffic.
    #[must_use]
    pub fn max_tokens(&self, active_requests: u64) -> u64 {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "bounded percent; precision loss acceptable for budget math"
        )]
        let computed = (active_requests as f64 * self.percent / 100.0) as u64;
        computed.max(u64::from(self.min_retries_per_second))
    }

    /// Refill tokens based on elapsed time since `last_refill`.
    ///
    /// Refill rate = `min_retries_per_second` tokens/second.
    /// `tokens_to_add = min_retries_per_second * elapsed_seconds`,
    /// capped at `max_tokens(active_requests)`.
    pub fn refill(&self, active_requests: u64) {
        let now = now_ms();
        let last = self.last_refill_ms.load(Ordering::Relaxed);
        if now <= last {
            return;
        }
        let elapsed_ms = now - last;
        if elapsed_ms == 0 {
            return;
        }

        let tokens_to_add = u64::from(self.min_retries_per_second).saturating_mul(elapsed_ms) / 1000;
        if tokens_to_add == 0 {
            return;
        }

        // Only one refiller should advance last_refill; losers skip.
        if self
            .last_refill_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.add_tokens(tokens_to_add, active_requests);
    }

    /// CAS loop to add tokens up to the dynamic cap.
    fn add_tokens(&self, tokens_to_add: u64, active_requests: u64) {
        let cap = self.max_tokens(active_requests);
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(tokens_to_add).min(cap);
            match self
                .tokens
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Try to consume one token. Returns `true` if admitted.
    ///
    /// Uses a compare-exchange loop that succeeds only when `tokens > 0`.
    pub fn try_acquire(&self) -> bool {
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return false;
            }
            match self
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Current token count (for tests/metrics).
    #[must_use]
    pub fn available(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

/// Returns the current wall-clock time as milliseconds since the unix epoch.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// -----------------------------------------------------------------------------
// ClusterRetryState
// -----------------------------------------------------------------------------

/// Per-cluster shared state for retry budgeting and active request tracking.
pub struct ClusterRetryState {
    /// In-flight requests currently targeting this cluster.
    pub active_requests: AtomicU64,
    /// Token-bucket retry budget (unlimited when no budget config).
    pub budget: RetryBudget,
}

impl ClusterRetryState {
    /// Create state from an optional budget config.
    #[must_use]
    pub fn new(budget_config: Option<&RetryBudgetConfig>) -> Self {
        let budget = budget_config.map_or_else(RetryBudget::unlimited, RetryBudget::new);
        Self {
            active_requests: AtomicU64::new(0),
            budget,
        }
    }

    /// Increment the active-request counter. Returns the new count.
    pub fn enter(&self) -> u64 {
        self.active_requests.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrement the active-request counter (saturating at zero).
    pub fn leave(&self) {
        let mut current = self.active_requests.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self
                .active_requests
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Refill the budget from the live active-request count, then try to
    /// acquire one token. Returns `true` when a retry is admitted.
    pub fn try_admit_retry(&self) -> bool {
        let active = self.active_requests.load(Ordering::Relaxed);
        self.budget.refill(active);
        self.budget.try_acquire()
    }

    /// Access the underlying budget (tests/metrics).
    #[must_use]
    pub fn budget(&self) -> &RetryBudget {
        &self.budget
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::config::BudgetPercent;

    fn budget(percent: f64, min_rps: u32) -> RetryBudget {
        RetryBudget::new(&RetryBudgetConfig {
            percent: BudgetPercent::try_from(percent).unwrap(),
            min_retries_per_second: min_rps,
        })
    }

    #[test]
    fn max_tokens_uses_percent_of_active() {
        let b = budget(20.0, 10);
        // 100 active * 20% = 20, which is > floor of 10
        assert_eq!(b.max_tokens(100), 20);
    }

    #[test]
    fn max_tokens_respects_floor() {
        let b = budget(20.0, 10);
        // 10 active * 20% = 2, floored to 10
        assert_eq!(b.max_tokens(10), 10);
    }

    #[test]
    fn try_acquire_decrements() {
        let b = budget(100.0, 5);
        // starts with min_retries_per_second tokens
        assert_eq!(b.available(), 5);
        assert!(b.try_acquire());
        assert_eq!(b.available(), 4);
    }

    #[test]
    fn try_acquire_rejects_at_zero() {
        let b = budget(100.0, 1);
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
        assert_eq!(b.available(), 0);
    }

    #[test]
    fn unlimited_always_admits() {
        let state = ClusterRetryState::new(None);
        for _ in 0..100 {
            assert!(state.try_admit_retry());
        }
    }

    #[test]
    fn enter_leave_tracks_active() {
        let state = ClusterRetryState::new(None);
        assert_eq!(state.enter(), 1);
        assert_eq!(state.enter(), 2);
        state.leave();
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);
        state.leave();
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
        // leave at zero is a no-op
        state.leave();
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
    }
}
