// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Token bucket for rate limiting.

use std::fmt;

use parking_lot::Mutex;

// -----------------------------------------------------------------------------
// TokenBucket
// -----------------------------------------------------------------------------

/// Token bucket for rate limiting.
///
/// # Example
///
/// ```ignore
/// use praxis_filter::builtins::http::traffic_management::token_bucket::TokenBucket;
///
/// let bucket = TokenBucket::new(5.0);
/// assert!(bucket.try_acquire(10.0, 5.0, 0).is_some());
/// ```
pub(crate) struct TokenBucket {
    /// Compound bucket state that must be updated atomically.
    state: Mutex<TokenBucketState>,
}

/// Mutable state for a [`TokenBucket`].
struct TokenBucketState {
    /// Last refill timestamp in nanoseconds since epoch.
    last_refill: u64,

    /// Current token count.
    tokens: f64,
}

impl TokenBucket {
    /// Create a bucket pre-filled with `burst` tokens.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::builtins::http::traffic_management::token_bucket::TokenBucket;
    ///
    /// let bucket = TokenBucket::new(10.0);
    /// ```
    pub(crate) fn new(burst: f64) -> Self {
        Self {
            state: Mutex::new(TokenBucketState {
                tokens: burst,
                last_refill: 0,
            }),
        }
    }

    /// Try to consume one token, refilling based on elapsed time.
    ///
    /// Returns `Some(remaining)` on success, `None` when the bucket
    /// is empty.
    ///
    /// Refill and consumption are serialized because the token count and
    /// timestamp form one logical state transition.
    pub(crate) fn try_acquire(&self, rate: f64, burst: f64, now_nanos: u64) -> Option<f64> {
        let mut state = self.lock_state();
        let mut tokens = state.tokens;
        let elapsed_nanos = now_nanos.saturating_sub(state.last_refill);
        if elapsed_nanos > 0 {
            let elapsed_secs = nanos_to_secs(elapsed_nanos);
            tokens = (tokens + elapsed_secs * rate).min(burst);
        }

        if tokens < 1.0 {
            return None;
        }

        state.tokens = tokens - 1.0;
        state.last_refill = state.last_refill.max(now_nanos);
        Some(state.tokens)
    }

    /// Read the last refill timestamp in nanoseconds.
    pub(crate) fn last_refill_nanos(&self) -> u64 {
        self.lock_state().last_refill
    }

    /// Read current token count without modification.
    pub(crate) fn current_tokens(&self, rate: f64, burst: f64, now_nanos: u64) -> f64 {
        let state = self.lock_state();
        let elapsed_secs = nanos_to_secs(now_nanos.saturating_sub(state.last_refill));
        (state.tokens + elapsed_secs * rate).min(burst)
    }

    /// Lock the compound state for one consistent bucket operation.
    fn lock_state(&self) -> parking_lot::MutexGuard<'_, TokenBucketState> {
        self.state.lock()
    }
}

impl fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        f.debug_struct("TokenBucket")
            .field("tokens", &state.tokens)
            .field("last_refill", &state.last_refill)
            .finish()
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Convert nanoseconds to seconds without `u64`-to-`f64` precision loss.
///
/// Splits the value into whole seconds (exact integer division) and a
/// sub-second remainder that fits within `f64`'s 53-bit mantissa,
/// avoiding the precision loss that occurs when casting large `u64`
/// nanosecond counts (>2^53, roughly 104 days) directly to `f64`.
///
/// ```ignore
/// let secs = nanos_to_secs(9_000_000_001_000_000_000); // ~285 years
/// assert!((secs - 9_000_000_001.0).abs() < 1e-9);
/// ```
#[expect(
    clippy::cast_precision_loss,
    reason = "whole_secs max ~1.8e10 (u64::MAX nanos); well within f64's 2^53 mantissa. remainder < 1e9 is exact"
)]
fn nanos_to_secs(nanos: u64) -> f64 {
    let whole_secs = nanos / 1_000_000_000;
    let remainder = nanos % 1_000_000_000;
    whole_secs as f64 + remainder as f64 / 1_000_000_000.0
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "tests"
)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    #[test]
    fn acquire_succeeds() {
        let bucket = TokenBucket::new(5.0);
        assert!(
            bucket.try_acquire(10.0, 5.0, 0).is_some(),
            "fresh bucket should allow acquisition"
        );
    }

    #[test]
    fn acquire_depletes() {
        let bucket = TokenBucket::new(3.0);
        for i in 0..3 {
            assert!(
                bucket.try_acquire(10.0, 3.0, 0).is_some(),
                "acquisition {i} should succeed within burst"
            );
        }
        assert!(
            bucket.try_acquire(10.0, 3.0, 0).is_none(),
            "acquisition past burst should fail"
        );
    }

    #[test]
    fn refills_over_time() {
        let bucket = TokenBucket::new(1.0);
        assert!(
            bucket.try_acquire(10.0, 1.0, 0).is_some(),
            "first acquisition should succeed"
        );
        assert!(
            bucket.try_acquire(10.0, 1.0, 0).is_none(),
            "second immediate acquisition should fail"
        );
        assert!(
            bucket.try_acquire(10.0, 1.0, 200_000_000).is_some(),
            "acquisition after 200ms at rate=10/s should succeed (2 tokens refilled)"
        );
    }

    #[test]
    fn last_refill_never_moves_backwards() {
        let bucket = TokenBucket::new(100.0);
        bucket.try_acquire(10.0, 100.0, 200);
        assert_eq!(
            bucket.last_refill_nanos(),
            200,
            "last_refill should be 200 after first acquire"
        );

        bucket.try_acquire(10.0, 100.0, 100);
        assert_eq!(
            bucket.last_refill_nanos(),
            200,
            "last_refill must not regress to an earlier timestamp"
        );
    }

    #[test]
    fn last_refill_advances_monotonically() {
        let bucket = TokenBucket::new(100.0);
        bucket.try_acquire(10.0, 100.0, 100);
        bucket.try_acquire(10.0, 100.0, 300);
        bucket.try_acquire(10.0, 100.0, 200);
        bucket.try_acquire(10.0, 100.0, 400);

        assert_eq!(
            bucket.last_refill_nanos(),
            400,
            "last_refill should reflect the highest timestamp seen"
        );
    }

    #[test]
    fn current_tokens_readonly() {
        let bucket = TokenBucket::new(5.0);
        bucket.try_acquire(10.0, 5.0, 0);
        let current = bucket.current_tokens(10.0, 5.0, 0);
        assert!(
            (current - 4.0).abs() < 0.01,
            "current_tokens should reflect remaining after one acquisition, got {current}"
        );
    }

    #[test]
    fn failed_acquisition_does_not_mutate_state() {
        let bucket = TokenBucket::new(1.0);
        assert!(bucket.try_acquire(1.0, 1.0, 0).is_some());
        assert!(bucket.try_acquire(1.0, 1.0, 500_000_000).is_none());
        assert_eq!(
            bucket.last_refill_nanos(),
            0,
            "a failed acquisition must not advance the refill timestamp"
        );
        assert!(
            (bucket.current_tokens(1.0, 1.0, 500_000_000) - 0.5).abs() < 0.01,
            "a failed acquisition must not consume the fractional refill"
        );
    }

    #[test]
    fn concurrent_fetch_max_monotonicity() {
        use std::{sync::Arc, thread};

        let bucket = Arc::new(TokenBucket::new(10_000.0));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let bucket = Arc::clone(&bucket);
                thread::spawn(move || {
                    for j in 0..500 {
                        let ts = (i * 1000 + j) as u64;
                        bucket.try_acquire(10_000.0, 10_000.0, ts);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let final_refill = bucket.last_refill_nanos();
        assert!(
            final_refill >= 7000,
            "last_refill should be at least the max timestamp from thread 7, got {final_refill}"
        );
    }

    #[test]
    fn concurrent_acquire_total_tokens_bounded() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            thread,
        };

        let bucket = Arc::new(TokenBucket::new(100.0));
        let acquired = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let bucket = Arc::clone(&bucket);
            let acquired = Arc::clone(&acquired);
            thread::spawn(move || {
                for _ in 0..50 {
                    if bucket.try_acquire(0.0, 100.0, 0).is_some() {
                        acquired.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .take(8)
        .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            acquired.load(Ordering::Relaxed),
            100,
            "exactly 100 tokens should be acquired from a burst-100 bucket at rate=0"
        );
    }

    #[test]
    fn concurrent_refill_never_duplicates_a_capped_token() {
        const CALLERS: usize = 8;
        const ROUNDS: usize = 64;

        for round in 0..ROUNDS {
            let bucket = Arc::new(TokenBucket::new(1.0));
            assert!(
                bucket.try_acquire(1.0, 1.0, 0).is_some(),
                "round {round}: initial burst token should be available"
            );
            let ready = Arc::new(Barrier::new(CALLERS));
            let acquired = count_concurrent_acquisitions(&bucket, &ready, CALLERS);
            assert_eq!(
                acquired, 1,
                "round {round}: a burst-1 bucket should admit exactly its one accrued token"
            );
        }
    }

    fn count_concurrent_acquisitions(bucket: &Arc<TokenBucket>, ready: &Arc<Barrier>, callers: usize) -> usize {
        let handles: Vec<_> = std::iter::repeat_with(|| {
            let bucket = Arc::clone(bucket);
            let ready = Arc::clone(ready);
            thread::spawn(move || {
                ready.wait();
                bucket.try_acquire(1.0, 1.0, 1_000_000_000).is_some()
            })
        })
        .take(callers)
        .collect();

        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum()
    }

    #[test]
    fn tokens_capped_at_burst() {
        let bucket = TokenBucket::new(5.0);
        let remaining = bucket.try_acquire(1000.0, 5.0, 1_000_000_000);
        assert!(
            remaining.is_some_and(|r| r <= 5.0),
            "tokens after refill should not exceed burst, got {remaining:?}"
        );
    }

    #[test]
    fn nanos_to_secs_precision_at_104_days() {
        let nanos_104_days: u64 = 104 * 24 * 3600 * 1_000_000_000;
        let secs = nanos_to_secs(nanos_104_days);
        let expected = 104.0 * 24.0 * 3600.0;
        assert!(
            (secs - expected).abs() < 1e-6,
            "nanos_to_secs should be precise at 104 days: got {secs}, expected {expected}"
        );
    }

    #[test]
    fn nanos_to_secs_precision_with_fractional_part() {
        let nanos: u64 = 104 * 24 * 3600 * 1_000_000_000 + 500_000_000;
        let secs = nanos_to_secs(nanos);
        let expected = 104.0 * 24.0 * 3600.0 + 0.5;
        assert!(
            (secs - expected).abs() < 1e-6,
            "nanos_to_secs should preserve sub-second precision: got {secs}, expected {expected}"
        );
    }

    #[test]
    fn refill_precise_after_104_days() {
        let bucket = TokenBucket::new(0.0);
        let nanos_104_days: u64 = 104 * 24 * 3600 * 1_000_000_000;
        let result = bucket.try_acquire(1.0, 100.0, nanos_104_days);
        assert!(
            result.is_some(),
            "bucket should refill correctly after 104 days of uptime"
        );
    }

    #[test]
    fn zero_elapsed_no_refill() {
        let bucket = TokenBucket::new(2.0);
        bucket.try_acquire(100.0, 2.0, 0);
        bucket.try_acquire(100.0, 2.0, 0);
        assert!(
            bucket.try_acquire(100.0, 2.0, 0).is_none(),
            "zero elapsed time should not refill tokens"
        );
    }
}
