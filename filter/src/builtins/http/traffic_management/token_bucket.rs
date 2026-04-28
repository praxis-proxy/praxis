// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Lock-free token bucket for rate limiting.

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

// -----------------------------------------------------------------------------
// TokenBucket
// -----------------------------------------------------------------------------

/// Token bucket for lock-free rate limiting.
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
    /// Current tokens stored as `f64::to_bits`.
    tokens: AtomicU64,

    /// Last refill timestamp in nanoseconds since epoch.
    last_refill: AtomicU64,
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
            tokens: AtomicU64::new(burst.to_bits()),
            last_refill: AtomicU64::new(0),
        }
    }

    /// Try to consume one token, refilling based on elapsed time.
    ///
    /// Returns `Some(remaining)` on success, `None` when the bucket
    /// is empty.
    ///
    /// # Precision
    ///
    /// There is a brief over-issue window between the `tokens` CAS
    /// and the `last_refill` update under contention. This is a
    /// known limitation of the lock-free design. Rate limiting is
    /// approximate by nature, and the burst cap bounds the impact.
    pub(crate) fn try_acquire(&self, rate: f64, burst: f64, now_nanos: u64) -> Option<f64> {
        loop {
            let old_tokens_bits = self.tokens.load(Ordering::Acquire);
            let old_refill = self.last_refill.load(Ordering::Acquire);

            let mut tokens = f64::from_bits(old_tokens_bits);

            let elapsed_nanos = now_nanos.saturating_sub(old_refill);
            if elapsed_nanos > 0 {
                let elapsed_secs = nanos_to_secs(elapsed_nanos);
                tokens = (tokens + elapsed_secs * rate).min(burst);
            }

            if tokens < 1.0 {
                return None;
            }

            let new_tokens = tokens - 1.0;
            let new_bits = new_tokens.to_bits();

            if self
                .tokens
                .compare_exchange_weak(old_tokens_bits, new_bits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.last_refill.fetch_max(now_nanos, Ordering::Release);
                return Some(new_tokens);
            }
        }
    }

    /// Read the last refill timestamp in nanoseconds.
    pub(crate) fn last_refill_nanos(&self) -> u64 {
        self.last_refill.load(Ordering::Acquire)
    }

    /// Read current token count without modification.
    pub(crate) fn current_tokens(&self, rate: f64, burst: f64, now_nanos: u64) -> f64 {
        let tokens = f64::from_bits(self.tokens.load(Ordering::Acquire));
        let last = self.last_refill.load(Ordering::Acquire);
        let elapsed_secs = nanos_to_secs(now_nanos.saturating_sub(last));
        (tokens + elapsed_secs * rate).min(burst)
    }
}

impl fmt::Debug for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenBucket")
            .field("tokens", &f64::from_bits(self.tokens.load(Ordering::Relaxed)))
            .field("last_refill", &self.last_refill.load(Ordering::Relaxed))
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
#[allow(
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
            sync::{Arc, atomic::AtomicUsize},
            thread,
        };

        let bucket = Arc::new(TokenBucket::new(100.0));
        let acquired = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
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
