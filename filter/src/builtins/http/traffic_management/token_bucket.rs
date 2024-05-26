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
    pub(crate) fn try_acquire(&self, rate: f64, burst: f64, now_nanos: u64) -> Option<f64> {
        loop {
            let old_tokens_bits = self.tokens.load(Ordering::Acquire);
            let old_refill = self.last_refill.load(Ordering::Acquire);

            let mut tokens = f64::from_bits(old_tokens_bits);

            let elapsed_nanos = now_nanos.saturating_sub(old_refill);
            if elapsed_nanos > 0 {
                let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;
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
                self.last_refill.store(now_nanos, Ordering::Release);
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
        let elapsed_secs = now_nanos.saturating_sub(last) as f64 / 1_000_000_000.0;
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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
    fn current_tokens_readonly() {
        let bucket = TokenBucket::new(5.0);
        bucket.try_acquire(10.0, 5.0, 0);
        let current = bucket.current_tokens(10.0, 5.0, 0);
        assert!(
            (current - 4.0).abs() < 0.01,
            "current_tokens should reflect remaining after one acquisition, got {current}"
        );
    }
}
