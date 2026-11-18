// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared, untimed circuit breaker contention workload and count accounting.

use praxis_core::circuit::{CircuitBreaker, CircuitCheck};

/// Counts returned by one worker after its assigned acquisitions finish.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WorkCounts {
    /// Acquisition attempts, including rejections.
    pub(crate) attempted: u64,
    /// Acquisitions that issued a token.
    pub(crate) allowed: u64,
    /// Acquisitions rejected by the breaker.
    pub(crate) rejected: u64,
    /// Issued tokens with a recorded outcome.
    pub(crate) completed: u64,
}

impl WorkCounts {
    /// Combine thread-local counts after workers have joined.
    pub(crate) fn combine(self, other: Self) -> Self {
        Self {
            attempted: self.attempted.saturating_add(other.attempted),
            allowed: self.allowed.saturating_add(other.allowed),
            rejected: self.rejected.saturating_add(other.rejected),
            completed: self.completed.saturating_add(other.completed),
        }
    }
}

/// Assign every requested iteration to one worker, distributing the remainder.
///
/// # Panics
///
/// Panics if there are no workers or `worker` is outside their range.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "positive worker count bounds the quotient and remainder"
)]
pub(crate) fn worker_iterations(iterations: u64, workers: usize, worker: usize) -> u64 {
    assert!(workers > 0, "contention requires at least one worker");
    assert!(worker < workers, "worker index must be in range");
    let worker_count = u64::try_from(workers).unwrap_or(u64::MAX);
    let worker_index = u64::try_from(worker).unwrap_or(u64::MAX);
    iterations / worker_count + u64::from(worker_index < iterations % worker_count)
}

/// Execute the closed-breaker workload and record every admitted success.
pub(crate) fn run_closed(breaker: &CircuitBreaker, iterations: u64) -> WorkCounts {
    let mut counts = WorkCounts::default();
    for _ in 0..iterations {
        counts.attempted = counts.attempted.saturating_add(1);
        match breaker.try_acquire() {
            CircuitCheck::Allowed(token) => {
                counts.allowed = counts.allowed.saturating_add(1);
                breaker.record_success(token);
                counts.completed = counts.completed.saturating_add(1);
            },
            CircuitCheck::Rejected => counts.rejected = counts.rejected.saturating_add(1),
        }
    }
    counts
}

/// Execute the tripped-breaker workload, retaining unexpected admissions.
pub(crate) fn run_open(breaker: &CircuitBreaker, iterations: u64) -> WorkCounts {
    let mut counts = WorkCounts::default();
    for _ in 0..iterations {
        counts.attempted = counts.attempted.saturating_add(1);
        match breaker.try_acquire() {
            CircuitCheck::Allowed(token) => {
                counts.allowed = counts.allowed.saturating_add(1);
                breaker.record_failure(token);
                counts.completed = counts.completed.saturating_add(1);
            },
            CircuitCheck::Rejected => counts.rejected = counts.rejected.saturating_add(1),
        }
    }
    counts
}
