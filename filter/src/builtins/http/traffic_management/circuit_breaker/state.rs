// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Per-cluster circuit breaker state machine.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

// -----------------------------------------------------------------------------
// CircuitState
// -----------------------------------------------------------------------------

/// The three states of a circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CircuitState {
    /// Requests pass through; failures are counted.
    Closed,

    /// Requests are rejected; waiting for recovery window.
    Open,

    /// One probe request is allowed through.
    HalfOpen,
}

// -----------------------------------------------------------------------------
// CircuitBreaker
// -----------------------------------------------------------------------------

/// Per-cluster circuit breaker state.
///
/// Thread-safe via internal [`Mutex`]. The critical section
/// is small (a few field reads/writes), so contention is
/// negligible at proxy scale.
#[derive(Debug)]
pub(super) struct CircuitBreaker {
    /// Mutex-protected mutable state.
    inner: Mutex<CircuitInner>,

    /// How long to stay Open before trying Half-Open.
    recovery_window: Duration,

    /// Consecutive failure threshold to trip.
    threshold: u32,
}

/// Mutable interior state.
#[derive(Debug)]
struct CircuitInner {
    /// Consecutive failure count (only meaningful in Closed).
    consecutive_failures: u32,

    /// When the circuit transitioned to Open.
    opened_at: Option<Instant>,

    /// Current state of the circuit.
    state: CircuitState,
}

impl CircuitBreaker {
    /// Create a new circuit breaker starting in Closed.
    pub(super) fn new(threshold: u32, recovery_window_secs: u64) -> Self {
        Self {
            inner: Mutex::new(CircuitInner {
                consecutive_failures: 0,
                opened_at: None,
                state: CircuitState::Closed,
            }),
            recovery_window: Duration::from_secs(recovery_window_secs),
            threshold,
        }
    }

    /// Check whether a request should be allowed through.
    ///
    /// Returns the current state after any time-based
    /// transitions. In Half-Open, the first caller gets
    /// `HalfOpen` (probe allowed); subsequent callers
    /// still see `Open` until the probe completes.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub(super) fn check(&self) -> CircuitState {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        match inner.state {
            CircuitState::Closed => CircuitState::Closed,
            CircuitState::Open => {
                if let Some(opened_at) = inner.opened_at
                    && opened_at.elapsed() >= self.recovery_window
                {
                    inner.state = CircuitState::HalfOpen;
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Open
                }
            },
            CircuitState::HalfOpen => CircuitState::HalfOpen,
        }
    }

    /// Record a failed upstream response.
    ///
    /// - Closed: increments failure counter; trips to Open at threshold.
    /// - Half-Open: transitions back to Open.
    /// - Open: no-op.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub(super) fn record_failure(&self) {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                if inner.consecutive_failures >= self.threshold {
                    inner.state = CircuitState::Open;
                    inner.opened_at = Some(Instant::now());
                }
            },
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.opened_at = Some(Instant::now());
            },
            CircuitState::Open => {},
        }
    }

    /// Record a successful upstream response.
    ///
    /// - Closed: resets failure counter.
    /// - Half-Open: transitions to Closed.
    /// - Open: no-op (should not happen; probe not sent).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub(super) fn record_success(&self) {
        let mut inner = self.inner.lock().expect("circuit breaker lock poisoned");
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = 0;
            },
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Closed;
                inner.consecutive_failures = 0;
                inner.opened_at = None;
            },
            CircuitState::Open => {},
        }
    }

    /// Returns the current state without side effects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[cfg(test)]
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub(super) fn state(&self) -> CircuitState {
        self.inner.lock().expect("circuit breaker lock poisoned").state
    }
}
