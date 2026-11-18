// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this dedicated integration target contains only count-contract tests"
)]

//! Untimed count and outcome checks for the concurrent circuit breaker fixture.

use std::{thread, time::Duration};

use praxis_core::circuit::{CircuitBreaker, CircuitBreakerConfig, CircuitCheck, CircuitState};

#[path = "../benches/circuit_workload.rs"]
mod circuit_workload;

use circuit_workload::{WorkCounts, run_closed, run_open, worker_iterations};

/// Build the same closed or tripped breaker used by the benchmark workload.
#[expect(clippy::panic, reason = "an invalid test fixture must fail immediately")]
fn breaker(open: bool) -> CircuitBreaker {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: if open { 1 } else { 1_000_000 },
        recovery_window: if open {
            Duration::from_secs(86_400) // 24 hours
        } else {
            Duration::from_millis(10_000)
        },
        half_open_timeout: Duration::from_millis(5_000),
    });
    if open {
        match breaker.try_acquire() {
            CircuitCheck::Allowed(token) => breaker.record_failure(token),
            CircuitCheck::Rejected => panic!("a fresh breaker must allow the trip request"),
        }
        assert_eq!(
            breaker.state(),
            CircuitState::Open,
            "trip request must open the fixture breaker"
        );
    }
    breaker
}

/// Run the shared worker helper concurrently, without a benchmark timer.
#[expect(clippy::expect_used, reason = "a worker panic must fail the test")]
fn run_workers(iterations: u64, workers: usize, open: bool) -> (WorkCounts, CircuitState) {
    let breaker = breaker(open);
    let counts = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let assigned = worker_iterations(iterations, workers, worker);
                let breaker = &breaker;
                scope.spawn(move || {
                    if open {
                        run_open(breaker, assigned)
                    } else {
                        run_closed(breaker, assigned)
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("contention worker panicked"))
            .fold(WorkCounts::default(), WorkCounts::combine)
    });
    (counts, breaker.state())
}

/// Quotient and remainder partitioning must preserve every requested attempt.
#[test]
fn contention_partition_preserves_iterations() {
    for iterations in [0, 1, 7, 8, 9, 17] {
        for workers in [1, 2, 4, 8] {
            let assigned: Vec<_> = (0..workers)
                .map(|worker| worker_iterations(iterations, workers, worker))
                .collect();
            let total: u64 = assigned.iter().sum();
            assert_eq!(total, iterations, "iterations={iterations}, workers={workers}");
            let smallest = assigned.iter().min().copied().unwrap_or(0);
            let largest = assigned.iter().max().copied().unwrap_or(0);
            assert!(
                largest.saturating_sub(smallest) <= 1,
                "worker assignments must differ by at most one: iterations={iterations}, workers={workers}"
            );
        }
    }
}

/// Closed workers must allow and complete every assigned acquisition.
#[test]
fn closed_workload_executes_requested_acquisitions() {
    for iterations in [1, 9, 17] {
        for workers in [2, 8] {
            let (counts, state) = run_workers(iterations, workers, false);
            assert_eq!(
                counts,
                WorkCounts {
                    attempted: iterations,
                    allowed: iterations,
                    rejected: 0,
                    completed: iterations,
                },
                "iterations={iterations}, workers={workers}"
            );
            assert_eq!(
                state,
                CircuitState::Closed,
                "closed workload must leave the breaker closed"
            );
        }
    }
}

/// Open workers must reject every assigned acquisition after fixture setup.
#[test]
fn open_workload_executes_requested_rejections() {
    for iterations in [1, 9, 17] {
        for workers in [2, 8] {
            let (counts, state) = run_workers(iterations, workers, true);
            assert_eq!(
                counts,
                WorkCounts {
                    attempted: iterations,
                    allowed: 0,
                    rejected: iterations,
                    completed: 0,
                },
                "iterations={iterations}, workers={workers}"
            );
            assert_eq!(
                state,
                CircuitState::Open,
                "open workload must leave the breaker tripped"
            );
        }
    }
}
