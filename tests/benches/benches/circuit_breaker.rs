// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for circuit breaker state machine operations.
//!
//! Covers token acquisition in different states (closed/open/half-open),
//! state transitions, success/failure recording, and concurrent access
//! patterns with varying thread counts.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::min_ident_chars,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::panic,
    clippy::unit_arg,
    clippy::map_with_unused_argument_over_ranges,
    reason = "benchmarks"
)]

use std::{
    hint::black_box,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use praxis_core::circuit::{CircuitBreaker, CircuitBreakerConfig, CircuitCheck};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// A recovery window that keeps a tripped breaker open however long criterion
/// runs.
const HOLD_OPEN_WINDOW: Duration = Duration::from_secs(86_400); // 24 hours

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_acquire_closed,
    bench_acquire_open,
    bench_acquire_half_open,
    bench_record_success,
    bench_record_failure,
    bench_concurrent_access
);
criterion_main!(benches);

/// Benchmark token acquisition when the circuit is closed (always succeeds).
fn bench_acquire_closed(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: 5,
        recovery_window: Duration::from_millis(10_000),
        half_open_timeout: Duration::from_millis(5_000),
    });

    c.bench_function("circuit_breaker/acquire_closed", |b| {
        b.iter(|| {
            let check = black_box(breaker.try_acquire());
            assert!(
                matches!(check, CircuitCheck::Allowed(_)),
                "a closed breaker must allow every request, or this measures the wrong path"
            );
        });
    });
}

/// Benchmark token acquisition when the circuit is open (fast reject).
fn bench_acquire_open(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: 1,
        recovery_window: HOLD_OPEN_WINDOW,
        half_open_timeout: Duration::from_millis(5_000),
    });

    if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
        breaker.record_failure(token);
    }

    c.bench_function("circuit_breaker/acquire_open", |b| {
        b.iter(|| {
            let check = black_box(breaker.try_acquire());
            assert!(
                matches!(check, CircuitCheck::Rejected),
                "a tripped breaker must stay open for the whole run, or this measures the wrong path"
            );
        });
    });
}

/// Benchmark the open-to-half-open transition that issues a probe token.
fn bench_acquire_half_open(c: &mut Criterion) {
    c.bench_function("circuit_breaker/acquire_half_open", |b| {
        // A fresh tripped breaker per iteration: once a probe is out, later
        // acquisitions are rejected until the probe resolves.
        b.iter_batched(
            || {
                let breaker = CircuitBreaker::new(CircuitBreakerConfig {
                    threshold: 1,
                    recovery_window: Duration::ZERO,
                    half_open_timeout: Duration::from_millis(5_000),
                });
                if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
                    breaker.record_failure(token);
                }
                breaker
            },
            |breaker| {
                let check = black_box(breaker.try_acquire());
                assert!(
                    matches!(check, CircuitCheck::Allowed(_)),
                    "a tripped breaker past its recovery window must issue a probe token"
                );
                (breaker, check)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Benchmark recording a successful request.
fn bench_record_success(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: 100,
        recovery_window: Duration::from_millis(10_000),
        half_open_timeout: Duration::from_millis(5_000),
    });

    c.bench_function("circuit_breaker/record_success", |b| {
        b.iter_batched(
            || breaker.try_acquire(),
            |check| {
                let CircuitCheck::Allowed(token) = check else {
                    panic!("a closed breaker must issue a token");
                };
                black_box(breaker.record_success(token));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Benchmark recording a failed request.
fn bench_record_failure(c: &mut Criterion) {
    c.bench_function("circuit_breaker/record_failure", |b| {
        // A new breaker per iteration keeps failures from tripping it.
        b.iter_batched(
            || {
                let breaker = CircuitBreaker::new(CircuitBreakerConfig {
                    threshold: 100,
                    recovery_window: Duration::from_millis(10_000),
                    half_open_timeout: Duration::from_millis(5_000),
                });
                let CircuitCheck::Allowed(token) = breaker.try_acquire() else {
                    panic!("a closed breaker must issue a token");
                };
                (breaker, token)
            },
            |(breaker, token)| {
                black_box(breaker.record_failure(token));
                breaker
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Benchmark concurrent access to a shared circuit breaker.
fn bench_concurrent_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_breaker/concurrent");

    for threads in [1, 2, 4, 8] {
        group.bench_function(BenchmarkId::new("closed", threads), |b| {
            bench_concurrent_closed(b, threads);
        });

        group.bench_function(BenchmarkId::new("open", threads), |b| {
            bench_concurrent_open(b, threads);
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// Concurrent Benchmark Helpers
// -----------------------------------------------------------------------------

/// Benchmark concurrent acquisition when the circuit is closed.
fn bench_concurrent_closed(b: &mut criterion::Bencher<'_>, thread_count: usize) {
    b.iter_custom(|iterations| {
        let breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            threshold: 1_000_000,
            recovery_window: Duration::from_millis(10_000),
            half_open_timeout: Duration::from_millis(5_000),
        }));
        let ready = Arc::new(Barrier::new(thread_count + 1));
        let go = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicUsize::new(0));

        thread::scope(|scope| {
            let handles: Vec<_> = (0..thread_count)
                .map(|_| {
                    let breaker = Arc::clone(&breaker);
                    let ready = Arc::clone(&ready);
                    let go = Arc::clone(&go);
                    let finished = Arc::clone(&finished);
                    let count = iterations / u64::try_from(thread_count).unwrap();

                    scope.spawn(move || {
                        ready.wait();
                        while !go.load(Ordering::Acquire) {
                            std::hint::spin_loop();
                        }

                        for _ in 0..count {
                            if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
                                breaker.record_success(token);
                            }
                        }
                        finished.fetch_add(1, Ordering::Release);
                    })
                })
                .collect();

            ready.wait();
            let start = Instant::now();
            go.store(true, Ordering::Release);

            while finished.load(Ordering::Acquire) != thread_count {
                std::hint::spin_loop();
            }
            let elapsed = start.elapsed();

            for handle in handles {
                handle.join().unwrap();
            }

            elapsed
        })
    });
}

/// Benchmark concurrent acquisition when the circuit is open (fast reject path).
fn bench_concurrent_open(b: &mut criterion::Bencher<'_>, thread_count: usize) {
    b.iter_custom(|iterations| {
        let breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            threshold: 1,
            recovery_window: HOLD_OPEN_WINDOW,
            half_open_timeout: Duration::from_millis(5_000),
        }));

        if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
            breaker.record_failure(token);
        }

        let ready = Arc::new(Barrier::new(thread_count + 1));
        let go = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicUsize::new(0));

        thread::scope(|scope| {
            let handles: Vec<_> = (0..thread_count)
                .map(|_| {
                    let breaker = Arc::clone(&breaker);
                    let ready = Arc::clone(&ready);
                    let go = Arc::clone(&go);
                    let finished = Arc::clone(&finished);
                    let count = iterations / u64::try_from(thread_count).unwrap();

                    scope.spawn(move || {
                        ready.wait();
                        while !go.load(Ordering::Acquire) {
                            std::hint::spin_loop();
                        }

                        for _ in 0..count {
                            let _ = breaker.try_acquire();
                        }
                        finished.fetch_add(1, Ordering::Release);
                    })
                })
                .collect();

            ready.wait();
            let start = Instant::now();
            go.store(true, Ordering::Release);

            while finished.load(Ordering::Acquire) != thread_count {
                std::hint::spin_loop();
            }
            let elapsed = start.elapsed();

            for handle in handles {
                handle.join().unwrap();
            }

            elapsed
        })
    });
}
