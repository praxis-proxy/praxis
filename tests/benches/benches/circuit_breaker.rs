// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

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
    clippy::missing_assert_message,
    clippy::disallowed_methods,
    clippy::drop_non_drop,
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
            assert!(matches!(check, CircuitCheck::Allowed(_)));
        });
    });
}

/// Benchmark token acquisition when the circuit is open (fast reject).
fn bench_acquire_open(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: 1,
        recovery_window: Duration::from_millis(10_000),
        half_open_timeout: Duration::from_millis(5_000),
    });

    // Trigger circuit open by recording a failure
    if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
        breaker.record_failure(token);
    }

    c.bench_function("circuit_breaker/acquire_open", |b| {
        b.iter(|| {
            let check = black_box(breaker.try_acquire());
            assert!(matches!(check, CircuitCheck::Rejected));
        });
    });
}

/// Benchmark token acquisition when the circuit is half-open (probe token).
fn bench_acquire_half_open(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(CircuitBreakerConfig {
        threshold: 1,
        recovery_window: Duration::from_millis(0), // Immediate recovery for benchmark
        half_open_timeout: Duration::from_millis(5_000),
    });

    // Trigger circuit open then wait for recovery window
    if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
        breaker.record_failure(token);
    }
    thread::sleep(Duration::from_millis(10));

    c.bench_function("circuit_breaker/acquire_half_open", |b| {
        b.iter(|| {
            let check = black_box(breaker.try_acquire());
            // Half-open allows one probe, then rejects
            drop(check);
        });
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
        b.iter(|| {
            if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
                black_box(breaker.record_success(token));
            }
        });
    });
}

/// Benchmark recording a failed request.
fn bench_record_failure(c: &mut Criterion) {
    c.bench_function("circuit_breaker/record_failure", |b| {
        // Create a new breaker per iteration to avoid state accumulation
        b.iter_batched(
            || {
                CircuitBreaker::new(CircuitBreakerConfig {
                    threshold: 100,
                    recovery_window: Duration::from_millis(10_000),
                    half_open_timeout: Duration::from_millis(5_000),
                })
            },
            |breaker| {
                if let CircuitCheck::Allowed(token) = breaker.try_acquire() {
                    black_box(breaker.record_failure(token));
                }
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
            recovery_window: Duration::from_millis(1_000_000), // Very long window to keep it open
            half_open_timeout: Duration::from_millis(5_000),
        }));

        // Trigger circuit open
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
