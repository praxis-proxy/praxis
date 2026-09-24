// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![forbid(unsafe_code)]

//! Criterion benchmarks for token-bucket state-management alternatives.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::missing_docs_in_private_items,
    clippy::min_ident_chars,
    clippy::needless_for_each,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "benchmark setup and the included private implementation"
)]

// Include the private implementation directly so the benchmark does not make
// token-bucket internals part of the filter crate's public API.
#[expect(
    dead_code,
    reason = "the included implementation also contains non-benchmarked introspection and test utilities"
)]
#[path = "../../../crates/filter/src/builtins/http/traffic_management/token_bucket.rs"]
mod production_token_bucket;

use std::{
    hint::black_box,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Instant,
};

use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime};
use governor::{Quota, RateLimiter, clock::Clock, middleware::NoOpMiddleware, nanos::Nanos};
use portable_atomic::AtomicU128;

// ----------------------------------------------------------------------------
// Benchmark Configuration
// ----------------------------------------------------------------------------

/// Fixed rate used by the comparable candidates.
const RATE: f64 = 10_000.0;

/// Fixed burst used to keep success benchmarks away from depletion.
const BURST: f64 = 1_000_000_000.0;

/// Exact interval for [`RATE`] in nanoseconds.
const INTERVAL_NANOS: u64 = 100_000;

/// Number of tokens in [`BURST`] as an integer.
const BURST_TOKENS: u64 = 1_000_000_000;

const _: () = assert!(
    BURST_TOKENS <= u32::MAX as u64,
    "BURST_TOKENS must fit in governor's u32 burst API"
);

/// Keep the rejection clock's wrap no longer than one token refill interval.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "RATE is a positive benchmark constant; zero is clamped to one nanosecond below"
)]
const REJECTION_CLOCK_MODULUS_NANOS: u64 = {
    let rate_interval_nanos = (1_000_000_000.0 / RATE) as u64;
    if rate_interval_nanos == 0 {
        1
    } else if rate_interval_nanos < INTERVAL_NANOS {
        rate_interval_nanos
    } else {
        INTERVAL_NANOS
    }
};

// ----------------------------------------------------------------------------
// Benchmark Candidates
// ----------------------------------------------------------------------------

/// Common operation surface for the benchmark candidates.
trait Candidate: Send + Sync + 'static {
    /// Construct a full bucket for successful-acquisition benchmarks.
    fn full() -> Self
    where
        Self: Sized;

    /// Construct a bucket with no available tokens for rejection benchmarks.
    fn empty() -> Self
    where
        Self: Sized;

    /// Construct a one-token bucket for contention benchmarks.
    fn single() -> Self
    where
        Self: Sized;

    /// Attempt one acquisition at the supplied monotonic timestamp.
    fn acquire(&self, now_nanos: u64) -> Option<f64>;
}

/// Call a candidate through an opaque boundary so benchmark-local state is
/// not constant-folded away by the optimizer.
#[inline(never)]
fn acquire_candidate(candidate: &dyn Candidate, now_nanos: u64) -> Option<f64> {
    candidate.acquire(now_nanos)
}

/// The mutex-protected compound state from the PR under test.
struct MutexCandidate {
    bucket: production_token_bucket::TokenBucket,
    rate: f64,
    burst: f64,
}

impl Candidate for MutexCandidate {
    fn full() -> Self {
        Self::with_burst(BURST)
    }

    fn empty() -> Self {
        let candidate = Self::single();
        let _ = candidate.acquire(0);
        candidate
    }

    fn single() -> Self {
        Self::with_burst(1.0)
    }

    fn acquire(&self, now_nanos: u64) -> Option<f64> {
        self.bucket.try_acquire(self.rate, self.burst, now_nanos)
    }
}

impl MutexCandidate {
    /// Construct a mutex candidate with a selected initial burst.
    fn with_burst(burst: f64) -> Self {
        Self {
            bucket: production_token_bucket::TokenBucket::new(burst),
            rate: RATE,
            burst,
        }
    }
}

/// A correctness-preserving split-field implementation guarded by an atomic
/// spin lock. This measures the cost of making the two fields one logical
/// transition without requiring a 128-bit atomic.
struct LockedSplitAtomicsCandidate {
    tokens: AtomicU64,
    last_refill: AtomicU64,
    lock: AtomicBool,
    rate: f64,
    burst: f64,
}

impl Candidate for LockedSplitAtomicsCandidate {
    fn full() -> Self {
        Self::with_burst(BURST)
    }

    fn empty() -> Self {
        let candidate = Self::single();
        let _ = candidate.acquire(0);
        candidate
    }

    fn single() -> Self {
        Self::with_burst(1.0)
    }

    fn acquire(&self, now_nanos: u64) -> Option<f64> {
        self.lock();

        let tokens = f64::from_bits(self.tokens.load(Ordering::Relaxed));
        let last_refill = self.last_refill.load(Ordering::Relaxed);
        let elapsed_nanos = now_nanos.saturating_sub(last_refill);
        let tokens = if elapsed_nanos > 0 {
            (tokens + production_token_bucket::nanos_to_secs(elapsed_nanos) * self.rate).min(self.burst)
        } else {
            tokens
        };

        let result = if tokens < 1.0 {
            None
        } else {
            let remaining = tokens - 1.0;
            self.tokens.store(remaining.to_bits(), Ordering::Relaxed);
            self.last_refill.store(last_refill.max(now_nanos), Ordering::Relaxed);
            Some(remaining)
        };

        self.unlock();
        result
    }
}

impl LockedSplitAtomicsCandidate {
    /// Construct a split-field candidate with serialized compound updates.
    fn with_burst(burst: f64) -> Self {
        Self {
            tokens: AtomicU64::new(burst.to_bits()),
            last_refill: AtomicU64::new(0),
            lock: AtomicBool::new(false),
            rate: RATE,
            burst,
        }
    }

    fn lock(&self) {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

/// A packed compound state updated with one compare-and-exchange operation.
///
/// The low 64 bits contain the exact `f64` token bits and the high 64 bits
/// contain the refill timestamp. This preserves the production state model
/// while making refill, admission, decrement, and timestamp advancement one
/// atomic transition. `portable-atomic` supplies a target-dependent native or
/// fallback implementation, so benchmark results must record that choice.
struct Packed128CasCandidate {
    /// Packed token bits and refill timestamp.
    state: AtomicU128,
    /// Tokens refilled per second.
    rate: f64,
    /// Maximum token count.
    burst: f64,
}

impl Candidate for Packed128CasCandidate {
    fn full() -> Self {
        Self::with_burst(BURST)
    }

    fn empty() -> Self {
        let candidate = Self::single();
        let _ = candidate.acquire(0);
        candidate
    }

    fn single() -> Self {
        Self::with_burst(1.0)
    }

    fn acquire(&self, now_nanos: u64) -> Option<f64> {
        loop {
            let old_state = self.state.load(Ordering::Acquire);
            let (tokens, last_refill) = unpack_state(old_state);
            let elapsed_nanos = now_nanos.saturating_sub(last_refill);
            let tokens = if elapsed_nanos > 0 {
                (tokens + production_token_bucket::nanos_to_secs(elapsed_nanos) * self.rate).min(self.burst)
            } else {
                tokens
            };

            if tokens < 1.0 {
                return None;
            }

            let remaining = tokens - 1.0;
            let next_state = pack_state(remaining, last_refill.max(now_nanos));
            if self
                .state
                .compare_exchange_weak(old_state, next_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(remaining);
            }
        }
    }
}

impl Packed128CasCandidate {
    /// Construct a packed-state candidate with a selected initial burst.
    fn with_burst(burst: f64) -> Self {
        Self {
            state: AtomicU128::new(pack_state(burst, 0)),
            rate: RATE,
            burst,
        }
    }
}

/// An absolute monotonic clock for deterministic governor measurements.
#[derive(Clone)]
struct BenchmarkClock {
    now_nanos: Arc<AtomicU64>,
}

impl Clock for BenchmarkClock {
    type Instant = Nanos;

    fn now(&self) -> Self::Instant {
        Nanos::new(self.now_nanos.load(Ordering::Acquire))
    }
}

/// The direct in-memory `governor` implementation using its GCRA state store.
///
/// This candidate exercises the actual library API and implementation. Governor
/// has no equivalent token-count introspection operation, so it is intentionally
/// absent from that workload.
struct GovernorCandidate {
    limiter:
        RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, BenchmarkClock, NoOpMiddleware<Nanos>>,
    clock: BenchmarkClock,
}

impl Candidate for GovernorCandidate {
    fn full() -> Self {
        Self::with_burst(BURST_TOKENS)
    }

    fn empty() -> Self {
        let candidate = Self::single();
        let _ = candidate.acquire(0);
        candidate
    }

    fn single() -> Self {
        Self::with_burst(1)
    }

    fn acquire(&self, now_nanos: u64) -> Option<f64> {
        self.advance_clock_to(now_nanos);
        self.limiter.check().ok().map(|_| 1.0)
    }
}

impl GovernorCandidate {
    /// Construct a governor limiter with the same rate and burst as the other candidates.
    fn with_burst(burst_tokens: u64) -> Self {
        let clock = BenchmarkClock {
            now_nanos: Arc::new(AtomicU64::new(0)),
        };
        let limiter = RateLimiter::direct_with_clock(
            Quota::with_period(std::time::Duration::from_nanos(INTERVAL_NANOS))
                .unwrap()
                .allow_burst(std::num::NonZeroU32::new(u32::try_from(burst_tokens).unwrap()).unwrap()),
            clock.clone(),
        );
        Self { limiter, clock }
    }

    fn advance_clock_to(&self, now_nanos: u64) {
        let mut previous = self.clock.now_nanos.load(Ordering::Acquire);
        while now_nanos > previous {
            match self
                .clock
                .now_nanos
                .compare_exchange_weak(previous, now_nanos, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(observed) => previous = observed,
            }
        }
    }
}

/// Candidates that retain the existing read-only introspection operation.
trait InspectableCandidate: Candidate {
    /// Return the current token count at the supplied timestamp.
    fn current(&self, now_nanos: u64) -> f64;
}

/// Call the introspection operation through the same opaque boundary.
#[inline(never)]
fn current_candidate(candidate: &dyn InspectableCandidate, now_nanos: u64) -> f64 {
    candidate.current(now_nanos)
}

impl InspectableCandidate for MutexCandidate {
    fn current(&self, now_nanos: u64) -> f64 {
        self.bucket.current_tokens(self.rate, self.burst, now_nanos)
    }
}

impl InspectableCandidate for LockedSplitAtomicsCandidate {
    fn current(&self, now_nanos: u64) -> f64 {
        self.lock();
        let tokens = f64::from_bits(self.tokens.load(Ordering::Relaxed));
        let last_refill = self.last_refill.load(Ordering::Relaxed);
        let current = (tokens
            + production_token_bucket::nanos_to_secs(now_nanos.saturating_sub(last_refill)) * self.rate)
            .min(self.burst);
        self.unlock();
        current
    }
}

impl InspectableCandidate for Packed128CasCandidate {
    fn current(&self, now_nanos: u64) -> f64 {
        let state = self.state.load(Ordering::Acquire);
        let (tokens, last_refill) = unpack_state(state);
        (tokens + production_token_bucket::nanos_to_secs(now_nanos.saturating_sub(last_refill)) * self.rate)
            .min(self.burst)
    }
}

// ----------------------------------------------------------------------------
// Benchmarks
// ----------------------------------------------------------------------------

criterion_group!(benches, bench_token_bucket);
criterion_main!(benches);

/// Run sequential, contended, rejected, and introspection workloads.
fn bench_token_bucket(c: &mut Criterion) {
    validate_packed_candidate();

    let mut success = c.benchmark_group("token_bucket/acquire_success");
    bench_sequential::<MutexCandidate>(&mut success, "mutex", 0);
    bench_sequential::<LockedSplitAtomicsCandidate>(&mut success, "split_atomics_locked", 0);
    bench_sequential::<Packed128CasCandidate>(&mut success, "packed_128_cas", 0);
    bench_sequential::<GovernorCandidate>(&mut success, "governor", 0);
    bench_sequential::<MutexCandidate>(&mut success, "mutex_refill", INTERVAL_NANOS);
    bench_sequential::<LockedSplitAtomicsCandidate>(&mut success, "split_atomics_locked_refill", INTERVAL_NANOS);
    bench_sequential::<Packed128CasCandidate>(&mut success, "packed_128_cas_refill", INTERVAL_NANOS);
    bench_sequential::<GovernorCandidate>(&mut success, "governor_refill", INTERVAL_NANOS);
    success.finish();

    let mut rejection = c.benchmark_group("token_bucket/acquire_rejection");
    bench_rejection::<MutexCandidate>(&mut rejection, "mutex");
    bench_rejection::<LockedSplitAtomicsCandidate>(&mut rejection, "split_atomics_locked");
    bench_rejection::<Packed128CasCandidate>(&mut rejection, "packed_128_cas");
    bench_rejection::<GovernorCandidate>(&mut rejection, "governor");
    rejection.finish();

    let mut introspection = c.benchmark_group("token_bucket/introspection");
    bench_introspection::<MutexCandidate>(&mut introspection, "mutex");
    bench_introspection::<LockedSplitAtomicsCandidate>(&mut introspection, "split_atomics_locked");
    bench_introspection::<Packed128CasCandidate>(&mut introspection, "packed_128_cas");
    introspection.finish();

    for (group_name, rejected) in [("contention_success", false), ("contention_rejection", true)] {
        let mut contention = c.benchmark_group(format!("token_bucket/{group_name}"));
        for threads in [1, 2, 4, 8, 16] {
            bench_contention::<MutexCandidate>(&mut contention, "mutex", threads, rejected);
            bench_contention::<LockedSplitAtomicsCandidate>(&mut contention, "split_atomics_locked", threads, rejected);
            bench_contention::<Packed128CasCandidate>(&mut contention, "packed_128_cas", threads, rejected);
            bench_contention::<GovernorCandidate>(&mut contention, "governor", threads, rejected);
        }
        contention.finish();
    }
}

/// Verify the packed representation preserves fractional refill and failed-call semantics.
fn validate_packed_candidate() {
    let fractional_candidate = Packed128CasCandidate::single();
    assert!(
        fractional_candidate.acquire(0).is_some(),
        "fresh packed bucket should allow acquisition"
    );
    assert!(
        fractional_candidate.acquire(50_000).is_none(),
        "half a refilled token should not allow acquisition"
    );
    assert!(
        (fractional_candidate.current(50_000) - 0.5).abs() < f64::EPSILON,
        "failed acquisition should preserve the fractional refill"
    );
    assert!(
        fractional_candidate.acquire(100_000).is_some(),
        "one full interval should refill one token"
    );

    let monotonic_candidate = Packed128CasCandidate::with_burst(100.0);
    assert!(
        monotonic_candidate.acquire(200).is_some(),
        "timestamped packed acquisition should succeed"
    );
    assert_eq!(
        unpack_state(monotonic_candidate.state.load(Ordering::Acquire)).1,
        200,
        "successful acquisition should advance the refill timestamp"
    );
    assert!(
        monotonic_candidate.acquire(100).is_some(),
        "rollback timestamp should still allow acquisition"
    );
    assert_eq!(
        unpack_state(monotonic_candidate.state.load(Ordering::Acquire)).1,
        200,
        "rollback timestamp should not move the refill timestamp backwards"
    );
}

/// Benchmark sequential acquisitions, optionally advancing the clock per call.
fn bench_sequential<C: Candidate>(group: &mut BenchmarkGroup<'_, WallTime>, name: &str, now_step: u64) {
    group.bench_function(name, |b| {
        let candidate = C::full();
        let mut now_nanos = 0;
        b.iter(|| {
            let result = acquire_candidate(&candidate, black_box(now_nanos));
            now_nanos = now_nanos.saturating_add(now_step);
            black_box(result)
        });
    });
}

/// Benchmark the fast rejection path after the bucket is empty.
fn bench_rejection<C: Candidate>(group: &mut BenchmarkGroup<'_, WallTime>, name: &str) {
    group.bench_function(name, |b| {
        let candidate = C::empty();
        b.iter(|| black_box(acquire_candidate(&candidate, black_box(0))));
    });
}

/// Benchmark the current read-only token-count introspection operation.
fn bench_introspection<C: InspectableCandidate>(group: &mut BenchmarkGroup<'_, WallTime>, name: &str) {
    group.bench_function(name, |b| {
        let candidate = C::full();
        b.iter(|| black_box(current_candidate(&candidate, black_box(123_456_789))));
    });
}

/// Benchmark shared-bucket throughput at several thread counts.
fn bench_contention<C: Candidate>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    threads: usize,
    rejected: bool,
) {
    group.bench_function(BenchmarkId::new(name, threads), |b| {
        b.iter_custom(|iterations| {
            let candidate = Arc::new(if rejected { C::single() } else { C::full() });
            let ready = Arc::new(Barrier::new(threads + 1));
            let go = Arc::new(AtomicBool::new(false));
            let finished = Arc::new(AtomicUsize::new(0));
            let total_acquired = Arc::new(AtomicU64::new(0));
            let threads_u64 = u64::try_from(threads).unwrap();
            let remainder = usize::try_from(iterations % threads_u64).unwrap();

            thread::scope(|scope| {
                let handles: Vec<_> = (0..threads)
                    .map(|worker| {
                        let candidate = Arc::clone(&candidate);
                        let finished = Arc::clone(&finished);
                        let go = Arc::clone(&go);
                        let ready = Arc::clone(&ready);
                        let total_acquired = Arc::clone(&total_acquired);
                        let count = iterations / threads_u64 + u64::from(worker < remainder);
                        scope.spawn(move || {
                            ready.wait();
                            while !go.load(Ordering::Acquire) {
                                std::hint::spin_loop();
                            }

                            let candidate = candidate.as_ref();
                            let mut now_nanos = 0_u64;
                            let mut acquired = 0_u64;
                            for _ in 0..count {
                                now_nanos = now_nanos.saturating_add(1);
                                let now = if rejected {
                                    now_nanos % REJECTION_CLOCK_MODULUS_NANOS
                                } else {
                                    now_nanos
                                };
                                acquired += u64::from(acquire_candidate(candidate, black_box(now)).is_some());
                            }
                            total_acquired.fetch_add(acquired, Ordering::Relaxed);
                            finished.fetch_add(1, Ordering::Release);
                        })
                    })
                    .collect();

                ready.wait();
                let start = Instant::now();
                go.store(true, Ordering::Release);
                while finished.load(Ordering::Acquire) != threads {
                    std::hint::spin_loop();
                }
                let elapsed = start.elapsed();

                handles.into_iter().for_each(|handle| handle.join().unwrap());

                let actual_acquired = total_acquired.load(Ordering::Acquire);
                // Rejection cases start with one token to exercise the transition.
                let expected_acquired = if rejected { 1 } else { iterations };
                assert_eq!(
                    actual_acquired, expected_acquired,
                    "contention acquisition count mismatch; rejected mode requires the synthetic clock to wrap before one token can refill"
                );
                black_box(actual_acquired);
                elapsed
            })
        });
    });
}

/// Pack the logical bucket state into one compare-and-exchange word.
fn pack_state(tokens: f64, last_refill: u64) -> u128 {
    (u128::from(last_refill) << 64) | u128::from(tokens.to_bits())
}

/// Unpack the logical bucket state from one atomic word.
fn unpack_state(state: u128) -> (f64, u64) {
    let token_bits = u64::try_from(state & u128::from(u64::MAX)).unwrap();
    let last_refill = u64::try_from(state >> 64).unwrap();
    (f64::from_bits(token_bits), last_refill)
}
