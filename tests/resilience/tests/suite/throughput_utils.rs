// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Shared benchmark harness for Praxis system benchmarks.
//!
//! Every throughput test in the suite holds [`bench_guard`] for its whole
//! measurement, so one benchmark runs at a time.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use praxis_test_utils::{http_get, http_post};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default number of warmup requests before timing begins.
pub(crate) const DEFAULT_WARMUP: usize = 50;

/// Default total requests per benchmark run.
pub(crate) const DEFAULT_TOTAL: usize = 2000;

/// Default concurrency level (number of worker threads).
pub(crate) const DEFAULT_CONCURRENCY: usize = 8;

/// Environment variable that scales every throughput floor.
///
/// The floors are sized for GitHub's hosted runners. A slower host (the FIPS
/// host runs the whole suite as the FIPS build inside the toolchain
/// container) sets this below 1 so the throughput tests still prove a working
/// proxy without asserting hosted-runner speed. Latency ceilings are not
/// scaled.
pub(crate) const THROUGHPUT_SCALE_VAR: &str = "PRAXIS_TEST_THROUGHPUT_SCALE";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for a single benchmark run.
pub(crate) struct BenchConfig {
    /// Human-readable label for the benchmark.
    pub label: String,

    /// Total number of timed requests to issue.
    pub total_requests: usize,

    /// Number of concurrent worker threads.
    pub concurrency: usize,

    /// Number of warmup requests (not timed).
    pub warmup: usize,
}

impl BenchConfig {
    /// Create a config with the given label and default parameters.
    pub(crate) fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            total_requests: DEFAULT_TOTAL,
            concurrency: DEFAULT_CONCURRENCY,
            warmup: DEFAULT_WARMUP,
        }
    }

    /// Override total requests.
    pub(crate) fn total(mut self, n: usize) -> Self {
        self.total_requests = n;
        self
    }

    /// Override concurrency level.
    pub(crate) fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }
}

// -----------------------------------------------------------------------------
// Results
// -----------------------------------------------------------------------------

/// Collected results from a benchmark run.
pub(crate) struct BenchResult {
    /// Label from the config.
    pub label: String,

    /// Total timed requests issued.
    pub total_requests: usize,

    /// Concurrency level used.
    pub concurrency: usize,

    /// Wall-clock elapsed time for the timed phase.
    pub elapsed: Duration,

    /// Per-request latencies, sorted ascending.
    pub latencies: Vec<Duration>,

    /// Number of requests that returned a non-200 status.
    pub errors: usize,
}

// -----------------------------------------------------------------------------
// Mutual Exclusion
// -----------------------------------------------------------------------------

/// Serializes every throughput benchmark in this binary.
///
/// A throughput floor only means something when the benchmark has the machine
/// to itself for the whole measurement. Under the default test-thread pool the
/// 16 benchmarks otherwise start together, and each `DEFAULT_CONCURRENCY`-wide
/// load generator plus its in-process proxy and backend competes with every
/// sibling, so the measured number depends on which benchmarks happened to be
/// running at the same moment. One test at a time is the only way the floors
/// measure the proxy rather than the scheduler.
static BENCH_LOCK: Mutex<()> = Mutex::new(());

/// Hold for the whole benchmark so no sibling benchmark runs meanwhile.
///
/// A poisoned lock is granted anyway: a benchmark that panics should not make
/// every later one hang on a lock that nobody will ever release again.
pub(crate) fn bench_guard() -> MutexGuard<'static, ()> {
    BENCH_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

// -----------------------------------------------------------------------------
// Benchmark Runner
// -----------------------------------------------------------------------------

/// Run a benchmark using a custom request function.
pub(crate) fn run_benchmark<F>(config: &BenchConfig, addr: &str, make_request: F) -> BenchResult
where
    F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
{
    let addr_owned = addr.to_owned();
    for _ in 0..config.warmup {
        make_request(&addr_owned);
    }

    let make_request = Arc::new(make_request);
    let per_thread = config.total_requests / config.concurrency;
    let remainder = config.total_requests % config.concurrency;
    let wall_start = Instant::now();
    let handles: Vec<_> = (0..config.concurrency)
        .map(|i| {
            let addr = addr_owned.clone();
            let make_req = Arc::clone(&make_request);
            let count = per_thread + if i < remainder { 1 } else { 0 };

            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(count);
                let mut errors = 0_usize;

                for _ in 0..count {
                    let start = Instant::now();
                    let (status, _body) = make_req(&addr);
                    latencies.push(start.elapsed());

                    if status != 200 {
                        errors += 1;
                    }
                }

                (latencies, errors)
            })
        })
        .collect();

    let mut all_latencies = Vec::with_capacity(config.total_requests);
    let mut total_errors = 0_usize;
    for handle in handles {
        let (latencies, errors) = handle.join().expect("worker thread panicked");
        all_latencies.extend(latencies);
        total_errors += errors;
    }
    let elapsed = wall_start.elapsed();
    all_latencies.sort();

    BenchResult {
        label: config.label.clone(),
        total_requests: all_latencies.len(),
        concurrency: config.concurrency,
        elapsed,
        latencies: all_latencies,
        errors: total_errors,
    }
}

/// Convenience: run a POST benchmark with a fixed path and body.
pub(crate) fn run_benchmark_with_body(config: &BenchConfig, addr: &str, path: &str, body: &str) -> BenchResult {
    let path = path.to_owned();
    let body = body.to_owned();
    run_benchmark(config, addr, move |a| http_post(a, &path, &body))
}

// -----------------------------------------------------------------------------
// Percentile Computation
// -----------------------------------------------------------------------------

/// Compute the p-th percentile from a sorted latency slice
/// using the nearest-rank method.
///
/// `p` must be in `0.0..=100.0`.
pub(crate) fn compute_percentile(sorted: &[Duration], p: f64) -> Duration {
    assert!(!sorted.is_empty(), "cannot compute percentile of empty slice");
    debug_assert!(
        sorted.windows(2).all(|w| w[0] <= w[1]),
        "compute_percentile requires a sorted slice"
    );

    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);

    sorted[index]
}

// -----------------------------------------------------------------------------
// Reporting
// -----------------------------------------------------------------------------

/// Assert baseline performance expectations.
///
/// `min_throughput` is multiplied by [`THROUGHPUT_SCALE_VAR`] when it is set.
pub(crate) fn assert_performance(result: &BenchResult, min_throughput: f64, max_p99_ms: f64) {
    let scale = throughput_scale();
    let min_throughput = min_throughput * scale;
    let throughput = result.total_requests as f64 / result.elapsed.as_secs_f64();
    let p99 = compute_percentile(&result.latencies, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;

    // Say when the floor was scaled, so a failure on a slower host is not read
    // against the number written in the test.
    let scaled = if (scale - 1.0).abs() < f64::EPSILON {
        String::new()
    } else {
        format!(" ({THROUGHPUT_SCALE_VAR}={scale})")
    };
    assert!(
        throughput >= min_throughput,
        "{}: throughput {throughput:.0} req/s below minimum {min_throughput:.0} req/s{scaled}",
        result.label,
    );
    assert!(
        p99_ms <= max_p99_ms,
        "{}: p99 latency {p99_ms:.1}ms exceeds maximum {max_p99_ms:.1}ms",
        result.label,
    );
}

/// The throughput floor multiplier from [`THROUGHPUT_SCALE_VAR`], 1 when unset.
fn throughput_scale() -> f64 {
    parse_throughput_scale(std::env::var(THROUGHPUT_SCALE_VAR).ok().as_deref())
}

/// Parse a throughput scale, which must be a positive number.
fn parse_throughput_scale(value: Option<&str>) -> f64 {
    let Some(value) = value else {
        return 1.0;
    };
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|scale| scale.is_finite() && *scale > 0.0)
        .unwrap_or_else(|| panic!("{THROUGHPUT_SCALE_VAR} must be a positive number, got {value:?}"))
}

/// Print a human-readable benchmark report to stderr.
pub(crate) fn report_results(result: &BenchResult) {
    let throughput = result.total_requests as f64 / result.elapsed.as_secs_f64();
    let p50 = compute_percentile(&result.latencies, 50.0);
    let p95 = compute_percentile(&result.latencies, 95.0);
    let p99 = compute_percentile(&result.latencies, 99.0);
    let min = result.latencies.first().copied().unwrap_or_default();
    let max = result.latencies.last().copied().unwrap_or_default();

    eprintln!();
    eprintln!("=== {} ===", result.label);
    eprintln!("  requests:    {}", result.total_requests);
    eprintln!("  concurrency: {}", result.concurrency);
    eprintln!("  errors:      {}", result.errors);
    eprintln!("  elapsed:     {:.2?}", result.elapsed);
    eprintln!("  throughput:  {throughput:.0} req/s");
    eprintln!("  latency p50: {p50:.2?}");
    eprintln!("  latency p95: {p95:.2?}");
    eprintln!("  latency p99: {p99:.2?}");
    eprintln!("  latency min: {min:.2?}");
    eprintln!("  latency max: {max:.2?}");
    eprintln!();
}

// -----------------------------------------------------------------------------
// GET Benchmark Runner
// -----------------------------------------------------------------------------

/// Run a GET benchmark against a given path.
pub(crate) fn run_get_benchmark(config: &BenchConfig, addr: &str, path: &str) -> BenchResult {
    let path = path.to_owned();
    run_benchmark(config, addr, move |a| http_get(a, &path, None))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::{bench_guard, parse_throughput_scale};

    #[test]
    fn an_unset_scale_leaves_the_floors_alone() {
        assert!((parse_throughput_scale(None) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_scale_applies_as_given() {
        assert!((parse_throughput_scale(Some(" 0.5 ")) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "must be a positive number")]
    fn a_non_numeric_scale_is_rejected() {
        parse_throughput_scale(Some("fast"));
    }

    #[test]
    #[should_panic(expected = "must be a positive number")]
    fn a_zero_scale_is_rejected() {
        parse_throughput_scale(Some("0"));
    }

    #[test]
    fn a_second_guard_waits_until_the_first_is_dropped() {
        let held = bench_guard();
        let acquired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&acquired);

        let worker = thread::spawn(move || {
            let _guard = bench_guard();
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        assert!(
            !acquired.load(std::sync::atomic::Ordering::SeqCst),
            "the second guard must block while the first is held"
        );

        drop(held);
        worker.join().expect("worker thread panicked");

        assert!(
            acquired.load(std::sync::atomic::Ordering::SeqCst),
            "the second guard must be granted once the first is dropped"
        );
    }

    #[test]
    fn a_poisoned_lock_is_still_granted_to_the_next_benchmark() {
        let poisoned = thread::spawn(|| {
            let _guard = bench_guard();
            panic!("poisoned by a panicked benchmark");
        });

        assert!(poisoned.join().is_err(), "the worker should have panicked");

        let _guard = bench_guard();
    }
}
