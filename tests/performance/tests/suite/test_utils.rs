//! Shared benchmark harness for Praxis system benchmarks.
//!
//! Provides request-level timing, multi-threaded load generation,
//! percentile computation, and result reporting.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_test_utils::{http_get, http_post};

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

/// Default number of warmup requests before timing begins.
pub(crate) const DEFAULT_WARMUP: usize = 50;

/// Default total requests per benchmark run.
pub(crate) const DEFAULT_TOTAL: usize = 2000;

/// Default concurrency level (number of worker threads).
pub(crate) const DEFAULT_CONCURRENCY: usize = 8;

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
            label: label.to_string(),
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
// Benchmark Runner
// -----------------------------------------------------------------------------

/// Run a benchmark using a custom request function.
pub(crate) fn run_benchmark<F>(config: &BenchConfig, addr: &str, make_request: F) -> BenchResult
where
    F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
{
    let addr_owned = addr.to_string();
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
                let mut errors = 0usize;

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

    // Collect results from all threads.
    let mut all_latencies = Vec::with_capacity(config.total_requests);
    let mut total_errors = 0usize;
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
    let path = path.to_string();
    let body = body.to_string();
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

    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);

    sorted[index]
}

// -----------------------------------------------------------------------------
// Reporting
// -----------------------------------------------------------------------------

/// Assert baseline performance expectations.
pub(crate) fn assert_performance(result: &BenchResult, min_throughput: f64, max_p99_ms: f64) {
    let throughput = result.total_requests as f64 / result.elapsed.as_secs_f64();
    let p99 = compute_percentile(&result.latencies, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;

    assert!(
        throughput >= min_throughput,
        "{}: throughput {throughput:.0} req/s below minimum {min_throughput:.0} req/s",
        result.label,
    );
    assert!(
        p99_ms <= max_p99_ms,
        "{}: p99 latency {p99_ms:.1}ms exceeds maximum {max_p99_ms:.1}ms",
        result.label,
    );
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
    let path = path.to_string();
    run_benchmark(config, addr, move |a| http_get(a, &path, None))
}
