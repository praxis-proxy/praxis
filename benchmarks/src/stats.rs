// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Docker container resource metrics collection via `docker stats`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::result::ResourceMetrics;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Interval between `docker stats --no-stream` polls.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

// -----------------------------------------------------------------------------
// Sample
// -----------------------------------------------------------------------------

/// A single sample from `docker stats`.
#[derive(Debug, Clone)]
struct StatsSample {
    /// CPU utilization as a percentage (e.g. 45.23).
    cpu_percent: f64,

    /// Memory RSS in bytes.
    memory_bytes: u64,
}

// -----------------------------------------------------------------------------
// DockerStatsCollector
// -----------------------------------------------------------------------------

/// Collects resource metrics from a running Docker container by
/// polling `docker stats --no-stream` at regular intervals.
///
/// Start collection with [`DockerStatsCollector::start`], then
/// call [`DockerStatsCollector::stop`] to join the background task
/// and compute aggregate metrics.
///
/// ```
/// use benchmarks::stats::DockerStatsCollector;
///
/// let collector = DockerStatsCollector::new("my-container");
/// assert_eq!(collector.container_name(), "my-container");
/// ```
pub struct DockerStatsCollector {
    /// Name of the Docker container to monitor.
    container: String,

    /// Signal to stop the background polling task.
    stop: Arc<AtomicBool>,

    /// Handle to the background polling task (set after start).
    handle: Option<JoinHandle<Vec<StatsSample>>>,
}

impl DockerStatsCollector {
    /// Create a new collector targeting the given container.
    #[must_use]
    pub fn new(container: &str) -> Self {
        Self {
            container: container.to_owned(),
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The container name being monitored.
    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container
    }

    /// Start collecting samples in a background tokio task.
    pub fn start(&mut self) {
        let container = self.container.clone();
        let stop = Arc::clone(&self.stop);
        self.handle = Some(tokio::spawn(poll_loop(container, stop)));
    }

    /// Stop collecting and compute aggregate [`ResourceMetrics`].
    ///
    /// Returns `None` if the background task panicked or no
    /// samples were collected.
    pub async fn stop(self) -> Option<ResourceMetrics> {
        self.stop.store(true, Ordering::Relaxed);
        let handle = self.handle?;
        let samples = handle.await.ok()?;
        compute_metrics(&samples)
    }
}

// -----------------------------------------------------------------------------
// Background Polling
// -----------------------------------------------------------------------------

/// Background loop that polls `docker stats` until stopped.
async fn poll_loop(container: String, stop: Arc<AtomicBool>) -> Vec<StatsSample> {
    let mut samples = Vec::new();

    while !stop.load(Ordering::Relaxed) {
        if let Some(sample) = poll_once(&container).await {
            trace!(
                cpu = sample.cpu_percent,
                mem_bytes = sample.memory_bytes,
                "docker stats sample"
            );
            samples.push(sample);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    debug!(count = samples.len(), "stats collection finished");
    samples
}

/// Execute one `docker stats --no-stream` poll and parse the output.
async fn poll_once(container: &str) -> Option<StatsSample> {
    let output = tokio::process::Command::new("docker")
        .args([
            "stats",
            "--no-stream",
            "--format",
            "{{.CPUPerc}}\t{{.MemUsage}}",
            container,
        ])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        trace!(
            container,
            code = output.status.code().unwrap_or(-1),
            "docker stats poll failed"
        );
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.trim();
    if line.is_empty() {
        return None;
    }

    parse_stats_line(line)
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse a single line from `docker stats --no-stream`.
///
/// Expected format: `45.23%\t128.5MiB / 2GiB`
fn parse_stats_line(line: &str) -> Option<StatsSample> {
    let (cpu_str, mem_str) = line.split_once('\t')?;
    let cpu = parse_cpu_percent(cpu_str)?;
    let mem = parse_memory_bytes(mem_str)?;
    Some(StatsSample {
        cpu_percent: cpu,
        memory_bytes: mem,
    })
}

/// Parse CPU percentage from a string like `"45.23%"`.
///
/// ```
/// use benchmarks::stats::parse_cpu_percent;
///
/// assert!((parse_cpu_percent("45.23%").unwrap() - 45.23).abs() < 0.001);
/// assert!((parse_cpu_percent("0.00%").unwrap()).abs() < 0.001);
/// assert!(parse_cpu_percent("bad").is_none());
/// ```
pub fn parse_cpu_percent(s: &str) -> Option<f64> {
    s.strip_suffix('%')?.trim().parse::<f64>().ok()
}

/// Parse memory usage from a string like `"128.5MiB / 2GiB"`.
///
/// Takes only the first value (before ` / `) and converts to
/// bytes based on the unit suffix (`B`, `KiB`, `MiB`, `GiB`).
///
/// ```
/// use benchmarks::stats::parse_memory_bytes;
///
/// assert_eq!(parse_memory_bytes("128.5MiB / 2GiB").unwrap(), 134_742_016);
/// assert_eq!(parse_memory_bytes("1GiB / 4GiB").unwrap(), 1_073_741_824);
/// assert_eq!(parse_memory_bytes("512KiB / 1GiB").unwrap(), 524_288);
/// assert_eq!(parse_memory_bytes("1024B / 2GiB").unwrap(), 1024);
/// ```
pub fn parse_memory_bytes(s: &str) -> Option<u64> {
    let usage = s.split(" / ").next()?.trim();
    parse_byte_value(usage)
}

/// Parse a value with a byte-unit suffix into raw bytes.
///
/// Supports `B`, `KiB`, `MiB`, `GiB`.
fn parse_byte_value(s: &str) -> Option<u64> {
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix("GiB") {
        (n, 1_073_741_824_u64)
    } else if let Some(n) = s.strip_suffix("MiB") {
        (n, 1_048_576_u64)
    } else if let Some(n) = s.strip_suffix("KiB") {
        (n, 1_024_u64)
    } else if let Some(n) = s.strip_suffix('B') {
        (n, 1_u64)
    } else {
        return None;
    };

    let value: f64 = num_str.trim().parse().ok()?;

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "memory values fit in u64; multiplier is a small power of 2"
    )]
    Some((value * multiplier as f64) as u64)
}

// -----------------------------------------------------------------------------
// Aggregation
// -----------------------------------------------------------------------------

/// Compute aggregate [`ResourceMetrics`] from collected samples.
#[expect(clippy::cast_precision_loss, reason = "sample counts and byte sums are small enough")]
fn compute_metrics(samples: &[StatsSample]) -> Option<ResourceMetrics> {
    if samples.is_empty() {
        warn!("no docker stats samples collected");
        return None;
    }

    let count = samples.len() as f64;
    let (cpu_avg, cpu_peak) = cpu_aggregates(samples, count);
    let (mem_avg, mem_peak) = mem_aggregates(samples, count);

    debug!(
        cpu_avg,
        cpu_peak,
        mem_avg,
        mem_peak,
        sample_count = samples.len(),
        "computed resource metrics"
    );

    Some(ResourceMetrics {
        cpu_percent_avg: cpu_avg,
        cpu_percent_peak: cpu_peak,
        memory_rss_bytes_avg: mem_avg,
        memory_rss_bytes_peak: mem_peak,
    })
}

/// Compute average and peak CPU from samples.
fn cpu_aggregates(samples: &[StatsSample], count: f64) -> (f64, f64) {
    let sum: f64 = samples.iter().map(|s| s.cpu_percent).sum();
    let peak = samples.iter().map(|s| s.cpu_percent).fold(f64::NEG_INFINITY, f64::max);
    (sum / count, peak)
}

/// Compute average and peak memory from samples.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "memory sums are small enough for f64; result fits u64"
)]
fn mem_aggregates(samples: &[StatsSample], count: f64) -> (u64, u64) {
    let sum: u64 = samples.iter().map(|s| s.memory_bytes).sum();
    let peak = samples.iter().map(|s| s.memory_bytes).max().unwrap_or(0);
    ((sum as f64 / count) as u64, peak)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_percent_typical() {
        let cpu = parse_cpu_percent("45.23%").unwrap();
        assert!((cpu - 45.23).abs() < 0.001, "expected 45.23, got {cpu}");
    }

    #[test]
    fn parse_cpu_percent_zero() {
        let cpu = parse_cpu_percent("0.00%").unwrap();
        assert!(cpu.abs() < 0.001, "expected 0.0, got {cpu}");
    }

    #[test]
    fn parse_cpu_percent_high() {
        let cpu = parse_cpu_percent("312.50%").unwrap();
        assert!(
            (cpu - 312.50).abs() < 0.001,
            "multi-core CPU can exceed 100%, got {cpu}"
        );
    }

    #[test]
    fn parse_cpu_percent_no_suffix() {
        assert!(
            parse_cpu_percent("45.23").is_none(),
            "missing % suffix should return None"
        );
    }

    #[test]
    fn parse_cpu_percent_empty() {
        assert!(parse_cpu_percent("").is_none(), "empty string should return None");
    }

    #[test]
    fn parse_cpu_percent_garbage() {
        assert!(parse_cpu_percent("abc%").is_none(), "non-numeric should return None");
    }

    #[test]
    fn parse_memory_bytes_mib() {
        let bytes = parse_memory_bytes("128.5MiB / 2GiB").unwrap();
        assert_eq!(bytes, 134_742_016, "128.5 MiB = 134_742_016 bytes");
    }

    #[test]
    fn parse_memory_bytes_gib() {
        let bytes = parse_memory_bytes("1GiB / 4GiB").unwrap();
        assert_eq!(bytes, 1_073_741_824, "1 GiB = 1_073_741_824 bytes");
    }

    #[test]
    fn parse_memory_bytes_kib() {
        let bytes = parse_memory_bytes("512KiB / 1GiB").unwrap();
        assert_eq!(bytes, 524_288, "512 KiB = 524_288 bytes");
    }

    #[test]
    fn parse_memory_bytes_raw_bytes() {
        let bytes = parse_memory_bytes("1024B / 2GiB").unwrap();
        assert_eq!(bytes, 1024, "1024B = 1024 bytes");
    }

    #[test]
    fn parse_memory_bytes_fractional_gib() {
        let bytes = parse_memory_bytes("1.5GiB / 4GiB").unwrap();
        assert_eq!(bytes, 1_610_612_736, "1.5 GiB = 1_610_612_736 bytes");
    }

    #[test]
    fn parse_memory_bytes_no_limit_portion() {
        let bytes = parse_memory_bytes("256MiB").unwrap();
        assert_eq!(bytes, 268_435_456, "256 MiB without limit portion");
    }

    #[test]
    fn parse_memory_bytes_unknown_unit() {
        assert!(
            parse_memory_bytes("100TB / 1PB").is_none(),
            "unsupported unit should return None"
        );
    }

    #[test]
    fn parse_memory_bytes_empty() {
        assert!(parse_memory_bytes("").is_none(), "empty string should return None");
    }

    #[test]
    fn parse_stats_line_typical() {
        let sample = parse_stats_line("45.23%\t128.5MiB / 2GiB").unwrap();
        assert!(
            (sample.cpu_percent - 45.23).abs() < 0.001,
            "cpu should be 45.23, got {}",
            sample.cpu_percent
        );
        assert_eq!(sample.memory_bytes, 134_742_016, "memory should be 128.5MiB in bytes");
    }

    #[test]
    fn parse_stats_line_no_tab() {
        assert!(
            parse_stats_line("45.23% 128.5MiB / 2GiB").is_none(),
            "missing tab delimiter should return None"
        );
    }

    #[test]
    fn parse_stats_line_bad_cpu() {
        assert!(
            parse_stats_line("bad%\t128.5MiB / 2GiB").is_none(),
            "non-numeric CPU should return None"
        );
    }

    #[test]
    fn parse_stats_line_bad_memory() {
        assert!(
            parse_stats_line("45.23%\tbadMiB / 2GiB").is_none(),
            "non-numeric memory should return None"
        );
    }

    #[test]
    fn compute_metrics_empty_samples() {
        let result = compute_metrics(&[]);
        assert!(result.is_none(), "empty samples should return None");
    }

    #[test]
    fn compute_metrics_single_sample() {
        let samples = vec![StatsSample {
            cpu_percent: 50.0,
            memory_bytes: 1_048_576,
        }];
        let m = compute_metrics(&samples).unwrap();
        assert!(
            (m.cpu_percent_avg - 50.0).abs() < 0.001,
            "avg should equal single sample, got {}",
            m.cpu_percent_avg
        );
        assert!(
            (m.cpu_percent_peak - 50.0).abs() < 0.001,
            "peak should equal single sample, got {}",
            m.cpu_percent_peak
        );
        assert_eq!(m.memory_rss_bytes_avg, 1_048_576, "avg mem should match single sample");
        assert_eq!(
            m.memory_rss_bytes_peak, 1_048_576,
            "peak mem should match single sample"
        );
    }

    #[test]
    fn compute_metrics_multiple_samples() {
        let samples = vec![
            StatsSample {
                cpu_percent: 20.0,
                memory_bytes: 100,
            },
            StatsSample {
                cpu_percent: 40.0,
                memory_bytes: 200,
            },
            StatsSample {
                cpu_percent: 60.0,
                memory_bytes: 300,
            },
        ];
        let m = compute_metrics(&samples).unwrap();
        assert!(
            (m.cpu_percent_avg - 40.0).abs() < 0.001,
            "cpu avg of 20/40/60 should be 40.0, got {}",
            m.cpu_percent_avg
        );
        assert!(
            (m.cpu_percent_peak - 60.0).abs() < 0.001,
            "cpu peak should be 60.0, got {}",
            m.cpu_percent_peak
        );
        assert_eq!(m.memory_rss_bytes_avg, 200, "mem avg of 100/200/300 should be 200");
        assert_eq!(m.memory_rss_bytes_peak, 300, "mem peak should be 300");
    }

    #[test]
    fn collector_new() {
        let c = DockerStatsCollector::new("test-container");
        assert_eq!(c.container_name(), "test-container");
        assert!(c.handle.is_none(), "handle should be None before start");
    }

    #[tokio::test]
    async fn collector_stop_without_start() {
        let c = DockerStatsCollector::new("nonexistent");
        let result = c.stop().await;
        assert!(result.is_none(), "stop without start should return None");
    }

    #[test]
    fn parse_byte_value_all_units() {
        assert_eq!(parse_byte_value("100B"), Some(100));
        assert_eq!(parse_byte_value("1KiB"), Some(1024));
        assert_eq!(parse_byte_value("1MiB"), Some(1_048_576));
        assert_eq!(parse_byte_value("1GiB"), Some(1_073_741_824));
    }

    #[test]
    fn parse_byte_value_no_unit() {
        assert!(parse_byte_value("12345").is_none(), "missing unit should return None");
    }

    #[test]
    fn parse_byte_value_fractional() {
        assert_eq!(parse_byte_value("2.5MiB"), Some(2_621_440), "2.5 MiB = 2_621_440 bytes");
    }
}
