// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Vegeta HTTP load generator wrapper.
//!
//! See: <https://github.com/tsenart/vegeta>

use std::{process::Stdio, time::Duration};

use serde::Deserialize;
use tempfile::TempDir;
use tokio::process::Command as TokioCommand;

use crate::{error::BenchmarkError, result::BenchmarkResult};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for a Vegeta load test.
#[derive(Debug, Clone)]
pub struct VegetaConfig {
    /// Target URL.
    pub target: String,

    /// Requests per second (constant rate).
    pub rate: u32,

    /// Test duration.
    pub duration: Duration,

    /// Number of workers.
    pub workers: u32,

    /// HTTP method (GET, POST, etc.).
    pub method: String,

    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

// -----------------------------------------------------------------------------
// JSON Types
// -----------------------------------------------------------------------------

/// Vegeta JSON report: latencies section (nanoseconds).
#[derive(Debug, Deserialize)]
struct VegetaLatencies {
    /// Mean latency in nanoseconds.
    mean: u64,

    /// 50th percentile latency in nanoseconds.
    #[serde(rename = "50th")]
    p50: u64,

    /// 90th percentile latency in nanoseconds.
    #[serde(rename = "90th")]
    p90: u64,

    /// 95th percentile latency in nanoseconds.
    #[serde(rename = "95th")]
    p95: u64,

    /// 99th percentile latency in nanoseconds.
    #[serde(rename = "99th")]
    p99: u64,

    /// Maximum latency in nanoseconds.
    max: u64,

    /// Minimum latency in nanoseconds.
    min: u64,
}

/// Vegeta JSON report: bytes section.
#[derive(Debug, Deserialize)]
struct VegetaBytes {
    /// Total bytes.
    total: u64,
}

/// Top-level Vegeta JSON report structure.
///
/// Produced by `vegeta report --type=json`.
#[derive(Debug, Deserialize)]
struct VegetaReport {
    /// Latency percentiles (nanoseconds).
    latencies: VegetaLatencies,

    /// Incoming bytes (body only).
    bytes_in: VegetaBytes,

    /// Outgoing bytes (body only).
    bytes_out: VegetaBytes,

    /// Total number of requests sent.
    requests: u64,

    /// Actual request send rate (req/s). Present in vegeta JSON output
    /// but not consumed by result conversion.
    #[serde(default)]
    #[expect(dead_code, reason = "deserialized from vegeta JSON but unused")]
    rate: f64,

    /// Successful response rate (req/s).
    throughput: f64,

    /// Duration of the attack in nanoseconds.
    duration: u64,

    /// Fraction of successful (2xx) responses.
    success: f64,

    /// Map of HTTP status code to count. Present in vegeta JSON output
    /// but not consumed by result conversion.
    #[serde(default)]
    #[expect(dead_code, reason = "deserialized from vegeta JSON but unused")]
    status_codes: std::collections::HashMap<String, u64>,

    /// List of error strings.
    #[serde(default)]
    errors: Vec<String>,
}

// -----------------------------------------------------------------------------
// Execution
// -----------------------------------------------------------------------------

/// Run a Vegeta load test and return raw JSON output.
///
/// # Errors
///
/// Returns [`BenchmarkError::ToolNotFound`] if Vegeta is not installed,
/// [`BenchmarkError::ToolFailed`] if the load test exits non-zero,
/// or [`BenchmarkError::Io`] if file preparation fails.
pub async fn run(config: &VegetaConfig) -> Result<String, BenchmarkError> {
    let (_tmpdir, target_path, body_path) = prepare_vegeta_files(config)?;

    let mut attack_cmd = tokio::process::Command::new("vegeta");
    attack_cmd
        .arg("attack")
        .arg("-targets")
        .arg(&target_path)
        .arg("-rate")
        .arg(config.rate.to_string())
        .arg("-duration")
        .arg(format!("{}s", config.duration.as_secs()));

    if config.rate == 0 {
        attack_cmd.arg("-max-workers").arg(config.workers.to_string());
    } else {
        attack_cmd.arg("-workers").arg(config.workers.to_string());
    }

    if let Some(path) = &body_path {
        attack_cmd.arg("-body").arg(path);
    }

    run_vegeta_pipeline(&mut attack_cmd).await
}

/// Write vegeta target and optional body files into a temp directory.
///
/// Returns the [`TempDir`] (must be kept alive), the target file
/// path, and an optional body file path.
fn prepare_vegeta_files(
    config: &VegetaConfig,
) -> Result<(TempDir, std::path::PathBuf, Option<std::path::PathBuf>), BenchmarkError> {
    let dir = tempfile::Builder::new()
        .prefix("praxis-bench-")
        .tempdir()
        .map_err(BenchmarkError::Io)?;

    let method = &config.method;
    let url = &config.target;
    let target_spec = format!("{method} {url}\n");
    let target_path = dir.path().join("vegeta-targets.txt");
    std::fs::write(&target_path, &target_spec).map_err(BenchmarkError::Io)?;

    let body_path = if let Some(body) = &config.body {
        let p = dir.path().join("vegeta-body.bin");
        std::fs::write(&p, body).map_err(BenchmarkError::Io)?;
        Some(p)
    } else {
        None
    };

    Ok((dir, target_path, body_path))
}

/// Spawn a vegeta attack command, pipe its output through
/// `vegeta report --type=json`, and return the JSON result.
///
/// # Errors
///
/// Returns [`BenchmarkError::ToolNotFound`] if vegeta is not
/// installed, or [`BenchmarkError::ToolFailed`] on non-zero exit.
pub(crate) async fn run_vegeta_pipeline(attack_cmd: &mut TokioCommand) -> Result<String, BenchmarkError> {
    let attack_output = attack_cmd.output().await.map_err(map_vegeta_spawn_error)?;
    check_vegeta_output(&attack_output)?;
    vegeta_report(&attack_output.stdout).await
}

/// Map a spawn/IO error to the appropriate [`BenchmarkError`].
fn map_vegeta_spawn_error(e: std::io::Error) -> BenchmarkError {
    if e.kind() == std::io::ErrorKind::NotFound {
        BenchmarkError::ToolNotFound("vegeta".to_owned())
    } else {
        BenchmarkError::Io(e)
    }
}

/// Check a vegeta process output for failure, returning an error
/// if the process exited non-zero.
fn check_vegeta_output(output: &std::process::Output) -> Result<(), BenchmarkError> {
    if output.status.success() {
        return Ok(());
    }
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not found") || stderr.contains("No such file") {
        return Err(BenchmarkError::ToolNotFound("vegeta".to_owned()));
    }
    Err(BenchmarkError::ToolFailed {
        tool: "vegeta".to_owned(),
        code,
        stderr: stderr.into_owned(),
    })
}

/// Feed attack output into `vegeta report --type=json` and return
/// the JSON string.
async fn vegeta_report(attack_stdout: &[u8]) -> Result<String, BenchmarkError> {
    let mut report_cmd = TokioCommand::new("vegeta");
    report_cmd
        .arg("report")
        .arg("--type=json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut report = report_cmd.spawn().map_err(map_vegeta_spawn_error)?;

    if let Some(mut stdin) = report.stdin.take() {
        use tokio::io::AsyncWriteExt as _;
        stdin.write_all(attack_stdout).await.map_err(BenchmarkError::Io)?;
    }

    let output = report.wait_with_output().await.map_err(BenchmarkError::Io)?;
    check_vegeta_output(&output)?;

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse Vegeta JSON report output into a [`BenchmarkResult`].
///
/// # Errors
///
/// Returns [`BenchmarkError::ParseError`] if the JSON is invalid.
///
/// [`BenchmarkResult`]: crate::result::BenchmarkResult
pub fn parse(
    json: &str,
    scenario: &str,
    proxy: &str,
    commit: &str,
    include_raw: bool,
) -> Result<BenchmarkResult, BenchmarkError> {
    let report: VegetaReport = serde_json::from_str(json).map_err(|e| BenchmarkError::ParseError {
        tool: "vegeta".into(),
        reason: e.to_string(),
    })?;

    let raw_report = if include_raw {
        serde_json::from_str(json).ok()
    } else {
        None
    };

    Ok(BenchmarkResult {
        commit: commit.into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        scenario: scenario.into(),
        proxy: proxy.into(),
        tool: "vegeta".into(),
        environment: crate::result::current_environment(),
        latency: vegeta_latency(&report.latencies),
        throughput: vegeta_throughput(&report),
        resource: None,
        errors: vegeta_errors(&report),
        raw_report,
    })
}

/// Convert vegeta latencies to `LatencyMetrics`.
fn vegeta_latency(l: &VegetaLatencies) -> crate::result::LatencyMetrics {
    crate::result::LatencyMetrics {
        min: ns_to_secs(l.min),
        max: ns_to_secs(l.max),
        mean: ns_to_secs(l.mean),
        p50: ns_to_secs(l.p50),
        p90: ns_to_secs(l.p90),
        p95: ns_to_secs(l.p95),
        p99: ns_to_secs(l.p99),
        // Vegeta does not report p99.9; p99 used as approximation.
        p99_9: ns_to_secs(l.p99),
    }
}

/// Compute throughput metrics from a vegeta report.
#[expect(clippy::cast_precision_loss, reason = "precision loss acceptable")]
fn vegeta_throughput(report: &VegetaReport) -> crate::result::ThroughputMetrics {
    let duration_secs = report.duration as f64 / 1_000_000_000.0;
    let total_bytes = report.bytes_in.total + report.bytes_out.total;
    let bytes_per_sec = if duration_secs > 0.0 {
        total_bytes as f64 / duration_secs
    } else {
        0.0
    };
    crate::result::ThroughputMetrics {
        requests_per_sec: report.throughput,
        bytes_per_sec,
    }
}

/// Extract error metrics from a vegeta report.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "precision loss acceptable"
)]
fn vegeta_errors(report: &VegetaReport) -> crate::result::ErrorMetrics {
    let non_2xx = if report.requests > 0 {
        let success_count = (report.success * report.requests as f64).round() as u64;
        report.requests.saturating_sub(success_count)
    } else {
        0
    };
    let timeouts = report
        .errors
        .iter()
        .filter(|e| e.contains("timeout") || e.contains("deadline exceeded"))
        .count() as u64;
    let connect_failures = report
        .errors
        .iter()
        .filter(|e| e.contains("connection refused") || e.contains("connect:") || e.contains("dial"))
        .count() as u64;
    crate::result::ErrorMetrics {
        non_2xx: Some(non_2xx),
        timeouts,
        connect_failures,
    }
}

/// Convert nanoseconds to seconds.
#[expect(clippy::cast_precision_loss, reason = "precision loss acceptable")]
fn ns_to_secs(ns: u64) -> f64 {
    ns as f64 / 1_000_000_000.0
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn ns_to_secs_zero() {
        let result = ns_to_secs(0);
        assert!(
            (result - 0.0).abs() < 1e-15,
            "0 ns should convert to 0.0 seconds, got {result}"
        );
    }

    #[test]
    fn ns_to_secs_one_second() {
        let result = ns_to_secs(1_000_000_000);
        assert!(
            (result - 1.0).abs() < 1e-9,
            "1_000_000_000 ns should convert to 1.0 second, got {result}"
        );
    }

    #[test]
    fn ns_to_secs_fractional() {
        let result = ns_to_secs(1_500_000);
        let expected = 0.0015;
        assert!(
            (result - expected).abs() < 1e-12,
            "1_500_000 ns should convert to {expected}, got {result}"
        );
    }

    #[test]
    fn parse_minimal_vegeta_json() {
        let json = r#"{
            "latencies": {
                "mean": 1000000,
                "50th": 900000,
                "90th": 2000000,
                "95th": 3000000,
                "99th": 5000000,
                "max": 10000000,
                "min": 500000
            },
            "bytes_in": {"total": 200000},
            "bytes_out": {"total": 50000},
            "requests": 1000,
            "rate": 100.0,
            "throughput": 98.5,
            "duration": 10000000000,
            "success": 0.99,
            "status_codes": {"200": 990, "503": 10},
            "errors": []
        }"#;

        let result = parse(json, "vegeta-test", "praxis", "abc123", false).expect("should parse valid vegeta JSON");

        assert_eq!(result.scenario, "vegeta-test", "scenario mismatch");
        assert_eq!(result.proxy, "praxis", "proxy mismatch");
        assert_eq!(result.commit, "abc123", "commit mismatch");
        assert_eq!(result.tool, "vegeta", "tool mismatch");

        assert!(
            (result.latency.min - 0.0005).abs() < 1e-9,
            "latency min should be 0.0005s, got {}",
            result.latency.min
        );
        assert!(
            (result.latency.max - 0.010).abs() < 1e-9,
            "latency max should be 0.010s, got {}",
            result.latency.max
        );
        assert!(
            (result.latency.mean - 0.001).abs() < 1e-9,
            "latency mean should be 0.001s, got {}",
            result.latency.mean
        );
        assert!(
            (result.latency.p50 - 0.0009).abs() < 1e-9,
            "latency p50 should be 0.0009s, got {}",
            result.latency.p50
        );
        assert!(
            (result.latency.p90 - 0.002).abs() < 1e-9,
            "latency p90 should be 0.002s, got {}",
            result.latency.p90
        );
        assert!(
            (result.latency.p99 - 0.005).abs() < 1e-9,
            "latency p99 should be 0.005s, got {}",
            result.latency.p99
        );

        assert!(
            (result.throughput.requests_per_sec - 98.5).abs() < 1e-3,
            "throughput should be 98.5, got {}",
            result.throughput.requests_per_sec
        );

        let expected_bps = 250_000.0 / 10.0;
        assert!(
            (result.throughput.bytes_per_sec - expected_bps).abs() < 1e-3,
            "bytes_per_sec should be {expected_bps}, got {}",
            result.throughput.bytes_per_sec
        );

        assert_eq!(result.errors.non_2xx, Some(10), "non_2xx should be 10");
        assert_eq!(result.errors.timeouts, 0, "timeouts should be 0");
        assert_eq!(result.errors.connect_failures, 0, "connect_failures should be 0");
        assert!(
            result.raw_report.is_none(),
            "raw_report should be None when include_raw=false"
        );
    }

    #[test]
    fn parse_with_include_raw() {
        let json = r#"{
            "latencies": {
                "mean": 1000000, "50th": 900000, "90th": 2000000,
                "95th": 3000000, "99th": 5000000, "max": 10000000, "min": 500000
            },
            "bytes_in": {"total": 100},
            "bytes_out": {"total": 100},
            "requests": 10,
            "throughput": 10.0,
            "duration": 1000000000,
            "success": 1.0,
            "errors": []
        }"#;

        let result = parse(json, "raw-test", "praxis", "def456", true).expect("should parse with include_raw");
        assert!(
            result.raw_report.is_some(),
            "raw_report should be Some when include_raw=true"
        );
    }

    #[test]
    fn parse_counts_timeout_errors() {
        let json = r#"{
            "latencies": {
                "mean": 1000000, "50th": 900000, "90th": 2000000,
                "95th": 3000000, "99th": 5000000, "max": 10000000, "min": 500000
            },
            "bytes_in": {"total": 100},
            "bytes_out": {"total": 100},
            "requests": 10,
            "throughput": 8.0,
            "duration": 1000000000,
            "success": 0.8,
            "errors": ["timeout exceeded", "connection refused", "dial tcp: connect refused"]
        }"#;

        let result = parse(json, "err-test", "praxis", "abc", false).expect("should parse error report");
        assert_eq!(result.errors.timeouts, 1, "should count 1 timeout error");
        assert_eq!(
            result.errors.connect_failures, 2,
            "should count 2 connect failures (refused + dial)"
        );
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse("not valid json", "test", "praxis", "abc", false);
        assert!(result.is_err(), "invalid JSON should return an error");
        let err = result.unwrap_err();
        match err {
            BenchmarkError::ParseError { tool, .. } => {
                assert_eq!(tool, "vegeta", "parse error should reference vegeta");
            },
            other => panic!("expected ParseError, got: {other}"),
        }
    }

    #[test]
    fn parse_zero_duration_avoids_division_by_zero() {
        let json = r#"{
            "latencies": {
                "mean": 1000000, "50th": 900000, "90th": 2000000,
                "95th": 3000000, "99th": 5000000, "max": 10000000, "min": 500000
            },
            "bytes_in": {"total": 100},
            "bytes_out": {"total": 100},
            "requests": 0,
            "throughput": 0.0,
            "duration": 0,
            "success": 0.0,
            "errors": []
        }"#;

        let result = parse(json, "zero-dur", "praxis", "abc", false).expect("should handle zero duration");
        assert!(
            (result.throughput.bytes_per_sec - 0.0).abs() < 1e-9,
            "bytes_per_sec should be 0 when duration is 0, got {}",
            result.throughput.bytes_per_sec
        );
    }
}
