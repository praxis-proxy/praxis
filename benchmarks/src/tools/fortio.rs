//! Fortio HTTP/TCP load generator wrapper.
//!
//! See: <https://fortio.org/>

use std::time::Duration;

use serde::Deserialize;

use crate::{error::BenchmarkError, result::BenchmarkResult};

// -----------------------------------------------------------------------------
// FortioConfig
// -----------------------------------------------------------------------------

/// Configuration for a Fortio load test.
#[derive(Debug, Clone)]
pub struct FortioConfig {
    /// Target URL or address.
    pub target: String,

    /// Protocol to test.
    pub protocol: FortioProtocol,

    /// Requests per second (0 = max rate).
    pub qps: u32,

    /// Test duration.
    pub duration: Duration,

    /// Number of connections.
    pub connections: u32,

    /// Disable catch-up behavior (open-loop mode).
    pub no_catchup: bool,

    /// Use HTTP/2 (h2c). Implies `-stdclient`.
    pub h2: bool,
}

/// Protocol for Fortio load test.
#[derive(Debug, Clone)]
pub enum FortioProtocol {
    /// HTTP load test.
    Http,

    /// TCP load test.
    Tcp,
}

// -----------------------------------------------------------------------------
// JSON Types
// -----------------------------------------------------------------------------

/// Fortio JSON: percentile entry within the histogram.
#[derive(Debug, Deserialize)]
struct FortioPercentile {
    /// Percentile value (0.0 to 100.0).
    #[serde(rename = "Percentile")]
    percentile: f64,

    /// Latency value in seconds.
    #[serde(rename = "Value")]
    value: f64,
}

/// Fortio JSON: duration histogram section.
#[derive(Debug, Deserialize)]
struct FortioDurationHistogram {
    /// Percentile buckets.
    #[serde(rename = "Percentiles", default)]
    percentiles: Vec<FortioPercentile>,

    /// Average latency in seconds.
    #[serde(rename = "Avg")]
    avg: f64,

    /// Minimum latency in seconds.
    #[serde(rename = "Min")]
    min: f64,

    /// Maximum latency in seconds.
    #[serde(rename = "Max")]
    max: f64,

    /// Total count of data points.
    #[serde(rename = "Count")]
    #[expect(dead_code)]
    count: u64,
}

/// Fortio JSON: top-level report structure.
#[derive(Debug, Deserialize)]
struct FortioReport {
    /// Duration histogram with percentile data.
    #[serde(rename = "DurationHistogram")]
    duration_histogram: FortioDurationHistogram,

    /// Actual queries per second achieved.
    #[serde(rename = "ActualQPS")]
    actual_qps: f64,

    /// Total bytes sent.
    #[serde(rename = "BytesSent", default)]
    bytes_sent: u64,

    /// Total bytes received.
    #[serde(rename = "BytesReceived", default)]
    bytes_received: u64,

    /// HTTP return codes (status code string to count).
    #[serde(rename = "RetCodes", default)]
    ret_codes: std::collections::HashMap<String, u64>,

    /// Actual test duration in nanoseconds (`time.Duration`).
    #[serde(rename = "ActualDuration", default)]
    actual_duration_ns: f64,
}

// -----------------------------------------------------------------------------
// Execution
// -----------------------------------------------------------------------------

/// Start Fortio's built-in echo server on the given port.
pub async fn start_echo_server(port: u16) -> Result<tokio::process::Child, BenchmarkError> {
    let child = tokio::process::Command::new("fortio")
        .args(["server", "-http-port", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BenchmarkError::ToolNotFound("fortio".into())
            } else {
                BenchmarkError::Io(e)
            }
        })?;

    Ok(child)
}

/// Run a Fortio load test and return raw JSON output.
pub async fn run(config: &FortioConfig) -> Result<String, BenchmarkError> {
    let duration_secs = config.duration.as_secs();
    let mut args = vec![
        "load".to_owned(),
        "-json".to_owned(),
        "-".to_owned(),
        "-qps".to_owned(),
        config.qps.to_string(),
        "-c".to_owned(),
        config.connections.to_string(),
        "-t".to_owned(),
        format!("{duration_secs}s"),
    ];

    if config.no_catchup {
        args.push("-nocatchup".to_owned());
    }

    if config.h2 {
        args.push("-h2".to_owned());
    }

    let target = match config.protocol {
        FortioProtocol::Http => config.target.clone(),
        FortioProtocol::Tcp => {
            if config.target.starts_with("tcp://") {
                config.target.clone()
            } else {
                format!("tcp://{}", config.target)
            }
        },
    };
    args.push(target);

    let output = tokio::process::Command::new("fortio")
        .args(&args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BenchmarkError::ToolNotFound("fortio".into())
            } else {
                BenchmarkError::Io(e)
            }
        })?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BenchmarkError::ToolFailed {
            tool: "fortio".into(),
            code,
            stderr: stderr.into_owned(),
        });
    }

    let json = String::from_utf8_lossy(&output.stdout).into_owned();
    Ok(json)
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Look up a percentile value from Fortio's percentile list.
fn lookup_percentile(percentiles: &[FortioPercentile], target: f64) -> f64 {
    // Exact match.
    if let Some(p) = percentiles.iter().find(|p| (p.percentile - target).abs() < 0.01) {
        return p.value;
    }

    // Interpolate between the two nearest surrounding values.
    let below = percentiles.iter().rev().find(|p| p.percentile < target);
    let above = percentiles.iter().find(|p| p.percentile > target);

    match (below, above) {
        (Some(lo), Some(hi)) => {
            let frac = (target - lo.percentile) / (hi.percentile - lo.percentile);
            lo.value + frac * (hi.value - lo.value)
        },
        (Some(lo), None) => lo.value,
        (None, Some(hi)) => hi.value,
        (None, None) => 0.0,
    }
}

/// Parse Fortio JSON output into a [`BenchmarkResult`].
///
/// [`BenchmarkResult`]: crate::result::BenchmarkResult
pub fn parse(
    json: &str,
    scenario: &str,
    proxy: &str,
    commit: &str,
    include_raw: bool,
) -> Result<BenchmarkResult, BenchmarkError> {
    let report: FortioReport = serde_json::from_str(json).map_err(|e| BenchmarkError::ParseError {
        tool: "fortio".into(),
        reason: e.to_string(),
    })?;

    let raw_report = if include_raw {
        serde_json::from_str(json).ok()
    } else {
        None
    };

    let hist = &report.duration_histogram;
    let pctiles = &hist.percentiles;

    let total_bytes = report.bytes_sent + report.bytes_received;
    let duration_secs = report.actual_duration_ns / 1_000_000_000.0;
    let bytes_per_sec = if duration_secs > 0.0 {
        total_bytes as f64 / duration_secs
    } else {
        0.0
    };

    let is_http = report.ret_codes.keys().any(|c| c.parse::<u16>().is_ok());
    let non_2xx = if is_http {
        let count: u64 = report
            .ret_codes
            .iter()
            .filter(|(code, _)| code.parse::<u16>().is_ok_and(|c| !(200..300).contains(&c)))
            .map(|(_, count)| count)
            .sum();
        Some(count)
    } else {
        None
    };

    Ok(BenchmarkResult {
        commit: commit.into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        scenario: scenario.into(),
        proxy: proxy.into(),
        tool: "fortio".into(),
        environment: crate::result::current_environment(),
        latency: crate::result::LatencyMetrics {
            min: hist.min,
            max: hist.max,
            mean: hist.avg,
            p50: lookup_percentile(pctiles, 50.0),
            p90: lookup_percentile(pctiles, 90.0),
            p95: lookup_percentile(pctiles, 95.0),
            p99: lookup_percentile(pctiles, 99.0),
            p99_9: lookup_percentile(pctiles, 99.9),
        },
        throughput: crate::result::ThroughputMetrics {
            requests_per_sec: report.actual_qps,
            bytes_per_sec,
        },
        resource: None,
        errors: crate::result::ErrorMetrics {
            non_2xx,
            timeouts: 0,
            connect_failures: 0,
        },
        raw_report,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a list of [`FortioPercentile`] entries for testing.
    fn sample_percentiles() -> Vec<FortioPercentile> {
        vec![
            FortioPercentile {
                percentile: 50.0,
                value: 0.005,
            },
            FortioPercentile {
                percentile: 75.0,
                value: 0.010,
            },
            FortioPercentile {
                percentile: 90.0,
                value: 0.020,
            },
            FortioPercentile {
                percentile: 99.0,
                value: 0.050,
            },
            FortioPercentile {
                percentile: 99.9,
                value: 0.090,
            },
        ]
    }

    #[test]
    fn lookup_percentile_exact_match() {
        let pctiles = sample_percentiles();
        let val = lookup_percentile(&pctiles, 90.0);
        assert!(
            (val - 0.020).abs() < 1e-9,
            "exact match at p90 should return 0.020, got {val}"
        );
    }

    #[test]
    fn lookup_percentile_interpolation() {
        let pctiles = sample_percentiles();
        let val = lookup_percentile(&pctiles, 82.5);
        let expected = 0.010 + (82.5 - 75.0) / (90.0 - 75.0) * (0.020 - 0.010);
        assert!(
            (val - expected).abs() < 1e-9,
            "interpolated p82.5 should be {expected}, got {val}"
        );
    }

    #[test]
    fn lookup_percentile_empty_input() {
        let val = lookup_percentile(&[], 50.0);
        assert!(
            (val - 0.0).abs() < 1e-9,
            "empty percentile list should return 0.0, got {val}"
        );
    }

    #[test]
    fn lookup_percentile_below_range() {
        let pctiles = sample_percentiles();
        let val = lookup_percentile(&pctiles, 10.0);
        assert!(
            (val - 0.005).abs() < 1e-9,
            "percentile below range should return first value, got {val}"
        );
    }

    #[test]
    fn lookup_percentile_above_range() {
        let pctiles = sample_percentiles();
        let val = lookup_percentile(&pctiles, 99.99);
        assert!(
            (val - 0.090).abs() < 1e-9,
            "percentile above range should return last value, got {val}"
        );
    }

    #[test]
    fn parse_minimal_fortio_json() {
        let json = r#"{
            "DurationHistogram": {
                "Percentiles": [
                    {"Percentile": 50.0, "Value": 0.001},
                    {"Percentile": 90.0, "Value": 0.002},
                    {"Percentile": 99.0, "Value": 0.005},
                    {"Percentile": 99.9, "Value": 0.008}
                ],
                "Avg": 0.0015,
                "Min": 0.0005,
                "Max": 0.010,
                "Count": 1000
            },
            "ActualQPS": 5000.0,
            "BytesSent": 50000,
            "BytesReceived": 200000,
            "RetCodes": {"200": 990, "503": 10},
            "ActualDuration": 1000000000.0
        }"#;

        let result = parse(json, "test-scenario", "praxis", "abc123", false).expect("should parse valid fortio JSON");

        assert_eq!(result.scenario, "test-scenario", "scenario mismatch");
        assert_eq!(result.proxy, "praxis", "proxy mismatch");
        assert_eq!(result.commit, "abc123", "commit mismatch");
        assert_eq!(result.tool, "fortio", "tool mismatch");

        assert!(
            (result.latency.min - 0.0005).abs() < 1e-9,
            "latency min should be 0.0005, got {}",
            result.latency.min
        );
        assert!(
            (result.latency.max - 0.010).abs() < 1e-9,
            "latency max should be 0.010, got {}",
            result.latency.max
        );
        assert!(
            (result.latency.mean - 0.0015).abs() < 1e-9,
            "latency mean should be 0.0015, got {}",
            result.latency.mean
        );
        assert!(
            (result.latency.p50 - 0.001).abs() < 1e-9,
            "latency p50 should be 0.001, got {}",
            result.latency.p50
        );
        assert!(
            (result.latency.p90 - 0.002).abs() < 1e-9,
            "latency p90 should be 0.002, got {}",
            result.latency.p90
        );
        assert!(
            (result.latency.p99 - 0.005).abs() < 1e-9,
            "latency p99 should be 0.005, got {}",
            result.latency.p99
        );

        assert!(
            (result.throughput.requests_per_sec - 5000.0).abs() < 1e-3,
            "throughput should be 5000.0, got {}",
            result.throughput.requests_per_sec
        );

        let expected_bps = 250_000.0 / 1.0;
        assert!(
            (result.throughput.bytes_per_sec - expected_bps).abs() < 1e-3,
            "bytes_per_sec should be {expected_bps}, got {}",
            result.throughput.bytes_per_sec
        );

        assert_eq!(result.errors.non_2xx, Some(10), "non_2xx should be 10 (503 responses)");
        assert!(
            result.raw_report.is_none(),
            "raw_report should be None when include_raw=false"
        );
    }

    #[test]
    fn parse_with_include_raw() {
        let json = r#"{
            "DurationHistogram": {
                "Percentiles": [],
                "Avg": 0.001,
                "Min": 0.0005,
                "Max": 0.010,
                "Count": 100
            },
            "ActualQPS": 1000.0,
            "ActualDuration": 1000000000.0
        }"#;

        let result = parse(json, "raw-test", "praxis", "def456", true).expect("should parse with include_raw");
        assert!(
            result.raw_report.is_some(),
            "raw_report should be Some when include_raw=true"
        );
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse("not valid json", "test", "praxis", "abc", false);
        assert!(result.is_err(), "invalid JSON should return an error");
        let err = result.unwrap_err();
        match err {
            BenchmarkError::ParseError { tool, .. } => {
                assert_eq!(tool, "fortio", "parse error should reference fortio");
            },
            other => panic!("expected ParseError, got: {other}"),
        }
    }
}
