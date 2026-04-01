//! Scenario definition and configuration.
//!
//! A [`Scenario`] describes a benchmark workload: which proxies
//! to test, what traffic pattern to generate, and how many runs
//! to perform.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Workload
// -----------------------------------------------------------------------------

/// Traffic pattern for a benchmark scenario.
#[derive(Debug, Clone)]
pub enum Workload {
    /// High-concurrency small GET requests.
    SmallRequests {
        /// Number of concurrent connections.
        concurrency: u32,
    },

    /// Large POST requests.
    LargePayload {
        /// Payload size in bytes.
        body_size: usize,
    },

    /// Large POST requests at high concurrency.
    LargePayloadHighConcurrency {
        /// Number of concurrent connections.
        concurrency: u32,
        /// Payload size for requests in bytes.
        body_size: usize,
    },

    /// High connection count HTTP/1.1 stress test.
    HighConnectionCount {
        /// Number of concurrent connections.
        connections: u32,
    },

    /// Sustained load for leak detection.
    ///
    /// Duration is controlled by the parent [`Scenario`].
    Sustained,

    /// Ramp-up from low to high QPS.
    Ramp {
        /// Starting requests per second.
        start_qps: u32,
        /// Ending requests per second.
        end_qps: u32,
        /// Step size between ramp levels.
        step: u32,
    },

    /// Raw TCP throughput via Fortio.
    TcpThroughput,

    /// TCP connection rate (new connection per request).
    TcpConnectionRate,
}

// -----------------------------------------------------------------------------
// Scenario
// -----------------------------------------------------------------------------

/// Configuration for a benchmark scenario.
///
/// ```
/// use benchmarks::scenario::Scenario;
///
/// let s = Scenario::default();
/// assert_eq!(s.runs, 5);
/// assert_eq!(s.warmup.as_secs(), 30);
/// ```
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Human-readable scenario name.
    pub name: String,

    /// Traffic pattern to generate.
    pub workload: Workload,

    /// Warmup duration before measurement.
    pub warmup: Duration,

    /// Measurement duration per run.
    pub duration: Duration,

    /// Number of runs (median is reported).
    pub runs: u32,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            name: String::new(),
            workload: Workload::SmallRequests { concurrency: 100 },
            warmup: Duration::from_secs(30),
            duration: Duration::from_secs(120),
            runs: 5,
        }
    }
}

// -----------------------------------------------------------------------------
// ScenarioSettings
// -----------------------------------------------------------------------------

/// Serializable snapshot of a scenario's configuration.
///
/// Included in benchmark reports so runs are reproducible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSettings {
    /// Warmup duration in seconds.
    pub warmup_secs: u64,

    /// Measurement duration in seconds.
    pub duration_secs: u64,

    /// Number of runs.
    pub runs: u32,

    /// Workload-specific parameters.
    #[serde(flatten)]
    pub workload: BTreeMap<String, serde_json::Value>,
}

impl ScenarioSettings {
    /// Build settings from a [`Scenario`].
    pub fn from_scenario(s: &Scenario) -> Self {
        let mut workload = BTreeMap::new();
        match &s.workload {
            Workload::SmallRequests { concurrency } => {
                workload.insert("concurrency".into(), (*concurrency).into());
            },
            Workload::LargePayload { body_size } => {
                workload.insert("body_size".into(), (*body_size).into());
            },
            Workload::LargePayloadHighConcurrency { concurrency, body_size } => {
                workload.insert("concurrency".into(), (*concurrency).into());
                workload.insert("body_size".into(), (*body_size).into());
            },
            Workload::HighConnectionCount { connections } => {
                workload.insert("connections".into(), (*connections).into());
            },
            Workload::Ramp {
                start_qps,
                end_qps,
                step,
            } => {
                workload.insert("start_qps".into(), (*start_qps).into());
                workload.insert("end_qps".into(), (*end_qps).into());
                workload.insert("step".into(), (*step).into());
            },
            Workload::Sustained | Workload::TcpThroughput | Workload::TcpConnectionRate => {},
        }
        Self {
            warmup_secs: s.warmup.as_secs(),
            duration_secs: s.duration.as_secs(),
            runs: s.runs,
            workload,
        }
    }
}

/// Build a settings map from a list of scenarios.
pub fn settings_map(scenarios: &[Scenario]) -> BTreeMap<String, ScenarioSettings> {
    scenarios
        .iter()
        .map(|s| (s.name.clone(), ScenarioSettings::from_scenario(s)))
        .collect()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that [`Scenario`] defaults are sensible.
    #[test]
    fn scenario_defaults() {
        let s = Scenario::default();
        assert_eq!(s.warmup, Duration::from_secs(30));
        assert_eq!(s.duration, Duration::from_secs(120));
        assert_eq!(s.runs, 5);
    }
}
