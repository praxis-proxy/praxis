// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Scenario definition and configuration.
//!
//! A `Scenario` describes a benchmark workload: which proxies
//! to test, what traffic pattern to generate, and how many runs
//! to perform.

mod settings;
mod workload;

use std::time::Duration;

pub use settings::{ScenarioSettings, settings_map};
pub use workload::Workload;

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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_defaults() {
        let s = Scenario::default();
        assert_eq!(s.warmup, Duration::from_secs(30));
        assert_eq!(s.duration, Duration::from_secs(120));
        assert_eq!(s.runs, 5);
    }
}
