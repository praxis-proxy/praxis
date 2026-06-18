// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Serializable scenario settings for benchmark reports.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Scenario, Workload};

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
        Self {
            warmup_secs: s.warmup.as_secs(),
            duration_secs: s.duration.as_secs(),
            runs: s.runs,
            workload: workload_params(&s.workload),
        }
    }
}

/// Extract workload-specific parameters into a map.
fn workload_params(workload: &Workload) -> BTreeMap<String, serde_json::Value> {
    let mut params = BTreeMap::new();
    match workload {
        Workload::SmallRequests { concurrency } => {
            params.insert("concurrency".into(), (*concurrency).into());
        },
        Workload::LargePayload { body_size } => {
            params.insert("body_size".into(), (*body_size).into());
        },
        Workload::LargePayloadHighConcurrency { concurrency, body_size } => {
            params.insert("concurrency".into(), (*concurrency).into());
            params.insert("body_size".into(), (*body_size).into());
        },
        Workload::HighConnectionCount { connections } => {
            params.insert("connections".into(), (*connections).into());
        },
        Workload::Ramp {
            start_qps,
            end_qps,
            step,
        } => {
            params.insert("start_qps".into(), (*start_qps).into());
            params.insert("end_qps".into(), (*end_qps).into());
            params.insert("step".into(), (*step).into());
        },
        Workload::Sustained | Workload::TcpThroughput | Workload::TcpConnectionRate => {},
    }
    params
}

/// Build a settings map from a list of scenarios.
pub fn settings_map(scenarios: &[Scenario]) -> BTreeMap<String, ScenarioSettings> {
    scenarios
        .iter()
        .map(|s| (s.name.clone(), ScenarioSettings::from_scenario(s)))
        .collect()
}
