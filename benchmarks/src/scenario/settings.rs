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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn workload_params_small_requests() {
        let params = workload_params(&Workload::SmallRequests { concurrency: 64 });
        assert_eq!(
            params.get("concurrency").and_then(serde_json::Value::as_u64),
            Some(64),
            "SmallRequests should emit concurrency"
        );
        assert_eq!(params.len(), 1, "SmallRequests should emit exactly one param");
    }

    #[test]
    fn workload_params_large_payload() {
        let params = workload_params(&Workload::LargePayload { body_size: 8192 });
        assert_eq!(
            params.get("body_size").and_then(serde_json::Value::as_u64),
            Some(8192),
            "LargePayload should emit body_size"
        );
        assert_eq!(params.len(), 1, "LargePayload should emit exactly one param");
    }

    #[test]
    fn workload_params_large_payload_high_concurrency() {
        let params = workload_params(&Workload::LargePayloadHighConcurrency {
            concurrency: 50,
            body_size: 4096,
        });
        assert_eq!(
            params.get("concurrency").and_then(serde_json::Value::as_u64),
            Some(50),
            "should emit concurrency"
        );
        assert_eq!(
            params.get("body_size").and_then(serde_json::Value::as_u64),
            Some(4096),
            "should emit body_size"
        );
        assert_eq!(params.len(), 2, "should emit exactly two params");
    }

    #[test]
    fn workload_params_high_connection_count() {
        let params = workload_params(&Workload::HighConnectionCount { connections: 5000 });
        assert_eq!(
            params.get("connections").and_then(serde_json::Value::as_u64),
            Some(5000),
            "HighConnectionCount should emit connections"
        );
        assert_eq!(params.len(), 1, "should emit exactly one param");
    }

    #[test]
    fn workload_params_ramp() {
        let params = workload_params(&Workload::Ramp {
            start_qps: 100,
            end_qps: 10_000,
            step: 500,
        });
        assert_eq!(
            params.get("start_qps").and_then(serde_json::Value::as_u64),
            Some(100),
            "Ramp should emit start_qps"
        );
        assert_eq!(
            params.get("end_qps").and_then(serde_json::Value::as_u64),
            Some(10_000),
            "Ramp should emit end_qps"
        );
        assert_eq!(
            params.get("step").and_then(serde_json::Value::as_u64),
            Some(500),
            "Ramp should emit step"
        );
        assert_eq!(params.len(), 3, "Ramp should emit exactly three params");
    }

    #[test]
    fn workload_params_unit_variants_are_empty() {
        for workload in [
            Workload::Sustained,
            Workload::TcpThroughput,
            Workload::TcpConnectionRate,
        ] {
            let params = workload_params(&workload);
            assert!(params.is_empty(), "{workload:?} should emit no params");
        }
    }

    #[test]
    fn scenario_settings_from_scenario() {
        let scenario = Scenario {
            name: "test-run".to_owned(),
            workload: Workload::SmallRequests { concurrency: 200 },
            warmup: Duration::from_secs(10),
            duration: Duration::from_secs(60),
            runs: 3,
        };
        let settings = ScenarioSettings::from_scenario(&scenario);
        assert_eq!(settings.warmup_secs, 10, "warmup_secs should match scenario");
        assert_eq!(settings.duration_secs, 60, "duration_secs should match scenario");
        assert_eq!(settings.runs, 3, "runs should match scenario");
        assert_eq!(
            settings.workload.get("concurrency").and_then(serde_json::Value::as_u64),
            Some(200),
            "workload params should be populated"
        );
    }

    #[test]
    fn scenario_settings_serialize_roundtrip() {
        let settings = ScenarioSettings::from_scenario(&Scenario::default());
        let json = serde_json::to_string(&settings).expect("serialization should succeed");
        let roundtripped: ScenarioSettings = serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(roundtripped.warmup_secs, settings.warmup_secs, "warmup_secs roundtrip");
        assert_eq!(
            roundtripped.duration_secs, settings.duration_secs,
            "duration_secs roundtrip"
        );
        assert_eq!(roundtripped.runs, settings.runs, "runs roundtrip");
    }

    #[test]
    fn settings_map_keys_are_scenario_names() {
        let scenarios = vec![
            Scenario {
                name: "alpha".to_owned(),
                ..Scenario::default()
            },
            Scenario {
                name: "beta".to_owned(),
                workload: Workload::Sustained,
                ..Scenario::default()
            },
        ];
        let map = settings_map(&scenarios);
        assert_eq!(map.len(), 2, "map should have one entry per scenario");
        assert!(map.contains_key("alpha"), "map should contain 'alpha'");
        assert!(map.contains_key("beta"), "map should contain 'beta'");
    }

    #[test]
    fn settings_map_empty_input() {
        let map = settings_map(&[]);
        assert!(map.is_empty(), "empty input should produce empty map");
    }
}
