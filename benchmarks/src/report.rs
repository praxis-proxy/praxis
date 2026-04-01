//! Top-level benchmark report for serialization.
//!
//! [`BenchmarkReport`] wraps all scenario results.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    result::{ComparativeResults, ScenarioResults},
    scenario::ScenarioSettings,
};

// -----------------------------------------------------------------------------
// BenchmarkReport
// -----------------------------------------------------------------------------

/// Top-level benchmark report combining all results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// ISO 8601 timestamp of the report.
    pub timestamp: String,

    /// Git commit SHA.
    pub commit: String,

    /// List of proxy names tested.
    pub proxies: Vec<String>,

    /// Scenario configurations used for this run.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, ScenarioSettings>,

    /// Results for each scenario/proxy combination.
    pub results: Vec<ScenarioResults>,

    /// Comparative results (when multiple proxies are tested)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparisons: Vec<ComparativeResults>,
}
