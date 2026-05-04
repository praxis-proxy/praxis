// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration for the circuit breaker filter.

use std::sync::Arc;

use serde::Deserialize;

// -----------------------------------------------------------------------------
// CircuitBreakerConfig
// -----------------------------------------------------------------------------

/// Top-level circuit breaker filter config.
///
/// ```
/// # use serde::Deserialize;
/// let yaml = r#"
/// clusters:
///   - name: backend
///     consecutive_failures: 5
///     recovery_window_secs: 30
/// "#;
/// #[derive(Deserialize)]
/// struct Cfg {
///     clusters: Vec<serde_yaml::Value>,
/// }
/// let cfg: Cfg = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(cfg.clusters.len(), 1);
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CircuitBreakerConfig {
    /// Per-cluster circuit breaker settings.
    pub clusters: Vec<ClusterCircuitBreakerConfig>,
}

// -----------------------------------------------------------------------------
// ClusterCircuitBreakerConfig
// -----------------------------------------------------------------------------

/// Circuit breaker settings for a single cluster.
///
/// ```
/// # use std::sync::Arc;
/// # use serde::Deserialize;
/// #[derive(Deserialize)]
/// struct Entry {
///     name: Arc<str>,
///     consecutive_failures: u32,
///     recovery_window_secs: u64,
/// }
/// let yaml = r#"
/// name: backend
/// consecutive_failures: 5
/// recovery_window_secs: 30
/// "#;
/// let e: Entry = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(&*e.name, "backend");
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterCircuitBreakerConfig {
    /// Cluster name (must match a cluster in the load balancer).
    pub name: Arc<str>,

    /// Number of consecutive upstream failures before the
    /// circuit trips to Open.
    pub consecutive_failures: u32,

    /// Seconds the circuit stays Open before transitioning
    /// to Half-Open.
    pub recovery_window_secs: u64,
}
