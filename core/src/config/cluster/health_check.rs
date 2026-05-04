// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Health check configuration for upstream clusters.

use std::fmt;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// HealthCheckType
// -----------------------------------------------------------------------------

/// Supported health check probe types.
///
/// ```
/// use praxis_core::config::HealthCheckType;
///
/// let http: HealthCheckType = serde_yaml::from_str("http").unwrap();
/// assert!(matches!(http, HealthCheckType::Http));
///
/// let tcp: HealthCheckType = serde_yaml::from_str("tcp").unwrap();
/// assert!(matches!(tcp, HealthCheckType::Tcp));
///
/// let grpc: HealthCheckType = serde_yaml::from_str("grpc").unwrap();
/// assert!(matches!(grpc, HealthCheckType::Grpc));
///
/// let bad: Result<HealthCheckType, _> = serde_yaml::from_str("websocket");
/// assert!(bad.is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckType {
    /// HTTP GET probe.
    Http,
    /// TCP connect probe.
    Tcp,
    /// gRPC health check (not yet supported).
    Grpc,
}

impl fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => f.write_str("http"),
            Self::Tcp => f.write_str("tcp"),
            Self::Grpc => f.write_str("grpc"),
        }
    }
}

// -----------------------------------------------------------------------------
// HealthCheckConfig
// -----------------------------------------------------------------------------

/// Per-cluster health check settings (active and passive).
///
/// Active checking configures periodic probing of upstream
/// endpoints. Passive checking observes real request outcomes
/// (5xx responses, connection errors) to update health state.
///
/// ```
/// # use praxis_core::config::{HealthCheckConfig, HealthCheckType};
/// let yaml = r#"
/// type: http
/// path: "/healthz"
/// expected_status: 200
/// interval_ms: 5000
/// timeout_ms: 2000
/// healthy_threshold: 2
/// unhealthy_threshold: 3
/// passive_unhealthy_threshold: 5
/// passive_healthy_threshold: 3
/// "#;
/// let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(hc.check_type, HealthCheckType::Http);
/// assert_eq!(hc.path, "/healthz");
/// assert_eq!(hc.interval_ms, 5000);
/// assert_eq!(hc.passive_unhealthy_threshold, Some(5));
/// assert_eq!(hc.passive_healthy_threshold, Some(3));
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Probe type: [`Http`], [`Tcp`], or [`Grpc`].
    ///
    /// [`Http`]: HealthCheckType::Http
    /// [`Tcp`]: HealthCheckType::Tcp
    /// [`Grpc`]: HealthCheckType::Grpc
    #[serde(rename = "type")]
    pub check_type: HealthCheckType,

    /// Expected HTTP status code for a healthy response.
    #[serde(default = "default_expected_status")]
    pub expected_status: u16,

    /// Consecutive successes required to mark an endpoint healthy.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Probe interval in milliseconds.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,

    /// Consecutive successes to mark an endpoint healthy again
    /// via passive observation. `None` disables passive recovery
    /// (active checks must recover it).
    #[serde(default)]
    pub passive_healthy_threshold: Option<u32>,

    /// Consecutive response failures (5xx or connect error) to
    /// mark an endpoint unhealthy via passive observation.
    /// `None` disables passive checking.
    #[serde(default)]
    pub passive_unhealthy_threshold: Option<u32>,

    /// HTTP path to probe (only used for `http` type).
    #[serde(default = "default_path")]
    pub path: String,

    /// Probe timeout in milliseconds. Must be less than `interval_ms`.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Consecutive failures required to mark an endpoint unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

/// Default HTTP probe path.
fn default_path() -> String {
    "/".to_owned()
}

/// Default expected HTTP status code.
fn default_expected_status() -> u16 {
    200
}

/// Default probe interval (5 seconds).
fn default_interval_ms() -> u64 {
    5000
}

/// Default probe timeout (2 seconds).
fn default_timeout_ms() -> u64 {
    2000
}

/// Default consecutive successes to mark healthy.
fn default_healthy_threshold() -> u32 {
    2
}

/// Default consecutive failures to mark unhealthy.
fn default_unhealthy_threshold() -> u32 {
    3
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let yaml = r#"
type: http
path: "/healthz"
expected_status: 200
interval_ms: 5000
timeout_ms: 2000
healthy_threshold: 2
unhealthy_threshold: 3
"#;
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(hc.check_type, HealthCheckType::Http, "type should be http");
        assert_eq!(hc.path, "/healthz", "path mismatch");
        assert_eq!(hc.expected_status, 200, "expected_status mismatch");
        assert_eq!(hc.interval_ms, 5000, "interval_ms mismatch");
        assert_eq!(hc.timeout_ms, 2000, "timeout_ms mismatch");
        assert_eq!(hc.healthy_threshold, 2, "healthy_threshold mismatch");
        assert_eq!(hc.unhealthy_threshold, 3, "unhealthy_threshold mismatch");
    }

    #[test]
    fn defaults_applied() {
        let yaml = "type: http\n";
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(hc.path, "/", "default path should be /");
        assert_eq!(hc.expected_status, 200, "default expected_status should be 200");
        assert_eq!(hc.interval_ms, 5000, "default interval_ms should be 5000");
        assert_eq!(hc.timeout_ms, 2000, "default timeout_ms should be 2000");
        assert_eq!(hc.healthy_threshold, 2, "default healthy_threshold should be 2");
        assert_eq!(hc.unhealthy_threshold, 3, "default unhealthy_threshold should be 3");
    }

    #[test]
    fn tcp_type_parses() {
        let yaml = "type: tcp\n";
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(hc.check_type, HealthCheckType::Tcp, "type should be tcp");
    }

    #[test]
    fn roundtrip_via_serde() {
        let hc = HealthCheckConfig {
            check_type: HealthCheckType::Http,
            expected_status: 204,
            healthy_threshold: 3,
            interval_ms: 10000,
            passive_healthy_threshold: Some(3),
            passive_unhealthy_threshold: Some(5),
            path: "/health".to_owned(),
            timeout_ms: 3000,
            unhealthy_threshold: 5,
        };
        let value = serde_yaml::to_value(&hc).unwrap();
        let back: HealthCheckConfig = serde_yaml::from_value(value).unwrap();
        assert_eq!(back.check_type, hc.check_type, "type should roundtrip");
        assert_eq!(back.path, hc.path, "path should roundtrip");
        assert_eq!(back.expected_status, hc.expected_status, "status should roundtrip");
        assert_eq!(back.interval_ms, hc.interval_ms, "interval should roundtrip");
        assert_eq!(back.timeout_ms, hc.timeout_ms, "timeout should roundtrip");
        assert_eq!(
            back.passive_unhealthy_threshold, hc.passive_unhealthy_threshold,
            "passive_unhealthy should roundtrip"
        );
        assert_eq!(
            back.passive_healthy_threshold, hc.passive_healthy_threshold,
            "passive_healthy should roundtrip"
        );
    }

    #[test]
    fn unknown_type_rejected_by_serde() {
        let yaml = "type: websocket\n";
        let result: Result<HealthCheckConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown type should be rejected by serde");
    }

    #[test]
    fn custom_expected_status() {
        let yaml = r#"
type: http
expected_status: 204
"#;
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(hc.expected_status, 204, "custom expected_status should be 204");
    }

    #[test]
    fn passive_thresholds_default_to_none() {
        let yaml = "type: http\n";
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            hc.passive_unhealthy_threshold, None,
            "passive_unhealthy_threshold should default to None"
        );
        assert_eq!(
            hc.passive_healthy_threshold, None,
            "passive_healthy_threshold should default to None"
        );
    }

    #[test]
    fn passive_thresholds_parse() {
        let yaml = r#"
type: http
passive_unhealthy_threshold: 5
passive_healthy_threshold: 3
"#;
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            hc.passive_unhealthy_threshold,
            Some(5),
            "passive_unhealthy_threshold mismatch"
        );
        assert_eq!(
            hc.passive_healthy_threshold,
            Some(3),
            "passive_healthy_threshold mismatch"
        );
    }

    #[test]
    fn passive_only_unhealthy_threshold() {
        let yaml = r#"
type: http
passive_unhealthy_threshold: 3
"#;
        let hc: HealthCheckConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            hc.passive_unhealthy_threshold,
            Some(3),
            "should parse passive_unhealthy_threshold alone"
        );
        assert_eq!(
            hc.passive_healthy_threshold, None,
            "passive_healthy_threshold should be None"
        );
    }
}
