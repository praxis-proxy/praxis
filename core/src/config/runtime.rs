// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Runtime tuning: worker thread count, work-stealing toggle, logging overrides, and upstream CA.

use std::collections::HashMap;

use serde::Deserialize;

// -----------------------------------------------------------------------------
// RuntimeConfig
// -----------------------------------------------------------------------------

/// Configuration for the runtime of the proxy server.
///
/// ```
/// use praxis_core::config::RuntimeConfig;
///
/// let cfg = RuntimeConfig::default();
/// assert_eq!(cfg.threads, 0);
/// assert!(cfg.work_stealing);
/// assert_eq!(cfg.global_queue_interval, Some(61));
/// assert!(cfg.log_overrides.is_empty());
/// assert_eq!(cfg.upstream_keepalive_pool_size, Some(64));
/// assert!(cfg.upstream_ca_file.is_none());
///
/// let cfg: RuntimeConfig = serde_yaml::from_str("threads: 4\nwork_stealing: true").unwrap();
/// assert_eq!(cfg.threads, 4);
/// assert!(cfg.work_stealing);
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Number of worker threads per service.
    ///
    /// Auto-detected by default.
    #[serde(default)]
    pub threads: usize,

    /// Allow work-stealing between worker threads of the same service.
    #[serde(default = "default_work_stealing")]
    pub work_stealing: bool,

    /// Per-module log level overrides.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let yaml = r#"
    /// log_overrides:
    ///   praxis_filter::pipeline: trace
    ///   praxis_protocol: debug
    /// "#;
    /// let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
    /// assert_eq!(cfg.log_overrides.len(), 2);
    /// assert_eq!(cfg.log_overrides["praxis_filter::pipeline"], "trace");
    /// ```
    #[serde(default)]
    pub log_overrides: HashMap<String, String>,

    /// Fixed global queue interval for the tokio scheduler.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert_eq!(cfg.global_queue_interval, Some(61));
    ///
    /// let cfg: RuntimeConfig = serde_yaml::from_str("global_queue_interval: 128").unwrap();
    /// assert_eq!(cfg.global_queue_interval, Some(128));
    /// ```
    #[serde(default = "default_global_queue_interval")]
    pub global_queue_interval: Option<u32>,

    /// Path to a PEM CA file used as the root certificate store for all upstream TLS connections.
    ///
    /// When set, this **replaces** the system trust store (not additive). If backends
    /// use both a private CA and public CAs, create a combined PEM bundle containing
    /// all required root certificates.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg: RuntimeConfig =
    ///     serde_yaml::from_str("upstream_ca_file: /etc/praxis/ca-bundle.pem").unwrap();
    /// assert_eq!(
    ///     cfg.upstream_ca_file.as_deref(),
    ///     Some("/etc/praxis/ca-bundle.pem")
    /// );
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert!(cfg.upstream_ca_file.is_none());
    /// ```
    #[serde(default)]
    pub upstream_ca_file: Option<String>,

    /// Maximum number of idle upstream connections kept per thread.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert_eq!(cfg.upstream_keepalive_pool_size, Some(64));
    ///
    /// let cfg: RuntimeConfig = serde_yaml::from_str("upstream_keepalive_pool_size: 32").unwrap();
    /// assert_eq!(cfg.upstream_keepalive_pool_size, Some(32));
    /// ```
    #[serde(default = "default_upstream_keepalive_pool_size")]
    pub upstream_keepalive_pool_size: Option<usize>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            work_stealing: default_work_stealing(),
            global_queue_interval: default_global_queue_interval(),
            log_overrides: HashMap::new(),
            upstream_ca_file: None,
            upstream_keepalive_pool_size: default_upstream_keepalive_pool_size(),
        }
    }
}

/// Serde default for [`RuntimeConfig::work_stealing`].
fn default_work_stealing() -> bool {
    true
}

/// Serde default for [`RuntimeConfig::upstream_keepalive_pool_size`].
#[allow(clippy::unnecessary_wraps, reason = "serde default")]
fn default_upstream_keepalive_pool_size() -> Option<usize> {
    Some(64)
}

/// Serde default for [`RuntimeConfig::global_queue_interval`].
#[allow(clippy::unnecessary_wraps, reason = "serde default")]
fn default_global_queue_interval() -> Option<u32> {
    Some(61)
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
    fn default_has_zero_threads_and_work_stealing_true() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.threads, 0, "default threads should be 0");
        assert!(cfg.work_stealing, "default work_stealing should be true");
    }

    #[test]
    fn deserialise_empty_yaml_gives_defaults() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.threads, 0, "empty yaml should give 0 threads");
        assert!(cfg.work_stealing, "empty yaml should give work_stealing=true");
    }

    #[test]
    fn deserialise_explicit_threads() {
        let cfg: RuntimeConfig = serde_yaml::from_str("threads: 4").unwrap();
        assert_eq!(cfg.threads, 4, "explicit threads should be preserved");
        assert!(cfg.work_stealing, "unset work_stealing should default to true");
    }

    #[test]
    fn deserialise_work_stealing_disabled() {
        let cfg: RuntimeConfig = serde_yaml::from_str("work_stealing: false").unwrap();
        assert_eq!(cfg.threads, 0, "unset threads should default to 0");
        assert!(!cfg.work_stealing, "explicit work_stealing=false should be preserved");
    }

    #[test]
    fn deserialise_all_fields() {
        let yaml = "threads: 8\nwork_stealing: true";
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.threads, 8, "threads should be 8");
        assert!(cfg.work_stealing, "work_stealing should be true");
    }

    #[test]
    fn deserialise_log_overrides() {
        let yaml = r#"
log_overrides:
  praxis_filter::pipeline: trace
  praxis_protocol: debug
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.log_overrides.len(), 2, "should have 2 log overrides");
        assert_eq!(
            cfg.log_overrides["praxis_filter::pipeline"], "trace",
            "pipeline override mismatch"
        );
        assert_eq!(
            cfg.log_overrides["praxis_protocol"], "debug",
            "protocol override mismatch"
        );
    }

    #[test]
    fn default_log_overrides_is_empty() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();
        assert!(cfg.log_overrides.is_empty(), "log_overrides should default to empty");
    }

    #[test]
    fn global_queue_interval_defaults_to_61() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.global_queue_interval, Some(61), "default interval should be 61");
    }

    #[test]
    fn deserialise_global_queue_interval() {
        let cfg: RuntimeConfig = serde_yaml::from_str("global_queue_interval: 128").unwrap();
        assert_eq!(cfg.global_queue_interval, Some(128), "explicit interval should be 128");
    }

    #[test]
    fn deserialise_global_queue_interval_null() {
        let cfg: RuntimeConfig = serde_yaml::from_str("global_queue_interval: null").unwrap();
        assert!(cfg.global_queue_interval.is_none(), "null interval should be None");
    }

    #[test]
    fn upstream_keepalive_pool_size_defaults_to_64() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(
            cfg.upstream_keepalive_pool_size,
            Some(64),
            "default pool size should be 64"
        );
    }

    #[test]
    fn deserialise_upstream_keepalive_pool_size() {
        let cfg: RuntimeConfig = serde_yaml::from_str("upstream_keepalive_pool_size: 64").unwrap();
        assert_eq!(
            cfg.upstream_keepalive_pool_size,
            Some(64),
            "explicit pool size should be 64"
        );
    }

    #[test]
    fn upstream_ca_file_defaults_to_none() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            cfg.upstream_ca_file.is_none(),
            "upstream_ca_file should default to None"
        );
    }

    #[test]
    fn deserialise_upstream_ca_file() {
        let cfg: RuntimeConfig = serde_yaml::from_str("upstream_ca_file: /etc/ssl/ca.pem").unwrap();
        assert_eq!(
            cfg.upstream_ca_file.as_deref(),
            Some("/etc/ssl/ca.pem"),
            "explicit upstream_ca_file should be preserved"
        );
    }
}
