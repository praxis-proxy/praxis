// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Runtime tuning: worker thread count, work-stealing toggle, logging
//! overrides, and upstream CA.
//!
//! [`RuntimeConfig`] controls Tokio and Pingora runtime parameters
//! that are fixed for the lifetime of the process (not hot-reloadable).
//! The server module reads these values once at startup to configure
//! the thread pool, upstream keepalive pool, and global CA trust.

use std::collections::HashMap;

use serde::Deserialize;

// -----------------------------------------------------------------------------
// SubRequestCircuitBreakerConfig
// -----------------------------------------------------------------------------

/// Circuit breaker settings for the shared sub-request connector.
///
/// When configured under `runtime.subrequest_circuit_breaker`, the
/// shared connector tracks consecutive failures per upstream peer
/// and rejects sub-requests while a peer's circuit is open.
///
/// ```
/// use praxis_core::config::runtime::SubRequestCircuitBreakerConfig;
///
/// let yaml = r#"
/// consecutive_failures: 5
/// recovery_window_secs: 30
/// "#;
/// let cfg: SubRequestCircuitBreakerConfig = serde_yaml::from_str(yaml).unwrap();
/// assert_eq!(cfg.consecutive_failures, 5);
/// assert_eq!(cfg.recovery_window_secs, 30);
/// assert_eq!(cfg.half_open_timeout_secs, 30);
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubRequestCircuitBreakerConfig {
    /// Consecutive failure threshold before the circuit opens.
    pub consecutive_failures: u32,

    /// Seconds the circuit stays open before allowing a probe.
    pub recovery_window_secs: u64,

    /// Seconds a half-open probe may remain in-flight before
    /// the circuit resets to open. Defaults to 30.
    #[serde(default = "default_half_open_timeout_secs")]
    pub half_open_timeout_secs: u64,
}

/// Default half-open timeout (30 seconds).
const fn default_half_open_timeout_secs() -> u64 {
    30
}

impl SubRequestCircuitBreakerConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `consecutive_failures`,
    /// `recovery_window_secs`, or `half_open_timeout_secs` is zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.consecutive_failures == 0 {
            return Err("subrequest_circuit_breaker: consecutive_failures must be > 0".to_owned());
        }
        if self.recovery_window_secs == 0 {
            return Err("subrequest_circuit_breaker: recovery_window_secs must be > 0".to_owned());
        }
        if self.half_open_timeout_secs == 0 {
            return Err("subrequest_circuit_breaker: half_open_timeout_secs must be > 0".to_owned());
        }
        Ok(())
    }
}

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
/// assert_eq!(cfg.subrequest_pool_size, Some(128));
/// assert_eq!(cfg.upstream_keepalive_pool_size, Some(64));
/// assert!(cfg.upstream_ca_file.is_none());
///
/// let cfg: RuntimeConfig = serde_yaml::from_str("threads: 4\nwork_stealing: true").unwrap();
/// assert_eq!(cfg.threads, 4);
/// assert!(cfg.work_stealing);
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Tokio scheduler global queue check interval, in ticks.
    ///
    /// Controls how often worker threads check the global task
    /// queue. The default of 61 (a prime) reduces contention
    /// under proxy workloads where most tasks are I/O-bound.
    /// Set to `null` to use the tokio default. Valid range is
    /// any positive `u32`.
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

    /// Process log destination, rotation, retention, and buffering.
    #[serde(default)]
    pub logging: super::logging::LoggingConfig,

    /// Process-wide maximum concurrent connections across all
    /// listeners (both HTTP and TCP).
    ///
    /// When set, new connections beyond this limit are rejected
    /// with HTTP 503 (or TCP close for non-HTTP listeners),
    /// regardless of per-listener limits. Connections are shed
    /// before filter pipeline execution. `None` (the default)
    /// means no global limit.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg: RuntimeConfig = serde_yaml::from_str("max_connections: 10000").unwrap();
    /// assert_eq!(cfg.max_connections, Some(10_000));
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert!(cfg.max_connections.is_none());
    /// ```
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// Maximum resident memory (RSS) in bytes before shedding load.
    ///
    /// When set, Praxis monitors process RSS and rejects new
    /// requests with 503 when the threshold is exceeded. `None`
    /// (the default) disables memory pressure monitoring.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg: RuntimeConfig = serde_yaml::from_str("max_memory_bytes: 1073741824").unwrap();
    /// assert_eq!(cfg.max_memory_bytes, Some(1_073_741_824));
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert!(cfg.max_memory_bytes.is_none());
    /// ```
    #[serde(default)]
    pub max_memory_bytes: Option<usize>,

    /// Per-peer circuit breaker for the shared sub-request connector.
    ///
    /// When configured, the connector tracks consecutive failures
    /// per upstream `SocketAddr` and rejects sub-requests while
    /// a peer's circuit is open. See
    /// [`SubRequestCircuitBreakerConfig`] for field descriptions.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let yaml = r#"
    /// subrequest_circuit_breaker:
    ///   consecutive_failures: 5
    ///   recovery_window_secs: 30
    /// "#;
    /// let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
    /// assert!(cfg.subrequest_circuit_breaker.is_some());
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert!(cfg.subrequest_circuit_breaker.is_none());
    /// ```
    #[serde(default)]
    pub subrequest_circuit_breaker: Option<SubRequestCircuitBreakerConfig>,

    /// Maximum concurrently active sub-request exchanges across
    /// all `iterative_request_router` instances.
    ///
    /// When set, a semaphore limits the number of in-flight
    /// exchanges. Requests that cannot acquire a permit within
    /// their step timeout produce an admission-timeout error.
    /// `None` (the default) means no concurrency limit.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg: RuntimeConfig = serde_yaml::from_str("subrequest_max_connections: 256").unwrap();
    /// assert_eq!(cfg.subrequest_max_connections, Some(256));
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert!(cfg.subrequest_max_connections.is_none());
    /// ```
    #[serde(default)]
    pub subrequest_max_connections: Option<usize>,

    /// Maximum idle connections in the sub-request connection pool
    /// used by `iterative_request_router` step chains.
    ///
    /// ```
    /// use praxis_core::config::RuntimeConfig;
    ///
    /// let cfg = RuntimeConfig::default();
    /// assert_eq!(cfg.subrequest_pool_size, Some(128));
    /// ```
    #[serde(default = "default_subrequest_pool_size")]
    pub subrequest_pool_size: Option<usize>,

    /// Number of worker threads per service.
    ///
    /// `0` (the default) auto-detects based on available CPU
    /// cores. Values above the CPU count are valid but yield
    /// diminishing returns for I/O-bound workloads.
    #[serde(default)]
    pub threads: usize,

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

    /// Maximum number of idle upstream connections kept per worker
    /// thread, shared across all clusters.
    ///
    /// When a worker's pool is full, the oldest idle connection
    /// is evicted. Set to `null` to use Pingora's built-in
    /// default. This is a per-thread limit, not per-cluster.
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

    /// Allow work-stealing between worker threads of the same service.
    #[serde(default = "default_work_stealing")]
    pub work_stealing: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_memory_bytes: None,
            subrequest_circuit_breaker: None,
            subrequest_max_connections: None,
            subrequest_pool_size: default_subrequest_pool_size(),
            threads: 0,
            work_stealing: default_work_stealing(),
            global_queue_interval: default_global_queue_interval(),
            log_overrides: HashMap::new(),
            logging: super::logging::LoggingConfig::default(),
            upstream_ca_file: None,
            upstream_keepalive_pool_size: default_upstream_keepalive_pool_size(),
        }
    }
}

/// Serde default for [`RuntimeConfig::work_stealing`].
fn default_work_stealing() -> bool {
    true
}

/// Default sub-request connection pool size.
pub const DEFAULT_SUBREQUEST_POOL_SIZE: usize = 128;

/// Serde default for [`RuntimeConfig::subrequest_pool_size`].
#[expect(clippy::unnecessary_wraps, reason = "serde default")]
fn default_subrequest_pool_size() -> Option<usize> {
    Some(DEFAULT_SUBREQUEST_POOL_SIZE)
}

/// Serde default for [`RuntimeConfig::upstream_keepalive_pool_size`].
#[expect(clippy::unnecessary_wraps, reason = "serde default")]
fn default_upstream_keepalive_pool_size() -> Option<usize> {
    Some(64)
}

/// Serde default for [`RuntimeConfig::global_queue_interval`].
#[expect(clippy::unnecessary_wraps, reason = "serde default")]
fn default_global_queue_interval() -> Option<u32> {
    Some(61)
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

    // -------------------------------------------------------------------------
    // SubRequestCircuitBreakerConfig
    // -------------------------------------------------------------------------

    #[test]
    fn subrequest_circuit_breaker_defaults_to_none() {
        let cfg = RuntimeConfig::default();
        assert!(cfg.subrequest_circuit_breaker.is_none(), "should default to None");
    }

    #[test]
    fn deserialise_subrequest_circuit_breaker() {
        let yaml = r#"
subrequest_circuit_breaker:
  consecutive_failures: 5
  recovery_window_secs: 30
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let cb = cfg.subrequest_circuit_breaker.unwrap();
        assert_eq!(cb.consecutive_failures, 5, "threshold should be 5");
        assert_eq!(cb.recovery_window_secs, 30, "recovery should be 30s");
        assert_eq!(cb.half_open_timeout_secs, 30, "half_open should default to 30s");
    }

    #[test]
    fn deserialise_subrequest_circuit_breaker_explicit_half_open() {
        let yaml = r#"
subrequest_circuit_breaker:
  consecutive_failures: 3
  recovery_window_secs: 60
  half_open_timeout_secs: 15
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();
        let cb = cfg.subrequest_circuit_breaker.unwrap();
        assert_eq!(cb.half_open_timeout_secs, 15, "explicit half_open should be 15s");
    }

    #[test]
    fn subrequest_circuit_breaker_validate_zero_failures() {
        let cb = SubRequestCircuitBreakerConfig {
            consecutive_failures: 0,
            recovery_window_secs: 30,
            half_open_timeout_secs: 30,
        };
        let err = cb.validate().unwrap_err();
        assert!(
            err.contains("consecutive_failures must be > 0"),
            "should reject zero failures: {err}"
        );
    }

    #[test]
    fn subrequest_circuit_breaker_validate_zero_recovery() {
        let cb = SubRequestCircuitBreakerConfig {
            consecutive_failures: 5,
            recovery_window_secs: 0,
            half_open_timeout_secs: 30,
        };
        let err = cb.validate().unwrap_err();
        assert!(
            err.contains("recovery_window_secs must be > 0"),
            "should reject zero recovery: {err}"
        );
    }

    #[test]
    fn subrequest_circuit_breaker_validate_zero_half_open() {
        let cb = SubRequestCircuitBreakerConfig {
            consecutive_failures: 5,
            recovery_window_secs: 30,
            half_open_timeout_secs: 0,
        };
        let err = cb.validate().unwrap_err();
        assert!(
            err.contains("half_open_timeout_secs must be > 0"),
            "should reject zero half_open: {err}"
        );
    }

    #[test]
    fn subrequest_circuit_breaker_validate_valid() {
        let cb = SubRequestCircuitBreakerConfig {
            consecutive_failures: 5,
            recovery_window_secs: 30,
            half_open_timeout_secs: 30,
        };
        assert!(cb.validate().is_ok(), "valid config should pass");
    }
}
