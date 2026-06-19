// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Runtime options passed from config into the server factory.

// -----------------------------------------------------------------------------
// RuntimeOptions
// -----------------------------------------------------------------------------

/// Runtime tuning passed from config into the server factory.
///
/// ```
/// use praxis_core::server::RuntimeOptions;
///
/// let opts = RuntimeOptions::default();
/// assert_eq!(opts.threads, 0);
/// assert!(opts.work_stealing);
/// assert_eq!(opts.global_queue_interval, Some(61));
/// assert!(opts.upstream_ca_file.is_none());
/// assert!(opts.upstream_keepalive_pool_size.is_none());
///
/// let opts = RuntimeOptions {
///     threads: 4,
///     work_stealing: true,
///     ..RuntimeOptions::default()
/// };
/// assert_eq!(opts.threads, 4);
/// ```
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    /// Worker threads per service. `0` means auto-detect.
    pub threads: usize,

    /// Allow work-stealing between threads.
    pub work_stealing: bool,

    /// Fixed global queue interval for the tokio scheduler.
    pub global_queue_interval: Option<u32>,

    /// PEM CA file for all upstream TLS connections. Replaces the
    /// system trust store when set (not additive).
    pub upstream_ca_file: Option<String>,

    /// Per-thread upstream keepalive pool size. `None` uses
    /// Pingora's default (128).
    pub upstream_keepalive_pool_size: Option<usize>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            threads: 0,
            work_stealing: true,
            global_queue_interval: Some(61),
            upstream_ca_file: None,
            upstream_keepalive_pool_size: None,
        }
    }
}

impl From<&crate::config::RuntimeConfig> for RuntimeOptions {
    fn from(cfg: &crate::config::RuntimeConfig) -> Self {
        Self {
            threads: cfg.threads,
            work_stealing: cfg.work_stealing,
            global_queue_interval: cfg.global_queue_interval,
            upstream_ca_file: cfg.upstream_ca_file.clone(),
            upstream_keepalive_pool_size: cfg.upstream_keepalive_pool_size,
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
    fn default_has_zero_threads_and_work_stealing_true() {
        let opts = RuntimeOptions::default();
        assert_eq!(opts.threads, 0, "default threads should be 0 (auto-detect)");
        assert!(opts.work_stealing, "work_stealing should default to true");
        assert_eq!(
            opts.global_queue_interval,
            Some(61),
            "default global_queue_interval should be 61"
        );
    }

    #[test]
    fn from_runtime_config_copies_all_fields() {
        let cfg = crate::config::RuntimeConfig {
            threads: 8,
            work_stealing: false,
            global_queue_interval: Some(128),
            upstream_ca_file: Some("/etc/ssl/ca.pem".to_owned()),
            upstream_keepalive_pool_size: Some(32),
            ..crate::config::RuntimeConfig::default()
        };
        let opts = RuntimeOptions::from(&cfg);
        assert_eq!(opts.threads, 8, "threads should match config");
        assert!(!opts.work_stealing, "work_stealing should match config");
        assert_eq!(opts.global_queue_interval, Some(128), "interval should match config");
        assert_eq!(
            opts.upstream_ca_file.as_deref(),
            Some("/etc/ssl/ca.pem"),
            "upstream_ca_file should match config"
        );
        assert_eq!(
            opts.upstream_keepalive_pool_size,
            Some(32),
            "pool size should match config"
        );
    }

    #[test]
    fn explicit_fields_are_preserved() {
        let opts = RuntimeOptions {
            threads: 4,
            work_stealing: false,
            global_queue_interval: Some(128),
            upstream_ca_file: Some("/ca.pem".to_owned()),
            upstream_keepalive_pool_size: Some(32),
        };
        assert_eq!(opts.threads, 4, "explicit threads should be preserved");
        assert!(!opts.work_stealing, "explicit work_stealing=false should be preserved");
        assert_eq!(
            opts.global_queue_interval,
            Some(128),
            "explicit interval should be preserved"
        );
        assert_eq!(
            opts.upstream_ca_file.as_deref(),
            Some("/ca.pem"),
            "explicit upstream_ca_file should be preserved"
        );
        assert_eq!(
            opts.upstream_keepalive_pool_size,
            Some(32),
            "explicit pool size should be preserved"
        );
    }
}
