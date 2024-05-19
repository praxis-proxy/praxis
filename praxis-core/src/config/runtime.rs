//! Runtime tuning: worker thread count, work-stealing toggle, and
//! logging overrides.
//!
//! Deserialized from the `runtime:` section of the config YAML.

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
/// assert!(cfg.log_overrides.is_empty());
///
/// let cfg: RuntimeConfig = serde_yaml::from_str("threads: 4\nwork_stealing: false").unwrap();
/// assert_eq!(cfg.threads, 4);
/// assert!(!cfg.work_stealing);
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct RuntimeConfig {
    /// Number of worker threads per service.
    ///
    /// Auto-detected by default.
    #[serde(default)]
    pub threads: usize,

    /// Allow work-stealing between worker threads of the same service.
    ///
    /// Enabled by default.
    #[serde(default = "default_work_stealing")]
    pub work_stealing: bool,

    /// Per-module log level overrides.
    ///
    /// Keys are module paths (e.g. `"praxis_filter::pipeline"`),
    /// values are level strings (`"trace"`, `"debug"`, `"info"`,
    /// `"warn"`, `"error"`). Merged into the `RUST_LOG` env
    /// filter at startup.
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
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            work_stealing: default_work_stealing(),
            log_overrides: HashMap::new(),
        }
    }
}

/// Serde default for [`RuntimeConfig::work_stealing`].
fn default_work_stealing() -> bool {
    true
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_zero_threads_and_work_stealing_true() {
        let cfg = RuntimeConfig::default();

        assert_eq!(cfg.threads, 0);
        assert!(cfg.work_stealing);
    }

    #[test]
    fn deserialise_empty_yaml_gives_defaults() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();

        assert_eq!(cfg.threads, 0);
        assert!(cfg.work_stealing);
    }

    #[test]
    fn deserialise_explicit_threads() {
        let cfg: RuntimeConfig = serde_yaml::from_str("threads: 4").unwrap();

        assert_eq!(cfg.threads, 4);
        assert!(cfg.work_stealing);
    }

    #[test]
    fn deserialise_work_stealing_disabled() {
        let cfg: RuntimeConfig = serde_yaml::from_str("work_stealing: false").unwrap();

        assert_eq!(cfg.threads, 0);
        assert!(!cfg.work_stealing);
    }

    #[test]
    fn deserialise_all_fields() {
        let yaml = "threads: 8\nwork_stealing: false";
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(cfg.threads, 8);
        assert!(!cfg.work_stealing);
    }

    #[test]
    fn deserialise_log_overrides() {
        let yaml = r#"
log_overrides:
  praxis_filter::pipeline: trace
  praxis_protocol: debug
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(cfg.log_overrides.len(), 2);
        assert_eq!(cfg.log_overrides["praxis_filter::pipeline"], "trace");
        assert_eq!(cfg.log_overrides["praxis_protocol"], "debug");
    }

    #[test]
    fn default_log_overrides_is_empty() {
        let cfg: RuntimeConfig = serde_yaml::from_str("{}").unwrap();

        assert!(cfg.log_overrides.is_empty());
    }
}
