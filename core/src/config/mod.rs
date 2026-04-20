// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! YAML configuration parsing, defaults, and validation.

use std::path::Path;

use serde::Deserialize;

mod admin;
mod body_limits;
mod bootstrap;
mod branch_chain;
mod chain_ref;
mod cluster;
mod condition;
mod filters;
mod insecure_options;
mod listener;
mod parse;
mod route;
mod runtime;
mod validate;

pub use admin::AdminConfig;
pub use body_limits::BodyLimitsConfig;
pub use bootstrap::{DEFAULT_CONFIG, load_config};
pub use branch_chain::{BranchChainConfig, BranchCondition};
pub use chain_ref::ChainRef;
pub use cluster::{
    Cluster, ConsistentHashOpts, Endpoint, HealthCheckConfig, HealthCheckType, LoadBalancerStrategy,
    ParameterisedStrategy, SimpleStrategy,
};
pub use condition::{Condition, ConditionMatch, ResponseCondition, ResponseConditionMatch};
pub use filters::{FilterChainConfig, FilterEntry};
pub use insecure_options::InsecureOptions;
pub use listener::{Listener, ListenerTls, ProtocolKind};
use parse::check_yaml_safety;
pub use praxis_tls::{CachedClusterTls, ClusterTls};
pub use route::Route;
pub use runtime::RuntimeConfig;
pub use validate::{MAX_BRANCH_DEPTH, MAX_ITERATIONS_CEILING};

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Top-level proxy configuration.
///
/// ```
/// use praxis_core::config::Config;
///
/// let config = Config::from_yaml(
///     r#"
/// listeners:
///   - name: web
///     address: "127.0.0.1:8080"
///     filter_chains: [main]
/// filter_chains:
///   - name: main
///     filters:
///       - filter: static_response
///         status: 200
/// "#,
/// )
/// .unwrap();
/// assert_eq!(config.listeners[0].address, "127.0.0.1:8080");
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Admin endpoint settings (address and verbosity).
    #[serde(default)]
    pub admin: AdminConfig,

    /// Global hard ceilings on request and response body size.
    #[serde(default)]
    pub body_limits: BodyLimitsConfig,

    /// Cluster definitions referenced by filters.
    #[serde(default)]
    pub clusters: Vec<Cluster>,

    /// Named filter chains.
    #[serde(default)]
    pub filter_chains: Vec<FilterChainConfig>,

    /// Consolidated security overrides. All default to `false`.
    #[serde(default)]
    pub insecure_options: InsecureOptions,

    /// Proxy listeners to bind.
    pub listeners: Vec<Listener>,

    /// Runtime configuration knobs.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Drain time for graceful shutdown.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

impl Config {
    /// Parse config from a YAML string.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if the YAML is invalid, oversized, or fails validation.
    ///
    /// # Security: Error Messages
    ///
    /// Parse errors from `serde_yaml` may include context snippets from the input YAML.
    /// This is acceptable for server-side operator tooling but callers should avoid
    /// exposing these errors to untrusted end users.
    ///
    /// ```
    /// use praxis_core::config::Config;
    ///
    /// let cfg = Config::from_yaml(
    ///     r#"
    /// listeners:
    ///   - name: web
    ///     address: "127.0.0.1:8080"
    ///     filter_chains: [main]
    /// filter_chains:
    ///   - name: main
    ///     filters:
    ///       - filter: static_response
    ///         status: 200
    /// "#,
    /// )
    /// .unwrap();
    /// assert_eq!(cfg.listeners[0].address, "127.0.0.1:8080");
    /// ```
    ///
    /// [`ProxyError::Config`]: crate::errors::ProxyError::Config
    pub fn from_yaml(s: &str) -> Result<Self, crate::errors::ProxyError> {
        check_yaml_safety(s)?;

        let mut config: Config =
            serde_yaml::from_str(s).map_err(|e| crate::errors::ProxyError::Config(format!("invalid YAML: {e}")))?;

        config.validate()?;

        Ok(config)
    }

    /// Load and validate config from a YAML file.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if the file cannot be read or contains invalid config.
    ///
    /// ```no_run
    /// use std::path::Path;
    ///
    /// use praxis_core::config::Config;
    ///
    /// let cfg = Config::from_file(Path::new("praxis.yaml")).unwrap();
    /// println!("listeners: {}", cfg.listeners.len());
    /// ```
    ///
    /// [`ProxyError::Config`]: crate::errors::ProxyError::Config
    pub fn from_file(path: &Path) -> Result<Self, crate::errors::ProxyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::errors::ProxyError::Config(format!("failed to read {}: {e}", path.display())))?;

        Self::from_yaml(&content)
    }

    /// Resolve configuration file. Fall back to `praxis.yaml` in the working directory, then `fallback_yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if the resolved config source cannot be loaded or is invalid.
    ///
    /// ```no_run
    /// use praxis_core::config::Config;
    ///
    /// let yaml = "listeners: [{name: w, address: '0:80'}]";
    /// let cfg = Config::load(None, yaml).unwrap();
    /// ```
    ///
    /// [`ProxyError::Config`]: crate::errors::ProxyError::Config
    pub fn load(explicit_path: Option<&str>, fallback_yaml: &str) -> Result<Self, crate::errors::ProxyError> {
        if let Some(path) = explicit_path {
            Self::from_file(Path::new(path))
        } else {
            let default_path = Path::new("praxis.yaml");
            if default_path.exists() {
                Self::from_file(default_path)
            } else {
                tracing::info!("no config file found, using built-in default");
                Self::from_yaml(fallback_yaml)
            }
        }
    }
}

/// Serde default for [`Config::shutdown_timeout_secs`].
fn default_shutdown_timeout_secs() -> u64 {
    30
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
    clippy::too_many_lines,
    clippy::panic,
    reason = "tests use unwrap/expect/indexing/raw strings/panic for brevity"
)]
mod tests {
    use std::path::Path;

    use super::Config;

    #[test]
    fn default_shutdown_timeout_is_30() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(
            config.shutdown_timeout_secs, 30,
            "default shutdown timeout should be 30s"
        );
    }

    #[test]
    fn default_runtime_config() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(config.runtime.threads, 0, "default threads should be 0");
        assert!(config.runtime.work_stealing, "default work_stealing should be true");
    }

    #[test]
    fn body_limits_default_to_none() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert!(
            config.body_limits.max_request_bytes.is_none(),
            "max_request_bytes should default to None"
        );
        assert!(
            config.body_limits.max_response_bytes.is_none(),
            "max_response_bytes should default to None"
        );
    }

    #[test]
    fn insecure_options_default_to_false() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert!(
            !config.insecure_options.skip_pipeline_validation,
            "skip_pipeline_validation should default to false"
        );
        assert!(
            !config.insecure_options.allow_root,
            "allow_root should default to false"
        );
        assert!(
            !config.insecure_options.allow_public_admin,
            "allow_public_admin should default to false"
        );
        assert!(
            !config.insecure_options.allow_unbounded_body,
            "allow_unbounded_body should default to false"
        );
        assert!(
            !config.insecure_options.allow_tls_without_sni,
            "allow_tls_without_sni should default to false"
        );
        assert!(
            !config.insecure_options.allow_private_health_checks,
            "allow_private_health_checks should default to false"
        );
    }

    #[test]
    fn insecure_options_parsed_from_yaml() {
        let yaml = format!("{VALID_YAML}\ninsecure_options:\n  skip_pipeline_validation: true\n  allow_root: true");
        let config = Config::from_yaml(&yaml).unwrap();
        assert!(
            config.insecure_options.skip_pipeline_validation,
            "skip_pipeline_validation should be true when set"
        );
        assert!(config.insecure_options.allow_root, "allow_root should be true when set");
    }

    #[test]
    fn parse_valid_config() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert_eq!(config.listeners.len(), 1, "should have 1 listener");
        assert_eq!(
            config.listeners[0].address, "127.0.0.1:8080",
            "listener address mismatch"
        );
        assert_eq!(config.filter_chains.len(), 1, "should have 1 filter chain");
        assert_eq!(
            config.filter_chains[0].filters.len(),
            2,
            "filter chain should have 2 filters"
        );
    }

    #[test]
    fn parse_config_with_tls() {
        let yaml = r#"
listeners:
  - name: secure
    address: "0.0.0.0:443"
    tls:
      certificates:
        - cert_path: "/etc/ssl/cert.pem"
          key_path: "/etc/ssl/key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        let (cert, _key) = tls.primary_cert_paths();
        assert_eq!(cert, "/etc/ssl/cert.pem", "cert_path mismatch");
    }

    #[test]
    fn load_from_file() {
        let dir = std::env::temp_dir().join("praxis-config-test");
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test.yaml");
        std::fs::write(&path, VALID_YAML).unwrap();

        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.listeners.len(), 1, "file-loaded config should have 1 listener");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_from_missing_file() {
        let err = Config::from_file(Path::new("/nonexistent/config.yaml")).unwrap_err();
        assert!(
            err.to_string().contains("failed to read"),
            "should report file read failure"
        );
    }

    #[test]
    fn parse_body_limits() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
body_limits:
  max_request_bytes: 10485760
  max_response_bytes: 5242880
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.body_limits.max_request_bytes,
            Some(10_485_760),
            "request body limit mismatch"
        );
        assert_eq!(
            config.body_limits.max_response_bytes,
            Some(5_242_880),
            "response body limit mismatch"
        );
    }

    #[test]
    fn parse_runtime_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
runtime:
  threads: 8
  work_stealing: false
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.runtime.threads, 8, "threads should be 8");
        assert!(!config.runtime.work_stealing, "work_stealing should be false");
    }

    #[test]
    fn load_returns_err_for_missing_explicit_path() {
        let err = Config::load(Some("/nonexistent/config.yaml"), "").unwrap_err();
        assert!(
            err.to_string().contains("failed to read"),
            "should report file read failure"
        );
    }

    #[test]
    fn load_uses_fallback_yaml() {
        let fallback = r#"
listeners:
  - name: fallback
    address: "127.0.0.1:9999"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let config = Config::load(None, fallback).unwrap();
        assert_eq!(config.listeners[0].name, "fallback", "should use fallback config");
    }

    #[test]
    fn parse_named_filter_chains() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains:
      - observability
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.filter_chains.len(), 2, "should have 2 named chains");
        assert_eq!(
            config.filter_chains[0].name, "observability",
            "first chain name mismatch"
        );
        assert_eq!(config.filter_chains[1].name, "routing", "second chain name mismatch");
        assert_eq!(
            config.listeners[0].filter_chains,
            vec!["observability", "routing"],
            "listener chain references mismatch"
        );
    }

    #[test]
    fn downstream_read_timeout_per_listener_isolation() {
        let yaml = r#"
listeners:
  - name: fast
    address: "127.0.0.1:8080"
    downstream_read_timeout_ms: 500
    filter_chains: [main]
  - name: slow
    address: "127.0.0.1:8081"
    downstream_read_timeout_ms: 30000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].downstream_read_timeout_ms,
            Some(500),
            "fast listener should have 500ms timeout"
        );
        assert_eq!(
            config.listeners[1].downstream_read_timeout_ms,
            Some(30000),
            "slow listener should have 30000ms timeout"
        );
    }

    #[test]
    fn insecure_options_all_flags_settable() {
        let yaml = format!(
            "{VALID_YAML}\ninsecure_options:\n  allow_unbounded_body: true\n  allow_public_admin: true\n  allow_tls_without_sni: true\n  allow_private_health_checks: true"
        );
        let config = Config::from_yaml(&yaml).unwrap();
        assert!(
            config.insecure_options.allow_unbounded_body,
            "allow_unbounded_body should be true"
        );
        assert!(
            config.insecure_options.allow_public_admin,
            "allow_public_admin should be true"
        );
        assert!(
            config.insecure_options.allow_tls_without_sni,
            "allow_tls_without_sni should be true"
        );
        assert!(
            config.insecure_options.allow_private_health_checks,
            "allow_private_health_checks should be true"
        );
    }

    #[test]
    fn all_example_configs_parse() {
        let root = format!("{}/../examples/configs", env!("CARGO_MANIFEST_DIR"));
        let mut count = 0;
        for entry in walkdir(&root) {
            Config::from_file(&entry).unwrap_or_else(|e| panic!("{}: {e}", entry.display()));
            count += 1;
        }
        assert!(count > 0, "no YAML files found in {root}");
    }

    #[test]
    fn parse_admin_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
admin:
  address: "127.0.0.1:9901"
  verbose: true
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.admin.address.as_deref(),
            Some("127.0.0.1:9901"),
            "admin address mismatch"
        );
        assert!(config.admin.verbose, "admin verbose should be true");
    }

    #[test]
    fn admin_defaults_to_none_and_false() {
        let config = Config::from_yaml(VALID_YAML).unwrap();
        assert!(config.admin.address.is_none(), "admin address should default to None");
        assert!(!config.admin.verbose, "admin verbose should default to false");
    }

    #[test]
    fn reject_unrecognized_top_level_key() {
        let yaml = format!("{VALID_YAML}\nunrecognized_key: true\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("unrecognized_key"),
            "error should name the unknown field"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    const VALID_YAML: &str = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:3000"
"#;

    /// Recursively collect all `.yaml` files under `root`.
    fn walkdir(root: &str) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "yaml") {
                    files.push(path);
                }
            }
        }
        files
    }
}
