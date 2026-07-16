// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Top-level configuration validation orchestration.

use std::{
    collections::HashSet,
    path::{Component, Path},
};

use tracing::warn;

use super::{
    branch_chain::validate_branch_chains,
    cluster::validate_clusters,
    filter_chain::validate_filter_chains,
    listener::{validate_listener_names, validate_listeners},
};
use crate::{
    config::{ABSOLUTE_MAX_BODY_BYTES, BodyLimitsConfig, Config, InsecureOptions, ProtocolKind, SkipPipelineChecks},
    connectivity::normalize_mapped_ipv4,
    errors::ProxyError,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed worker threads per service.
const MAX_THREADS: usize = 1_024;

/// Maximum allowed `upstream_keepalive_pool_size` (10,000 per worker).
const MAX_KEEPALIVE_POOL_SIZE: usize = 10_000;

/// Minimum allowed `max_memory_bytes` (1 MiB).
const MIN_MEMORY_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum allowed `max_memory_bytes` (1 `TiB`).
const MAX_MEMORY_BYTES: usize = 1_099_511_627_776; // 1 TiB

/// Maximum allowed `shutdown_timeout_secs` (1 hour).
const MAX_SHUTDOWN_TIMEOUT_SECS: u64 = 3_600;

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "validation is split into a dedicated module"
)]
impl Config {
    /// Validate config constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if any constraint is violated.
    ///
    /// ```
    /// use praxis_core::config::Config;
    ///
    /// let err = Config::from_yaml("listeners: []\n").unwrap_err();
    /// assert!(err.to_string().contains("at least one listener"));
    /// ```
    pub fn validate(&mut self) -> Result<(), ProxyError> {
        warn_active_insecure_options(&self.insecure_options);
        validate_listeners(&mut self.listeners)?;
        validate_listener_names(&self.listeners)?;
        validate_filter_chains(&self.filter_chains, &self.listeners)?;
        validate_branch_chains(&self.filter_chains)?;
        validate_admin_address(self.admin.address.as_deref(), self.insecure_options.allow_public_admin)?;
        warn_filter_duration_without_admin(self.metrics.filter_duration, self.admin.address.is_some());

        for listener in &self.listeners {
            if listener.protocol != ProtocolKind::Tcp && listener.filter_chains.is_empty() {
                return Err(ProxyError::Config(format!(
                    "listener '{}': at least one filter chain required for HTTP listeners",
                    listener.name
                )));
            }
        }

        validate_body_limits(&self.body_limits, self.insecure_options.allow_unbounded_body)?;
        validate_cluster_names(&self.clusters)?;
        validate_clusters(&self.clusters, &self.insecure_options)?;
        validate_upstream_ca_file(self.runtime.upstream_ca_file.as_deref())?;
        validate_runtime_threads(self.runtime.threads)?;
        validate_runtime_max_connections(self.runtime.max_connections)?;
        validate_keepalive_pool_size(self.runtime.upstream_keepalive_pool_size)?;
        validate_max_memory_bytes(self.runtime.max_memory_bytes)?;
        validate_global_queue_interval(self.runtime.global_queue_interval)?;
        validate_shutdown_timeout(self.shutdown_timeout_secs)?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Insecure Options Warning
// -----------------------------------------------------------------------------

/// Emit a warning for each active insecure option flag.
fn warn_active_insecure_options(opts: &InsecureOptions) {
    for (name, active) in [
        ("allow_open_security_filters", opts.allow_open_security_filters),
        ("allow_private_endpoints", opts.allow_private_endpoints),
        ("allow_private_health_checks", opts.allow_private_health_checks),
        ("allow_private_upstreams", opts.allow_private_upstreams),
        ("allow_public_admin", opts.allow_public_admin),
        ("allow_root", opts.allow_root),
        ("allow_tls_without_sni", opts.allow_tls_without_sni),
        ("allow_unbounded_body", opts.allow_unbounded_body),
        ("csrf_log_only", opts.csrf_log_only),
        ("skip_pipeline_validation", opts.skip_pipeline_validation),
    ] {
        if active {
            warn!(flag = name, "insecure_options flag is active");
        }
    }
    warn_active_pipeline_checks(&opts.skip_pipeline_checks);
}

/// Emit a warning for each active granular pipeline check skip flag.
fn warn_active_pipeline_checks(s: &SkipPipelineChecks) {
    for (name, active) in [
        ("skip_pipeline_checks.conditional_security", s.conditional_security),
        (
            "skip_pipeline_checks.conflicting_cluster_selectors",
            s.conflicting_cluster_selectors,
        ),
        (
            "skip_pipeline_checks.duplicate_load_balancers",
            s.duplicate_load_balancers,
        ),
        (
            "skip_pipeline_checks.duplicate_rewrite_filters",
            s.duplicate_rewrite_filters,
        ),
        ("skip_pipeline_checks.duplicate_routers", s.duplicate_routers),
        ("skip_pipeline_checks.lb_without_router", s.lb_without_router),
        ("skip_pipeline_checks.misaligned_clusters", s.misaligned_clusters),
        ("skip_pipeline_checks.unreachable_filters", s.unreachable_filters),
    ] {
        if active {
            warn!(flag = name, "insecure_options flag is active");
        }
    }
}

// -----------------------------------------------------------------------------
// Body Limits Validation
// -----------------------------------------------------------------------------

/// Require both body limits unless the operator opts out.
fn validate_body_limits(limits: &BodyLimitsConfig, allow_unbounded: bool) -> Result<(), ProxyError> {
    validate_body_limit_ceiling("max_request_bytes", limits.max_request_bytes)?;
    validate_body_limit_ceiling("max_response_bytes", limits.max_response_bytes)?;

    let missing_request = limits.max_request_bytes.is_none();
    let missing_response = limits.max_response_bytes.is_none();

    if !missing_request && !missing_response {
        return Ok(());
    }

    if allow_unbounded {
        warn!(
            max_request_bytes = ?limits.max_request_bytes,
            max_response_bytes = ?limits.max_response_bytes,
            "body limits not fully configured; allowed by insecure_options.allow_unbounded_body"
        );
        return Ok(());
    }

    Err(ProxyError::Config(format!(
        "body_limits.max_request_bytes ({}) and body_limits.max_response_bytes ({}) \
         must both be set; use insecure_options.allow_unbounded_body: true to override",
        limits
            .max_request_bytes
            .map_or_else(|| "none".to_owned(), |v| v.to_string()),
        limits
            .max_response_bytes
            .map_or_else(|| "none".to_owned(), |v| v.to_string()),
    )))
}

/// Reject a body limit that exceeds the absolute ceiling.
fn validate_body_limit_ceiling(field: &str, value: Option<usize>) -> Result<(), ProxyError> {
    if let Some(v) = value
        && v > ABSOLUTE_MAX_BODY_BYTES
    {
        return Err(ProxyError::Config(format!(
            "body_limits.{field} ({v} bytes) exceeds maximum ({ABSOLUTE_MAX_BODY_BYTES} bytes / 64 MiB)"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Cluster Name Validation
// -----------------------------------------------------------------------------

/// Reject duplicate cluster names.
fn validate_cluster_names(clusters: &[crate::config::Cluster]) -> Result<(), ProxyError> {
    let mut seen = HashSet::new();
    for cluster in clusters {
        if !seen.insert(&cluster.name) {
            return Err(ProxyError::Config(format!("duplicate cluster name '{}'", cluster.name)));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Admin Address Validation
// -----------------------------------------------------------------------------

/// Reject admin addresses that bind outside loopback unless explicitly allowed.
fn validate_admin_address(addr: Option<&str>, allow_public: bool) -> Result<(), ProxyError> {
    let Some(addr) = addr else { return Ok(()) };
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|_parse_err| ProxyError::Config(format!("invalid admin_address '{addr}'")))?;
    if normalize_mapped_ipv4(socket_addr.ip()).is_loopback() {
        return Ok(());
    }
    if allow_public {
        warn!(
            admin_address = %addr,
            "admin endpoint binds to a non-loopback address; allowed by insecure_options.allow_public_admin"
        );
        return Ok(());
    }
    Err(ProxyError::Config(format!(
        "admin endpoint '{addr}' must bind to a loopback address (127.0.0.1 or [::1]); \
         set insecure_options.allow_public_admin: true to allow non-loopback binding"
    )))
}

/// Warn when filter duration metrics are enabled but the admin endpoint is disabled.
pub(super) fn warn_filter_duration_without_admin(filter_duration: bool, admin_enabled: bool) {
    if filter_duration && !admin_enabled {
        warn!(
            "metrics.filter_duration is enabled but admin is disabled; \
             filter duration metrics will be recorded but not scrapeable via /metrics"
        );
    }
}

// -----------------------------------------------------------------------------
// Upstream CA File Validation
// -----------------------------------------------------------------------------

/// Reject `upstream_ca_file` paths that contain directory traversal or do not exist.
fn validate_upstream_ca_file(ca_file: Option<&str>) -> Result<(), ProxyError> {
    let Some(path) = ca_file else { return Ok(()) };

    if Path::new(path).components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ProxyError::Config(format!(
            "upstream_ca_file must not contain path traversal (..): {path}"
        )));
    }

    if !Path::new(path).exists() {
        return Err(ProxyError::Config(format!("upstream_ca_file does not exist: {path}")));
    }

    warn_if_symlink(path);

    Ok(())
}

/// Emit a warning when a path is a symlink.
fn warn_if_symlink(path: &str) {
    let p = Path::new(path);
    if p.is_symlink() {
        let target = std::fs::canonicalize(p).map_or_else(|_| "unknown".to_owned(), |c| c.display().to_string());
        warn!(
            path = path,
            target = %target,
            "file is a symlink"
        );
    }
}

// -----------------------------------------------------------------------------
// Runtime Validation
// -----------------------------------------------------------------------------

/// Reject unreasonable thread counts.
fn validate_runtime_threads(threads: usize) -> Result<(), ProxyError> {
    if threads > MAX_THREADS {
        return Err(ProxyError::Config(format!(
            "runtime.threads must be <= {MAX_THREADS}, got {threads}"
        )));
    }
    Ok(())
}

/// Reject `runtime.max_connections` values that are zero or above the ceiling.
fn validate_runtime_max_connections(max_connections: Option<u32>) -> Result<(), ProxyError> {
    let Some(v) = max_connections else {
        return Ok(());
    };
    if v == 0 {
        return Err(ProxyError::Config("runtime.max_connections must be >= 1".into()));
    }
    if v > super::MAX_CONNECTIONS {
        return Err(ProxyError::Config(format!(
            "runtime.max_connections ({v}) exceeds maximum ({})",
            super::MAX_CONNECTIONS,
        )));
    }
    Ok(())
}

/// Reject `upstream_keepalive_pool_size` above the ceiling.
fn validate_keepalive_pool_size(pool_size: Option<usize>) -> Result<(), ProxyError> {
    if let Some(v) = pool_size
        && v > MAX_KEEPALIVE_POOL_SIZE
    {
        return Err(ProxyError::Config(format!(
            "runtime.upstream_keepalive_pool_size ({v}) exceeds maximum ({MAX_KEEPALIVE_POOL_SIZE})"
        )));
    }
    Ok(())
}

/// Reject `runtime.max_memory_bytes` outside the allowed range.
fn validate_max_memory_bytes(max_memory_bytes: Option<usize>) -> Result<(), ProxyError> {
    let Some(v) = max_memory_bytes else {
        return Ok(());
    };
    if v < MIN_MEMORY_BYTES {
        return Err(ProxyError::Config(format!(
            "runtime.max_memory_bytes ({v}) must be >= {MIN_MEMORY_BYTES} (1 MiB)"
        )));
    }
    if v > MAX_MEMORY_BYTES {
        return Err(ProxyError::Config(format!(
            "runtime.max_memory_bytes ({v}) exceeds maximum ({MAX_MEMORY_BYTES} / 1 TiB)"
        )));
    }
    Ok(())
}

/// Reject `runtime.global_queue_interval` of zero.
fn validate_global_queue_interval(interval: Option<u32>) -> Result<(), ProxyError> {
    if let Some(0) = interval {
        return Err(ProxyError::Config(
            "runtime.global_queue_interval must be > 0".to_owned(),
        ));
    }
    Ok(())
}

/// Reject `shutdown_timeout_secs` of zero or above the ceiling.
fn validate_shutdown_timeout(secs: u64) -> Result<(), ProxyError> {
    if secs == 0 {
        return Err(ProxyError::Config("shutdown_timeout_secs must be > 0".to_owned()));
    }
    if secs > MAX_SHUTDOWN_TIMEOUT_SECS {
        return Err(ProxyError::Config(format!(
            "shutdown_timeout_secs ({secs}) exceeds maximum ({MAX_SHUTDOWN_TIMEOUT_SECS}s / 1 hour)"
        )));
    }
    Ok(())
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
    clippy::too_many_lines,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use crate::config::{Config, DEFAULT_MAX_BODY_BYTES, ProtocolKind};

    #[test]
    fn reject_invalid_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "not-valid"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("invalid admin_address"), "got: {err}");
    }

    #[test]
    fn accept_valid_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "127.0.0.1:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.admin.address.as_deref(), Some("127.0.0.1:9901"));
    }

    #[test]
    fn reject_public_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "0.0.0.0:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must bind to a loopback address"),
            "should reject public admin: {err}"
        );
    }

    #[test]
    fn reject_non_loopback_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "10.0.0.5:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must bind to a loopback address"),
            "should reject non-loopback admin: {err}"
        );
    }

    #[test]
    fn reject_lan_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "192.168.1.50:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must bind to a loopback address"),
            "should reject LAN admin binding: {err}"
        );
    }

    #[test]
    fn accept_ipv6_loopback_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "[::1]:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.admin.address.as_deref(),
            Some("[::1]:9901"),
            "IPv6 loopback admin address should be accepted"
        );
    }

    #[test]
    fn accept_ipv4_mapped_loopback_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "[::ffff:127.0.0.1]:9901"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.admin.address.as_deref(),
            Some("[::ffff:127.0.0.1]:9901"),
            "IPv4-mapped loopback admin address should be accepted"
        );
    }

    #[test]
    fn allow_public_admin_with_override() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "0.0.0.0:9901"
insecure_options:
  allow_public_admin: true
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.admin.address.as_deref(),
            Some("0.0.0.0:9901"),
            "allow_public_admin should permit public admin binding"
        );
    }

    #[test]
    fn allow_public_admin_with_lan_override() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
admin:
  address: "192.168.1.50:9901"
insecure_options:
  allow_public_admin: true
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.admin.address.as_deref(),
            Some("192.168.1.50:9901"),
            "allow_public_admin should permit non-loopback LAN admin binding"
        );
    }

    #[test]
    fn reject_upstream_ca_file_traversal() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  upstream_ca_file: /etc/../../tmp/evil-ca.pem
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "should reject traversal: {err}"
        );
    }

    #[test]
    fn reject_upstream_ca_file_missing() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  upstream_ca_file: nonexistent/ca.pem
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "should reject missing file: {err}"
        );
    }

    #[test]
    fn accept_upstream_ca_file_when_file_exists() {
        let dir = std::env::temp_dir().join("praxis-ca-test");
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("test-ca.pem").to_string_lossy().into_owned();
        std::fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let yaml = format!(
            r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  upstream_ca_file: {ca_path}
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#
        );
        let config = Config::from_yaml(&yaml).unwrap();
        assert_eq!(
            config.runtime.upstream_ca_file.as_deref(),
            Some(ca_path.as_str()),
            "upstream_ca_file should be accepted"
        );

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn reject_no_filter_chains_for_http() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("at least one filter chain"),
            "should reject HTTP listener without chains: {err}"
        );
    }

    #[test]
    fn reject_http_listener_without_chains_when_sibling_has_chains() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    filter_chains: [tcp_chain]
  - name: web
    address: "0.0.0.0:8080"
filter_chains:
  - name: tcp_chain
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("listener 'web'"),
            "should name the HTTP listener without chains: {err}"
        );
    }

    #[test]
    fn tcp_only_config_needs_no_pipeline() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].protocol,
            ProtocolKind::Tcp,
            "protocol should be Tcp"
        );
    }

    #[test]
    fn reject_duplicate_cluster_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
  - name: backend
    endpoints: ["10.0.0.2:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate cluster name 'backend'"),
            "should reject duplicate cluster names: {err}"
        );
    }

    #[test]
    fn reject_empty_listener_name() {
        let yaml = r#"
listeners:
  - name: ""
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("name must not be empty"),
            "should reject empty listener name: {err}"
        );
    }

    #[test]
    fn reject_excessive_threads() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  threads: 10000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("threads must be <= 1024"),
            "should reject excessive threads: {err}"
        );
    }

    #[test]
    fn accept_valid_threads() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  threads: 16
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_threads_at_max() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  threads: 1024
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_invalid_yaml() {
        let err = Config::from_yaml("not: [valid: yaml: {{").unwrap_err();
        assert!(err.to_string().contains("invalid YAML"));
    }

    #[test]
    fn reject_null_body_limits() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
body_limits:
  max_request_bytes: null
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("allow_unbounded_body"),
            "should reject null body limits: {err}"
        );
    }

    #[test]
    fn reject_body_limits_exceeding_ceiling() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
body_limits:
  max_request_bytes: 100000000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "body limit above 64 MiB should be rejected: {err}"
        );
    }

    #[test]
    fn accept_body_limits_at_ceiling() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
body_limits:
  max_request_bytes: 67108864
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_null_body_limits_with_insecure_flag() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
body_limits:
  max_request_bytes: null
  max_response_bytes: null
insecure_options:
  allow_unbounded_body: true
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_default_body_limits() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.body_limits.max_request_bytes,
            Some(DEFAULT_MAX_BODY_BYTES),
            "default body limit should be 10 MiB"
        );
    }

    #[test]
    fn accept_valid_unique_listener_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: api
    address: "0.0.0.0:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml);
        assert!(
            config.is_ok(),
            "unique listener names should be accepted: {:?}",
            config.err()
        );
    }

    #[test]
    fn accept_valid_unique_cluster_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
clusters:
  - name: backend_a
    endpoints: ["10.0.0.1:80"]
  - name: backend_b
    endpoints: ["10.0.0.2:80"]
"#;
        let config = Config::from_yaml(yaml);
        assert!(
            config.is_ok(),
            "unique cluster names should be accepted: {:?}",
            config.err()
        );
    }

    #[test]
    fn reject_runtime_zero_max_connections() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  max_connections: 0
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_connections must be >= 1"),
            "should reject zero runtime max_connections: {err}"
        );
    }

    #[test]
    fn reject_runtime_max_connections_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  max_connections: 1000001
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject runtime max_connections > 1M: {err}"
        );
    }

    #[test]
    fn accept_runtime_max_connections_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  max_connections: 1000000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_keepalive_pool_size_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  upstream_keepalive_pool_size: 10001
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject keepalive pool > 10K: {err}"
        );
    }

    #[test]
    fn accept_keepalive_pool_size_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  upstream_keepalive_pool_size: 10000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_max_memory_bytes_below_minimum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  max_memory_bytes: 1000
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must be >= 1048576"),
            "should reject max_memory_bytes below 1 MiB: {err}"
        );
    }

    #[test]
    fn accept_max_memory_bytes_at_minimum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  max_memory_bytes: 1048576
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn accept_max_memory_bytes_unset() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert!(
            config.runtime.max_memory_bytes.is_none(),
            "max_memory_bytes should default to None"
        );
    }

    #[test]
    fn reject_global_queue_interval_zero() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  global_queue_interval: 0
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("global_queue_interval must be > 0"),
            "should reject zero global_queue_interval: {err}"
        );
    }

    #[test]
    fn accept_global_queue_interval_positive() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
runtime:
  global_queue_interval: 1
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_shutdown_timeout_zero() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
shutdown_timeout_secs: 0
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("shutdown_timeout_secs must be > 0"),
            "should reject zero shutdown timeout: {err}"
        );
    }

    #[test]
    fn reject_shutdown_timeout_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
shutdown_timeout_secs: 7200
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject shutdown timeout > 1 hour: {err}"
        );
    }

    #[test]
    fn accept_shutdown_timeout_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
shutdown_timeout_secs: 3600
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
