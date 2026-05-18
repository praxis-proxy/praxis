// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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
    config::{BodyLimitsConfig, Config, ProtocolKind},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

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
        validate_listeners(&mut self.listeners)?;
        validate_listener_names(&self.listeners)?;
        validate_filter_chains(&self.filter_chains, &self.listeners)?;
        validate_branch_chains(&self.filter_chains)?;
        validate_admin_address(self.admin.address.as_deref(), self.insecure_options.allow_public_admin)?;

        let all_tcp = self.listeners.iter().all(|l| l.protocol == ProtocolKind::Tcp);
        let has_chains = self.listeners.iter().any(|l| !l.filter_chains.is_empty());

        if !all_tcp && !has_chains {
            return Err(ProxyError::Config(
                "at least one filter chain required for HTTP listeners".into(),
            ));
        }

        validate_body_limits(&self.body_limits, self.insecure_options.allow_unbounded_body)?;
        validate_cluster_names(&self.clusters)?;
        validate_clusters(&self.clusters, &self.insecure_options)?;
        validate_upstream_ca_file(self.runtime.upstream_ca_file.as_deref())?;
        validate_runtime_threads(self.runtime.threads)?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Body Limits Validation
// -----------------------------------------------------------------------------

/// Require both body limits unless the operator opts out.
fn validate_body_limits(limits: &BodyLimitsConfig, allow_unbounded: bool) -> Result<(), ProxyError> {
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

/// Reject admin addresses that bind to all interfaces unless explicitly allowed.
fn validate_admin_address(addr: Option<&str>, allow_public: bool) -> Result<(), ProxyError> {
    let Some(addr) = addr else { return Ok(()) };
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|_parse_err| ProxyError::Config(format!("invalid admin_address '{addr}'")))?;
    if socket_addr.ip().is_unspecified() {
        if allow_public {
            warn!(
                admin_address = %addr,
                "admin endpoint binds to all interfaces; allowed by insecure_options.allow_public_admin"
            );
        } else {
            return Err(ProxyError::Config(format!(
                "admin endpoint '{addr}' binds to all interfaces; \
                 bind to 127.0.0.1 or a management network, or set \
                 insecure_options.allow_public_admin: true to allow"
            )));
        }
    }
    Ok(())
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

    Ok(())
}

// -----------------------------------------------------------------------------
// Runtime Validation
// -----------------------------------------------------------------------------

/// Maximum allowed worker threads per service.
const MAX_THREADS: usize = 1_024;

/// Reject unreasonable thread counts.
fn validate_runtime_threads(threads: usize) -> Result<(), ProxyError> {
    if threads > MAX_THREADS {
        return Err(ProxyError::Config(format!(
            "runtime.threads must be <= {MAX_THREADS}, got {threads}"
        )));
    }
    Ok(())
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
            err.to_string().contains("binds to all interfaces"),
            "should reject public admin: {err}"
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
        assert!(err.to_string().contains("at least one filter chain"));
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
}
