// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Listener validation: presence, count, protocol constraints, and name uniqueness.

use std::collections::HashSet;

use crate::{
    config::{Listener, ProtocolKind},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Listener Constants
// -----------------------------------------------------------------------------

/// Maximum number of listeners.
const MAX_LISTENERS: usize = 1_000;

// -----------------------------------------------------------------------------
// Listener Validation
// -----------------------------------------------------------------------------

/// Validate listener count, addresses, protocol constraints, and TLS paths.
pub(in crate::config::validate) fn validate_listeners(listeners: &mut [Listener]) -> Result<(), ProxyError> {
    if listeners.is_empty() {
        return Err(ProxyError::Config("at least one listener required".into()));
    }
    if listeners.len() > MAX_LISTENERS {
        return Err(ProxyError::Config(format!(
            "too many listeners ({}, max {MAX_LISTENERS})",
            listeners.len()
        )));
    }

    for listener in listeners.iter_mut() {
        validate_single_listener(listener)?;
    }

    Ok(())
}

/// Validate a single listener: address, protocol constraints, TLS, timeouts, and limits.
fn validate_single_listener(listener: &mut Listener) -> Result<(), ProxyError> {
    super::address::validate_address(&listener.address, &listener.name)?;
    validate_max_connections(listener)?;

    if listener.protocol == ProtocolKind::Tcp {
        validate_tcp_routing(listener)?;
    }

    super::timeouts::apply_tcp_defaults(listener);

    if let Some(tls) = &listener.tls {
        tls.validate()
            .map_err(|e| ProxyError::Config(format!("listener '{name}': {e}", name = listener.name)))?;
    }

    super::timeouts::validate_listener_timeouts(listener)?;

    if listener.protocol == ProtocolKind::Tcp {
        super::timeouts::validate_tcp_max_duration(listener)?;
    }

    Ok(())
}

/// Validate `max_connections` is at least 1 when set.
fn validate_max_connections(listener: &Listener) -> Result<(), ProxyError> {
    if listener.max_connections == Some(0) {
        return Err(ProxyError::Config(format!(
            "listener '{name}': max_connections must be >= 1",
            name = listener.name,
        )));
    }
    Ok(())
}

/// Validate TCP listener routing: upstream, cluster, and filter chain constraints.
fn validate_tcp_routing(listener: &Listener) -> Result<(), ProxyError> {
    if listener.upstream.is_some() && listener.cluster.is_some() {
        return Err(ProxyError::Config(format!(
            "TCP listener '{}' cannot have both 'upstream' and 'cluster'",
            listener.name
        )));
    }

    if listener.upstream.is_none() && listener.cluster.is_none() && listener.filter_chains.is_empty() {
        return Err(ProxyError::Config(format!(
            "TCP listener '{}' requires an upstream address, cluster, or filter chains",
            listener.name
        )));
    }

    if let Some(ref upstream) = listener.upstream {
        super::address::validate_tcp_upstream(upstream, &listener.name)?;
    }

    Ok(())
}

/// Reject duplicate listener names.
pub(in crate::config::validate) fn validate_listener_names(listeners: &[Listener]) -> Result<(), ProxyError> {
    let mut seen = HashSet::new();
    for listener in listeners {
        if !seen.insert(&listener.name) {
            return Err(ProxyError::Config(format!(
                "duplicate listener name '{}'",
                listener.name
            )));
        }
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
    clippy::default_trait_access,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::validate_listeners;
    use crate::config::{Config, Listener};

    #[test]
    fn reject_no_listeners() {
        let yaml = r#"
listeners: []
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("at least one listener"));
    }

    #[test]
    fn validate_listeners_rejects_empty() {
        let err = validate_listeners(&mut []).unwrap_err();
        assert!(err.to_string().contains("at least one listener"));
    }

    #[test]
    fn tcp_listener_without_upstream_or_chains_is_rejected() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires an upstream address, cluster, or filter chains"),
            "error should mention upstream, cluster, or filter chains: {err}"
        );
    }

    #[test]
    fn tcp_listener_with_both_upstream_and_cluster_is_rejected() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    cluster: db_pool
    filter_chains: [tcp_lb]
filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints: ["10.0.0.1:5432"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("cannot have both 'upstream' and 'cluster'"),
            "error should mention both upstream and cluster: {err}"
        );
    }

    #[test]
    fn tcp_listener_with_cluster_and_chains_is_accepted() {
        let yaml = r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    cluster: db_pool
    filter_chains: [tcp_lb]
filter_chains:
  - name: tcp_lb
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: db_pool
            endpoints: ["10.0.0.1:5432"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].cluster.as_deref(),
            Some("db_pool"),
            "cluster should be preserved"
        );
    }

    #[test]
    fn reject_duplicate_listener_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: web
    address: "0.0.0.0:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate listener name"));
    }

    #[test]
    fn reject_too_many_listeners() {
        let mut listeners: Vec<Listener> = (0..1_001)
            .map(|i| Listener {
                address: format!("127.0.0.1:{}", 10_000 + i),
                cluster: None,
                downstream_read_timeout_ms: None,
                filter_chains: vec![],
                max_connections: None,
                name: format!("l{i}"),
                protocol: Default::default(),
                tcp_idle_timeout_ms: None,
                tcp_max_duration_secs: None,
                tls: None,
                upstream: None,
            })
            .collect();
        let err = validate_listeners(&mut listeners).unwrap_err();
        assert!(err.to_string().contains("too many listeners"), "got: {err}");
    }

    #[test]
    fn reject_zero_max_connections() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    max_connections: 0
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("max_connections must be >= 1"), "got: {err}");
    }

    #[test]
    fn accept_valid_max_connections() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    max_connections: 1
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_tls_cert_path_traversal() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:443"
    tls:
      certificates:
        - cert_path: "/etc/../../tmp/evil.pem"
          key_path: "/etc/ssl/key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("path traversal"), "got: {err}");
    }

    #[test]
    fn reject_tls_key_path_traversal() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:443"
    tls:
      certificates:
        - cert_path: "certs/cert.pem"
          key_path: "../secret/key.pem"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("path traversal"), "got: {err}");
    }
}
