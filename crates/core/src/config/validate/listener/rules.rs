// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Listener validation: presence, count, protocol constraints, and name uniqueness.

use std::{collections::HashSet, net::IpAddr};

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

    validate_unique_addresses(listeners)?;

    for listener in listeners.iter_mut() {
        validate_single_listener(listener)?;
    }

    Ok(())
}

/// Reject duplicate and overlapping bind addresses across listeners.
///
/// Parses addresses as [`SocketAddr`] before comparing so that the same
/// concrete IP (after IPv4-mapped normalization) on the same port is a
/// duplicate, and a wildcard bind overlaps every address it covers on
/// that port: `0.0.0.0` covers all IPv4 addresses, `[::]` covers both
/// families on dual-stack systems. Distinct specific IPs sharing a port
/// are valid. Pingora binds with `SO_REUSEPORT`, so overlapping binds
/// would succeed at startup and route connections non-deterministically
/// instead of failing loudly.
///
/// [`SocketAddr`]: std::net::SocketAddr
fn validate_unique_addresses(listeners: &[Listener]) -> Result<(), ProxyError> {
    let mut seen_raw = HashSet::new();
    let mut tracker = AddressOverlapTracker::default();
    for listener in listeners {
        if !seen_raw.insert(&listener.address) {
            return Err(ProxyError::Config(format!(
                "duplicate listener address '{}' (listeners '{}' and another share the same address)",
                listener.address, listener.name
            )));
        }
        if let Ok(addr) = listener.address.parse::<std::net::SocketAddr>()
            && tracker.record(addr)
        {
            return Err(ProxyError::Config(format!(
                "listener '{}' address '{}' overlaps with another listener on the same port",
                listener.name, listener.address
            )));
        }
    }
    Ok(())
}

/// Tracks parsed listener addresses to detect overlapping binds.
#[derive(Default)]
struct AddressOverlapTracker {
    /// Concrete `(ip, port)` pairs after IPv4-mapped normalization.
    seen_ips: HashSet<(IpAddr, u16)>,
    /// Ports bound by an IPv4 wildcard (`0.0.0.0`).
    v4_wildcard_ports: HashSet<u16>,
    /// Ports bound by an IPv6 wildcard (`[::]`, covers both families).
    v6_wildcard_ports: HashSet<u16>,
    /// Ports bound by a specific IPv4 address.
    v4_specific_ports: HashSet<u16>,
    /// Ports bound by a specific IPv6 address.
    v6_specific_ports: HashSet<u16>,
}

impl AddressOverlapTracker {
    /// Record `addr`, returning `true` when it overlaps a previous address.
    fn record(&mut self, addr: std::net::SocketAddr) -> bool {
        let ip = normalize_mapped_ip(addr.ip());
        let port = addr.port();
        let overlap = self.overlaps(ip, port);
        self.index(ip, port);
        overlap
    }

    /// Whether `(ip, port)` overlaps any previously recorded address.
    fn overlaps(&self, ip: IpAddr, port: u16) -> bool {
        let v6_wildcard = self.v6_wildcard_ports.contains(&port);
        match ip {
            IpAddr::V4(v4) if v4.is_unspecified() => {
                v6_wildcard || self.v4_wildcard_ports.contains(&port) || self.v4_specific_ports.contains(&port)
            },
            IpAddr::V6(v6) if v6.is_unspecified() => {
                v6_wildcard
                    || self.v4_wildcard_ports.contains(&port)
                    || self.v4_specific_ports.contains(&port)
                    || self.v6_specific_ports.contains(&port)
            },
            IpAddr::V4(_) => {
                v6_wildcard || self.v4_wildcard_ports.contains(&port) || self.seen_ips.contains(&(ip, port))
            },
            IpAddr::V6(_) => v6_wildcard || self.seen_ips.contains(&(ip, port)),
        }
    }

    /// Index `(ip, port)` for subsequent overlap checks.
    fn index(&mut self, ip: IpAddr, port: u16) {
        let ports = match ip {
            IpAddr::V4(v4) if v4.is_unspecified() => &mut self.v4_wildcard_ports,
            IpAddr::V6(v6) if v6.is_unspecified() => &mut self.v6_wildcard_ports,
            IpAddr::V4(_) => &mut self.v4_specific_ports,
            IpAddr::V6(_) => &mut self.v6_specific_ports,
        };
        let _new_port = ports.insert(port);
        if !ip.is_unspecified() {
            let _new_ip = self.seen_ips.insert((ip, port));
        }
    }
}

/// Normalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to IPv4.
fn normalize_mapped_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Validate a single listener: address, protocol constraints, TLS, timeouts, and limits.
fn validate_single_listener(listener: &mut Listener) -> Result<(), ProxyError> {
    if listener.name.is_empty() {
        return Err(ProxyError::Config("listener name must not be empty".into()));
    }
    super::super::validate_name_chars(&listener.name, "listener")?;
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

/// Validate `max_connections` is at least 1 and within the allowed ceiling.
fn validate_max_connections(listener: &Listener) -> Result<(), ProxyError> {
    let Some(v) = listener.max_connections else {
        return Ok(());
    };
    let name = &listener.name;
    if v == 0 {
        return Err(ProxyError::Config(format!(
            "listener '{name}': max_connections must be >= 1",
        )));
    }
    if v > crate::config::validate::MAX_CONNECTIONS {
        return Err(ProxyError::Config(format!(
            "listener '{name}': max_connections ({v}) exceeds maximum ({})",
            crate::config::validate::MAX_CONNECTIONS,
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

    if let Some(upstream) = &listener.upstream {
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    fn reject_duplicate_listener_addresses() {
        let yaml = r#"
listeners:
  - name: web1
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: web2
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
            err.to_string().contains("duplicate listener address"),
            "should reject duplicate addresses: {err}"
        );
    }

    #[test]
    fn reject_overlapping_wildcard_addresses() {
        let yaml = r#"
listeners:
  - name: ipv4
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: ipv6
    address: "[::]:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("overlaps"),
            "0.0.0.0 and [::] on same port should overlap: {err}"
        );
    }

    #[test]
    fn accept_distinct_specific_ips_on_same_port() {
        let yaml = r#"
listeners:
  - name: a
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: b
    address: "127.0.0.2:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).expect("distinct specific IPs on the same port do not overlap");
    }

    #[test]
    fn reject_wildcard_then_specific_on_same_port() {
        let yaml = r#"
listeners:
  - name: all
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: loopback
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("overlaps"),
            "wildcard covers the specific IP on the same port: {err}"
        );
    }

    #[test]
    fn reject_specific_then_wildcard_on_same_port() {
        let yaml = r#"
listeners:
  - name: loopback
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: all
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
            err.to_string().contains("overlaps"),
            "wildcard covers the earlier specific IP on the same port: {err}"
        );
    }

    #[test]
    fn reject_ipv4_mapped_duplicate() {
        let yaml = r#"
listeners:
  - name: v4
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: mapped
    address: "[::ffff:127.0.0.1]:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("overlaps"),
            "IPv4-mapped IPv6 address is the same concrete IP: {err}"
        );
    }

    #[test]
    fn accept_v4_wildcard_with_v6_specific_on_same_port() {
        let yaml = r#"
listeners:
  - name: v4all
    address: "0.0.0.0:8080"
    filter_chains: [main]
  - name: v6loop
    address: "[::1]:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).expect("IPv4 wildcard does not cover a specific IPv6 address");
    }

    #[test]
    fn reject_v6_wildcard_with_v4_specific_on_same_port() {
        let yaml = r#"
listeners:
  - name: v6all
    address: "[::]:8080"
    filter_chains: [main]
  - name: v4loop
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("overlaps"),
            "[::] covers IPv4 on dual-stack systems: {err}"
        );
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
                tcp_session_timeout_ms: None,
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

    #[test]
    fn accept_listener_without_tls() {
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
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_listener_max_connections_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    max_connections: 1000001
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject max_connections > 1M: {err}"
        );
    }

    #[test]
    fn accept_listener_max_connections_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    max_connections: 1000000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
