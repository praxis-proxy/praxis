// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Address validation for listeners.

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Address Validation
// -----------------------------------------------------------------------------

/// Verify the listener address parses as a valid `SocketAddr`.
pub(super) fn validate_address(addr: &str, listener_name: &str) -> Result<(), ProxyError> {
    use std::net::SocketAddr;

    addr.parse::<SocketAddr>().map_err(|_parse_err| {
        ProxyError::Config(format!("listener '{listener_name}': invalid socket address '{addr}'"))
    })?;
    Ok(())
}

/// Validate that a TCP upstream address is a valid socket address.
pub(super) fn validate_tcp_upstream(addr: &str, listener_name: &str) -> Result<(), ProxyError> {
    use std::net::SocketAddr;

    addr.parse::<SocketAddr>().map_err(|_parse_err| {
        ProxyError::Config(format!(
            "TCP listener '{listener_name}': invalid upstream socket address '{addr}'"
        ))
    })?;

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
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use crate::config::Config;

    #[test]
    fn reject_invalid_listener_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "not-a-socket-addr"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("invalid socket address"), "got: {err}");
    }

    #[test]
    fn accept_valid_listener_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "x"
      - filter: load_balancer
        clusters:
          - name: "x"
            endpoints: ["1.2.3.4:80"]
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_invalid_tcp_upstream_address() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "not-a-socket-addr"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("invalid upstream socket address"),
            "got: {err}"
        );
    }

    #[test]
    fn accept_ipv6_listener_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "[::1]:8080"
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
    fn accept_valid_tcp_upstream_address() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
