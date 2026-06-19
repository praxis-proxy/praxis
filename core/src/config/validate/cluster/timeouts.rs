// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Timeout bounds validation for clusters.

use super::MAX_TIMEOUT_MS;
use crate::{config::Cluster, errors::ProxyError};

// -----------------------------------------------------------------------------
// Timeout Validation
// -----------------------------------------------------------------------------

/// Validates timeout bounds and relational consistency.
pub(super) fn validate_timeouts(cluster: &Cluster) -> Result<(), ProxyError> {
    let name = &cluster.name;

    for (field, value) in [
        ("connection_timeout_ms", cluster.connection_timeout_ms),
        ("total_connection_timeout_ms", cluster.total_connection_timeout_ms),
        ("idle_timeout_ms", cluster.idle_timeout_ms),
        ("read_timeout_ms", cluster.read_timeout_ms),
        ("write_timeout_ms", cluster.write_timeout_ms),
    ] {
        if let Some(0) = value {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': {field} is 0 (must be > 0)"
            )));
        }
        if let Some(v) = value
            && v > MAX_TIMEOUT_MS
        {
            return Err(ProxyError::Config(format!(
                "cluster '{name}': {field} ({v} ms) exceeds maximum ({MAX_TIMEOUT_MS} ms / 1 hour)"
            )));
        }
    }

    if let (Some(conn), Some(total)) = (cluster.connection_timeout_ms, cluster.total_connection_timeout_ms)
        && conn > total
    {
        return Err(ProxyError::Config(format!(
            "cluster '{name}': connection_timeout_ms ({conn}) exceeds \
             total_connection_timeout_ms ({total})"
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
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use crate::config::Config;

    #[test]
    fn reject_zero_timeout() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("connection_timeout_ms is 0"), "got: {err}");
    }

    #[test]
    fn reject_timeout_exceeding_maximum() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    idle_timeout_ms: 7200000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject timeout > 1 hour, got: {err}"
        );
    }

    #[test]
    fn accept_timeout_at_maximum() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 3600000
    total_connection_timeout_ms: 3600000
    idle_timeout_ms: 3600000
    read_timeout_ms: 3600000
    write_timeout_ms: 3600000
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_connection_exceeds_total() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 10000
    total_connection_timeout_ms: 5000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    #[test]
    fn reject_zero_total_connection_timeout() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    total_connection_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("total_connection_timeout_ms is 0"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_zero_idle_timeout() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    idle_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("idle_timeout_ms is 0"), "got: {err}");
    }

    #[test]
    fn reject_zero_read_timeout() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    read_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("read_timeout_ms is 0"), "got: {err}");
    }

    #[test]
    fn reject_zero_write_timeout() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    write_timeout_ms: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("write_timeout_ms is 0"), "got: {err}");
    }

    #[test]
    fn accept_valid_timeouts() {
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
  - name: "backend"
    endpoints: ["10.0.0.1:80"]
    connection_timeout_ms: 5000
    total_connection_timeout_ms: 10000
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
