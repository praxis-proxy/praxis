// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Timeout and TCP duration validation for listeners.

use tracing::debug;

use super::super::cluster::MAX_TIMEOUT_MS;
use crate::{
    config::{Listener, ProtocolKind},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Timeout Constants
// -----------------------------------------------------------------------------

/// Default TCP idle timeout in milliseconds (5 minutes).
const DEFAULT_TCP_IDLE_TIMEOUT_MS: u64 = 300_000;

/// Maximum allowed TCP max duration in seconds (24 hours).
const MAX_TCP_DURATION_SECS: u64 = 86_400;

// -----------------------------------------------------------------------------
// Timeout Defaults
// -----------------------------------------------------------------------------

/// Apply default TCP idle timeout when not explicitly configured.
pub(super) fn apply_tcp_defaults(listener: &mut Listener) {
    if listener.protocol == ProtocolKind::Tcp && listener.tcp_idle_timeout_ms.is_none() {
        debug!(
            listener = %listener.name,
            default_ms = DEFAULT_TCP_IDLE_TIMEOUT_MS,
            "applying default TCP idle timeout"
        );
        listener.tcp_idle_timeout_ms = Some(DEFAULT_TCP_IDLE_TIMEOUT_MS);
    }
}

// -----------------------------------------------------------------------------
// Timeout Validation
// -----------------------------------------------------------------------------

/// Validate listener-level timeout values are within the allowed maximum.
pub(super) fn validate_listener_timeouts(listener: &Listener) -> Result<(), ProxyError> {
    let name = &listener.name;

    for (field, value) in [
        ("tcp_idle_timeout_ms", listener.tcp_idle_timeout_ms),
        ("downstream_read_timeout_ms", listener.downstream_read_timeout_ms),
    ] {
        if let Some(v) = value {
            if v == 0 {
                return Err(ProxyError::Config(format!("listener '{name}': {field} must be > 0")));
            }
            if v > MAX_TIMEOUT_MS {
                return Err(ProxyError::Config(format!(
                    "listener '{name}': {field} ({v} ms) exceeds maximum ({MAX_TIMEOUT_MS} ms / 1 hour)"
                )));
            }
        }
    }

    Ok(())
}

/// Validate `tcp_max_duration_secs` is within a sane range.
pub(super) fn validate_tcp_max_duration(listener: &Listener) -> Result<(), ProxyError> {
    if let Some(secs) = listener.tcp_max_duration_secs {
        if secs == 0 {
            return Err(ProxyError::Config(format!(
                "listener '{}': tcp_max_duration_secs must be > 0",
                listener.name
            )));
        }
        if secs > MAX_TCP_DURATION_SECS {
            return Err(ProxyError::Config(format!(
                "listener '{name}': tcp_max_duration_secs ({secs}s) exceeds maximum ({MAX_TCP_DURATION_SECS}s / 24h)",
                name = listener.name
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
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use crate::config::Config;

    #[test]
    fn reject_listener_timeout_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_read_timeout_ms: 7200000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject listener timeout > 1 hour, got: {err}"
        );
    }

    #[test]
    fn reject_tcp_idle_timeout_exceeding_maximum() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_idle_timeout_ms: 7200000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "should reject TCP idle timeout > 1 hour, got: {err}"
        );
    }

    #[test]
    fn accept_listener_timeout_at_maximum() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_read_timeout_ms: 3600000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_zero_downstream_read_timeout() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    downstream_read_timeout_ms: 0
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must be > 0"),
            "zero timeout should be rejected: {err}"
        );
    }

    #[test]
    fn tcp_listener_gets_default_idle_timeout() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].tcp_idle_timeout_ms,
            Some(300_000),
            "TCP listener should get default 5-minute idle timeout"
        );
    }

    #[test]
    fn tcp_listener_preserves_explicit_idle_timeout() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_idle_timeout_ms: 60000
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].tcp_idle_timeout_ms,
            Some(60000),
            "explicit idle timeout should be preserved"
        );
    }

    #[test]
    fn accept_tcp_max_duration_secs() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_max_duration_secs: 3600
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].tcp_max_duration_secs,
            Some(3600),
            "tcp_max_duration_secs should be parsed"
        );
    }

    #[test]
    fn reject_zero_tcp_max_duration() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_max_duration_secs: 0
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("tcp_max_duration_secs must be > 0"),
            "got: {err}"
        );
    }

    #[test]
    fn accept_tcp_idle_timeout_at_maximum() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_idle_timeout_ms: 3600000
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.listeners[0].tcp_idle_timeout_ms,
            Some(3_600_000),
            "TCP idle timeout at maximum should be accepted"
        );
    }

    #[test]
    fn reject_tcp_max_duration_exceeding_24h() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    tcp_max_duration_secs: 100000
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }
}
