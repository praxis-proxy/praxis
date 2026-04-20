// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Network listener configuration: bind address, protocol, TLS, and filter chains.

pub use praxis_tls::ListenerTls;
use serde::Deserialize;

// -----------------------------------------------------------------------------
// Listener
// -----------------------------------------------------------------------------

/// A network listener (address + protocol + optional TLS).
///
/// ```
/// use praxis_core::config::Listener;
///
/// let listener: Listener = serde_yaml::from_str(
///     r#"
/// name: web
/// address: "0.0.0.0:8080"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(listener.name, "web");
/// assert_eq!(listener.address, "0.0.0.0:8080");
/// assert!(listener.tls.is_none());
/// ```
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// Unique name for this listener.
    pub name: String,

    /// Address to bind to (e.g. "0.0.0.0:8080").
    pub address: String,

    /// Downstream read timeout in milliseconds for HTTP listeners.
    ///
    /// Only applies to `protocol: http` listeners.
    #[serde(default)]
    pub downstream_read_timeout_ms: Option<u64>,

    /// Named filter chains to apply to this listener.
    #[serde(default)]
    pub filter_chains: Vec<String>,

    /// Protocol this listener handles. Default: `http`.
    #[serde(default)]
    pub protocol: ProtocolKind,

    /// Idle timeout in milliseconds for TCP forwarding sessions.
    ///
    /// When set, `copy_bidirectional` is wrapped in a deadline.
    /// Connections idle longer than this are closed. Only applies
    /// to `protocol: tcp` listeners. Defaults to 300,000 ms
    /// (5 minutes) for TCP listeners when not set.
    #[serde(default)]
    pub tcp_idle_timeout_ms: Option<u64>,

    /// Maximum total session duration in seconds for TCP listeners.
    ///
    /// When set, the entire TCP session is capped at this duration
    /// regardless of activity. Only applies to `protocol: tcp` listeners.
    #[serde(default)]
    pub tcp_max_duration_secs: Option<u64>,

    /// TLS configuration for the listener.
    #[serde(default)]
    pub tls: Option<ListenerTls>,

    /// Upstream address for TCP listeners (e.g. "10.0.0.1:5432").
    ///
    /// Required for `protocol: tcp` unless filter chains provide
    /// routing (e.g. via `sni_router`). Ignored for HTTP listeners.
    #[serde(default)]
    pub upstream: Option<String>,
}

// -----------------------------------------------------------------------------
// ProtocolKind
// -----------------------------------------------------------------------------

/// The protocol a listener accepts.
///
/// ```
/// use praxis_core::config::ProtocolKind;
///
/// let kind: ProtocolKind = serde_yaml::from_str("http").unwrap();
/// assert_eq!(kind, ProtocolKind::Http);
/// ```
#[derive(Debug, Clone, Deserialize, serde::Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    /// HTTP (default).
    #[default]
    Http,

    /// Raw TCP / L4 forwarding. Requires an `upstream` address
    /// unless filter chains provide routing (e.g. via `sni_router`).
    Tcp,
}

impl ProtocolKind {
    /// Returns the protocol stack for this protocol kind.
    ///
    /// Higher-level protocols include lower levels.
    /// HTTP includes TCP. A filter for level X is compatible
    /// with any listener whose stack includes X.
    ///
    /// ```
    /// use praxis_core::config::ProtocolKind;
    ///
    /// assert_eq!(ProtocolKind::Tcp.stack().len(), 1);
    /// assert_eq!(ProtocolKind::Http.stack().len(), 2);
    /// ```
    pub fn stack(&self) -> &'static [ProtocolKind] {
        match self {
            Self::Tcp => &[ProtocolKind::Tcp],
            Self::Http => &[ProtocolKind::Tcp, ProtocolKind::Http],
        }
    }

    /// Whether this protocol supports a filter at the given protocol level.
    ///
    /// ```
    /// use praxis_core::config::ProtocolKind;
    ///
    /// assert!(ProtocolKind::Http.supports(&ProtocolKind::Tcp));
    /// assert!(!ProtocolKind::Tcp.supports(&ProtocolKind::Http));
    /// ```
    pub fn supports(&self, filter_level: &ProtocolKind) -> bool {
        self.stack().contains(filter_level)
    }
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
    use super::*;

    #[test]
    fn parse_listener_without_tls() {
        let yaml = "name: test\naddress: \"0.0.0.0:8080\"";
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.address, "0.0.0.0:8080", "address should be parsed");
        assert!(listener.tls.is_none(), "tls should default to None");
    }

    #[test]
    fn parse_listener_with_tls() {
        let yaml = r#"
name: secure
address: "0.0.0.0:443"
tls:
  certificates:
    - cert_path: "/certs/server.crt"
      key_path: "/certs/server.key"
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.address, "0.0.0.0:443", "address mismatch");
        let tls = listener.tls.unwrap();
        let (cert, key) = tls.primary_cert_paths();
        assert_eq!(cert, "/certs/server.crt", "cert_path mismatch");
        assert_eq!(key, "/certs/server.key", "key_path mismatch");
    }

    #[test]
    fn parse_listener_defaults_to_http() {
        let yaml = "name: test\naddress: \"0.0.0.0:8080\"";
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.protocol, ProtocolKind::Http, "default protocol should be Http");
        assert!(listener.upstream.is_none(), "upstream should default to None for HTTP");
    }

    #[test]
    fn parse_tcp_listener() {
        let yaml = r#"
name: db
address: "0.0.0.0:5432"
protocol: tcp
upstream: "10.0.0.1:5432"
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.protocol, ProtocolKind::Tcp, "protocol should be Tcp");
        assert_eq!(
            listener.upstream.as_deref(),
            Some("10.0.0.1:5432"),
            "upstream address mismatch"
        );
    }

    #[test]
    fn protocol_stack_tcp() {
        let stack = ProtocolKind::Tcp.stack();
        assert_eq!(stack, &[ProtocolKind::Tcp], "TCP stack should contain only Tcp");
    }

    #[test]
    fn protocol_stack_http_includes_tcp() {
        let stack = ProtocolKind::Http.stack();
        assert_eq!(
            stack,
            &[ProtocolKind::Tcp, ProtocolKind::Http],
            "HTTP stack should include both"
        );
    }

    #[test]
    fn http_supports_tcp_filters() {
        assert!(
            ProtocolKind::Http.supports(&ProtocolKind::Tcp),
            "HTTP should support TCP filters"
        );
    }

    #[test]
    fn tcp_does_not_support_http_filters() {
        assert!(
            !ProtocolKind::Tcp.supports(&ProtocolKind::Http),
            "TCP should not support HTTP filters"
        );
    }

    #[test]
    fn tcp_supports_tcp_filters() {
        assert!(
            ProtocolKind::Tcp.supports(&ProtocolKind::Tcp),
            "TCP should support TCP filters"
        );
    }

    #[test]
    fn http_supports_http_filters() {
        assert!(
            ProtocolKind::Http.supports(&ProtocolKind::Http),
            "HTTP should support HTTP filters"
        );
    }

    #[test]
    fn parse_tcp_listener_with_idle_timeout() {
        let yaml = r#"
name: db
address: "0.0.0.0:5432"
protocol: tcp
upstream: "10.0.0.1:5432"
tcp_idle_timeout_ms: 30000
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            listener.tcp_idle_timeout_ms,
            Some(30000),
            "idle timeout should be 30000"
        );
    }

    #[test]
    fn tcp_idle_timeout_defaults_to_none() {
        let yaml = r#"
name: db
address: "0.0.0.0:5432"
protocol: tcp
upstream: "10.0.0.1:5432"
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert!(
            listener.tcp_idle_timeout_ms.is_none(),
            "idle timeout should default to None"
        );
    }

    #[test]
    fn parse_listener_with_downstream_read_timeout() {
        let yaml = r#"
name: web
address: "0.0.0.0:8080"
downstream_read_timeout_ms: 5000
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            listener.downstream_read_timeout_ms,
            Some(5000),
            "downstream read timeout should be 5000"
        );
    }

    #[test]
    fn downstream_read_timeout_defaults_to_none() {
        let yaml = "name: test\naddress: \"0.0.0.0:8080\"";
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert!(
            listener.downstream_read_timeout_ms.is_none(),
            "downstream read timeout should default to None"
        );
    }
}
