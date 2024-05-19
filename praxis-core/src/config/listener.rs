//! Network listener configuration: bind address, protocol, TLS, and filter chains.
//!
//! Each listener becomes a bound socket at startup; HTTP listeners are served
//! by Pingora, TCP listeners by the bidirectional forwarder.

use serde::Deserialize;

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
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]

pub enum ProtocolKind {
    /// HTTP/1.1 and HTTP/2 (default).
    #[default]
    Http,

    /// Raw TCP / L4 forwarding. Requires an `upstream` address.
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
// Listener
// -----------------------------------------------------------------------------

/// A network listener (address + protocol + optional TLS).
///
/// ```
/// use praxis_core::config::Listener;
///
/// let listener: Listener = serde_yaml::from_str(r#"
/// name: web
/// address: "0.0.0.0:8080"
/// "#).unwrap();
/// assert_eq!(listener.name, "web");
/// assert_eq!(listener.address, "0.0.0.0:8080");
/// assert!(listener.tls.is_none());
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct Listener {
    /// Unique name for this listener.
    pub name: String,

    /// Address to bind to (e.g. "0.0.0.0:8080").
    pub address: String,

    /// Protocol this listener handles. Default: `http`.
    #[serde(default)]
    pub protocol: ProtocolKind,

    /// TLS configuration for the listener.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Upstream address for TCP listeners (e.g. "10.0.0.1:5432").
    ///
    /// Required when `protocol: tcp`. Ignored for HTTP listeners.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Named filter chains to apply to this listener.
    #[serde(default)]
    pub filter_chains: Vec<String>,

    /// Idle timeout in milliseconds for TCP forwarding sessions.
    ///
    /// When set, `copy_bidirectional` is wrapped in a deadline.
    /// Connections idle longer than this are closed. Only applies
    /// to `protocol: tcp` listeners. Default: no timeout.
    #[serde(default)]
    pub tcp_idle_timeout_ms: Option<u64>,
}

// -----------------------------------------------------------------------------
// TLS Config
// -----------------------------------------------------------------------------

/// TLS certificate and key paths.
///
/// ```
/// use praxis_core::config::TlsConfig;
///
/// let tls: TlsConfig = serde_yaml::from_str(r#"
/// cert_path: "/etc/ssl/cert.pem"
/// key_path: "/etc/ssl/key.pem"
/// "#).unwrap();
/// assert_eq!(tls.cert_path, "/etc/ssl/cert.pem");
/// assert_eq!(tls.key_path, "/etc/ssl/key.pem");
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: String,

    /// Path to the TLS private key file.
    pub key_path: String,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listener_without_tls() {
        let yaml = "name: test\naddress: \"0.0.0.0:8080\"";
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.address, "0.0.0.0:8080");
        assert!(listener.tls.is_none());
    }

    #[test]
    fn parse_listener_with_tls() {
        let yaml = r#"
name: secure
address: "0.0.0.0:443"
tls:
  cert_path: "/certs/server.crt"
  key_path: "/certs/server.key"
"#;
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.address, "0.0.0.0:443");
        let tls = listener.tls.unwrap();
        assert_eq!(tls.cert_path, "/certs/server.crt");
        assert_eq!(tls.key_path, "/certs/server.key");
    }

    #[test]
    fn parse_listener_defaults_to_http() {
        let yaml = "name: test\naddress: \"0.0.0.0:8080\"";
        let listener: Listener = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(listener.protocol, ProtocolKind::Http);
        assert!(listener.upstream.is_none());
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
        assert_eq!(listener.protocol, ProtocolKind::Tcp);
        assert_eq!(listener.upstream.as_deref(), Some("10.0.0.1:5432"));
    }

    #[test]
    fn protocol_stack_tcp() {
        let stack = ProtocolKind::Tcp.stack();
        assert_eq!(stack, &[ProtocolKind::Tcp]);
    }

    #[test]
    fn protocol_stack_http_includes_tcp() {
        let stack = ProtocolKind::Http.stack();
        assert_eq!(stack, &[ProtocolKind::Tcp, ProtocolKind::Http]);
    }

    #[test]
    fn http_supports_tcp_filters() {
        assert!(ProtocolKind::Http.supports(&ProtocolKind::Tcp));
    }

    #[test]
    fn tcp_does_not_support_http_filters() {
        assert!(!ProtocolKind::Tcp.supports(&ProtocolKind::Http));
    }

    #[test]
    fn tcp_supports_tcp_filters() {
        assert!(ProtocolKind::Tcp.supports(&ProtocolKind::Tcp));
    }

    #[test]
    fn http_supports_http_filters() {
        assert!(ProtocolKind::Http.supports(&ProtocolKind::Http));
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
        assert_eq!(listener.tcp_idle_timeout_ms, Some(30000));
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
        assert!(listener.tcp_idle_timeout_ms.is_none());
    }
}
