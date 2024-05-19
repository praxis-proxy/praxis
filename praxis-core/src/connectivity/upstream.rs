//! Resolved upstream endpoint: address, TLS settings, and connection options.
//!
//! Produced by the load-balancer filter and consumed by the protocol layer
//! to open connections to backends.

use super::ConnectionOptions;

// -----------------------------------------------------------------------------
// Upstream
// -----------------------------------------------------------------------------

/// An upstream endpoint to proxy requests to.
///
/// ```
/// use praxis_core::connectivity::{ConnectionOptions, Upstream};
///
/// let upstream = Upstream {
///     address: "127.0.0.1:8080".into(),
///     tls: false,
///     sni: String::new(),
///     connection: ConnectionOptions::default(),
/// };
///
/// assert_eq!(upstream.address, "127.0.0.1:8080");
/// assert!(!upstream.tls);
/// ```
#[derive(Debug, Clone)]

pub struct Upstream {
    /// Address in `host:port` form.
    pub address: String,

    /// Connection tuning for this upstream.
    pub connection: ConnectionOptions,

    /// SNI hostname for TLS.
    pub sni: String,

    /// Whether to use TLS to this upstream.
    pub tls: bool,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_upstream(address: &str, tls: bool, sni: &str) -> Upstream {
        Upstream {
            address: address.into(),
            tls,
            sni: sni.into(),
            connection: ConnectionOptions::default(),
        }
    }

    #[test]
    fn fields_are_accessible() {
        let u = make_upstream("10.0.0.1:8080", false, "");
        assert_eq!(u.address, "10.0.0.1:8080");
        assert!(!u.tls);
        assert_eq!(u.sni, "");
    }

    #[test]
    fn tls_with_sni() {
        let u = make_upstream("10.0.0.1:443", true, "api.example.com");
        assert!(u.tls);
        assert_eq!(u.sni, "api.example.com");
    }
}
