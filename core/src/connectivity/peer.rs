// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared [`HttpPeer`] construction helpers for TLS, SNI, and connection options.
//!
//! Used by both the protocol layer's upstream peer builder and the
//! filter layer's sub-request executor to avoid duplicating TLS
//! and connection option mapping.
//!
//! [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer

use std::sync::Arc;

use pingora_core::upstreams::peer::HttpPeer;

use super::ConnectionOptions;

// ---------------------------------------------------------------------------
// Connection Options
// ---------------------------------------------------------------------------

/// Apply configured connection timeouts to an [`HttpPeer`].
///
/// ```
/// use pingora_core::upstreams::peer::HttpPeer;
/// use praxis_core::connectivity::{ConnectionOptions, peer};
///
/// let mut p = HttpPeer::new("127.0.0.1:8080", false, String::new());
/// peer::apply_connection_options(&mut p, &ConnectionOptions::default());
/// ```
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
#[inline]
pub fn apply_connection_options(peer: &mut HttpPeer, opts: &ConnectionOptions) {
    peer.options.connection_timeout = opts.connection_timeout;
    peer.options.total_connection_timeout = opts.total_connection_timeout;
    peer.options.idle_timeout = opts.idle_timeout;
    peer.options.read_timeout = opts.read_timeout;
    peer.options.write_timeout = opts.write_timeout;
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// Apply pre-cached TLS settings to an [`HttpPeer`].
///
/// Maps CA certificates, client certificates, and the verify toggle
/// from [`CachedClusterTls`] onto the peer's options.
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
/// [`CachedClusterTls`]: praxis_tls::CachedClusterTls
pub fn apply_cached_tls(peer: &mut HttpPeer, tls: &praxis_tls::CachedClusterTls, address: &str) {
    if !tls.verify() {
        tracing::debug!(upstream = %address, "upstream TLS verification disabled for this peer");
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
    }

    if let Some(ca) = tls.ca() {
        peer.options.ca = Some(Arc::from(ca_from_cached(ca)));
    }

    if let Some(client) = tls.client_cert() {
        peer.client_cert_key = Some(Arc::new(client_cert_from_cached(client)));
    }
}

/// Convert cached CA DER bytes into [`WrappedX509`] values.
///
/// [`WrappedX509`]: pingora_core::utils::tls::WrappedX509
pub fn ca_from_cached(cached: &praxis_tls::CachedCaCerts) -> Vec<pingora_core::utils::tls::WrappedX509> {
    cached
        .der_certs()
        .iter()
        .filter_map(|der| {
            pingora_core::utils::tls::WrappedX509::parse(der.clone())
                .inspect_err(|e| tracing::warn!("failed to parse cached CA cert: {e}"))
                .ok()
        })
        .collect()
}

/// Convert cached client cert/key DER bytes into a [`CertKey`].
///
/// [`CertKey`]: pingora_core::utils::tls::CertKey
pub fn client_cert_from_cached(cached: &praxis_tls::CachedClientCert) -> pingora_core::utils::tls::CertKey {
    pingora_core::utils::tls::CertKey::new(cached.cert_der().to_vec(), cached.key_der().to_vec())
}

// ---------------------------------------------------------------------------
// SNI
// ---------------------------------------------------------------------------

/// Derive an SNI hostname from an `address` string in `host:port` form.
///
/// Returns the host portion if it is a DNS name. Returns an empty
/// string if the host is an IP address (IP-based SNI is not standard
/// per [RFC 6066]).
///
/// ```
/// use praxis_core::connectivity::peer;
///
/// assert_eq!(peer::derive_sni("api.example.com:443"), "api.example.com");
/// assert_eq!(peer::derive_sni("127.0.0.1:443"), "");
/// ```
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066
pub fn derive_sni(address: &str) -> String {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    let host_bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host_bare.parse::<std::net::IpAddr>().is_ok() {
        tracing::warn!(
            address,
            "upstream is an IP without explicit SNI; TLS hostname verification is meaningless"
        );
        return String::new();
    }
    tracing::debug!(address, sni = host, "derived SNI from upstream address");
    host.to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn derive_sni_extracts_hostname() {
        assert_eq!(
            derive_sni("backend.example.com:8443"),
            "backend.example.com",
            "should extract hostname from host:port"
        );
    }

    #[test]
    fn derive_sni_returns_empty_for_ip() {
        assert_eq!(derive_sni("127.0.0.1:8443"), "", "should return empty for IP address");
    }

    #[test]
    fn derive_sni_returns_empty_for_ipv6() {
        assert_eq!(derive_sni("[::1]:8443"), "", "should return empty for IPv6 address");
    }

    #[test]
    fn apply_connection_options_sets_timeouts() {
        use std::time::Duration;

        let opts = ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(1)),
            read_timeout: Some(Duration::from_secs(2)),
            write_timeout: Some(Duration::from_secs(3)),
            idle_timeout: Some(Duration::from_secs(4)),
            total_connection_timeout: Some(Duration::from_secs(5)),
        };
        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        apply_connection_options(&mut peer, &opts);

        assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(1)));
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(2)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(3)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_secs(4)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(5)));
    }
}
