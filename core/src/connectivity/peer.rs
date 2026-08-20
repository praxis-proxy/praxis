// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared [`HttpPeer`] construction helpers for TLS, SNI, and connection options.
//!
//! Used by both the protocol layer's upstream peer builder and the
//! filter layer's sub-request executor to avoid duplicating TLS
//! and connection option mapping.
//!
//! [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use pingora_core::upstreams::peer::HttpPeer;

use super::ConnectionOptions;

/// TTL for cached DNS entries.
const DNS_TTL_SECS: u64 = 60;

/// Maximum cached DNS entries before oldest-entry eviction.
const MAX_DNS_ENTRIES: usize = 1_024;

/// Address resolution failure.
#[derive(Debug, thiserror::Error)]
pub enum AddressResolutionError {
    /// The blocking resolver task could not complete.
    #[error("DNS resolution task failed for '{address}': {message}")]
    Task {
        /// Address being resolved.
        address: String,
        /// Join error text.
        message: String,
    },

    /// The operating-system resolver failed.
    #[error("upstream address resolution failed for '{address}': {source}")]
    Resolve {
        /// Address being resolved.
        address: String,
        /// Resolver error.
        #[source]
        source: std::io::Error,
    },

    /// DNS returned no usable address.
    #[error("upstream address '{0}' resolved to zero addresses")]
    Empty(String),
}

/// Cached DNS resolution result.
struct DnsCacheEntry {
    /// All addresses returned by the resolver.
    addrs: Vec<SocketAddr>,
    /// Cache insertion time.
    resolved_at: Instant,
}

/// Process-wide bounded DNS cache.
fn dns_cache() -> &'static Mutex<HashMap<String, DnsCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, DnsCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve an upstream address without blocking the async worker.
///
/// Literal socket addresses take the allocation-free fast path. Hostnames use
/// a bounded process-wide cache and run the operating-system resolver through
/// [`tokio::task::spawn_blocking`].
///
/// # Errors
///
/// Returns [`AddressResolutionError`] when resolution fails or returns no
/// usable addresses.
#[expect(
    clippy::too_many_lines,
    reason = "cache lookup, resolution, and insertion form one operation"
)]
pub async fn resolve_address(address: &str) -> Result<SocketAddr, AddressResolutionError> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some(addr) = lookup_cached(address) {
        return Ok(addr);
    }

    let owned = address.to_owned();
    let task_address = owned.clone();
    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs as _;
        task_address.to_socket_addrs().map(Iterator::collect::<Vec<_>>)
    })
    .await
    .map_err(|error| AddressResolutionError::Task {
        address: owned.clone(),
        message: error.to_string(),
    })?
    .map_err(|source| AddressResolutionError::Resolve {
        address: owned.clone(),
        source,
    })?;
    let preferred = select_preferred_address(&addrs, address)?;

    let mut cache = dns_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.len() >= MAX_DNS_ENTRIES && !cache.contains_key(address) {
        cache.retain(|_, entry| entry.resolved_at.elapsed().as_secs() < DNS_TTL_SECS);
        if cache.len() >= MAX_DNS_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.resolved_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        owned,
        DnsCacheEntry {
            addrs,
            resolved_at: Instant::now(),
        },
    );
    drop(cache);
    Ok(preferred)
}

/// Return a non-expired cached address, preferring IPv4.
fn lookup_cached(address: &str) -> Option<SocketAddr> {
    let cache = dns_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.get(address).and_then(|entry| {
        (entry.resolved_at.elapsed().as_secs() < DNS_TTL_SECS)
            .then(|| {
                entry
                    .addrs
                    .iter()
                    .find(|addr| addr.is_ipv4())
                    .or_else(|| entry.addrs.first())
                    .copied()
            })
            .flatten()
    })
}

/// Select IPv4 when available, otherwise the first result.
fn select_preferred_address(addrs: &[SocketAddr], address: &str) -> Result<SocketAddr, AddressResolutionError> {
    addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| AddressResolutionError::Empty(address.to_owned()))
}

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
        #[cfg(feature = "rustls")]
        {
            peer.options.ca = Some(Arc::from(ca_from_cached(ca)));
        }
        #[cfg(feature = "openssl")]
        {
            peer.options.ca = Some(Arc::new(ca_from_cached(ca).into_boxed_slice()));
        }
    }

    if let Some(client) = tls.client_cert() {
        if let Some(cert_key) = client_cert_from_cached(client) {
            peer.client_cert_key = Some(Arc::new(cert_key));
        }
    }
}

/// Convert cached CA DER bytes into values for the active TLS backend.
#[cfg(feature = "rustls")]
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

/// Convert cached CA DER bytes into values for the active TLS backend.
#[cfg(feature = "openssl")]
pub fn ca_from_cached(cached: &praxis_tls::CachedCaCerts) -> Vec<openssl::x509::X509> {
    cached
        .der_certs()
        .iter()
        .filter_map(|der| {
            openssl::x509::X509::from_der(der)
                .inspect_err(|e| tracing::warn!("failed to parse cached CA cert: {e}"))
                .ok()
        })
        .collect()
}

/// Convert cached client cert/key DER bytes into a [`CertKey`].
///
/// Returns `None` and logs a warning if the bytes cannot be parsed.
///
/// [`CertKey`]: pingora_core::utils::tls::CertKey
#[cfg(feature = "rustls")]
pub fn client_cert_from_cached(
    cached: &praxis_tls::CachedClientCert,
) -> Option<pingora_core::utils::tls::CertKey> {
    Some(pingora_core::utils::tls::CertKey::new(
        cached.cert_der().to_vec(),
        cached.key_der().to_vec(),
    ))
}

/// Convert cached client cert/key DER bytes into a [`CertKey`].
///
/// Returns `None` and logs a warning if the bytes cannot be parsed.
///
/// [`CertKey`]: pingora_core::utils::tls::CertKey
#[cfg(feature = "openssl")]
pub fn client_cert_from_cached(
    cached: &praxis_tls::CachedClientCert,
) -> Option<pingora_core::utils::tls::CertKey> {
    let certs = cached
        .cert_der()
        .iter()
        .map(|der| openssl::x509::X509::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .inspect_err(|e| tracing::warn!("failed to parse cached client cert: {e}"))
        .ok()?;
    let key = openssl::pkey::PKey::private_key_from_der(cached.key_der())
        .inspect_err(|e| tracing::warn!("failed to parse cached client key: {e}"))
        .ok()?;
    Some(pingora_core::utils::tls::CertKey::new(certs, key))
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

    #[tokio::test]
    async fn resolve_address_parses_literal_without_dns() {
        let address = resolve_address("127.0.0.1:8080").await.unwrap();
        assert_eq!(address, "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_address_rejects_missing_port() {
        resolve_address("127.0.0.1").await.unwrap_err();
    }

    #[test]
    fn preferred_address_favors_ipv4() {
        let ipv6 = "[::1]:8080".parse().unwrap();
        let ipv4 = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(select_preferred_address(&[ipv6, ipv4], "example:8080").unwrap(), ipv4);
    }

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
