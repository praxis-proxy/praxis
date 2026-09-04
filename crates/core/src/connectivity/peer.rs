// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared [`HttpPeer`] construction helpers for TLS, SNI, and connection options.
//!
//! Used by both the protocol layer's upstream peer builder and the
//! filter layer's sub-request executor to avoid duplicating TLS
//! and connection option mapping.
//!
//! [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer

use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use dashmap::DashMap;
use pingora_core::upstreams::peer::HttpPeer;

use super::ConnectionOptions;

/// TTL for cached DNS entries.
const DNS_TTL_SECS: u64 = 60;

/// TTL for cached resolution failures.
///
/// Short enough that a recovered resolver is picked up quickly, long
/// enough that a dead hostname cannot stampede the blocking resolver
/// with one getaddrinfo call per request.
const NEGATIVE_DNS_TTL_SECS: u64 = 5;

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

    /// A recent resolution of the same address failed (negative cache).
    #[error("upstream address resolution recently failed for '{address}': {message}")]
    RecentFailure {
        /// Address being resolved.
        address: String,
        /// Message from the cached failure.
        message: String,
    },
}

/// Cached DNS resolution result: the preferred address, or the failure
/// message when the last resolution failed (negative caching).
struct DnsCacheEntry {
    /// Outcome of the last resolution.
    outcome: Result<SocketAddr, String>,
    /// Cache insertion time.
    resolved_at: Instant,
}

impl DnsCacheEntry {
    /// Whether this entry is still valid at its outcome-specific TTL.
    fn is_fresh(&self) -> bool {
        let ttl = if self.outcome.is_ok() {
            DNS_TTL_SECS
        } else {
            NEGATIVE_DNS_TTL_SECS
        };
        self.resolved_at.elapsed().as_secs() < ttl
    }
}

/// Process-wide bounded DNS cache.
///
/// Sharded ([`DashMap`]) so the per-request read path never contends
/// on a single process-wide lock; the preferred address is stored
/// pre-selected so a hit is one lock-free lookup with no scan.
fn dns_cache() -> &'static DashMap<String, DnsCacheEntry> {
    static CACHE: OnceLock<DashMap<String, DnsCacheEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Per-hostname single-flight gates: concurrent misses on one hostname
/// coalesce into a single blocking `getaddrinfo` call instead of a
/// stampede at every TTL boundary.
fn dns_inflight() -> &'static DashMap<String, Arc<tokio::sync::Mutex<()>>> {
    static INFLIGHT: OnceLock<DashMap<String, Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
    INFLIGHT.get_or_init(DashMap::new)
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
pub async fn resolve_address(address: &str) -> Result<SocketAddr, AddressResolutionError> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some(cached) = lookup_cached(address) {
        return cached;
    }

    // Single-flight: losers wait on the winner's lock, then hit the cache
    // it populated. The Arc is cloned before the shard guard drops so the
    // await below never holds a DashMap lock.
    let gate = Arc::clone(
        &dns_inflight()
            .entry(address.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
    );
    let _flight = gate.lock().await;
    if let Some(cached) = lookup_cached(address) {
        return cached;
    }

    let outcome = resolve_uncached(address).await;
    insert_cached(
        address,
        match &outcome {
            Ok(preferred) => Ok(*preferred),
            Err(e) => Err(e.to_string()),
        },
    );
    dns_inflight().remove(address);
    outcome
}

/// Run the blocking resolver and select the preferred address.
async fn resolve_uncached(address: &str) -> Result<SocketAddr, AddressResolutionError> {
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
    .map_err(|source| AddressResolutionError::Resolve { address: owned, source })?;
    select_preferred_address(&addrs, address)
}

/// Store a resolution outcome, evicting the oldest entry at capacity.
fn insert_cached(address: &str, outcome: Result<SocketAddr, String>) {
    let cache = dns_cache();
    if cache.len() >= MAX_DNS_ENTRIES && !cache.contains_key(address) {
        cache.retain(|_, entry| entry.is_fresh());
        if cache.len() >= MAX_DNS_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|entry| entry.value().resolved_at)
                .map(|entry| entry.key().clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        address.to_owned(),
        DnsCacheEntry {
            outcome,
            resolved_at: Instant::now(),
        },
    );
}

/// Return a non-expired cached outcome (positive or negative).
fn lookup_cached(address: &str) -> Option<Result<SocketAddr, AddressResolutionError>> {
    dns_cache().get(address).and_then(|entry| {
        entry.is_fresh().then(|| {
            entry
                .outcome
                .as_ref()
                .map_err(|message| AddressResolutionError::RecentFailure {
                    address: address.to_owned(),
                    message: message.clone(),
                })
                .copied()
        })
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
/// from [`CachedClusterTls`] onto the peer's options. The Pingora-typed
/// conversions are memoized per cluster on first use, so the request
/// path pays only an [`Arc`] clone instead of re-parsing certificate
/// DER on every request.
///
/// [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer
/// [`CachedClusterTls`]: praxis_tls::CachedClusterTls
pub fn apply_cached_tls(peer: &mut HttpPeer, tls: &praxis_tls::CachedClusterTls, address: &str) {
    if !tls.verify() {
        tracing::debug!(upstream = %address, "upstream TLS verification disabled for this peer");
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
    }

    if let Some(ca) = tls.ca()
        && let Some(converted) =
            ca.converted_or_init(|| -> Arc<[pingora_core::utils::tls::WrappedX509]> { Arc::from(ca_from_cached(ca)) })
    {
        peer.options.ca = Some(Arc::clone(converted));
    }

    if let Some(client) = tls.client_cert()
        && let Some(converted) = client.converted_or_init(|| Arc::new(client_cert_from_cached(client)))
    {
        peer.client_cert_key = Some(Arc::clone(converted));
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
        tracing::debug!(
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
    fn apply_cached_tls_memoizes_ca_conversion() {
        let cached_ca = Arc::new(praxis_tls::CachedCaCerts::new(vec![vec![1, 2, 3]]));
        let converted_a: *const [pingora_core::utils::tls::WrappedX509] = cached_ca
            .converted_or_init(|| -> Arc<[pingora_core::utils::tls::WrappedX509]> {
                Arc::from(ca_from_cached(&cached_ca))
            })
            .map(Arc::as_ptr)
            .unwrap();
        let converted_b: *const [pingora_core::utils::tls::WrappedX509] = cached_ca
            .converted_or_init(|| -> Arc<[pingora_core::utils::tls::WrappedX509]> {
                Arc::from(ca_from_cached(&cached_ca))
            })
            .map(Arc::as_ptr)
            .unwrap();
        assert_eq!(
            converted_a, converted_b,
            "the CA conversion must be memoized, not rebuilt per request"
        );
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

    #[tokio::test]
    async fn resolve_address_resolves_hostname_and_caches_it() {
        let first = resolve_address("localhost:8123")
            .await
            .expect("localhost must resolve via the hosts file");
        assert_eq!(first.port(), 8123, "the requested port must be preserved");
        assert!(first.ip().is_loopback(), "localhost must resolve to loopback");

        let second = resolve_address("localhost:8123")
            .await
            .expect("a cached hostname must resolve");
        assert_eq!(first, second, "the cached lookup must return the same address");
    }

    #[tokio::test]
    async fn failed_resolution_is_negatively_cached() {
        let bogus = "does-not-exist.praxis-negative-cache-test.invalid:80";
        resolve_address(bogus)
            .await
            .expect_err(".invalid hostnames must fail to resolve");

        let second = resolve_address(bogus)
            .await
            .expect_err("a recent failure must be served from the negative cache");
        assert!(
            matches!(second, AddressResolutionError::RecentFailure { .. }),
            "the second failure should come from the negative cache, got: {second}"
        );
    }

    #[tokio::test]
    async fn concurrent_misses_coalesce_into_one_resolution() {
        // All tasks race the same uncached hostname; single-flight means
        // they either win the gate or wait and hit the cache — every task
        // must still get the same answer.
        let tasks: Vec<_> = std::iter::repeat_with(|| tokio::spawn(resolve_address("localhost:8124")))
            .take(8)
            .collect();
        let mut addrs = Vec::new();
        for task in tasks {
            addrs.push(task.await.unwrap().expect("localhost must resolve"));
        }
        assert!(
            addrs.windows(2).all(|w| w[0] == w[1]),
            "coalesced resolutions must agree on the address"
        );
    }

    #[test]
    fn preferred_address_errors_on_empty_resolution() {
        let err = select_preferred_address(&[], "empty.example:80").expect_err("no addresses must be an error");
        assert!(
            err.to_string().contains("empty.example"),
            "the error must name the address: {err}"
        );
    }

    #[test]
    fn preferred_address_falls_back_to_ipv6_only() {
        let ipv6 = "[::1]:9090".parse().unwrap();
        assert_eq!(
            select_preferred_address(&[ipv6], "v6.example:9090").unwrap(),
            ipv6,
            "an IPv6-only resolution must be usable"
        );
    }
}
