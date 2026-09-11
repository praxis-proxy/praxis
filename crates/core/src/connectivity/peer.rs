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

    /// DNS resolved the hostname to a private or reserved address.
    #[error(
        "upstream address '{address}' resolved to private/reserved IP address {ip}; \
         set insecure_options.allow_private_upstreams to allow"
    )]
    PrivateAddress {
        /// Hostname being resolved.
        address: String,
        /// The private or reserved address DNS returned.
        ip: std::net::IpAddr,
    },
}

/// Cached DNS addresses, or the last resolution failure.
struct DnsCacheEntry {
    /// Outcome of the last resolution.
    outcome: Result<Arc<[SocketAddr]>, String>,
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

/// Process-wide bounded cache of complete DNS results.
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

/// Resolve one upstream address, preferring IPv4.
///
/// Use [`resolve_addresses`] when the caller can fail over.
///
/// # Errors
///
/// Returns [`AddressResolutionError`] when resolution fails or returns no
/// usable addresses.
pub async fn resolve_address(address: &str) -> Result<SocketAddr, AddressResolutionError> {
    // Answer a literal without building the list, so the common host:port
    // upstream costs no allocation on the request path.
    if let Some(addr) = literal_socket_addr(address) {
        return Ok(addr);
    }
    let addresses = resolve_addresses(address).await?;
    select_preferred_address(&addresses, address)
}

/// Resolve every address returned for an upstream.
///
/// Results retain resolver order and are cached. Callers must validate each
/// address before dialing it.
///
/// # Errors
///
/// Returns [`AddressResolutionError`] when resolution fails or returns no
/// usable addresses.
pub async fn resolve_addresses(address: &str) -> Result<Arc<[SocketAddr]>, AddressResolutionError> {
    if let Some(addr) = literal_socket_addr(address) {
        return Ok(Arc::from([addr]));
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
            Ok(addresses) => Ok(Arc::clone(addresses)),
            Err(e) => Err(e.to_string()),
        },
    );
    dns_inflight().remove(address);
    outcome
}

/// Resolve an upstream address, rejecting DNS answers that point at a
/// private or reserved range.
///
/// Wraps [`resolve_address`] with the runtime SSRF / DNS-rebinding control
/// documented for `insecure_options.allow_private_upstreams`: a hostname
/// that resolves into loopback, RFC 1918, link-local (including
/// `169.254.169.254`), CGNAT, the unspecified address, or IPv6
/// unique-local space is refused unless `allow_private` is `true`.
///
/// Literal socket addresses bypass the check. They are not forgeable,
/// the operator wrote the exact address Praxis connects to, and they are
/// already gated at config time by `insecure_options.allow_private_endpoints`.
/// Only DNS answers can change under the operator's feet, which is the
/// rebinding case this guards.
///
/// The check runs on every call, so a cached resolution
/// ([`resolve_address`] caches positive answers for 60 s) is re-validated
/// per request rather than trusted for the life of the entry.
///
/// # Errors
///
/// Returns [`AddressResolutionError::PrivateAddress`] when a resolved
/// address is private or reserved and `allow_private` is `false`, or any
/// [`AddressResolutionError`] [`resolve_address`] returns.
///
/// ```
/// use praxis_core::connectivity::peer::resolve_address_checked;
///
/// tokio::runtime::Runtime::new()
///     .expect("runtime")
///     .block_on(async {
///         // A literal private address is the operator's own choice, not a
///         // DNS answer, so it is not subject to the rebinding check.
///         let addr = resolve_address_checked("127.0.0.1:8080", false)
///             .await
///             .expect("literal addresses bypass the private-IP check");
///         assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
///     });
/// ```
pub async fn resolve_address_checked(address: &str, allow_private: bool) -> Result<SocketAddr, AddressResolutionError> {
    if let Some(literal) = literal_socket_addr(address) {
        return Ok(literal);
    }

    let resolved = resolve_address(address).await?;
    let ip = resolved.ip();
    if !allow_private && crate::connectivity::is_private_ip(&ip) {
        tracing::warn!(
            upstream = %address,
            resolved_ip = %ip,
            "upstream hostname resolved to private/reserved IP address; \
             set insecure_options.allow_private_upstreams to allow"
        );
        return Err(AddressResolutionError::PrivateAddress {
            address: address.to_owned(),
            ip,
        });
    }
    Ok(resolved)
}

/// Parse `address` as a literal `host:port` socket address, if it is one.
///
/// A hit means no DNS was consulted, so the address cannot have been
/// substituted by a resolver.
fn literal_socket_addr(address: &str) -> Option<SocketAddr> {
    address.parse::<SocketAddr>().ok()
}

/// Run the blocking resolver and keep every address it answers with.
async fn resolve_uncached(address: &str) -> Result<Arc<[SocketAddr]>, AddressResolutionError> {
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
    if addrs.is_empty() {
        return Err(AddressResolutionError::Empty(owned));
    }
    Ok(Arc::from(addrs))
}

/// Store a resolution outcome, evicting the oldest entry at capacity.
fn insert_cached(address: &str, outcome: Result<Arc<[SocketAddr]>, String>) {
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
fn lookup_cached(address: &str) -> Option<Result<Arc<[SocketAddr]>, AddressResolutionError>> {
    dns_cache().get(address).and_then(|entry| {
        entry.is_fresh().then(|| {
            entry
                .outcome
                .as_ref()
                .map_err(|message| AddressResolutionError::RecentFailure {
                    address: address.to_owned(),
                    message: message.clone(),
                })
                .map(Arc::clone)
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

/// Whether a URI host is an IP literal rather than a DNS name.
///
/// Accepts the bracketed form an IPv6 authority is written in, so a host
/// taken straight from a URL can be tested without unwrapping it first.
///
/// ```
/// use praxis_core::connectivity::peer;
///
/// assert!(peer::is_ip_literal("127.0.0.1"));
/// assert!(peer::is_ip_literal("[::1]"));
/// assert!(!peer::is_ip_literal("api.example.com"));
/// ```
#[must_use]
pub fn is_ip_literal(host: &str) -> bool {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<std::net::IpAddr>()
        .is_ok()
}

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
    if is_ip_literal(host) {
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

    #[tokio::test]
    async fn checked_resolution_rejects_private_dns_answer() {
        let err = resolve_address_checked("localhost:8125", false)
            .await
            .expect_err("a hostname resolving to loopback must be rejected by default");
        let AddressResolutionError::PrivateAddress { address, ip } = &err else {
            unreachable!("expected PrivateAddress, got: {err}")
        };
        assert_eq!(address, "localhost:8125", "the error must name the configured address");
        assert!(ip.is_loopback(), "the error must carry the rejected IP, got {ip}");
    }

    #[tokio::test]
    async fn checked_resolution_allows_private_dns_answer_with_override() {
        let addr = resolve_address_checked("localhost:8126", true)
            .await
            .expect("allow_private must permit a loopback resolution");
        assert!(addr.ip().is_loopback(), "localhost must resolve to loopback");
    }

    #[tokio::test]
    async fn checked_resolution_allows_literal_private_address() {
        // Literal addresses cannot be substituted by a resolver, and are
        // gated at config time instead; the runtime check must not break
        // the ordinary `127.0.0.1:port` upstream.
        let addr = resolve_address_checked("127.0.0.1:8080", false)
            .await
            .expect("a literal address must bypass the private-IP check");
        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn checked_resolution_rechecks_the_cached_answer() {
        // The positive DNS cache pins an answer for its TTL, so the check
        // must run per call rather than only on a cache miss.
        resolve_address("localhost:8127")
            .await
            .expect("localhost must resolve via the hosts file");
        let err = resolve_address_checked("localhost:8127", false)
            .await
            .expect_err("a cached private answer must still be rejected");
        assert!(
            matches!(err, AddressResolutionError::PrivateAddress { .. }),
            "expected PrivateAddress, got: {err}"
        );
    }

    #[tokio::test]
    async fn checked_resolution_propagates_resolver_failures() {
        let err = resolve_address_checked("does-not-exist.praxis-checked-test.invalid:80", false)
            .await
            .expect_err(".invalid hostnames must fail to resolve");
        assert!(
            !matches!(err, AddressResolutionError::PrivateAddress { .. }),
            "a resolver failure must not be reported as a private address: {err}"
        );
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
