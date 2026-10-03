// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared [`HttpPeer`] construction utilities for TLS, SNI, and connection options.
//!
//! Used by both the protocol layer's upstream peer builder and the
//! filter layer's sub-request executor to avoid duplicating TLS
//! and connection option mapping.
//!
//! [`HttpPeer`]: pingora_core::upstreams::peer::HttpPeer

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use pingora_core::{protocols::ALPN, upstreams::peer::HttpPeer};

use super::{
    ConnectionOptions,
    trusted_private::{is_trusted_host, trusted_host_may_reach},
};
use crate::config::UpstreamHttpVersion;

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

/// Maximum concurrent client-selected DNS lookups. Waiting for a slot is
/// covered by the caller's URL deadline. A lookup keeps its slot after the
/// caller times out until the blocking resolver actually finishes.
const MAX_PER_CALL_DNS_LOOKUPS: usize = 64;

/// How long a positive answer may be served past its TTL while re-resolution
/// keeps failing for lack of a local resource.
const MAX_STALE_SECS: u64 = 300; // 5 min

/// Re-resolution backoff after a local resource failure, so a stale answer is
/// served from cache instead of retried by every request.
const LOCAL_FAILURE_RETRY_SECS: u64 = 1;

/// `EMFILE`: per-process descriptor table full.
const EMFILE: i32 = 24;

/// `ENFILE`: system-wide descriptor table full.
const ENFILE: i32 = 23;

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
        ip: IpAddr,
    },

    /// A trusted host resolved outside the ranges a trusted host may reach.
    #[error(
        "upstream address '{address}' is in trusted_private_endpoints but resolved to {ip}, \
         outside the ranges a trusted host may reach"
    )]
    UntrustedRange {
        /// Hostname being resolved.
        address: String,
        /// The address DNS returned.
        ip: IpAddr,
    },
}

impl AddressResolutionError {
    /// Whether resolution failed because this process ran out of descriptors
    /// or memory, rather than because DNS answered with an error.
    ///
    /// Such a failure says nothing about the hostname, so it must not be
    /// cached as one.
    ///
    /// ```
    /// use praxis_core::connectivity::peer::AddressResolutionError;
    ///
    /// let exhausted = AddressResolutionError::Resolve {
    ///     address: "upstream.internal:80".to_owned(),
    ///     source: std::io::Error::from_raw_os_error(24),
    /// };
    /// assert!(exhausted.is_local_resource_exhaustion());
    ///
    /// let nxdomain = AddressResolutionError::Empty("upstream.internal:80".to_owned());
    /// assert!(!nxdomain.is_local_resource_exhaustion());
    /// ```
    pub fn is_local_resource_exhaustion(&self) -> bool {
        match self {
            Self::Resolve { source, .. } => {
                matches!(source.raw_os_error(), Some(EMFILE | ENFILE))
                    || source.kind() == std::io::ErrorKind::OutOfMemory
            },
            Self::Task { .. }
            | Self::Empty(_)
            | Self::RecentFailure { .. }
            | Self::PrivateAddress { .. }
            | Self::UntrustedRange { .. } => false,
        }
    }
}

/// Cached DNS resolution: the complete raw address set (portless, resolver
/// order), or the failure message when the last resolution failed.
struct DnsCacheEntry {
    /// Outcome of the last resolution.
    outcome: Result<Arc<[IpAddr]>, String>,
    /// When a resolver last produced `outcome`.
    resolved_at: Instant,
    /// Until when `outcome` is served without re-resolving.
    fresh_until: Instant,
}

impl DnsCacheEntry {
    /// Entry for a resolver outcome, fresh for its outcome-specific TTL.
    fn new(outcome: Result<Arc<[IpAddr]>, String>) -> Self {
        let ttl = if outcome.is_ok() {
            DNS_TTL_SECS
        } else {
            NEGATIVE_DNS_TTL_SECS
        };
        let resolved_at = Instant::now();
        Self {
            outcome,
            resolved_at,
            fresh_until: later(resolved_at, ttl),
        }
    }

    /// Whether this entry may be served without re-resolving.
    fn is_fresh(&self) -> bool {
        Instant::now() < self.fresh_until
    }
}

/// Process-wide bounded DNS cache, keyed by canonical lowercase host.
fn dns_cache() -> &'static DashMap<String, DnsCacheEntry> {
    static CACHE: OnceLock<DashMap<String, DnsCacheEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Fan-out payload for the inflight resolution result. `None` = still pending;
/// `Some` = terminal. The error is `Arc`-wrapped because
/// [`AddressResolutionError`] is not `Clone` (`Resolve { source: io::Error }`).
type ResolvePayload = Option<Result<Arc<[IpAddr]>, Arc<AddressResolutionError>>>;

/// Per-host inflight resolutions: a `watch::Receiver` fans the owner task's
/// result out to every coalescing caller. The map value is only a result
/// channel — the resolution itself is driven by a runtime-spawned owner task,
/// so it completes even if every awaiter drops.
fn dns_inflight() -> &'static DashMap<String, tokio::sync::watch::Receiver<ResolvePayload>> {
    static INFLIGHT: OnceLock<DashMap<String, tokio::sync::watch::Receiver<ResolvePayload>>> = OnceLock::new();
    INFLIGHT.get_or_init(DashMap::new)
}

/// Canonical cache key: DNS names are case-insensitive, so fold to lowercase.
fn cache_key(host: &str) -> String {
    host.to_ascii_lowercase()
}

/// The blocking name lookup beneath the cache + single-flight. Production uses
/// `getaddrinfo`; tests inject a controllable double.
///
/// A *resolver* failure (NXDOMAIN, etc.) returns `Err`. An *infrastructure*
/// failure (the blocking thread panicked / `JoinError`) MUST panic, so the
/// owner task drops its result channel without publishing — the failure is
/// never cached and the next caller re-resolves.
pub(crate) trait BlockingLookup: Clone + Send + Sync + 'static {
    /// Resolve `host` to its complete address set, or an [`AddressResolutionError`].
    fn lookup(&self, host: String) -> impl Future<Output = Result<Vec<IpAddr>, AddressResolutionError>> + Send;
}

/// The real `getaddrinfo`-backed lookup.
#[derive(Clone)]
struct SystemLookup;

impl BlockingLookup for SystemLookup {
    async fn lookup(&self, host: String) -> Result<Vec<IpAddr>, AddressResolutionError> {
        let task_host = host.clone();
        let joined = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs as _;
            (task_host.as_str(), 0_u16)
                .to_socket_addrs()
                .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
        })
        .await;
        let resolved = match joined {
            Ok(resolved) => resolved,
            // Blocking thread panicked: propagate so the owner drops the
            // channel without poisoning the entry.
            #[expect(
                clippy::panic,
                reason = "infrastructure panic (not resolver failure) must propagate to prevent poisoning"
            )]
            Err(join_err) => panic!("DNS resolver task panicked for '{host}': {join_err}"),
        };
        resolved.map_err(|source| AddressResolutionError::Resolve { address: host, source })
    }
}

/// Rebuild an owned [`AddressResolutionError`] from the `Arc` fan-out payload,
/// preserving the `Resolve` `io::Error`'s OS code when present.
fn owned_from_arc(err: &AddressResolutionError) -> AddressResolutionError {
    match err {
        AddressResolutionError::Task { address, message } => AddressResolutionError::Task {
            address: address.clone(),
            message: message.clone(),
        },
        AddressResolutionError::Resolve { address, source } => AddressResolutionError::Resolve {
            address: address.clone(),
            source: source.raw_os_error().map_or_else(
                || std::io::Error::new(source.kind(), source.to_string()),
                std::io::Error::from_raw_os_error,
            ),
        },
        AddressResolutionError::Empty(address) => AddressResolutionError::Empty(address.clone()),
        AddressResolutionError::RecentFailure { address, message } => AddressResolutionError::RecentFailure {
            address: address.clone(),
            message: message.clone(),
        },
        AddressResolutionError::PrivateAddress { address, ip } => AddressResolutionError::PrivateAddress {
            address: address.clone(),
            ip: *ip,
        },
        AddressResolutionError::UntrustedRange { address, ip } => AddressResolutionError::UntrustedRange {
            address: address.clone(),
            ip: *ip,
        },
    }
}

/// Resolve an upstream `host:port` to a single preferred address.
///
/// Literal socket addresses take the fast path. Hostnames use a
/// bounded process-wide cache and the detached-owner single-flight, resolving
/// the host to its complete set and applying the requested port.
///
/// # Errors
///
/// Returns [`AddressResolutionError`] when resolution fails or returns no
/// usable addresses. Error `address` fields name the caller-visible
/// `"host:port"`, not the portless cache key.
pub async fn resolve_address(address: &str) -> Result<SocketAddr, AddressResolutionError> {
    if let Some(addr) = literal_socket_addr(address) {
        return Ok(addr);
    }
    let addresses = resolve_addresses(address).await?;
    select_preferred_address(&addresses, address)
}

/// Resolve every address returned for an upstream `host:port`.
///
/// Results retain resolver order (unlike [`resolve_address`], which prefers
/// IPv4) and are cached. Callers must validate each address before dialing it.
/// Literal socket addresses take the fast path.
///
/// # Errors
///
/// Returns [`AddressResolutionError`] when resolution fails or returns no
/// usable addresses. Error `address` fields name the caller-visible
/// `"host:port"`, not the portless cache key.
pub async fn resolve_addresses(address: &str) -> Result<Arc<[SocketAddr]>, AddressResolutionError> {
    if let Some(addr) = literal_socket_addr(address) {
        return Ok(Arc::from([addr]));
    }
    let (host, port) = split_host_port(address).ok_or_else(|| AddressResolutionError::Resolve {
        address: address.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing port"),
    })?;
    let ips = resolve_host_cached(host).await.map_err(|err| readdress(err, address))?;
    let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
    Ok(Arc::from(addrs))
}

/// Split `host:port`, stripping IPv6 brackets. `None` when no port is present.
fn split_host_port(address: &str) -> Option<(&str, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|stripped| stripped.strip_suffix(']'))
        .unwrap_or(host);
    let port = port.parse::<u16>().ok()?;
    Some((host, port))
}

/// Re-address a host-keyed resolution error to the caller-visible `host:port`,
/// moving the inner `io::Error` intact so `kind()`/`raw_os_error()` survive.
fn readdress(err: AddressResolutionError, caller: &str) -> AddressResolutionError {
    match err {
        AddressResolutionError::Resolve { source, .. } => AddressResolutionError::Resolve {
            address: caller.to_owned(),
            source,
        },
        AddressResolutionError::Task { message, .. } => AddressResolutionError::Task {
            address: caller.to_owned(),
            message,
        },
        AddressResolutionError::Empty(_) => AddressResolutionError::Empty(caller.to_owned()),
        AddressResolutionError::RecentFailure { message, .. } => AddressResolutionError::RecentFailure {
            address: caller.to_owned(),
            message,
        },
        other @ (AddressResolutionError::PrivateAddress { .. } | AddressResolutionError::UntrustedRange { .. }) => {
            other
        },
    }
}

/// Resolve a bare host to its complete address set (cached, single-flight),
/// portless, raw resolver order preserved. Never returns `Ok(vec![])`.
///
/// # Errors
///
/// Returns [`AddressResolutionError`] on resolver failure or a zero-address
/// answer (mapped to [`AddressResolutionError::Empty`] and negatively cached).
pub(crate) async fn resolve_host_cached(host: &str) -> Result<Vec<IpAddr>, AddressResolutionError> {
    resolve_host_cached_with(host, &SystemLookup).await
}

/// Resolve a client-selected host once without reading, joining, or changing
/// the process-wide positive/negative cache or its in-flight resolutions.
pub(crate) async fn resolve_host_per_call(host: &str) -> Result<Vec<IpAddr>, AddressResolutionError> {
    resolve_host_per_call_with(host, &SystemLookup, per_call_dns_admission()).await
}

/// Shared admission bound for per-call DNS without sharing cached answers or
/// per-host in-flight results.
fn per_call_dns_admission() -> &'static Arc<tokio::sync::Semaphore> {
    static ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_PER_CALL_DNS_LOOKUPS)))
}

/// Run one lookup under admission. The detached owner retains the permit if
/// the caller's deadline expires while `getaddrinfo` is still blocking.
async fn resolve_host_per_call_with<L: BlockingLookup>(
    host: &str,
    lookup: &L,
    admission: &Arc<tokio::sync::Semaphore>,
) -> Result<Vec<IpAddr>, AddressResolutionError> {
    let permit = Arc::clone(admission)
        .acquire_owned()
        .await
        .map_err(|err| AddressResolutionError::Task {
            address: host.to_owned(),
            message: err.to_string(),
        })?;
    let task_host = host.to_owned();
    let task_lookup = lookup.clone();
    let ips = tokio::spawn(async move {
        let _permit = permit;
        task_lookup.lookup(task_host).await
    })
    .await
    .map_err(|err| AddressResolutionError::Task {
        address: host.to_owned(),
        message: err.to_string(),
    })??;
    if ips.is_empty() {
        Err(AddressResolutionError::Empty(host.to_owned()))
    } else {
        Ok(ips)
    }
}

/// Cache-checked, single-flight resolution over an injectable [`BlockingLookup`].
/// The real machinery behind [`resolve_host_cached`]; tests drive it with a
/// controllable lookup double.
#[expect(
    clippy::too_many_lines,
    reason = "detached-owner single-flight spans setup, await loop, and error fan-out"
)]
async fn resolve_host_cached_with<L: BlockingLookup>(
    host: &str,
    lookup: &L,
) -> Result<Vec<IpAddr>, AddressResolutionError> {
    if let Some(cached) = lookup_cached(host) {
        return cached.map(|arc| arc.to_vec());
    }
    let key = cache_key(host);

    // Occupy (or join) the inflight entry. The first caller spawns the owner;
    // the closure does nothing but create the channel and spawn (both
    // non-blocking) while the DashMap shard lock is held.
    let mut rx = dns_inflight()
        .entry(key.clone())
        .or_insert_with(|| {
            let (tx, rx) = tokio::sync::watch::channel(None);
            let owner_host = host.to_owned();
            let owner_key = key.clone();
            let owner_lookup = lookup.clone();
            tokio::spawn(owner_resolve(owner_host, owner_key, tx, owner_lookup));
            rx
        })
        .clone();

    // Await the owner's terminal publish, or a channel close (owner dropped
    // while still pending → panic path).
    let payload = loop {
        let current = rx.borrow_and_update().clone();
        if let Some(terminal) = current {
            break Some(terminal);
        }
        if rx.changed().await.is_err() {
            break None;
        }
    };

    match payload {
        Some(Ok(ips)) => Ok(ips.to_vec()),
        Some(Err(arc)) => Err(owned_from_arc(&arc)),
        None => Err(AddressResolutionError::Resolve {
            address: host.to_owned(),
            source: std::io::Error::other("DNS resolution task ended without a result"),
        }),
    }
}

/// The detached owner: re-check the cache, run the blocking lookup, populate
/// the cache, publish exactly one terminal payload. A cleanup guard removes the
/// inflight entry on EVERY exit (success, error, panic).
#[expect(
    clippy::too_many_lines,
    reason = "cleanup guard, TOCTOU re-check, blocking lookup, cache write, and channel publish"
)]
async fn owner_resolve<L: BlockingLookup>(
    host: String,
    key: String,
    tx: tokio::sync::watch::Sender<ResolvePayload>,
    lookup: L,
) {
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            dns_inflight().remove(&self.0);
        }
    }
    let _guard = Cleanup(key);

    // TOCTOU re-check: a previous owner may have populated the cache between our
    // caller's miss and our spawn. Mirrors the old post-lock re-check.
    if let Some(cached) = lookup_cached(&host) {
        let payload = match cached {
            Ok(arc) => Ok(arc),
            Err(err) => Err(Arc::new(err)),
        };
        drop(tx.send(Some(payload)));
        return;
    }

    // A zero-address answer is negative, never a positive empty set.
    let outcome = lookup.lookup(host.clone()).await.and_then(|ips| {
        if ips.is_empty() {
            Err(AddressResolutionError::Empty(host.clone()))
        } else {
            Ok(ips)
        }
    });

    // Running out of descriptors or memory is this process's problem, not the
    // hostname's: never cache it as a negative answer, and keep serving the last
    // good answer so a local shortage cannot black out a healthy upstream.
    let outcome = match outcome {
        Err(err) if err.is_local_resource_exhaustion() => {
            let payload = if let Some(stale) = serve_stale(&host) {
                tracing::warn!(%host, error = %err, "local resource exhaustion during DNS; serving last good answer");
                Ok(stale)
            } else {
                tracing::debug!(%host, error = %err, "local resource exhaustion during DNS; not cached");
                Err(Arc::new(err))
            };
            drop(tx.send(Some(payload)));
            return;
        },
        other => other,
    };

    // Cache-write happens-before entry-removal: the guard fires at return, after
    // this write, so a caller that finds the slot empty finds the cache filled.
    insert_cached(
        &host,
        match &outcome {
            Ok(ips) => Ok(Arc::from(ips.as_slice())),
            Err(err) => Err(err.to_string()),
        },
    );

    let payload = match outcome {
        Ok(ips) => Ok(Arc::<[IpAddr]>::from(ips.as_slice())),
        Err(err) => Err(Arc::new(err)),
    };
    drop(tx.send(Some(payload)));
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
    resolve_checked(address, allow_private, &[]).await
}

/// [`resolve_address_checked`] honouring the upstream's `trusted_private_endpoints`.
///
/// # Errors
///
/// As [`resolve_address_checked`], plus [`AddressResolutionError::UntrustedRange`].
pub async fn resolve_upstream_checked(
    upstream: &crate::connectivity::Upstream,
    allow_private: bool,
) -> Result<SocketAddr, AddressResolutionError> {
    resolve_checked(
        &upstream.address,
        allow_private,
        &upstream.connection.trusted_private_endpoints,
    )
    .await
}

/// Resolve `address`, refusing a private answer unless allowed or trusted.
async fn resolve_checked(
    address: &str,
    allow_private: bool,
    trusted: &[Box<str>],
) -> Result<SocketAddr, AddressResolutionError> {
    if let Some(literal) = literal_socket_addr(address) {
        return Ok(literal);
    }

    let resolved = resolve_address(address).await?;
    let ip = resolved.ip();
    if allow_private || !crate::connectivity::is_private_upstream_ip(&ip) {
        return Ok(resolved);
    }
    let listed =
        !trusted.is_empty() && split_host_port(address).is_some_and(|(host, _)| is_trusted_host(trusted, host));
    if listed && trusted_host_may_reach(&ip) {
        return Ok(resolved);
    }
    Err(refuse_private(address, ip, listed))
}

/// Log and build the refusal for a private answer.
fn refuse_private(address: &str, ip: IpAddr, listed: bool) -> AddressResolutionError {
    let address = address.to_owned();
    if listed {
        tracing::warn!(
            upstream = %address,
            resolved_ip = %ip,
            "trusted upstream hostname resolved outside the ranges a trusted host may reach"
        );
        AddressResolutionError::UntrustedRange { address, ip }
    } else {
        tracing::warn!(
            upstream = %address,
            resolved_ip = %ip,
            "upstream hostname resolved to private/reserved IP address; \
             set insecure_options.allow_private_upstreams to allow"
        );
        AddressResolutionError::PrivateAddress { address, ip }
    }
}

/// Parse `address` as a literal `host:port` socket address, if it is one.
///
/// A hit means no DNS was consulted, so the address cannot have been
/// substituted by a resolver.
fn literal_socket_addr(address: &str) -> Option<SocketAddr> {
    address.parse::<SocketAddr>().ok()
}

/// Seed the DNS cache so a test hostname resolves to `ips` without a resolver.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn seed_dns(host: &str, ips: &[IpAddr]) {
    insert_cached(host, Ok(Arc::from(ips)));
}

/// Store a resolution outcome, evicting the oldest entry at capacity.
fn insert_cached(host: &str, outcome: Result<Arc<[IpAddr]>, String>) {
    let cache = dns_cache();
    let key = cache_key(host);
    if cache.len() >= MAX_DNS_ENTRIES && !cache.contains_key(&key) {
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
    cache.insert(key, DnsCacheEntry::new(outcome));
}

/// The last positive answer for `host`, if one was resolved within
/// [`MAX_STALE_SECS`], re-armed for a short backoff so the next requests take
/// it from cache instead of retrying the failing resolver.
fn serve_stale(host: &str) -> Option<Arc<[IpAddr]>> {
    let mut entry = dns_cache().get_mut(&cache_key(host))?;
    let ips = entry.outcome.as_ref().ok().map(Arc::clone)?;
    if entry.resolved_at.elapsed().as_secs() >= MAX_STALE_SECS {
        return None;
    }
    entry.fresh_until = later(Instant::now(), LOCAL_FAILURE_RETRY_SECS);
    drop(entry);
    Some(ips)
}

/// `secs` after `from`, saturating at `from` on the (unreachable) overflow.
fn later(from: Instant, secs: u64) -> Instant {
    from.checked_add(Duration::from_secs(secs)).unwrap_or(from)
}

/// Return a non-expired cached outcome (positive or negative) for `host`.
fn lookup_cached(host: &str) -> Option<Result<Arc<[IpAddr]>, AddressResolutionError>> {
    dns_cache().get(&cache_key(host)).and_then(|entry| {
        entry.is_fresh().then(|| {
            entry
                .outcome
                .as_ref()
                .map(Arc::clone)
                .map_err(|message| AddressResolutionError::RecentFailure {
                    address: host.to_owned(),
                    message: message.clone(),
                })
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

// -----------------------------------------------------------------------------
// Connection Options
// -----------------------------------------------------------------------------

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
    peer.options.alpn = alpn_for(opts.http_version);
}

/// Map the configured upstream HTTP version onto Pingora's ALPN setting.
///
/// Pingora's connector reads only the ALPN bounds: `get_max_http_version()
/// == 1` forces the HTTP/1.1 pool, and over plaintext (where there is no
/// negotiation) `get_min_http_version() == 2` is the signal to speak h2c
/// with prior knowledge.
fn alpn_for(version: UpstreamHttpVersion) -> ALPN {
    match version {
        UpstreamHttpVersion::H1 => ALPN::H1,
        UpstreamHttpVersion::H2 => ALPN::H2,
        UpstreamHttpVersion::Auto => ALPN::H2H1,
    }
}

// -----------------------------------------------------------------------------
// TLS
// -----------------------------------------------------------------------------

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
                .inspect_err(|err| tracing::warn!("failed to parse cached CA cert: {err}"))
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

// -----------------------------------------------------------------------------
// SNI
// -----------------------------------------------------------------------------

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
        .and_then(|stripped| stripped.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
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
    let raw = address.rsplit_once(':').map_or(address, |(host_part, _)| host_part);
    // Certificates never carry the root dot; a dotted IP spelling keeps it and fails closed.
    let stripped = super::strip_root_dot(raw);
    let host = if stripped != raw && is_ip_literal(stripped) {
        raw
    } else {
        stripped
    };
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    reason = "tests"
)]
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

    /// An upstream built through the load balancer's `Cluster` to options path.
    fn upstream_in_cluster(address: &str, trusted: &[&str]) -> crate::connectivity::Upstream {
        let mut cluster = crate::config::Cluster::with_defaults("models", vec![address.into()]);
        cluster.trusted_private_endpoints = trusted.iter().map(|host| (*host).to_owned()).collect();
        crate::connectivity::Upstream {
            address: Arc::from(address),
            authority: None,
            connection: Arc::new(ConnectionOptions::from(&cluster)),
            tls: None,
        }
    }

    /// Expected resolution outcome.
    enum Want {
        Admit,
        Unlisted,
        OutOfRange,
    }

    /// One row of the trusted-private resolution table.
    struct TrustCase {
        name: &'static str,
        host: &'static str,
        answer: &'static str,
        trusted: &'static [&'static str],
        allow_private: bool,
        want: Want,
    }

    const SVC: &str = "model.tenant-1306.svc";

    const TRUST_CASES: &[TrustCase] = &[
        TrustCase {
            name: "listed service to its ClusterIP",
            host: SVC,
            answer: "172.30.202.42",
            trusted: &[SVC],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "match is case-insensitive",
            host: SVC,
            answer: "172.30.202.42",
            trusted: &["Model.Tenant-1306.SVC"],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "trailing dot on the entry",
            host: SVC,
            answer: "172.30.202.42",
            trusted: &["model.tenant-1306.svc."],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "listed host to 10/8",
            host: "a.p1306.invalid",
            answer: "10.96.0.10",
            trusted: &["a.p1306.invalid"],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "listed host to 192.168/16",
            host: "b.p1306.invalid",
            answer: "192.168.4.2",
            trusted: &["b.p1306.invalid"],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "listed host to unique local",
            host: "c.p1306.invalid",
            answer: "fd12:3456::1",
            trusted: &["c.p1306.invalid"],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "public answer needs no listing",
            host: "d.p1306.invalid",
            answer: "8.8.8.8",
            trusted: &[],
            allow_private: false,
            want: Want::Admit,
        },
        TrustCase {
            name: "unlisted host, same cluster",
            host: "other.tenant-1306.svc",
            answer: "10.96.0.20",
            trusted: &[SVC],
            allow_private: false,
            want: Want::Unlisted,
        },
        TrustCase {
            name: "same host, other cluster",
            host: SVC,
            answer: "172.30.202.42",
            trusted: &[],
            allow_private: false,
            want: Want::Unlisted,
        },
        TrustCase {
            name: "a suffix is not a match",
            host: "x.model.tenant-1306.svc",
            answer: "10.96.0.30",
            trusted: &[SVC],
            allow_private: false,
            want: Want::Unlisted,
        },
        TrustCase {
            name: "listed host to loopback",
            host: "e.p1306.invalid",
            answer: "127.0.0.1",
            trusted: &["e.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to IPv6 loopback",
            host: "f.p1306.invalid",
            answer: "::1",
            trusted: &["f.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to metadata",
            host: "g.p1306.invalid",
            answer: "169.254.169.254",
            trusted: &["g.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to link-local",
            host: "h.p1306.invalid",
            answer: "169.254.3.4",
            trusted: &["h.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to metadata in ULA",
            host: "i.p1306.invalid",
            answer: "fd00:ec2::254",
            trusted: &["i.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to shared space",
            host: "j.p1306.invalid",
            answer: "100.64.0.5",
            trusted: &["j.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "listed host to unspecified",
            host: "k.p1306.invalid",
            answer: "0.0.0.0",
            trusted: &["k.p1306.invalid"],
            allow_private: false,
            want: Want::OutOfRange,
        },
        TrustCase {
            name: "global flag still admits unlisted",
            host: "l.p1306.invalid",
            answer: "10.96.0.40",
            trusted: &[],
            allow_private: true,
            want: Want::Admit,
        },
        TrustCase {
            name: "global flag still admits loopback",
            host: "m.p1306.invalid",
            answer: "127.0.0.1",
            trusted: &[],
            allow_private: true,
            want: Want::Admit,
        },
    ];

    #[tokio::test]
    async fn trusted_private_endpoints_relax_only_listed_hosts_to_rfc1918_and_ula() {
        for case in TRUST_CASES {
            let answer: IpAddr = case.answer.parse().unwrap();
            insert_cached(case.host, Ok(Arc::from([answer].as_slice())));
            let upstream = upstream_in_cluster(&format!("{}:8000", case.host), case.trusted);
            let got = resolve_upstream_checked(&upstream, case.allow_private).await;
            match case.want {
                Want::Admit => assert_eq!(
                    got.as_ref().map(SocketAddr::ip).ok(),
                    Some(answer),
                    "{}: {got:?}",
                    case.name
                ),
                Want::Unlisted => assert!(
                    matches!(got, Err(AddressResolutionError::PrivateAddress { .. })),
                    "{}: {got:?}",
                    case.name
                ),
                Want::OutOfRange => assert!(
                    matches!(got, Err(AddressResolutionError::UntrustedRange { .. })),
                    "{}: {got:?}",
                    case.name
                ),
            }
        }
    }

    #[tokio::test]
    async fn nat64_wrapped_private_answer_is_refused() {
        let host = "nat64.p1306.invalid";
        insert_cached(
            host,
            Ok(Arc::from(["64:ff9b::a00:1".parse::<IpAddr>().unwrap()].as_slice())),
        );
        let got = resolve_address_checked(&format!("{host}:8000"), false).await;
        assert!(
            matches!(got, Err(AddressResolutionError::PrivateAddress { .. })),
            "a DNS64-synthesized private answer must be refused: {got:?}"
        );
    }

    #[tokio::test]
    async fn the_address_level_check_trusts_no_host() {
        let host = "n.p1306.invalid";
        insert_cached(
            host,
            Ok(Arc::from(["10.96.0.50".parse::<IpAddr>().unwrap()].as_slice())),
        );
        let err = resolve_address_checked(&format!("{host}:8000"), false)
            .await
            .expect_err("no cluster, so a private answer is refused");
        assert!(
            err.to_string()
                .contains("set insecure_options.allow_private_upstreams to allow"),
            "{err}"
        );
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
        let addr = resolve_address_checked("127.0.0.1:8080", false)
            .await
            .expect("a literal address must bypass the private-IP check");
        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn checked_resolution_rechecks_the_cached_answer() {
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
    fn derive_sni_strips_the_root_dot() {
        assert_eq!(
            derive_sni("backend.ns.svc.cluster.local.:8443"),
            "backend.ns.svc.cluster.local"
        );
        assert_eq!(
            derive_sni("10.0.0.5.:443"),
            "10.0.0.5.",
            "a dotted IP must not become an empty SNI"
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
    fn apply_connection_options_defaults_to_http1() {
        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        apply_connection_options(&mut peer, &ConnectionOptions::default());
        assert_eq!(
            peer.options.alpn.get_max_http_version(),
            1,
            "the default upstream leg must stay HTTP/1.1"
        );
    }

    #[test]
    fn apply_connection_options_sets_h2_alpn() {
        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        let opts = ConnectionOptions {
            http_version: UpstreamHttpVersion::H2,
            ..ConnectionOptions::default()
        };
        apply_connection_options(&mut peer, &opts);
        assert_eq!(
            peer.options.alpn.get_min_http_version(),
            2,
            "h2 must be the minimum so Pingora speaks h2c over plaintext"
        );
        assert_eq!(
            peer.options.alpn.get_max_http_version(),
            2,
            "h2 must be the maximum so the h1 pool is not used"
        );
    }

    #[test]
    fn apply_connection_options_sets_h2h1_alpn_for_auto() {
        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        let opts = ConnectionOptions {
            http_version: UpstreamHttpVersion::Auto,
            ..ConnectionOptions::default()
        };
        apply_connection_options(&mut peer, &opts);
        assert_eq!(
            peer.options.alpn.get_min_http_version(),
            1,
            "auto must allow falling back to HTTP/1.1"
        );
        assert_eq!(
            peer.options.alpn.get_max_http_version(),
            2,
            "auto must allow negotiating HTTP/2"
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
            ..ConnectionOptions::default()
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

    #[tokio::test]
    async fn resolve_host_cached_returns_complete_portless_set() {
        let ips = resolve_host_cached("localhost")
            .await
            .expect("localhost must resolve via the hosts file");
        assert!(!ips.is_empty(), "must never return an empty set");
        assert!(
            ips.iter().all(|ip: &IpAddr| ip.is_loopback()),
            "localhost must be loopback: {ips:?}"
        );
    }

    #[tokio::test]
    async fn resolve_host_cached_is_case_folded() {
        resolve_host_cached("localhost").await.expect("resolve lowercase");
        assert!(
            lookup_cached("LOCALHOST").is_some(),
            "case-folded host must share the cache entry"
        );
    }

    #[tokio::test]
    async fn resolve_address_still_prefers_ipv4_and_preserves_port() {
        let addr = resolve_address("localhost:8123").await.expect("localhost must resolve");
        assert_eq!(addr.port(), 8123, "the requested port must be preserved");
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn resolve_address_readdresses_errors_to_host_port() {
        let bogus = "does-not-exist.praxis-readdress-test.invalid:80";
        let err = resolve_address(bogus).await.expect_err(".invalid must fail");
        assert!(
            err.to_string()
                .contains("does-not-exist.praxis-readdress-test.invalid:80"),
            "resolve_address errors must name the caller-visible host:port, not the portless key: {err}"
        );
    }

    #[test]
    fn is_ip_literal_detects_v4_v6_and_rejects_dns() {
        assert!(is_ip_literal("127.0.0.1"), "bare IPv4 is a literal");
        assert!(is_ip_literal("[::1]"), "bracketed IPv6 is a literal");
        assert!(is_ip_literal("::1"), "bare IPv6 is a literal");
        assert!(!is_ip_literal("api.example.com"), "a DNS name is not a literal");
        assert!(!is_ip_literal("localhost"), "localhost is a DNS name, not a literal");
    }

    #[tokio::test]
    async fn resolve_addresses_returns_literal_without_dns() {
        let addrs = resolve_addresses("127.0.0.1:8080").await.expect("a literal must parse");
        assert_eq!(addrs.len(), 1, "a literal resolves to exactly itself");
        assert_eq!(addrs[0], "127.0.0.1:8080".parse().unwrap());
    }

    #[tokio::test]
    async fn resolve_addresses_resolves_hostname_and_applies_port() {
        let addrs = resolve_addresses("localhost:8123")
            .await
            .expect("localhost must resolve via the hosts file");
        assert!(!addrs.is_empty(), "must never return an empty set");
        assert!(
            addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 8123),
            "every address must be loopback on the requested port: {addrs:?}"
        );
    }

    #[tokio::test]
    async fn resolve_addresses_rejects_missing_port() {
        resolve_addresses("localhost")
            .await
            .expect_err("a bare host with no port must be rejected");
    }

    #[test]
    fn local_resource_exhaustion_is_classified() {
        for code in [EMFILE, ENFILE] {
            assert!(
                os_resolve_error("h", code).is_local_resource_exhaustion(),
                "errno {code} is a local descriptor shortage"
            );
        }
        let oom = AddressResolutionError::Resolve {
            address: "h".to_owned(),
            source: std::io::Error::from(std::io::ErrorKind::OutOfMemory),
        };
        assert!(oom.is_local_resource_exhaustion(), "out of memory is a local shortage");
    }

    #[test]
    fn dns_and_policy_failures_are_not_local_resource_exhaustion() {
        let not_local = [
            os_resolve_error("h", 2),
            AddressResolutionError::Resolve {
                address: "h".to_owned(),
                source: std::io::Error::other("failed to lookup address information: Name does not resolve"),
            },
            AddressResolutionError::Empty("h".to_owned()),
            AddressResolutionError::RecentFailure {
                address: "h".to_owned(),
                message: "Too many open files (os error 24)".to_owned(),
            },
            AddressResolutionError::Task {
                address: "h".to_owned(),
                message: "cancelled".to_owned(),
            },
            AddressResolutionError::PrivateAddress {
                address: "h".to_owned(),
                ip: "10.0.0.1".parse().unwrap(),
            },
        ];
        for err in not_local {
            assert!(
                !err.is_local_resource_exhaustion(),
                "{err} is not a local resource shortage"
            );
        }
    }

    #[test]
    fn readdress_preserves_local_resource_classification() {
        let err = readdress(os_resolve_error("host", EMFILE), "host:8080");
        assert!(
            err.is_local_resource_exhaustion(),
            "re-addressing must keep the errno, got {err}"
        );
        assert!(
            err.to_string().contains("host:8080"),
            "error must name the caller address: {err}"
        );
    }

    #[tokio::test]
    async fn local_exhaustion_is_not_negatively_cached() {
        let host = "emfile-nocache.praxis-sf-test.invalid";
        let failing = ControlledLookup::new(Behavior::FailOs(EMFILE));
        failing.release.notify_one();
        let err = resolve_host_cached_with(host, &failing)
            .await
            .expect_err("with nothing cached the local failure must surface");
        assert!(
            err.is_local_resource_exhaustion(),
            "caller must see the local failure, got {err}"
        );
        assert!(
            lookup_cached(host).is_none(),
            "a local shortage must not be cached as a negative answer"
        );

        let healthy = ControlledLookup::new(Behavior::Ok(vec!["4.4.4.4".parse().unwrap()]));
        healthy.release.notify_one();
        let ips = resolve_host_cached_with(host, &healthy)
            .await
            .expect("resolution must recover as soon as descriptors free up");
        assert_eq!(ips, vec!["4.4.4.4".parse::<IpAddr>().unwrap()], "recovered answer");
        assert_eq!(
            healthy.calls.load(Ordering::SeqCst),
            1,
            "recovery must re-resolve at once rather than wait out a negative TTL"
        );
    }

    #[tokio::test]
    async fn local_exhaustion_serves_the_last_good_answer() {
        let host = "emfile-stale.praxis-sf-test.invalid";
        let stale_age = Duration::from_secs(DNS_TTL_SECS + 1);
        insert_aged(host, "5.6.7.8", stale_age);
        assert!(
            lookup_cached(host).is_none(),
            "precondition: the positive answer has expired"
        );

        let failing = ControlledLookup::new(Behavior::FailOs(EMFILE));
        failing.release.notify_one();
        let ips = resolve_host_cached_with(host, &failing)
            .await
            .expect("the last good answer must be served during a local shortage");
        assert_eq!(ips, vec!["5.6.7.8".parse::<IpAddr>().unwrap()], "stale answer");
        assert!(
            dns_cache().get(&cache_key(host)).unwrap().resolved_at.elapsed() >= stale_age,
            "serving stale must not pretend the answer was re-resolved"
        );

        let untouched = ControlledLookup::new(Behavior::FailOs(EMFILE));
        let again = resolve_host_cached_with(host, &untouched)
            .await
            .expect("the retry backoff must serve the stale answer from cache");
        assert_eq!(again, ips, "same stale answer within the backoff");
        assert_eq!(
            untouched.calls.load(Ordering::SeqCst),
            0,
            "requests inside the retry backoff must not hit the failing resolver"
        );
    }

    #[tokio::test]
    async fn local_exhaustion_does_not_serve_answers_past_max_stale() {
        let host = "emfile-too-old.praxis-sf-test.invalid";
        insert_aged(host, "5.6.7.8", Duration::from_secs(MAX_STALE_SECS + 1));

        let failing = ControlledLookup::new(Behavior::FailOs(ENFILE));
        failing.release.notify_one();
        let err = resolve_host_cached_with(host, &failing)
            .await
            .expect_err("an answer older than the stale limit must not be served");
        assert!(
            err.is_local_resource_exhaustion(),
            "caller must see the local failure, got {err}"
        );
        assert!(
            lookup_cached(host).is_none(),
            "nothing may be re-armed or negatively cached"
        );
    }

    #[tokio::test]
    async fn resolver_failure_still_replaces_a_stale_answer() {
        let host = "servfail-stale.praxis-sf-test.invalid";
        insert_aged(host, "5.6.7.8", Duration::from_secs(DNS_TTL_SECS + 1));

        let failing = ControlledLookup::new(Behavior::Fail);
        failing.release.notify_one();
        let err = resolve_host_cached_with(host, &failing)
            .await
            .expect_err("a DNS failure must surface");
        assert!(
            !err.is_local_resource_exhaustion(),
            "precondition: not a local shortage"
        );
        assert!(
            matches!(
                lookup_cached(host),
                Some(Err(AddressResolutionError::RecentFailure { .. }))
            ),
            "a DNS failure must still be negatively cached"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_share_the_stale_answer_during_exhaustion() {
        let host = "emfile-coalesce.praxis-sf-test.invalid";
        insert_aged(host, "8.8.4.4", Duration::from_secs(DNS_TTL_SECS + 1));
        let lookup = ControlledLookup::new(Behavior::FailOs(EMFILE));
        let tasks: Vec<_> = std::iter::repeat_with(|| {
            let l = lookup.clone();
            tokio::spawn(async move { resolve_host_cached_with(host, &l).await })
        })
        .take(6)
        .collect();
        await_lookup_started(&lookup.calls).await;
        lookup.release.notify_waiters();
        for t in tasks {
            let ips = t.await.unwrap().expect("every waiter gets the stale answer");
            assert_eq!(ips, vec!["8.8.4.4".parse::<IpAddr>().unwrap()], "stale answer fan-out");
        }
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 1, "exactly one blocking lookup");
        assert!(
            !dns_inflight().contains_key(&cache_key(host)),
            "inflight entry removed after serving stale"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    use std::sync::{
        Arc as StdArc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    enum Behavior {
        Ok(Vec<IpAddr>),
        Empty,
        Fail,
        FailOs(i32),
        Panic,
    }

    #[derive(Clone)]
    struct ControlledLookup {
        calls: StdArc<AtomicUsize>,
        release: StdArc<tokio::sync::Notify>,
        behavior: Behavior,
    }

    impl ControlledLookup {
        fn new(behavior: Behavior) -> Self {
            Self {
                calls: StdArc::new(AtomicUsize::new(0)),
                release: StdArc::new(tokio::sync::Notify::new()),
                behavior,
            }
        }
    }

    impl BlockingLookup for ControlledLookup {
        async fn lookup(&self, host: String) -> Result<Vec<IpAddr>, AddressResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let release = StdArc::clone(&self.release);
            let behavior = self.behavior.clone();
            release.notified().await;
            match behavior {
                Behavior::Ok(ips) => Ok(ips),
                Behavior::Empty => Ok(Vec::new()),
                Behavior::Fail => Err(AddressResolutionError::Resolve {
                    address: host,
                    source: std::io::Error::from_raw_os_error(111),
                }),
                Behavior::FailOs(code) => Err(os_resolve_error(&host, code)),
                #[expect(clippy::panic, reason = "test double intentionally panics to verify cleanup guard")]
                Behavior::Panic => panic!("controlled lookup panic for {host}"),
            }
        }
    }

    fn os_resolve_error(host: &str, code: i32) -> AddressResolutionError {
        AddressResolutionError::Resolve {
            address: host.to_owned(),
            source: std::io::Error::from_raw_os_error(code),
        }
    }

    fn insert_aged(host: &str, ip: &str, age: Duration) {
        let resolved_at = Instant::now()
            .checked_sub(age)
            .expect("the monotonic clock must be older than the test offset");
        dns_cache().insert(
            cache_key(host),
            DnsCacheEntry {
                outcome: Ok(Arc::from([ip.parse::<IpAddr>().unwrap()].as_slice())),
                resolved_at,
                fresh_until: later(resolved_at, DNS_TTL_SECS),
            },
        );
    }

    // Poll until the lookup has been entered (calls > 0), yielding cooperatively.
    #[expect(clippy::panic, reason = "test utility panics on timeout to fail the test early")]
    async fn await_lookup_started(calls: &AtomicUsize) {
        for _ in 0..1_000 {
            if calls.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("lookup never started");
    }

    #[tokio::test]
    async fn concurrent_callers_coalesce_to_one_lookup() {
        let host = "coalesce.praxis-sf-test.invalid";
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let tasks: Vec<_> = std::iter::repeat_with(|| {
            let l = lookup.clone();
            tokio::spawn(async move { resolve_host_cached_with(host, &l).await })
        })
        .take(8)
        .collect();
        await_lookup_started(&lookup.calls).await;
        assert!(
            dns_inflight().contains_key(&cache_key(host)),
            "inflight entry must exist while blocked"
        );
        lookup.release.notify_waiters();
        for t in tasks {
            let ips = t.await.unwrap().expect("all callers resolve");
            assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        }
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 1, "exactly one blocking lookup");
        assert!(
            !dns_inflight().contains_key(&cache_key(host)),
            "entry removed after completion"
        );
        assert!(lookup_cached(host).is_some(), "cache populated after completion");
    }

    #[tokio::test]
    async fn error_fans_out_to_all_waiters_and_removes_entry() {
        let host = "errfanout.praxis-sf-test.invalid";
        let lookup = ControlledLookup::new(Behavior::Fail);
        let tasks: Vec<_> = std::iter::repeat_with(|| {
            let l = lookup.clone();
            tokio::spawn(async move { resolve_host_cached_with(host, &l).await })
        })
        .take(5)
        .collect();
        await_lookup_started(&lookup.calls).await;
        lookup.release.notify_waiters();
        for t in tasks {
            let err = t.await.unwrap().expect_err("every waiter gets the error");
            assert!(matches!(err, AddressResolutionError::Resolve { .. }), "got {err}");
            if let AddressResolutionError::Resolve { source, .. } = &err {
                assert_eq!(source.raw_os_error(), Some(111), "raw_os_error must survive fan-out");
                assert_eq!(
                    source.kind(),
                    std::io::Error::from_raw_os_error(111).kind(),
                    "io::ErrorKind must survive fan-out",
                );
            }
        }
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
        assert!(
            !dns_inflight().contains_key(&cache_key(host)),
            "entry removed after error"
        );
    }

    #[tokio::test]
    async fn zero_address_answer_is_negatively_cached() {
        let host = "empty.praxis-sf-test.invalid";
        let lookup = ControlledLookup::new(Behavior::Empty);
        lookup.release.notify_one();
        let err = resolve_host_cached_with(host, &lookup)
            .await
            .expect_err("empty → error");
        assert!(matches!(err, AddressResolutionError::Empty(_)), "got {err}");
        let cached = lookup_cached(host).expect("negative cache entry");
        assert!(matches!(cached, Err(AddressResolutionError::RecentFailure { .. })));
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "covers positive, negative, and absent cache entries"
    )]
    async fn per_call_bypasses_positive_and_negative_cache_without_replacing_them() {
        let positive = "per-call-positive.praxis-test.invalid";
        insert_cached(positive, Ok(Arc::from(["1.2.3.4".parse::<IpAddr>().unwrap()])));
        let fresh = ControlledLookup::new(Behavior::Ok(vec!["5.6.7.8".parse().unwrap()]));
        fresh.release.notify_one();
        assert_eq!(
            resolve_host_per_call_with(positive, &fresh, per_call_dns_admission())
                .await
                .unwrap(),
            vec!["5.6.7.8".parse::<IpAddr>().unwrap()],
            "per-call lookup must ignore the positive cache entry"
        );
        assert_eq!(fresh.calls.load(Ordering::SeqCst), 1, "fresh lookup must run once");
        assert_eq!(
            resolve_host_cached_with(positive, &fresh).await.unwrap(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
            "per-call lookup must leave the positive answer intact"
        );
        assert_eq!(fresh.calls.load(Ordering::SeqCst), 1, "cached read must not repeat DNS");

        let negative = "per-call-negative.praxis-test.invalid";
        insert_cached(negative, Err("cached failure".to_owned()));
        let recovered = ControlledLookup::new(Behavior::Ok(vec!["9.8.7.6".parse().unwrap()]));
        recovered.release.notify_one();
        assert_eq!(
            resolve_host_per_call_with(negative, &recovered, per_call_dns_admission())
                .await
                .unwrap(),
            vec!["9.8.7.6".parse::<IpAddr>().unwrap()],
            "per-call lookup must ignore the negative cache entry"
        );
        assert!(
            matches!(
                resolve_host_cached_with(negative, &recovered).await,
                Err(AddressResolutionError::RecentFailure { .. })
            ),
            "per-call success must leave the cached failure intact"
        );
        assert_eq!(
            recovered.calls.load(Ordering::SeqCst),
            1,
            "cached failure must not repeat DNS"
        );

        let uncached = "per-call-new.praxis-test.invalid";
        let only_this_call = ControlledLookup::new(Behavior::Ok(vec!["4.3.2.1".parse().unwrap()]));
        only_this_call.release.notify_one();
        resolve_host_per_call_with(uncached, &only_this_call, per_call_dns_admission())
            .await
            .expect("per-call lookup succeeds without populating the cache");
        assert!(
            lookup_cached(uncached).is_none(),
            "per-call success must not populate cache"
        );
        assert!(
            lookup_cached(positive).is_some(),
            "per-call lookup must not evict cached entries"
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "verifies independent in-flight cache and per-call lookups"
    )]
    async fn per_call_does_not_join_or_publish_to_cached_inflight() {
        let host = "per-call-inflight.praxis-test.invalid";
        let cached = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let cached_lookup = cached.clone();
        let cached_task = tokio::spawn(async move { resolve_host_cached_with(host, &cached_lookup).await });
        await_lookup_started(&cached.calls).await;
        assert!(
            dns_inflight().contains_key(&cache_key(host)),
            "cached lookup must remain in flight while its resolver waits"
        );

        let per_call = ControlledLookup::new(Behavior::Empty);
        per_call.release.notify_one();
        assert!(
            matches!(
                resolve_host_per_call_with(host, &per_call, per_call_dns_admission()).await,
                Err(AddressResolutionError::Empty(_))
            ),
            "per-call lookup must use its own empty answer"
        );
        assert_eq!(
            per_call.calls.load(Ordering::SeqCst),
            1,
            "per-call resolver must run once"
        );
        assert!(
            !cached_task.is_finished(),
            "per-call result must not complete cached lookup"
        );
        assert!(
            lookup_cached(host).is_none(),
            "per-call failure must not populate cache"
        );

        cached.release.notify_one();
        assert_eq!(
            cached_task.await.unwrap().unwrap(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
            "cached in-flight lookup must publish its own answer"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "verifies admission ownership across cancellation")]
    async fn per_call_admission_survives_caller_cancellation() {
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let first = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let first_lookup = first.clone();
        let first_admission = Arc::clone(&admission);
        let first_caller = tokio::spawn(async move {
            resolve_host_per_call_with("first.praxis-test.invalid", &first_lookup, &first_admission).await
        });
        await_lookup_started(&first.calls).await;
        assert_eq!(
            admission.available_permits(),
            0,
            "first lookup must hold the only permit"
        );

        first_caller.abort();
        let second = ControlledLookup::new(Behavior::Ok(vec!["5.6.7.8".parse().unwrap()]));
        let second_lookup = second.clone();
        let second_admission = Arc::clone(&admission);
        let second_caller = tokio::spawn(async move {
            resolve_host_per_call_with("second.praxis-test.invalid", &second_lookup, &second_admission).await
        });
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            second.calls.load(Ordering::SeqCst),
            0,
            "canceling the first caller must not let the second resolver start"
        );
        assert_eq!(
            admission.available_permits(),
            0,
            "canceling the caller must not release the permit while its resolver is blocked"
        );

        first.release.notify_one();
        await_lookup_started(&second.calls).await;
        second.release.notify_one();
        assert_eq!(
            second_caller.await.unwrap().unwrap(),
            vec!["5.6.7.8".parse::<IpAddr>().unwrap()],
            "second lookup must finish after the first releases admission"
        );
        assert_eq!(
            admission.available_permits(),
            1,
            "completed lookups must release the permit"
        );
    }

    #[tokio::test]
    async fn owner_panic_removes_entry_and_does_not_poison() {
        let host = "panic.praxis-sf-test.invalid";
        let panicking = ControlledLookup::new(Behavior::Panic);
        panicking.release.notify_one();
        let first = resolve_host_cached_with(host, &panicking).await;
        assert!(first.is_err(), "a panicked owner surfaces a fresh error");
        assert!(
            !dns_inflight().contains_key(&cache_key(host)),
            "cleanup guard removed the entry"
        );
        assert!(
            lookup_cached(host).is_none(),
            "a panic must not be cached (positive or negative)"
        );

        let healthy = ControlledLookup::new(Behavior::Ok(vec!["9.9.9.9".parse().unwrap()]));
        healthy.release.notify_one();
        let ips = resolve_host_cached_with(host, &healthy).await.expect("re-resolves");
        assert_eq!(ips, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(healthy.calls.load(Ordering::SeqCst), 1, "fresh owner ran");
    }

    #[tokio::test]
    async fn owner_re_check_short_circuits_a_cached_host() {
        let host = "recheck.praxis-sf-test.invalid";
        insert_cached(host, Ok(Arc::from(["7.7.7.7".parse::<IpAddr>().unwrap()].as_slice())));
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["0.0.0.0".parse().unwrap()]));
        lookup.release.notify_waiters();
        let ips = resolve_host_cached_with(host, &lookup)
            .await
            .expect("served from cache");
        assert_eq!(
            ips,
            vec!["7.7.7.7".parse::<IpAddr>().unwrap()],
            "cache hit, not the fresh lookup"
        );
        assert_eq!(
            lookup.calls.load(Ordering::SeqCst),
            0,
            "re-check must skip BlockingLookup"
        );
    }

    #[tokio::test]
    async fn caller_cancellation_leaves_the_owner_running() {
        let host = "cancel.praxis-sf-test.invalid";
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["1.1.1.1".parse().unwrap()]));
        let waiter = {
            let l = lookup.clone();
            tokio::spawn(async move { resolve_host_cached_with(host, &l).await })
        };
        await_lookup_started(&lookup.calls).await;
        waiter.abort();
        drop(waiter.await);
        assert!(
            dns_inflight().contains_key(&cache_key(host)),
            "the detached owner must survive caller cancellation"
        );
        lookup.release.notify_waiters();
        for _ in 0..1_000 {
            if lookup_cached(host).is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(lookup_cached(host).is_some(), "owner completed after caller cancel");
    }
}
