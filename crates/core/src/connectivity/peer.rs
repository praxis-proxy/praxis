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
    sync::{Arc, Mutex, OnceLock, PoisonError},
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

/// Maximum client-selected DNS lookups a caller is waiting on at once.
///
/// A caller holds one of these slots for at most [`PER_CALL_DNS_LOOKUP_CAP`].
/// A lookup still blocking past that hands its slot back and runs on against
/// [`MAX_ABANDONED_PER_CALL_DNS_LOOKUPS`]; the contract is documented on
/// [`UrlResolutionPolicy::ClientPerCall`](crate::connectivity::UrlResolutionPolicy::ClientPerCall).
const MAX_PER_CALL_DNS_LOOKUPS: usize = 64;

/// Maximum client-selected lookups whose caller stopped waiting while the
/// blocking resolver is still running. Together with the attended slots this
/// is half of tokio's default 512 blocking threads, so stalled per-call DNS
/// can never take the whole pool from the cached resolver and file IO.
const MAX_ABANDONED_PER_CALL_DNS_LOOKUPS: usize = 192; // 64 + 192 = 256

/// How long a client-selected lookup may hold its admission slot, and how
/// long a caller waits for one. One glibc `RES_TIMEOUT` round: a healthy
/// resolver answers in milliseconds, and a lookup past this has already lost
/// a UDP round to a dead nameserver.
const PER_CALL_DNS_LOOKUP_CAP: Duration = Duration::from_secs(5); // one RES_TIMEOUT

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

    /// A client-selected lookup was still blocking when its slot cap fired.
    /// The resolver thread keeps running, counted against the abandoned
    /// budget or, when that budget was full, still holding its slot.
    #[error("upstream address resolution for '{address}' exceeded {after:?}")]
    Stalled {
        /// Hostname being resolved.
        address: String,
        /// The cap the lookup outran.
        after: Duration,
    },

    /// No client-selected lookup slot freed up within one slot cap.
    #[error("upstream address resolution for '{address}' refused: per-call DNS lookups saturated")]
    Saturated {
        /// Hostname being resolved.
        address: String,
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
            | Self::UntrustedRange { .. }
            | Self::Stalled { .. }
            | Self::Saturated { .. } => false,
        }
    }
}

/// A TLS upstream with no server name to verify its certificate against.
#[derive(Debug, thiserror::Error)]
#[error("refusing TLS to upstream '{address}': no server name to verify its certificate against")]
pub struct MissingServerName {
    /// The upstream address no name was found for.
    pub address: String,
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
#[expect(clippy::too_many_lines, reason = "one arm per variant, rebuilt field by field")]
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
        AddressResolutionError::Stalled { address, after } => AddressResolutionError::Stalled {
            address: address.clone(),
            after: *after,
        },
        AddressResolutionError::Saturated { address } => AddressResolutionError::Saturated {
            address: address.clone(),
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
        AddressResolutionError::Stalled { after, .. } => AddressResolutionError::Stalled {
            address: caller.to_owned(),
            after,
        },
        AddressResolutionError::Saturated { .. } => AddressResolutionError::Saturated {
            address: caller.to_owned(),
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
///
/// The lookup runs under the process-wide per-call bounds: at most
/// [`MAX_PER_CALL_DNS_LOOKUPS`] callers wait on a lookup at once, each for at
/// most [`PER_CALL_DNS_LOOKUP_CAP`], and a lookup still blocking past that cap
/// hands its slot back and runs on against the abandoned budget.
pub(crate) async fn resolve_host_per_call(host: &str) -> Result<Vec<IpAddr>, AddressResolutionError> {
    resolve_host_per_call_with(host, &SystemLookup, per_call_dns_bounds()).await
}

/// The bounds every client-selected lookup runs under.
pub(crate) struct PerCallDnsBounds {
    /// Lookups whose caller stopped waiting while the resolver thread is
    /// still running.
    pub(crate) abandoned: Arc<tokio::sync::Semaphore>,
    /// Lookups a caller is waiting on.
    pub(crate) admission: Arc<tokio::sync::Semaphore>,
    /// How long a lookup may hold an admission slot, and how long a caller
    /// waits for one.
    pub(crate) cap: Duration,
}

/// The process-wide [`PerCallDnsBounds`], sized by the constants above.
fn per_call_dns_bounds() -> &'static PerCallDnsBounds {
    static BOUNDS: OnceLock<PerCallDnsBounds> = OnceLock::new();
    BOUNDS.get_or_init(|| PerCallDnsBounds {
        abandoned: Arc::new(tokio::sync::Semaphore::new(MAX_ABANDONED_PER_CALL_DNS_LOOKUPS)),
        admission: Arc::new(tokio::sync::Semaphore::new(MAX_PER_CALL_DNS_LOOKUPS)),
        cap: PER_CALL_DNS_LOOKUP_CAP,
    })
}

/// A lookup task's outcome.
type LookupAnswer = Result<Vec<IpAddr>, AddressResolutionError>;

/// Which bound a running client-selected lookup is counted against.
enum Held {
    /// Its caller is still waiting: an admission slot.
    Attended(tokio::sync::OwnedSemaphorePermit),
    /// Its caller stopped waiting: a share of the abandoned budget.
    Abandoned(tokio::sync::OwnedSemaphorePermit),
}

impl Held {
    /// The permit itself, whichever bound it came from.
    fn into_permit(self) -> tokio::sync::OwnedSemaphorePermit {
        match self {
            Self::Attended(permit) | Self::Abandoned(permit) => permit,
        }
    }
}

/// The permit a running lookup holds, shared between its caller and the
/// lookup task. Empty once the lookup has finished.
type Slot = Mutex<Option<Held>>;

/// Lock `slot`, recovering from poison: the only writes are a swap and a
/// take, so a poisoned slot still holds a consistent value.
fn lock_slot(slot: &Slot) -> std::sync::MutexGuard<'_, Option<Held>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Owned by the lookup task: empties the slot when the lookup finishes, by
/// any exit including a panic, so the permit is released exactly when the
/// resolver thread is done.
struct SlotRelease(Arc<Slot>);

impl Drop for SlotRelease {
    fn drop(&mut self) {
        let released = lock_slot(&self.0).take().map(Held::into_permit);
        drop(released);
    }
}

/// Owned by the caller: when the caller stops waiting (its cap fired, or its
/// own deadline dropped it), a lookup that is still running moves to the
/// abandoned budget, which hands the admission slot back. When the budget is
/// full the lookup keeps its slot until it finishes.
struct Attendance {
    /// The budget a still-running lookup moves to.
    abandoned: Arc<tokio::sync::Semaphore>,
    /// The lookup's permit slot.
    slot: Arc<Slot>,
}

impl Drop for Attendance {
    fn drop(&mut self) {
        let mut held = lock_slot(&self.slot);
        let previous = if matches!(*held, Some(Held::Attended(_)))
            && let Ok(budget) = Arc::clone(&self.abandoned).try_acquire_owned()
        {
            held.replace(Held::Abandoned(budget))
        } else {
            None
        };
        drop(held);
        drop(previous);
    }
}

/// Run one lookup under `bounds`. The caller holds an admission slot for at
/// most `bounds.cap`; a lookup still blocking past that is handed to the
/// abandoned budget and reported as [`AddressResolutionError::Stalled`]. A
/// caller that finds no slot within one cap gets
/// [`AddressResolutionError::Saturated`] without starting a lookup.
pub(crate) async fn resolve_host_per_call_with<L: BlockingLookup>(
    host: &str,
    lookup: &L,
    bounds: &PerCallDnsBounds,
) -> Result<Vec<IpAddr>, AddressResolutionError> {
    let permit = admit(host, bounds).await?;
    let release = SlotRelease(Arc::new(Slot::new(Some(Held::Attended(permit)))));
    let attendance = Attendance {
        abandoned: Arc::clone(&bounds.abandoned),
        slot: Arc::clone(&release.0),
    };
    let task_host = host.to_owned();
    let task_lookup = lookup.clone();
    let mut handle = tokio::spawn(async move {
        let _release = release;
        task_lookup.lookup(task_host).await
    });
    match tokio::time::timeout(bounds.cap, &mut handle).await {
        Ok(joined) => {
            drop(attendance);
            answer(host, joined)
        },
        Err(_elapsed) => settle_after_cap(host, handle, attendance, bounds.cap).await,
    }
}

/// Wait at most `bounds.cap` for an admission slot.
async fn admit(
    host: &str,
    bounds: &PerCallDnsBounds,
) -> Result<tokio::sync::OwnedSemaphorePermit, AddressResolutionError> {
    match tokio::time::timeout(bounds.cap, Arc::clone(&bounds.admission).acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(closed)) => Err(AddressResolutionError::Task {
            address: host.to_owned(),
            message: closed.to_string(),
        }),
        Err(_elapsed) => Err(AddressResolutionError::Saturated {
            address: host.to_owned(),
        }),
    }
}

/// The caller's side of a lookup that outran the cap. Dropping `attendance`
/// moves a lookup that is still running to the abandoned budget; one that
/// finished in the meantime left its slot empty, and its answer is returned
/// rather than a `Stalled` the caller would take for a resolver problem.
async fn settle_after_cap(
    host: &str,
    handle: tokio::task::JoinHandle<LookupAnswer>,
    attendance: Attendance,
    cap: Duration,
) -> LookupAnswer {
    let slot = Arc::clone(&attendance.slot);
    drop(attendance);
    let finished = lock_slot(&slot).is_none();
    if finished {
        return answer(host, handle.await);
    }
    Err(AddressResolutionError::Stalled {
        address: host.to_owned(),
        after: cap,
    })
}

/// The caller-visible outcome of a joined lookup task.
fn answer(host: &str, joined: Result<LookupAnswer, tokio::task::JoinError>) -> LookupAnswer {
    let ips = joined.map_err(|err| AddressResolutionError::Task {
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

/// Derive the TLS server name for an `address` in `host:port` form.
///
/// A DNS name comes back as the hostname. An IP address comes back as
/// the bare IP, brackets stripped: rustls verifies it against the
/// certificate's IP SAN and, as [RFC 6066] requires, sends no SNI
/// extension for it.
///
/// ```
/// use praxis_core::connectivity::peer;
///
/// assert_eq!(peer::derive_sni("api.example.com:443"), "api.example.com");
/// assert_eq!(peer::derive_sni("127.0.0.1:443"), "127.0.0.1");
/// assert_eq!(peer::derive_sni("[::1]:443"), "::1");
/// ```
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
pub fn derive_sni(address: &str) -> String {
    let raw = address.rsplit_once(':').map_or(address, |(host_part, _)| host_part);
    // Certificates never carry the root dot; a dotted IP spelling keeps it and fails closed.
    let stripped = super::strip_root_dot(raw);
    let host = if stripped != raw && is_ip_literal(stripped) {
        raw
    } else {
        stripped
    };
    let name = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .filter(|inner| inner.parse::<IpAddr>().is_ok())
        .unwrap_or(host);
    tracing::debug!(address, sni = name, "derived TLS server name from upstream address");
    name.to_owned()
}

/// The name a TLS peer for `address` presents and verifies the upstream
/// certificate against.
///
/// `tls.sni` wins when set, whether configured or filled in from the
/// request by the load balancer. Otherwise the name comes from the
/// endpoint address (see [`derive_sni`]).
///
/// ```
/// use praxis_core::connectivity::peer;
/// use praxis_tls::{CachedClusterTls, ClusterTls};
///
/// let mut tls = CachedClusterTls::try_from_config(&ClusterTls::default()).unwrap();
/// assert_eq!(
///     peer::tls_server_name(&tls, "10.0.0.5:443").unwrap(),
///     "10.0.0.5"
/// );
///
/// tls.set_sni("api.example.com");
/// assert_eq!(
///     peer::tls_server_name(&tls, "10.0.0.5:443").unwrap(),
///     "api.example.com"
/// );
///
/// tls.set_sni("");
/// assert!(peer::tls_server_name(&tls, "10.0.0.5:443").is_err());
/// ```
///
/// # Errors
///
/// Returns [`MissingServerName`] when neither gives a name. Pingora's
/// connector turns certificate verification off for an empty name, so a
/// TLS peer must never be built with one.
pub fn tls_server_name(tls: &praxis_tls::CachedClusterTls, address: &str) -> Result<String, MissingServerName> {
    let name = tls.sni().map_or_else(|| derive_sni(address), str::to_owned);
    if name.is_empty() {
        return Err(MissingServerName {
            address: address.to_owned(),
        });
    }
    Ok(name)
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
            base_path: None,
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
    fn derive_sni_returns_the_ip_for_an_ipv4_address() {
        assert_eq!(
            derive_sni("10.0.0.5:443"),
            "10.0.0.5",
            "an IPv4 endpoint should be verified against its IP SAN, so its name is the IP"
        );
    }

    #[test]
    fn derive_sni_returns_the_unbracketed_ip_for_an_ipv6_address() {
        assert_eq!(
            derive_sni("[::1]:8443"),
            "::1",
            "rustls parses a bare IPv6 address, not the bracketed authority form"
        );
        assert_eq!(derive_sni("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn tls_server_name_refuses_an_empty_name() {
        let mut tls = praxis_tls::CachedClusterTls::try_from_config(&praxis_tls::ClusterTls::default()).unwrap();
        let unnamed_address = tls_server_name(&tls, ":443").unwrap_err();
        assert_eq!(unnamed_address.address, ":443", "the error should name the upstream");

        tls.set_sni("");
        let empty_sni = tls_server_name(&tls, "10.0.0.5:443").unwrap_err();
        assert!(
            empty_sni.to_string().contains("no server name"),
            "an empty configured name must be refused, not fall back to the address: {empty_sni}"
        );
    }

    #[test]
    fn tls_server_name_prefers_the_set_sni_over_the_address() {
        let mut tls = praxis_tls::CachedClusterTls::try_from_config(&praxis_tls::ClusterTls::default()).unwrap();
        assert_eq!(
            tls_server_name(&tls, "backend.example.com:443").unwrap(),
            "backend.example.com"
        );

        tls.set_sni("api.example.com");
        assert_eq!(
            tls_server_name(&tls, "backend.example.com:443").unwrap(),
            "api.example.com",
            "a set SNI should win over the endpoint name"
        );
    }

    #[test]
    fn derive_sni_keeps_brackets_around_a_non_ip() {
        assert_eq!(
            derive_sni("[backend]:443"),
            "[backend]",
            "only a real IPv6 literal loses its brackets; anything else stays invalid and fails closed"
        );
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
    #[expect(
        clippy::too_many_lines,
        reason = "one entry per variant that is not a local shortage"
    )]
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
            AddressResolutionError::Stalled {
                address: "h".to_owned(),
                after: TEST_CAP,
            },
            AddressResolutionError::Saturated {
                address: "h".to_owned(),
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

    #[derive(Clone)]
    struct SleepingLookup {
        delay: Duration,
    }

    impl BlockingLookup for SleepingLookup {
        async fn lookup(&self, _host: String) -> Result<Vec<IpAddr>, AddressResolutionError> {
            tokio::time::sleep(self.delay).await;
            Ok(vec!["1.2.3.4".parse().unwrap()])
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

    // Poll until the semaphore shows `want` permits, yielding cooperatively.
    #[expect(clippy::panic, reason = "test utility panics on timeout to fail the test early")]
    async fn await_permits(semaphore: &tokio::sync::Semaphore, want: usize) {
        for _ in 0..1_000 {
            if semaphore.available_permits() == want {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("semaphore never reached {want} permits");
    }

    const TEST_CAP: Duration = Duration::from_secs(5);

    fn test_bounds(admission: usize, abandoned: usize) -> PerCallDnsBounds {
        PerCallDnsBounds {
            abandoned: Arc::new(tokio::sync::Semaphore::new(abandoned)),
            admission: Arc::new(tokio::sync::Semaphore::new(admission)),
            cap: TEST_CAP,
        }
    }

    fn spawn_per_call(
        host: &'static str,
        lookup: &ControlledLookup,
        bounds: &Arc<PerCallDnsBounds>,
    ) -> tokio::task::JoinHandle<LookupAnswer> {
        let lookup = lookup.clone();
        let bounds = Arc::clone(bounds);
        tokio::spawn(async move { resolve_host_per_call_with(host, &lookup, &bounds).await })
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
            resolve_host_per_call_with(positive, &fresh, per_call_dns_bounds())
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
            resolve_host_per_call_with(negative, &recovered, per_call_dns_bounds())
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
        resolve_host_per_call_with(uncached, &only_this_call, per_call_dns_bounds())
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
                resolve_host_per_call_with(host, &per_call, per_call_dns_bounds()).await,
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
    #[expect(
        clippy::too_many_lines,
        reason = "verifies the slot hand-off across caller cancellation"
    )]
    async fn cancelled_caller_moves_its_lookup_to_the_abandoned_budget() {
        let bounds = Arc::new(test_bounds(1, 1));
        let first = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let first_caller = spawn_per_call("first.praxis-test.invalid", &first, &bounds);
        await_lookup_started(&first.calls).await;
        assert_eq!(
            bounds.admission.available_permits(),
            0,
            "the first lookup must hold the only slot while its caller waits"
        );

        first_caller.abort();
        drop(first_caller.await);
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "a cancelled caller must hand its slot back while its lookup is still blocked"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "the orphaned lookup must be counted against the abandoned budget"
        );

        let second = ControlledLookup::new(Behavior::Ok(vec!["5.6.7.8".parse().unwrap()]));
        let second_caller = spawn_per_call("second.praxis-test.invalid", &second, &bounds);
        await_lookup_started(&second.calls).await;
        second.release.notify_one();
        assert_eq!(
            second_caller.await.unwrap().unwrap(),
            vec!["5.6.7.8".parse::<IpAddr>().unwrap()],
            "the second caller must resolve while the first lookup is still blocked"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "the first lookup is still blocked, so it must still be budgeted"
        );

        first.release.notify_one();
        await_permits(&bounds.abandoned, 1).await;
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "every slot must be free once both lookups have finished"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "cancels a queued caller, then drains the holder")]
    async fn caller_cancelled_while_waiting_for_a_slot_leaves_nothing_behind() {
        let bounds = Arc::new(test_bounds(1, 1));
        let holder = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let holder_caller = spawn_per_call("holder.praxis-test.invalid", &holder, &bounds);
        await_lookup_started(&holder.calls).await;

        let waiter = ControlledLookup::new(Behavior::Ok(vec!["5.6.7.8".parse().unwrap()]));
        let waiter_caller = spawn_per_call("waiter.praxis-test.invalid", &waiter, &bounds);
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        waiter_caller.abort();
        drop(waiter_caller.await);
        assert_eq!(
            waiter.calls.load(Ordering::SeqCst),
            0,
            "a caller cancelled in the admission queue must never have started a lookup"
        );

        holder.release.notify_one();
        assert_eq!(
            holder_caller.await.unwrap().unwrap(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
            "the holder resolves once released"
        );
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "the slot must come back to the pool, not to the cancelled waiter"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            1,
            "a caller that never held a slot has nothing to hand to the budget"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "proves the slot hand-off and the later budget refill"
    )]
    async fn cap_frees_the_slot_while_the_lookup_is_still_blocked() {
        let bounds = test_bounds(1, 1);
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(6),
            resolve_host_per_call_with("stalled.praxis-test.invalid", &lookup, &bounds),
        )
        .await
        .expect("the caller must be released at the cap, not held for the life of the blocking lookup")
        .expect_err("a lookup still blocked at the cap must not be reported as resolved");
        assert_eq!(
            started.elapsed(),
            TEST_CAP,
            "the caller must be released exactly when the cap fires"
        );
        assert!(
            matches!(
                &err,
                AddressResolutionError::Stalled { address, after }
                    if address == "stalled.praxis-test.invalid" && *after == TEST_CAP
            ),
            "the cap must surface as Stalled naming the host and the cap: {err}"
        );
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "the cap must hand the admission slot back while the lookup is still blocked"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "the still-running lookup must be counted against the abandoned budget"
        );
        assert_eq!(
            lookup.calls.load(Ordering::SeqCst),
            1,
            "exactly one lookup must have run"
        );

        lookup.release.notify_one();
        await_permits(&bounds.abandoned, 1).await;
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "an abandoned lookup finishing must refill the budget, not admission"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(clippy::too_many_lines, reason = "walks two stuck lookups through a budget of one")]
    async fn full_abandoned_budget_keeps_the_slot_until_the_lookup_finishes() {
        let bounds = test_bounds(1, 1);
        let stuck = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let budgeted = resolve_host_per_call_with("budgeted.praxis-test.invalid", &stuck, &bounds)
            .await
            .expect_err("the first stuck lookup stalls at the cap");
        assert!(
            matches!(budgeted, AddressResolutionError::Stalled { .. }),
            "got {budgeted}"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "the first lookup takes the budget"
        );

        let kept = resolve_host_per_call_with("kept.praxis-test.invalid", &stuck, &bounds)
            .await
            .expect_err("the caller must still be released at the cap when the budget is full");
        assert!(matches!(kept, AddressResolutionError::Stalled { .. }), "got {kept}");
        assert_eq!(
            bounds.admission.available_permits(),
            0,
            "with the budget full the blocked lookup must keep its admission slot"
        );
        assert_eq!(stuck.calls.load(Ordering::SeqCst), 2, "both lookups ran");

        stuck.release.notify_waiters();
        await_permits(&bounds.admission, 1).await;
        await_permits(&bounds.abandoned, 1).await;
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "a kept slot must return to admission when its lookup finishes"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "pins the admission wait to one cap with a far deadline"
    )]
    async fn admission_wait_is_capped_and_starts_no_lookup() {
        let bounds = Arc::new(test_bounds(1, 0));
        let holder = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let holder_caller = spawn_per_call("holder.praxis-test.invalid", &holder, &bounds);
        await_lookup_started(&holder.calls).await;
        tokio::time::advance(Duration::from_secs(1)).await;

        let waiter = ControlledLookup::new(Behavior::Ok(vec!["5.6.7.8".parse().unwrap()]));
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(60),
            resolve_host_per_call_with("waiter.praxis-test.invalid", &waiter, &bounds),
        )
        .await
        .expect("a caller with a far deadline must not wait for a slot past one cap")
        .expect_err("no slot freed, so the caller must fail");
        assert_eq!(
            started.elapsed(),
            TEST_CAP,
            "the admission wait must end exactly at the cap"
        );
        assert!(
            matches!(&err, AddressResolutionError::Saturated { address } if address == "waiter.praxis-test.invalid"),
            "an admission wait that outruns the cap must surface as Saturated: {err}"
        );
        assert_eq!(
            waiter.calls.load(Ordering::SeqCst),
            0,
            "a saturated caller must never start a lookup"
        );
        assert_eq!(
            bounds.admission.available_permits(),
            0,
            "the slot stays with the blocked lookup that could not be budgeted"
        );
        assert!(
            matches!(
                holder_caller.await.unwrap(),
                Err(AddressResolutionError::Stalled { .. })
            ),
            "the holder itself was released at its own cap"
        );

        holder.release.notify_one();
        await_permits(&bounds.admission, 1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn resolved_lookup_leaves_both_bounds_full() {
        let bounds = test_bounds(1, 1);
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        lookup.release.notify_one();
        let started = tokio::time::Instant::now();
        let ips = resolve_host_per_call_with("quick.praxis-test.invalid", &lookup, &bounds)
            .await
            .expect("a lookup that answers within the cap resolves");
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "an answered lookup must not wait for the cap"
        );
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "an answered lookup must hand its slot back"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            1,
            "an answered lookup must never touch the abandoned budget"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(clippy::too_many_lines, reason = "walks the budget from empty to full to refilled")]
    async fn abandoned_budget_refills_when_stuck_lookups_finish() {
        let bounds = test_bounds(1, 2);
        let stuck = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        for host in ["one.praxis-test.invalid", "two.praxis-test.invalid"] {
            let err = resolve_host_per_call_with(host, &stuck, &bounds)
                .await
                .expect_err("each stuck lookup stalls at the cap");
            assert!(matches!(err, AddressResolutionError::Stalled { .. }), "{host}: {err}");
            assert_eq!(
                bounds.admission.available_permits(),
                1,
                "{host}: the slot must be handed back while the budget has room"
            );
        }
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "two stuck lookups fill a budget of two"
        );

        let kept = resolve_host_per_call_with("three.praxis-test.invalid", &stuck, &bounds)
            .await
            .expect_err("the third stuck lookup stalls at the cap too");
        assert!(matches!(kept, AddressResolutionError::Stalled { .. }), "got {kept}");
        assert_eq!(
            bounds.admission.available_permits(),
            0,
            "with the budget full the third lookup must keep its slot"
        );

        let refused = resolve_host_per_call_with("four.praxis-test.invalid", &stuck, &bounds)
            .await
            .expect_err("with every slot pinned a new caller must fail");
        assert!(
            matches!(refused, AddressResolutionError::Saturated { .. }),
            "a new caller must fail fast rather than queue: {refused}"
        );
        assert_eq!(
            stuck.calls.load(Ordering::SeqCst),
            3,
            "the saturated caller must not have started a lookup"
        );

        stuck.release.notify_waiters();
        await_permits(&bounds.abandoned, 2).await;
        await_permits(&bounds.admission, 1).await;
        let fresh = ControlledLookup::new(Behavior::Ok(vec!["9.9.9.9".parse().unwrap()]));
        fresh.release.notify_one();
        let ips = resolve_host_per_call_with("five.praxis-test.invalid", &fresh, &bounds)
            .await
            .expect("once the stuck lookups finish a fresh lookup resolves");
        assert_eq!(ips, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(bounds.admission.available_permits(), 1, "admission fully recovered");
        assert_eq!(bounds.abandoned.available_permits(), 2, "the budget fully recovered");
    }

    #[tokio::test]
    async fn a_lookup_that_finished_as_the_cap_fired_still_returns_its_answer() {
        let bounds = test_bounds(1, 1);
        let handle = tokio::spawn(async { Ok(vec!["1.2.3.4".parse::<IpAddr>().unwrap()]) });
        let ips = settle_after_cap(
            "gap.praxis-test.invalid",
            handle,
            Attendance {
                abandoned: Arc::clone(&bounds.abandoned),
                slot: Arc::new(Slot::new(None)),
            },
            TEST_CAP,
        )
        .await
        .expect("an answer that exists must not be reported as stalled");
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            bounds.abandoned.available_permits(),
            1,
            "a finished lookup must not consume the abandoned budget"
        );
    }

    #[tokio::test]
    async fn settling_after_the_cap_moves_a_running_lookup_to_the_budget() {
        let bounds = test_bounds(1, 1);
        let permit = Arc::clone(&bounds.admission).try_acquire_owned().unwrap();
        let slot = Arc::new(Slot::new(Some(Held::Attended(permit))));
        let handle = tokio::spawn(std::future::pending());
        let err = settle_after_cap(
            "running.praxis-test.invalid",
            handle,
            Attendance {
                abandoned: Arc::clone(&bounds.abandoned),
                slot: Arc::clone(&slot),
            },
            TEST_CAP,
        )
        .await
        .expect_err("a lookup still running at the cap is stalled");
        assert!(matches!(err, AddressResolutionError::Stalled { .. }), "got {err}");
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "settling must hand the admission slot back"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "settling must charge the abandoned budget instead"
        );
        assert!(
            matches!(*lock_slot(&slot), Some(Held::Abandoned(_))),
            "the slot must now hold the budget share for the lookup task to release"
        );
    }

    #[tokio::test(start_paused = true)]
    #[expect(clippy::too_many_lines, reason = "covers a panic while attended and while abandoned")]
    async fn panicking_lookup_releases_its_slot_whether_attended_or_abandoned() {
        let bounds = test_bounds(1, 1);
        let attended = ControlledLookup::new(Behavior::Panic);
        attended.release.notify_one();
        let err = resolve_host_per_call_with("panic-attended.praxis-test.invalid", &attended, &bounds)
            .await
            .expect_err("a panicking lookup surfaces as an error");
        assert!(
            matches!(err, AddressResolutionError::Task { .. }),
            "an attended panic must surface as Task, never as an answer: {err}"
        );
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "an attended lookup that panics must release its slot"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            1,
            "an attended panic must not touch the budget"
        );

        let abandoned = ControlledLookup::new(Behavior::Panic);
        let stalled = resolve_host_per_call_with("panic-abandoned.praxis-test.invalid", &abandoned, &bounds)
            .await
            .expect_err("a lookup still blocked at the cap stalls");
        assert!(
            matches!(stalled, AddressResolutionError::Stalled { .. }),
            "got {stalled}"
        );
        assert_eq!(
            bounds.abandoned.available_permits(),
            0,
            "the lookup moved to the budget at the cap"
        );

        abandoned.release.notify_one();
        await_permits(&bounds.abandoned, 1).await;
        assert_eq!(
            bounds.admission.available_permits(),
            1,
            "an abandoned lookup that panics must release its budget share and nothing else"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::too_many_lines,
        reason = "drives many racing callers and checks the final accounting"
    )]
    async fn racing_callers_on_a_multi_thread_runtime_return_every_permit() {
        let bounds = Arc::new(PerCallDnsBounds {
            abandoned: Arc::new(tokio::sync::Semaphore::new(3)),
            admission: Arc::new(tokio::sync::Semaphore::new(3)),
            cap: Duration::from_millis(3),
        });
        let callers: Vec<_> = (0_u64..120)
            .map(|index| {
                let lookup = SleepingLookup {
                    delay: Duration::from_millis(index % 7),
                };
                let bounds = Arc::clone(&bounds);
                tokio::spawn(
                    async move { resolve_host_per_call_with("race.praxis-test.invalid", &lookup, &bounds).await },
                )
            })
            .collect();
        for caller in callers {
            match caller.await.unwrap() {
                Ok(ips) => assert_eq!(
                    ips,
                    vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
                    "an answer is the real one"
                ),
                Err(AddressResolutionError::Stalled { .. } | AddressResolutionError::Saturated { .. }) => {},
                Err(other) => unreachable!("only answers, stalls and saturation may surface: {other}"),
            }
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while bounds.admission.available_permits() != 3 || bounds.abandoned.available_permits() != 3 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("every admission slot and every budget share must come back once the lookups finish");
    }

    #[tokio::test]
    async fn closed_admission_surfaces_as_a_task_error() {
        let bounds = test_bounds(1, 1);
        bounds.admission.close();
        let lookup = ControlledLookup::new(Behavior::Ok(vec!["1.2.3.4".parse().unwrap()]));
        let err = resolve_host_per_call_with("closed.praxis-test.invalid", &lookup, &bounds)
            .await
            .expect_err("a closed admission pool cannot admit");
        assert!(matches!(err, AddressResolutionError::Task { .. }), "got {err}");
        assert_eq!(
            lookup.calls.load(Ordering::SeqCst),
            0,
            "no lookup may start without a slot"
        );
    }

    #[test]
    fn stalled_and_saturated_name_the_host_only() {
        let stalled = AddressResolutionError::Stalled {
            address: "host".to_owned(),
            after: TEST_CAP,
        };
        let saturated = AddressResolutionError::Saturated {
            address: "host".to_owned(),
        };
        assert_eq!(
            stalled.to_string(),
            "upstream address resolution for 'host' exceeded 5s",
            "Stalled names the host and the cap, nothing from the resolver"
        );
        assert_eq!(
            saturated.to_string(),
            "upstream address resolution for 'host' refused: per-call DNS lookups saturated",
            "Saturated names the host only"
        );
    }

    #[test]
    fn stalled_and_saturated_survive_fan_out_and_readdress() {
        let stalled = AddressResolutionError::Stalled {
            address: "host".to_owned(),
            after: TEST_CAP,
        };
        let saturated = AddressResolutionError::Saturated {
            address: "host".to_owned(),
        };
        assert!(
            matches!(
                &owned_from_arc(&stalled),
                AddressResolutionError::Stalled { address, after } if address == "host" && *after == TEST_CAP
            ),
            "fan-out must keep the cap"
        );
        assert!(
            matches!(&owned_from_arc(&saturated), AddressResolutionError::Saturated { address } if address == "host"),
            "fan-out must keep the host"
        );
        assert!(
            matches!(
                &readdress(stalled, "host:8080"),
                AddressResolutionError::Stalled { address, after } if address == "host:8080" && *after == TEST_CAP
            ),
            "re-addressing must name the caller address and keep the cap"
        );
        assert!(
            matches!(&readdress(saturated, "host:8080"), AddressResolutionError::Saturated { address } if address == "host:8080"),
            "re-addressing must name the caller address"
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
