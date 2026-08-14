// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::{sync::Arc, time::Duration};

use http::HeaderMap;
use metrics::{counter, histogram};
use pingora_core::{
    connectors::{ConnectorOptions, http::Connector},
    protocols::http::client::HttpSession,
    upstreams::peer::{HttpPeer, Peer as _},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use super::types::{SubRequestError, SubResponse};
use crate::circuit::{CircuitBreakerConfig, CircuitBreakerRegistry, CircuitToken, PeerKey};

// ---------------------------------------------------------------------------
// Metric names
// ---------------------------------------------------------------------------

/// Metric name for total streaming sub-request count (with termination label).
pub(super) const SUBREQUEST_STREAMS_TOTAL: &str = "praxis_subrequest_streams_total";
/// Metric name for streaming sub-request duration histogram.
pub(super) const SUBREQUEST_STREAM_DURATION_SECONDS: &str = "praxis_subrequest_stream_duration_seconds";
/// Metric name for streaming sub-request total bytes counter.
pub(super) const SUBREQUEST_STREAM_BYTES_TOTAL: &str = "praxis_subrequest_stream_bytes_total";
/// Metric name for header phase duration (shared buffered/streaming).
pub(super) const SUBREQUEST_HEADER_DURATION_SECONDS: &str = "praxis_subrequest_header_duration_seconds";

// ---------------------------------------------------------------------------
// SubRequestConnectorOptions
// ---------------------------------------------------------------------------

/// Options for constructing a [`SubRequestConnector`].
#[derive(Debug)]
pub struct SubRequestConnectorOptions {
    /// Number of idle connections to keep in the pool.
    pub keepalive_pool_size: usize,

    /// Maximum number of concurrently active exchanges.
    pub max_connections: Option<usize>,

    /// Circuit breaker configuration for peer-level failure tracking.
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

// ---------------------------------------------------------------------------
// SubRequestConnector
// ---------------------------------------------------------------------------

/// Shared HTTP connector for sub-requests.
///
/// Wraps Pingora's [`Connector`] behind an [`Arc`] so that all
/// filter instances share a single connection pool. Created once at
/// server startup and passed through unchanged on config reload.
///
/// An optional admission semaphore limits the number of concurrently
/// active sub-request exchanges.
///
/// ```
/// use praxis_core::subrequest::SubRequestConnector;
///
/// let connector = SubRequestConnector::new(128, None);
/// let _clone = connector.clone();
/// ```
///
/// [`Arc`]: std::sync::Arc
/// [`Connector`]: pingora_core::connectors::http::Connector
#[derive(Clone)]
pub struct SubRequestConnector {
    /// Shared Pingora HTTP connector.
    pub(super) inner: Arc<Connector<()>>,

    /// Admission semaphore bounding concurrently active exchanges.
    pub(super) admission: Option<Arc<Semaphore>>,

    /// The configured concurrency limit, retained for error reporting.
    pub(super) configured_max_connections: Option<usize>,

    /// Per-peer circuit breaker registry.
    pub(super) circuit_breakers: Option<Arc<CircuitBreakerRegistry>>,
}

impl SubRequestConnector {
    /// Create a connector with the given keepalive pool size and
    /// optional active-connection limit.
    ///
    /// ```
    /// use praxis_core::subrequest::SubRequestConnector;
    ///
    /// let connector = SubRequestConnector::new(64, None);
    /// let bounded = SubRequestConnector::new(64, Some(256));
    /// ```
    pub fn new(keepalive_pool_size: usize, max_connections: Option<usize>) -> Self {
        let options = ConnectorOptions::new(keepalive_pool_size);
        Self {
            inner: Arc::new(Connector::new(Some(options))),
            admission: max_connections.map(|n| Arc::new(Semaphore::new(n))),
            configured_max_connections: max_connections,
            circuit_breakers: None,
        }
    }

    /// Create a connector from [`SubRequestConnectorOptions`].
    ///
    /// ```
    /// use praxis_core::subrequest::{SubRequestConnector, SubRequestConnectorOptions};
    ///
    /// let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
    ///     keepalive_pool_size: 64,
    ///     max_connections: Some(256),
    ///     circuit_breaker: None,
    /// });
    /// ```
    pub fn with_options(opts: SubRequestConnectorOptions) -> Self {
        let options = ConnectorOptions::new(opts.keepalive_pool_size);
        Self {
            inner: Arc::new(Connector::new(Some(options))),
            admission: opts.max_connections.map(|n| Arc::new(Semaphore::new(n))),
            configured_max_connections: opts.max_connections,
            circuit_breakers: opts
                .circuit_breaker
                .map(|cfg| Arc::new(CircuitBreakerRegistry::new(cfg))),
        }
    }

    /// Access the underlying Pingora [`Connector`].
    ///
    /// [`Connector`]: pingora_core::connectors::http::Connector
    pub fn connector(&self) -> &Connector<()> {
        &self.inner
    }

    /// Acquire an admission permit if a concurrency limit is
    /// configured. Returns `None` when no limit is set.
    ///
    /// The returned permit must be held for the entire sub-request
    /// exchange. Dropping it releases the slot.
    pub async fn acquire_permit(&self) -> Option<OwnedSemaphorePermit> {
        let semaphore = self.admission.as_ref()?;
        Arc::clone(semaphore).acquire_owned().await.ok()
    }

    /// Try to acquire an admission permit within the given deadline.
    ///
    /// Returns `Ok(Some(permit))` if acquired, `Ok(None)` if no
    /// concurrency limit is configured, or `Err` if the deadline
    /// expires before a slot opens.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError::AdmissionTimeout`] when the
    /// semaphore cannot be acquired within the timeout.
    pub async fn try_acquire_permit(&self, timeout: Duration) -> Result<Option<OwnedSemaphorePermit>, SubRequestError> {
        let Some(semaphore) = self.admission.as_ref() else {
            return Ok(None);
        };
        let configured = self.configured_max_connections.unwrap_or(0);
        match tokio::time::timeout(timeout, Arc::clone(semaphore).acquire_owned()).await {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_closed)) => Err(SubRequestError::AdmissionTimeout {
                max_connections: configured,
            }),
            Err(_elapsed) => Err(SubRequestError::AdmissionTimeout {
                max_connections: configured,
            }),
        }
    }
}

impl std::fmt::Debug for SubRequestConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubRequestConnector")
            .field("pool", &"Connector<()>")
            .field("max_connections", &self.configured_max_connections)
            .field("circuit_breakers", &self.circuit_breakers.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RawExchange
// ---------------------------------------------------------------------------

/// Live HTTP exchange after validated response headers.
///
/// Returned by `open_exchange()` and consumed by either
/// `execute()` (buffered collection) or `send_streaming()`
/// (body ownership handoff).
pub(super) struct RawExchange<'a> {
    /// Live Pingora HTTP session.
    pub(super) session: HttpSession<()>,
    /// Peer address (timeout-bounded).
    pub(super) peer: HttpPeer,
    /// Connector ref for session release.
    pub(super) connector: &'a SubRequestConnector,
    /// HTTP status code.
    pub(super) status: u16,
    /// Sanitized response headers.
    pub(super) headers: HeaderMap,
    /// Optional circuit breaker guard.
    pub(super) circuit_guard: Option<CircuitGuard<'a>>,
    /// Admission permit.
    pub(super) permit: Option<OwnedSemaphorePermit>,
    /// Absolute deadline for the entire exchange.
    pub(super) deadline: tokio::time::Instant,
}

// ---------------------------------------------------------------------------
// Circuit Breaker Guard
// ---------------------------------------------------------------------------

/// RAII guard ensuring every acquired circuit token is finalized.
///
/// On drop without explicit [`finalize`](Self::finalize), records a
/// failure — this covers deadline exits, panics, and any early-return
/// path after token acquisition.
pub(super) struct CircuitGuard<'a> {
    /// The registry that issued the token.
    registry: &'a CircuitBreakerRegistry,
    /// Logical peer identity the token was acquired for.
    peer: PeerKey,
    /// The generation token; `None` after finalization.
    token: Option<CircuitToken>,
}

impl<'a> CircuitGuard<'a> {
    /// Create a guard from an acquired token.
    pub(super) fn new(registry: &'a CircuitBreakerRegistry, peer: PeerKey, token: CircuitToken) -> Self {
        Self {
            registry,
            peer,
            token: Some(token),
        }
    }

    /// Finalize the guard as a success regardless of later body outcome.
    pub(super) fn finalize_success(mut self) {
        if let Some(token) = self.token.take() {
            self.registry.record_success(&self.peer, token);
        }
    }

    /// Finalize the guard with the actual exchange outcome.
    pub(super) fn finalize(mut self, result: &Result<SubResponse, SubRequestError>) {
        let Some(token) = self.token.take() else {
            return;
        };
        match result {
            Err(SubRequestError::Connect(_) | SubRequestError::Io(_) | SubRequestError::DeadlineExceeded) => {
                self.registry.record_failure(&self.peer, token);
            },
            Ok(_) | Err(_) => {
                self.registry.record_success(&self.peer, token);
            },
        }
    }
}

impl Drop for CircuitGuard<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.registry.record_failure(&self.peer, token);
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol-aware completion check
// ---------------------------------------------------------------------------

/// Protocol-aware clean completion check.
///
/// Returns `Ok(true)` for clean EOF, `Ok(false)` for incomplete,
/// and `Err` for H2 error-terminated streams.
pub(super) fn check_clean_completion(session: &mut HttpSession<()>) -> Result<bool, SubRequestError> {
    use pingora_core::protocols::http::custom::client::Session as _;
    match session {
        HttpSession::H1(h1) => Ok(h1.is_body_done()),
        HttpSession::H2(h2) => h2
            .check_response_end_or_error()
            .map_err(|e| SubRequestError::Io(e.to_string())),
        HttpSession::Custom(c) => Ok(c.response_finished()),
    }
}

/// Record metrics and trace for header-phase stream termination.
///
/// Used by `send_streaming()` when the response completes at header
/// time (HEAD, 204, 304, zero-length, or H2 error).
pub(super) fn record_header_termination(termination: &str) {
    counter!(SUBREQUEST_STREAMS_TOTAL, "termination" => termination.to_owned()).increment(1);
    histogram!(SUBREQUEST_STREAM_DURATION_SECONDS).record(0.0);
    debug!(termination, "sub-request: stream terminated at header phase");
}

// ---------------------------------------------------------------------------
// Header sanitization
// ---------------------------------------------------------------------------

/// Headers that apply only to one HTTP connection and must not be
/// forwarded across a sub-request boundary.
pub(super) const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove hop-by-hop headers and headers nominated by `Connection`.
pub(super) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_values: Vec<_> = headers.get_all(http::header::CONNECTION).iter().cloned().collect();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            headers.remove(token);
        }
    }
}

/// Remove request framing headers that the executor re-computes.
pub(super) fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Remove headers matching reserved internal prefixes (`x-praxis-*`,
/// `x-ext-protocol-*`, `x-ext-agent-*`).
pub(super) fn strip_reserved_headers(headers: &mut HeaderMap) {
    let reserved: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| crate::reserved_headers::is_reserved(name.as_str()))
        .cloned()
        .collect();
    for name in reserved {
        headers.remove(&name);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whether a header is a transport-level header that must not be
/// injected via framework metadata.
pub(super) fn is_transport_header(name: &http::header::HeaderName) -> bool {
    HOP_BY_HOP_HEADERS.iter().any(|h| *h == name.as_str()) || name == http::header::CONTENT_LENGTH
}

/// Methods whose empty payload is commonly rejected without explicit framing.
pub(super) fn empty_body_needs_framing(method: &http::Method) -> bool {
    matches!(*method, http::Method::POST | http::Method::PUT | http::Method::PATCH)
}

/// Ensure HTTP/1.1 virtual hosting and HTTP/2 `:authority` are valid.
pub(super) fn ensure_host_header(
    request: &mut pingora_http::RequestHeader,
    peer: &HttpPeer,
) -> Result<(), SubRequestError> {
    if !request.headers.contains_key(http::header::HOST) {
        request
            .insert_header(http::header::HOST, peer.address().to_string())
            .map_err(|error| SubRequestError::InvalidRequest(error.to_string()))?;
    }
    Ok(())
}

/// Clamp connect timeouts to the remaining overall deadline.
pub(super) fn clamp_peer_timeouts(peer: &mut HttpPeer, deadline: Duration) {
    peer.options.connection_timeout = Some(min_timeout(peer.options.connection_timeout, deadline));
    peer.options.total_connection_timeout = Some(min_timeout(peer.options.total_connection_timeout, deadline));
}

/// Keep an operator-configured timeout when it is stricter than the deadline.
pub(super) fn min_timeout(configured: Option<Duration>, deadline: Duration) -> Duration {
    configured.map_or(deadline, |configured| configured.min(deadline))
}

/// Classify a timeout expiry as either `DeadlineExceeded` (the overall
/// request deadline fired) or `Io` (a shorter operator-configured
/// read/write timeout fired).  Call this inside the `Err(_elapsed)`
/// arm of `tokio::time::timeout` to preserve the 502-vs-504 distinction.
pub(super) fn classify_timeout(deadline: tokio::time::Instant, phase: &str) -> SubRequestError {
    if tokio::time::Instant::now() >= deadline {
        SubRequestError::DeadlineExceeded
    } else {
        SubRequestError::Io(format!("upstream {phase} timeout"))
    }
}
