// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Sub-request types, hardened executor, and shared HTTP connector.
//!
//! Defines the `SubRequest` and `SubResponse` data types used by
//! sub-request exchanges, the `SubRequestConnector` that wraps a
//! Pingora `Connector` for connection pooling, and the
//! `SubRequestClient` that owns the shared connector and provides
//! a safe, bounded execution API.
//!
//! ```
//! use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
//!
//! let connector = SubRequestConnector::new(128, None);
//! let client = SubRequestClient::new(connector);
//! ```
//!
//! [`Connector`]: pingora_core::connectors::http::Connector

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use pingora_core::{
    connectors::{ConnectorOptions, http::Connector},
    upstreams::peer::{HttpPeer, Peer as _},
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

use crate::circuit::{CircuitBreakerConfig, CircuitBreakerRegistry, CircuitCheck, CircuitToken};

// ---------------------------------------------------------------------------
// SubRequest / SubResponse
// ---------------------------------------------------------------------------

/// An outbound HTTP request for a sub-request exchange.
#[derive(Clone, Debug)]
pub struct SubRequest {
    /// HTTP method.
    pub method: http::Method,

    /// Request URI (path + query).
    pub uri: http::Uri,

    /// Request headers.
    ///
    /// Reserved headers (`x-praxis-*`, `x-ext-*`) are stripped by the
    /// executor before dispatch. Use [`FrameworkHeaders`] on
    /// [`SubRequestClient::execute`] to inject metadata that must
    /// survive sanitisation.
    pub headers: HeaderMap,

    /// Request body.
    pub body: Bytes,
}

/// The response from a sub-request exchange.
#[derive(Clone, Debug)]
pub struct SubResponse {
    /// HTTP status code.
    pub status: u16,

    /// Response headers.
    pub headers: HeaderMap,

    /// Buffered response body.
    pub body: Bytes,
}

/// Reserved header for iterative-router loop prevention.
///
/// Uses the `x-praxis-*` reserved prefix so ingress rejects
/// client-spoofed values with 400. Injected by
/// [`FrameworkHeaders::set_depth`].
pub const DEPTH_HEADER: &str = "x-praxis-iterative-depth";

/// Framework metadata injected into sub-requests after sanitisation.
///
/// This typed struct replaces an open `HeaderMap` so that the executor
/// controls exactly which headers survive reserved-header stripping.
/// Each field maps to a specific header name chosen by the caller;
/// the executor validates that the name is neither transport-level
/// nor reserved before injection.
#[derive(Clone, Debug, Default)]
pub struct FrameworkHeaders {
    /// Validated (name, value) pairs to inject.
    entries: Vec<(http::header::HeaderName, http::HeaderValue)>,
}

impl FrameworkHeaders {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a header, returning `Err` if the name is transport-level
    /// or uses a reserved prefix (`x-praxis-*`, `x-ext-*`).
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError::InvalidRequest`] when the header
    /// name is forbidden.
    pub fn insert(&mut self, name: http::header::HeaderName, value: http::HeaderValue) -> Result<(), SubRequestError> {
        if is_transport_header(&name) {
            return Err(SubRequestError::InvalidRequest(format!(
                "transport header `{name}` cannot be injected as framework metadata"
            )));
        }
        if crate::reserved_headers::is_reserved(name.as_str()) {
            return Err(SubRequestError::InvalidRequest(format!(
                "reserved header `{name}` cannot be injected as framework metadata"
            )));
        }
        self.entries.push((name, value));
        Ok(())
    }

    /// Set the iterative-router depth header.
    ///
    /// This is the only way to inject the reserved
    /// `x-praxis-iterative-depth` header. The value is
    /// formatted from `depth` and inserted unconditionally.
    pub fn set_depth(&mut self, depth: u8) {
        let value = http::HeaderValue::from(u16::from(depth));
        self.entries
            .push((http::header::HeaderName::from_static(DEPTH_HEADER), value));
    }

    /// Iterate over the validated entries.
    pub fn iter(&self) -> impl Iterator<Item = &(http::header::HeaderName, http::HeaderValue)> {
        self.entries.iter()
    }

    /// Whether no entries have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SubRequestError
// ---------------------------------------------------------------------------

/// Errors from sub-request execution.
///
/// Typed so callers can map transport failures to appropriate HTTP
/// status codes without inspecting error strings.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SubRequestError {
    /// Failed to construct a valid request (bad headers, URI, etc.).
    #[error("sub-request construction error: {0}")]
    InvalidRequest(String),

    /// The concurrency admission semaphore timed out before a slot
    /// became available.
    #[error("sub-request admission timeout (all {max_connections} slots busy)")]
    AdmissionTimeout {
        /// Configured concurrency limit.
        max_connections: usize,
    },

    /// Failed to connect to the upstream.
    #[error("sub-request connect error: {0}")]
    Connect(String),

    /// Failed to write the request or read the response.
    #[error("sub-request I/O error: {0}")]
    Io(String),

    /// The overall deadline expired.
    #[error("sub-request deadline exceeded")]
    DeadlineExceeded,

    /// The circuit breaker for the target peer is open.
    #[error("sub-request circuit open for peer {peer}")]
    CircuitOpen {
        /// Peer address whose circuit is open.
        peer: String,
    },

    /// Response body exceeded the size limit.
    #[error(
        "sub-request response body exceeded limit \
         ({actual} > {limit} bytes)"
    )]
    ResponseTooLarge {
        /// Actual bytes received before truncation.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
}

// ---------------------------------------------------------------------------
// SubRequestConnector
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
    inner: Arc<Connector<()>>,

    /// Admission semaphore bounding concurrently active exchanges.
    admission: Option<Arc<Semaphore>>,

    /// The configured concurrency limit, retained for error reporting.
    configured_max_connections: Option<usize>,

    /// Per-peer circuit breaker registry.
    circuit_breakers: Option<Arc<CircuitBreakerRegistry>>,
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
// SubRequestClient
// ---------------------------------------------------------------------------

/// Hardened sub-request executor wrapping a shared connector.
///
/// Provides a safe, bounded execution API that enforces:
///
/// - An overall deadline covering admission, connect, and I/O.
/// - Bounded response body reads: each call supplies a per-call limit, clamped to the client-wide ceiling set at
///   construction via [`with_max_response_bytes`]. The server derives this ceiling from
///   `body_limits.max_response_bytes`.
/// - Hop-by-hop header sanitization on both request and response.
/// - Proper `Host` framing.
///
/// [`with_max_response_bytes`]: Self::with_max_response_bytes
///
/// Callers own routing, retries, circuit breaking, SSRF policy,
/// depth propagation, and status interpretation.
///
/// Responses are fully buffered. Streaming is not supported by
/// this API.
///
/// ```
/// use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
///
/// let connector = SubRequestConnector::new(128, None);
/// let client = SubRequestClient::new(connector);
/// ```
#[derive(Clone, Debug)]
pub struct SubRequestClient {
    /// Wrapped shared connector.
    connector: SubRequestConnector,

    /// Hard ceiling on buffered response bytes. Per-call limits are
    /// clamped to `min(this, per_call)` so callers cannot exceed it.
    max_response_bytes: usize,
}

impl SubRequestClient {
    /// Create a client wrapping the given shared connector.
    ///
    /// Defaults the client-wide response ceiling to
    /// [`ABSOLUTE_MAX_BODY_BYTES`] (64 MiB). Use
    /// [`with_max_response_bytes`] for a tighter cap.
    ///
    /// [`ABSOLUTE_MAX_BODY_BYTES`]: crate::config::ABSOLUTE_MAX_BODY_BYTES
    /// [`with_max_response_bytes`]: Self::with_max_response_bytes
    pub fn new(connector: SubRequestConnector) -> Self {
        Self {
            connector,
            max_response_bytes: crate::config::ABSOLUTE_MAX_BODY_BYTES,
        }
    }

    /// Create a client with an explicit response ceiling.
    ///
    /// Every `execute()` call clamps its per-call limit to
    /// `min(per_call, ceiling)`, preventing callers from
    /// exceeding the global cap.
    pub fn with_max_response_bytes(connector: SubRequestConnector, max_response_bytes: usize) -> Self {
        Self {
            connector,
            max_response_bytes,
        }
    }

    /// Access the underlying connector for direct pool operations.
    pub fn connector(&self) -> &SubRequestConnector {
        &self.connector
    }

    /// Execute a buffered sub-request.
    ///
    /// Acquires an admission permit (inside the deadline), connects
    /// to `peer`, sends `request`, reads the full response (bounded
    /// by `max_response_bytes`), and returns a [`SubResponse`].
    ///
    /// Transport-level headers (hop-by-hop, `Connection`-nominated)
    /// and reserved internal headers (`x-praxis-*`, `x-ext-*`) are
    /// stripped from both request and response.
    ///
    /// `framework_headers` are injected **after** all sanitisation
    /// passes. The [`FrameworkHeaders`] type validates at insertion
    /// time that no transport-level or reserved internal header
    /// (`x-praxis-*`, `x-ext-*`) can be added, so callers cannot
    /// reintroduce sanitised headers.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError`] on admission timeout, connection
    /// failure, I/O error, response body exceeding the size limit,
    /// or deadline expiry.
    #[expect(
        clippy::too_many_arguments,
        reason = "framework_headers is the typed metadata injection point"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "circuit + admission + deadline logic is sequential"
    )]
    pub async fn execute(
        &self,
        peer: &HttpPeer,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, SubRequestError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut bounded_peer = peer.clone();
        clamp_peer_timeouts(&mut bounded_peer, timeout);

        // Extract a std::net::SocketAddr for circuit breaker keying.
        // Unix sockets map to 0.0.0.0:0 (they are not peer-faultable).
        let peer_addr: SocketAddr = bounded_peer
            .address()
            .as_inet()
            .copied()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        // Circuit precheck: fast-fail before consuming an admission slot.
        if let Some(registry) = &self.connector.circuit_breakers
            && !registry.precheck(peer_addr)
        {
            return Err(SubRequestError::CircuitOpen {
                peer: peer_addr.to_string(),
            });
        }

        let admission_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if admission_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let _permit = self.connector.try_acquire_permit(admission_budget).await?;

        // Circuit try_acquire: get a generation token after admission.
        let circuit_token = self
            .connector
            .circuit_breakers
            .as_ref()
            .map(|registry| registry.try_acquire(peer_addr));

        // If the circuit rejected between precheck and acquire, fail.
        if let Some(CircuitCheck::Rejected) = &circuit_token {
            return Err(SubRequestError::CircuitOpen {
                peer: peer_addr.to_string(),
            });
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let effective_limit = max_response_bytes.min(self.max_response_bytes);
        let result = tokio::time::timeout(
            remaining,
            Box::pin(execute_inner(
                &self.connector,
                &bounded_peer,
                request,
                effective_limit,
                remaining,
                framework_headers,
            )),
        )
        .await
        .map_err(|_elapsed| SubRequestError::DeadlineExceeded)?;

        // Record outcome on the circuit breaker token.
        if let Some(registry) = &self.connector.circuit_breakers
            && let Some(CircuitCheck::Allowed(token)) = circuit_token
        {
            record_circuit_outcome(registry, peer_addr, token, &result);
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Executor internals
// ---------------------------------------------------------------------------

/// Execute the exchange under the deadline enforced by
/// [`SubRequestClient::execute`].
#[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
#[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
#[expect(clippy::too_many_arguments, reason = "internal function, all parameters required")]
async fn execute_inner(
    connector: &SubRequestConnector,
    peer: &HttpPeer,
    request: &SubRequest,
    max_response_bytes: usize,
    timeout: Duration,
    framework_headers: Option<&FrameworkHeaders>,
) -> Result<SubResponse, SubRequestError> {
    let (mut session, reused) = Box::pin(connector.connector().get_http_session(peer))
        .await
        .map_err(|e| SubRequestError::Connect(e.to_string()))?;

    debug!(
        peer = %peer.address(),
        reused,
        method = %request.method,
        uri = %request.uri,
        "sub-request: connected"
    );

    session.set_read_timeout(Some(min_timeout(peer.options.read_timeout, timeout)));
    session.set_write_timeout(Some(min_timeout(peer.options.write_timeout, timeout)));

    let path = request
        .uri
        .path_and_query()
        .map_or(b"/".as_slice(), |pq| pq.as_str().as_bytes());
    let mut req_header = pingora_http::RequestHeader::build(request.method.clone(), path, None)
        .map_err(|e| SubRequestError::InvalidRequest(e.to_string()))?;

    let mut sanitized = request.headers.clone();
    strip_hop_by_hop_headers(&mut sanitized);
    strip_request_framing_headers(&mut sanitized);
    strip_reserved_headers(&mut sanitized);
    if let Some(fw) = framework_headers {
        for (name, value) in fw.iter() {
            sanitized.insert(name.clone(), value.clone());
        }
    }

    for (name, value) in &sanitized {
        let _append = req_header.append_header(name.clone(), value.clone());
    }

    ensure_host_header(&mut req_header, peer)?;

    if !request.body.is_empty() || empty_body_needs_framing(&request.method) {
        let _cl = req_header.insert_header("Content-Length", request.body.len().to_string());
    }

    session
        .write_request_header(Box::new(req_header))
        .await
        .map_err(|e| SubRequestError::Io(e.to_string()))?;

    if !request.body.is_empty() {
        session
            .write_request_body(request.body.clone(), true)
            .await
            .map_err(|e| SubRequestError::Io(e.to_string()))?;
    }

    session
        .finish_request_body()
        .await
        .map_err(|e| SubRequestError::Io(e.to_string()))?;

    session
        .read_response_header()
        .await
        .map_err(|e| SubRequestError::Io(e.to_string()))?;

    let resp_header = session
        .response_header()
        .ok_or_else(|| SubRequestError::Io("no response header received".to_owned()))?;

    let status = resp_header.status.as_u16();
    if !(100..=599).contains(&status) {
        session.shutdown().await;
        return Err(SubRequestError::Io(format!(
            "upstream returned unsupported HTTP status {status}"
        )));
    }
    let mut resp_headers = HeaderMap::new();
    for (name, value) in &resp_header.headers {
        if let Ok(v) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
            resp_headers.append(name.clone(), v);
        }
    }
    strip_hop_by_hop_headers(&mut resp_headers);
    strip_reserved_headers(&mut resp_headers);

    let mut body_buf = Vec::new();
    while !session.response_done() {
        match session.read_response_body().await {
            Ok(Some(chunk)) => {
                if body_buf.len() + chunk.len() > max_response_bytes {
                    warn!(
                        current = body_buf.len(),
                        chunk = chunk.len(),
                        limit = max_response_bytes,
                        "sub-request response body exceeded limit"
                    );
                    session.shutdown().await;
                    return Err(SubRequestError::ResponseTooLarge {
                        actual: body_buf.len() + chunk.len(),
                        limit: max_response_bytes,
                    });
                }
                body_buf.extend_from_slice(&chunk);
            },
            Ok(None) => break,
            Err(e) => {
                session.shutdown().await;
                return Err(SubRequestError::Io(e.to_string()));
            },
        }
    }

    debug!(status, body_bytes = body_buf.len(), "sub-request: response received");

    connector.connector().release_http_session(session, peer, None).await;

    Ok(SubResponse {
        status,
        headers: resp_headers,
        body: Bytes::from(body_buf),
    })
}

// ---------------------------------------------------------------------------
// Circuit Breaker Outcome
// ---------------------------------------------------------------------------

/// Record the outcome of a sub-request exchange on the circuit breaker.
///
/// Success and `ResponseTooLarge` are not peer faults; `Connect`, `Io`,
/// and `DeadlineExceeded` are. Other variants (construction errors,
/// admission timeout) drop the token silently.
fn record_circuit_outcome(
    registry: &CircuitBreakerRegistry,
    peer: SocketAddr,
    token: CircuitToken,
    result: &Result<SubResponse, SubRequestError>,
) {
    match result {
        Ok(_) | Err(SubRequestError::ResponseTooLarge { .. }) => {
            registry.record_success(peer, token);
        },
        Err(SubRequestError::Connect(_) | SubRequestError::Io(_) | SubRequestError::DeadlineExceeded) => {
            registry.record_failure(peer, token);
        },
        // Construction errors, admission timeout, circuit open:
        // not peer faults — drop token (no-op).
        Err(_) => {},
    }
}

// ---------------------------------------------------------------------------
// Header sanitization
// ---------------------------------------------------------------------------

/// Headers that apply only to one HTTP connection and must not be
/// forwarded across a sub-request boundary.
const HOP_BY_HOP_HEADERS: &[&str] = &[
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
fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
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
fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Remove headers matching reserved internal prefixes (`x-praxis-*`,
/// `x-ext-protocol-*`, `x-ext-agent-*`).
fn strip_reserved_headers(headers: &mut HeaderMap) {
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
fn is_transport_header(name: &http::header::HeaderName) -> bool {
    HOP_BY_HOP_HEADERS.iter().any(|h| *h == name.as_str()) || name == http::header::CONTENT_LENGTH
}

/// Methods whose empty payload is commonly rejected without explicit framing.
fn empty_body_needs_framing(method: &http::Method) -> bool {
    matches!(*method, http::Method::POST | http::Method::PUT | http::Method::PATCH)
}

/// Ensure HTTP/1.1 virtual hosting and HTTP/2 `:authority` are valid.
fn ensure_host_header(request: &mut pingora_http::RequestHeader, peer: &HttpPeer) -> Result<(), SubRequestError> {
    if !request.headers.contains_key(http::header::HOST) {
        request
            .insert_header(http::header::HOST, peer.address().to_string())
            .map_err(|error| SubRequestError::InvalidRequest(error.to_string()))?;
    }
    Ok(())
}

/// Clamp connect timeouts to the remaining overall deadline.
fn clamp_peer_timeouts(peer: &mut HttpPeer, deadline: Duration) {
    peer.options.connection_timeout = Some(min_timeout(peer.options.connection_timeout, deadline));
    peer.options.total_connection_timeout = Some(min_timeout(peer.options.total_connection_timeout, deadline));
}

/// Keep an operator-configured timeout when it is stricter than the deadline.
fn min_timeout(configured: Option<Duration>, deadline: Duration) -> Duration {
    configured.map_or(deadline, |configured| configured.min(deadline))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    // -- SubRequestConnector ------------------------------------------------

    #[test]
    fn clone_shares_same_arc() {
        let a = SubRequestConnector::new(16, None);
        let b = a.clone();
        assert!(
            Arc::ptr_eq(&a.inner, &b.inner),
            "cloned connectors should share the same Arc"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let connector = SubRequestConnector::new(8, None);
        let debug = format!("{connector:?}");
        assert!(
            debug.contains("SubRequestConnector"),
            "debug output should contain type name"
        );
    }

    #[test]
    fn unbounded_connector_has_no_admission() {
        let connector = SubRequestConnector::new(8, None);
        assert!(
            connector.admission.is_none(),
            "no max_connections should mean no semaphore"
        );
    }

    #[test]
    fn bounded_connector_has_admission_semaphore() {
        let connector = SubRequestConnector::new(8, Some(16));
        let semaphore = connector
            .admission
            .as_ref()
            .expect("max_connections should create semaphore");
        assert_eq!(
            semaphore.available_permits(),
            16,
            "semaphore should have the configured permits"
        );
    }

    #[tokio::test]
    async fn acquire_permit_returns_none_without_limit() {
        let connector = SubRequestConnector::new(4, None);
        assert!(
            connector.acquire_permit().await.is_none(),
            "unbounded connector should return None"
        );
    }

    #[tokio::test]
    async fn acquire_permit_returns_some_with_limit() {
        let connector = SubRequestConnector::new(4, Some(2));
        assert!(
            connector.acquire_permit().await.is_some(),
            "bounded connector should return a permit"
        );
    }

    #[tokio::test]
    async fn dropping_permit_restores_capacity() {
        let connector = SubRequestConnector::new(4, Some(1));
        let permit = connector.acquire_permit().await.unwrap();
        assert_eq!(
            connector.admission.as_ref().unwrap().available_permits(),
            0,
            "all permits should be taken"
        );
        drop(permit);
        assert_eq!(
            connector.admission.as_ref().unwrap().available_permits(),
            1,
            "dropping permit should restore capacity"
        );
    }

    #[test]
    fn clone_shares_admission_semaphore() {
        let a = SubRequestConnector::new(4, Some(8));
        let b = a.clone();
        assert!(
            Arc::ptr_eq(a.admission.as_ref().unwrap(), b.admission.as_ref().unwrap()),
            "cloned connectors should share the semaphore"
        );
    }

    // -- SubRequest / SubResponse -------------------------------------------

    #[test]
    fn subrequest_clone_preserves_fields() {
        let req = SubRequest {
            method: http::Method::POST,
            uri: "/v1/chat".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"hello"),
        };
        let cloned = req.clone();
        assert_eq!(cloned.method, http::Method::POST);
        assert_eq!(cloned.body, Bytes::from_static(b"hello"));
    }

    #[test]
    fn subresponse_clone_preserves_fields() {
        let resp = SubResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"world"),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.status, 200);
        assert_eq!(cloned.body, Bytes::from_static(b"world"));
    }

    // -- SubRequestClient ---------------------------------------------------

    #[test]
    fn client_wraps_connector() {
        let connector = SubRequestConnector::new(8, None);
        let client = SubRequestClient::new(connector);
        let debug = format!("{client:?}");
        assert!(
            debug.contains("SubRequestClient"),
            "debug output should contain type name"
        );
    }

    #[test]
    fn client_clone_shares_connector() {
        let connector = SubRequestConnector::new(8, Some(4));
        let a = SubRequestClient::new(connector);
        let b = a.clone();
        assert!(
            Arc::ptr_eq(&a.connector.inner, &b.connector.inner,),
            "cloned clients should share the same connector"
        );
    }

    // -- SubRequestError ----------------------------------------------------

    #[test]
    fn subrequest_error_invalid_request_display() {
        let err = SubRequestError::InvalidRequest("bad header".to_owned());
        assert!(
            err.to_string().contains("bad header"),
            "InvalidRequest error should include reason: {err}"
        );
    }

    #[test]
    fn subrequest_error_admission_timeout_display() {
        let err = SubRequestError::AdmissionTimeout { max_connections: 64 };
        let msg = err.to_string();
        assert!(msg.contains("64"), "should include max_connections: {msg}");
        assert!(msg.contains("admission"), "should mention admission: {msg}");
    }

    #[test]
    fn subrequest_error_connect_display() {
        let err = SubRequestError::Connect("connection refused".to_owned());
        assert!(
            err.to_string().contains("connection refused"),
            "Connect error should include reason: {err}"
        );
    }

    #[test]
    fn subrequest_error_io_display() {
        let err = SubRequestError::Io("broken pipe".to_owned());
        assert!(
            err.to_string().contains("broken pipe"),
            "Io error should include reason: {err}"
        );
    }

    #[test]
    fn subrequest_error_response_too_large_display() {
        let err = SubRequestError::ResponseTooLarge {
            actual: 20_000,
            limit: 10_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("20000"), "should include actual: {msg}");
        assert!(msg.contains("10000"), "should include limit: {msg}");
    }

    #[test]
    fn subrequest_error_deadline_exceeded_display() {
        let err = SubRequestError::DeadlineExceeded;
        assert!(
            !err.to_string().is_empty(),
            "DeadlineExceeded should have a display message"
        );
    }

    // -- Header sanitization ------------------------------------------------

    #[test]
    fn strip_hop_by_hop_removes_static_and_connection_nominated() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "x-custom, keep-alive".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());
        headers.insert("x-safe", "kept".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-custom"));
        assert!(!headers.contains_key("transfer-encoding"));
        assert_eq!(headers.get("x-safe").unwrap(), "kept");
    }

    #[test]
    fn strip_request_framing_removes_content_length_and_transfer_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "42".parse().unwrap());
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert("x-safe", "kept".parse().unwrap());

        strip_request_framing_headers(&mut headers);

        assert!(!headers.contains_key(http::header::CONTENT_LENGTH));
        assert!(!headers.contains_key(http::header::TRANSFER_ENCODING));
        assert_eq!(headers.get("x-safe").unwrap(), "kept");
    }

    // -- Helpers ------------------------------------------------------------

    #[test]
    fn empty_entity_methods_get_explicit_framing() {
        assert!(empty_body_needs_framing(&http::Method::POST));
        assert!(empty_body_needs_framing(&http::Method::PUT));
        assert!(empty_body_needs_framing(&http::Method::PATCH));
        assert!(!empty_body_needs_framing(&http::Method::GET));
        assert!(!empty_body_needs_framing(&http::Method::HEAD));
    }

    #[test]
    fn min_timeout_preserves_stricter_cluster_limit() {
        assert_eq!(
            min_timeout(Some(Duration::from_secs(1)), Duration::from_secs(10)),
            Duration::from_secs(1)
        );
        assert_eq!(
            min_timeout(Some(Duration::from_secs(20)), Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(min_timeout(None, Duration::from_secs(10)), Duration::from_secs(10));
    }

    #[test]
    fn clamp_peer_timeouts_bounds_connection_setup() {
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(1));
        peer.options.total_connection_timeout = Some(Duration::from_secs(20));

        clamp_peer_timeouts(&mut peer, Duration::from_secs(10));

        assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(1)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(10)));
    }

    #[test]
    fn ensure_host_header_uses_peer_address_without_overwriting_explicit_host() {
        let peer = HttpPeer::new("127.0.0.1:8443", false, String::new());
        let mut generated = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        ensure_host_header(&mut generated, &peer).unwrap();
        assert_eq!(generated.headers.get(http::header::HOST).unwrap(), "127.0.0.1:8443");

        let mut explicit = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        explicit.insert_header(http::header::HOST, "model.example").unwrap();
        ensure_host_header(&mut explicit, &peer).unwrap();
        assert_eq!(explicit.headers.get(http::header::HOST).unwrap(), "model.example");
    }

    // -- Integration-style tests --------------------------------------------

    #[tokio::test]
    async fn deadline_bounds_the_complete_exchange() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let connector = SubRequestConnector::new(1, None);
        let client = SubRequestClient::new(connector);
        let peer = HttpPeer::new(address.to_string(), false, String::new());
        let request = SubRequest {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };

        let started = std::time::Instant::now();
        let result = Box::pin(client.execute(&peer, &request, 1024, Duration::from_millis(10), None)).await;
        let elapsed = started.elapsed();
        backend.abort();

        assert!(result.is_err(), "a backend that never responds must time out");
        assert!(
            elapsed < Duration::from_millis(500),
            "exchange exceeded its deadline: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn admission_timeout_returns_typed_error() {
        let connector = SubRequestConnector::new(4, Some(1));
        let permit = connector.acquire_permit().await.unwrap();

        let result = connector.try_acquire_permit(Duration::from_millis(10)).await;

        assert!(
            matches!(result, Err(SubRequestError::AdmissionTimeout { .. })),
            "should return AdmissionTimeout when slots are full: {result:?}"
        );
        drop(result);
        drop(permit);
    }

    #[tokio::test]
    async fn admission_timeout_reports_configured_max() {
        let configured_limit = 4;
        let connector = SubRequestConnector::new(4, Some(configured_limit));
        let mut permits = Vec::new();
        for _ in 0..configured_limit {
            permits.push(connector.acquire_permit().await.unwrap());
        }

        let result = connector.try_acquire_permit(Duration::from_millis(10)).await;
        match &result {
            Err(SubRequestError::AdmissionTimeout { max_connections }) => {
                assert_eq!(
                    *max_connections, configured_limit,
                    "should report configured limit, not available permits"
                );
            },
            other => panic!("expected AdmissionTimeout, got: {other:?}"),
        }
        drop(result);
        drop(permits);
    }

    #[tokio::test]
    async fn try_acquire_permit_returns_none_without_limit() {
        let connector = SubRequestConnector::new(4, None);
        let result = connector.try_acquire_permit(Duration::from_millis(10)).await;
        assert!(
            matches!(result, Ok(None)),
            "unbounded connector should return Ok(None): {result:?}"
        );
        drop(result);
    }

    // -- Client ceiling -------------------------------------------------------

    #[test]
    fn client_with_custom_ceiling() {
        let connector = SubRequestConnector::new(8, None);
        let client = SubRequestClient::with_max_response_bytes(connector, 4096);
        assert_eq!(client.max_response_bytes, 4096);
    }

    #[test]
    fn client_default_ceiling_is_absolute_max() {
        let connector = SubRequestConnector::new(8, None);
        let client = SubRequestClient::new(connector);
        assert_eq!(
            client.max_response_bytes,
            crate::config::ABSOLUTE_MAX_BODY_BYTES,
            "default ceiling should be ABSOLUTE_MAX_BODY_BYTES (64 MiB)"
        );
    }

    // -- Response header sanitization -----------------------------------------

    #[test]
    fn response_hop_by_hop_headers_are_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "x-nominated".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-nominated", "internal".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("transfer-encoding"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-nominated"));
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }

    // -- Reserved header sanitization ------------------------------------------

    #[test]
    fn strip_reserved_removes_internal_prefixes() {
        let mut headers = HeaderMap::new();
        headers.insert("x-praxis-route", "internal".parse().unwrap());
        headers.insert("x-ext-protocol-model", "gpt-4".parse().unwrap());
        headers.insert("x-ext-agent-task", "classify".parse().unwrap());
        headers.insert("x-custom", "kept".parse().unwrap());
        headers.insert("authorization", "Bearer tok".parse().unwrap());

        strip_reserved_headers(&mut headers);

        assert!(!headers.contains_key("x-praxis-route"));
        assert!(!headers.contains_key("x-ext-protocol-model"));
        assert!(!headers.contains_key("x-ext-agent-task"));
        assert_eq!(headers.get("x-custom").unwrap(), "kept");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer tok");
    }

    #[test]
    fn strip_reserved_is_no_op_for_safe_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-request-id", "abc".parse().unwrap());

        strip_reserved_headers(&mut headers);

        assert_eq!(headers.len(), 2);
    }

    // -- Connector configured_max_connections ---------------------------------

    #[test]
    fn connector_stores_configured_max_connections() {
        let connector = SubRequestConnector::new(4, Some(256));
        assert_eq!(connector.configured_max_connections, Some(256));

        let unbounded = SubRequestConnector::new(4, None);
        assert_eq!(unbounded.configured_max_connections, None);
    }

    // -- SubRequestConnectorOptions -----------------------------------------------

    #[test]
    fn with_options_creates_connector() {
        let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
            keepalive_pool_size: 32,
            max_connections: Some(64),
            circuit_breaker: None,
        });
        assert_eq!(
            connector.configured_max_connections,
            Some(64),
            "max_connections should be forwarded"
        );
        assert!(
            connector.circuit_breakers.is_none(),
            "no circuit breaker config should mean no registry"
        );
    }

    #[test]
    fn with_options_circuit_breaker_enabled() {
        let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
            keepalive_pool_size: 16,
            max_connections: None,
            circuit_breaker: Some(CircuitBreakerConfig {
                threshold: 3,
                recovery_window: Duration::from_secs(30),
                half_open_timeout: Duration::from_secs(30),
            }),
        });
        assert!(
            connector.circuit_breakers.is_some(),
            "circuit breaker config should create a registry"
        );
    }

    // -- SubRequestError (CircuitOpen) ------------------------------------------

    #[test]
    fn subrequest_error_circuit_open_display() {
        let err = SubRequestError::CircuitOpen {
            peer: "127.0.0.1:8080".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("circuit open"), "should mention circuit open: {msg}");
        assert!(msg.contains("127.0.0.1:8080"), "should include peer address: {msg}");
    }

    // -- Framework headers ------------------------------------------------------

    #[test]
    fn is_transport_header_rejects_hop_by_hop_and_framing() {
        let transport_names = [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ];
        for name in transport_names {
            let hdr: http::header::HeaderName = name.parse().unwrap();
            assert!(is_transport_header(&hdr), "{name} should be classified as transport");
        }

        let safe_names = ["authorization", "x-request-id", "x-custom-header"];
        for name in safe_names {
            let hdr: http::header::HeaderName = name.parse().unwrap();
            assert!(
                !is_transport_header(&hdr),
                "{name} should not be classified as transport"
            );
        }
    }

    #[test]
    fn framework_headers_rejects_transport_headers() {
        let mut fw = FrameworkHeaders::new();
        let val = http::HeaderValue::from_static("1");
        let result = fw.insert(http::header::CONTENT_LENGTH, val);
        assert!(result.is_err(), "transport header should be rejected");
        assert!(fw.is_empty());
    }

    #[test]
    fn framework_headers_rejects_reserved_headers() {
        let mut fw = FrameworkHeaders::new();
        let val = http::HeaderValue::from_static("1");
        let name: http::header::HeaderName = "x-praxis-depth".parse().unwrap();
        let result = fw.insert(name, val);
        assert!(result.is_err(), "reserved header should be rejected");
        assert!(fw.is_empty());
    }

    #[test]
    fn framework_headers_accepts_non_reserved_non_transport() {
        let mut fw = FrameworkHeaders::new();
        let val = http::HeaderValue::from_static("3");
        let name: http::header::HeaderName = "x-request-id".parse().unwrap();
        fw.insert(name, val).unwrap();
        assert!(!fw.is_empty());
        assert_eq!(fw.iter().count(), 1);
    }

    #[test]
    fn framework_headers_set_depth_injects_reserved_header() {
        let mut fw = FrameworkHeaders::new();
        fw.set_depth(2);
        assert_eq!(fw.iter().count(), 1);
        let (name, value) = fw.iter().next().unwrap();
        assert_eq!(name.as_str(), DEPTH_HEADER);
        assert_eq!(value, "2");
    }

    #[test]
    fn framework_headers_set_depth_zero() {
        let mut fw = FrameworkHeaders::new();
        fw.set_depth(0);
        let (_, value) = fw.iter().next().unwrap();
        assert_eq!(value, "0");
    }
}
