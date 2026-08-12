// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared HTTP connector and hardened sub-request executor.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use pingora_core::{
    connectors::{ConnectorOptions, http::Connector},
    upstreams::peer::{HttpPeer, Peer as _},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

use super::{
    internals::{
        clamp_peer_timeouts, empty_body_needs_framing, ensure_host_header, min_timeout, strip_hop_by_hop_headers,
        strip_request_framing_headers, strip_reserved_headers,
    },
    types::{FrameworkHeaders, SubRequest, SubRequestError, SubResponse},
};
use crate::circuit::{CircuitBreakerConfig, CircuitBreakerRegistry, CircuitCheck, CircuitToken, PeerKey};

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
    pub(super) max_response_bytes: usize,
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

    /// Evict idle circuit breaker entries that have been healthy for
    /// at least `idle_threshold`. Returns the number of entries
    /// removed, or `0` if no circuit breaker is configured.
    pub fn evict_idle_circuits(&self, idle_threshold: Duration) -> usize {
        self.connector
            .circuit_breakers
            .as_ref()
            .map_or(0, |registry| registry.evict_idle(idle_threshold))
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

        let peer_key: Option<PeerKey> = bounded_peer.address().as_inet().copied().map(|addr| {
            let sni = &bounded_peer.sni;
            PeerKey::new(addr, sni.as_str())
        });

        if let (Some(registry), Some(key)) = (&self.connector.circuit_breakers, &peer_key)
            && !registry.precheck(key)
        {
            return Err(SubRequestError::CircuitOpen { peer: key.to_string() });
        }

        let admission_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if admission_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let _permit = self.connector.try_acquire_permit(admission_budget).await?;

        let circuit_guard = match (&self.connector.circuit_breakers, peer_key) {
            (Some(registry), Some(key)) => match registry.try_acquire(key.clone()) {
                CircuitCheck::Rejected => {
                    return Err(SubRequestError::CircuitOpen { peer: key.to_string() });
                },
                CircuitCheck::Allowed(token) => Some(CircuitGuard::new(registry, key, token)),
            },
            _ => None,
        };

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let effective_limit = max_response_bytes.min(self.max_response_bytes);
        let result: Result<SubResponse, SubRequestError> = tokio::time::timeout(
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
        .unwrap_or_else(|_elapsed| Err(SubRequestError::DeadlineExceeded));

        if let Some(guard) = circuit_guard {
            guard.finalize(&result);
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

    /// Finalize the guard with the actual exchange outcome.
    ///
    /// Success and `ResponseTooLarge` are not peer faults; `Connect`,
    /// `Io`, and `DeadlineExceeded` are. Other variants (construction
    /// errors, admission timeout) record success (the peer responded,
    /// the fault is local).
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
