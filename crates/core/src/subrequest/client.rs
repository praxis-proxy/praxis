// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hardened sub-request client executor.
//!
//! [`SubRequestClient`] wraps a shared connector to provide safe,
//! bounded execution of outbound HTTP exchanges with deadline
//! enforcement, response body size limits, and automatic hop-by-hop
//! header sanitization. Supports both buffered (collect full body)
//! and streaming (chunk-by-chunk) response modes.
//!
//! The client is generic over the build's egress [`Connector`]: it speaks
//! only [`PeerSpec`] and the [`Session`] contract, so it runs unchanged on
//! any network backend.
//!
//! [`Connector`]: crate::egress::Connector
//! [`PeerSpec`]: crate::egress::PeerSpec
//! [`Session`]: crate::egress::Session

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use metrics::histogram;
use praxis_tls::CachedCaCerts;
use tracing::{Instrument as _, Span, debug, warn};

use super::{
    internals::{
        CircuitGuard, RawExchange, SUBREQUEST_HEADER_DURATION_SECONDS, SubRequestConnector, classify_timeout,
        connection_nominated_tokens, empty_body_needs_framing, ensure_host_header, is_boundary_stripped,
        is_request_stripped, min_timeout, record_header_termination, transport_error,
    },
    types::{
        FrameworkHeaders, StreamLimits, StreamingSubResponse, SubRequest, SubRequestError, SubResponse,
        SubResponseBody, UrlSubRequestError,
    },
};
use crate::{
    backend,
    circuit::CircuitCheck,
    connectivity::{UrlResolutionPolicy, UrlTargetError, prepare_url_target_with_policy},
    egress::{Completion, Connector, PeerSpec, RequestHead, Session as _},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of 1xx interim responses tolerated before a final
/// response, bounding a pathological upstream that only emits interim
/// headers (the overall deadline is the other bound).
const MAX_INTERIM_RESPONSES: u32 = 32;

/// Eager buffer capacity cap for buffered response bodies.
///
/// Content-Length pre-sizes the collection buffer, but the header is
/// untrusted: an upstream advertising a huge length while sending
/// little must not pin limit-sized buffers per in-flight exchange.
/// Doubling growth covers honest bodies past this cap.
const EAGER_BODY_CAPACITY: usize = 131_072; // 128 KiB

/// Maximum addresses dialed for a client-selected URL target.
///
/// A [`UrlResolutionPolicy::ClientPerCall`] address set comes from
/// client-controlled DNS, which may return an arbitrarily long answer. The
/// validation hook still inspects the complete set (in preparation), but
/// fallback dials at most this many of them so a hostile answer cannot fan a
/// single call out across unbounded connection attempts. Operator-configured
/// targets ([`UrlResolutionPolicy::OperatorCached`]) are not capped.
const MAX_CLIENT_SELECTED_DIALS: usize = 4;

// -----------------------------------------------------------------------------
// SubRequestClient
// -----------------------------------------------------------------------------

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
/// Supports both buffered ([`execute()`](Self::execute)) and streaming
/// ([`send_streaming()`](Self::send_streaming)) response modes.
///
/// ```
/// use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
/// praxis_tls::provider::install(); // required before any connector is built
///
/// let connector = SubRequestConnector::new(128, None);
/// let client = SubRequestClient::new(connector);
/// ```
#[derive(Clone, Debug)]
pub struct SubRequestClient<C: Connector = backend::Connector> {
    /// Wrapped shared connector.
    connector: SubRequestConnector<C>,

    /// Hard ceiling on buffered response bytes. Per-call limits are
    /// clamped to `min(this, per_call)` so callers cannot exceed it.
    pub(super) max_response_bytes: usize,

    /// Trust anchors from `runtime.upstream_ca_file`, when one is configured.
    upstream_ca: Option<Arc<CachedCaCerts>>,
}

impl<C: Connector> SubRequestClient<C> {
    /// Create a client wrapping the given shared connector.
    ///
    /// Defaults the client-wide response ceiling to
    /// [`ABSOLUTE_MAX_BODY_BYTES`] (64 MiB). Use
    /// [`with_max_response_bytes`] for a tighter cap.
    ///
    /// [`ABSOLUTE_MAX_BODY_BYTES`]: crate::config::ABSOLUTE_MAX_BODY_BYTES
    /// [`with_max_response_bytes`]: Self::with_max_response_bytes
    pub fn new(connector: SubRequestConnector<C>) -> Self {
        Self {
            connector,
            max_response_bytes: crate::config::ABSOLUTE_MAX_BODY_BYTES,
            upstream_ca: None,
        }
    }

    /// Create a client with an explicit response ceiling.
    ///
    /// Every `execute()` call clamps its per-call limit to
    /// `min(per_call, ceiling)`, preventing callers from
    /// exceeding the global cap.
    pub fn with_max_response_bytes(connector: SubRequestConnector<C>, max_response_bytes: usize) -> Self {
        Self {
            connector,
            max_response_bytes,
            upstream_ca: None,
        }
    }

    /// Trust `ca` when a cluster does not set its own CA.
    #[must_use]
    pub fn with_upstream_ca(mut self, ca: Arc<CachedCaCerts>) -> Self {
        self.upstream_ca = Some(ca);
        self
    }

    /// Runtime CA bundle, when `runtime.upstream_ca_file` was loaded.
    #[must_use]
    pub fn upstream_ca(&self) -> Option<Arc<CachedCaCerts>> {
        self.upstream_ca.as_ref().map(Arc::clone)
    }

    /// Execute a buffered request against an absolute HTTP(S) URL.
    ///
    /// The explicit `policy` selects cached DNS for operator-configured hosts
    /// or a fresh per-call lookup for client-selected hosts. The `validate`
    /// hook sees the complete normalized address set before any connection.
    /// The URL authority replaces the request's `Host` and supplies TLS SNI.
    /// The original request body is reused across address attempts. Another
    /// address is tried after a connection failure or when a peer's circuit is
    /// already open, before any request is sent to that peer.
    ///
    /// `timeout` is one overall budget for DNS, fallback attempts, and response
    /// collection. Every dial but the last gets an equal share of the remaining
    /// budget for its connect phase, so one unresponsive address cannot consume
    /// the whole deadline before fallback; request and response I/O still use the
    /// overall deadline. A [`UrlResolutionPolicy::ClientPerCall`] target dials at
    /// most `MAX_CLIENT_SELECTED_DIALS` of its client-controlled addresses, even
    /// though `validate` still inspects the complete set.
    /// `max_response_bytes` is also capped by this client's ceiling.
    /// For incremental response bodies, use policy-aware target preparation,
    /// [`crate::connectivity::PreparedTarget::bind`], and [`Self::send_streaming`]
    /// with appropriate [`StreamLimits`].
    ///
    /// # Errors
    ///
    /// Returns [`UrlSubRequestError`]. Its display does not include the URL,
    /// including any credential-bearing query string.
    #[expect(clippy::too_many_arguments, reason = "explicit target policy, bounds, and metadata")]
    #[expect(clippy::too_many_lines, reason = "single-deadline preparation and fallback loop")]
    pub async fn execute_url<F>(
        &self,
        url: &str,
        request: SubRequest,
        validate: F,
        policy: UrlResolutionPolicy,
        timeout: Duration,
        max_response_bytes: usize,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, UrlSubRequestError>
    where
        F: FnOnce(&[SocketAddr]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send,
    {
        // Framework metadata is applied after the request's headers by the
        // existing executor. A URL request must never lose or replace its
        // authority at that stage.
        if framework_headers.is_some_and(|headers| {
            headers.iter().any(|(name, _)| name == http::header::HOST)
                || headers.removals().any(|name| name == http::header::HOST)
        }) {
            return Err(UrlSubRequestError::Exchange(SubRequestError::InvalidRequest(
                "framework headers cannot change a URL target's Host".to_owned(),
            )));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(UrlSubRequestError::DeadlineExceeded)?;
        let target = prepare_url_target_with_policy(url, deadline.into_std(), validate, policy)
            .await
            .map_err(|err| match err {
                UrlTargetError::DeadlineExceeded => UrlSubRequestError::DeadlineExceeded,
                other @ (UrlTargetError::InvalidTarget(_)
                | UrlTargetError::Resolve(_)
                | UrlTargetError::PolicyRejected(_)) => UrlSubRequestError::Target(other),
            })?;
        let prepared = target.bind(request);
        // The validation hook already inspected the COMPLETE resolved set during
        // preparation. The dial cap below only bounds how many of those
        // addresses fallback will connect to, never what policy validated.
        let max_dials = match policy {
            UrlResolutionPolicy::ClientPerCall => prepared.addresses().len().min(MAX_CLIENT_SELECTED_DIALS),
            UrlResolutionPolicy::OperatorCached => prepared.addresses().len(),
        };
        let mut last_peer_error = None;
        for index in 0..max_dials {
            let Some(peer) = prepared.peer_at(index) else { break };
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(UrlSubRequestError::DeadlineExceeded);
            }
            // Every attempt but the last gets an equal share of the remaining
            // budget for its connect phase, so one blackholed address cannot
            // burn the whole deadline. Request and response I/O still use the
            // full overall deadline (see `execute_with_connect_cap`).
            let attempts_left = max_dials.saturating_sub(index);
            let connect_cap = connect_attempt_cap(remaining, attempts_left);
            match Box::pin(self.execute_with_connect_cap(
                &peer,
                prepared.request(),
                max_response_bytes,
                remaining,
                connect_cap,
                framework_headers,
            ))
            .await
            {
                Ok(response) => return Ok(response),
                // A per-attempt connect-cap timeout surfaces as `Connect` while
                // the overall deadline survives, so it falls back like any other
                // connection failure.
                Err(err @ (SubRequestError::Connect(_) | SubRequestError::CircuitOpen { .. })) => {
                    last_peer_error = Some(redact_url_exchange_error(err));
                },
                Err(SubRequestError::DeadlineExceeded) => return Err(UrlSubRequestError::DeadlineExceeded),
                Err(err) => return Err(UrlSubRequestError::Exchange(redact_url_exchange_error(err))),
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(UrlSubRequestError::DeadlineExceeded);
        }
        // Preparation rejects an empty address set, so the final error came
        // from a frozen peer, never a missing attempt.
        Err(UrlSubRequestError::Exchange(last_peer_error.unwrap_or_else(|| {
            SubRequestError::Connect("prepared URL target has no peers".to_owned())
        })))
    }

    /// Access the underlying connector for direct pool operations.
    pub fn connector(&self) -> &SubRequestConnector<C> {
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

    /// Shared transport path: admission, connect, I/O, header validation.
    ///
    /// Returns a live `RawExchange` owning the session, sanitized
    /// headers, circuit guard, and admission permit. Both `execute()`
    /// and `send_streaming()` call this, then diverge.
    #[expect(
        clippy::too_many_arguments,
        reason = "connect cap and hedge cancellation policy are both per-exchange"
    )]
    async fn open_exchange<'conn>(
        &'conn self,
        peer: &PeerSpec,
        request: &SubRequest,
        timeout: Duration,
        connect_attempt_cap: Option<Duration>,
        framework_headers: Option<&FrameworkHeaders>,
        abandon_neutral: bool,
    ) -> Result<RawExchange<'conn, 'conn, C>, SubRequestError> {
        #[cfg(feature = "otel")]
        let client_span = subrequest_client_span(peer, request);
        #[cfg(not(feature = "otel"))]
        let client_span = Span::none();

        let result = self
            .open_exchange_inner(
                peer,
                request,
                timeout,
                connect_attempt_cap,
                framework_headers,
                &client_span,
                abandon_neutral,
            )
            .instrument(client_span.clone())
            .await;
        if result.is_err() && !client_span.is_disabled() {
            client_span.record("otel.status_code", "ERROR");
            client_span.record("error.type", "subrequest");
        }
        result
    }

    /// Open an HTTP exchange while its per-attempt span is active.
    #[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit per-attempt span keeps propagation bound to this exchange"
    )]
    async fn open_exchange_inner<'conn>(
        &'conn self,
        peer: &PeerSpec,
        request: &SubRequest,
        timeout: Duration,
        connect_attempt_cap: Option<Duration>,
        framework_headers: Option<&FrameworkHeaders>,
        client_span: &Span,
        abandon_neutral: bool,
    ) -> Result<RawExchange<'conn, 'conn, C>, SubRequestError> {
        let exchange_started = tokio::time::Instant::now();
        let deadline = exchange_started
            .checked_add(timeout)
            .ok_or(SubRequestError::DeadlineExceeded)?;

        // ---------------------------------------------------------------------
        // 1. Validate request (before any circuit/admission state)
        // ---------------------------------------------------------------------
        let head = build_request_head(peer, request, framework_headers, client_span)?;

        // ---------------------------------------------------------------------
        // 2. Circuit precheck
        // ---------------------------------------------------------------------
        let peer_key = peer.circuit_key();
        if let Some(registry) = &self.connector.circuit_breakers
            && !registry.precheck(&peer_key)
        {
            return Err(SubRequestError::CircuitOpen {
                peer: peer_key.to_string(),
            });
        }

        // ---------------------------------------------------------------------
        // 3. Admission
        // ---------------------------------------------------------------------
        let admission_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if admission_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let permit = self.connector.try_acquire_permit(admission_budget).await?;

        // ---------------------------------------------------------------------
        // 4. Circuit try_acquire
        // ---------------------------------------------------------------------
        let mut circuit_guard = match &self.connector.circuit_breakers {
            Some(registry) => match registry.try_acquire(peer_key.clone()) {
                CircuitCheck::Rejected => {
                    return Err(SubRequestError::CircuitOpen {
                        peer: peer_key.to_string(),
                    });
                },
                CircuitCheck::Allowed(token) => Some(CircuitGuard::new(registry, peer_key, token)),
            },
            None => None,
        };
        if abandon_neutral && let Some(guard) = circuit_guard.as_mut() {
            guard.abandon_as_neutral();
        }

        // ---------------------------------------------------------------------
        // 5. Connect + I/O
        // ---------------------------------------------------------------------
        let overall_connect_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if overall_connect_budget.is_zero() {
            return Err(charge(&mut circuit_guard, SubRequestError::DeadlineExceeded));
        }
        // An optional per-attempt cap bounds only this connect phase; everything
        // after a successful connect still runs against the overall deadline.
        // The backend's own setup timers are bounded by the exchange timeout, so
        // this outer timer is what reports a cap that ran out.
        let connect_budget = connect_attempt_cap.map_or(overall_connect_budget, |cap| cap.min(overall_connect_budget));

        let mut session = tokio::time::timeout(connect_budget, Box::pin(self.connector.inner.connect(peer, timeout)))
            .await
            .map_err(|_elapsed| charge(&mut circuit_guard, connect_timeout_error(deadline)))?
            .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;

        debug!(
            peer = %peer.address,
            reused = session.reused(),
            method = %request.method,
            // URL-mode paths and queries can carry credentials. Prepared URL
            // requests carry an internal marker that is stripped before send.
            path = request_path_for_log(request),
            "sub-request: connected"
        );

        let write_timeout = peer.connection.write_timeout;
        let header_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if header_budget.is_zero() {
            return Err(charge(&mut circuit_guard, SubRequestError::DeadlineExceeded));
        }

        let header_write_timeout = min_timeout(write_timeout, header_budget);
        tokio::time::timeout(header_write_timeout, session.send_request_head(head))
            .await
            .map_err(|_elapsed| {
                charge(
                    &mut circuit_guard,
                    classify_timeout(header_budget, write_timeout, "write"),
                )
            })?
            .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;

        if !request.body.is_empty() {
            let body_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            if body_budget.is_zero() {
                session.shutdown().await;
                return Err(charge(&mut circuit_guard, SubRequestError::DeadlineExceeded));
            }
            let body_write_timeout = min_timeout(write_timeout, body_budget);
            tokio::time::timeout(
                body_write_timeout,
                session.send_request_body(request.body.clone(), true),
            )
            .await
            .map_err(|_elapsed| {
                charge(
                    &mut circuit_guard,
                    classify_timeout(body_budget, write_timeout, "write"),
                )
            })?
            .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;
        }

        let finish_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if finish_budget.is_zero() {
            session.shutdown().await;
            return Err(charge(&mut circuit_guard, SubRequestError::DeadlineExceeded));
        }
        let finish_write_timeout = min_timeout(write_timeout, finish_budget);
        tokio::time::timeout(finish_write_timeout, session.finish_request())
            .await
            .map_err(|_elapsed| {
                charge(
                    &mut circuit_guard,
                    classify_timeout(finish_budget, write_timeout, "write"),
                )
            })?
            .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;

        // ---------------------------------------------------------------------
        // 6. Read the response header, skipping 1xx interim responses
        // ---------------------------------------------------------------------
        //
        // A transport reads exactly one header block per call and does not
        // advance past an informational (1xx) response. An upstream may send an
        // unsolicited `100 Continue` or `103 Early Hints` (RFC 8297) ahead of
        // the final response, so loop until a final status arrives, honoring
        // the overall deadline. `101 Switching Protocols` is a final response,
        // not interim.
        let read_timeout = peer.connection.read_timeout;
        let mut interim_count = 0_u32;
        let (status, version, resp_headers) = loop {
            let read_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            if read_budget.is_zero() {
                session.shutdown().await;
                return Err(charge(&mut circuit_guard, SubRequestError::DeadlineExceeded));
            }
            let read_wait = min_timeout(read_timeout, read_budget);

            tokio::time::timeout(read_wait, session.read_response_head())
                .await
                .map_err(|_elapsed| charge(&mut circuit_guard, classify_timeout(read_budget, read_timeout, "read")))?
                .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;

            let candidate = session
                .response_head()
                .map_err(|err| charge(&mut circuit_guard, transport_error(err)))?;

            if (100..=199).contains(&candidate.status) && candidate.status != 101 {
                interim_count = interim_count.saturating_add(1);
                if interim_count > MAX_INTERIM_RESPONSES {
                    session.shutdown().await;
                    return Err(charge(
                        &mut circuit_guard,
                        SubRequestError::Io("upstream sent too many 1xx interim responses".to_owned()),
                    ));
                }
                continue;
            }
            break (
                candidate.status,
                candidate.version,
                sanitize_response_headers(candidate.headers),
            );
        };
        record_http_client_status(client_span, status);

        if !(100..=599).contains(&status) {
            session.shutdown().await;
            return Err(charge(
                &mut circuit_guard,
                SubRequestError::Io(format!("upstream returned unsupported HTTP status {status}")),
            ));
        }

        // ---------------------------------------------------------------------
        // 7. Return RawExchange
        // ---------------------------------------------------------------------
        histogram!(SUBREQUEST_HEADER_DURATION_SECONDS).record(exchange_started.elapsed().as_secs_f64());

        Ok(RawExchange {
            session,
            read_timeout,
            connector: &self.connector,
            status,
            version,
            headers: resp_headers,
            circuit_guard,
            permit,
            deadline,
            client_span: client_span.clone(),
        })
    }

    /// Send a streaming sub-request.
    ///
    /// Acquires admission, connects to `peer`, sends `request`, reads
    /// response headers, and returns a [`StreamingSubResponse`] with
    /// an opaque body handle for incremental chunk reads.
    ///
    /// Circuit breaker success is finalized only when the header
    /// exchange completes cleanly (header-only response or a streaming
    /// body); a header-incomplete or H2-error termination records a
    /// failure. Late body failures only affect stream metrics.
    ///
    /// **Timeout semantics:** `timeout` bounds only the header phase
    /// (connect + send + receive headers). Body reads are governed by
    /// [`StreamLimits`]: `idle_timeout` per chunk, optional
    /// `max_stream_duration` for end-to-end lifetime, and the peer's
    /// configured `read_timeout`. Callers needing a single end-to-end
    /// deadline should set `max_stream_duration` accordingly.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError`] on admission timeout, connection
    /// failure, I/O error, or deadline expiry during the header phase.
    #[expect(
        clippy::too_many_arguments,
        reason = "framework_headers is the typed metadata injection point"
    )]
    #[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
    pub async fn send_streaming(
        &self,
        peer: &PeerSpec,
        request: &SubRequest,
        timeout: Duration,
        limits: StreamLimits,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<StreamingSubResponse<C>, SubRequestError> {
        // Streaming uses no per-attempt connect cap: its header `timeout` already
        // bounds the whole connect-plus-header phase. Cancellation still records
        // a circuit failure; only a hedged attempt is neutral on drop.
        let mut exchange = self
            .open_exchange(peer, request, timeout, None, framework_headers, false)
            .await?;

        // Hold the circuit guard until the header-time outcome is known.
        // Finalizing success here (before the completion check below) would
        // record a header-incomplete or H2-error termination as a circuit
        // success, masking a real upstream failure. On the failure paths the
        // guard is dropped, which records a failure via its Drop impl.
        let circuit_guard = exchange.circuit_guard.take();

        // Check for header-time completion (HEAD, 204, 304, zero-length).
        if exchange.session.response_done() {
            match exchange.session.completion() {
                Ok(Completion::Finished) => {},
                Ok(Completion::Incomplete) => {
                    let err = SubRequestError::Io(
                        "upstream indicated response done but stream is not cleanly terminated".to_owned(),
                    );
                    return Err(
                        Box::pin(fail_header_exchange(exchange, circuit_guard, "header_incomplete", err)).await,
                    );
                },
                Err(err) => {
                    return Err(Box::pin(fail_header_exchange(
                        exchange,
                        circuit_guard,
                        "h2_error",
                        transport_error(err),
                    ))
                    .await);
                },
            }
            if let Some(guard) = circuit_guard {
                guard.finalize_success();
            }
            exchange.connector.inner.release(exchange.session, true).await;
            record_header_termination("header_only");
            return Ok(StreamingSubResponse {
                status: exchange.status,
                headers: exchange.headers,
                body: SubResponseBody::new_done(),
            });
        }

        // Valid headers received and the response is streaming: the header
        // exchange succeeded, so finalize the circuit guard as success. The
        // body may still fail later, but the guard is scoped to the header
        // exchange.
        if let Some(guard) = circuit_guard {
            guard.finalize_success();
        }

        // Capture the operator-configured read timeout before clearing the
        // transport's internal timer. next_chunk() enforces it externally
        // alongside idle_timeout and stream_deadline.
        let read_timeout = exchange.read_timeout;
        exchange.session.clear_read_timeout();

        // Compute stream deadline from max_stream_duration. One clock
        // read serves both the deadline and the stream start below.
        let handoff_now = tokio::time::Instant::now();
        let stream_deadline = limits
            .max_stream_duration
            .map(|dur| handoff_now.checked_add(dur).ok_or(SubRequestError::DeadlineExceeded))
            .transpose()?;

        let body = SubResponseBody {
            session: Some(exchange.session),
            connector: Some(exchange.connector.clone()),
            permit: exchange.permit,
            client_span: exchange.client_span,
            read_timeout,
            idle_timeout: limits.idle_timeout,
            stream_deadline,
            max_total_bytes: limits.max_total_bytes,
            received_bytes: 0,
            chunk_count: 0,
            stream_started_at: handoff_now,
            done: false,
        };

        debug!(
            status = exchange.status,
            header_count = exchange.headers.len(),
            "sub-request: streaming handoff"
        );

        Ok(StreamingSubResponse {
            status: exchange.status,
            headers: exchange.headers,
            body,
        })
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
        reason = "stable public buffered-execution signature with framework metadata"
    )]
    pub async fn execute(
        &self,
        peer: &PeerSpec,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, SubRequestError> {
        self.execute_inner(
            peer,
            request,
            max_response_bytes,
            timeout,
            None,
            framework_headers,
            false,
        )
        .await
    }

    /// Execute a buffered sub-request whose cancellation is neutral to the circuit breaker.
    ///
    /// Dropping this future after the exchange has started releases the circuit
    /// slot without recording success or failure. A connect, I/O, or deadline
    /// error still records a failure.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError`] on admission timeout, connection failure,
    /// I/O error, response body exceeding the size limit, or deadline expiry.
    #[expect(
        clippy::too_many_arguments,
        reason = "framework_headers is the typed metadata injection point"
    )]
    pub async fn execute_abandon_neutral(
        &self,
        peer: &PeerSpec,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, SubRequestError> {
        self.execute_inner(
            peer,
            request,
            max_response_bytes,
            timeout,
            None,
            framework_headers,
            true,
        )
        .await
    }

    /// Buffered execution with an optional per-attempt connect cap.
    ///
    /// `connect_attempt_cap` bounds only the connection phase; a `None` cap lets
    /// it use the whole deadline, so [`Self::execute`] is unchanged. URL fallback
    /// passes a share of the remaining budget so one unresponsive address cannot
    /// consume the whole deadline before the next address is tried.
    #[expect(
        clippy::too_many_arguments,
        reason = "connect cap is URL fallback's per-attempt budget alongside framework metadata"
    )]
    async fn execute_with_connect_cap(
        &self,
        peer: &PeerSpec,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        connect_attempt_cap: Option<Duration>,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, SubRequestError> {
        self.execute_inner(
            peer,
            request,
            max_response_bytes,
            timeout,
            connect_attempt_cap,
            framework_headers,
            false,
        )
        .await
    }

    /// Shared body of [`execute`](Self::execute), [`execute_abandon_neutral`](Self::execute_abandon_neutral),
    /// and [`execute_with_connect_cap`](Self::execute_with_connect_cap).
    #[expect(
        clippy::too_many_arguments,
        reason = "connect cap and hedge cancellation policy are both per-exchange"
    )]
    #[expect(clippy::too_many_lines, reason = "inline body collection loop")]
    async fn execute_inner(
        &self,
        peer: &PeerSpec,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        connect_attempt_cap: Option<Duration>,
        framework_headers: Option<&FrameworkHeaders>,
        abandon_neutral: bool,
    ) -> Result<SubResponse, SubRequestError> {
        let exchange = self
            .open_exchange(
                peer,
                request,
                timeout,
                connect_attempt_cap,
                framework_headers,
                abandon_neutral,
            )
            .await;

        let RawExchange {
            mut session,
            read_timeout: configured_read,
            connector,
            status,
            version,
            headers: resp_headers,
            circuit_guard,
            permit: _permit,
            deadline,
            client_span,
        } = match exchange {
            Ok(ex) => ex,
            Err(err) => return Err(err),
        };

        let effective_limit = max_response_bytes.min(self.max_response_bytes);

        // Enforce the overall deadline on body collection, and the peer
        // `read_timeout` on each chunk. A stall between chunks must stop at
        // the cluster read timeout the same way a header read does.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            record_subrequest_client_error(&client_span, "subrequest_body");
            let err = SubRequestError::DeadlineExceeded;
            if let Some(guard) = circuit_guard {
                guard.fail(&err);
            }
            return Err(err);
        }

        // Size the buffer from Content-Length when present, clamped to
        // the limit so an untrusted length can never over-allocate, and
        // to a modest eager cap so an upstream advertising a huge
        // length while sending little cannot pin limit-sized buffers
        // per in-flight exchange. Doubling growth covers honest large
        // bodies; the ResponseTooLarge check below stays authoritative.
        let advertised = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .map_or(0, |len| len.min(effective_limit).min(EAGER_BODY_CAPACITY));
        let body_result: Result<Bytes, SubRequestError> = tokio::time::timeout(remaining, async {
            let mut body_buf = Vec::with_capacity(advertised);
            while !session.response_done() {
                let read_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
                if read_budget.is_zero() {
                    session.shutdown().await;
                    return Err(SubRequestError::DeadlineExceeded);
                }
                let read_wait = min_timeout(configured_read, read_budget);
                match tokio::time::timeout(read_wait, session.read_response_body()).await {
                    Ok(Ok(Some(chunk))) => {
                        if body_buf.len().saturating_add(chunk.len()) > effective_limit {
                            warn!(
                                current = body_buf.len(),
                                chunk = chunk.len(),
                                limit = effective_limit,
                                "sub-request response body exceeded limit"
                            );
                            session.shutdown().await;
                            return Err(SubRequestError::ResponseTooLarge {
                                actual: body_buf.len().saturating_add(chunk.len()),
                                limit: effective_limit,
                            });
                        }
                        body_buf.extend_from_slice(&chunk);
                    },
                    Ok(Ok(None)) => break,
                    Ok(Err(err)) => {
                        session.shutdown().await;
                        return Err(transport_error(err));
                    },
                    Err(_elapsed) => {
                        session.shutdown().await;
                        return Err(classify_timeout(read_budget, configured_read, "read"));
                    },
                }
            }

            match session.completion() {
                Ok(Completion::Finished) => {},
                Ok(Completion::Incomplete) => {
                    session.shutdown().await;
                    return Err(SubRequestError::Io("upstream closed without clean EOF".to_owned()));
                },
                Err(err) => {
                    session.shutdown().await;
                    return Err(transport_error(err));
                },
            }

            debug!(status, body_bytes = body_buf.len(), "sub-request: response received");

            connector.inner.release(session, true).await;

            Ok(Bytes::from(body_buf))
        })
        .instrument(client_span.clone())
        .await
        .unwrap_or_else(|_elapsed| Err(SubRequestError::DeadlineExceeded));

        // Finalize circuit guard with full-exchange outcome.
        if body_result.is_err() {
            record_subrequest_client_error(&client_span, "subrequest_body");
        }
        let result = body_result.map(|body| SubResponse {
            status,
            version,
            headers: resp_headers,
            body,
        });
        if let Some(guard) = circuit_guard {
            guard.finalize(&result);
        }
        result
    }
}

// -----------------------------------------------------------------------------
// Request Assembly
// -----------------------------------------------------------------------------

/// Return the request path or a fixed label for a URL-bound target.
fn request_path_for_log(request: &SubRequest) -> &str {
    if request.headers.contains_key(crate::connectivity::URL_TARGET_MARKER) {
        "<redacted>"
    } else {
        request.uri.path()
    }
}

/// Build the sanitized request head: the method, the origin-form target, and
/// the headers that may cross the sub-request boundary.
///
/// Framework metadata and trace context replace whatever the caller sent
/// under the same names, and `Host` and `Content-Length` are settled last.
#[expect(clippy::too_many_lines, reason = "one pass over the headers, then framing")]
fn build_request_head(
    peer: &PeerSpec,
    request: &SubRequest,
    framework_headers: Option<&FrameworkHeaders>,
    client_span: &Span,
) -> Result<RequestHead, SubRequestError> {
    let target = request
        .uri
        .path_and_query()
        .map_or_else(|| String::from("/"), |pq| String::from(pq.as_str()));

    // Forward the request headers in one pass: skip hop-by-hop (fixed and
    // Connection-nominated), framing (re-computed below), and reserved
    // internal names as each header streams by. Framework headers are
    // inserted afterwards with replace semantics.
    let nominated = connection_nominated_tokens(&request.headers);
    let mut headers = HeaderMap::with_capacity(request.headers.len());
    for (name, value) in &request.headers {
        if is_request_stripped(name, &nominated) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    drop(nominated);

    if let Some(fw) = framework_headers {
        for name in fw.removals() {
            headers.remove(name);
        }
        for (name, value) in fw.iter() {
            headers.insert(name.clone(), value.clone());
        }
    }

    #[cfg(feature = "otel")]
    inject_subrequest_trace_context(&mut headers, client_span);
    #[cfg(not(feature = "otel"))]
    {
        _ = client_span;
    }

    ensure_host_header(&mut headers, peer.address)?;
    if !request.body.is_empty() || empty_body_needs_framing(&request.method) {
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from(request.body.len()),
        );
    }

    Ok(RequestHead {
        headers,
        method: request.method.clone(),
        target,
    })
}

/// Copy the response headers that may cross the sub-request boundary.
fn sanitize_response_headers(received: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated_tokens(received);
    let mut headers = HeaderMap::with_capacity(received.len());
    for (name, value) in received {
        if is_boundary_stripped(name, &nominated) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers
}

/// Replace propagated request headers with the active exported client span context.
#[cfg(feature = "otel")]
fn inject_subrequest_trace_context(headers: &mut HeaderMap, client_span: &Span) {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let span_context = client_span.context();
    let mut propagated = HeaderMap::new();
    if crate::trace_context::inject_context(&mut propagated, &span_context) {
        headers.remove("traceparent");
        headers.remove("tracestate");
        if let Some(value) = propagated.get("traceparent") {
            headers.insert("traceparent", value.clone());
        }
        if let Some(value) = propagated.get("tracestate") {
            headers.insert("tracestate", value.clone());
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Record `err` against the circuit guard, then return it.
///
/// Taking the guard here means a later drop cannot record the same attempt again.
fn charge(guard: &mut Option<CircuitGuard<'_>>, err: SubRequestError) -> SubRequestError {
    if let Some(guard) = guard.take() {
        guard.fail(&err);
    }
    err
}

/// Create a bounded HTTP client span for a framework sub-request.
#[cfg(feature = "otel")]
fn subrequest_client_span(peer: &PeerSpec, request: &SubRequest) -> Span {
    let method = request.method.as_str();
    tracing::info_span!(
        "http_client_request",
        "otel.name" = method,
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        "http.request.method" = method,
        "http.response.status_code" = tracing::field::Empty,
        "error.type" = tracing::field::Empty,
        "server.address" = peer.address.ip().to_string(),
        "server.port" = peer.address.port(),
    )
}

/// Record HTTP CLIENT response status attributes on an active span.
pub fn record_http_client_status(client_span: &Span, status: u16) {
    if client_span.is_disabled() {
        return;
    }
    client_span.record("http.response.status_code", status);
    if let Some(error_type) = subrequest_client_status_error_type(status) {
        client_span.record("otel.status_code", "ERROR");
        client_span.record("error.type", error_type.as_str());
    }
}

/// Mark a failed sub-request phase without exporting transport error text.
pub(super) fn record_subrequest_client_error(client_span: &Span, error_type: &'static str) {
    if !client_span.is_disabled() {
        client_span.record("otel.status_code", "ERROR");
        client_span.record("error.type", error_type);
    }
}

/// Return the bounded `error.type` value for an HTTP error status.
fn subrequest_client_status_error_type(status: u16) -> Option<String> {
    (status >= 400).then(|| status.to_string())
}

/// The per-attempt connect budget for a URL fallback dial: an equal share of
/// the remaining deadline for every attempt but the last. The last attempt
/// returns `None` (its connect may use everything that is left), as does a
/// degenerate zero/overflowing count, which falls back to the overall deadline.
fn connect_attempt_cap(remaining: Duration, attempts_left: usize) -> Option<Duration> {
    if attempts_left <= 1 {
        return None;
    }
    u32::try_from(attempts_left)
        .ok()
        .and_then(|count| remaining.checked_div(count))
}

/// Classify a connect-phase timeout. Once the overall deadline has elapsed the
/// whole call is done; otherwise the per-attempt cap fired, which URL fallback
/// treats as a retryable connection failure and tries the next address.
fn connect_timeout_error(deadline: tokio::time::Instant) -> SubRequestError {
    if tokio::time::Instant::now() >= deadline {
        SubRequestError::DeadlineExceeded
    } else {
        SubRequestError::Connect("connection attempt exceeded its per-attempt budget".to_owned())
    }
}

/// Transport diagnostics may include raw response header bytes. URL
/// execution must not return those bytes because upstreams can reflect a
/// credential-bearing query in a malformed response. Keep the error category
/// while replacing untrusted free-form messages with fixed text.
fn redact_url_exchange_error(error: SubRequestError) -> SubRequestError {
    match error {
        SubRequestError::InvalidRequest(_) => {
            SubRequestError::InvalidRequest("URL request could not be sent".to_owned())
        },
        SubRequestError::Connect(_) => SubRequestError::Connect("upstream connection failed".to_owned()),
        SubRequestError::Io(_) => SubRequestError::Io("upstream exchange failed".to_owned()),
        other @ (SubRequestError::AdmissionTimeout { .. }
        | SubRequestError::DeadlineExceeded
        | SubRequestError::StreamIdleTimeout { .. }
        | SubRequestError::CircuitOpen { .. }
        | SubRequestError::ResponseTooLarge { .. }) => other,
    }
}

/// Tear down an abnormally terminated header exchange: drop the circuit
/// guard (recording a failure via its `Drop` impl), discard the session,
/// record the termination metric, and hand back the error to return.
async fn fail_header_exchange<C: Connector>(
    exchange: RawExchange<'_, '_, C>,
    circuit_guard: Option<CircuitGuard<'_>>,
    termination: &'static str,
    error: SubRequestError,
) -> SubRequestError {
    record_subrequest_client_error(&exchange.client_span, "subrequest_header");
    drop(circuit_guard);
    exchange.connector.inner.release(exchange.session, false).await;
    record_header_termination(termination);
    error
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::too_many_lines, clippy::items_after_statements, reason = "tests")]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn subrequest_client_status_marks_4xx_and_5xx_as_errors() {
        use tracing_subscriber::layer::SubscriberExt as _;

        for (status, expected) in [(200, None), (404, Some("404")), (500, Some("500"))] {
            assert_eq!(subrequest_client_status_error_type(status).as_deref(), expected);
            let capture = StatusRecordCapture::default();
            let subscriber = tracing_subscriber::registry().with(capture.clone());
            let _guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!(
                "subrequest_client",
                "http.response.status_code" = tracing::field::Empty,
                "otel.status_code" = tracing::field::Empty,
                "error.type" = tracing::field::Empty,
            );
            record_http_client_status(&span, status);
            drop(span);

            let fields = capture
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            assert!(
                fields
                    .iter()
                    .any(|(name, value)| { name == "http.response.status_code" && value == &status.to_string() })
            );
            assert_eq!(
                fields
                    .iter()
                    .find(|(name, _)| name == "otel.status_code")
                    .map(|(_, value)| value.as_str()),
                expected.map(|_| "\"ERROR\""),
                "subrequest CLIENT OTel status for HTTP {status}"
            );
            let error_type = expected.map(|value| format!("\"{value}\""));
            assert_eq!(
                fields
                    .iter()
                    .find(|(name, _)| name == "error.type")
                    .map(|(_, value)| value.as_str()),
                error_type.as_deref(),
                "subrequest CLIENT error.type for HTTP {status}"
            );
        }
    }

    #[test]
    fn subrequest_body_error_marks_client_span_without_error_text() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = StatusRecordCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!(
            "subrequest_client",
            "otel.status_code" = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
        );
        record_subrequest_client_error(&span, "subrequest_body");

        let fields = capture
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert!(
            fields
                .iter()
                .any(|(name, value)| name == "otel.status_code" && value == "\"ERROR\"")
        );
        assert!(
            fields
                .iter()
                .any(|(name, value)| name == "error.type" && value == "\"subrequest_body\"")
        );
    }

    #[derive(Clone, Default)]
    struct StatusRecordCapture(Arc<Mutex<Vec<(String, String)>>>);

    impl<S> tracing_subscriber::Layer<S> for StatusRecordCapture
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_record(
            &self,
            _id: &tracing::span::Id,
            record: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'fields>(&'fields mut Vec<(String, String)>);

            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    self.0.push((field.name().to_owned(), format!("{value:?}")));
                }
            }

            let mut captured = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            record.record(&mut Visitor(&mut captured));
        }
    }

    #[test]
    fn max_interim_responses_constant_is_32() {
        assert_eq!(MAX_INTERIM_RESPONSES, 32, "MAX_INTERIM_RESPONSES should equal 32");
    }

    #[test]
    fn eager_body_capacity_constant_is_128_kib() {
        assert_eq!(
            EAGER_BODY_CAPACITY, 131_072,
            "EAGER_BODY_CAPACITY should be 128 KiB in bytes"
        );
        assert_eq!(EAGER_BODY_CAPACITY, 128 * 1024, "EAGER_BODY_CAPACITY should be 128 KiB");
    }

    #[test]
    fn direct_request_path_remains_visible_in_connection_event() {
        let request = SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/operator-health-path?query-is-never-logged"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };

        assert_eq!(request_path_for_log(&request), "/operator-health-path");
    }

    #[test]
    fn new_client_uses_absolute_max_body_bytes() {
        let connector = test_connector();
        let client = SubRequestClient::new(connector);

        assert_eq!(
            client.max_response_bytes,
            crate::config::ABSOLUTE_MAX_BODY_BYTES,
            "new() should default to ABSOLUTE_MAX_BODY_BYTES"
        );
    }

    #[test]
    fn with_max_response_bytes_sets_ceiling() {
        let connector = test_connector();
        let custom_ceiling = 1_048_576;
        let client = SubRequestClient::with_max_response_bytes(connector, custom_ceiling);

        assert_eq!(
            client.max_response_bytes, custom_ceiling,
            "with_max_response_bytes() should set the provided ceiling"
        );
    }

    #[test]
    fn connector_accessor_returns_stored_connector() {
        let connector = test_connector();
        let client = SubRequestClient::new(connector.clone());

        let retrieved = client.connector();
        assert!(
            !std::ptr::eq(retrieved, &connector),
            "connector() should return reference to the stored connector"
        );
    }

    #[test]
    fn evict_idle_circuits_returns_zero_without_circuit_breaker() {
        let connector = test_connector();
        let client = SubRequestClient::new(connector);

        let evicted = client.evict_idle_circuits(Duration::from_secs(60));

        assert_eq!(
            evicted, 0,
            "evict_idle_circuits should return 0 when no circuit breaker is configured"
        );
    }

    #[test]
    fn debug_output_names_the_type() {
        let connector = test_connector();
        let client = SubRequestClient::new(connector);

        let debug_str = format!("{client:?}");
        assert!(
            debug_str.contains("SubRequestClient"),
            "Debug impl should include type name"
        );
        assert!(
            debug_str.contains("connector"),
            "Debug impl should show connector field"
        );
        assert!(
            debug_str.contains("max_response_bytes"),
            "Debug impl should show max_response_bytes field"
        );
    }

    #[test]
    fn clone_preserves_ceiling() {
        let connector = test_connector();
        let client = SubRequestClient::with_max_response_bytes(connector, 5_000_000);

        let cloned = client.clone();

        assert_eq!(
            client.max_response_bytes, cloned.max_response_bytes,
            "clone should preserve max_response_bytes"
        );
    }

    #[test]
    fn with_max_response_bytes_sets_various_ceilings() {
        let connector = test_connector();

        let test_cases = vec![
            (1_000, "small ceiling"),
            (10_000_000, "large ceiling"),
            (EAGER_BODY_CAPACITY, "ceiling equal to eager capacity"),
            (EAGER_BODY_CAPACITY / 2, "ceiling smaller than eager capacity"),
            (EAGER_BODY_CAPACITY * 2, "ceiling larger than eager capacity"),
        ];

        for (ceiling, description) in test_cases {
            let client = SubRequestClient::with_max_response_bytes(connector.clone(), ceiling);
            assert_eq!(client.max_response_bytes, ceiling, "Failed for case: {description}");
        }
    }

    #[test]
    fn with_max_response_bytes_accepts_boundary_values() {
        let connector = test_connector();

        let zero_client = SubRequestClient::with_max_response_bytes(connector.clone(), 0);
        assert_eq!(
            zero_client.max_response_bytes, 0,
            "a ceiling of 0 should be stored unchanged"
        );

        let one_client = SubRequestClient::with_max_response_bytes(connector.clone(), 1);
        assert_eq!(
            one_client.max_response_bytes, 1,
            "a ceiling of 1 should be stored unchanged"
        );

        let large_client = SubRequestClient::with_max_response_bytes(connector, usize::MAX);
        assert_eq!(
            large_client.max_response_bytes,
            usize::MAX,
            "a ceiling of usize::MAX should be stored unchanged"
        );
    }

    #[test]
    fn eager_capacity_caps_preallocation() {
        let test_sizes = vec![
            0,
            1,
            1024,
            EAGER_BODY_CAPACITY - 1,
            EAGER_BODY_CAPACITY,
            EAGER_BODY_CAPACITY + 1,
            EAGER_BODY_CAPACITY * 2,
            10_485_760,
        ];

        for size in test_sizes {
            let effective_limit = 67_108_864;
            let pre_alloc = size.min(effective_limit).min(EAGER_BODY_CAPACITY);

            if size <= EAGER_BODY_CAPACITY {
                assert_eq!(
                    pre_alloc, size,
                    "sizes <= EAGER_BODY_CAPACITY should not be capped (size: {size})"
                );
            } else {
                assert_eq!(
                    pre_alloc, EAGER_BODY_CAPACITY,
                    "sizes > EAGER_BODY_CAPACITY should be capped (size: {size})"
                );
            }
        }
    }

    #[test]
    fn per_call_limit_clamps_to_client_ceiling() {
        let connector = test_connector();

        let client_ceiling = 1_048_576;
        let client = SubRequestClient::with_max_response_bytes(connector, client_ceiling);

        let test_cases = vec![
            (500_000, 500_000, "per-call smaller than ceiling"),
            (1_048_576, 1_048_576, "per-call equal to ceiling"),
            (2_000_000, 1_048_576, "per-call larger than ceiling (should clamp)"),
            (10_000_000, 1_048_576, "per-call much larger (should clamp)"),
            (0, 0, "per-call zero"),
        ];

        for (per_call_limit, expected_effective, description) in test_cases {
            let effective = per_call_limit.min(client.max_response_bytes);
            assert_eq!(effective, expected_effective, "Failed for case: {description}");
        }
    }

    #[test]
    fn limit_clamping_across_various_ceilings() {
        let connector = test_connector();

        struct TestCase {
            client_ceiling: usize,
            per_call_limit: usize,
            expected_effective: usize,
            description: &'static str,
        }

        let test_cases = vec![
            TestCase {
                client_ceiling: 1_000_000,
                per_call_limit: 500_000,
                expected_effective: 500_000,
                description: "normal case: per-call < ceiling",
            },
            TestCase {
                client_ceiling: 1_000_000,
                per_call_limit: 2_000_000,
                expected_effective: 1_000_000,
                description: "clamp case: per-call > ceiling",
            },
            TestCase {
                client_ceiling: 100,
                per_call_limit: 1_000_000,
                expected_effective: 100,
                description: "tight ceiling: per-call >> ceiling",
            },
            TestCase {
                client_ceiling: usize::MAX,
                per_call_limit: 1_000_000,
                expected_effective: 1_000_000,
                description: "no ceiling: per-call is effective",
            },
            TestCase {
                client_ceiling: 0,
                per_call_limit: 1_000_000,
                expected_effective: 0,
                description: "zero ceiling: always zero",
            },
        ];

        for tc in test_cases {
            let client = SubRequestClient::with_max_response_bytes(connector.clone(), tc.client_ceiling);

            let effective = tc.per_call_limit.min(client.max_response_bytes);
            let description = tc.description;

            assert_eq!(effective, tc.expected_effective, "Failed for case: {description}");
        }
    }

    #[test]
    fn eager_body_capacity_is_kib_aligned() {
        assert_eq!(EAGER_BODY_CAPACITY % 1024, 0, "should be KiB-aligned");
        assert_eq!(EAGER_BODY_CAPACITY / 1024, 128, "should be exactly 128 KiB");
    }

    #[test]
    fn interim_responses_limit_boundary() {
        let limit = MAX_INTERIM_RESPONSES;

        assert!(limit > 0, "limit should be positive");
        assert!(limit < 1000, "limit should be reasonable");

        let acceptable_count = limit;
        let unacceptable_count = limit + 1;

        assert!(
            acceptable_count <= limit,
            "exactly {limit} interim responses should be within limit"
        );
        assert!(
            unacceptable_count > limit,
            "{unacceptable_count} interim responses should exceed limit"
        );
    }

    #[test]
    fn multiple_clients_keep_independent_limits() {
        let connector = test_connector();

        let client_a = SubRequestClient::with_max_response_bytes(connector.clone(), 1_000_000);
        let client_b = SubRequestClient::with_max_response_bytes(connector.clone(), 5_000_000);
        let client_c = SubRequestClient::new(connector);

        assert_eq!(
            client_a.max_response_bytes, 1_000_000,
            "client_a should keep its own ceiling"
        );
        assert_eq!(
            client_b.max_response_bytes, 5_000_000,
            "client_b should keep its own ceiling"
        );
        assert_eq!(
            client_c.max_response_bytes,
            crate::config::ABSOLUTE_MAX_BODY_BYTES,
            "client_c should default to ABSOLUTE_MAX_BODY_BYTES"
        );
    }

    #[test]
    fn evict_idle_circuits_returns_zero_for_any_duration() {
        let connector = test_connector();
        let client = SubRequestClient::new(connector);

        let durations = vec![
            Duration::from_secs(0),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(3600),
            Duration::from_secs(86400),
        ];

        for duration in durations {
            let evicted = client.evict_idle_circuits(duration);
            assert_eq!(
                evicted, 0,
                "should always return 0 when no circuit breaker, duration: {duration:?}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a connector with the crypto provider installed first. The server
    /// bootstrap normally installs it, but these tests never run that code.
    fn test_connector() -> SubRequestConnector {
        praxis_tls::provider::install();
        SubRequestConnector::new(128, None)
    }
}
