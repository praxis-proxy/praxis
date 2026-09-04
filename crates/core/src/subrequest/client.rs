// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use metrics::histogram;
use pingora_core::upstreams::peer::{HttpPeer, Peer as _};
use tracing::{debug, warn};

use super::{
    body::dispose_session_abnormal,
    internals::{
        CircuitGuard, RawExchange, SUBREQUEST_HEADER_DURATION_SECONDS, SubRequestConnector, check_clean_completion,
        clamp_peer_timeouts, classify_timeout, connection_nominated_tokens, empty_body_needs_framing,
        ensure_host_header, is_boundary_stripped, is_request_stripped, min_timeout, record_header_termination,
    },
    types::{
        FrameworkHeaders, StreamLimits, StreamingSubResponse, SubRequest, SubRequestError, SubResponse, SubResponseBody,
    },
};
use crate::circuit::{CircuitCheck, PeerKey};

// ---------------------------------------------------------------------------
// SubRequestClient
// ---------------------------------------------------------------------------

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

    /// Shared transport path: admission, connect, I/O, header validation.
    ///
    /// Returns a live `RawExchange` owning the session, peer, sanitized
    /// headers, circuit guard, and admission permit. Both `execute()`
    /// and `send_streaming()` call this, then diverge.
    #[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
    #[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
    async fn open_exchange<'a>(
        &'a self,
        peer: &HttpPeer,
        request: &SubRequest,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<RawExchange<'a>, SubRequestError> {
        let exchange_started = tokio::time::Instant::now();
        let deadline = exchange_started
            .checked_add(timeout)
            .ok_or(SubRequestError::DeadlineExceeded)?;
        let mut bounded_peer = peer.clone();
        clamp_peer_timeouts(&mut bounded_peer, timeout);

        // -- 1. Validate request (before any circuit/admission state) --
        let path = request
            .uri
            .path_and_query()
            .map_or(b"/".as_slice(), |pq| pq.as_str().as_bytes());
        let mut req_header = pingora_http::RequestHeader::build(request.method.clone(), path, None)
            .map_err(|e| SubRequestError::InvalidRequest(e.to_string()))?;

        // Forward the request headers in one pass — no intermediate map
        // clone, no repeated removal passes: skip hop-by-hop (fixed and
        // Connection-nominated), framing (re-computed below), and
        // reserved internal names as each header streams by. Framework
        // headers are inserted afterwards with replace semantics, as the
        // old map-insert had.
        let nominated = connection_nominated_tokens(&request.headers);
        for (name, value) in &request.headers {
            if is_request_stripped(name, &nominated) {
                continue;
            }
            let _append = req_header.append_header(name.clone(), value.clone());
        }
        drop(nominated);
        if let Some(fw) = framework_headers {
            for (name, value) in fw.iter() {
                let _insert = req_header.insert_header(name.clone(), value.clone());
            }
        }
        ensure_host_header(&mut req_header, &bounded_peer)?;
        if !request.body.is_empty() || empty_body_needs_framing(&request.method) {
            let _cl = req_header.insert_header("Content-Length", request.body.len().to_string());
        }

        // -- 2. Circuit precheck --
        let peer_key: Option<PeerKey> = bounded_peer
            .address()
            .as_inet()
            .copied()
            .map(|addr| PeerKey::new(addr, bounded_peer.sni.as_str()));

        if let (Some(registry), Some(key)) = (&self.connector.circuit_breakers, &peer_key)
            && !registry.precheck(key)
        {
            return Err(SubRequestError::CircuitOpen { peer: key.to_string() });
        }

        // -- 3. Admission --
        let admission_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if admission_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }
        let permit = self.connector.try_acquire_permit(admission_budget).await?;

        // -- 4. Circuit try_acquire --
        let circuit_guard = match (&self.connector.circuit_breakers, peer_key) {
            (Some(registry), Some(key)) => match registry.try_acquire(key.clone()) {
                CircuitCheck::Rejected => {
                    return Err(SubRequestError::CircuitOpen { peer: key.to_string() });
                },
                CircuitCheck::Allowed(token) => Some(CircuitGuard::new(registry, key, token)),
            },
            _ => None,
        };

        // -- 5. Connect + I/O --
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }

        let (mut session, reused) = tokio::time::timeout(
            remaining,
            Box::pin(self.connector.connector().get_http_session(&bounded_peer)),
        )
        .await
        .map_err(|_elapsed| SubRequestError::DeadlineExceeded)?
        .map_err(|e| SubRequestError::Connect(e.to_string()))?;

        debug!(
            peer = %bounded_peer.address(),
            reused,
            method = %request.method,
            uri = %request.uri,
            "sub-request: connected"
        );

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }

        let write_timeout = min_timeout(bounded_peer.options.write_timeout, remaining);
        tokio::time::timeout(write_timeout, session.write_request_header(Box::new(req_header)))
            .await
            .map_err(|_elapsed| classify_timeout(remaining, bounded_peer.options.write_timeout, "write"))?
            .map_err(|e| SubRequestError::Io(e.to_string()))?;

        if !request.body.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                session.shutdown().await;
                return Err(SubRequestError::DeadlineExceeded);
            }
            let write_timeout = min_timeout(bounded_peer.options.write_timeout, remaining);
            tokio::time::timeout(write_timeout, session.write_request_body(request.body.clone(), true))
                .await
                .map_err(|_elapsed| classify_timeout(remaining, bounded_peer.options.write_timeout, "write"))?
                .map_err(|e| SubRequestError::Io(e.to_string()))?;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            session.shutdown().await;
            return Err(SubRequestError::DeadlineExceeded);
        }
        let write_timeout = min_timeout(bounded_peer.options.write_timeout, remaining);
        tokio::time::timeout(write_timeout, session.finish_request_body())
            .await
            .map_err(|_elapsed| classify_timeout(remaining, bounded_peer.options.write_timeout, "write"))?
            .map_err(|e| SubRequestError::Io(e.to_string()))?;

        // -- 6. Read the response header, skipping 1xx interim responses --
        //
        // Pingora's H1 client reads exactly one header block per call and does
        // not advance past an informational (1xx) response; its body reader is
        // left uninitialized, so reading the body while the status is still 1xx
        // panics. An upstream may send an unsolicited `100 Continue` or
        // `103 Early Hints` (RFC 8297) ahead of the final response, so loop
        // until a final status arrives, honoring the overall deadline.
        // `101 Switching Protocols` is a final response, not interim.
        let mut interim_count = 0_u32;
        let status = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                session.shutdown().await;
                return Err(SubRequestError::DeadlineExceeded);
            }
            let read_timeout = min_timeout(bounded_peer.options.read_timeout, remaining);

            tokio::time::timeout(read_timeout, session.read_response_header())
                .await
                .map_err(|_elapsed| classify_timeout(remaining, bounded_peer.options.read_timeout, "read"))?
                .map_err(|e| SubRequestError::Io(e.to_string()))?;

            let resp_header = session
                .response_header()
                .ok_or_else(|| SubRequestError::Io("no response header received".to_owned()))?;
            let status = resp_header.status.as_u16();

            if (100..=199).contains(&status) && status != 101 {
                interim_count += 1;
                if interim_count > MAX_INTERIM_RESPONSES {
                    session.shutdown().await;
                    return Err(SubRequestError::Io(
                        "upstream sent too many 1xx interim responses".to_owned(),
                    ));
                }
                continue;
            }
            break status;
        };

        if !(100..=599).contains(&status) {
            session.shutdown().await;
            return Err(SubRequestError::Io(format!(
                "upstream returned unsupported HTTP status {status}"
            )));
        }
        let resp_header = session
            .response_header()
            .ok_or_else(|| SubRequestError::Io("no response header received".to_owned()))?;
        // Copy the response headers in one pass, sized up front. The
        // values are already-validated `HeaderValue`s (pingora's header
        // map stores the http crate's type), so cloning is a refcount
        // bump — re-validating every byte through `from_bytes` was pure
        // waste and its error arm was unreachable.
        let nominated = connection_nominated_tokens(&resp_header.headers);
        let mut resp_headers = HeaderMap::with_capacity(resp_header.headers.len());
        for (name, value) in &resp_header.headers {
            if is_boundary_stripped(name, &nominated) {
                continue;
            }
            resp_headers.append(name.clone(), value.clone());
        }

        // -- 7. Return RawExchange --
        histogram!(SUBREQUEST_HEADER_DURATION_SECONDS).record(exchange_started.elapsed().as_secs_f64());

        Ok(RawExchange {
            session,
            peer: bounded_peer,
            connector: &self.connector,
            status,
            headers: resp_headers,
            circuit_guard,
            permit,
            deadline,
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
    #[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
    #[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
    pub async fn send_streaming(
        &self,
        peer: &HttpPeer,
        request: &SubRequest,
        timeout: Duration,
        limits: StreamLimits,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<StreamingSubResponse, SubRequestError> {
        let mut exchange = self.open_exchange(peer, request, timeout, framework_headers).await?;

        // Hold the circuit guard until the header-time outcome is known.
        // Finalizing success here (before the completion check below) would
        // record a header-incomplete or H2-error termination as a circuit
        // success, masking a real upstream failure. On the failure paths the
        // guard is dropped, which records a failure via its Drop impl.
        let circuit_guard = exchange.circuit_guard.take();

        // Check for header-time completion (HEAD, 204, 304, zero-length).
        if exchange.session.response_done() {
            match check_clean_completion(&mut exchange.session) {
                Ok(true) => {},
                Ok(false) => {
                    let e = SubRequestError::Io(
                        "upstream indicated response done but stream is not cleanly terminated".to_owned(),
                    );
                    return Err(Box::pin(fail_header_exchange(exchange, circuit_guard, "header_incomplete", e)).await);
                },
                Err(e) => return Err(Box::pin(fail_header_exchange(exchange, circuit_guard, "h2_error", e)).await),
            }
            if let Some(guard) = circuit_guard {
                guard.finalize_success();
            }
            exchange
                .connector
                .connector()
                .release_http_session(exchange.session, &exchange.peer, None)
                .await;
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

        // Capture the operator-configured read timeout before clearing
        // Pingora's internal timer. next_chunk() enforces it externally
        // alongside idle_timeout and stream_deadline.
        let read_timeout = exchange.peer.options.read_timeout;
        exchange.session.set_read_timeout(None);

        // Compute stream deadline from max_stream_duration. One clock
        // read serves both the deadline and the stream start below.
        let handoff_now = tokio::time::Instant::now();
        let stream_deadline = limits
            .max_stream_duration
            .map(|d| handoff_now.checked_add(d).ok_or(SubRequestError::DeadlineExceeded))
            .transpose()?;

        let body = SubResponseBody {
            session: Some(exchange.session),
            peer: Some(exchange.peer),
            connector: Some(exchange.connector.clone()),
            permit: exchange.permit,
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
        reason = "framework_headers is the typed metadata injection point"
    )]
    #[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
    #[expect(clippy::too_many_lines, reason = "inline body collection loop")]
    pub async fn execute(
        &self,
        peer: &HttpPeer,
        request: &SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<SubResponse, SubRequestError> {
        let exchange = self.open_exchange(peer, request, timeout, framework_headers).await;

        let RawExchange {
            mut session,
            peer: bounded_peer,
            connector,
            status,
            headers: resp_headers,
            circuit_guard,
            permit: _permit,
            deadline,
        } = match exchange {
            Ok(ex) => ex,
            Err(e) => return Err(e),
        };

        let effective_limit = max_response_bytes.min(self.max_response_bytes);

        // Enforce deadline on body collection phase.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }

        // Size the buffer from Content-Length when present, clamped to
        // the limit so an untrusted length can never over-allocate, and
        // to a modest eager cap so an upstream advertising a huge
        // length while sending little cannot pin limit-sized buffers
        // per in-flight exchange. Doubling growth covers honest large
        // bodies; the ResponseTooLarge check below stays authoritative.
        let advertised = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(0, |len| len.min(effective_limit).min(EAGER_BODY_CAPACITY));
        let body_result: Result<Bytes, SubRequestError> = tokio::time::timeout(remaining, async {
            let mut body_buf = Vec::with_capacity(advertised);
            while !session.response_done() {
                match session.read_response_body().await {
                    Ok(Some(chunk)) => {
                        if body_buf.len() + chunk.len() > effective_limit {
                            warn!(
                                current = body_buf.len(),
                                chunk = chunk.len(),
                                limit = effective_limit,
                                "sub-request response body exceeded limit"
                            );
                            session.shutdown().await;
                            return Err(SubRequestError::ResponseTooLarge {
                                actual: body_buf.len() + chunk.len(),
                                limit: effective_limit,
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

            connector
                .connector()
                .release_http_session(session, &bounded_peer, None)
                .await;

            Ok(Bytes::from(body_buf))
        })
        .await
        .unwrap_or_else(|_elapsed| Err(SubRequestError::DeadlineExceeded));

        // Finalize circuit guard with full-exchange outcome.
        let result = body_result.map(|body| SubResponse {
            status,
            headers: resp_headers,
            body,
        });
        if let Some(guard) = circuit_guard {
            guard.finalize(&result);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Private Utilities
// ---------------------------------------------------------------------------

/// Tear down an abnormally terminated header exchange: drop the circuit
/// guard (recording a failure via its `Drop` impl), discard the session,
/// record the termination metric, and hand back the error to return.
async fn fail_header_exchange(
    exchange: RawExchange<'_>,
    circuit_guard: Option<CircuitGuard<'_>>,
    termination: &'static str,
    error: SubRequestError,
) -> SubRequestError {
    drop(circuit_guard);
    dispose_session_abnormal(
        exchange.session,
        Some(&exchange.peer),
        Some(exchange.connector.connector()),
    )
    .await;
    record_header_termination(termination);
    error
}
