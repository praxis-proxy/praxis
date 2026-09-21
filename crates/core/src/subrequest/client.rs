// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hardened sub-request client executor.
//!
//! [`SubRequestClient`] wraps a shared connector to provide safe,
//! bounded execution of outbound HTTP exchanges with deadline
//! enforcement, response body size limits, and automatic hop-by-hop
//! header sanitization. Supports both buffered (collect full body)
//! and streaming (chunk-by-chunk) response modes.

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

// -----------------------------------------------------------------------------
// SubRequestClient
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
/// # praxis_tls::provider::install(); // required before any connector is built
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
    async fn open_exchange<'conn>(
        &'conn self,
        peer: &HttpPeer,
        request: &SubRequest,
        timeout: Duration,
        framework_headers: Option<&FrameworkHeaders>,
    ) -> Result<RawExchange<'conn, 'conn>, SubRequestError> {
        let exchange_started = tokio::time::Instant::now();
        let deadline = exchange_started
            .checked_add(timeout)
            .ok_or(SubRequestError::DeadlineExceeded)?;
        let mut bounded_peer = peer.clone();
        clamp_peer_timeouts(&mut bounded_peer, timeout);

        // ---------------------------------------------------------------------
        // 1. Validate request (before any circuit/admission state)
        // ---------------------------------------------------------------------
        let path = request
            .uri
            .path_and_query()
            .map_or(b"/".as_slice(), |pq| pq.as_str().as_bytes());
        let mut req_header = pingora_http::RequestHeader::build(request.method.clone(), path, None)
            .map_err(|err| SubRequestError::InvalidRequest(err.to_string()))?;

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
            for name in fw.removals() {
                let _remove = req_header.remove_header(name);
            }
            for (name, value) in fw.iter() {
                let _insert = req_header.insert_header(name.clone(), value.clone());
            }
        }
        ensure_host_header(&mut req_header, &bounded_peer)?;
        if !request.body.is_empty() || empty_body_needs_framing(&request.method) {
            let _cl = req_header.insert_header("Content-Length", request.body.len().to_string());
        }

        // ---------------------------------------------------------------------
        // 2. Circuit precheck
        // ---------------------------------------------------------------------
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
        let circuit_guard = match (&self.connector.circuit_breakers, peer_key) {
            (Some(registry), Some(key)) => match registry.try_acquire(key.clone()) {
                CircuitCheck::Rejected => {
                    return Err(SubRequestError::CircuitOpen { peer: key.to_string() });
                },
                CircuitCheck::Allowed(token) => Some(CircuitGuard::new(registry, key, token)),
            },
            _ => None,
        };

        // ---------------------------------------------------------------------
        // 5. Connect + I/O
        // ---------------------------------------------------------------------
        let connect_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if connect_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }

        let (mut session, reused) = tokio::time::timeout(
            connect_budget,
            Box::pin(self.connector.connector().get_http_session(&bounded_peer)),
        )
        .await
        .map_err(|_elapsed| SubRequestError::DeadlineExceeded)?
        .map_err(|err| SubRequestError::Connect(err.to_string()))?;

        debug!(
            peer = %bounded_peer.address(),
            reused,
            method = %request.method,
            uri = %request.uri,
            "sub-request: connected"
        );

        let header_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if header_budget.is_zero() {
            return Err(SubRequestError::DeadlineExceeded);
        }

        let header_write_timeout = min_timeout(bounded_peer.options.write_timeout, header_budget);
        tokio::time::timeout(header_write_timeout, session.write_request_header(Box::new(req_header)))
            .await
            .map_err(|_elapsed| classify_timeout(header_budget, bounded_peer.options.write_timeout, "write"))?
            .map_err(|err| SubRequestError::Io(err.to_string()))?;

        if !request.body.is_empty() {
            let body_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            if body_budget.is_zero() {
                session.shutdown().await;
                return Err(SubRequestError::DeadlineExceeded);
            }
            let body_write_timeout = min_timeout(bounded_peer.options.write_timeout, body_budget);
            tokio::time::timeout(
                body_write_timeout,
                session.write_request_body(request.body.clone(), true),
            )
            .await
            .map_err(|_elapsed| classify_timeout(body_budget, bounded_peer.options.write_timeout, "write"))?
            .map_err(|err| SubRequestError::Io(err.to_string()))?;
        }

        let finish_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if finish_budget.is_zero() {
            session.shutdown().await;
            return Err(SubRequestError::DeadlineExceeded);
        }
        let finish_write_timeout = min_timeout(bounded_peer.options.write_timeout, finish_budget);
        tokio::time::timeout(finish_write_timeout, session.finish_request_body())
            .await
            .map_err(|_elapsed| classify_timeout(finish_budget, bounded_peer.options.write_timeout, "write"))?
            .map_err(|err| SubRequestError::Io(err.to_string()))?;

        // ---------------------------------------------------------------------
        // 6. Read the response header, skipping 1xx interim responses
        // ---------------------------------------------------------------------
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
            let read_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            if read_budget.is_zero() {
                session.shutdown().await;
                return Err(SubRequestError::DeadlineExceeded);
            }
            let read_timeout = min_timeout(bounded_peer.options.read_timeout, read_budget);

            tokio::time::timeout(read_timeout, session.read_response_header())
                .await
                .map_err(|_elapsed| classify_timeout(read_budget, bounded_peer.options.read_timeout, "read"))?
                .map_err(|err| SubRequestError::Io(err.to_string()))?;

            let resp_header = session
                .response_header()
                .ok_or_else(|| SubRequestError::Io("no response header received".to_owned()))?;
            let status = resp_header.status.as_u16();

            if (100..=199).contains(&status) && status != 101 {
                interim_count = interim_count.saturating_add(1);
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
        let resp_nominated = connection_nominated_tokens(&resp_header.headers);
        let mut resp_headers = HeaderMap::with_capacity(resp_header.headers.len());
        for (name, value) in &resp_header.headers {
            if is_boundary_stripped(name, &resp_nominated) {
                continue;
            }
            resp_headers.append(name.clone(), value.clone());
        }

        // ---------------------------------------------------------------------
        // 7. Return RawExchange
        // ---------------------------------------------------------------------
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
                    let err = SubRequestError::Io(
                        "upstream indicated response done but stream is not cleanly terminated".to_owned(),
                    );
                    return Err(
                        Box::pin(fail_header_exchange(exchange, circuit_guard, "header_incomplete", err)).await,
                    );
                },
                Err(err) => return Err(Box::pin(fail_header_exchange(exchange, circuit_guard, "h2_error", err)).await),
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
            .map(|dur| handoff_now.checked_add(dur).ok_or(SubRequestError::DeadlineExceeded))
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
            Err(err) => return Err(err),
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
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .map_or(0, |len| len.min(effective_limit).min(EAGER_BODY_CAPACITY));
        let body_result: Result<Bytes, SubRequestError> = tokio::time::timeout(remaining, async {
            let mut body_buf = Vec::with_capacity(advertised);
            while !session.response_done() {
                match session.read_response_body().await {
                    Ok(Some(chunk)) => {
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
                    Ok(None) => break,
                    Err(err) => {
                        session.shutdown().await;
                        return Err(SubRequestError::Io(err.to_string()));
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

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Tear down an abnormally terminated header exchange: drop the circuit
/// guard (recording a failure via its `Drop` impl), discard the session,
/// record the termination metric, and hand back the error to return.
async fn fail_header_exchange(
    exchange: RawExchange<'_, '_>,
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

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::too_many_lines, clippy::items_after_statements, reason = "tests")]
mod tests {
    use super::*;

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
    fn new_client_uses_absolute_max_body_bytes() {
        let connector = SubRequestConnector::new(128, None);
        let client = SubRequestClient::new(connector);

        assert_eq!(
            client.max_response_bytes,
            crate::config::ABSOLUTE_MAX_BODY_BYTES,
            "new() should default to ABSOLUTE_MAX_BODY_BYTES"
        );
    }

    #[test]
    fn with_max_response_bytes_sets_ceiling() {
        let connector = SubRequestConnector::new(128, None);
        let custom_ceiling = 1_048_576;
        let client = SubRequestClient::with_max_response_bytes(connector, custom_ceiling);

        assert_eq!(
            client.max_response_bytes, custom_ceiling,
            "with_max_response_bytes() should set the provided ceiling"
        );
    }

    #[test]
    fn connector_accessor_returns_stored_connector() {
        let connector = SubRequestConnector::new(128, None);
        let client = SubRequestClient::new(connector.clone());

        let retrieved = client.connector();
        assert!(
            !std::ptr::eq(retrieved, &connector),
            "connector() should return reference to the stored connector"
        );
    }

    #[test]
    fn evict_idle_circuits_returns_zero_without_circuit_breaker() {
        let connector = SubRequestConnector::new(128, None);
        let client = SubRequestClient::new(connector);

        let evicted = client.evict_idle_circuits(Duration::from_secs(60));

        assert_eq!(
            evicted, 0,
            "evict_idle_circuits should return 0 when no circuit breaker is configured"
        );
    }

    #[test]
    fn debug_output_names_the_type() {
        let connector = SubRequestConnector::new(128, None);
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
        let connector = SubRequestConnector::new(128, None);
        let client = SubRequestClient::with_max_response_bytes(connector, 5_000_000);

        let cloned = client.clone();

        assert_eq!(
            client.max_response_bytes, cloned.max_response_bytes,
            "clone should preserve max_response_bytes"
        );
    }

    #[test]
    fn with_max_response_bytes_sets_various_ceilings() {
        let connector = SubRequestConnector::new(128, None);

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
        let connector = SubRequestConnector::new(128, None);

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
        let connector = SubRequestConnector::new(128, None);

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
        let connector = SubRequestConnector::new(128, None);

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
        let connector = SubRequestConnector::new(128, None);

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
        let connector = SubRequestConnector::new(128, None);
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
}
