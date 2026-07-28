// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Sub-request execution for the iterative request router.
//!
//! Provides the types and executor function that let the
//! `iterative_request_router` filter make HTTP calls using
//! Pingora's native [`Connector`] — getting connection pooling,
//! HTTP/2, and TLS without a separate HTTP stack.
//!
//! [`Connector`]: pingora_core::connectors::http::Connector

use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use pingora_core::upstreams::peer::{HttpPeer, Peer as _};
use praxis_core::subrequest::SubRequestConnector;
use thiserror::Error;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum response body size (10 MiB) to prevent unbounded
/// memory growth from sub-request responses.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 10_485_760; // 10 MiB

/// Reserved header injected into sub-requests for loop prevention.
pub(crate) const DEPTH_HEADER: &str = "x-praxis-iterative-depth";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An outbound HTTP request for a sub-request exchange.
#[derive(Clone, Debug)]
pub struct SubRequest {
    /// HTTP method.
    pub method: http::Method,

    /// Request URI (path + query).
    pub uri: http::Uri,

    /// Request headers.
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

/// Per-request accumulator for state that persists across
/// iterations of the iterative request router.
///
/// Step chain filters can access this via
/// `ctx.extensions.get::<IterationState>()` to read the
/// previous response and accumulated cross-step data.
#[derive(Clone, Debug)]
pub struct IterationState {
    /// The original client request, preserved for reference.
    pub original_request: SubRequest,

    /// The most recent sub-request response.
    pub previous_response: Option<SubResponse>,

    /// Named data accumulator for cross-step state (e.g.,
    /// tool results, conversation history).
    pub accumulator: HashMap<String, Bytes>,

    /// Current iteration count (zero-indexed).
    pub(crate) iteration: u32,

    /// Maximum allowed iterations.
    pub(crate) max_iterations: u32,

    /// Overall deadline for the entire loop.
    pub(crate) deadline: std::time::Instant,

    /// Maximum response body bytes per sub-request.
    pub(crate) max_response_bytes: usize,

    /// Current iterative depth for loop prevention.
    pub(crate) depth: u8,
}

impl IterationState {
    /// Current iteration count, starting at zero.
    #[must_use]
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Maximum iterations configured for this router.
    #[must_use]
    pub fn max_iterations(&self) -> u32 {
        self.max_iterations
    }

    /// Overall deadline shared by every step.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    /// Maximum buffered response bytes per step.
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Current nesting depth used for loop prevention.
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Approximate bytes retained by the framework-owned iteration state.
    ///
    /// Counts request and response metadata, bodies, and accumulator
    /// entries. Container allocation overhead is intentionally excluded;
    /// configured limits bound attacker-controlled payload bytes.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        subrequest_bytes(&self.original_request)
            .saturating_add(self.previous_response.as_ref().map_or(0, subresponse_bytes))
            .saturating_add(
                self.accumulator
                    .iter()
                    .map(|(key, value)| key.len().saturating_add(value.len()))
                    .fold(0, usize::saturating_add),
            )
    }
}

/// Replacement body for the next iterative-router step.
///
/// External step filters can insert this into
/// [`HttpFilterContext::extensions`] to replace the body inherited
/// from the current step.
///
/// [`HttpFilterContext::extensions`]: crate::HttpFilterContext::extensions
#[derive(Clone, Debug)]
pub struct NextIterationBody(pub Bytes);

/// Approximate retained bytes for one request snapshot.
fn subrequest_bytes(request: &SubRequest) -> usize {
    request
        .method
        .as_str()
        .len()
        .saturating_add(
            request
                .uri
                .path_and_query()
                .map_or(0, |path_and_query| path_and_query.as_str().len()),
        )
        .saturating_add(header_bytes(&request.headers))
        .saturating_add(request.body.len())
}

/// Approximate retained bytes for one response snapshot.
fn subresponse_bytes(response: &SubResponse) -> usize {
    header_bytes(&response.headers).saturating_add(response.body.len())
}

/// Bytes retained by header names and values.
fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len().saturating_add(value.as_bytes().len()))
        .fold(0, usize::saturating_add)
}

/// Errors from sub-request execution.
#[derive(Debug, Error)]
pub(crate) enum SubRequestError {
    /// Failed to connect to the upstream.
    #[error("sub-request connect error: {0}")]
    Connect(String),

    /// Failed to write the request or read the response.
    #[error("sub-request I/O error: {0}")]
    Io(String),

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

    /// The overall deadline expired.
    #[error("sub-request deadline exceeded")]
    DeadlineExceeded,
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Execute a sub-request using Pingora's [`Connector`].
///
/// Connects to `peer`, sends `request`, reads the full response
/// (bounded by `max_response_bytes`), and returns a
/// [`SubResponse`].
///
/// # Errors
///
/// Returns [`SubRequestError`] on connection failure, I/O error,
/// response body exceeding the size limit, or deadline expiry.
///
/// [`Connector`]: pingora_core::connectors::http::Connector
pub(crate) async fn execute(
    connector: &SubRequestConnector,
    peer: &HttpPeer,
    request: &SubRequest,
    max_response_bytes: usize,
    timeout: Duration,
) -> Result<SubResponse, SubRequestError> {
    let mut bounded_peer = peer.clone();
    clamp_peer_timeouts(&mut bounded_peer, timeout);

    let _permit = connector.acquire_permit().await;

    tokio::time::timeout(
        timeout,
        Box::pin(execute_inner(
            connector,
            &bounded_peer,
            request,
            max_response_bytes,
            timeout,
        )),
    )
    .await
    .map_err(|_elapsed| SubRequestError::DeadlineExceeded)?
}

/// Execute the exchange under the deadline enforced by [`execute`].
#[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
#[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
async fn execute_inner(
    connector: &SubRequestConnector,
    peer: &HttpPeer,
    request: &SubRequest,
    max_response_bytes: usize,
    timeout: Duration,
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
        .map_err(|e| SubRequestError::Io(e.to_string()))?;

    for (name, value) in &request.headers {
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

/// Methods whose empty payload is commonly rejected without explicit framing.
fn empty_body_needs_framing(method: &http::Method) -> bool {
    matches!(*method, http::Method::POST | http::Method::PUT | http::Method::PATCH)
}

/// Ensure HTTP/1.1 virtual hosting and HTTP/2 `:authority` are valid.
fn ensure_host_header(request: &mut pingora_http::RequestHeader, peer: &HttpPeer) -> Result<(), SubRequestError> {
    if !request.headers.contains_key(http::header::HOST) {
        request
            .insert_header(http::header::HOST, peer.address().to_string())
            .map_err(|error| SubRequestError::Io(error.to_string()))?;
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

/// Returns the default maximum response body size for sub-requests.
pub(crate) fn default_max_response_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BYTES
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn empty_entity_methods_get_explicit_framing() {
        assert!(empty_body_needs_framing(&http::Method::POST));
        assert!(empty_body_needs_framing(&http::Method::PUT));
        assert!(empty_body_needs_framing(&http::Method::PATCH));
        assert!(!empty_body_needs_framing(&http::Method::GET));
        assert!(!empty_body_needs_framing(&http::Method::HEAD));
    }

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

    #[test]
    fn iteration_state_default_depth() {
        let state = IterationState {
            original_request: SubRequest {
                method: http::Method::GET,
                uri: "/".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
            previous_response: None,
            accumulator: HashMap::new(),
            iteration: 0,
            max_iterations: 10,
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            depth: 0,
        };
        assert_eq!(state.depth, 0, "initial depth should be zero");
        assert_eq!(state.iteration, 0, "initial iteration should be zero");
    }

    #[test]
    fn default_max_response_bytes_is_10_mib() {
        assert_eq!(default_max_response_bytes(), 10_485_760, "default max should be 10 MiB");
    }

    #[test]
    fn retained_bytes_counts_payloads_headers_and_accumulator() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "value".parse().unwrap());
        let mut accumulator = HashMap::new();
        accumulator.insert("key".to_owned(), Bytes::from_static(b"data"));
        let state = IterationState {
            original_request: SubRequest {
                method: http::Method::POST,
                uri: "/path".parse().unwrap(),
                headers,
                body: Bytes::from_static(b"request"),
            },
            previous_response: Some(SubResponse {
                status: 200,
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"response"),
            }),
            accumulator,
            iteration: 1,
            max_iterations: 10,
            deadline: std::time::Instant::now() + Duration::from_secs(1),
            max_response_bytes: 1024,
            depth: 0,
        };

        assert_eq!(state.retained_bytes(), 42, "all retained payloads should be counted");
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

    #[tokio::test]
    async fn deadline_bounds_the_complete_exchange() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let connector = SubRequestConnector::new(1, None);
        let peer = HttpPeer::new(address.to_string(), false, String::new());
        let request = SubRequest {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };

        let started = std::time::Instant::now();
        let result = Box::pin(execute(&connector, &peer, &request, 1024, Duration::from_millis(10))).await;
        let elapsed = started.elapsed();
        backend.abort();

        assert!(result.is_err(), "a backend that never responds must time out");
        assert!(
            elapsed < Duration::from_millis(500),
            "exchange exceeded its deadline: {elapsed:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "comprehensive clone verification")]
    fn iteration_state_clone_with_populated_fields() {
        let mut accumulator = HashMap::new();
        accumulator.insert("key".to_owned(), Bytes::from_static(b"value"));

        let prev = SubResponse {
            status: 200,
            headers: {
                let mut h = HeaderMap::new();
                h.insert("content-type", "application/json".parse().unwrap());
                h
            },
            body: Bytes::from_static(b"previous response body"),
        };

        let state = IterationState {
            original_request: SubRequest {
                method: http::Method::POST,
                uri: "/v1/chat".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::from_static(b"original body"),
            },
            previous_response: Some(prev),
            accumulator,
            iteration: 3,
            max_iterations: 10,
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            max_response_bytes: 1024,
            depth: 2,
        };

        let cloned = state.clone();
        assert_eq!(cloned.iteration, 3, "iteration should survive clone");
        assert_eq!(cloned.depth, 2, "depth should survive clone");
        assert_eq!(
            cloned.max_response_bytes, 1024,
            "max_response_bytes should survive clone"
        );
        assert!(
            cloned.previous_response.is_some(),
            "previous_response should survive clone"
        );
        assert_eq!(
            cloned.previous_response.as_ref().unwrap().body,
            Bytes::from_static(b"previous response body"),
            "previous response body should survive clone"
        );
        assert_eq!(
            cloned.accumulator.get("key").unwrap(),
            &Bytes::from_static(b"value"),
            "accumulator entry should survive clone"
        );
        assert_eq!(
            cloned.original_request.body,
            Bytes::from_static(b"original body"),
            "original request body should survive clone"
        );
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
}
