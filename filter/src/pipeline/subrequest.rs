// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
pub(crate) struct SubRequest {
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
pub(crate) struct SubResponse {
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
pub(crate) struct IterationState {
    /// The original client request, preserved for reference.
    pub original_request: SubRequest,

    /// The most recent sub-request response.
    pub previous_response: Option<SubResponse>,

    /// Named data accumulator for cross-step state (e.g.,
    /// tool results, conversation history).
    pub accumulator: HashMap<String, Bytes>,

    /// Current iteration count (zero-indexed).
    pub iteration: u32,

    /// Maximum allowed iterations.
    pub max_iterations: u32,

    /// Overall deadline for the entire loop.
    pub deadline: std::time::Instant,

    /// Maximum response body bytes per sub-request.
    pub max_response_bytes: usize,

    /// Current iterative depth for loop prevention.
    pub depth: u8,
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
#[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
#[expect(clippy::large_futures, reason = "Pingora session types are large")]
#[expect(clippy::too_many_lines, reason = "sequential HTTP exchange steps")]
pub(crate) async fn execute(
    connector: &SubRequestConnector,
    peer: &HttpPeer,
    request: &SubRequest,
    max_response_bytes: usize,
    timeout: Duration,
) -> Result<SubResponse, SubRequestError> {
    let (mut session, reused) = connector
        .connector()
        .get_http_session(peer)
        .await
        .map_err(|e| SubRequestError::Connect(e.to_string()))?;

    debug!(
        peer = %peer.address(),
        reused,
        method = %request.method,
        uri = %request.uri,
        "sub-request: connected"
    );

    session.set_read_timeout(Some(timeout));
    session.set_write_timeout(Some(timeout));

    let path = request
        .uri
        .path_and_query()
        .map_or(b"/".as_slice(), |pq| pq.as_str().as_bytes());
    let mut req_header = pingora_http::RequestHeader::build(request.method.clone(), path, None)
        .map_err(|e| SubRequestError::Io(e.to_string()))?;

    for (name, value) in &request.headers {
        let _append = req_header.append_header(name.clone(), value.clone());
    }

    if !request.body.is_empty() {
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
}
