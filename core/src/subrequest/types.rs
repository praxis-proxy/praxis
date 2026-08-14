// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use thiserror::Error;
use tokio::sync::OwnedSemaphorePermit;

use super::internals::SubRequestConnector;

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
    /// [`super::SubRequestClient::execute`] to inject metadata that must
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
        if super::internals::is_transport_header(&name) {
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

    /// The upstream stopped sending data for longer than the idle timeout.
    #[error("sub-request stream idle timeout ({idle_timeout:?} with no data)")]
    StreamIdleTimeout {
        /// The configured idle timeout that was exceeded.
        idle_timeout: Duration,
    },

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
// Streaming response types
// ---------------------------------------------------------------------------

/// Limits governing a streaming sub-request response body.
#[derive(Clone, Debug)]
pub struct StreamLimits {
    /// Maximum wait for the next upstream chunk. Applied per
    /// `next_chunk()` call. Required.
    pub idle_timeout: Duration,

    /// Optional absolute stream lifetime measured from header receipt.
    /// `None` means no duration limit.
    pub max_stream_duration: Option<Duration>,

    /// Optional cumulative byte limit across all chunks. The buffered
    /// `max_response_bytes` ceiling is not applied to streaming
    /// responses — only this explicit limit constrains the stream.
    /// `None` means no byte limit.
    pub max_total_bytes: Option<usize>,
}

/// A streaming sub-request response with headers and an opaque body handle.
///
/// The body handle owns the live Pingora session, admission permit,
/// and transport deadlines. It does not borrow `SubRequestClient`
/// or any other external state.
pub struct StreamingSubResponse {
    /// HTTP status code.
    pub status: u16,

    /// Response headers (sanitized).
    pub headers: HeaderMap,

    /// Opaque streaming body handle.
    pub body: SubResponseBody,
}

/// Opaque handle to a streaming sub-request response body.
///
/// Pull-based: call [`next_chunk()`](Self::next_chunk) to receive
/// the next body chunk. Returns `Ok(None)` at clean EOF.
///
/// Owns the live Pingora HTTP session, admission permit, connector
/// (for session release), and all streaming deadlines. No background
/// tasks or channels — downstream backpressure naturally paces
/// upstream reads.
pub struct SubResponseBody {
    /// Live Pingora HTTP session.
    pub(super) session: Option<pingora_core::protocols::http::client::HttpSession<()>>,
    /// Peer address for connection pooling.
    pub(super) peer: Option<pingora_core::upstreams::peer::HttpPeer>,
    /// Connector for session release.
    pub(super) connector: Option<SubRequestConnector>,
    /// Admission permit.
    pub(super) permit: Option<OwnedSemaphorePermit>,
    /// Operator-configured per-read timeout from the peer.
    pub(super) read_timeout: Option<Duration>,
    /// Per-chunk idle timeout.
    pub(super) idle_timeout: Duration,
    /// Optional absolute stream deadline.
    pub(super) stream_deadline: Option<tokio::time::Instant>,
    /// Optional cumulative byte limit.
    pub(super) max_total_bytes: Option<usize>,
    /// Total bytes received so far.
    pub(super) received_bytes: usize,
    /// Number of chunks received so far.
    pub(super) chunk_count: u64,
    /// When the stream started (for metrics).
    pub(super) stream_started_at: tokio::time::Instant,
    /// Whether the stream is done.
    pub(super) done: bool,
}
