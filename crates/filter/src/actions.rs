// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Filter return types: continue, reject, or return a terminal response.

use std::fmt;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{FilterError, RequestExtensions};

// -----------------------------------------------------------------------------
// Streaming terminal response
// -----------------------------------------------------------------------------

/// Opaque, pull-based body for a terminal streaming response.
///
/// Implementations own any inner transport and response-filter continuation
/// state. The protocol layer pulls at most one chunk at a time and does not
/// read the next chunk until the previous downstream write completes.
#[async_trait]
pub trait StreamingResponseBody: Send + 'static {
    /// Pull the next filtered body chunk.
    ///
    /// `Ok(None)` means clean completion. Implementations must run their
    /// owned completion lifecycle exactly once before returning it.
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError>;

    /// Suppress the unread body for HEAD, 204, or 304 delivery.
    ///
    /// Implementations cancel their underlying source while still running
    /// any owned clean-suppression lifecycle exactly once.
    async fn suppress(&mut self) -> Result<(), FilterError>;

    /// Abort the source and release all owned resources.
    ///
    /// This operation must be idempotent.
    async fn cancel(&mut self);

    /// Exchange request extensions with the protocol lifecycle owner.
    ///
    /// Most streaming bodies do not own filter extensions and use this
    /// default no-op. Iterative sessions override it so the same extension
    /// set can move between step filters and parent response filters without
    /// cloning type-erased values.
    #[doc(hidden)]
    fn swap_extensions(&mut self, _extensions: &mut RequestExtensions) {}
}

/// A terminal response whose body is delivered incrementally.
#[must_use]
pub struct StreamingTerminalResponse {
    /// HTTP status code.
    pub status: u16,

    /// Response headers available before downstream commitment.
    pub headers: http::HeaderMap,

    /// Opaque pull-based body and its owned continuation state.
    pub body: Box<dyn StreamingResponseBody>,
}

impl StreamingTerminalResponse {
    /// Create a streaming terminal response.
    ///
    /// # Panics
    ///
    /// Panics if `code` is outside 200..=599. Informational responses cannot
    /// terminate a request.
    pub fn new(code: u16, body: Box<dyn StreamingResponseBody>) -> Self {
        assert!(
            (200..=599).contains(&code),
            "streaming terminal status must be 200..=599, got {code}"
        );
        Self {
            status: code,
            headers: http::HeaderMap::new(),
            body,
        }
    }

    /// Set the response headers.
    pub fn with_headers(mut self, headers: http::HeaderMap) -> Self {
        self.headers = headers;
        self
    }
}

impl fmt::Debug for StreamingTerminalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingTerminalResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &"<opaque streaming body>")
            .finish()
    }
}

// -----------------------------------------------------------------------------
// FilterAction
// -----------------------------------------------------------------------------

/// Result of a filter's request or response processing.
///
/// ```
/// use praxis_filter::{FilterAction, Rejection, TerminalResponse};
///
/// let action = FilterAction::Continue;
/// assert!(matches!(action, FilterAction::Continue));
///
/// let reject = FilterAction::Reject(Rejection::status(403));
/// assert!(matches!(reject, FilterAction::Reject(r) if r.status == 403));
///
/// let terminal = FilterAction::TerminalResponse(Box::new(TerminalResponse::new(200)));
/// assert!(matches!(terminal, FilterAction::TerminalResponse(r) if r.status == 200));
///
/// let release = FilterAction::Release;
/// assert!(matches!(release, FilterAction::Release));
///
/// let body_done = FilterAction::BodyDone;
/// assert!(matches!(body_done, FilterAction::BodyDone));
/// ```
#[derive(Debug)]
#[must_use]
pub enum FilterAction {
    /// Continue to the next filter in the pipeline.
    Continue,

    /// Stop processing and respond with the given rejection.
    Reject(Rejection),

    /// Return a complete response to the client, running
    /// response-phase filters for all filters that already
    /// executed during the request phase.
    ///
    /// Unlike [`Reject`], this preserves downstream keepalive
    /// and is intended for filters that produce a real response
    /// (e.g. the iterative request router returning an upstream
    /// response). Response-header and response-body filters
    /// execute before the response is sent, so preceding
    /// observability filters see the terminal response.
    ///
    /// Only valid in request-phase filters.
    ///
    /// [`Reject`]: FilterAction::Reject
    TerminalResponse(Box<TerminalResponse>),

    /// Return a streaming response to the client.
    ///
    /// Response-header filters run before commitment. After commitment, the
    /// protocol pulls one chunk, runs response-body filters, awaits the
    /// downstream write, and only then requests the next chunk. Source or
    /// filter failures after commitment terminate the downstream stream and
    /// cannot produce a replacement response.
    ///
    /// Only valid in request-phase filters.
    StreamingTerminalResponse(Box<StreamingTerminalResponse>),

    /// Signal that accumulated body data ([`StreamBuffer`] mode)
    /// should be forwarded to upstream. After release, remaining
    /// chunks flow through in stream mode.
    ///
    /// In non-StreamBuffer contexts (including the TCP pipeline),
    /// behaves as [`Continue`].
    ///
    /// [`StreamBuffer`]: crate::BodyMode::StreamBuffer
    /// [`Continue`]: FilterAction::Continue
    Release,

    /// Skip this filter for remaining body chunks.
    ///
    /// The filter has completed its body inspection and does
    /// not need to see further chunks. The pipeline continues
    /// calling other body filters; only this filter is skipped.
    ///
    /// In non-body contexts (request and response phases),
    /// behaves as [`Continue`].
    ///
    /// [`Continue`]: FilterAction::Continue
    BodyDone,
}

// -----------------------------------------------------------------------------
// Rejection
// -----------------------------------------------------------------------------

/// A filter rejection response.
///
/// ```
/// use praxis_filter::Rejection;
///
/// // Simple status-only rejection:
/// let r = Rejection::status(403);
/// assert_eq!(r.status, 403);
/// assert!(r.headers.is_empty());
/// assert!(r.body.is_none());
///
/// // Rich rejection with headers and body:
/// let r = Rejection::status(429)
///     .with_header("Retry-After", "60")
///     .with_body(b"rate limit exceeded".as_slice());
/// assert_eq!(r.status, 429);
/// assert_eq!(r.headers.len(), 1);
/// assert!(r.body.is_some());
/// ```
#[derive(Debug)]
#[must_use]
pub struct Rejection {
    /// Response body.
    pub body: Option<Bytes>,

    /// Response headers.
    pub headers: Vec<(String, String)>,

    /// Byte-preserving response headers.
    ///
    /// Used when proxying an existing response whose values may contain
    /// opaque bytes that are valid in HTTP but are not UTF-8.
    pub header_map: Option<Box<http::HeaderMap>>,

    /// Keep the downstream connection reusable after this response.
    ///
    /// Short-circuit rejections default to closing because the request body
    /// may be unread. Filters that have consumed the complete body and are
    /// returning a normal terminal response may opt into reuse.
    pub preserve_keepalive: bool,

    /// HTTP status code.
    pub status: u16,
}

impl Rejection {
    /// Create a rejection with the given status code.
    ///
    /// # Panics
    ///
    /// Panics if `code` is outside the valid HTTP status range
    /// (100..=599).
    pub fn status(code: u16) -> Self {
        assert!(
            (100..=599).contains(&code),
            "HTTP status code must be 100..=599, got {code}"
        );
        Self {
            status: code,
            headers: Vec::new(),
            header_map: None,
            body: None,
            preserve_keepalive: false,
        }
    }

    /// Set the body of the rejection response.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Add a header to the rejection response.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Preserve downstream keepalive after sending this complete response.
    pub fn preserving_keepalive(mut self) -> Self {
        self.preserve_keepalive = true;
        self
    }
}

// -----------------------------------------------------------------------------
// TerminalResponse
// -----------------------------------------------------------------------------

/// A complete response produced by a request-phase filter.
///
/// Unlike [`Rejection`], a terminal response preserves downstream
/// keepalive and triggers the response-header and response-body
/// filter lifecycle for filters that already executed during the
/// request phase.
///
/// ```
/// use praxis_filter::TerminalResponse;
///
/// let r = TerminalResponse::new(200)
///     .with_headers(http::HeaderMap::new())
///     .with_body(b"ok".as_slice());
/// assert_eq!(r.status, 200);
/// assert!(r.body.is_some());
/// ```
#[derive(Debug)]
#[must_use]
pub struct TerminalResponse {
    /// HTTP status code.
    pub status: u16,

    /// Response headers.
    pub headers: http::HeaderMap,

    /// Buffered response body.
    pub body: Option<Bytes>,
}

impl TerminalResponse {
    /// Create a terminal response with the given status code.
    ///
    /// # Panics
    ///
    /// Panics if `code` is outside the valid terminal status range
    /// (200..=599). Informational (1xx) statuses cannot be terminal
    /// because they require a subsequent final response.
    pub fn new(code: u16) -> Self {
        assert!(
            (200..=599).contains(&code),
            "terminal status must be 200..=599 (1xx is informational, not final), got {code}"
        );
        Self {
            status: code,
            headers: http::HeaderMap::new(),
            body: None,
        }
    }

    /// Set the headers of the terminal response.
    pub fn with_headers(mut self, headers: http::HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Set the body of the terminal response.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }
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
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn rejection_status_defaults() {
        let r = Rejection::status(404);
        assert_eq!(r.status, 404, "status should match constructor arg");
        assert!(r.headers.is_empty(), "headers should default to empty");
        assert!(
            r.header_map.is_none(),
            "byte-preserving headers should default to empty"
        );
        assert!(r.body.is_none(), "body should default to None");
        assert!(!r.preserve_keepalive, "rejections should close by default");
    }

    #[test]
    fn rejection_status_boundary_100() {
        let r = Rejection::status(100);
        assert_eq!(r.status, 100, "100 is a valid HTTP status");
    }

    #[test]
    fn rejection_status_boundary_599() {
        let r = Rejection::status(599);
        assert_eq!(r.status, 599, "599 is a valid HTTP status");
    }

    #[test]
    #[should_panic(expected = "HTTP status code must be 100..=599")]
    fn rejection_status_zero_panics() {
        let _r = Rejection::status(0);
    }

    #[test]
    #[should_panic(expected = "HTTP status code must be 100..=599")]
    fn rejection_status_600_panics() {
        let _r = Rejection::status(600);
    }

    #[test]
    fn rejection_with_header_appends() {
        let r = Rejection::status(403)
            .with_header("X-Reason", "forbidden")
            .with_header("X-Request-Id", "abc");
        assert_eq!(r.headers.len(), 2, "should have two appended headers");
        assert_eq!(
            r.headers[0],
            ("X-Reason".into(), "forbidden".into()),
            "first header should match"
        );
        assert_eq!(
            r.headers[1],
            ("X-Request-Id".into(), "abc".into()),
            "second header should match"
        );
    }

    #[test]
    fn preserving_keepalive_is_explicit() {
        let rejection = Rejection::status(200).preserving_keepalive();
        assert!(rejection.preserve_keepalive);
    }

    #[test]
    fn rejection_with_body_sets_bytes() {
        let r = Rejection::status(400).with_body(b"bad request".as_slice());
        assert_eq!(
            r.body.unwrap(),
            Bytes::from_static(b"bad request"),
            "body should contain provided bytes"
        );
    }

    #[test]
    fn filter_action_continue_variant() {
        assert!(
            matches!(FilterAction::Continue, FilterAction::Continue),
            "Continue should match Continue"
        );
    }

    #[test]
    fn filter_action_reject_carries_rejection() {
        let action = FilterAction::Reject(Rejection::status(503));
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "Reject should carry rejection with status 503"
        );
    }

    #[test]
    fn terminal_response_200() {
        let r = TerminalResponse::new(200);
        assert_eq!(r.status, 200);
    }

    #[test]
    fn terminal_response_599() {
        let r = TerminalResponse::new(599);
        assert_eq!(r.status, 599);
    }

    #[test]
    #[should_panic(expected = "terminal status must be 200..=599")]
    fn terminal_response_1xx_panics() {
        let _r = TerminalResponse::new(100);
    }

    #[test]
    #[should_panic(expected = "terminal status must be 200..=599")]
    fn terminal_response_199_panics() {
        let _r = TerminalResponse::new(199);
    }

    #[test]
    fn filter_action_release_variant() {
        assert!(
            matches!(FilterAction::Release, FilterAction::Release),
            "Release should match Release"
        );
    }

    #[test]
    fn filter_action_body_done_variant() {
        assert!(
            matches!(FilterAction::BodyDone, FilterAction::BodyDone),
            "BodyDone should match BodyDone"
        );
    }

    // ---------------------------------------------------------------------------
    // Test Utilities for Streaming Types
    // ---------------------------------------------------------------------------

    struct NullStreamBody;

    #[async_trait]
    impl StreamingResponseBody for NullStreamBody {
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
            Ok(None)
        }

        async fn suppress(&mut self) -> Result<(), FilterError> {
            Ok(())
        }

        async fn cancel(&mut self) {}
    }

    struct SingleChunkStreamBody(Option<Bytes>);

    #[async_trait]
    impl StreamingResponseBody for SingleChunkStreamBody {
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
            Ok(self.0.take())
        }

        async fn suppress(&mut self) -> Result<(), FilterError> {
            self.0 = None;
            Ok(())
        }

        async fn cancel(&mut self) {
            self.0 = None;
        }
    }

    // ---------------------------------------------------------------------------
    // Streaming Terminal Response Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn streaming_terminal_response_200() {
        let r = StreamingTerminalResponse::new(200, Box::new(NullStreamBody));
        assert_eq!(r.status, 200, "status should be 200");
    }

    #[test]
    fn streaming_terminal_response_599() {
        let r = StreamingTerminalResponse::new(599, Box::new(NullStreamBody));
        assert_eq!(r.status, 599, "599 is the upper boundary");
    }

    #[test]
    #[should_panic(expected = "streaming terminal status must be 200..=599")]
    fn streaming_terminal_response_1xx_panics() {
        let _r = StreamingTerminalResponse::new(100, Box::new(NullStreamBody));
    }

    #[test]
    #[should_panic(expected = "streaming terminal status must be 200..=599")]
    fn streaming_terminal_response_199_panics() {
        let _r = StreamingTerminalResponse::new(199, Box::new(NullStreamBody));
    }

    #[test]
    fn streaming_terminal_response_with_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-custom", "value".parse().unwrap());
        let r = StreamingTerminalResponse::new(200, Box::new(NullStreamBody)).with_headers(headers);
        assert_eq!(
            r.headers.get("x-custom").unwrap(),
            "value",
            "custom header should be set"
        );
    }

    #[tokio::test]
    async fn null_stream_body_returns_none() {
        let mut body = NullStreamBody;
        let chunk = body.next_chunk().await.unwrap();
        assert!(chunk.is_none(), "NullStreamBody should return None");
    }

    #[tokio::test]
    async fn single_chunk_stream_body_yields_then_none() {
        let mut body = SingleChunkStreamBody(Some(Bytes::from_static(b"hello")));
        let first = body.next_chunk().await.unwrap();
        assert_eq!(
            first.unwrap(),
            Bytes::from_static(b"hello"),
            "first chunk should contain the payload"
        );
        let second = body.next_chunk().await.unwrap();
        assert!(second.is_none(), "second call should return None");
    }

    #[test]
    fn streaming_terminal_debug_format() {
        let r = StreamingTerminalResponse::new(200, Box::new(NullStreamBody));
        let debug = format!("{r:?}");
        assert!(
            debug.contains("StreamingTerminalResponse"),
            "debug should contain type name"
        );
        assert!(debug.contains("200"), "debug should contain status code");
        assert!(debug.contains("opaque"), "debug should indicate opaque body");
    }

    #[test]
    fn filter_action_streaming_terminal_variant() {
        let action = FilterAction::StreamingTerminalResponse(Box::new(StreamingTerminalResponse::new(
            200,
            Box::new(NullStreamBody),
        )));
        assert!(
            matches!(action, FilterAction::StreamingTerminalResponse(_)),
            "should match StreamingTerminalResponse variant"
        );
    }
}
