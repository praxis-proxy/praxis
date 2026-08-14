// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Sub-request and sub-response data types, error enum, and
//! framework header injection.

use bytes::Bytes;
use http::HeaderMap;
use thiserror::Error;

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
// Transport header classification
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

/// Whether a header is a transport-level header that must not be
/// injected via framework metadata.
pub(super) fn is_transport_header(name: &http::header::HeaderName) -> bool {
    HOP_BY_HOP_HEADERS.iter().any(|h| *h == name.as_str()) || name == http::header::CONTENT_LENGTH
}
