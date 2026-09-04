// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Provider-neutral proxy error response formatting contracts.

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderValue;

// -----------------------------------------------------------------------------
// ErrorResponseContext
// -----------------------------------------------------------------------------

/// Classified proxy error information supplied to a custom formatter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorResponseContext<'a> {
    /// Machine-readable error code.
    pub code: &'a str,

    /// Human-readable error message.
    pub message: &'a str,

    /// HTTP status code returned to the downstream client.
    pub status: u16,
}

impl<'a> ErrorResponseContext<'a> {
    /// Create a classified proxy error context.
    pub const fn new(code: &'a str, message: &'a str, status: u16) -> Self {
        Self { code, message, status }
    }
}

// -----------------------------------------------------------------------------
// FormattedErrorResponse
// -----------------------------------------------------------------------------

/// Body and content type produced by an [`ErrorResponseFormatter`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormattedErrorResponse {
    /// Serialized downstream response body.
    pub body: Bytes,

    /// Media type describing [`body`].
    ///
    /// [`body`]: Self::body
    pub content_type: HeaderValue,
}

impl FormattedErrorResponse {
    /// Create a formatted proxy error response.
    pub fn new(body: impl Into<Bytes>, content_type: HeaderValue) -> Self {
        Self {
            body: body.into(),
            content_type,
        }
    }
}

// -----------------------------------------------------------------------------
// ErrorResponseFormatter
// -----------------------------------------------------------------------------

/// Formats classified proxy failures for a downstream API protocol.
///
/// External filters can install an [`ErrorResponseFormatterHandle`] in
/// [`HttpFilterContext::extensions`] during request processing. The protocol
/// layer invokes it only when synthesizing a fatal proxy response. When no
/// formatter is installed, Praxis emits RFC 9457 Problem Details.
///
/// [`HttpFilterContext::extensions`]: crate::HttpFilterContext::extensions
pub trait ErrorResponseFormatter: Send + Sync {
    /// Format a classified proxy failure.
    fn format(&self, context: &ErrorResponseContext<'_>) -> FormattedErrorResponse;
}

// -----------------------------------------------------------------------------
// ErrorResponseFormatterHandle
// -----------------------------------------------------------------------------

/// Cloneable request-extension value wrapping a custom error formatter.
#[derive(Clone)]
pub struct ErrorResponseFormatterHandle {
    /// Shared custom formatter implementation.
    formatter: Arc<dyn ErrorResponseFormatter>,
}

impl ErrorResponseFormatterHandle {
    /// Wrap a custom error formatter for insertion into request extensions.
    pub fn new(formatter: impl ErrorResponseFormatter + 'static) -> Self {
        Self {
            formatter: Arc::new(formatter),
        }
    }

    /// Format a classified proxy failure with the wrapped formatter.
    pub fn format(&self, context: &ErrorResponseContext<'_>) -> FormattedErrorResponse {
        self.formatter.format(context)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn context_constructor_sets_fields() {
        let context = ErrorResponseContext::new("upstream_error", "Upstream error", 502);

        assert_eq!(context.code, "upstream_error");
        assert_eq!(context.message, "Upstream error");
        assert_eq!(context.status, 502);
    }

    #[test]
    fn formatter_handle_delegates_to_external_formatter() {
        let formatter = ErrorResponseFormatterHandle::new(TestFormatter);
        let context = ErrorResponseContext::new("upstream_error", "Upstream error", 502);

        let response = formatter.format(&context);

        assert_eq!(
            response.body,
            Bytes::from_static(br#"{"code":"upstream_error","status":502}"#)
        );
        assert_eq!(
            response.content_type,
            HeaderValue::from_static("application/vnd.praxis.test+json")
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    struct TestFormatter;

    impl ErrorResponseFormatter for TestFormatter {
        fn format(&self, context: &ErrorResponseContext<'_>) -> FormattedErrorResponse {
            FormattedErrorResponse::new(
                format!(r#"{{"code":"{}","status":{}}}"#, context.code, context.status),
                HeaderValue::from_static("application/vnd.praxis.test+json"),
            )
        }
    }
}
