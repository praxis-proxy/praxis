// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Pre-computed body processing capabilities for filter pipelines.

use super::BodyMode;

// -----------------------------------------------------------------------------
// BodyCapabilities
// -----------------------------------------------------------------------------

/// Pre-computed body processing capabilities for a pipeline.
///
/// ```
/// use praxis_filter::{BodyCapabilities, BodyMode};
///
/// let caps = BodyCapabilities::default();
/// assert!(!caps.needs_request_body);
/// assert!(!caps.needs_response_body);
/// assert_eq!(caps.request_body_mode, BodyMode::Stream);
/// assert_eq!(caps.response_body_mode, BodyMode::Stream);
///
/// let caps = BodyCapabilities {
///     needs_request_body: true,
///     request_body_mode: BodyMode::StreamBuffer {
///         max_bytes: Some(4096),
///     },
///     ..Default::default()
/// };
/// assert!(caps.needs_request_body);
/// assert!(matches!(
///     caps.request_body_mode,
///     BodyMode::StreamBuffer {
///         max_bytes: Some(4096)
///     }
/// ));
/// assert!(!caps.needs_response_body, "unset fields stay at default");
/// ```
#[derive(Debug, Clone, Default)]
#[expect(clippy::struct_excessive_bools, reason = "capability flags")]
pub struct BodyCapabilities {
    /// Whether any filter writes to the request body.
    pub any_request_body_writer: bool,

    /// Whether any filter writes to the response body.
    pub any_response_body_writer: bool,

    /// Whether any response condition references headers.
    pub any_response_condition_uses_headers: bool,

    /// Whether any filter needs request body access.
    pub needs_request_body: bool,

    /// Whether any filter needs the original request context during body phases.
    pub needs_request_context: bool,

    /// Whether any filter needs response body access.
    pub needs_response_body: bool,

    /// Resolved request body mode (`StreamBuffer` if any filter requires it).
    pub request_body_mode: BodyMode,

    /// Resolved response body mode (`StreamBuffer` if any filter requires it).
    pub response_body_mode: BodyMode,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_capabilities_default_is_no_op() {
        let caps = BodyCapabilities::default();

        assert!(!caps.needs_request_body, "default caps should not need request body");
        assert!(!caps.needs_response_body, "default caps should not need response body");
        assert!(
            !caps.any_request_body_writer,
            "default caps should have no request body writer"
        );
        assert!(
            !caps.any_response_body_writer,
            "default caps should have no response body writer"
        );
        assert!(
            !caps.needs_request_context,
            "default caps should not need request context"
        );
        assert_eq!(
            caps.request_body_mode,
            BodyMode::Stream,
            "default request mode should be Stream"
        );
        assert_eq!(
            caps.response_body_mode,
            BodyMode::Stream,
            "default response mode should be Stream"
        );
    }
}
