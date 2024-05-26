//! Pre-computed body processing capabilities for filter pipelines.

use super::BodyMode;

// -----------------------------------------------------------------------------
// BodyCapabilities
// -----------------------------------------------------------------------------

/// Pre-computed body processing capabilities for a pipeline.
///
/// ```
/// use praxis_filter::BodyCapabilities;
///
/// let caps = BodyCapabilities::default();
/// assert!(!caps.needs_request_body);
/// assert!(!caps.needs_response_body);
/// ```
#[derive(Debug, Clone)]

pub struct BodyCapabilities {
    /// Whether any filter writes to the request body.
    pub any_request_body_writer: bool,

    /// Whether any response condition references headers.
    pub any_response_condition_uses_headers: bool,

    /// Whether any filter writes to the response body.
    pub any_response_body_writer: bool,

    /// Whether any filter needs request body access.
    pub needs_request_body: bool,

    /// Whether any filter needs the original request context during body phases.
    pub needs_request_context: bool,

    /// Whether any filter needs response body access.
    pub needs_response_body: bool,

    /// Resolved request body mode (Buffer if any filter requires it).
    pub request_body_mode: BodyMode,

    /// Resolved response body mode (Buffer if any filter requires it).
    pub response_body_mode: BodyMode,
}

impl Default for BodyCapabilities {
    fn default() -> Self {
        Self {
            any_request_body_writer: false,
            any_response_body_writer: false,
            any_response_condition_uses_headers: false,
            needs_request_body: false,
            needs_request_context: false,
            needs_response_body: false,
            request_body_mode: BodyMode::Stream,
            response_body_mode: BodyMode::Stream,
        }
    }
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
