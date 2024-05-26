//! Filter return types: continue processing or reject with a response.

use bytes::Bytes;

// -----------------------------------------------------------------------------
// FilterAction
// -----------------------------------------------------------------------------

/// Result of a filter's request or response processing.
///
/// ```
/// use praxis_filter::{FilterAction, Rejection};
///
/// let action = FilterAction::Continue;
/// assert!(matches!(action, FilterAction::Continue));
///
/// let reject = FilterAction::Reject(Rejection::status(403));
/// assert!(matches!(reject, FilterAction::Reject(r) if r.status == 403));
///
/// let release = FilterAction::Release;
/// assert!(matches!(release, FilterAction::Release));
/// ```
#[derive(Debug)]

pub enum FilterAction {
    /// Continue to the next filter in the pipeline.
    Continue,

    /// Stop processing and respond with the given rejection.
    Reject(Rejection),

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
///     .with_body(b"rate limit exceeded" as &[u8]);
/// assert_eq!(r.status, 429);
/// assert_eq!(r.headers.len(), 1);
/// assert!(r.body.is_some());
/// ```
#[derive(Debug)]

pub struct Rejection {
    /// Response body.
    pub body: Option<Bytes>,

    /// Response headers.
    pub headers: Vec<(String, String)>,

    /// HTTP status code.
    pub status: u16,
}

impl Rejection {
    /// Create a rejection with the given status code.
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a header to the rejection response.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body of the rejection response.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_status_defaults() {
        let r = Rejection::status(404);
        assert_eq!(r.status, 404);
        assert!(r.headers.is_empty());
        assert!(r.body.is_none());
    }

    #[test]
    fn rejection_with_header_appends() {
        let r = Rejection::status(403)
            .with_header("X-Reason", "forbidden")
            .with_header("X-Request-Id", "abc");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0], ("X-Reason".into(), "forbidden".into()));
        assert_eq!(r.headers[1], ("X-Request-Id".into(), "abc".into()));
    }

    #[test]
    fn rejection_with_body_sets_bytes() {
        let r = Rejection::status(400).with_body(b"bad request" as &[u8]);
        assert_eq!(r.body.unwrap(), Bytes::from_static(b"bad request"));
    }

    #[test]
    fn filter_action_continue_variant() {
        assert!(matches!(FilterAction::Continue, FilterAction::Continue));
    }

    #[test]
    fn filter_action_reject_carries_rejection() {
        let action = FilterAction::Reject(Rejection::status(503));
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 503));
    }

    #[test]
    fn filter_action_release_variant() {
        assert!(matches!(FilterAction::Release, FilterAction::Release));
    }
}
