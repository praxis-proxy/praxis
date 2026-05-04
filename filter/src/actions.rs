// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

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
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
        assert!(r.body.is_none(), "body should default to None");
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
}
