// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Iterative-router types and constants for sub-request execution.
//!
//! The transport executor now lives in
//! [`praxis_core::subrequest::SubRequestClient`]. This module retains
//! only the IRR-specific iteration state, depth tracking, and
//! response-limit defaults.

use std::collections::HashMap;

use bytes::Bytes;
use http::HeaderMap;
use praxis_core::subrequest::{SubRequest, SubResponse};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum response body size (10 MiB) to prevent unbounded
/// memory growth from sub-request responses.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 10_485_760; // 10 MiB

/// Header for iterative-router loop prevention.
///
/// Re-exported from core where [`FrameworkHeaders::set_depth`]
/// uses it for injection.
///
/// [`FrameworkHeaders::set_depth`]: praxis_core::subrequest::FrameworkHeaders::set_depth
pub(crate) use praxis_core::subrequest::DEPTH_HEADER;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
    use std::time::Duration;

    use super::*;

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
}
