// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reusable test-only filters for integration testing.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext};

/// Test probe for body-phase header mutations through `StreamBuffer`.
///
/// Sets a custom header, removes a client-provided header, and adds
/// a reserved `x-praxis-*` header during body pre-read so the
/// writeback and stripping contracts can be validated.
pub struct HeaderMutatingStreamBufferFilter;

#[async_trait]
impl HttpFilter for HeaderMutatingStreamBufferFilter {
    fn name(&self) -> &'static str {
        "test_header_mutator"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        ctx.request_headers_to_set.push((
            http::header::HeaderName::from_static("x-body-phase-set"),
            http::header::HeaderValue::from_static("from-body-filter"),
        ));

        ctx.request_headers_to_set.push((
            http::header::HeaderName::from_static("x-praxis-internal-leak"),
            http::header::HeaderValue::from_static("should-be-stripped"),
        ));

        if let Ok(name) = http::header::HeaderName::from_bytes(b"x-client-remove-me") {
            ctx.request_headers_to_remove.push(name);
        }

        Ok(FilterAction::Release)
    }
}

/// Test probe for body-phase condition gating through `StreamBuffer`.
///
/// A [`ReadOnly`] `StreamBuffer` body filter that, when its body hook runs
/// (i.e. its `conditions` matched during pre-read), stamps a
/// backend-visible `x-gated-ran: yes` request header. The absence of that
/// header at the backend means the filter was gated out.
///
/// [`ReadOnly`]: praxis_filter::BodyAccess::ReadOnly
pub struct ConditionRecordingStreamBufferFilter;

#[async_trait]
impl HttpFilter for ConditionRecordingStreamBufferFilter {
    fn name(&self) -> &'static str {
        "condition_recorder"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            ctx.request_headers_to_set.push((
                http::header::HeaderName::from_static("x-gated-ran"),
                http::header::HeaderValue::from_static("yes"),
            ));
        }
        Ok(FilterAction::Continue)
    }
}

/// Test-only probe for the `ReadWrite` + `StreamBuffer` adapter contract.
///
/// Exercises body mutation, path rewrite, and cluster selection during
/// `StreamBuffer` pre-read so the adapter contract can be validated
/// before protocol-specific body-phase filters exist.
pub struct BodyMutatingStreamBufferFilter {
    /// Replacement payload used to make framing repair observable.
    pub replacement_body: Bytes,
    /// Kept configurable so tests can assert path writeback independently.
    pub rewritten_path: String,
    /// Kept configurable so tests can exercise load-balancer handoff.
    pub cluster: String,
}

impl BodyMutatingStreamBufferFilter {
    /// Default probe that exercises body, path, and cluster writeback.
    pub fn default_test() -> Self {
        Self {
            replacement_body: Bytes::from_static(b"mutated"),
            rewritten_path: "/rewritten/path".to_owned(),
            cluster: "backend".to_owned(),
        }
    }
}

#[async_trait]
impl HttpFilter for BodyMutatingStreamBufferFilter {
    fn name(&self) -> &'static str {
        "test_body_mutator"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(65_536),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        *body = Some(self.replacement_body.clone());
        ctx.rewritten_path = Some(self.rewritten_path.clone());
        ctx.cluster = Some(std::sync::Arc::from(self.cluster.as_str()));

        Ok(FilterAction::Release)
    }
}
