// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reusable test-only filters for integration testing.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{BodyAccess, BodyMode, FilterAction, FilterError, HttpFilter, HttpFilterContext};

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
        BodyAccess::ReadWrite
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
