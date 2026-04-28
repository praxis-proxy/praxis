// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter pipeline: ordered chain of filters executed on each request.

mod body;
pub(crate) mod branch;
mod build;
mod build_branch;
mod checks;
mod clusters;
pub(crate) mod evaluate;
pub(crate) mod filter;
mod http;
mod http_utils;
mod tcp;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::field_reassign_with_default,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::redundant_closure_for_method_calls,
    clippy::doc_markdown,
    reason = "tests"
)]
mod tests;

use praxis_core::{config::FailureMode, health::HealthRegistry};
use tracing::warn;

use self::filter::PipelineFilter;
use crate::{
    FilterError,
    body::{BodyCapabilities, BodyMode},
    builtins::http::payload_processing::compression_config::CompressionConfig,
};

// -----------------------------------------------------------------------------
// FilterPipeline
// -----------------------------------------------------------------------------

/// An ordered list of filters executed on every request.
///
/// ```
/// use praxis_filter::{FilterPipeline, FilterRegistry};
///
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
/// assert!(pipeline.is_empty());
/// ```
pub struct FilterPipeline {
    /// Pre-computed body processing capabilities for this pipeline.
    body_capabilities: BodyCapabilities,

    /// Compression configuration, if a compression filter is present.
    compression: Option<CompressionConfig>,

    /// Ordered list of filters with their conditions and branches.
    pub(crate) filters: Vec<PipelineFilter>,

    /// Shared health registry for endpoint health lookups.
    health_registry: Option<HealthRegistry>,
}

impl FilterPipeline {
    /// Apply global body size ceilings.
    ///
    /// When no filter requires body access (mode is [`Stream`]),
    /// uses [`SizeLimit`] to enforce the ceiling without
    /// buffering. When a filter already requested [`Buffer`] or
    /// [`StreamBuffer`], the ceiling tightens the existing limit.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a [`StreamBuffer`] has no byte limit
    /// and `allow_unbounded` is `false`.
    ///
    /// [`Stream`]: BodyMode::Stream
    /// [`SizeLimit`]: BodyMode::SizeLimit
    /// [`Buffer`]: BodyMode::Buffer
    /// [`StreamBuffer`]: BodyMode::StreamBuffer
    pub fn apply_body_limits(
        &mut self,
        max_request: Option<usize>,
        max_response: Option<usize>,
        allow_unbounded: bool,
    ) -> Result<(), FilterError> {
        if let Some(ceiling) = max_request {
            self.body_capabilities.request_body_mode =
                clamp_body_mode(self.body_capabilities.request_body_mode, ceiling);
            self.body_capabilities.needs_request_body = true;
        }

        if let Some(ceiling) = max_response {
            self.body_capabilities.response_body_mode =
                clamp_body_mode(self.body_capabilities.response_body_mode, ceiling);
            self.body_capabilities.needs_response_body = true;
        }

        check_unbounded_stream_buffer("request", self.body_capabilities.request_body_mode, allow_unbounded)?;
        check_unbounded_stream_buffer("response", self.body_capabilities.response_body_mode, allow_unbounded)?;

        Ok(())
    }

    /// Pre-computed body processing capabilities for this pipeline.
    pub fn body_capabilities(&self) -> &BodyCapabilities {
        &self.body_capabilities
    }

    /// Whether any filter in the pipeline needs body access.
    pub fn needs_body_filters(&self) -> bool {
        self.body_capabilities.needs_request_body || self.body_capabilities.needs_response_body
    }

    /// Number of filters in the pipeline.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the pipeline has no filters.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Compression configuration, if a compression filter is present.
    pub fn compression_config(&self) -> Option<&CompressionConfig> {
        self.compression.as_ref()
    }

    /// Set the shared [`HealthRegistry`] for this pipeline.
    pub fn set_health_registry(&mut self, registry: HealthRegistry) {
        self.health_registry = Some(registry);
    }

    /// The shared health registry, if set.
    pub fn health_registry(&self) -> Option<&HealthRegistry> {
        self.health_registry.as_ref()
    }
}

// -----------------------------------------------------------------------------
// Body Limit Utilities
// -----------------------------------------------------------------------------

/// Tighten a body mode's size limit to the given ceiling.
fn clamp_body_mode(mode: BodyMode, ceiling: usize) -> BodyMode {
    match mode {
        BodyMode::Buffer { max_bytes } => BodyMode::Buffer {
            max_bytes: max_bytes.min(ceiling),
        },
        BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
        },
        BodyMode::SizeLimit { max_bytes } => BodyMode::SizeLimit {
            max_bytes: max_bytes.min(ceiling),
        },
        BodyMode::Stream => BodyMode::SizeLimit { max_bytes: ceiling },
    }
}

/// Reject unbounded [`StreamBuffer`] body modes unless explicitly allowed.
///
/// When `allow_unbounded` is `true`, the error is demoted to a warning.
///
/// # Errors
///
/// Returns [`FilterError`] when the body mode is unbounded
/// and `allow_unbounded` is `false`.
///
/// [`StreamBuffer`]: BodyMode::StreamBuffer
fn check_unbounded_stream_buffer(direction: &str, mode: BodyMode, allow_unbounded: bool) -> Result<(), FilterError> {
    if matches!(mode, BodyMode::StreamBuffer { max_bytes: None }) {
        if allow_unbounded {
            warn!(
                direction = direction,
                "StreamBuffer body mode has no size limit; \
                 allowed by insecure_options.allow_unbounded_body"
            );
        } else {
            return Err(format!(
                "StreamBuffer {direction} body mode has no size limit; \
                 set max_{direction}_body_bytes or set \
                 insecure_options.allow_unbounded_body: true to allow"
            )
            .into());
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Failure Mode
// -----------------------------------------------------------------------------

/// Check failure mode and either swallow or propagate a filter error.
///
/// When `failure_mode` is [`FailureMode::Open`], the error is logged as a
/// warning and `Ok(())` is returned so the caller can continue.
pub(crate) fn check_failure_mode(
    filter_name: &str,
    error: FilterError,
    phase: &str,
    failure_mode: FailureMode,
) -> Result<(), FilterError> {
    match failure_mode {
        FailureMode::Open => {
            warn!(
                filter = filter_name,
                error = %error,
                "filter error during {phase}, continuing (failure_mode=open)"
            );
            Ok(())
        },
        FailureMode::Closed => {
            warn!(
                filter = filter_name,
                error = %error,
                "filter error during {phase}, aborting"
            );
            Err(error)
        },
    }
}
