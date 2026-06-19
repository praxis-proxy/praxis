// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Filter pipeline: ordered chain of filters executed on each request.

pub(crate) mod body;
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::field_reassign_with_default,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::redundant_closure_for_method_calls,
    clippy::significant_drop_tightening,
    clippy::doc_markdown,
    reason = "tests"
)]
mod tests;

use std::sync::Arc;

use praxis_core::{
    config::{ABSOLUTE_MAX_BODY_BYTES, FailureMode, InsecureOptions},
    health::HealthRegistry,
    id::IdGenerator,
    kv::KvStoreRegistry,
    time::TimeSource,
};
use tracing::warn;

use self::filter::PipelineFilter;
#[cfg(feature = "ai-inference")]
use crate::builtins::http::ai::store::ResponseStoreRegistry;
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

    /// Shared ID generator for request correlation IDs.
    id_generator: Arc<IdGenerator>,

    /// Named key-value stores for runtime mappings.
    kv_stores: Option<KvStoreRegistry>,

    /// Named response store backends for AI API persistence.
    #[cfg(feature = "ai-inference")]
    response_stores: Option<ResponseStoreRegistry>,

    /// Wall-clock time source for filters that need timestamps.
    time_source: Arc<dyn TimeSource>,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "pipeline concerns are split across modules"
)]
impl FilterPipeline {
    /// Apply global body size ceilings.
    ///
    /// When no filter requires body access (mode is [`Stream`]),
    /// uses [`SizeLimit`] to enforce the ceiling without
    /// buffering. When a filter already requested
    /// [`StreamBuffer`], the ceiling tightens the existing limit.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a [`StreamBuffer`] has no byte limit
    /// and `allow_unbounded` is `false`.
    ///
    /// [`Stream`]: BodyMode::Stream
    /// [`SizeLimit`]: BodyMode::SizeLimit
    /// [`StreamBuffer`]: BodyMode::StreamBuffer
    pub fn apply_body_limits(
        &mut self,
        max_request: Option<usize>,
        max_response: Option<usize>,
        allow_unbounded: bool,
    ) -> Result<(), FilterError> {
        if let Some(ceiling) = max_request {
            self.body_capabilities.request_body_mode = clamp_body_mode(
                self.body_capabilities.request_body_mode,
                ceiling,
                self.body_capabilities.needs_request_body,
            );
            self.body_capabilities.needs_request_body = true;
        }

        if let Some(ceiling) = max_response {
            self.body_capabilities.response_body_mode = clamp_body_mode(
                self.body_capabilities.response_body_mode,
                ceiling,
                self.body_capabilities.needs_response_body,
            );
            self.body_capabilities.needs_response_body = true;
        }

        check_unbounded_stream_buffer(
            "request",
            &mut self.body_capabilities.request_body_mode,
            allow_unbounded,
        )?;
        check_unbounded_stream_buffer(
            "response",
            &mut self.body_capabilities.response_body_mode,
            allow_unbounded,
        )?;

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

    /// The shared request ID generator.
    pub fn id_generator(&self) -> &IdGenerator {
        &self.id_generator
    }

    /// Override the [`IdGenerator`] for this pipeline.
    pub fn set_id_generator(&mut self, generator: Arc<IdGenerator>) {
        self.id_generator = generator;
    }

    /// The shared KV store registry, if set.
    pub fn kv_stores(&self) -> Option<&KvStoreRegistry> {
        self.kv_stores.as_ref()
    }

    /// Set the shared [`KvStoreRegistry`] for this pipeline.
    pub fn set_kv_stores(&mut self, stores: KvStoreRegistry) {
        self.kv_stores = Some(stores);
    }

    /// The shared response store registry, if set.
    #[cfg(feature = "ai-inference")]
    pub fn response_stores(&self) -> Option<&ResponseStoreRegistry> {
        self.response_stores.as_ref()
    }

    /// Set the shared [`ResponseStoreRegistry`] for this pipeline.
    #[cfg(feature = "ai-inference")]
    pub fn set_response_stores(&mut self, stores: ResponseStoreRegistry) {
        self.response_stores = Some(stores);
    }

    /// The wall-clock time source.
    pub fn time_source(&self) -> &dyn TimeSource {
        &*self.time_source
    }

    /// Override the [`TimeSource`] for this pipeline.
    pub fn set_time_source(&mut self, source: Arc<dyn TimeSource>) {
        self.time_source = source;
    }

    /// Apply [`InsecureOptions`] to all filters in the pipeline.
    ///
    /// Delegates to each filter's [`apply_insecure_options`] method.
    /// Filters that support insecure overrides (e.g. CSRF log-only
    /// mode) handle the relevant flags; others ignore the call.
    ///
    /// [`apply_insecure_options`]: crate::HttpFilter::apply_insecure_options
    /// [`InsecureOptions`]: praxis_core::config::InsecureOptions
    pub fn apply_insecure_options(&self, options: &InsecureOptions) {
        for pf in &self.filters {
            if let crate::any_filter::AnyFilter::Http(f) = &pf.filter {
                f.apply_insecure_options(options);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Body Limit Utilities
// -----------------------------------------------------------------------------

/// Tighten a body mode's size limit to the given ceiling.
/// When `filter_declared` is true a filter explicitly chose Stream
/// mode; preserve it so streaming filters keep working. When false
/// the mode is the default (no filter needs body); convert to
/// `SizeLimit` so the body limit is enforced by buffering.
fn clamp_body_mode(mode: BodyMode, ceiling: usize, filter_declared: bool) -> BodyMode {
    match mode {
        BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
        },
        BodyMode::SizeLimit { max_bytes } => BodyMode::SizeLimit {
            max_bytes: max_bytes.min(ceiling),
        },
        BodyMode::Stream if filter_declared => BodyMode::Stream,
        BodyMode::Stream => BodyMode::SizeLimit { max_bytes: ceiling },
    }
}

/// Reject or clamp unbounded [`StreamBuffer`] body modes.
///
/// When `allow_unbounded` is `true`, the mode is clamped to
/// [`ABSOLUTE_MAX_BODY_BYTES`] and a warning is emitted.
///
/// # Errors
///
/// Returns [`FilterError`] when the body mode is unbounded
/// and `allow_unbounded` is `false`.
///
/// [`StreamBuffer`]: BodyMode::StreamBuffer
/// [`ABSOLUTE_MAX_BODY_BYTES`]: praxis_core::config::ABSOLUTE_MAX_BODY_BYTES
fn check_unbounded_stream_buffer(
    direction: &str,
    mode: &mut BodyMode,
    allow_unbounded: bool,
) -> Result<(), FilterError> {
    if let BodyMode::StreamBuffer { max_bytes: max @ None } = mode {
        if allow_unbounded {
            warn!(
                direction = direction,
                ceiling = ABSOLUTE_MAX_BODY_BYTES,
                "StreamBuffer body mode has no per-filter size limit; \
                 clamped to absolute ceiling ({} MiB)",
                ABSOLUTE_MAX_BODY_BYTES / 1_048_576
            );
            *max = Some(ABSOLUTE_MAX_BODY_BYTES);
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
