// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Filter pipeline engine: the runtime representation of a listener's
//! filter processing.
//!
//! ## Module Layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`build`] | `FilterPipeline` construction from config entries |
//! | [`build_branch`] | Recursive branch chain resolution |
//! | [`http`] | Request, response, and body execution loops |
//! | [`tcp`] | Connect/disconnect execution |
//! | [`evaluate`] | Branch condition checking and dispatch |
//! | [`branch`] | Runtime branch types ([`ResolvedBranch`], [`BranchOutcome`]) |
//! | [`filter`] | [`PipelineFilter`] — the per-filter wrapper |
//! | [`body`] | Body chunk processing utilities |
//! | [`checks`] | Ordering validation (router before LB, etc.) |
//! | [`clusters`] | Cluster reference collection |
//! | [`extension`] | [`PipelineExtension`] trait for injecting per-request resources |
//!
//! At runtime, chains do not exist. All listener chains are
//! concatenated into a flat `Vec<PipelineFilter>`. Branch chains are
//! stored as nested `Vec<PipelineFilter>` inside each filter's
//! [`branches`] field.
//!
//! [`ResolvedBranch`]: branch::ResolvedBranch
//! [`BranchOutcome`]: branch::BranchOutcome
//! [`PipelineFilter`]: filter::PipelineFilter
//! [`branches`]: filter::PipelineFilter::branches

pub(crate) mod body;
pub(crate) mod branch;
mod build;
mod build_branch;
mod checks;
mod clusters;
pub(crate) mod evaluate;
mod extension;
pub(crate) mod filter;
mod http;
mod http_utils;
/// Public pipeline introspection snapshots for admin surfaces.
pub(crate) mod introspection;
/// Sub-request execution for iterative request routing.
pub(crate) mod subrequest;
mod tcp;
#[cfg(test)]
mod test_filters;

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

pub use extension::PipelineExtension;
use praxis_core::{
    config::{ABSOLUTE_MAX_BODY_BYTES, FailureMode, InsecureOptions},
    health::HealthRegistry,
    id::IdGenerator,
    kv::KvStoreRegistry,
    time::TimeSource,
};
use tracing::{error, warn};

use self::filter::PipelineFilter;
use crate::{
    FilterError,
    body::{BodyCapabilities, BodyMode},
    builtins::http::payload_processing::compression_config::CompressionConfig,
    extensions::RequestExtensions,
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

    /// Whether per-filter duration metrics are recorded.
    record_filter_duration_metrics: bool,

    /// Shared health registry for endpoint health lookups.
    health_registry: Option<HealthRegistry>,

    /// Shared ID generator for request correlation IDs.
    id_generator: Arc<IdGenerator>,

    /// Named key-value stores for runtime mappings.
    kv_stores: Option<KvStoreRegistry>,

    /// Per-cluster session stores for sticky session affinity, preserved across reloads.
    session_stores: Option<Arc<crate::SessionStoreRegistry>>,

    /// Shared sub-request client for iterative sub-requests.
    subrequest_client: Option<praxis_core::subrequest::SubRequestClient>,

    /// Whether any filter, including branch filters, may select a streaming
    /// sub-request response.
    may_select_streaming_subrequest_response: bool,

    /// External pipeline extensions injected after construction.
    pipeline_extensions: Vec<Box<dyn PipelineExtension>>,

    /// Wall-clock time source for filters that need timestamps.
    time_source: Arc<dyn TimeSource>,

    /// Global request body ceiling, enforced by counting in Stream mode.
    request_body_ceiling: Option<usize>,

    /// Global response body ceiling, enforced by counting in Stream mode.
    response_body_ceiling: Option<usize>,

    /// Indices into `filters` of filters declaring request-body access.
    request_body_filter_indices: Vec<usize>,

    /// Indices into `filters` of filters declaring response-body access.
    response_body_filter_indices: Vec<usize>,
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
        self.apply_nested_body_limits(max_request, max_response, allow_unbounded)?;

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

        self.request_body_ceiling = max_request;
        self.response_body_ceiling = max_response;

        Ok(())
    }

    /// Apply the listener ceilings recursively to nested pipelines.
    fn apply_nested_body_limits(
        &mut self,
        max_request: Option<usize>,
        max_response: Option<usize>,
        allow_unbounded: bool,
    ) -> Result<(), FilterError> {
        let mut nested_error = None;
        self.visit_nested_pipelines(&mut |pipeline| {
            if nested_error.is_none()
                && let Err(error) = pipeline.apply_body_limits(max_request, max_response, allow_unbounded)
            {
                nested_error = Some(error);
            }
        });
        if let Some(error) = nested_error {
            return Err(error);
        }
        Ok(())
    }

    /// Global request body ceiling; `None` means unbounded was allowed.
    #[must_use]
    pub fn request_body_ceiling(&self) -> Option<usize> {
        self.request_body_ceiling
    }

    /// Global response body ceiling; `None` means unbounded was allowed.
    #[must_use]
    pub fn response_body_ceiling(&self) -> Option<usize> {
        self.response_body_ceiling
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

    /// Whether any top-level filter has the given type name.
    ///
    /// ```
    /// use praxis_filter::{FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
    /// assert!(!pipeline.contains_filter("access_log"));
    /// ```
    pub fn contains_filter(&self, type_name: &str) -> bool {
        self.filters.iter().any(|pf| pf.filter.name() == type_name)
    }

    /// Names of filters in this pipeline whose protocol level is not
    /// supported by `listener_protocol`.
    ///
    /// A TCP listener silently skips HTTP-level filters at runtime, so an
    /// HTTP security filter placed on a TCP listener would never run. This
    /// surfaces that mismatch at build time.
    pub fn filters_unsupported_by(&self, listener_protocol: praxis_core::config::ProtocolKind) -> Vec<&'static str> {
        self.filters
            .iter()
            .filter(|pf| !listener_protocol.supports(pf.filter.protocol_level()))
            .map(|pf| pf.filter.name())
            .collect()
    }

    /// Whether any filter of `type_name` has request conditions matching
    /// `request` (an unconditional entry always matches).
    ///
    /// Used by protocol-level fallbacks that emit on a filter's behalf, so
    /// an operator's `when`/`unless` scoping is honored outside the normal
    /// request phase.
    pub fn filter_request_conditions_match(&self, type_name: &str, request: &crate::Request) -> bool {
        self.filters
            .iter()
            .filter(|pf| pf.filter.name() == type_name)
            .any(|pf| crate::condition::should_execute(&pf.conditions, request))
    }

    /// Compression configuration, if a compression filter is present.
    pub fn compression_config(&self) -> Option<&CompressionConfig> {
        self.compression.as_ref()
    }

    /// Set the shared [`HealthRegistry`] for this pipeline.
    pub fn set_health_registry(&mut self, registry: HealthRegistry) {
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_health_registry(Arc::clone(&registry)));
        self.health_registry = Some(registry);
    }

    /// Enable or disable recording of per-filter duration metrics.
    pub fn set_record_filter_duration_metrics(&mut self, enabled: bool) {
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_record_filter_duration_metrics(enabled));
        self.record_filter_duration_metrics = enabled;
    }

    /// Whether per-filter duration metrics are recorded.
    pub fn records_filter_duration_metrics(&self) -> bool {
        self.record_filter_duration_metrics
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
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_id_generator(Arc::clone(&generator)));
        self.id_generator = generator;
    }

    /// The shared KV store registry, if set.
    pub fn kv_stores(&self) -> Option<&KvStoreRegistry> {
        self.kv_stores.as_ref()
    }

    /// Set the shared [`KvStoreRegistry`] for this pipeline.
    pub fn set_kv_stores(&mut self, stores: KvStoreRegistry) {
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_kv_stores(stores.clone()));
        self.kv_stores = Some(stores);
    }

    /// The shared session store registry, if set.
    pub fn session_stores(&self) -> Option<&Arc<crate::SessionStoreRegistry>> {
        self.session_stores.as_ref()
    }

    /// Set the shared [`crate::SessionStoreRegistry`] for this pipeline.
    pub fn set_session_stores(&mut self, stores: Arc<crate::SessionStoreRegistry>) {
        self.session_stores = Some(stores);
    }

    /// The shared sub-request client, if set.
    pub fn subrequest_client(&self) -> Option<&praxis_core::subrequest::SubRequestClient> {
        self.subrequest_client.as_ref()
    }

    /// Whether any filter in this pipeline or its branches may select a
    /// streaming sub-request response.
    pub fn may_select_streaming_subrequest_response(&self) -> bool {
        self.may_select_streaming_subrequest_response
    }

    /// Set the shared [`SubRequestClient`] for this pipeline.
    ///
    /// [`SubRequestClient`]: praxis_core::subrequest::SubRequestClient
    pub fn set_subrequest_client(&mut self, client: praxis_core::subrequest::SubRequestClient) {
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_subrequest_client(client.clone()));
        self.subrequest_client = Some(client);
    }

    /// Register an external pipeline extension.
    ///
    /// Extensions are called once per request via
    /// [`prepare_extensions`] to inject pipeline-scoped resources
    /// into the per-request [`RequestExtensions`] container.
    ///
    /// [`prepare_extensions`]: FilterPipeline::prepare_extensions
    /// [`RequestExtensions`]: crate::RequestExtensions
    pub fn add_pipeline_extension(&mut self, ext: Box<dyn PipelineExtension>) {
        self.pipeline_extensions.push(ext);
    }

    /// Inject pipeline-level resources into per-request extensions.
    ///
    /// Called by the protocol adapter when building each request's
    /// filter context. Delegates to each registered
    /// [`PipelineExtension`].
    pub fn prepare_extensions(&self, extensions: &mut RequestExtensions) {
        for ext in &self.pipeline_extensions {
            ext.prepare(extensions);
        }
    }

    /// The wall-clock time source.
    pub fn time_source(&self) -> &dyn TimeSource {
        &*self.time_source
    }

    /// Override the [`TimeSource`] for this pipeline.
    pub fn set_time_source(&mut self, source: Arc<dyn TimeSource>) {
        self.visit_nested_pipelines(&mut |pipeline| pipeline.set_time_source(Arc::clone(&source)));
        self.time_source = source;
    }

    /// Filesystem paths the filters in this pipeline read configuration from,
    /// beyond the main Praxis config.
    ///
    /// Used by the config watcher to decide which files should trigger a reload.
    /// Without this, a filter that loads an external document never picks up edits
    /// to it, because the reload gate only ever sees the main config's bytes.
    ///
    /// Mirrors [`Self::apply_insecure_options`], including its limitation: only
    /// top-level filters are walked, not filters nested inside branch chains. A
    /// document referenced solely from a branch is therefore not observed. That is
    /// the same blind spot the insecure-options walk already has, and widening both
    /// belongs in one change rather than half of one here.
    pub fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        self.filters
            .iter()
            .filter_map(|pf| match &pf.filter {
                crate::any_filter::AnyFilter::Http(f) => Some(f.referenced_files()),
                crate::any_filter::AnyFilter::Tcp(_) => None,
            })
            .flatten()
            .collect()
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

    /// Apply a mutation to every pipeline directly embedded by a filter.
    fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
        for pf in &mut self.filters {
            if let crate::any_filter::AnyFilter::Http(filter) = &mut pf.filter {
                filter.visit_nested_pipelines(visitor);
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
                phase,
                failure_mode = "open",
                "filter error, continuing"
            );
            Ok(())
        },
        FailureMode::Closed => {
            error!(
                filter = filter_name,
                error = %error,
                phase,
                failure_mode = "closed",
                "filter error, aborting request"
            );
            Err(error)
        },
    }
}
