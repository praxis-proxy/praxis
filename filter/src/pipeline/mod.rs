//! Filter pipeline: ordered chain of filters executed on each request.

mod body;
mod build;
mod http;
mod tcp;

#[cfg(test)]
mod tests;

use praxis_core::health::HealthRegistry;

use crate::{
    FilterError,
    body::{BodyCapabilities, BodyMode},
    compression_config::CompressionConfig,
};

// -----------------------------------------------------------------------------
// FilterPipeline
// -----------------------------------------------------------------------------

/// A filter paired with its request-phase and response-phase conditions.
pub(crate) type ConditionalFilter = (
    crate::any_filter::AnyFilter,
    Vec<praxis_core::config::Condition>,
    Vec<praxis_core::config::ResponseCondition>,
);

/// An ordered list of filters executed on every request.
///
/// ```
/// use praxis_filter::{FilterPipeline, FilterRegistry};
///
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = FilterPipeline::build(&[], &registry).unwrap();
/// assert!(pipeline.is_empty());
/// ```
pub struct FilterPipeline {
    /// Pre-computed body processing capabilities for this pipeline.
    body_capabilities: BodyCapabilities,

    /// Compression configuration, if a compression filter is present.
    compression: Option<CompressionConfig>,

    /// Ordered list of filters with their request and response conditions.
    pub(crate) filters: Vec<ConditionalFilter>,

    /// Shared health registry for endpoint health lookups.
    health_registry: Option<HealthRegistry>,
}

impl FilterPipeline {
    /// Build a pipeline from a parsed [`Config`] and registry.
    ///
    /// [`Config`]: praxis_core::config::Config
    ///
    /// ```
    /// use praxis_core::config::Config;
    /// use praxis_filter::{FilterPipeline, FilterRegistry};
    ///
    /// let config = Config::from_yaml(r#"
    /// listeners:
    ///   - name: default
    ///     address: "127.0.0.1:8080"
    /// pipeline:
    ///   - filter: static_response
    ///     status: 200
    /// "#).unwrap();
    /// let registry = FilterRegistry::with_builtins();
    /// let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    /// assert_eq!(pipeline.len(), 1);
    /// ```
    pub fn from_config(
        config: &praxis_core::config::Config,
        registry: &crate::FilterRegistry,
    ) -> Result<Self, FilterError> {
        let mut pipeline = Self::build(&config.pipeline, registry)?;
        pipeline.apply_body_limits(config.max_request_body_bytes, config.max_response_body_bytes);
        Ok(pipeline)
    }

    /// Apply global body size ceilings.
    pub fn apply_body_limits(&mut self, max_request: Option<usize>, max_response: Option<usize>) {
        if let Some(ceiling) = max_request {
            self.body_capabilities.request_body_mode = match self.body_capabilities.request_body_mode {
                BodyMode::Buffer { max_bytes } => BodyMode::Buffer {
                    max_bytes: max_bytes.min(ceiling),
                },
                BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
                    max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
                },
                BodyMode::Stream => BodyMode::Buffer { max_bytes: ceiling },
            };
            self.body_capabilities.needs_request_body = true;
        }

        if let Some(ceiling) = max_response {
            self.body_capabilities.response_body_mode = match self.body_capabilities.response_body_mode {
                BodyMode::Buffer { max_bytes } => BodyMode::Buffer {
                    max_bytes: max_bytes.min(ceiling),
                },
                BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
                    max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
                },
                BodyMode::Stream => BodyMode::Buffer { max_bytes: ceiling },
            };
            self.body_capabilities.needs_response_body = true;
        }
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

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
    ///
    /// The registry is cloned into every [`HttpFilterContext`] so
    /// filters (e.g. load balancer) can look up endpoint health
    /// at request time.
    ///
    /// [`HttpFilterContext`]: crate::HttpFilterContext
    pub fn set_health_registry(&mut self, registry: HealthRegistry) {
        self.health_registry = Some(registry);
    }

    /// The shared health registry, if set.
    pub fn health_registry(&self) -> Option<&HealthRegistry> {
        self.health_registry.as_ref()
    }
}
