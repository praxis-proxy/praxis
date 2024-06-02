//! Maps listener names to their resolved [`FilterPipeline`].
//!
//! [`FilterPipeline`]: praxis_filter::FilterPipeline

use std::{collections::HashMap, sync::Arc};

use praxis_filter::FilterPipeline;

// -----------------------------------------------------------------------------
// ListenerPipelines
// -----------------------------------------------------------------------------

/// Maps listener names to their resolved [`FilterPipeline`]s.
///
/// ```
/// use std::{collections::HashMap, sync::Arc};
/// use praxis_filter::{FilterPipeline, FilterRegistry};
/// use praxis_protocol::ListenerPipelines;
///
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = Arc::new(FilterPipeline::build(&[], &registry).unwrap());
///
/// let mut map = HashMap::new();
/// map.insert("web".to_string(), pipeline);
/// let pipelines = ListenerPipelines::new(map);
///
/// assert!(pipelines.get("web").is_some());
/// assert!(pipelines.get("missing").is_none());
/// ```
pub struct ListenerPipelines {
    /// Maps listener names to their resolved filter pipelines.
    pipelines: HashMap<String, Arc<FilterPipeline>>,
}

impl ListenerPipelines {
    /// Create from a map of listener name to pipeline.
    pub fn new(pipelines: HashMap<String, Arc<FilterPipeline>>) -> Self {
        Self { pipelines }
    }

    /// Get the pipeline for a listener by name.
    pub fn get(&self, listener_name: &str) -> Option<&Arc<FilterPipeline>> {
        self.pipelines.get(listener_name)
    }
}
