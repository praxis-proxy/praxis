// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Maps listener names to their resolved [`FilterPipeline`].
//!
//! [`FilterPipeline`]: praxis_filter::FilterPipeline

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use praxis_filter::FilterPipeline;

// -----------------------------------------------------------------------------
// ListenerPipelines
// -----------------------------------------------------------------------------

/// Maps listener names to their resolved [`FilterPipeline`]s.
///
/// Each pipeline is wrapped in [`ArcSwap`] so it can be atomically
/// replaced at runtime without blocking in-flight requests.
///
/// ```
/// use std::{collections::HashMap, sync::Arc};
///
/// use praxis_filter::{FilterPipeline, FilterRegistry};
/// use praxis_protocol::ListenerPipelines;
///
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
///
/// let mut map = HashMap::new();
/// map.insert("web".to_owned(), pipeline);
/// let pipelines = ListenerPipelines::new(map);
///
/// assert!(pipelines.get("web").is_some());
/// assert!(pipelines.get("missing").is_none());
/// ```
///
/// [`ArcSwap`]: arc_swap::ArcSwap
pub struct ListenerPipelines {
    /// Maps listener names to their swappable filter pipelines.
    pipelines: HashMap<String, Arc<ArcSwap<FilterPipeline>>>,
}

impl ListenerPipelines {
    /// Create from a map of listener name to pipeline.
    pub fn new(pipelines: HashMap<String, Arc<FilterPipeline>>) -> Self {
        let swappable = pipelines
            .into_iter()
            .map(|(name, p)| (name, Arc::new(ArcSwap::from(p))))
            .collect();
        Self { pipelines: swappable }
    }

    /// Get the swappable pipeline for a listener by name.
    pub fn get(&self, listener_name: &str) -> Option<&Arc<ArcSwap<FilterPipeline>>> {
        self.pipelines.get(listener_name)
    }

    /// Atomically replace the pipeline for a listener.
    ///
    /// No-op if the listener name is not present.
    ///
    /// ```
    /// use std::{collections::HashMap, sync::Arc};
    ///
    /// use praxis_filter::{FilterPipeline, FilterRegistry};
    /// use praxis_protocol::ListenerPipelines;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let old = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
    /// let new = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
    ///
    /// let mut map = HashMap::new();
    /// map.insert("web".to_owned(), old);
    /// let pipelines = ListenerPipelines::new(map);
    ///
    /// pipelines.swap("web", new);
    /// pipelines.swap(
    ///     "nonexistent",
    ///     Arc::new(FilterPipeline::build(&mut [], &registry).unwrap()),
    /// );
    /// ```
    pub fn swap(&self, listener_name: &str, new_pipeline: Arc<FilterPipeline>) {
        if let Some(slot) = self.pipelines.get(listener_name) {
            slot.store(new_pipeline);
        }
    }

    /// Returns an iterator over listener names.
    pub fn listener_names(&self) -> impl Iterator<Item = &str> {
        self.pipelines.keys().map(String::as_str)
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use arc_swap::ArcSwap;
    use praxis_filter::{FilterPipeline, FilterRegistry};

    use super::*;

    #[test]
    fn get_returns_pipeline() {
        let pipelines = make_pipelines(&["web"]);
        assert!(pipelines.get("web").is_some(), "should find 'web' pipeline");
    }

    #[test]
    fn get_returns_none_for_missing() {
        let pipelines = make_pipelines(&["web"]);
        assert!(pipelines.get("missing").is_none(), "should return None for missing");
    }

    #[test]
    fn swap_replaces_pipeline_pointer() {
        let pipelines = make_pipelines(&["web"]);
        let old_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());

        let registry = FilterRegistry::with_builtins();
        let new_pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        pipelines.swap("web", Arc::clone(&new_pipeline));

        let new_ptr = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "swap should replace the pipeline pointer");
    }

    #[test]
    fn old_guard_remains_valid_after_swap() {
        let pipelines = make_pipelines(&["web"]);
        let old_guard = pipelines.get("web").unwrap().load();
        let old_ptr = Arc::as_ptr(&old_guard);

        let registry = FilterRegistry::with_builtins();
        let new_pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        pipelines.swap("web", new_pipeline);

        let still_old_ptr = Arc::as_ptr(&old_guard);
        assert_eq!(
            old_ptr, still_old_ptr,
            "old guard should still point to the original pipeline"
        );
    }

    #[test]
    fn swap_nonexistent_is_noop() {
        let pipelines = make_pipelines(&["web"]);
        let registry = FilterRegistry::with_builtins();
        let new_pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
        pipelines.swap("nonexistent", new_pipeline);
        assert!(pipelines.get("web").is_some(), "existing pipeline should be unaffected");
    }

    #[test]
    fn get_returns_arcswap_reference() {
        let pipelines = make_pipelines(&["web"]);
        let slot: &Arc<ArcSwap<FilterPipeline>> = pipelines.get("web").unwrap();
        let _loaded: arc_swap::Guard<Arc<FilterPipeline>> = slot.load();
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build [`ListenerPipelines`] with empty pipelines for the given names.
    fn make_pipelines(names: &[&str]) -> ListenerPipelines {
        let registry = FilterRegistry::with_builtins();
        let mut map = HashMap::new();
        for name in names {
            let pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
            map.insert((*name).to_owned(), pipeline);
        }
        ListenerPipelines::new(map)
    }
}
