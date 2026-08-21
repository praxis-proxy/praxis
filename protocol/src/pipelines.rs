// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Hot-swappable pipeline storage for protocol adapters.
//!
//! [`ListenerPipelines`] lives in the protocol crate because it is
//! the interface between protocol adapters (which invoke filter
//! execution) and the filter engine (which owns [`FilterPipeline`]).
//!
//! Each pipeline is wrapped in [`ArcSwap`] for lock-free atomic
//! replacement during hot reloads. In-flight requests hold an
//! [`Arc`] guard to the old pipeline, so they drain safely while
//! new requests pick up the replacement.
//!
//! [`FilterPipeline`]: praxis_filter::FilterPipeline
//! [`ArcSwap`]: arc_swap::ArcSwap

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

    /// Every filesystem path any filter in any listener's pipeline reads
    /// configuration from, de-duplicated.
    ///
    /// Two listeners can share a filter chain, so the same document would
    /// otherwise appear more than once and be watched and hashed repeatedly.
    pub fn referenced_files(&self) -> Vec<std::path::PathBuf> {
        let mut seen = std::collections::BTreeSet::new();
        for name in self.listener_names() {
            if let Some(slot) = self.get(name) {
                for path in slot.load().referenced_files() {
                    seen.insert(path);
                }
            }
        }
        seen.into_iter().collect()
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use praxis_filter::FilterRegistry;

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

    #[test]
    fn referenced_files_empty_without_listeners() {
        let pipelines = make_pipelines(&[]);
        assert!(
            pipelines.referenced_files().is_empty(),
            "no listeners means no referenced documents"
        );
    }

    #[test]
    fn referenced_files_empty_when_no_filter_declares_one() {
        let pipelines = make_pipelines(&["web"]);
        assert!(
            pipelines.referenced_files().is_empty(),
            "a pipeline of non-declaring filters contributes nothing"
        );
    }

    #[test]
    fn referenced_files_collects_across_listeners() {
        let pipelines =
            make_pipelines_with_documents(&[("web", "/etc/praxis/web.yaml"), ("api", "/etc/praxis/api.yaml")]);
        assert_eq!(
            pipelines.referenced_files(),
            vec![
                std::path::PathBuf::from("/etc/praxis/api.yaml"),
                std::path::PathBuf::from("/etc/praxis/web.yaml"),
            ],
            "every listener's documents must be collected, sorted by the BTreeSet"
        );
    }

    /// Two listeners can share a filter chain. The document must be reported once
    /// so the watcher does not hash and watch it twice.
    #[test]
    fn referenced_files_dedupes_a_document_shared_by_two_listeners() {
        let shared = "/etc/praxis/shared.yaml";
        let pipelines = make_pipelines_with_documents(&[("web", shared), ("api", shared)]);
        assert_eq!(
            pipelines.referenced_files(),
            vec![std::path::PathBuf::from(shared)],
            "a shared document must appear once"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A filter that declares the document named by its `document:` config key.
    struct DocumentReaderFilter {
        document: std::path::PathBuf,
    }

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for DocumentReaderFilter {
        fn name(&self) -> &'static str {
            "document_reader"
        }

        fn referenced_files(&self) -> Vec<std::path::PathBuf> {
            vec![self.document.clone()]
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
            Ok(praxis_filter::FilterAction::Continue)
        }
    }

    /// Build [`ListenerPipelines`] where each named listener runs a single filter
    /// declaring the given document.
    fn make_pipelines_with_documents(listeners: &[(&str, &str)]) -> ListenerPipelines {
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "document_reader",
                praxis_filter::FilterFactory::Http(Arc::new(|cfg: &serde_yaml::Value| {
                    let document = cfg
                        .get("document")
                        .and_then(serde_yaml::Value::as_str)
                        .ok_or_else(|| praxis_filter::FilterError::from("document_reader: missing document"))?;
                    let filter: Box<dyn praxis_filter::HttpFilter> = Box::new(DocumentReaderFilter {
                        document: std::path::PathBuf::from(document),
                    });
                    Ok(filter)
                })),
            )
            .unwrap();

        let mut map = HashMap::new();
        for (listener, document) in listeners {
            let yaml = format!("- filter: document_reader\n  document: {document}\n");
            let mut entries: Vec<praxis_core::config::FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
            let pipeline = Arc::new(FilterPipeline::build(&mut entries, &registry).unwrap());
            map.insert((*listener).to_owned(), pipeline);
        }
        ListenerPipelines::new(map)
    }

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
