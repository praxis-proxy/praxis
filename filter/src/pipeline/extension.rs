// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Pipeline extension trait for injecting pipeline-scoped resources
//! into per-request [`RequestExtensions`].
//!
//! External filter crates (e.g. AI filters) implement this trait to
//! attach pipeline-level singletons (stores, registries, caches) that
//! their filters retrieve via [`RequestExtensions::get`] during
//! request processing.
//!
//! [`RequestExtensions`]: crate::RequestExtensions

use crate::extensions::RequestExtensions;

// ---------------------------------------------------------------------------
// PipelineExtension Trait
// ---------------------------------------------------------------------------

/// Injects pipeline-scoped resources into per-request extensions.
///
/// Implementations are registered after pipeline construction via
/// [`FilterPipeline::add_pipeline_extension`] and called once per
/// request from [`FilterPipeline::prepare_extensions`].
///
/// ```ignore
/// use praxis_filter::{PipelineExtension, RequestExtensions};
///
/// #[derive(Clone)]
/// struct MyRegistry { /* ... */ }
///
/// impl PipelineExtension for MyRegistry {
///     fn prepare(&self, extensions: &mut RequestExtensions) {
///         extensions.insert(self.clone());
///     }
/// }
/// ```
///
/// [`FilterPipeline::add_pipeline_extension`]: crate::FilterPipeline::add_pipeline_extension
/// [`FilterPipeline::prepare_extensions`]: crate::FilterPipeline::prepare_extensions
pub trait PipelineExtension: Send + Sync {
    /// Insert this extension's resources into per-request extensions.
    fn prepare(&self, extensions: &mut RequestExtensions);
}
