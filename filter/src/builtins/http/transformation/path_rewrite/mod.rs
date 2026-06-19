// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Path rewriting filter: strip prefix, add prefix, or regex replace on request paths.

mod config;
mod ops;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use tracing::{debug, trace};

use self::{
    config::PathRewriteConfig,
    ops::{PathRewriteOp, append_query, build_op, rewrite_path},
};
use super::path_sanitize::normalize_rewritten_path;
use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// PathRewriteFilter
// -----------------------------------------------------------------------------

/// Rewrites the request path before forwarding to the upstream.
///
/// Supports three operations (one per filter instance):
/// - `strip_prefix`: remove a leading path prefix
/// - `add_prefix`: prepend a path prefix
/// - `replace`: regex find/replace on the path
///
/// Query strings are preserved across all operations.
///
/// # YAML configuration
///
/// ```yaml
/// filter: path_rewrite
/// strip_prefix: "/api/v1"
/// ```
///
/// ```yaml
/// filter: path_rewrite
/// add_prefix: "/api/v1"
/// ```
///
/// ```yaml
/// filter: path_rewrite
/// replace:
///   pattern: "^/old/(.*)"
///   replacement: "/new/$1"
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::PathRewriteFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"strip_prefix: "/api/v1""#).unwrap();
/// let filter = PathRewriteFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "path_rewrite");
/// ```
pub struct PathRewriteFilter {
    /// The compiled rewrite operation.
    op: PathRewriteOp,
}

impl PathRewriteFilter {
    /// Create a path rewrite filter from parsed YAML config.
    ///
    /// Exactly one of `strip_prefix`, `add_prefix`, or `replace`
    /// must be specified.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config is invalid or the
    /// regex pattern fails to compile.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::PathRewriteFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"add_prefix: "/v2""#).unwrap();
    /// let filter = PathRewriteFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "path_rewrite");
    /// ```
    ///
    /// ```ignore
    /// use praxis_filter::PathRewriteFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// replace:
    ///   pattern: "^/old/(.*)"
    ///   replacement: "/new/$1"
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = PathRewriteFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "path_rewrite");
    /// ```
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: PathRewriteConfig = parse_filter_config("path_rewrite", config)?;
        let operation = cfg.into_operation()?;
        let op = build_op(operation)?;
        Ok(Box::new(Self { op }))
    }
}

#[async_trait]
impl HttpFilter for PathRewriteFilter {
    fn name(&self) -> &'static str {
        "path_rewrite"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let path = ctx.request.uri.path();
        let query = ctx.request.uri.query();

        let new_path = rewrite_path(&self.op, path);

        match &new_path {
            Cow::Borrowed(_) => {
                trace!(path = %path, "path rewrite: no change");
            },
            Cow::Owned(rewritten) => {
                let normalized = normalize_rewritten_path(rewritten);
                let full = append_query(&normalized, query);
                debug!(original = %path, rewritten = %full, "path rewritten");
                ctx.rewritten_path = Some(full);
            },
        }

        Ok(FilterAction::Continue)
    }
}
