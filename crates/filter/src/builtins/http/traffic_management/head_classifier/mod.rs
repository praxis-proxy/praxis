// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request-head path classifier filter.

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use serde::Deserialize;
use tracing::trace;

use crate::{
    FilterAction, FilterError, TrustedHeaderMutation,
    builtins::http::value_safety::is_safe_promoted_value,
    filter::{HttpFilter, HttpFilterContext},
    parse_filter_config,
};

/// Deserialized YAML config for the head classifier filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadClassifierConfig {
    /// Ordered classification rules; the first rule whose `path_prefix` matches
    /// the request path supplies the class.
    rules: Vec<ClassRule>,

    /// Class assigned when no rule matches. When unset, an unmatched request
    /// publishes no class and the chain proceeds unclassified.
    #[serde(default)]
    default_class: Option<String>,
}

/// A single path-prefix classification rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassRule {
    /// Request path prefix this rule matches (for example `/api/`).
    path_prefix: String,

    /// Class published when `path_prefix` matches the request path.
    class: String,
}

/// Classifies a request from its head and promotes the matched class as a
/// reserved, client-unspoofable `x-praxis-head-class` header.
///
/// Runs in the request-head phase, before any `StreamBuffer` request-body
/// pre-read, so the class is visible to the pre-read pass, later request-phase
/// filters, and the `router` (which matches request headers). The first rule
/// whose `path_prefix` matches the request path supplies the class; an
/// unmatched request takes `default_class` when set, otherwise no class is
/// published and the chain proceeds unclassified.
///
/// The class is also written to `head_classifier.class` filter metadata and to
/// the `head_classifier` filter results (`class`), so a branch chain can split
/// on it. Class values are validated at config time to be safe header values.
///
/// # YAML
///
/// ```yaml
/// filter: head_classifier
/// rules:
///   - path_prefix: /api/
///     class: api
///   - path_prefix: /assets/
///     class: assets
/// default_class: other
/// ```
pub struct HeadClassifierFilter {
    /// Ordered path-prefix rules, checked in configuration order.
    rules: Vec<ClassRule>,

    /// Class for requests that no rule matches, if configured.
    default_class: Option<String>,
}

impl HeadClassifierFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when the config is invalid, a `path_prefix` is
    /// empty, or a class value is empty or unsafe to promote to a header.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: HeadClassifierConfig = parse_filter_config("head_classifier", config)?;
        for rule in &cfg.rules {
            if rule.path_prefix.is_empty() {
                return Err("head_classifier: rule path_prefix must not be empty".into());
            }
            validate_class(&rule.class)?;
        }
        if let Some(default) = &cfg.default_class {
            validate_class(default)?;
        }
        Ok(Box::new(Self {
            rules: cfg.rules,
            default_class: cfg.default_class,
        }))
    }

    /// Return the class for `path`: the first matching rule, else the default.
    fn classify(&self, path: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| path.starts_with(rule.path_prefix.as_str()))
            .map(|rule| rule.class.as_str())
            .or(self.default_class.as_deref())
    }
}

/// Validate that a class value is non-empty and safe to promote to a header.
///
/// # Errors
///
/// Returns [`FilterError`] when `class` is empty or carries control bytes.
fn validate_class(class: &str) -> Result<(), FilterError> {
    if class.is_empty() {
        return Err("head_classifier: class must not be empty".into());
    }
    if !is_safe_promoted_value(class) {
        return Err(format!("head_classifier: class {class:?} contains unsafe characters").into());
    }
    Ok(())
}

#[async_trait]
impl HttpFilter for HeadClassifierFilter {
    fn name(&self) -> &'static str {
        "head_classifier"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn runs_request_head(&self) -> bool {
        true
    }

    async fn on_request_head(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(class) = self.classify(ctx.request.uri.path()) else {
            return Ok(FilterAction::Continue);
        };
        let value = HeaderValue::from_str(class)
            .map_err(|err| -> FilterError { format!("head_classifier: invalid class value: {err}").into() })?;
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            HeaderName::from_static("x-praxis-head-class"),
            value,
        ));
        ctx.set_metadata("head_classifier.class", class);
        ctx.filter_results
            .entry("head_classifier")
            .or_default()
            .set("class", class.to_owned())?;
        trace!(head_class = class, "classified request from head");
        Ok(FilterAction::Continue)
    }
}
