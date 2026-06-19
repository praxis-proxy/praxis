// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Extracts top-level JSON fields from the request body and promotes them to request headers.

mod config;
mod extract;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::debug;

use self::{
    config::{JsonBodyFieldConfig, build_mappings},
    extract::extract_fields,
};
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// JsonBodyFieldFilter
// -----------------------------------------------------------------------------

/// Extracts top-level fields from a JSON request body and promotes
/// their values to request headers using [`StreamBuffer`] mode.
///
/// If the field is missing or the body is not valid JSON, the filter
/// passes through without modification.
///
/// # Single-field YAML
///
/// ```yaml
/// filter: json_body_field
/// field: model
/// header: X-Model
/// ```
///
/// # Multi-field YAML
///
/// ```yaml
/// filter: json_body_field
/// fields:
///   - field: model
///     header: X-Model
///   - field: user_id
///     header: X-User-Id
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::JsonBodyFieldFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// field: model
/// header: X-Model
/// "#,
/// )
/// .unwrap();
/// let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "json_body_field");
/// ```
///
/// [`StreamBuffer`]: crate::BodyMode::StreamBuffer
pub struct JsonBodyFieldFilter {
    /// Maximum body size for `StreamBuffer` mode.
    max_body_bytes: usize,

    /// Field-to-header mappings: `(json_field_name, header_name)`.
    pub(crate) mappings: Vec<(String, String)>,
}

impl JsonBodyFieldFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// Accepts either single-field (`field`/`header`) or multi-field
    /// (`fields` list) syntax.
    ///
    /// ```ignore
    /// use praxis_filter::JsonBodyFieldFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// fields:
    ///   - field: model
    ///     header: X-Model
    ///   - field: user_id
    ///     header: X-User-Id
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = JsonBodyFieldFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "json_body_field");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid or field mappings are empty.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: JsonBodyFieldConfig = parse_filter_config("json_body_field", config)?;
        let max_body_bytes = cfg.max_body_bytes;
        let mappings = build_mappings(cfg)?;
        Ok(Box::new(Self {
            max_body_bytes,
            mappings,
        }))
    }
}

#[async_trait]
impl HttpFilter for JsonBodyFieldFilter {
    fn name(&self) -> &'static str {
        "json_body_field"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(chunk) else {
            debug!(body_len = chunk.len(), "JSON parsing failed; skipping field extraction");
            return Ok(FilterAction::Continue);
        };

        if extract_fields(&self.mappings, &value, &mut ctx.extra_request_headers) {
            Ok(FilterAction::Release)
        } else {
            Ok(FilterAction::Continue)
        }
    }
}
