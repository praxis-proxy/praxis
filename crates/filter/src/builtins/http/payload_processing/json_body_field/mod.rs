// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Extracts top-level JSON fields from the request body and promotes them to request headers.
//!
//! Parsing walks the complete top-level object without building a full DOM:
//! unmapped values are skipped, duplicate keys are last-wins (matching
//! `serde_json` and typical backend parsers), and trailing non-whitespace
//! content after the document blocks promotion so a promoted value always
//! matches what the backend will parse.

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

/// Per-request marker: this filter instance already promoted headers.
struct Promoted;

// -----------------------------------------------------------------------------
// JsonBodyFieldFilter
// -----------------------------------------------------------------------------

/// Extracts top-level fields from a JSON request body and promotes
/// their values to request headers using [`StreamBuffer`] mode.
///
/// Uses a map visitor (not a full JSON DOM). Unmapped values are skipped;
/// the whole top-level object is scanned so duplicate keys are last-wins
/// (matching `serde_json` and typical backend parsers), and trailing
/// non-whitespace content after the document blocks promotion.
///
/// On successful promotion the filter returns [`FilterAction::BodyDone`] so
/// [`StreamBuffer`] pre-read does not re-run extraction on later chunks
/// (including the frozen full body at EOS).
///
/// If the field is missing or the body is not valid JSON before the needed
/// fields are collected, the filter passes through without modification.
///
/// A promoted header can gate a later body filter in the same chain via that
/// filter's `conditions.headers`, which are evaluated against the effective
/// pre-read headers (the request overlaid with promotions from earlier
/// pre-read filters). The promoter must precede the gated filter. Use a
/// reserved `x-praxis-*` name for security-relevant gates so clients cannot
/// supply the header themselves.
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

    /// Field names from `mappings`, pre-built for the extraction walk.
    ///
    /// The extractor probes this on every JSON key it visits, and the
    /// hook can run once per buffered chunk; rebuilding the set from
    /// `mappings` each call allocated per chunk for config-stable data.
    needed: std::collections::HashSet<String>,
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
        let needed = mappings.iter().map(|(field, _)| field.clone()).collect();
        Ok(Box::new(Self {
            max_body_bytes,
            mappings,
            needed,
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
        // Skip re-entry after a successful promote (BodyDone also tells the
        // pipeline to stop calling us). Do not key off header names — an
        // incoming or pre-existing X-* must not block the first promotion.
        if ctx.get_filter_state::<Promoted>().is_some() {
            return Ok(FilterAction::BodyDone);
        }

        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        if extract_fields(&self.mappings, &self.needed, chunk, &mut ctx.extra_request_headers) {
            ctx.insert_filter_state(Promoted);
            // BodyDone skips this filter on remaining chunks; Release would
            // still re-enter at EOS and duplicate TrustedHeaderMutation::Add.
            Ok(FilterAction::BodyDone)
        } else {
            Ok(FilterAction::Continue)
        }
    }
}
