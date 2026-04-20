// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the JSON body field filter.

use serde::Deserialize;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Body Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (10 MiB).
pub(super) const DEFAULT_MAX_BODY_BYTES: usize = 10_485_760;

// -----------------------------------------------------------------------------
// JsonBodyFieldMapping
// -----------------------------------------------------------------------------

/// A single field-to-header mapping used in the `fields` list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonBodyFieldMapping {
    /// Top-level JSON field name to extract.
    pub field: String,

    /// Request header name to promote the extracted value into.
    pub header: String,
}

// -----------------------------------------------------------------------------
// JsonBodyFieldConfig
// -----------------------------------------------------------------------------

/// YAML configuration for [`JsonBodyFieldFilter`].
///
/// Accepts either single-field syntax (`field` + `header`) or
/// multi-field syntax (`fields` list), but not both.
///
/// [`JsonBodyFieldFilter`]: super::JsonBodyFieldFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonBodyFieldConfig {
    /// Single-field: top-level JSON field name to extract.
    pub field: Option<String>,

    /// Single-field: request header name to promote into.
    pub header: Option<String>,

    /// Multi-field: list of field-to-header mappings.
    pub fields: Option<Vec<JsonBodyFieldMapping>>,
}

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

/// Validate a single field-to-header mapping.
fn validate_mapping(field: &str, header: &str) -> Result<(), FilterError> {
    if field.is_empty() {
        return Err("json_body_field: 'field' must not be empty".into());
    }
    if header.is_empty() {
        return Err("json_body_field: 'header' must not be empty".into());
    }
    Ok(())
}

/// Build the mappings vec from either single-field or multi-field
/// config syntax.
pub(super) fn build_mappings(cfg: JsonBodyFieldConfig) -> Result<Vec<(String, String)>, FilterError> {
    let has_single = cfg.field.is_some() || cfg.header.is_some();
    let has_multi = cfg.fields.is_some();

    if has_single && has_multi {
        return Err("json_body_field: use 'field'/'header' or 'fields', not both".into());
    }

    if let Some(fields) = cfg.fields {
        if fields.is_empty() {
            return Err("json_body_field: 'fields' must not be empty".into());
        }
        let mut mappings = Vec::with_capacity(fields.len());
        for m in fields {
            validate_mapping(&m.field, &m.header)?;
            mappings.push((m.field, m.header));
        }
        return Ok(mappings);
    }

    let field = cfg.field.ok_or("json_body_field: 'field' is required")?;
    let header = cfg.header.ok_or("json_body_field: 'header' is required")?;
    validate_mapping(&field, &header)?;
    Ok(vec![(field, header)])
}
