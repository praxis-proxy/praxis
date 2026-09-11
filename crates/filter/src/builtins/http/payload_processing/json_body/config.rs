// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! YAML configuration for the JSON body pointer filter.

use serde::Deserialize;

use crate::{
    FilterError,
    body::DEFAULT_JSON_BODY_MAX_BYTES,
    builtins::http::payload_processing::{OnInvalidBehavior, config_validation::validate_max_body_bytes},
    json_ops::{ExtractDest, JsonError, JsonOps, JsonValue},
};

// -----------------------------------------------------------------------------
// YAML types
// -----------------------------------------------------------------------------

/// YAML configuration for [`super::JsonBodyFilter`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonBodyConfig {
    /// Pointers to insert (or overwrite, for existing object keys) on the request body.
    #[serde(default)]
    pub request_add: Vec<PointerOpConfig>,

    /// Pointers to omit from the request body.
    #[serde(default)]
    pub request_remove: Vec<String>,

    /// Pointers to overwrite on the request body when present.
    #[serde(default)]
    pub request_replace: Vec<PointerOpConfig>,

    /// Pointers whose JSON is copied into request-scoped context.
    ///
    /// `filter_metadata` values are capped at 256 bytes by the context.
    /// Use `structured_metadata` for nested or larger values. Use `header`
    /// to promote into `extra_request_headers` (request extract only).
    #[serde(default)]
    pub request_extract: Vec<ExtractOpConfig>,

    /// Rejected when non-empty. Response add can grow the body after
    /// `Content-Length` is committed.
    // Named field so the error mentions `response_add` instead of serde unknown-field.
    #[serde(default)]
    pub response_add: Vec<PointerOpConfig>,

    /// Pointers to omit from the response body. Shrinks are padded with
    /// trailing spaces so `Content-Length` still matches.
    #[serde(default)]
    pub response_remove: Vec<String>,

    /// Rejected when non-empty. Response replace can grow the body after
    /// `Content-Length` is committed.
    // Named field so the error mentions `response_replace` instead of serde unknown-field.
    #[serde(default)]
    pub response_replace: Vec<PointerOpConfig>,

    /// Pointers whose JSON is copied into request-scoped context from the response body.
    #[serde(default)]
    pub response_extract: Vec<ExtractOpConfig>,

    /// Maximum body size in bytes for `StreamBuffer` mode.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Behavior when the body is not valid JSON.
    #[serde(default = "OnInvalidBehavior::default_continue")]
    pub on_invalid: OnInvalidBehavior,
}

/// A pointer plus exactly one of `value`, `metadata`, `structured_metadata`, or `env_var`.
///
/// Four `Option` fields rather than a serde enum: the generated filter-docs
/// table needs named YAML keys, and `value_source` can say "exactly one of".
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PointerOpConfig {
    /// JSON Pointer (RFC 6901) identifying the target.
    pub pointer: String,

    /// Static JSON value (YAML maps to JSON). Mutually exclusive with the other sources.
    pub value: Option<serde_json::Value>,

    /// `filter_metadata` key; injected as a JSON string. Mutually exclusive with the other sources.
    pub metadata: Option<String>,

    /// Namespaced structured metadata; injected as JSON as-is. Mutually exclusive with the other sources.
    pub structured_metadata: Option<StructuredMetadataRef>,

    /// Environment variable read once at filter construction. Mutually exclusive
    /// with the other sources. Valid JSON in the variable is injected as-is;
    /// otherwise the raw text is injected as a JSON string.
    pub env_var: Option<String>,
}

/// A pointer plus exactly one of `metadata`, `structured_metadata`, or `header` as the extract destination.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExtractOpConfig {
    /// JSON Pointer (RFC 6901) identifying the value to copy.
    pub pointer: String,

    /// `filter_metadata` key to write. Mutually exclusive with the other destinations.
    ///
    /// JSON strings are stored decoded; other values are stored as their source JSON
    /// text. Values over 256 bytes are dropped by the context.
    pub metadata: Option<String>,

    /// Namespaced structured metadata to write. Mutually exclusive with the other destinations.
    pub structured_metadata: Option<StructuredMetadataRef>,

    /// Request header to promote the extracted value into. Mutually exclusive with
    /// the other destinations. JSON strings are promoted decoded; other values use
    /// their source JSON text. Values over 256 bytes or containing control
    /// characters are skipped. Not supported on `response_extract`.
    pub header: Option<String>,
}

/// Namespace + key addressing [`HttpFilterContext::get_structured_metadata`].
///
/// [`HttpFilterContext::get_structured_metadata`]: crate::HttpFilterContext::get_structured_metadata
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredMetadataRef {
    /// Structured-metadata namespace.
    pub namespace: String,

    /// Field within the namespace object.
    pub key: String,
}

/// Default maximum body size (10 MiB).
fn default_max_body_bytes() -> usize {
    DEFAULT_JSON_BODY_MAX_BYTES
}

/// Request-side and response-side compiled operations.
pub(super) struct CompiledOps {
    /// Request-body operations.
    pub request: JsonOps,
    /// Response-body operations.
    pub response: JsonOps,
}

/// Validate config and compile pointers through [`JsonOps::builder`](crate::json_ops::JsonOps::builder).
///
/// # Errors
///
/// Returns [`FilterError`] when no operations are configured, a pointer is
/// invalid, value sources are missing or duplicated, pointers overlap within
/// a direction, `response_add` or `response_replace` is set, or
/// `max_body_bytes` is out of range.
pub(super) fn build_ops(cfg: JsonBodyConfig) -> Result<(usize, OnInvalidBehavior, CompiledOps), FilterError> {
    validate_max_body_bytes("json_body", cfg.max_body_bytes)?;

    if !cfg.response_add.is_empty() || !cfg.response_replace.is_empty() {
        return Err("json_body: response_add and response_replace are not supported; \
             response Content-Length is already committed. Use response_remove or response_extract"
            .into());
    }

    let request = compile_direction(
        "request",
        cfg.request_add,
        cfg.request_replace,
        cfg.request_remove,
        cfg.request_extract,
    )?;
    let response = compile_direction(
        "response",
        Vec::new(),
        Vec::new(),
        cfg.response_remove,
        cfg.response_extract,
    )?;

    if request.is_empty() && response.is_empty() {
        return Err("json_body: at least one add, remove, replace, or extract operation is required".into());
    }

    Ok((cfg.max_body_bytes, cfg.on_invalid, CompiledOps { request, response }))
}

/// Compile one direction's extract/add/replace/remove lists.
fn compile_direction(
    direction: &str,
    add: Vec<PointerOpConfig>,
    replace: Vec<PointerOpConfig>,
    remove: Vec<String>,
    extract: Vec<ExtractOpConfig>,
) -> Result<JsonOps, FilterError> {
    let mut builder = JsonOps::builder();
    for cfg in extract {
        builder = builder
            .extract(&cfg.pointer, extract_dest(direction, &cfg)?)
            .map_err(|e| json_err(&e))?;
    }
    for cfg in add {
        builder = builder
            .add(&cfg.pointer, value_source(direction, "add", &cfg)?)
            .map_err(|e| json_err(&e))?;
    }
    for cfg in replace {
        builder = builder
            .replace(&cfg.pointer, value_source(direction, "replace", &cfg)?)
            .map_err(|e| json_err(&e))?;
    }
    for pointer in remove {
        builder = builder.remove(pointer).map_err(|e| json_err(&e))?;
    }
    builder.build().map_err(|e| json_err(&e))
}

/// Map engine errors onto the filter's `json_body:` prefix.
fn json_err(err: &JsonError) -> FilterError {
    format!("json_body: {err}").into()
}

/// Require exactly one of `metadata`, `structured_metadata`, or `header`.
fn extract_dest(direction: &str, cfg: &ExtractOpConfig) -> Result<ExtractDest, FilterError> {
    let n = usize::from(cfg.metadata.is_some())
        + usize::from(cfg.structured_metadata.is_some())
        + usize::from(cfg.header.is_some());
    if n != 1 {
        return Err(extract_dest_count_error(direction, &cfg.pointer));
    }
    if let Some(key) = &cfg.metadata {
        return Ok(ExtractDest::metadata(key.clone()));
    }
    if let Some(header) = &cfg.header {
        return extract_dest_header(direction, &cfg.pointer, header);
    }
    match &cfg.structured_metadata {
        Some(meta) => Ok(ExtractDest::structured(meta.namespace.clone(), meta.key.clone())),
        None => Err(extract_dest_count_error(direction, &cfg.pointer)),
    }
}

/// Error when an extract op does not set exactly one destination field.
fn extract_dest_count_error(direction: &str, pointer: &str) -> FilterError {
    format!(
        "json_body: {direction}_extract pointer '{pointer}' must set exactly one of \
         'metadata', 'structured_metadata', or 'header'"
    )
    .into()
}

/// Map a YAML header extract destination after request/response checks.
fn extract_dest_header(direction: &str, pointer: &str, header: &str) -> Result<ExtractDest, FilterError> {
    if direction == "response" {
        return Err(format!(
            "json_body: response_extract pointer '{pointer}' cannot use 'header'; \
             use metadata or structured_metadata"
        )
        .into());
    }
    if header.is_empty() {
        return Err(format!("json_body: {direction}_extract pointer '{pointer}' 'header' must not be empty").into());
    }
    if http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
        return Err(
            format!("json_body: {direction}_extract pointer '{pointer}' has invalid header name '{header}'").into(),
        );
    }
    Ok(ExtractDest::header(header))
}

/// Require exactly one of `value`, `metadata`, `structured_metadata`, or `env_var`.
fn value_source(direction: &str, section: &str, cfg: &PointerOpConfig) -> Result<JsonValue, FilterError> {
    let n = usize::from(cfg.value.is_some())
        + usize::from(cfg.metadata.is_some())
        + usize::from(cfg.structured_metadata.is_some())
        + usize::from(cfg.env_var.is_some());
    if n != 1 {
        return Err(format!(
            "json_body: {direction}_{section} pointer '{}' must set exactly one of \
             'value', 'metadata', 'structured_metadata', or 'env_var'",
            cfg.pointer
        )
        .into());
    }
    if let Some(value) = cfg.value.clone() {
        return JsonValue::static_json(value).map_err(|e| json_err(&e));
    }
    if let Some(key) = &cfg.metadata {
        return Ok(JsonValue::metadata(key.clone()));
    }
    if let Some(var) = &cfg.env_var {
        return JsonValue::env_var(var.clone()).map_err(|e| json_err(&e));
    }
    match &cfg.structured_metadata {
        Some(meta) => Ok(JsonValue::structured(meta.namespace.clone(), meta.key.clone())),
        None => Err(format!(
            "json_body: {direction}_{section} pointer '{}' must set exactly one of \
             'value', 'metadata', 'structured_metadata', or 'env_var'",
            cfg.pointer
        )
        .into()),
    }
}
