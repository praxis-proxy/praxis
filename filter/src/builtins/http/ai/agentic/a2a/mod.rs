// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! A2A protocol classifier filter for body-aware routing.

pub(crate) mod config;
pub(crate) mod envelope;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use std::borrow::Cow;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::trace;

use self::{
    config::{A2aConfig, InvalidA2aBehavior, build_config},
    envelope::{A2aEnvelope, extract_a2a_envelope},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::ai::agentic::json_rpc::{
        config::JsonRpcConfig, contains_control_chars, envelope::parse_json_rpc_value,
    },
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum length for dynamic values before promotion (256 bytes to match durable metadata limit).
const MAX_DYNAMIC_VALUE_LEN: usize = 256;

// -----------------------------------------------------------------------------
// A2aFilter
// -----------------------------------------------------------------------------

/// Extracts A2A protocol metadata from JSON-RPC request bodies and promotes
/// method, family, task ID, streaming detection, and version to request headers,
/// filter results, and durable metadata for routing.
///
/// # YAML
///
/// ```yaml
/// filter: a2a
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: a2a
/// max_body_bytes: 65536
/// on_invalid: reject
/// method_aliases:
///   message/send: SendMessage
///   message/stream: SendStreamingMessage
///   tasks/get: GetTask
///   tasks/cancel: CancelTask
/// headers:
///   method: x-praxis-a2a-method
///   family: x-praxis-a2a-family
///   task_id: x-praxis-a2a-task-id
///   kind: x-praxis-a2a-kind
///   streaming: x-praxis-a2a-streaming
///   version: x-praxis-a2a-version
/// ```
pub struct A2aFilter {
    /// Parsed filter configuration.
    config: A2aConfig,

    /// Shared JSON-RPC parser configuration.
    json_rpc_config: JsonRpcConfig,

    /// Maximum body bytes for `StreamBuffer`.
    max_body_bytes: usize,
}

impl A2aFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: A2aConfig = parse_filter_config("a2a", config)?;
        let validated_config = build_config(cfg)?;
        let json_rpc_config = build_json_rpc_config(validated_config.max_body_bytes);

        Ok(Box::new(Self {
            max_body_bytes: validated_config.max_body_bytes,
            config: validated_config,
            json_rpc_config,
        }))
    }
}

#[async_trait]
impl HttpFilter for A2aFilter {
    fn name(&self) -> &'static str {
        "a2a"
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

    #[allow(
        clippy::too_many_lines,
        reason = "sequential parse-extract-validate-promote pipeline"
    )]
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let value: serde_json::Value = match serde_json::from_slice(chunk) {
            Ok(v) => v,
            Err(_) => return handle_non_a2a(&self.config),
        };

        let envelope = match parse_json_rpc_value(&value, &self.json_rpc_config) {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return handle_non_a2a(&self.config),
            Err(ref e) => return handle_parse_error(e, &self.config),
        };

        let Some(method_str) = &envelope.method else {
            return handle_non_a2a(&self.config);
        };

        let a2a_envelope = extract_a2a_envelope(&value, method_str, &self.config.method_aliases, &ctx.request.headers);

        write_metadata(ctx, &envelope, &a2a_envelope);
        promote_a2a_headers(&a2a_envelope, &envelope, &self.config, &mut ctx.extra_request_headers);
        promote_filter_results(ctx, &envelope, &a2a_envelope)?;

        trace!(
            a2a_method = a2a_envelope.method.as_str(),
            a2a_family = a2a_envelope.family.as_str(),
            streaming = a2a_envelope.streaming,
            task_id = ?a2a_envelope.task_id,
            version = ?a2a_envelope.version,
            "extracted A2A envelope metadata"
        );

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a `JsonRpcConfig` for the shared parser with A2A-appropriate defaults.
fn build_json_rpc_config(max_body_bytes: usize) -> JsonRpcConfig {
    use crate::builtins::http::ai::agentic::json_rpc::config::{BatchPolicy, InvalidJsonRpcBehavior, JsonRpcHeaders};

    JsonRpcConfig {
        max_body_bytes,
        // A2A classification produces one static routing decision per request.
        // JSON-RPC batches can mix methods, task IDs, and streaming semantics,
        // so reject them instead of routing by an arbitrary batch element.
        batch_policy: BatchPolicy::Reject,
        on_invalid: InvalidJsonRpcBehavior::Continue,
        headers: JsonRpcHeaders {
            method: None,
            id: None,
            kind: None,
        },
    }
}

/// Handle JSON-RPC parse errors, separating batch rejection from general errors.
fn handle_parse_error(
    e: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcParseError,
    config: &A2aConfig,
) -> Result<FilterAction, FilterError> {
    use crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcParseError;

    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            Ok(FilterAction::Reject(Rejection::status(400)))
        },
        _ => handle_non_a2a(config),
    }
}

/// Handle non-A2A input based on config.
#[allow(
    clippy::unnecessary_wraps,
    reason = "caller returns Result<FilterAction, FilterError> from trait method"
)]
fn handle_non_a2a(config: &A2aConfig) -> Result<FilterAction, FilterError> {
    match config.on_invalid {
        InvalidA2aBehavior::Continue => Ok(FilterAction::Continue),
        InvalidA2aBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
    }
}

/// Write durable metadata that persists across all Pingora lifecycle phases.
fn write_metadata(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    a2a: &A2aEnvelope,
) {
    let method_str = a2a.method.as_str();

    set_safe_metadata(ctx, "json_rpc.method", envelope.method.as_deref());

    if is_promotable(method_str) {
        ctx.set_metadata("a2a.method", method_str);
    }
    ctx.set_metadata("json_rpc.kind", envelope.kind.as_str());

    set_safe_metadata(ctx, "a2a.original_method", a2a.original_method.as_deref());
    ctx.set_metadata("a2a.family", a2a.family.as_str());
    ctx.set_metadata("a2a.streaming", if a2a.streaming { "true" } else { "false" });
    set_safe_metadata(ctx, "a2a.task_id", a2a.task_id.as_deref());
    set_safe_metadata(ctx, "a2a.version", a2a.version.as_deref());
}

/// Write a dynamic value to durable metadata if it is within promotion bounds.
fn set_safe_metadata(ctx: &mut HttpFilterContext<'_>, key: &str, value: Option<&str>) {
    if let Some(v) = value
        && is_promotable(v)
    {
        ctx.set_metadata(key, v);
    }
}

/// Whether a dynamic value is safe and bounded for promotion to headers/metadata.
fn is_promotable(value: &str) -> bool {
    !contains_control_chars(value) && value.len() <= MAX_DYNAMIC_VALUE_LEN
}

/// Promote A2A metadata to internal request headers.
fn promote_a2a_headers(
    a2a: &A2aEnvelope,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    config: &A2aConfig,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) {
    if let Some(header_name) = &config.headers.method {
        let method_str = a2a.method.as_str();
        if !contains_control_chars(method_str) && method_str.len() <= MAX_DYNAMIC_VALUE_LEN {
            headers.push((Cow::Owned(header_name.clone()), method_str.to_owned()));
        }
    }

    if let Some(header_name) = &config.headers.family {
        headers.push((Cow::Owned(header_name.clone()), a2a.family.as_str().to_owned()));
    }

    promote_optional_header(&config.headers.task_id, a2a.task_id.as_deref(), headers);

    if let Some(header_name) = &config.headers.kind {
        headers.push((Cow::Owned(header_name.clone()), envelope.kind.as_str().to_owned()));
    }

    if let Some(header_name) = &config.headers.streaming {
        let streaming = if a2a.streaming { "true" } else { "false" };
        headers.push((Cow::Owned(header_name.clone()), streaming.to_owned()));
    }

    promote_optional_header(&config.headers.version, a2a.version.as_deref(), headers);
}

/// Promote a dynamic optional value to a request header if configured and safe.
fn promote_optional_header(
    header_name: &Option<String>,
    value: Option<&str>,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) {
    if let Some(header_name) = header_name
        && let Some(value) = value
        && is_promotable(value)
    {
        headers.push((Cow::Owned(header_name.clone()), value.to_owned()));
    }
}

/// Promote A2A metadata to filter results for router branch conditions.
fn promote_filter_results(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    a2a: &A2aEnvelope,
) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("a2a").or_default();

    let method_str = a2a.method.as_str();
    if is_promotable(method_str) {
        results.set("method", method_str.to_owned())?;
    }

    results.set("family", a2a.family.as_str())?;
    results.set("streaming", if a2a.streaming { "true" } else { "false" })?;
    results.set("kind", envelope.kind.as_str())?;

    set_optional_result(results, "task_id", a2a.task_id.as_deref())?;
    set_optional_result(results, "version", a2a.version.as_deref())?;

    Ok(())
}

/// Set a dynamic optional value in filter results if safe and bounded.
fn set_optional_result(
    results: &mut crate::results::FilterResultSet,
    key: &'static str,
    value: Option<&str>,
) -> Result<(), FilterError> {
    if let Some(v) = value
        && is_promotable(v)
    {
        results.set(key, v.to_owned())?;
    }
    Ok(())
}
