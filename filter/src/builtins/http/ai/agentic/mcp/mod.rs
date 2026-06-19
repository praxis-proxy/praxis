// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! MCP protocol filter for body-aware routing and static catalog behavior.

mod broker;
pub(crate) mod config;
pub(crate) mod envelope;
pub(crate) mod protocol;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
use tracing::{trace, warn};

use self::{
    config::{InvalidMcpBehavior, McpConfig, MismatchBehavior, MissingHeaderBehavior, build_config},
    envelope::{McpEnvelope, extract_mcp_envelope},
};
use super::{
    MAX_DYNAMIC_VALUE_LEN,
    json_rpc::{config::JsonRpcConfig, envelope::parse_json_rpc_value},
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::value_safety::contains_control_chars,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// McpFilter
// -----------------------------------------------------------------------------

/// Extracts MCP protocol metadata from JSON-RPC request bodies and promotes
/// method, tool/resource/prompt name, JSON-RPC kind, protocol version, and
/// session presence to request headers/filter results; stores session ID in
/// durable metadata.
///
/// Recognized methods include `initialize`, `tools/call`, `tools/list`,
/// `resources/read`, `resources/list`, `prompts/get`, `prompts/list`,
/// and `ping`.
///
/// Methods requiring a name selector (`tools/call`, `resources/read`,
/// `prompts/get`) return a JSON-RPC error if the selector is missing
/// and `on_invalid` is `reject`.
///
/// Writes `mcp.*` and `json_rpc.*` entries to the filter result set
/// for branch chain conditions.
///
/// # YAML
///
/// ```yaml
/// filter: mcp
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: mcp
/// max_body_bytes: 65536
/// on_invalid: reject
/// header_validation:
///   mismatch: reject
///   missing: ignore
/// headers:
///   method: x-praxis-mcp-method
///   name: x-praxis-mcp-name
///   kind: x-praxis-mcp-kind
///   protocol_version: x-praxis-mcp-protocol-version
///   session_present: x-praxis-mcp-session-present
/// ```
pub struct McpFilter {
    /// Parsed filter configuration.
    config: McpConfig,
    /// Shared JSON-RPC parser configuration.
    json_rpc_config: JsonRpcConfig,
    /// Maximum body bytes for `StreamBuffer`.
    max_body_bytes: usize,
}

impl McpFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        if broker::McpBrokerFilter::matches_config(config) {
            return broker::McpBrokerFilter::from_config(config);
        }

        let cfg: McpConfig = parse_filter_config("mcp", config)?;
        let validated_config = build_config(cfg)?;
        let max_body_bytes = validated_config.max_body_bytes;
        let json_rpc_config = build_json_rpc_config(max_body_bytes);

        Ok(Box::new(Self {
            config: validated_config,
            json_rpc_config,
            max_body_bytes,
        }))
    }
}

#[async_trait]
impl HttpFilter for McpFilter {
    fn name(&self) -> &'static str {
        "mcp"
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

    #[expect(
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
            Err(_) => return handle_non_mcp(&self.config),
        };

        let envelope = match parse_json_rpc_value(&value, &self.json_rpc_config) {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return handle_non_mcp(&self.config),
            Err(e) => return handle_parse_error(&e, &self.config),
        };

        let Some(method_str) = &envelope.method else {
            return handle_non_mcp(&self.config);
        };

        let mcp_envelope = extract_mcp_envelope(&value, method_str, &ctx.request.headers);

        if let Some(action) = reject_missing_required_selector(&mcp_envelope, &envelope, &self.config) {
            return Ok(action);
        }

        if let Err(action) = validate_mcp_headers(ctx, &mcp_envelope, &envelope, &self.config) {
            return Ok(action);
        }

        write_metadata(ctx, &envelope, &mcp_envelope);
        promote_mcp_headers(&mcp_envelope, &envelope, &self.config, &mut ctx.extra_request_headers);
        promote_filter_results(ctx, &envelope, &mcp_envelope)?;

        trace!(
            mcp_method = mcp_envelope.method.as_str(),
            mcp_name = ?mcp_envelope.name,
            session_present = mcp_envelope.session_id.is_some(),
            "extracted MCP envelope metadata"
        );

        Ok(FilterAction::Release)
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Build a `JsonRpcConfig` for the shared parser with MCP-appropriate defaults.
fn build_json_rpc_config(max_body_bytes: usize) -> JsonRpcConfig {
    use super::json_rpc::config::{BatchPolicy, InvalidJsonRpcBehavior, JsonRpcHeaders};

    JsonRpcConfig {
        batch_policy: BatchPolicy::Reject,
        headers: JsonRpcHeaders {
            id: None,
            kind: None,
            method: None,
        },
        max_body_bytes,
        on_invalid: InvalidJsonRpcBehavior::Continue,
    }
}

/// Handle JSON-RPC parse errors, separating batch rejection from general errors.
fn handle_parse_error(
    e: &super::json_rpc::envelope::JsonRpcParseError,
    config: &McpConfig,
) -> Result<FilterAction, FilterError> {
    use super::json_rpc::envelope::JsonRpcParseError;

    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            Ok(FilterAction::Reject(Rejection::status(400)))
        },
        _ => handle_non_mcp(config),
    }
}

/// Handle non-MCP input based on config.
#[expect(
    clippy::unnecessary_wraps,
    reason = "caller returns Result<FilterAction, FilterError> from trait method"
)]
fn handle_non_mcp(config: &McpConfig) -> Result<FilterAction, FilterError> {
    match config.on_invalid {
        InvalidMcpBehavior::Continue => Ok(FilterAction::Continue),
        InvalidMcpBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
    }
}

/// Selector-bearing methods cannot be trusted when the selector is absent or malformed.
fn reject_missing_required_selector(
    mcp: &McpEnvelope,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    config: &McpConfig,
) -> Option<FilterAction> {
    let requires = mcp.method.requires_name() || mcp.method.requires_uri();
    if requires && mcp.name.is_none() {
        match config.on_invalid {
            InvalidMcpBehavior::Reject => Some(mcp_invalid_params_rejection(envelope)),
            InvalidMcpBehavior::Continue => Some(FilterAction::Continue),
        }
    } else {
        None
    }
}

/// Validate `Mcp-Method` and `Mcp-Name` headers against body-derived values.
///
/// When `missing: synthesize` is configured and a standard MCP header is
/// absent, the body-derived value is injected as an upstream request header.
fn validate_mcp_headers(
    ctx: &mut HttpFilterContext<'_>,
    mcp: &McpEnvelope,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    config: &McpConfig,
) -> Result<(), FilterAction> {
    validate_single_header(ctx, "mcp-method", mcp.method.as_str(), envelope, config)?;

    if let Some(name) = &mcp.name {
        validate_single_header(ctx, "mcp-name", name, envelope, config)?;
    } else if ctx.request.headers.get("mcp-name").is_some() {
        match config.header_validation.mismatch {
            MismatchBehavior::Reject => {
                warn!("client sent Mcp-Name header but body method has no name");
                return Err(mcp_header_mismatch_rejection(envelope));
            },
            MismatchBehavior::Ignore => {},
        }
    }

    Ok(())
}

/// Validate a single MCP header value against its body-derived counterpart.
#[expect(clippy::too_many_lines, reason = "present/missing/invalid UTF-8 branches")]
fn validate_single_header(
    ctx: &mut HttpFilterContext<'_>,
    header_name: &str,
    body_value: &str,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    config: &McpConfig,
) -> Result<(), FilterAction> {
    match ctx.request.headers.get(header_name) {
        Some(raw_value) => {
            let Ok(header_value) = raw_value.to_str() else {
                match config.header_validation.mismatch {
                    MismatchBehavior::Reject => {
                        warn!(header_name = header_name, "MCP header contains invalid UTF-8");
                        return Err(mcp_header_mismatch_rejection(envelope));
                    },
                    MismatchBehavior::Ignore => return Ok(()),
                }
            };
            if header_value != body_value {
                match config.header_validation.mismatch {
                    MismatchBehavior::Reject => {
                        warn!(
                            header_name = header_name,
                            header_value = header_value,
                            body_value = body_value,
                            "MCP header/body mismatch"
                        );
                        return Err(mcp_header_mismatch_rejection(envelope));
                    },
                    MismatchBehavior::Ignore => {},
                }
            }
        },
        None => match config.header_validation.missing {
            MissingHeaderBehavior::Reject => {
                return Err(FilterAction::Reject(Rejection::status(400)));
            },
            MissingHeaderBehavior::Synthesize => {
                if !contains_control_chars(body_value) && body_value.len() <= MAX_DYNAMIC_VALUE_LEN {
                    ctx.extra_request_headers
                        .push((Cow::Owned(header_name.to_owned()), body_value.to_owned()));
                }
            },
            MissingHeaderBehavior::Ignore => {},
        },
    }

    Ok(())
}

/// Build the JSON-RPC error -32602 (`InvalidParams`) rejection.
fn mcp_invalid_params_rejection(envelope: &super::json_rpc::envelope::JsonRpcEnvelope) -> FilterAction {
    mcp_json_rpc_error_rejection(envelope, -32602, "InvalidParams")
}

/// Build the JSON-RPC error -32001 (`HeaderMismatch`) rejection.
fn mcp_header_mismatch_rejection(envelope: &super::json_rpc::envelope::JsonRpcEnvelope) -> FilterAction {
    mcp_json_rpc_error_rejection(envelope, -32001, "HeaderMismatch")
}

/// MCP rejections preserve JSON-RPC IDs so clients can correlate errors.
///
/// Returns HTTP 200 per the JSON-RPC over HTTP spec: application-level
/// errors are conveyed inside the JSON-RPC error object, not via HTTP
/// status codes. Only transport-level failures (malformed HTTP, non-JSON
/// bodies) use HTTP 4xx.
fn mcp_json_rpc_error_rejection(
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    code: i32,
    message: &str,
) -> FilterAction {
    use super::json_rpc::envelope::JsonRpcIdKind;

    let id_json = match (&envelope.id, &envelope.id_kind) {
        (Some(id), JsonRpcIdKind::Integer | JsonRpcIdKind::Number) => id.clone(),
        (Some(id), JsonRpcIdKind::String) => serde_json::to_string(id).unwrap_or_else(|_| "null".to_owned()),
        _ => "null".to_owned(),
    };
    let message_json = serde_json::to_string(message).unwrap_or_else(|_| "\"internal error\"".to_owned());
    let body = Bytes::from(format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{code},"message":{message_json}}},"id":{id_json}}}"#,
    ));
    FilterAction::Reject(
        Rejection::status(200)
            .with_header("content-type", "application/json")
            .with_body(body),
    )
}

/// Write durable metadata that persists across all Pingora lifecycle phases.
fn write_metadata(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    mcp: &McpEnvelope,
) {
    let max_len = MAX_DYNAMIC_VALUE_LEN;

    let method_str = mcp.method.as_str();
    if !contains_control_chars(method_str) && method_str.len() <= max_len {
        ctx.set_metadata("json_rpc.method", method_str);
        ctx.set_metadata("mcp.method", method_str);
    }
    ctx.set_metadata("json_rpc.kind", envelope.kind.as_str());

    if let Some(name) = &mcp.name
        && !contains_control_chars(name)
        && name.len() <= max_len
    {
        ctx.set_metadata("mcp.name", name.clone());
    }
    if let Some(sid) = &mcp.session_id
        && !contains_control_chars(sid)
    {
        ctx.set_metadata("mcp.session_id", sid.clone());
    }
    if let Some(pv) = &mcp.protocol_version
        && !contains_control_chars(pv)
    {
        ctx.set_metadata("mcp.protocol_version", pv.clone());
    }
}

/// Promote MCP metadata to internal request headers.
fn promote_mcp_headers(
    mcp: &McpEnvelope,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    config: &McpConfig,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) {
    let max_len = MAX_DYNAMIC_VALUE_LEN;

    if let Some(header_name) = &config.headers.method {
        let method_str = mcp.method.as_str();
        if !contains_control_chars(method_str) && method_str.len() <= max_len {
            headers.push((Cow::Owned(header_name.clone()), method_str.to_owned()));
        }
    }

    if let Some(header_name) = &config.headers.name
        && let Some(name) = &mcp.name
        && !contains_control_chars(name)
        && name.len() <= max_len
    {
        headers.push((Cow::Owned(header_name.clone()), name.clone()));
    }

    if let Some(header_name) = &config.headers.protocol_version
        && let Some(pv) = &mcp.protocol_version
        && !contains_control_chars(pv)
    {
        headers.push((Cow::Owned(header_name.clone()), pv.clone()));
    }

    if let Some(header_name) = &config.headers.kind {
        headers.push((Cow::Owned(header_name.clone()), envelope.kind.as_str().to_owned()));
    }

    if let Some(header_name) = &config.headers.session_present {
        let present = if mcp.session_id.is_some() { "true" } else { "false" };
        headers.push((Cow::Owned(header_name.clone()), present.to_owned()));
    }
}

/// Promote MCP metadata to filter results for router branch conditions.
fn promote_filter_results(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &super::json_rpc::envelope::JsonRpcEnvelope,
    mcp: &McpEnvelope,
) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("mcp").or_default();
    let method_str = mcp.method.as_str();
    if !contains_control_chars(method_str) {
        results.set("method", method_str.to_owned())?;
    }

    if let Some(name) = &mcp.name
        && !contains_control_chars(name)
    {
        results.set("name", name.clone())?;
    }

    if let Some(pv) = &mcp.protocol_version
        && !contains_control_chars(pv)
    {
        results.set("protocol_version", pv.clone())?;
    }

    let session_present = if mcp.session_id.is_some() { "true" } else { "false" };
    results.set("session_present", session_present)?;
    results.set("kind", envelope.kind.as_str())?;

    Ok(())
}
