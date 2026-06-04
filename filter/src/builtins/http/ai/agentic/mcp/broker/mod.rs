// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! MCP static catalog filter: static tool catalog, prefix management, and broker
//! behavior for `initialize`, `tools/list`, `ping`, and `notifications`.

pub(crate) mod config;

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

use async_trait::async_trait;
use bytes::Bytes;
use rand::{TryRngCore, rngs::OsRng};
use tracing::{debug, trace};

use self::config::{CatalogTool, McpBrokerConfig, build_config};
use super::protocol;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::{
        ai::agentic::json_rpc::{
            config::JsonRpcConfig,
            envelope::{JsonRpcEnvelope, JsonRpcIdKind, JsonRpcKind, parse_json_rpc_value},
        },
        value_safety::contains_control_chars,
    },
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Server name reported in MCP initialize responses.
const SERVER_NAME: &str = "praxis";

// -----------------------------------------------------------------------------
// McpBrokerFilter
// -----------------------------------------------------------------------------

/// MCP static catalog filter that aggregates tool catalogs from multiple backend
/// MCP servers and handles `initialize`, `tools/list`, `tools/call`, `ping`,
/// and `notifications/initialized` directly as a static broker.
///
/// This first MCP static catalog change short-circuits all methods: no request is
/// forwarded to backends. `tools/call` returns a controlled `-32601` error
/// until backend routing is added.
///
/// # YAML
///
/// ```yaml
/// filter: mcp
/// path: /mcp
/// max_body_bytes: 65536
/// servers:
///   - name: weather
///     cluster: weather-mcp
///     path: /mcp
///     tool_prefix: weather_
///     tools:
///       - name: get_weather
///         description: Get current weather
///   - name: calendar
///     cluster: calendar-mcp
///     path: /mcp
///     tool_prefix: cal_
///     tools:
///       - name: create_event
///         description: Create a calendar event
/// ```
pub(crate) struct McpBrokerFilter {
    /// Static tool catalog built from config.
    catalog: Vec<CatalogTool>,
    /// Protocol version the broker uses in `initialize` responses.
    default_version: String,
    /// Shared JSON-RPC parser configuration.
    json_rpc_config: JsonRpcConfig,
    /// Maximum body bytes for `StreamBuffer`.
    max_body_bytes: usize,
    /// Configured protocol profile (stored for future profile-aware dispatch).
    #[allow(dead_code, reason = "plumbing for follow-up profile-aware behavior")]
    protocol_profile: protocol::ProtocolProfile,
    /// Public path this MCP broker handles (e.g. `/mcp`).
    public_path: String,
    /// Implemented versions used for protocol version negotiation.
    supported_versions: Vec<String>,
}

impl McpBrokerFilter {
    /// Return true when this MCP config selects static catalog behavior.
    pub(crate) fn matches_config(config: &serde_yaml::Value) -> bool {
        config.get("servers").is_some()
    }

    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid or if
    /// the static tool catalog cannot be serialized.
    pub(crate) fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: McpBrokerConfig = parse_filter_config("mcp", config)?;
        let (validated, catalog) = build_config(cfg)?;

        let json_rpc_config = build_json_rpc_config(validated.max_body_bytes);

        Ok(Box::new(Self {
            catalog,
            default_version: validated.default_version.clone(),
            json_rpc_config,
            max_body_bytes: validated.max_body_bytes,
            protocol_profile: validated.protocol_profile,
            public_path: validated.path.clone(),
            supported_versions: validated.supported_versions.clone(),
        }))
    }
}

#[async_trait]
impl HttpFilter for McpBrokerFilter {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if !request_path_matches(&ctx.request.uri, &self.public_path) {
            return Ok(FilterAction::Reject(Rejection::status(404)));
        }

        match ctx.request.method {
            http::Method::POST => Ok(FilterAction::Continue),
            http::Method::DELETE => Ok(handle_delete(ctx)),
            _ => Ok(FilterAction::Reject(Rejection::status(405))),
        }
    }

    #[allow(clippy::too_many_lines, reason = "sequential parse-extract-dispatch pipeline")]
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if ctx.request.method != http::Method::POST {
            return Ok(FilterAction::Continue);
        }

        if !request_path_matches(&ctx.request.uri, &self.public_path) {
            return Ok(FilterAction::Reject(Rejection::status(404)));
        }

        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(chunk) else {
            return Ok(FilterAction::Reject(Rejection::status(400)));
        };

        let Ok(Some(envelope)) = parse_json_rpc_value(&value, &self.json_rpc_config) else {
            return Ok(FilterAction::Reject(Rejection::status(400)));
        };

        let Some(ref method_str) = envelope.method else {
            return Ok(FilterAction::Reject(Rejection::status(400)));
        };

        if !contains_control_chars(method_str) {
            ctx.set_metadata("json_rpc.method", method_str.clone());
            ctx.set_metadata("mcp.method", method_str.clone());
        }

        dispatch_method(
            ctx,
            &self.catalog,
            &value,
            &envelope,
            method_str,
            &self.supported_versions,
            &self.default_version,
        )
    }
}

// -----------------------------------------------------------------------------
// Method Dispatch
// -----------------------------------------------------------------------------

/// Maps a JSON-RPC method to the MCP handler that owns it.
/// Never returns [`FilterAction::Release`] — all paths produce
/// a terminal synthetic response.
#[allow(
    clippy::too_many_arguments,
    reason = "project threshold is 5; version plumbing adds two"
)]
fn dispatch_method(
    ctx: &mut HttpFilterContext<'_>,
    catalog: &[CatalogTool],
    value: &serde_json::Value,
    envelope: &JsonRpcEnvelope,
    method_str: &str,
    supported_versions: &[String],
    default_version: &str,
) -> Result<FilterAction, FilterError> {
    if method_str.starts_with("notifications/") {
        return Ok(handle_notification(envelope));
    }

    if !has_valid_request_id(envelope) {
        return Ok(invalid_request_action(envelope));
    }

    let action = match method_str {
        "initialize" => handle_initialize(ctx, value, envelope, supported_versions, default_version)?,
        "tools/list" => handle_tools_list(catalog, envelope)?,
        "tools/call" => json_rpc_error_action(envelope, -32601, "method not yet supported"),
        "ping" => handle_ping(envelope),
        _ => {
            debug!(method_len = method_str.len(), "unsupported MCP method");
            json_rpc_error_action(envelope, -32601, "method not found")
        },
    };

    Ok(action)
}

/// MCP notifications are one-way messages, so successful handling must not
/// produce a JSON-RPC response body.
fn handle_notification(envelope: &JsonRpcEnvelope) -> FilterAction {
    if matches!(envelope.kind, JsonRpcKind::Notification) && matches!(envelope.id_kind, JsonRpcIdKind::Missing) {
        FilterAction::Reject(Rejection::status(202))
    } else {
        invalid_request_action(envelope)
    }
}

/// MCP request ids are narrower than JSON-RPC's parser accepts.
fn has_valid_request_id(envelope: &JsonRpcEnvelope) -> bool {
    matches!(envelope.id_kind, JsonRpcIdKind::String | JsonRpcIdKind::Integer)
}

/// Invalid request responses use id `null` when the client omitted or nulled
/// the request id, matching JSON-RPC error-envelope conventions.
fn invalid_request_action(envelope: &JsonRpcEnvelope) -> FilterAction {
    let id_json = match envelope.id_kind {
        JsonRpcIdKind::String | JsonRpcIdKind::Integer => format_id_json(envelope),
        JsonRpcIdKind::Number | JsonRpcIdKind::Null | JsonRpcIdKind::Missing => "null".to_owned(),
    };
    json_rpc_error_action_with_id(&id_json, -32600, "invalid request")
}

// -----------------------------------------------------------------------------
// Request Handlers
// -----------------------------------------------------------------------------

/// Returns 204 when a valid `Mcp-Session-Id` header is present, 400 otherwise.
fn handle_delete(ctx: &HttpFilterContext<'_>) -> FilterAction {
    if ctx
        .request
        .headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .is_some()
    {
        FilterAction::Reject(Rejection::status(204))
    } else {
        FilterAction::Reject(Rejection::status(400))
    }
}

/// Generates a new MCP session and returns MCP capabilities.
/// Does not initialize backends, that belongs to follow-up backend session work.
fn handle_initialize(
    ctx: &mut HttpFilterContext<'_>,
    value: &serde_json::Value,
    envelope: &JsonRpcEnvelope,
    supported_versions: &[String],
    default_version: &str,
) -> Result<FilterAction, FilterError> {
    record_client_protocol_version(ctx, value);
    let response_version = negotiate_protocol_version(value, supported_versions, default_version);
    let session_id = generate_session_id()?;

    debug!(session_id_len = session_id.len(), "MCP initialize");
    ctx.set_metadata("mcp.session_id", session_id.clone());

    Ok(FilterAction::Reject(
        Rejection::status(200)
            .with_header("content-type", "application/json")
            .with_header("mcp-session-id", &session_id)
            .with_body(Bytes::from(
                initialize_response_body(envelope, response_version).to_string(),
            )),
    ))
}

/// Select the protocol version for the initialize response.
///
/// Echoes the client's requested version when the broker supports it,
/// otherwise falls back to `default_version`.
fn negotiate_protocol_version<'a>(
    value: &serde_json::Value,
    supported_versions: &'a [String],
    default_version: &'a str,
) -> &'a str {
    let requested = value
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str());

    if let Some(req) = requested
        && let Some(matched) = supported_versions.iter().find(|v| v.as_str() == req)
    {
        return matched.as_str();
    }

    default_version
}

/// Persist the client's advertised MCP protocol version for later negotiation
/// work, avoiding metadata writes for malformed control-character values.
fn record_client_protocol_version(ctx: &mut HttpFilterContext<'_>, value: &serde_json::Value) {
    if let Some(version) = value
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str())
        && !contains_control_chars(version)
    {
        ctx.set_metadata("mcp.protocol_version", version.to_owned());
    }
}

/// Build the initialize response from the configured protocol version.
fn initialize_response_body(envelope: &JsonRpcEnvelope, protocol_version: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id_value(envelope),
        "result": {
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": false,
                },
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    })
}

/// Returns the aggregated static catalog. Dynamic backend discovery
/// and per-identity filtering belong to later PRs.
fn handle_tools_list(catalog: &[CatalogTool], envelope: &JsonRpcEnvelope) -> Result<FilterAction, FilterError> {
    let tools_json = serialize_catalog(catalog)?;
    let id_json = format_id_json(envelope);
    let response_body = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"result":{{"tools":{tools_json}}}}}"#,);

    trace!(tool_count = catalog.len(), "serving aggregated tools/list");

    Ok(FilterAction::Reject(
        Rejection::status(200)
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(response_body)),
    ))
}

/// Fails at request time if serialization fails, so callers must
/// return a controlled error rather than silently degrading.
fn serialize_catalog(catalog: &[CatalogTool]) -> Result<String, FilterError> {
    let tools: Vec<serde_json::Value> = catalog.iter().map(catalog_tool_to_json).collect();
    serde_json::to_string(&tools).map_err(|e| FilterError::from(format!("mcp: failed to serialize tool catalog: {e}")))
}

/// Produces the MCP tool object shape (`name`, optional `description`
/// and `inputSchema`) expected by `tools/list` responses.
fn catalog_tool_to_json(tool: &CatalogTool) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("name".to_owned(), serde_json::Value::String(tool.exposed_name.clone()));
    if let Some(ref desc) = tool.description {
        obj.insert("description".to_owned(), serde_json::Value::String(desc.clone()));
    }
    obj.insert("inputSchema".to_owned(), tool.input_schema.clone());
    if let Some(ref annotations) = tool.annotations {
        obj.insert("annotations".to_owned(), annotations.clone());
    }
    serde_json::Value::Object(obj)
}

/// Returns `{"result":{}}` with the caller's JSON-RPC id preserved.
fn handle_ping(envelope: &JsonRpcEnvelope) -> FilterAction {
    let id_json = format_id_json(envelope);
    let response_body = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"result":{{}}}}"#);

    FilterAction::Reject(
        Rejection::status(200)
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(response_body)),
    )
}

// -----------------------------------------------------------------------------
// JSON-RPC Helpers
// -----------------------------------------------------------------------------

/// Format the JSON-RPC `id` field for response serialization.
///
/// String ids are escaped with [`serde_json::to_string`] so special
/// characters (quotes, backslashes, control chars) produce valid JSON.
fn format_id_json(envelope: &JsonRpcEnvelope) -> String {
    let id = envelope.id.as_deref().unwrap_or("null");
    match envelope.id_kind {
        JsonRpcIdKind::String => serde_json::to_string(id).unwrap_or_else(|_| "null".to_owned()),
        JsonRpcIdKind::Integer | JsonRpcIdKind::Number => id.to_owned(),
        JsonRpcIdKind::Null | JsonRpcIdKind::Missing => "null".to_owned(),
    }
}

/// Convert the parsed JSON-RPC id into a response JSON value.
fn id_value(envelope: &JsonRpcEnvelope) -> serde_json::Value {
    let Some(id) = envelope.id.as_deref() else {
        return serde_json::Value::Null;
    };
    match envelope.id_kind {
        JsonRpcIdKind::String => serde_json::Value::String(id.to_owned()),
        JsonRpcIdKind::Integer | JsonRpcIdKind::Number => serde_json::from_str(id).unwrap_or(serde_json::Value::Null),
        JsonRpcIdKind::Null | JsonRpcIdKind::Missing => serde_json::Value::Null,
    }
}

/// Build a JSON-RPC error [`FilterAction::Reject`] response.
///
/// The message is JSON-escaped so future caller-supplied values
/// (e.g. tool names from backend routing) cannot break the response envelope.
fn json_rpc_error_action(envelope: &JsonRpcEnvelope, code: i32, message: &str) -> FilterAction {
    let id_json = format_id_json(envelope);
    json_rpc_error_action_with_id(&id_json, code, message)
}

/// Some protocol errors cannot safely reuse the parsed request id.
fn json_rpc_error_action_with_id(id_json: &str, code: i32, message: &str) -> FilterAction {
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

// -----------------------------------------------------------------------------
// Path Matching
// -----------------------------------------------------------------------------

/// Returns `true` when the request URI path matches the configured MCP
/// path. Uses exact match on the path component only.
fn request_path_matches(uri: &http::Uri, public_path: &str) -> bool {
    uri.path() == public_path
}

// -----------------------------------------------------------------------------
// Session ID
// -----------------------------------------------------------------------------

/// Generate a cryptographically random MCP session ID.
fn generate_session_id() -> Result<String, FilterError> {
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut bytes)
        .map_err(|e| FilterError::from(format!("mcp: failed to generate session id: {e}")))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("mcp-{hex}"))
}

// -----------------------------------------------------------------------------
// Shared Parser Config
// -----------------------------------------------------------------------------

/// Build a [`JsonRpcConfig`] for the shared parser with MCP broker-appropriate
/// defaults.
fn build_json_rpc_config(max_body_bytes: usize) -> JsonRpcConfig {
    use crate::builtins::http::ai::agentic::json_rpc::config::{BatchPolicy, InvalidJsonRpcBehavior, JsonRpcHeaders};

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
