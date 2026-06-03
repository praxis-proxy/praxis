// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! MCP-specific extraction from parsed JSON-RPC values and MCP request headers.

use serde_json::Value;

// -----------------------------------------------------------------------------
// McpMethod
// -----------------------------------------------------------------------------

/// MCP method classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum McpMethod {
    /// `initialize` handshake request.
    Initialize,
    /// `notifications/initialized` post-handshake notification.
    NotificationsInitialized,
    /// `tools/list` discovery request.
    ToolsList,
    /// `tools/call` invocation request.
    ToolsCall,
    /// `resources/read` resource access request.
    ResourcesRead,
    /// `resources/list` resource discovery request.
    ResourcesList,
    /// `prompts/get` prompt retrieval request.
    PromptsGet,
    /// `prompts/list` prompt discovery request.
    PromptsList,
    /// `ping` keep-alive request.
    Ping,
    /// `logging/setLevel` log configuration request.
    LoggingSetLevel,
    /// `completion/complete` completion request.
    CompletionComplete,
    /// `notifications/tools/list_changed` tool change notification.
    NotificationsToolsListChanged,
    /// `notifications/resources/list_changed` resource change notification.
    NotificationsResourcesListChanged,
    /// `notifications/prompts/list_changed` prompt change notification.
    NotificationsPromptsListChanged,
    /// Any other method string not in the known set.
    Other(String),
}

impl McpMethod {
    /// Parse an MCP method from the JSON-RPC method string.
    pub(crate) fn from_method_str(s: &str) -> Self {
        match s {
            "initialize" => Self::Initialize,
            "notifications/initialized" => Self::NotificationsInitialized,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "resources/read" => Self::ResourcesRead,
            "resources/list" => Self::ResourcesList,
            "prompts/get" => Self::PromptsGet,
            "prompts/list" => Self::PromptsList,
            "ping" => Self::Ping,
            "logging/setLevel" => Self::LoggingSetLevel,
            "completion/complete" => Self::CompletionComplete,
            "notifications/tools/list_changed" => Self::NotificationsToolsListChanged,
            "notifications/resources/list_changed" => Self::NotificationsResourcesListChanged,
            "notifications/prompts/list_changed" => Self::NotificationsPromptsListChanged,
            other => Self::Other(other.to_owned()),
        }
    }

    /// String representation for headers and metadata.
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Initialize => "initialize",
            Self::NotificationsInitialized => "notifications/initialized",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::ResourcesRead => "resources/read",
            Self::ResourcesList => "resources/list",
            Self::PromptsGet => "prompts/get",
            Self::PromptsList => "prompts/list",
            Self::Ping => "ping",
            Self::LoggingSetLevel => "logging/setLevel",
            Self::CompletionComplete => "completion/complete",
            Self::NotificationsToolsListChanged => "notifications/tools/list_changed",
            Self::NotificationsResourcesListChanged => "notifications/resources/list_changed",
            Self::NotificationsPromptsListChanged => "notifications/prompts/list_changed",
            Self::Other(s) => s,
        }
    }

    /// Whether extraction of `params.name` is attempted for this method.
    pub(crate) fn requires_name(&self) -> bool {
        matches!(self, Self::ToolsCall | Self::PromptsGet)
    }

    /// Whether extraction of `params.uri` is attempted for this method.
    pub(crate) fn requires_uri(&self) -> bool {
        matches!(self, Self::ResourcesRead)
    }
}

// -----------------------------------------------------------------------------
// McpEnvelope
// -----------------------------------------------------------------------------

/// Extracted MCP envelope metadata.
#[derive(Debug, Clone)]
pub(crate) struct McpEnvelope {
    /// Classified MCP method.
    pub method: McpMethod,
    /// Tool/resource/prompt name extracted from params.
    pub name: Option<String>,
    /// Protocol version from initialize params or `Mcp-Protocol-Version` header.
    pub protocol_version: Option<String>,
    /// `Mcp-Session-Id` value from the request header.
    pub session_id: Option<String>,
}

// -----------------------------------------------------------------------------
// Extraction
// -----------------------------------------------------------------------------

/// Extract MCP-specific metadata from a pre-parsed JSON value and request headers.
pub(crate) fn extract_mcp_envelope(value: &Value, method_str: &str, request_headers: &http::HeaderMap) -> McpEnvelope {
    let method = McpMethod::from_method_str(method_str);
    let name = extract_name(value, &method);
    let session_id = request_headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let protocol_version = extract_protocol_version(value, &method, request_headers);

    McpEnvelope {
        method,
        name,
        protocol_version,
        session_id,
    }
}

/// Extract the name (tool name, resource URI, or prompt name) from params.
fn extract_name(value: &Value, method: &McpMethod) -> Option<String> {
    if !method.requires_name() && !method.requires_uri() {
        return None;
    }

    let params = value.get("params")?;

    if method.requires_uri() {
        params.get("uri").and_then(|v| v.as_str()).map(str::to_owned)
    } else {
        params.get("name").and_then(|v| v.as_str()).map(str::to_owned)
    }
}

/// Extract protocol version from initialize body params or `Mcp-Protocol-Version` header.
///
/// For `initialize`, `params.protocolVersion` from the handshake body takes
/// precedence. For all other methods, the `Mcp-Protocol-Version` request
/// header is used if present.
fn extract_protocol_version(value: &Value, method: &McpMethod, headers: &http::HeaderMap) -> Option<String> {
    if let McpMethod::Initialize = method
        && let Some(version) = value
            .get("params")
            .and_then(|p| p.get("protocolVersion"))
            .and_then(|v| v.as_str())
    {
        return Some(version.to_owned());
    }

    headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
