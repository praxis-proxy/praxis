// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the MCP filter.

use serde::Deserialize;

use crate::{FilterError, body::MAX_JSON_BODY_BYTES};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (64 `KiB`).
pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

// -----------------------------------------------------------------------------
// Behavior Enums
// -----------------------------------------------------------------------------

/// Header validation mismatch behavior.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MismatchBehavior {
    /// Reject the request with a JSON-RPC error response.
    #[default]
    Reject,
    /// Ignore the mismatch and continue processing.
    Ignore,
}

/// Header validation missing behavior.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MissingHeaderBehavior {
    /// Ignore the missing headers and continue processing.
    #[default]
    Ignore,
    /// Synthesize the missing headers from body-derived values.
    Synthesize,
    /// Reject the request when expected MCP headers are absent.
    Reject,
}

/// Invalid MCP message handling.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InvalidMcpBehavior {
    /// Reject non-MCP input with HTTP 400.
    #[default]
    Reject,
    /// Continue processing without MCP metadata.
    Continue,
}

// -----------------------------------------------------------------------------
// HeaderValidation
// -----------------------------------------------------------------------------

/// Header validation config controlling how header/body mismatches are handled.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderValidation {
    /// Behavior when header value conflicts with body-derived value.
    #[serde(default)]
    pub mismatch: MismatchBehavior,
    /// Behavior when expected MCP headers are absent.
    #[serde(default)]
    pub missing: MissingHeaderBehavior,
}

// -----------------------------------------------------------------------------
// McpHeaders
// -----------------------------------------------------------------------------

/// Promoted header names for MCP metadata.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpHeaders {
    /// Header name for the JSON-RPC kind (e.g. `x-praxis-mcp-kind`).
    #[serde(default = "default_kind_header")]
    pub kind: Option<String>,
    /// Header name for the MCP method (e.g. `x-praxis-mcp-method`).
    #[serde(default = "default_method_header")]
    pub method: Option<String>,
    /// Header name for the tool/resource/prompt name (e.g. `x-praxis-mcp-name`).
    #[serde(default = "default_name_header")]
    pub name: Option<String>,
    /// Header name for the MCP protocol version (e.g. `x-praxis-mcp-protocol-version`).
    #[serde(default = "default_protocol_version_header")]
    pub protocol_version: Option<String>,
    /// Header name for MCP session presence (e.g. `x-praxis-mcp-session-present`).
    #[serde(default = "default_session_present_header")]
    pub session_present: Option<String>,
}

impl Default for McpHeaders {
    fn default() -> Self {
        Self {
            kind: default_kind_header(),
            method: default_method_header(),
            name: default_name_header(),
            protocol_version: default_protocol_version_header(),
            session_present: default_session_present_header(),
        }
    }
}

/// Default method header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_method_header() -> Option<String> {
    Some("x-praxis-mcp-method".to_owned())
}

/// Default name header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_name_header() -> Option<String> {
    Some("x-praxis-mcp-name".to_owned())
}

/// Default kind header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_kind_header() -> Option<String> {
    Some("x-praxis-mcp-kind".to_owned())
}

/// Default protocol-version header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_protocol_version_header() -> Option<String> {
    Some("x-praxis-mcp-protocol-version".to_owned())
}

/// Default session-present header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_session_present_header() -> Option<String> {
    Some("x-praxis-mcp-session-present".to_owned())
}

// -----------------------------------------------------------------------------
// McpConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the MCP filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpConfig {
    /// Header validation settings.
    #[serde(default)]
    pub header_validation: HeaderValidation,

    /// Header names for MCP metadata promotion.
    #[serde(default)]
    pub headers: McpHeaders,

    /// Maximum body size in bytes for `StreamBuffer`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Invalid input handling behavior.
    #[serde(default)]
    pub on_invalid: InvalidMcpBehavior,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate and build the final configuration.
pub(crate) fn build_config(cfg: McpConfig) -> Result<McpConfig, FilterError> {
    if cfg.max_body_bytes == 0 {
        return Err("mcp: 'max_body_bytes' must be greater than 0".into());
    }
    if cfg.max_body_bytes > MAX_JSON_BODY_BYTES {
        return Err(format!(
            "mcp: max_body_bytes ({}) exceeds maximum ({MAX_JSON_BODY_BYTES})",
            cfg.max_body_bytes
        )
        .into());
    }
    validate_header_name("method", cfg.headers.method.as_deref())?;
    validate_header_name("name", cfg.headers.name.as_deref())?;
    validate_header_name("kind", cfg.headers.kind.as_deref())?;
    validate_header_name("protocol_version", cfg.headers.protocol_version.as_deref())?;
    validate_header_name("session_present", cfg.headers.session_present.as_deref())?;
    Ok(cfg)
}

/// Validate configured header names using the HTTP header-name parser.
fn validate_header_name(field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
    let Some(header_name) = header_name else {
        return Ok(());
    };
    if header_name.is_empty() {
        return Err(format!("mcp: {field} header name must not be empty").into());
    }
    if http::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
        return Err(format!("mcp: {field} header name is not a valid HTTP header name").into());
    }
    Ok(())
}
