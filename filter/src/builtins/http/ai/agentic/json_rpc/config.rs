// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the JSON-RPC filter.

use serde::Deserialize;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Body Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (1 MiB).
pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

// -----------------------------------------------------------------------------
// BatchPolicy
// -----------------------------------------------------------------------------

/// Batch handling policy for JSON-RPC arrays.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BatchPolicy {
    /// Reject JSON-RPC batch arrays with HTTP 400.
    #[default]
    Reject,
    /// Use the first valid request/notification in the batch for routing.
    First,
}

// -----------------------------------------------------------------------------
// InvalidJsonRpcBehavior
// -----------------------------------------------------------------------------

/// Invalid JSON or non-JSON-RPC input handling.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InvalidJsonRpcBehavior {
    /// Continue processing (default proxy behavior).
    #[default]
    Continue,
    /// Reject with HTTP 400.
    Reject,
    /// Return filter error (pipeline failure).
    Error,
}

// -----------------------------------------------------------------------------
// JsonRpcHeaders
// -----------------------------------------------------------------------------

/// Header configuration for JSON-RPC metadata promotion.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonRpcHeaders {
    /// Header name for JSON-RPC method (e.g., `X-Json-Rpc-Method`).
    pub method: Option<String>,
    /// Header name for JSON-RPC id (e.g., `X-Json-Rpc-Id`).
    pub id: Option<String>,
    /// Header name for JSON-RPC kind (e.g., `X-Json-Rpc-Kind`).
    pub kind: Option<String>,
}

impl Default for JsonRpcHeaders {
    fn default() -> Self {
        Self {
            method: Some("X-Json-Rpc-Method".to_owned()),
            id: Some("X-Json-Rpc-Id".to_owned()),
            kind: Some("X-Json-Rpc-Kind".to_owned()),
        }
    }
}

// -----------------------------------------------------------------------------
// JsonRpcConfig
// -----------------------------------------------------------------------------

/// YAML configuration for [`JsonRpcFilter`].
///
/// [`JsonRpcFilter`]: super::JsonRpcFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonRpcConfig {
    /// Maximum body size in bytes for `StreamBuffer`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Batch handling policy.
    #[serde(default)]
    pub batch_policy: BatchPolicy,

    /// Invalid input handling behavior.
    #[serde(default)]
    pub on_invalid: InvalidJsonRpcBehavior,

    /// Header names for metadata promotion.
    #[serde(default)]
    pub headers: JsonRpcHeaders,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate and build the final configuration.
pub(crate) fn build_config(cfg: JsonRpcConfig) -> Result<(usize, JsonRpcConfig), FilterError> {
    if cfg.max_body_bytes == 0 {
        return Err("json_rpc: 'max_body_bytes' must be greater than 0".into());
    }

    validate_header_name("method", cfg.headers.method.as_deref())?;
    validate_header_name("id", cfg.headers.id.as_deref())?;
    validate_header_name("kind", cfg.headers.kind.as_deref())?;

    Ok((cfg.max_body_bytes, cfg))
}

/// Validate configured header names using the HTTP header-name parser.
fn validate_header_name(field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
    let Some(header_name) = header_name else {
        return Ok(());
    };

    if header_name.is_empty() {
        return Err(format!("json_rpc: {field} header name must not be empty").into());
    }

    if http::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
        return Err(format!("json_rpc: {field} header name is not a valid HTTP header name").into());
    }

    Ok(())
}
