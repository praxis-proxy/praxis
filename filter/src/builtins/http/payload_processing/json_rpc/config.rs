// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the JSON-RPC filter.

use serde::Deserialize;

use super::super::{
    OnInvalidBehavior,
    config_validation::{validate_header_name, validate_max_body_bytes},
};
use crate::FilterError;

// -----------------------------------------------------------------------------
// Body Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

// -----------------------------------------------------------------------------
// BatchPolicy
// -----------------------------------------------------------------------------

/// Batch handling policy for JSON-RPC arrays.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchPolicy {
    /// Reject JSON-RPC batch arrays with HTTP 400.
    #[default]
    Reject,
    /// Use the first valid request/notification in the batch for routing.
    First,
}

// -----------------------------------------------------------------------------
// JsonRpcHeaders
// -----------------------------------------------------------------------------

/// Header configuration for JSON-RPC metadata promotion.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcHeaders {
    /// Header name for JSON-RPC id (e.g., `X-Json-Rpc-Id`).
    pub id: Option<String>,
    /// Header name for JSON-RPC kind (e.g., `X-Json-Rpc-Kind`).
    pub kind: Option<String>,
    /// Header name for JSON-RPC method (e.g., `X-Json-Rpc-Method`).
    pub method: Option<String>,
}

impl Default for JsonRpcHeaders {
    fn default() -> Self {
        Self {
            id: Some("X-Json-Rpc-Id".to_owned()),
            kind: Some("X-Json-Rpc-Kind".to_owned()),
            method: Some("X-Json-Rpc-Method".to_owned()),
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
pub struct JsonRpcConfig {
    /// Batch handling policy.
    #[serde(default)]
    pub batch_policy: BatchPolicy,

    /// Header names for metadata promotion.
    #[serde(default)]
    pub headers: JsonRpcHeaders,

    /// Maximum body size in bytes for `StreamBuffer`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Invalid input handling behavior.
    #[serde(default = "OnInvalidBehavior::default_continue")]
    pub on_invalid: OnInvalidBehavior,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate and build the final configuration.
///
/// # Errors
///
/// Returns [`FilterError`] if header names or body size are invalid.
pub fn build_config(cfg: JsonRpcConfig) -> Result<(usize, JsonRpcConfig), FilterError> {
    validate_max_body_bytes("json_rpc", cfg.max_body_bytes)?;
    validate_header_name("json_rpc", "method", cfg.headers.method.as_deref())?;
    validate_header_name("json_rpc", "id", cfg.headers.id.as_deref())?;
    validate_header_name("json_rpc", "kind", cfg.headers.kind.as_deref())?;

    Ok((cfg.max_body_bytes, cfg))
}
