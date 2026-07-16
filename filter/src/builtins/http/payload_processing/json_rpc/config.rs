// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the JSON-RPC filter.

use serde::Deserialize;

use super::super::{
    OnInvalidBehavior,
    config_validation::{validate_header_name, validate_max_body_bytes},
};
use crate::FilterError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576; // 1 MiB

/// Default maximum number of items allowed in a JSON-RPC batch array.
///
/// Applies only when [`BatchPolicy::First`] is active. A single HTTP
/// request carrying a large batch can bypass per-request rate limits,
/// so this cap provides a safety net. The default (100) is
/// conservative enough for legitimate use while preventing abuse.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// BatchPolicy
// ---------------------------------------------------------------------------

/// Batch handling policy for JSON-RPC arrays.
///
/// JSON-RPC 2.0 allows clients to send an array of requests as a
/// single HTTP payload. Because the proxy applies per-request
/// processing (rate limiting, authentication, etc.) at the HTTP
/// level, a batch effectively multiplexes many logical calls inside
/// one HTTP request. This can bypass per-request rate limits and
/// amplify backend load.
///
/// The default policy ([`Reject`]) is the secure choice for most
/// deployments. Use [`First`] only when the upstream requires batch
/// support, and always pair it with [`max_batch_size`] to bound the
/// amplification factor.
///
/// [`Reject`]: BatchPolicy::Reject
/// [`First`]: BatchPolicy::First
/// [`max_batch_size`]: JsonRpcConfig::max_batch_size
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchPolicy {
    /// Reject all JSON-RPC batch arrays with HTTP 400.
    ///
    /// This is the secure default. No batch processing occurs, so
    /// every JSON-RPC call maps 1:1 to an HTTP request and is subject
    /// to normal rate limiting, authentication, and logging.
    #[default]
    Reject,

    /// Use the first valid request or notification in the batch for
    /// routing and metadata promotion.
    ///
    /// # Security
    ///
    /// Enabling this policy allows clients to embed many JSON-RPC
    /// calls in a single HTTP request, which can bypass per-request
    /// rate limits. Always set [`max_batch_size`] to cap the
    /// amplification factor. The batch length is recorded in the
    /// `json_rpc.batch_len` filter result for downstream conditions.
    ///
    /// [`max_batch_size`]: JsonRpcConfig::max_batch_size
    First,
}

// ---------------------------------------------------------------------------
// JsonRpcHeaders
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// JsonRpcConfig
// ---------------------------------------------------------------------------

/// YAML configuration for [`JsonRpcFilter`].
///
/// [`JsonRpcFilter`]: super::JsonRpcFilter
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcConfig {
    /// Batch handling policy (default: [`reject`]).
    ///
    /// Controls whether JSON-RPC batch arrays are allowed. See
    /// [`BatchPolicy`] for security implications.
    ///
    /// [`reject`]: BatchPolicy::Reject
    #[serde(default)]
    pub batch_policy: BatchPolicy,

    /// Header names for metadata promotion.
    #[serde(default)]
    pub headers: JsonRpcHeaders,

    /// Maximum number of items allowed in a JSON-RPC batch array.
    ///
    /// Only enforced when [`batch_policy`] is [`First`]. Requests
    /// exceeding this limit are rejected with HTTP 400. This prevents
    /// a single HTTP request from multiplexing an excessive number of
    /// JSON-RPC calls, which could bypass per-request rate limits.
    ///
    /// Default: [`DEFAULT_MAX_BATCH_SIZE`] (100).
    ///
    /// [`batch_policy`]: JsonRpcConfig::batch_policy
    /// [`First`]: BatchPolicy::First
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,

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

/// Default max batch size.
fn default_max_batch_size() -> usize {
    DEFAULT_MAX_BATCH_SIZE
}

// ---------------------------------------------------------------------------
// Config Validation
// ---------------------------------------------------------------------------

/// Validate and build the final configuration.
///
/// # Errors
///
/// Returns [`FilterError`] if header names, body size, or batch size
/// are invalid.
pub fn build_config(cfg: JsonRpcConfig) -> Result<(usize, JsonRpcConfig), FilterError> {
    validate_max_body_bytes("json_rpc", cfg.max_body_bytes)?;
    validate_header_name("json_rpc", "method", cfg.headers.method.as_deref())?;
    validate_header_name("json_rpc", "id", cfg.headers.id.as_deref())?;
    validate_header_name("json_rpc", "kind", cfg.headers.kind.as_deref())?;
    validate_max_batch_size(&cfg)?;

    Ok((cfg.max_body_bytes, cfg))
}

/// Validate that `max_batch_size` is at least 1.
fn validate_max_batch_size(cfg: &JsonRpcConfig) -> Result<(), FilterError> {
    if cfg.max_batch_size == 0 {
        return Err("json_rpc: max_batch_size must be greater than 0".into());
    }
    Ok(())
}
