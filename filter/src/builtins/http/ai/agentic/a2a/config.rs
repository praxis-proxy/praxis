// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the A2A filter.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::FilterError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (64 `KiB`).
pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

// -----------------------------------------------------------------------------
// Behavior Enums
// -----------------------------------------------------------------------------

/// Invalid A2A message handling.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InvalidA2aBehavior {
    /// Reject non-A2A input with HTTP 400.
    #[default]
    Reject,
    /// Continue processing without A2A metadata.
    Continue,
}

// -----------------------------------------------------------------------------
// A2aHeaders
// -----------------------------------------------------------------------------

/// Promoted header names for A2A metadata.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct A2aHeaders {
    /// Header name for the canonical A2A method (e.g. `x-praxis-a2a-method`).
    #[serde(default = "default_method_header")]
    pub method: Option<String>,

    /// Header name for the A2A family (e.g. `x-praxis-a2a-family`).
    #[serde(default = "default_family_header")]
    pub family: Option<String>,

    /// Header name for the extracted task ID (e.g. `x-praxis-a2a-task-id`).
    #[serde(default = "default_task_id_header")]
    pub task_id: Option<String>,

    /// Header name for the JSON-RPC kind (e.g. `x-praxis-a2a-kind`).
    #[serde(default = "default_kind_header")]
    pub kind: Option<String>,

    /// Header name for streaming detection (e.g. `x-praxis-a2a-streaming`).
    #[serde(default = "default_streaming_header")]
    pub streaming: Option<String>,

    /// Header name for A2A version (e.g. `x-praxis-a2a-version`).
    #[serde(default = "default_version_header")]
    pub version: Option<String>,
}

impl Default for A2aHeaders {
    fn default() -> Self {
        Self {
            method: default_method_header(),
            family: default_family_header(),
            task_id: default_task_id_header(),
            kind: default_kind_header(),
            streaming: default_streaming_header(),
            version: default_version_header(),
        }
    }
}

/// Default method header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_method_header() -> Option<String> {
    Some("x-praxis-a2a-method".to_owned())
}

/// Default family header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_family_header() -> Option<String> {
    Some("x-praxis-a2a-family".to_owned())
}

/// Default task ID header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_task_id_header() -> Option<String> {
    Some("x-praxis-a2a-task-id".to_owned())
}

/// Default kind header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_kind_header() -> Option<String> {
    Some("x-praxis-a2a-kind".to_owned())
}

/// Default streaming header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_streaming_header() -> Option<String> {
    Some("x-praxis-a2a-streaming".to_owned())
}

/// Default version header name.
#[allow(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_version_header() -> Option<String> {
    Some("x-praxis-a2a-version".to_owned())
}

// -----------------------------------------------------------------------------
// A2aConfig
// -----------------------------------------------------------------------------

/// YAML configuration for the A2A filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct A2aConfig {
    /// Maximum body size in bytes for `StreamBuffer`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Invalid input handling behavior.
    #[serde(default)]
    pub on_invalid: InvalidA2aBehavior,

    /// Method aliases for compatibility (slash-delimited → `PascalCase`).
    #[serde(default)]
    pub method_aliases: BTreeMap<String, String>,

    /// Header names for A2A metadata promotion.
    #[serde(default)]
    pub headers: A2aHeaders,
}

/// Default max body bytes.
fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate and build the final configuration.
pub(crate) fn build_config(cfg: A2aConfig) -> Result<A2aConfig, FilterError> {
    if cfg.max_body_bytes == 0 {
        return Err("a2a: 'max_body_bytes' must be greater than 0".into());
    }

    // Validate header names
    validate_header_name("method", cfg.headers.method.as_deref())?;
    validate_header_name("family", cfg.headers.family.as_deref())?;
    validate_header_name("task_id", cfg.headers.task_id.as_deref())?;
    validate_header_name("kind", cfg.headers.kind.as_deref())?;
    validate_header_name("streaming", cfg.headers.streaming.as_deref())?;
    validate_header_name("version", cfg.headers.version.as_deref())?;

    // Validate method aliases
    for (alias, canonical) in &cfg.method_aliases {
        if alias.is_empty() {
            return Err("a2a: alias key must be non-empty".into());
        }
        if canonical.is_empty() {
            return Err("a2a: alias value must be non-empty".into());
        }
        // Validate that canonical method maps to a known A2A method
        if !is_known_a2a_method(canonical) {
            return Err(format!("a2a: alias target '{canonical}' is not a known A2A method").into());
        }
    }

    Ok(cfg)
}

/// Validate configured header names using the HTTP header-name parser.
fn validate_header_name(field: &str, header_name: Option<&str>) -> Result<(), FilterError> {
    let Some(header_name) = header_name else {
        return Ok(());
    };
    if header_name.is_empty() {
        return Err(format!("a2a: {field} header name must not be empty").into());
    }
    if http::HeaderName::from_bytes(header_name.as_bytes()).is_err() {
        return Err(format!("a2a: {field} header name is not a valid HTTP header name").into());
    }
    Ok(())
}

/// Check if a method is a known canonical A2A method.
fn is_known_a2a_method(method: &str) -> bool {
    matches!(
        method,
        "SendMessage"
            | "SendStreamingMessage"
            | "GetTask"
            | "ListTasks"
            | "CancelTask"
            | "SubscribeToTask"
            | "CreateTaskPushNotificationConfig"
            | "GetTaskPushNotificationConfig"
            | "ListTaskPushNotificationConfigs"
            | "DeleteTaskPushNotificationConfig"
            | "GetExtendedAgentCard"
    )
}
