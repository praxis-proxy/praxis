// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the A2A filter.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{
    FilterError,
    builtins::http::ai::{
        OnInvalidBehavior,
        config_validation::{validate_header_name, validate_max_body_bytes},
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum request body size for `StreamBuffer` mode (64 `KiB`).
pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

/// Default route cluster header name for task routing.
const DEFAULT_ROUTE_CLUSTER_HEADER: &str = "x-praxis-a2a-route-cluster";

/// Default TTL for non-terminal task routes (1 hour).
const DEFAULT_TTL_SECONDS: u64 = 3_600; // 1 hour

/// Default TTL for terminal task routes (5 minutes).
const DEFAULT_TERMINAL_TTL_SECONDS: u64 = 300; // 5 minutes

/// Default maximum response body bytes for task route capture (64 `KiB`).
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 65_536;

// -----------------------------------------------------------------------------
// Behavior Enums
// -----------------------------------------------------------------------------

/// Task route lookup miss behavior.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OnLookupMiss {
    /// Continue without a route header; let the router fallback decide.
    #[default]
    Continue,
}

/// Task route store backend.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaskRouteStore {
    /// In-process local store.
    #[default]
    Local,
}

// -----------------------------------------------------------------------------
// TaskRoutingConfig
// -----------------------------------------------------------------------------

/// Configuration for A2A task-ownership routing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskRoutingConfig {
    /// Whether task routing is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum response body bytes to buffer for task route capture.
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,

    /// Behavior when a task route lookup misses.
    #[serde(default)]
    #[expect(dead_code, reason = "validated at parse time, used in follow-up PRs")]
    pub on_lookup_miss: OnLookupMiss,

    /// Internal header name injected on task route hit.
    #[serde(default = "default_route_cluster_header")]
    pub route_cluster_header: String,

    /// Storage backend for task routes.
    #[serde(default)]
    #[expect(dead_code, reason = "validated at parse time, only local supported in this PR")]
    pub store: TaskRouteStore,

    /// TTL in seconds for terminal task routes (0 = remove immediately).
    #[serde(default = "default_terminal_ttl_seconds")]
    pub terminal_ttl_seconds: u64,

    /// TTL in seconds for non-terminal task routes.
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for TaskRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            on_lookup_miss: OnLookupMiss::default(),
            route_cluster_header: DEFAULT_ROUTE_CLUSTER_HEADER.to_owned(),
            store: TaskRouteStore::default(),
            terminal_ttl_seconds: DEFAULT_TERMINAL_TTL_SECONDS,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

/// Default route cluster header.
fn default_route_cluster_header() -> String {
    DEFAULT_ROUTE_CLUSTER_HEADER.to_owned()
}

/// Default TTL seconds.
fn default_ttl_seconds() -> u64 {
    DEFAULT_TTL_SECONDS
}

/// Default terminal TTL seconds.
fn default_terminal_ttl_seconds() -> u64 {
    DEFAULT_TERMINAL_TTL_SECONDS
}

/// Default max response body bytes.
fn default_max_response_body_bytes() -> usize {
    DEFAULT_MAX_RESPONSE_BODY_BYTES
}

// -----------------------------------------------------------------------------
// A2aHeaders
// -----------------------------------------------------------------------------

/// Promoted header names for A2A metadata.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct A2aHeaders {
    /// Header name for the A2A family (e.g. `x-praxis-a2a-family`).
    #[serde(default = "default_family_header")]
    pub family: Option<String>,

    /// Header name for the JSON-RPC kind (e.g. `x-praxis-a2a-kind`).
    #[serde(default = "default_kind_header")]
    pub kind: Option<String>,

    /// Header name for the canonical A2A method (e.g. `x-praxis-a2a-method`).
    #[serde(default = "default_method_header")]
    pub method: Option<String>,

    /// Header name for streaming detection (e.g. `x-praxis-a2a-streaming`).
    #[serde(default = "default_streaming_header")]
    pub streaming: Option<String>,

    /// Header name for the extracted task ID (e.g. `x-praxis-a2a-task-id`).
    #[serde(default = "default_task_id_header")]
    pub task_id: Option<String>,

    /// Header name for A2A version (e.g. `x-praxis-a2a-version`).
    #[serde(default = "default_version_header")]
    pub version: Option<String>,
}

impl Default for A2aHeaders {
    fn default() -> Self {
        Self {
            family: default_family_header(),
            kind: default_kind_header(),
            method: default_method_header(),
            streaming: default_streaming_header(),
            task_id: default_task_id_header(),
            version: default_version_header(),
        }
    }
}

/// Default method header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_method_header() -> Option<String> {
    Some("x-praxis-a2a-method".to_owned())
}

/// Default family header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_family_header() -> Option<String> {
    Some("x-praxis-a2a-family".to_owned())
}

/// Default task ID header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_task_id_header() -> Option<String> {
    Some("x-praxis-a2a-task-id".to_owned())
}

/// Default kind header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_kind_header() -> Option<String> {
    Some("x-praxis-a2a-kind".to_owned())
}

/// Default streaming header name.
#[expect(
    clippy::unnecessary_wraps,
    reason = "serde default functions require Option return type"
)]
fn default_streaming_header() -> Option<String> {
    Some("x-praxis-a2a-streaming".to_owned())
}

/// Default version header name.
#[expect(
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
    /// Header names for A2A metadata promotion.
    #[serde(default)]
    pub headers: A2aHeaders,

    /// Maximum body size in bytes for `StreamBuffer`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Method aliases for compatibility (slash-delimited → `PascalCase`).
    #[serde(default)]
    pub method_aliases: BTreeMap<String, String>,

    /// Invalid input handling behavior.
    #[serde(default = "OnInvalidBehavior::default_reject")]
    pub on_invalid: OnInvalidBehavior,

    /// Task-ownership routing configuration.
    #[serde(default)]
    pub task_routing: TaskRoutingConfig,
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
    validate_max_body_bytes("a2a", cfg.max_body_bytes)?;

    validate_header_name("a2a", "method", cfg.headers.method.as_deref())?;
    validate_header_name("a2a", "family", cfg.headers.family.as_deref())?;
    validate_header_name("a2a", "task_id", cfg.headers.task_id.as_deref())?;
    validate_header_name("a2a", "kind", cfg.headers.kind.as_deref())?;
    validate_header_name("a2a", "streaming", cfg.headers.streaming.as_deref())?;
    validate_header_name("a2a", "version", cfg.headers.version.as_deref())?;

    if cfg.task_routing.enabled {
        validate_task_routing(&cfg.task_routing)?;
    }

    for (alias, canonical) in &cfg.method_aliases {
        if alias.is_empty() {
            return Err("a2a: alias key must be non-empty".into());
        }
        if canonical.is_empty() {
            return Err("a2a: alias value must be non-empty".into());
        }
        if !is_known_a2a_method(canonical) {
            return Err(format!("a2a: alias target '{canonical}' is not a known A2A method").into());
        }
    }

    Ok(cfg)
}

/// Validate task routing configuration.
fn validate_task_routing(tr: &TaskRoutingConfig) -> Result<(), FilterError> {
    if tr.ttl_seconds == 0 {
        return Err("a2a: task_routing.ttl_seconds must be greater than 0".into());
    }

    validate_max_body_bytes("a2a: task_routing", tr.max_response_body_bytes)?;

    validate_header_name(
        "a2a",
        "task_routing.route_cluster_header",
        Some(&tr.route_cluster_header),
    )?;

    // The route header must use the reserved x-praxis-a2a- prefix so that
    // the protocol layer's reserved-header rejection guard prevents clients
    // from injecting it directly.
    if !tr.route_cluster_header.starts_with("x-praxis-a2a-") {
        return Err(format!(
            "a2a: task_routing.route_cluster_header '{}' must start with 'x-praxis-a2a-'",
            tr.route_cluster_header
        )
        .into());
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
