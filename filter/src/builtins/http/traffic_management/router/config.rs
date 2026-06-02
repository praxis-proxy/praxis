// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the router filter.

use praxis_core::config::Route;
use serde::Deserialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default header name for the resolved JSON alias value.
pub(super) const DEFAULT_JSON_ALIAS_HEADER: &str = "X-Json-Alias";

/// Default maximum body bytes to buffer for JSON alias resolution.
pub(super) const DEFAULT_JSON_ALIAS_MAX_BODY_BYTES: usize = 10_485_760; // 10 MiB

/// Hard upper bound for `json_alias_max_body_bytes`.
pub(super) const MAX_JSON_ALIAS_BODY_BYTES: usize = 67_108_864; // 64 MiB

// -----------------------------------------------------------------------------
// RouterConfig
// -----------------------------------------------------------------------------

/// Deserialization wrapper for the router's YAML config.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouterConfig {
    /// Header name for the promoted JSON field value during alias
    /// resolution.
    #[serde(default = "default_json_alias_header")]
    pub json_alias_header: String,

    /// Maximum body bytes to buffer when resolving JSON aliases.
    #[serde(default = "default_json_alias_max_body_bytes")]
    pub json_alias_max_body_bytes: usize,

    /// Route table entries.
    #[serde(default)]
    pub routes: Vec<RouterRouteConfig>,

    /// Enable multi-level subdomain matching for wildcard hosts.
    ///
    /// When `false` (default), `*.example.com` matches only single-level
    /// subdomains like `foo.example.com`. When `true`, it also matches
    /// multi-level subdomains like `foo.bar.example.com` (suffix match).
    ///
    /// Some control planes (e.g. Kubernetes Gateway API) require this.
    #[serde(default)]
    pub multi_level_subdomain_matching: bool,
}

/// Router-owned route config so JSON body aliasing stays out of
/// [`praxis_core::config::Route`].
///
/// `deny_unknown_fields` is intentionally omitted because
/// `#[serde(flatten)]` on `route` is incompatible with it.
/// Unknown fields within the `Route` portion are validated by
/// `Route`'s own `deny_unknown_fields`.
///
/// [`praxis_core::config::Route`]: praxis_core::config::Route
#[derive(Debug, Clone, Deserialize)]
pub(super) struct RouterRouteConfig {
    /// Generic path, host, header, and cluster routing fields.
    #[serde(flatten)]
    pub route: Route,

    /// Optional JSON field aliases evaluated for this route.
    #[serde(default)]
    pub json_aliases: Option<Vec<JsonAlias>>,
}

impl From<Route> for RouterRouteConfig {
    fn from(route: Route) -> Self {
        Self {
            route,
            json_aliases: None,
        }
    }
}

/// JSON field alias rule scoped to a router route.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JsonAlias {
    /// Request JSON field whose string value is compared with `pattern`.
    pub field: String,

    /// Exact or single-wildcard pattern for the configured field value.
    #[serde(rename = "match")]
    pub pattern: String,

    /// Replacement value; omitted aliases preserve the original value.
    #[serde(default)]
    pub target: Option<String>,
}

/// Serde default for [`RouterConfig::json_alias_header`].
fn default_json_alias_header() -> String {
    DEFAULT_JSON_ALIAS_HEADER.to_owned()
}

/// Serde default for [`RouterConfig::json_alias_max_body_bytes`].
fn default_json_alias_max_body_bytes() -> usize {
    DEFAULT_JSON_ALIAS_MAX_BODY_BYTES
}
