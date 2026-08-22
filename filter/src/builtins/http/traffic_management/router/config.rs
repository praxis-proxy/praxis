// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the router filter.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::{PathMatch, Route};
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
    /// Reserved for the unimplemented JSON alias feature; has no effect.
    ///
    /// Kept so existing configs continue to parse. Any route that
    /// actually sets `json_aliases` is rejected at startup.
    #[serde(default = "default_json_alias_header")]
    pub json_alias_header: String,

    /// Reserved for the unimplemented JSON alias feature; has no effect.
    ///
    /// Kept so existing configs continue to parse. Any route that
    /// actually sets `json_aliases` is rejected at startup.
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
/// Deserializes via [`RouterRouteConfigRaw`], which spells out the
/// route fields instead of flattening [`Route`]: `#[serde(flatten)]`
/// is incompatible with `deny_unknown_fields`, and would silently
/// absorb typoed route keys.
///
/// [`praxis_core::config::Route`]: praxis_core::config::Route
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RouterRouteConfigRaw")]
pub(super) struct RouterRouteConfig {
    /// Generic path, host, header, and cluster routing fields.
    pub route: Route,

    /// Not implemented. Setting this is rejected at startup.
    ///
    /// Body-field routing is not wired into the request path. Promote
    /// the value to a header with a classifier filter and match it via
    /// the route's `headers` field instead.
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

/// Raw deserialization target for [`RouterRouteConfig`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouterRouteConfigRaw {
    /// Exact path to match. Exactly one of `path` or `path_prefix`
    /// must be set.
    #[serde(default)]
    path: Option<String>,

    /// Path prefix to match; the longest matching prefix wins. Exactly
    /// one of `path` or `path_prefix` must be set.
    #[serde(default)]
    path_prefix: Option<String>,

    /// Name of the cluster to route matched requests to.
    cluster: Arc<str>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    headers: Option<HashMap<String, String>>,

    /// Host to match. If set, the route only applies to this host.
    #[serde(default)]
    host: Option<String>,

    /// Not implemented. Setting this is rejected at startup.
    #[serde(default)]
    json_aliases: Option<Vec<JsonAlias>>,

    /// Optional per-route retry policy override.
    #[serde(default)]
    retry_policy: Option<praxis_core::config::RetryPolicy>,
}

impl TryFrom<RouterRouteConfigRaw> for RouterRouteConfig {
    type Error = String;

    fn try_from(raw: RouterRouteConfigRaw) -> Result<Self, Self::Error> {
        Ok(Self {
            route: Route {
                path_match: PathMatch::from_parts(raw.path, raw.path_prefix)?,
                cluster: raw.cluster,
                headers: raw.headers,
                host: raw.host,
                retry_policy: raw.retry_policy,
            },
            json_aliases: raw.json_aliases,
        })
    }
}

/// JSON field alias rule scoped to a router route.
///
/// Parsed and shape-checked, but not applied: see
/// [`reject_unimplemented_json_aliases`].
///
/// [`reject_unimplemented_json_aliases`]: super::reject_unimplemented_json_aliases
#[derive(Clone, Debug, Deserialize)]
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
