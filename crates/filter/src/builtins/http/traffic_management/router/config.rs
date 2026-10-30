// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the router filter.

use praxis_core::config::Route;
use serde::Deserialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default header name for the resolved JSON alias value.
#[cfg(feature = "router-json-aliases")]
pub(super) const DEFAULT_JSON_ALIAS_HEADER: &str = "X-Json-Alias";

/// Default maximum body bytes to buffer for JSON alias resolution.
#[cfg(feature = "router-json-aliases")]
pub(super) const DEFAULT_JSON_ALIAS_MAX_BODY_BYTES: usize = 10_485_760; // 10 MiB

/// Hard upper bound for `json_alias_max_body_bytes`.
#[cfg(feature = "router-json-aliases")]
pub(super) const MAX_JSON_ALIAS_BODY_BYTES: usize = 67_108_864; // 64 MiB

// -----------------------------------------------------------------------------
// RouterConfig
// -----------------------------------------------------------------------------

/// Deserialization wrapper for the router's YAML config.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouterConfig {
    /// Reserved for the experimental, unimplemented JSON alias feature.
    ///
    /// Only present under the `router-json-aliases` feature, and even then
    /// it has no effect: any route setting `json_aliases` is rejected at
    /// startup. Default builds do not accept this key.
    #[cfg(feature = "router-json-aliases")]
    #[serde(default = "default_json_alias_header")]
    pub json_alias_header: String,

    /// Reserved for the experimental, unimplemented JSON alias feature.
    ///
    /// Only present under the `router-json-aliases` feature, and even then
    /// it has no effect: any route setting `json_aliases` is rejected at
    /// startup. Default builds do not accept this key.
    #[cfg(feature = "router-json-aliases")]
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
/// Deserialization delegates every route field to [`Route`] itself, so the
/// router and the core config cannot drift. The router-specific
/// `json_aliases` key is split off the mapping first; when the feature is
/// disabled it is left in place and `Route` rejects it as unknown.
///
/// [`praxis_core::config::Route`]: praxis_core::config::Route
#[derive(Clone, Debug)]
pub(super) struct RouterRouteConfig {
    /// Generic path, host, header, and cluster routing fields.
    pub route: Route,

    /// Not implemented. Setting this is rejected at startup.
    ///
    /// Body-field routing is not wired into the request path. Promote
    /// the value to a header with a classifier filter and match it via
    /// the route's `headers` field instead. Only present under the
    /// experimental `router-json-aliases` feature.
    #[cfg(feature = "router-json-aliases")]
    pub json_aliases: Option<Vec<JsonAlias>>,
}

impl From<Route> for RouterRouteConfig {
    fn from(route: Route) -> Self {
        Self {
            route,
            #[cfg(feature = "router-json-aliases")]
            json_aliases: None,
        }
    }
}

impl<'de> Deserialize<'de> for RouterRouteConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[cfg(feature = "router-json-aliases")]
        let mut value = serde_yaml::Value::deserialize(deserializer)?;
        #[cfg(not(feature = "router-json-aliases"))]
        let value = serde_yaml::Value::deserialize(deserializer)?;

        #[cfg(feature = "router-json-aliases")]
        let json_aliases = match &mut value {
            serde_yaml::Value::Mapping(map) => map
                .remove(serde_yaml::Value::String("json_aliases".to_owned()))
                .map(serde_yaml::from_value::<Option<Vec<JsonAlias>>>)
                .transpose()
                .map_err(serde::de::Error::custom)?
                .flatten(),
            _ => None,
        };

        let route: Route = serde_yaml::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            route,
            #[cfg(feature = "router-json-aliases")]
            json_aliases,
        })
    }
}

/// JSON field alias rule scoped to a router route.
///
/// Parsed and shape-checked, but not applied: see
/// [`reject_unimplemented_json_aliases`].
///
/// [`reject_unimplemented_json_aliases`]: super::reject_unimplemented_json_aliases
#[cfg(feature = "router-json-aliases")]
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
#[cfg(feature = "router-json-aliases")]
fn default_json_alias_header() -> String {
    DEFAULT_JSON_ALIAS_HEADER.to_owned()
}

/// Serde default for [`RouterConfig::json_alias_max_body_bytes`].
#[cfg(feature = "router-json-aliases")]
fn default_json_alias_max_body_bytes() -> usize {
    DEFAULT_JSON_ALIAS_MAX_BODY_BYTES
}
