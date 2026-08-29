// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shorthand routing rules.
//!
//! [`PathMatch`] and [`Route`] provide the YAML-level routing model
//! consumed by the router filter. Routes match requests by path
//! (exact or prefix), optional host, and optional header predicates,
//! then select a target cluster. These types are config-only; runtime
//! matching logic lives in the router filter's `matching` module.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

use super::RetryPolicy;

// -----------------------------------------------------------------------------
// PathMatch
// -----------------------------------------------------------------------------

/// How a route matches request paths.
///
/// Deserializes from YAML as an untagged enum: a `path` key produces
/// [`Exact`], a `path_prefix` key produces [`Prefix`].
///
/// ```
/// use praxis_core::config::PathMatch;
///
/// let exact: PathMatch = serde_yaml::from_str("path: /one\n").unwrap();
/// assert!(matches!(exact, PathMatch::Exact { .. }));
/// assert_eq!(exact.value(), "/one");
///
/// let prefix: PathMatch = serde_yaml::from_str("path_prefix: /api/\n").unwrap();
/// assert!(matches!(prefix, PathMatch::Prefix { .. }));
/// assert_eq!(prefix.value(), "/api/");
/// ```
///
/// [`Exact`]: PathMatch::Exact
/// [`Prefix`]: PathMatch::Prefix
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PathMatch {
    /// Exact path match.
    Exact {
        /// The exact path to match.
        path: String,
    },

    /// Segment-boundary prefix match (Gateway API semantics).
    /// `/api` matches `/api`, `/api/`, `/api/v1` but NOT `/apikeys`.
    Prefix {
        /// Path prefix. The longest matching prefix wins.
        path_prefix: String,
    },
}

impl PathMatch {
    /// Build a [`PathMatch`] from optional `path` / `path_prefix` keys,
    /// enforcing that exactly one is set.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let exact = PathMatch::from_parts(Some("/one".to_owned()), None).unwrap();
    /// assert!(exact.is_exact());
    ///
    /// let both = PathMatch::from_parts(Some("/one".to_owned()), Some("/api".to_owned()));
    /// assert!(both.is_err());
    ///
    /// let neither = PathMatch::from_parts(None, None);
    /// assert!(neither.is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when both or neither of `path` and
    /// `path_prefix` are set.
    pub fn from_parts(path: Option<String>, path_prefix: Option<String>) -> Result<Self, String> {
        match (path, path_prefix) {
            (Some(path), None) => {
                if path.is_empty() {
                    return Err("route 'path' must not be empty (request paths always begin with '/')".to_owned());
                }
                if !path.starts_with('/') {
                    return Err(format!(
                        "route 'path' must start with '/' (got '{path}'); request paths always begin with '/', \
                         so this route can never match"
                    ));
                }
                Ok(Self::Exact { path })
            },
            (None, Some(path_prefix)) => {
                // An empty prefix is the documented match-all; any other
                // non-'/'-prefixed value can never match a request path.
                if !path_prefix.is_empty() && !path_prefix.starts_with('/') {
                    return Err(format!(
                        "route 'path_prefix' must start with '/' or be empty (got '{path_prefix}'); \
                         request paths always begin with '/', so this prefix can never match"
                    ));
                }
                Ok(Self::Prefix { path_prefix })
            },
            (Some(_), Some(_)) => Err("route cannot set both 'path' and 'path_prefix' (use exactly one)".to_owned()),
            (None, None) => Err("route requires either 'path' or 'path_prefix'".to_owned()),
        }
    }

    /// Returns `true` when this is an exact-path match.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let exact = PathMatch::Exact {
    ///     path: "/one".to_owned(),
    /// };
    /// assert!(exact.is_exact());
    ///
    /// let prefix = PathMatch::Prefix {
    ///     path_prefix: "/".to_owned(),
    /// };
    /// assert!(!prefix.is_exact());
    /// ```
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }

    /// Byte length of the matched path or prefix.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Prefix {
    ///     path_prefix: "/api/".to_owned(),
    /// };
    /// assert_eq!(m.len(), 5);
    /// ```
    pub fn len(&self) -> usize {
        self.value().len()
    }

    /// Returns `true` when the path or prefix string is empty.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Prefix {
    ///     path_prefix: "/".to_owned(),
    /// };
    /// assert!(!m.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.value().is_empty()
    }

    /// The path or prefix string.
    ///
    /// ```
    /// use praxis_core::config::PathMatch;
    ///
    /// let m = PathMatch::Exact {
    ///     path: "/health".to_owned(),
    /// };
    /// assert_eq!(m.value(), "/health");
    /// ```
    pub fn value(&self) -> &str {
        match self {
            Self::Exact { path } => path,
            Self::Prefix { path_prefix } => path_prefix,
        }
    }
}

// -----------------------------------------------------------------------------
// Route
// -----------------------------------------------------------------------------

/// A routing rule mapping requests to a cluster.
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path_prefix: "/api/"
/// cluster: backend
/// "#,
/// )
/// .unwrap();
/// assert_eq!(route.path_match.value(), "/api/");
/// assert_eq!(&*route.cluster, "backend");
/// assert!(!route.path_match.is_exact());
/// assert!(route.host.is_none());
/// assert!(route.headers.is_none());
/// ```
///
/// Exact path matching:
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(
///     r#"
/// path: "/one"
/// cluster: backend
/// "#,
/// )
/// .unwrap();
/// assert!(route.path_match.is_exact());
/// assert_eq!(route.path_match.value(), "/one");
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "RouteRaw")]
pub struct Route {
    /// Path matching strategy (exact or prefix).
    #[serde(flatten)]
    pub path_match: PathMatch,

    /// Name of the cluster to route matched requests to.
    pub cluster: Arc<str>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    pub headers: Option<HashMap<String, String>>,

    /// Host to match. If set, the route only applies to this host.
    pub host: Option<String>,

    /// Optional per-route retry policy override.
    ///
    /// Merged onto the cluster `retry_policy`: route fields replace
    /// cluster fields where present. List fields replace entirely.
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,
}

/// Raw deserialization target for [`Route`].
///
/// Spells out `path` / `path_prefix` as plain optional fields so
/// `deny_unknown_fields` works (it is incompatible with the
/// `#[serde(flatten)]` + untagged-enum shape that [`Route`] uses for
/// serialization); [`TryFrom`] enforces exactly-one-of.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteRaw {
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

    /// Optional per-route retry policy override.
    #[serde(default)]
    retry_policy: Option<RetryPolicy>,
}

impl Route {
    /// Validate cross-field route semantics that the type system does
    /// not enforce: retry-policy timeout bounds and header-match keys.
    ///
    /// Called from every construction path (the [`Route`] deserializer
    /// and the router filter's own route config) so a route can never
    /// reach the runtime with an out-of-bounds retry timeout or an empty
    /// header-match key (which can never match a request).
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending field.
    pub fn validate_semantics(&self) -> Result<(), String> {
        if let Some(policy) = &self.retry_policy {
            policy.validate_timeout_bounds(&format!("route '{}'", self.path_match.value()))?;
        }
        if let Some(headers) = &self.headers
            && headers.keys().any(String::is_empty)
        {
            return Err(format!(
                "route '{}': header match key must not be empty (an empty header name can never match)",
                self.path_match.value()
            ));
        }
        if self.host.as_ref().is_some_and(String::is_empty) {
            return Err(format!(
                "route '{}': host must not be empty (an empty host can never match; \
                 omit 'host' to match any host)",
                self.path_match.value()
            ));
        }
        Ok(())
    }
}

impl TryFrom<RouteRaw> for Route {
    type Error = String;

    fn try_from(raw: RouteRaw) -> Result<Self, Self::Error> {
        let route = Self {
            path_match: PathMatch::from_parts(raw.path, raw.path_prefix)?,
            cluster: raw.cluster,
            headers: raw.headers,
            host: raw.host,
            retry_policy: raw.retry_policy,
        };
        route.validate_semantics()?;
        Ok(route)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_without_host() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.path_match.value(), "/api", "path value mismatch");
        assert!(!route.path_match.is_exact(), "should be prefix match");
        assert_eq!(&*route.cluster, "backend", "cluster mismatch");
        assert!(route.host.is_none(), "host should be None when omitted");
    }

    #[test]
    fn parse_route_with_headers() {
        let yaml = r#"
path_prefix: "/"
cluster: "backend"
headers:
  x-model: "model-alpha-1"
  x-version: "v1"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let headers = route.headers.unwrap();
        assert_eq!(headers.len(), 2, "should have 2 header constraints");
        assert_eq!(
            headers.get("x-model").unwrap(),
            "model-alpha-1",
            "x-model header mismatch"
        );
        assert_eq!(headers.get("x-version").unwrap(), "v1", "x-version header mismatch");
    }

    #[test]
    fn parse_route_with_host() {
        let yaml = r#"
path_prefix: "/"
host: "api.example.com"
cluster: "api"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.host.as_deref(), Some("api.example.com"), "host should be parsed");
    }

    #[test]
    fn parse_exact_path() {
        let yaml = r#"
path: "/exact"
cluster: "backend"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert!(route.path_match.is_exact(), "should be exact match");
        assert_eq!(route.path_match.value(), "/exact", "exact path mismatch");
    }

    #[test]
    fn reject_unknown_route_keys() {
        let yaml = r#"
path_prfix: "/api"
path_prefix: "/api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("path_prfix") || err.to_string().contains("unknown field"),
            "typoed keys must be rejected, not silently absorbed: {err}"
        );
    }

    #[test]
    fn reject_both_path_and_prefix() {
        let yaml = r#"
path: "/one"
path_prefix: "/api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("both 'path' and 'path_prefix'"),
            "setting both path keys must be rejected: {err}"
        );
    }

    #[test]
    fn reject_missing_path_keys() {
        let yaml = r#"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("either 'path' or 'path_prefix'"),
            "a route without a path key must be rejected: {err}"
        );
    }

    #[test]
    fn reject_prefix_without_leading_slash() {
        let yaml = r#"
path_prefix: "api"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must start with '/'"),
            "a prefix that can never match a request path must be rejected: {err}"
        );
    }

    #[test]
    fn reject_exact_path_without_leading_slash() {
        let yaml = r#"
path: "health"
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(err.to_string().contains("must start with '/'"), "got: {err}");
    }

    #[test]
    fn reject_empty_exact_path() {
        let yaml = r#"
path: ""
cluster: "backend"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn empty_prefix_is_match_all() {
        // The documented match-all prefix stays valid.
        let route: Route = serde_yaml::from_str("path_prefix: \"\"\ncluster: backend\n").unwrap();
        assert_eq!(route.path_match.value(), "");
    }

    #[test]
    fn reject_empty_header_match_key() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
headers:
  "": "value"
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("header match key must not be empty"),
            "an empty header name can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_host_match() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
host: ""
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("host must not be empty"),
            "an empty host can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_route_retry_policy_zero_timeout() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
retry_policy:
  per_try_timeout_ms: 0
"#;
        let err = serde_yaml::from_str::<Route>(yaml).unwrap_err();
        assert!(
            err.to_string().contains("per_try_timeout_ms is 0"),
            "route-level retry overrides get the same timeout bounds as clusters: {err}"
        );
    }

    #[test]
    fn route_serializes_with_flattened_path() {
        let route = Route {
            path_match: PathMatch::Prefix {
                path_prefix: "/api".to_owned(),
            },
            cluster: Arc::from("backend"),
            headers: None,
            host: None,
            retry_policy: None,
        };
        let yaml = serde_yaml::to_string(&route).unwrap();
        assert!(
            yaml.contains("path_prefix: /api"),
            "serialization keeps the flattened path key: {yaml}"
        );
    }

    #[test]
    fn path_match_len() {
        let prefix = PathMatch::Prefix {
            path_prefix: "/api/".to_owned(),
        };
        assert_eq!(prefix.len(), 5, "prefix length mismatch");

        let exact = PathMatch::Exact {
            path: "/one".to_owned(),
        };
        assert_eq!(exact.len(), 4, "exact length mismatch");
    }
}
