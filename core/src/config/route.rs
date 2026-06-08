// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shorthand routing rules.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Route {
    /// Path matching strategy (exact or prefix).
    #[serde(flatten)]
    pub path_match: PathMatch,

    /// Host to match. If set, the route only applies to this host.
    #[serde(default)]
    pub host: Option<String>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Name of the cluster to route matched requests to.
    pub cluster: Arc<str>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
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
  x-model: "claude-sonnet-4-5"
  x-version: "v1"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let headers = route.headers.unwrap();
        assert_eq!(headers.len(), 2, "should have 2 header constraints");
        assert_eq!(
            headers.get("x-model").unwrap(),
            "claude-sonnet-4-5",
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
