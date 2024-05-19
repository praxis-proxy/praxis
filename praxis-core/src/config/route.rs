//! Legacy routing rules (path-prefix + optional host to cluster).
//!
//! Used by [`Config::apply_defaults`] to generate a
//! default router + load-balancer pipeline when no explicit pipeline is set.
//!
//! [`Config::apply_defaults`]: super::Config

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Route
// -----------------------------------------------------------------------------

/// A routing rule mapping requests to a cluster.
///
/// ```
/// use praxis_core::config::Route;
///
/// let route: Route = serde_yaml::from_str(r#"
/// path_prefix: "/api"
/// cluster: backend
/// "#).unwrap();
/// assert_eq!(route.path_prefix, "/api");
/// assert_eq!(route.cluster, "backend");
/// assert!(route.host.is_none());
/// assert!(route.headers.is_none());
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]

pub struct Route {
    /// Path prefix to match. The longest matching prefix wins.
    pub path_prefix: String,

    /// Host to match. If set, the route only applies to this host.
    #[serde(default)]
    pub host: Option<String>,

    /// Request headers to match. All specified headers must be present
    /// with matching values (AND semantics, case-sensitive).
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Name of the cluster to route matched requests to.
    pub cluster: String,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_without_host() {
        let yaml = r#"
path_prefix: "/api"
cluster: "backend"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.path_prefix, "/api");
        assert_eq!(route.cluster, "backend");
        assert!(route.host.is_none());
    }

    #[test]
    fn parse_route_with_headers() {
        let yaml = r#"
path_prefix: "/"
cluster: "backend"
headers:
  x-model: "gpt-4"
  x-version: "v1"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        let headers = route.headers.unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("x-model").unwrap(), "gpt-4");
        assert_eq!(headers.get("x-version").unwrap(), "v1");
    }

    #[test]
    fn parse_route_with_host() {
        let yaml = r#"
path_prefix: "/"
host: "api.example.com"
cluster: "api"
"#;
        let route: Route = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.host.as_deref(), Some("api.example.com"));
    }
}
