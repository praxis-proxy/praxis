//! Path-prefix and host-header routing filter.
//!
//! Selects a cluster name for each request, which the load-balancer filter
//! then resolves to a specific endpoint.
//! Registered as `"router"` in the filter registry.

use std::collections::HashMap;

use async_trait::async_trait;
use http::HeaderMap;
use praxis_core::config::Route;
use tracing::{debug, trace};

use crate::{
    FilterError,
    actions::{FilterAction, Rejection},
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// RouterFilter
// -----------------------------------------------------------------------------

/// Routes requests to clusters based on path prefix and host header.
///
/// # YAML configuration
///
/// ```yaml
/// filter: router
/// routes:
///   - path_prefix: "/"
///     cluster: default
/// ```
///
/// # Example
///
/// ```
/// use praxis_filter::RouterFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(r#"
/// routes:
///   - path_prefix: "/"
///     cluster: default
/// "#).unwrap();
/// let filter = RouterFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "router");
/// ```
pub struct RouterFilter {
    /// Ordered route table; first match wins.
    routes: Vec<Route>,
}

impl RouterFilter {
    /// Create a router from a list of routes.
    ///
    /// ```
    /// use praxis_core::config::Route;
    /// use praxis_filter::RouterFilter;
    ///
    /// let router = RouterFilter::new(vec![
    ///     Route { path_prefix: "/".into(), host: None, headers: None, cluster: "default".into() },
    ///     Route { path_prefix: "/api/".into(), host: None, headers: None, cluster: "api".into() },
    /// ]);
    /// // Longer prefixes are checked first (internal sorting).
    /// ```
    pub fn new(routes: Vec<Route>) -> Self {
        let mut routes = routes;
        routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
        debug!(routes = routes.len(), "router initialized");
        Self { routes }
    }

    /// Create a router from parsed YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let routes: Vec<Route> = serde_yaml::from_value(
            config
                .get("routes")
                .cloned()
                .unwrap_or(serde_yaml::Value::Sequence(vec![])),
        )
        .map_err(|e| -> FilterError { format!("router: {e}").into() })?;
        Ok(Box::new(Self::new(routes)))
    }

    /// Find the best matching route for the given path, host, and headers.
    ///
    /// When multiple routes share the same prefix length, the route with
    /// more constraints (host presence + header count) wins.
    ///
    /// Note: prefix matching is raw string comparison, not path-segment-aware.
    /// A `path_prefix` of `"/api"` will match both `"/api/v1"` and `"/apiary"`.
    /// End prefixes with `"/"` (e.g. `"/api/"`) to avoid unintended matches.
    fn match_route(&self, path: &str, host: Option<&str>, req_headers: &HeaderMap) -> Option<&Route> {
        let mut best: Option<(usize, usize, &Route)> = None;

        for route in &self.routes {
            if !path.starts_with(&route.path_prefix) {
                continue;
            }

            let host_ok = match &route.host {
                Some(h) => host.is_some_and(|req_host| {
                    let req_host = strip_port(req_host);
                    req_host == h
                }),
                None => true,
            };

            if !host_ok {
                continue;
            }

            if !headers_match(&route.headers, req_headers) {
                continue;
            }

            let prefix_len = route.path_prefix.len();
            let constraints = route.host.is_some() as usize + route.headers.as_ref().map_or(0, HashMap::len);
            let dominated = best.is_some_and(|(bp, bc, _)| (prefix_len, constraints) <= (bp, bc));
            if !dominated {
                best = Some((prefix_len, constraints, route));
            }

            // Routes are sorted descending by prefix length. Once we see a
            // prefix shorter than our best, no later route can beat it.
            if let Some((bp, _, _)) = best
                && route.path_prefix.len() < bp
            {
                break;
            }
        }

        best.map(|(_, _, r)| r)
    }
}

// -----------------------------------------------------------------------------
// Host helpers
// -----------------------------------------------------------------------------

/// Strip the port from a host string, handling both IPv4 and bracketed IPv6.
///
/// Bracketed IPv6 (e.g. `[::1]:8080`) keeps everything up to and including `]`.
/// Plain hosts (e.g. `example.com:8080`) split on the first `:`.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 bracketed form: find closing `]`
        match host.find(']') {
            Some(i) => &host[..=i],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

// -----------------------------------------------------------------------------
// Header matching
// -----------------------------------------------------------------------------

/// Returns `true` if the request headers satisfy all route header constraints.
///
/// Each entry in `required` must appear in `actual` with a case-sensitive
/// value match. `None` means no header constraints (always matches).
fn headers_match(required: &Option<std::collections::HashMap<String, String>>, actual: &HeaderMap) -> bool {
    let Some(required) = required else {
        return true;
    };
    required.iter().all(|(key, val)| {
        actual
            .get_all(key.as_str())
            .iter()
            .any(|v| v.to_str().ok().is_some_and(|v| v == val))
    })
}

// -----------------------------------------------------------------------------
// Filter Impl
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for RouterFilter {
    fn name(&self) -> &'static str {
        "router"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let path = ctx.request.uri.path();
        // Prefer the Host header (HTTP/1.1). Fall back to
        // the URI authority (HTTP/2 :authority pseudo-header).
        let host = ctx
            .request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| ctx.request.uri.authority().map(http::uri::Authority::as_str));

        trace!(path = %path, host = host.unwrap_or(""), "matching route");
        match self.match_route(path, host, &ctx.request.headers) {
            Some(route) => {
                debug!(
                    path = %path,
                    cluster = %route.cluster,
                    "route matched"
                );
                ctx.cluster = Some(route.cluster.clone());
                Ok(FilterAction::Continue)
            },
            None => {
                debug!(path = %path, "no route matched");
                Ok(FilterAction::Reject(Rejection::status(404)))
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use http::{HeaderMap, HeaderValue};
    use praxis_core::config::Route;

    use super::*;

    fn make_router(routes: Vec<Route>) -> RouterFilter {
        RouterFilter::new(routes)
    }

    #[test]
    fn match_root() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: None,
            cluster: "default".into(),
        }]);
        let route = router.match_route("/anything", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "default");
    }

    #[test]
    fn longest_prefix_wins() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
            Route {
                path_prefix: "/api/".into(),
                host: None,
                headers: None,
                cluster: "api".into(),
            },
        ]);

        let route = router.match_route("/api/users", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "api");

        let route = router.match_route("/static/main.js", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "default");
    }

    #[test]
    fn host_filtering() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("api.example.com".into()),
                headers: None,
                cluster: "api".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let route = router
            .match_route("/", Some("api.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(&*route.cluster, "api");

        let route = router
            .match_route("/", Some("other.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(&*route.cluster, "default");
    }

    #[test]
    fn host_with_port() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        }]);

        let route = router
            .match_route("/", Some("api.example.com:8080"), &HeaderMap::new())
            .unwrap();
        assert_eq!(&*route.cluster, "api");
    }

    #[test]
    fn no_match() {
        let router = make_router(vec![Route {
            path_prefix: "/api/".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }]);
        assert!(router.match_route("/other", None, &HeaderMap::new()).is_none());
    }

    #[test]
    fn no_match_wrong_host() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        }]);
        assert!(router.match_route("/", Some("other.com"), &HeaderMap::new()).is_none());
    }

    #[test]
    fn from_config_parses_routes() {
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            routes:
              - path_prefix: "/api/"
                cluster: "api"
              - path_prefix: "/"
                cluster: "default"
            "#,
        )
        .unwrap();

        let filter = RouterFilter::from_config(&yaml).unwrap();

        assert_eq!(filter.name(), "router");
    }

    #[test]
    fn from_config_empty_routes_key_missing() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());

        let filter = RouterFilter::from_config(&yaml).unwrap();

        assert_eq!(filter.name(), "router");
    }

    #[tokio::test]
    async fn on_request_sets_cluster_on_match() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: None,
            cluster: "default".into(),
        }]);
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = router.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.cluster.as_deref(), Some("default"));
    }

    #[tokio::test]
    async fn on_request_rejects_on_no_match() {
        let router = make_router(vec![Route {
            path_prefix: "/api/".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }]);
        let req = crate::test_utils::make_request(http::Method::GET, "/other");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = router.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 404));
        assert!(ctx.cluster.is_none());
    }

    #[tokio::test]
    async fn on_request_combined_host_and_path() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("api.example.com".into()),
                headers: None,
                cluster: "api".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut req = crate::test_utils::make_request(http::Method::GET, "/v1/users");
        req.headers.insert("host", HeaderValue::from_static("api.example.com"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        router.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.cluster.as_deref(), Some("api"));

        let req2 = crate::test_utils::make_request(http::Method::GET, "/v1/users");
        let mut ctx2 = crate::test_utils::make_filter_context(&req2);
        router.on_request(&mut ctx2).await.unwrap();
        assert_eq!(ctx2.cluster.as_deref(), Some("default"));
    }

    // ---------------------------------------------------------
    // Header-Based Routing
    // ---------------------------------------------------------

    #[test]
    fn route_matches_by_header() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "gpt-4".into())])),
            cluster: "gpt4".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("gpt-4"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(&*route.cluster, "gpt4");
    }

    #[test]
    fn route_skips_mismatched_header() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "gpt-4".into())])),
            cluster: "gpt4".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("gpt-3.5"));
        assert!(router.match_route("/chat", None, &hdrs).is_none());
    }

    #[test]
    fn route_with_headers_wins_over_plain() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-model".into(), "gpt-4".into())])),
                cluster: "gpt4".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("gpt-4"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(&*route.cluster, "gpt4");
    }

    #[test]
    fn route_without_headers_used_as_fallback() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-model".into(), "gpt-4".into())])),
                cluster: "gpt4".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("claude-3"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(&*route.cluster, "default");
    }

    #[tokio::test]
    async fn host_falls_back_to_uri_authority() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("api.example.com".into()),
                headers: None,
                cluster: "api".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        // No Host header, but URI has authority (simulates H2).
        let req = crate::context::Request {
            method: http::Method::GET,
            uri: "http://api.example.com/v1/data".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        router.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.cluster.as_deref(), Some("api"));
    }

    #[test]
    fn multi_value_header_matches_any() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "gpt-4".into())])),
            cluster: "gpt4".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.append("x-model", HeaderValue::from_static("claude-3"));
        hdrs.append("x-model", HeaderValue::from_static("gpt-4"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(&*route.cluster, "gpt4");
    }

    // ---------------------------------------------------------
    // IPv6 Host Matching
    // ---------------------------------------------------------

    #[test]
    fn ipv6_host_with_port() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("[::1]".into()),
            headers: None,
            cluster: "ipv6".into(),
        }]);

        let route = router.match_route("/", Some("[::1]:8080"), &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "ipv6");
    }

    #[test]
    fn ipv6_host_without_port() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("[::1]".into()),
            headers: None,
            cluster: "ipv6".into(),
        }]);

        let route = router.match_route("/", Some("[::1]"), &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "ipv6");
    }

    // ---------------------------------------------------------
    // Edge Cases
    // ---------------------------------------------------------

    #[test]
    fn empty_route_table() {
        let router = make_router(vec![]);
        assert!(router.match_route("/anything", None, &HeaderMap::new()).is_none());
    }

    #[test]
    fn route_with_host_and_headers() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("api.example.com".into()),
                headers: Some(HashMap::from([("x-version".into(), "v2".into())])),
                cluster: "api-v2".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-version", HeaderValue::from_static("v2"));
        let route = router.match_route("/", Some("api.example.com"), &hdrs).unwrap();
        assert_eq!(&*route.cluster, "api-v2");
        // host (1) + headers (1) = 2 constraints, beating default (0)
    }

    #[test]
    fn same_prefix_same_constraints_first_wins() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-a".into(), "1".into())])),
                cluster: "first".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-b".into(), "2".into())])),
                cluster: "second".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-a", HeaderValue::from_static("1"));
        hdrs.insert("x-b", HeaderValue::from_static("2"));
        // Both routes match with equal prefix length and equal constraint
        // count (1 each). The first declared route wins.
        let route = router.match_route("/", None, &hdrs).unwrap();
        assert_eq!(&*route.cluster, "first");
    }

    #[test]
    fn empty_headers_map_matches_everything() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::new()),
            cluster: "vacuous".into(),
        }]);

        let route = router.match_route("/test", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "vacuous");
    }

    #[tokio::test]
    async fn on_request_strips_port_from_host_header() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("example.com".into()),
            headers: None,
            cluster: "example".into(),
        }]);

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("host", HeaderValue::from_static("example.com:9090"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = router.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.cluster.as_deref(), Some("example"));
    }

    #[test]
    fn non_segment_boundary_prefix_matches() {
        // Documenting behavior: "/api" matches "/apiary" because matching
        // is raw string prefix, not path-segment-aware.
        let router = make_router(vec![Route {
            path_prefix: "/api".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }]);

        let route = router.match_route("/apiary", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "api");
    }
}
