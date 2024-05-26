//! Path-prefix and host-header routing filter.

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
#[derive(Debug)]
pub struct RouterFilter {
    /// Ordered route table with pre-computed wildcard suffixes.
    routes: Vec<ResolvedRoute>,
}

/// A route paired with its pre-lowercased wildcard suffix (if any).
#[derive(Debug)]
struct ResolvedRoute {
    /// The original route configuration.
    route: Route,

    /// For wildcard hosts (e.g. `*.example.com`), the pre-lowercased
    /// suffix with leading dot: `.example.com`. `None` for exact hosts
    /// or routes without a host constraint.
    wildcard_suffix: Option<String>,
}

impl RouterFilter {
    /// Create a router from a list of routes.
    ///
    /// Returns an error if any `path_prefix` (other than `"/"`)
    /// does not end with `'/'`.
    ///
    /// ```
    /// use praxis_core::config::Route;
    /// use praxis_filter::RouterFilter;
    ///
    /// let router = RouterFilter::new(vec![
    ///     Route { path_prefix: "/".into(), host: None, headers: None, cluster: "default".into() },
    ///     Route { path_prefix: "/api/".into(), host: None, headers: None, cluster: "api".into() },
    /// ]).unwrap();
    /// ```
    ///
    /// ```
    /// use praxis_core::config::Route;
    /// use praxis_filter::RouterFilter;
    ///
    /// let err = RouterFilter::new(vec![
    ///     Route { path_prefix: "/api".into(), host: None, headers: None, cluster: "api".into() },
    /// ]).unwrap_err();
    /// assert!(err.to_string().contains("must end with '/'"));
    /// ```
    pub fn new(routes: Vec<Route>) -> Result<Self, FilterError> {
        let mut routes = routes;
        routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));
        for route in &routes {
            if route.path_prefix != "/" && !route.path_prefix.ends_with('/') {
                return Err(format!(
                    "router: path_prefix '{}' for cluster '{}' must end with '/' \
                     to ensure segment-bounded matching",
                    route.path_prefix, route.cluster,
                )
                .into());
            }
        }
        let resolved: Vec<ResolvedRoute> = routes
            .into_iter()
            .map(|route| {
                let wildcard_suffix = route
                    .host
                    .as_ref()
                    .and_then(|h| h.strip_prefix("*."))
                    .map(|suffix| format!(".{}", suffix.to_ascii_lowercase()));
                ResolvedRoute { route, wildcard_suffix }
            })
            .collect();
        debug!(routes = resolved.len(), "router initialized");
        Ok(Self { routes: resolved })
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
        Ok(Box::new(Self::new(routes)?))
    }

    /// Find the best matching route for the given path, host, and headers.
    ///
    /// When multiple routes share the same prefix length, the route with
    /// more constraints (host presence + header count) wins.
    fn match_route(&self, path: &str, host: Option<&str>, req_headers: &HeaderMap) -> Option<&Route> {
        let mut best: Option<(usize, usize, &Route)> = None;

        for resolved in &self.routes {
            let route = &resolved.route;
            if !path.starts_with(&route.path_prefix) {
                continue;
            }

            let host_ok = match &route.host {
                Some(h) => host.is_some_and(|req_host| {
                    let req_host = strip_port(req_host);
                    host_matches(h, resolved.wildcard_suffix.as_deref(), req_host)
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
// Wildcard host matching
// -----------------------------------------------------------------------------

/// Check whether a request host matches a route host pattern.
///
/// When `wildcard_suffix` is `Some`, the pattern is a wildcard
/// (e.g. `*.example.com`) and `wildcard_suffix` holds the
/// pre-lowercased suffix (`.example.com`). Zero allocations.
fn host_matches(pattern: &str, wildcard_suffix: Option<&str>, host: &str) -> bool {
    if let Some(suffix) = wildcard_suffix {
        if host.len() <= suffix.len() {
            return false;
        }
        let host_suffix = &host[host.len() - suffix.len()..];
        if !host_suffix.eq_ignore_ascii_case(suffix) {
            return false;
        }
        let subdomain = &host[..host.len() - suffix.len()];
        !subdomain.is_empty() && !subdomain.contains('.')
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

// -----------------------------------------------------------------------------
// Header matching
// -----------------------------------------------------------------------------

/// Returns `true` if the request headers satisfy all route header constraints.
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
// Host Utilities
// -----------------------------------------------------------------------------

/// Strip the port from a host string, handling both IPv4 and bracketed IPv6.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        match host.find(']') {
            Some(i) => &host[..=i],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
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
        RouterFilter::new(routes).expect("test routes should be valid")
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
        assert_eq!(&*route.cluster, "default", "root prefix should match any path");
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
        assert_eq!(&*route.cluster, "api", "longer /api/ prefix should win");

        let route = router.match_route("/static/main.js", None, &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "default", "non-api path should fall back to root");
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
        assert_eq!(
            &*route.cluster, "api",
            "matching host should select host-specific route"
        );

        let route = router
            .match_route("/", Some("other.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(
            &*route.cluster, "default",
            "non-matching host should fall back to default"
        );
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
        assert_eq!(
            &*route.cluster, "api",
            "host with port should match after stripping port"
        );
    }

    #[test]
    fn no_match() {
        let router = make_router(vec![Route {
            path_prefix: "/api/".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }]);
        assert!(
            router.match_route("/other", None, &HeaderMap::new()).is_none(),
            "non-matching prefix should return None"
        );
    }

    #[test]
    fn no_match_wrong_host() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        }]);
        assert!(
            router.match_route("/", Some("other.com"), &HeaderMap::new()).is_none(),
            "wrong host should return no match"
        );
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

        assert_eq!(filter.name(), "router", "filter name should be router");
    }

    #[test]
    fn from_config_empty_routes_key_missing() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());

        let filter = RouterFilter::from_config(&yaml).unwrap();

        assert_eq!(filter.name(), "router", "missing routes key should still create router");
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
        assert!(
            matches!(action, FilterAction::Continue),
            "matched route should continue"
        );
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("default"),
            "cluster should be set to matched route"
        );
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
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 404),
            "unmatched route should reject with 404"
        );
        assert!(ctx.cluster.is_none(), "cluster should remain unset on no match");
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
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("api"),
            "host header should select api cluster"
        );

        let req2 = crate::test_utils::make_request(http::Method::GET, "/v1/users");
        let mut ctx2 = crate::test_utils::make_filter_context(&req2);
        router.on_request(&mut ctx2).await.unwrap();
        assert_eq!(
            ctx2.cluster.as_deref(),
            Some("default"),
            "missing host should select default"
        );
    }

    #[test]
    fn route_matches_by_header() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
            cluster: "claude_sonnet".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(
            &*route.cluster, "claude_sonnet",
            "matching header should select header-constrained route"
        );
    }

    #[test]
    fn route_skips_mismatched_header() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
            cluster: "claude_sonnet".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
        assert!(
            router.match_route("/chat", None, &hdrs).is_none(),
            "mismatched header value should return no match"
        );
    }

    #[test]
    fn route_with_headers_wins_over_plain() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
                cluster: "claude_sonnet".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(
            &*route.cluster, "claude_sonnet",
            "header-constrained route should win over plain"
        );
    }

    #[test]
    fn route_without_headers_used_as_fallback() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
                cluster: "claude_sonnet".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(
            &*route.cluster, "default",
            "non-matching header should fall back to default"
        );
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

        let req = crate::context::Request {
            method: http::Method::GET,
            uri: "http://api.example.com/v1/data".parse().unwrap(),
            headers: http::HeaderMap::new(),
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        router.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("api"),
            "URI authority should be used when Host header is absent"
        );
    }

    #[test]
    fn multi_value_header_matches_any() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
            cluster: "claude_sonnet".into(),
        }]);

        let mut hdrs = HeaderMap::new();
        hdrs.append("x-model", HeaderValue::from_static("claude-3"));
        hdrs.append("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
        let route = router.match_route("/chat", None, &hdrs).unwrap();
        assert_eq!(
            &*route.cluster, "claude_sonnet",
            "any matching value in multi-value header should match"
        );
    }

    #[test]
    fn ipv6_host_with_port() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("[::1]".into()),
            headers: None,
            cluster: "ipv6".into(),
        }]);

        let route = router.match_route("/", Some("[::1]:8080"), &HeaderMap::new()).unwrap();
        assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 with port should match");
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
        assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 without port should match");
    }

    #[test]
    fn empty_route_table() {
        let router = make_router(vec![]);
        assert!(
            router.match_route("/anything", None, &HeaderMap::new()).is_none(),
            "empty route table should match nothing"
        );
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
        assert_eq!(
            &*route.cluster, "api-v2",
            "route with both host and headers should match"
        );
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
        let route = router.match_route("/", None, &hdrs).unwrap();
        assert_eq!(
            &*route.cluster, "first",
            "equal-constraint routes should prefer first match"
        );
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
        assert_eq!(&*route.cluster, "vacuous", "empty headers map should match everything");
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
        assert!(
            matches!(action, FilterAction::Continue),
            "host with port should still match route"
        );
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("example"),
            "port should be stripped from Host header for matching"
        );
    }

    #[test]
    fn non_segment_boundary_prefix_rejected() {
        let err = RouterFilter::new(vec![Route {
            path_prefix: "/api".into(),
            host: None,
            headers: None,
            cluster: "api".into(),
        }])
        .unwrap_err();
        assert!(
            err.to_string().contains("must end with '/'"),
            "path_prefix without trailing slash should be rejected: {err}"
        );
    }

    #[test]
    fn wildcard_host_matches_subdomain() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        let route = router
            .match_route("/", Some("api.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(
            &*route.cluster, "wildcard",
            "*.example.com should match api.example.com"
        );
    }

    #[test]
    fn wildcard_host_does_not_match_bare_domain() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        assert!(
            router
                .match_route("/", Some("example.com"), &HeaderMap::new())
                .is_none(),
            "*.example.com should not match bare example.com"
        );
    }

    #[test]
    fn wildcard_host_does_not_match_multi_level_subdomain() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        assert!(
            router
                .match_route("/", Some("a.b.example.com"), &HeaderMap::new())
                .is_none(),
            "*.example.com should not match multi-level subdomain a.b.example.com"
        );
    }

    #[test]
    fn wildcard_host_with_port() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        let route = router
            .match_route("/", Some("www.example.com:8080"), &HeaderMap::new())
            .unwrap();
        assert_eq!(
            &*route.cluster, "wildcard",
            "wildcard host should match after stripping port"
        );
    }

    #[test]
    fn wildcard_host_case_insensitive() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.Example.COM".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        let route = router
            .match_route("/", Some("API.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(
            &*route.cluster, "wildcard",
            "wildcard host matching should be case-insensitive"
        );
    }

    #[test]
    fn wildcard_host_with_fallback() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("*.example.com".into()),
                headers: None,
                cluster: "wildcard".into(),
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
        assert_eq!(
            &*route.cluster, "wildcard",
            "wildcard route should match api.example.com"
        );

        let route = router.match_route("/", Some("other.dev"), &HeaderMap::new()).unwrap();
        assert_eq!(
            &*route.cluster, "default",
            "non-matching host should fall back to default"
        );
    }

    #[test]
    fn exact_host_wins_over_wildcard_same_constraints() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("api.example.com".into()),
                headers: None,
                cluster: "exact".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: Some("*.example.com".into()),
                headers: None,
                cluster: "wildcard".into(),
            },
        ]);

        let route = router
            .match_route("/", Some("api.example.com"), &HeaderMap::new())
            .unwrap();
        assert_eq!(
            &*route.cluster, "exact",
            "exact host match should win over wildcard (first-match semantics)"
        );
    }

    #[test]
    fn wildcard_host_does_not_match_empty_subdomain() {
        let router = make_router(vec![Route {
            path_prefix: "/".into(),
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        }]);

        assert!(
            router
                .match_route("/", Some(".example.com"), &HeaderMap::new())
                .is_none(),
            "*.example.com should not match .example.com (empty subdomain)"
        );
    }

    #[tokio::test]
    async fn on_request_wildcard_host_via_host_header() {
        let router = make_router(vec![
            Route {
                path_prefix: "/".into(),
                host: Some("*.example.com".into()),
                headers: None,
                cluster: "wildcard".into(),
            },
            Route {
                path_prefix: "/".into(),
                host: None,
                headers: None,
                cluster: "default".into(),
            },
        ]);

        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("host", HeaderValue::from_static("app.example.com"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        router.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("wildcard"),
            "wildcard should match via Host header"
        );
    }
}
