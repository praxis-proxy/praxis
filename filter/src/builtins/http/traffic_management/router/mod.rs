// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path-prefix and host-header routing filter.

mod config;
mod json_alias;
mod matching;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "tests"
)]
mod tests;

use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderMap, header::HeaderName};
use praxis_core::config::{PathMatch, Route};
use tracing::{debug, trace};

use self::{
    config::{
        DEFAULT_JSON_ALIAS_HEADER, DEFAULT_JSON_ALIAS_MAX_BODY_BYTES, JsonAlias, MAX_JSON_ALIAS_BODY_BYTES,
        RouterConfig, RouterRouteConfig,
    },
    matching::{route_matches_request, should_stop_early, update_best_match},
};
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
/// If a preceding filter (such as `path_rewrite` or `url_rewrite`) has
/// set [`rewritten_path`], the router matches against the rewritten
/// path. Otherwise, it uses the original request path.
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
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// routes:
///   - path_prefix: "/"
///     cluster: default
/// "#,
/// )
/// .unwrap();
/// let filter = RouterFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "router");
/// ```
///
/// [`rewritten_path`]: crate::HttpFilterContext::rewritten_path
#[derive(Debug)]
pub struct RouterFilter {
    /// Whether any route has JSON aliases configured.
    #[allow(dead_code, reason = "alias config is validated before body access is wired")]
    has_json_alias_routes: bool,

    /// Maximum body bytes to buffer for JSON alias resolution.
    #[allow(dead_code, reason = "alias config is validated before body buffering is wired")]
    json_alias_max_body_bytes: usize,

    /// Header name for the promoted JSON alias value.
    #[allow(dead_code, reason = "alias config is validated before header promotion is wired")]
    json_alias_header: HeaderName,

    /// Enable multi-level subdomain matching for wildcard hosts.
    multi_level_subdomain_matching: bool,

    /// Ordered route table with pre-computed wildcard suffixes.
    routes: Vec<ResolvedRoute>,
}

/// A route paired with its pre-lowercased wildcard suffix (if any).
#[derive(Debug)]
struct ResolvedRoute {
    /// The original route configuration.
    route: Route,

    /// Optional JSON aliases configured on this route.
    #[allow(dead_code, reason = "route aliases are validated before body aliasing is wired")]
    json_aliases: Option<Vec<JsonAlias>>,

    /// For wildcard hosts (e.g. `*.example.com`), the pre-lowercased
    /// suffix with leading dot: `.example.com`. `None` for exact hosts
    /// or routes without a host constraint.
    wildcard_suffix: Option<String>,
}

impl RouterFilter {
    /// Create a router from a list of routes with default alias options.
    ///
    /// Path prefix matching uses segment-boundary semantics per Gateway API:
    /// `/api` matches `/api`, `/api/`, `/api/v1` but NOT `/apikeys`.
    /// Trailing slashes on prefixes are ignored (`/api` is equivalent to `/api/`).
    ///
    /// ```
    /// use praxis_core::config::{PathMatch, Route};
    /// use praxis_filter::RouterFilter;
    ///
    /// let router = RouterFilter::new(vec![
    ///     Route {
    ///         path_match: PathMatch::Prefix {
    ///             path_prefix: "/".to_owned(),
    ///         },
    ///         host: None,
    ///         headers: None,
    ///         cluster: "default".into(),
    ///     },
    ///     Route {
    ///         path_match: PathMatch::Prefix {
    ///             path_prefix: "/api".to_owned(),
    ///         },
    ///         host: None,
    ///         headers: None,
    ///         cluster: "api".into(),
    ///     },
    /// ])
    /// .unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if alias configuration is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn new(routes: Vec<Route>) -> Result<Self, FilterError> {
        Self::with_alias_options(
            routes.into_iter().map(RouterRouteConfig::from).collect(),
            DEFAULT_JSON_ALIAS_HEADER,
            DEFAULT_JSON_ALIAS_MAX_BODY_BYTES,
        )
    }

    /// Create a router with explicit alias options.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if route or alias configuration is invalid.
    fn with_alias_options(
        routes: Vec<RouterRouteConfig>,
        json_alias_header: &str,
        json_alias_max_body_bytes: usize,
    ) -> Result<Self, FilterError> {
        let mut routes = routes;
        sort_routes(&mut routes);
        validate_json_aliases(&routes)?;
        let json_alias_header = parse_json_alias_header(json_alias_header)?;
        validate_alias_options(&routes, json_alias_max_body_bytes)?;

        let has_json_alias_routes = routes.iter().any(|r| r.json_aliases.is_some());

        let resolved = resolve_routes(routes);
        debug!(
            routes = resolved.len(),
            has_aliases = has_json_alias_routes,
            "router initialized"
        );
        Ok(Self {
            has_json_alias_routes,
            json_alias_max_body_bytes,
            json_alias_header,
            multi_level_subdomain_matching: false,
            routes: resolved,
        })
    }

    /// Enable multi-level subdomain matching for wildcard hosts.
    ///
    /// By default, `*.example.com` matches only `foo.example.com`.
    /// When enabled, it also matches `foo.bar.example.com` (suffix
    /// match), as required by Gateway API.
    #[must_use]
    pub fn with_multi_level_subdomain_matching(mut self, enabled: bool) -> Self {
        self.multi_level_subdomain_matching = enabled;
        self
    }

    /// Create a router from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if route YAML is invalid or routes fail validation.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: RouterConfig = crate::parse_filter_config("router", config)?;
        let router = Self::with_alias_options(cfg.routes, &cfg.json_alias_header, cfg.json_alias_max_body_bytes)?
            .with_multi_level_subdomain_matching(cfg.multi_level_subdomain_matching);
        Ok(Box::new(router))
    }

    /// Find the best matching route for the given path, host, and headers.
    ///
    /// When multiple routes share the same prefix length, the route with
    /// more constraints (host presence + header count) wins.
    fn match_route(&self, path: &str, host: Option<&str>, req_headers: &HeaderMap) -> Option<&Route> {
        let mut best: Option<(matching::Specificity, &Route)> = None;

        for resolved in &self.routes {
            let route = &resolved.route;
            if !route_matches_request(resolved, path, host, req_headers, self.multi_level_subdomain_matching) {
                continue;
            }
            best = update_best_match(best, route);
            if should_stop_early(best, route) {
                break;
            }
        }

        best.map(|(_, r)| r)
    }
}

/// Sorts routes by specificity: exact paths first, then longest prefix.
fn sort_routes(routes: &mut [RouterRouteConfig]) {
    routes.sort_by(|a, b| {
        let a_len = match &a.route.path_match {
            PathMatch::Exact { path } => path.len(),
            PathMatch::Prefix { path_prefix } => crate::path_match::path_prefix_specificity(path_prefix),
        };
        let b_len = match &b.route.path_match {
            PathMatch::Exact { path } => path.len(),
            PathMatch::Prefix { path_prefix } => crate::path_match::path_prefix_specificity(path_prefix),
        };
        b_len.cmp(&a_len).then_with(|| {
            let a_exact = u8::from(a.route.path_match.is_exact());
            let b_exact = u8::from(b.route.path_match.is_exact());
            b_exact.cmp(&a_exact)
        })
    });
}

/// Validates JSON alias configuration on all routes.
fn validate_json_aliases(routes: &[RouterRouteConfig]) -> Result<(), FilterError> {
    for route_config in routes {
        let route = &route_config.route;
        let Some(aliases) = &route_config.json_aliases else {
            continue;
        };
        if aliases.is_empty() {
            return Err(format!(
                "router: json_aliases for cluster '{}' must not be empty (omit the key instead)",
                route.cluster,
            )
            .into());
        }
        for alias in aliases {
            validate_single_alias(alias, &route.cluster)?;
        }
    }
    Ok(())
}

/// Validates a single JSON alias field, pattern, and target.
fn validate_single_alias(alias: &JsonAlias, cluster: &str) -> Result<(), FilterError> {
    if alias.field.is_empty() {
        return Err(format!("router: json alias field for cluster '{cluster}' must not be empty").into());
    }
    if alias.pattern.is_empty() {
        return Err(format!("router: json alias match pattern for cluster '{cluster}' must not be empty").into());
    }
    if alias.pattern.chars().filter(|&c| c == '*').count() > 1 {
        return Err(format!(
            "router: json alias pattern '{}' for cluster '{cluster}' must contain at most one '*'",
            alias.pattern,
        )
        .into());
    }
    if alias.target.as_ref().is_some_and(String::is_empty) {
        return Err(format!(
            "router: json alias target for pattern '{}' in cluster '{cluster}' \
             must not be empty (omit the key to preserve the original value)",
            alias.pattern,
        )
        .into());
    }
    Ok(())
}

/// Parsed unconditionally so an invalid name fails at construction, not at
/// request time when alias validation may have been skipped (no alias routes).
fn parse_json_alias_header(json_alias_header: &str) -> Result<HeaderName, FilterError> {
    HeaderName::from_bytes(json_alias_header.as_bytes()).map_err(|e| {
        format!("router: json_alias_header '{json_alias_header}' is not a valid HTTP header name: {e}").into()
    })
}

/// Validates global alias options when alias routes exist.
fn validate_alias_options(routes: &[RouterRouteConfig], max_bytes: usize) -> Result<(), FilterError> {
    let has_aliases = routes.iter().any(|r| r.json_aliases.is_some());
    if !has_aliases {
        return Ok(());
    }
    if max_bytes == 0 {
        return Err("router: json_alias_max_body_bytes must be greater than 0".into());
    }
    if max_bytes > MAX_JSON_ALIAS_BODY_BYTES {
        return Err(format!(
            "router: json_alias_max_body_bytes must be <= {MAX_JSON_ALIAS_BODY_BYTES} bytes (got {max_bytes})",
        )
        .into());
    }
    Ok(())
}

/// Converts raw routes into resolved routes with pre-computed wildcard suffixes.
fn resolve_routes(routes: Vec<RouterRouteConfig>) -> Vec<ResolvedRoute> {
    routes
        .into_iter()
        .map(|route_config| {
            let route = route_config.route;
            let wildcard_suffix = route.host.as_ref().and_then(|h| h.strip_prefix("*.")).map(|suffix| {
                let lower = suffix.to_ascii_lowercase();
                format!(".{lower}")
            });
            ResolvedRoute {
                route,
                json_aliases: route_config.json_aliases,
                wildcard_suffix,
            }
        })
        .collect()
}

#[async_trait]
impl HttpFilter for RouterFilter {
    fn name(&self) -> &'static str {
        "router"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let path = ctx.rewritten_path.as_deref().unwrap_or_else(|| ctx.request.uri.path());
        let host = ctx
            .request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .or_else(|| ctx.request.uri.authority().map(http::uri::Authority::as_str));

        trace!(path = %path, host = host.unwrap_or(""), "matching route");
        if let Some(route) = self.match_route(path, host, &ctx.request.headers) {
            debug!(
                path = %path,
                cluster = %route.cluster,
                "route matched"
            );
            ctx.cluster = Some(Arc::clone(&route.cluster));
            Ok(FilterAction::Continue)
        } else {
            debug!(path = %path, "no route matched");
            Ok(FilterAction::Reject(Rejection::status(404)))
        }
    }
}
