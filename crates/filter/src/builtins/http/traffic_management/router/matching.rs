// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Path, host, and header matching logic for the router filter.

use std::collections::HashMap;

use http::{HeaderMap, header::HeaderName};
use praxis_core::config::{PathMatch, Route};

use super::ResolvedRoute;
use crate::{FilterError, HttpFilterContext, context::PendingHeaderResult};

// -----------------------------------------------------------------------------
// Route Header Sources
// -----------------------------------------------------------------------------

/// Where route `headers` predicates read request header values from.
pub(super) trait RouteHeaderSource {
    /// Whether any effective value of `name` equals `expected`.
    fn has_value(&self, name: &str, expected: &str) -> bool;
}

impl RouteHeaderSource for HeaderMap {
    fn has_value(&self, name: &str, expected: &str) -> bool {
        self.get_all(name)
            .iter()
            .any(|v| v.to_str().ok().is_some_and(|v| v == expected))
    }
}

/// The request headers as received, overlaid with what earlier filters in
/// the same phase set, added, or removed on the names routes match on.
///
/// Those mutations sit in the context's pending queues until the protocol
/// layer applies them after the pipeline, so reading the request alone would
/// route on the client's value rather than the one the upstream receives.
pub(super) struct PendingRouteHeaders<'req> {
    /// Pending state of each routed header name an earlier filter touched.
    pending: Vec<(&'req HeaderName, PendingHeaderResult)>,

    /// The request headers as received.
    request: &'req HeaderMap,
}

impl<'req> PendingRouteHeaders<'req> {
    /// Resolve each routed header name in `names` against the pending header
    /// mutations in `ctx`.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] when a routed header has more than one distinct
    /// pending value (or a non-text one): picking one would route on a guess.
    ///
    /// [`FilterError`]: crate::FilterError
    pub(super) fn resolve(names: &'req [HeaderName], ctx: &'req HttpFilterContext<'_>) -> Result<Self, FilterError> {
        let mut pending = Vec::new();
        for name in names {
            let state = ctx
                .pending_header_value(name)
                .map_err(|e| -> FilterError { format!("router: {e}").into() })?;
            if state != PendingHeaderResult::Absent {
                pending.push((name, state));
            }
        }
        Ok(Self {
            pending,
            request: &ctx.request.headers,
        })
    }
}

impl RouteHeaderSource for PendingRouteHeaders<'_> {
    fn has_value(&self, name: &str, expected: &str) -> bool {
        let pending = self
            .pending
            .iter()
            .find(|(pending_name, _)| pending_name.as_str().eq_ignore_ascii_case(name));
        match pending.map(|(_, state)| state) {
            Some(PendingHeaderResult::Value(value)) => value == expected,
            Some(PendingHeaderResult::Removed) => false,
            Some(PendingHeaderResult::Absent) | None => self.request.has_value(name, expected),
        }
    }
}

// -----------------------------------------------------------------------------
// Route Matching
// -----------------------------------------------------------------------------

/// Check whether a resolved route matches the request path, host, and headers.
pub(super) fn route_matches_request<S: RouteHeaderSource>(
    resolved: &ResolvedRoute,
    path: &str,
    host: Option<&str>,
    req_headers: &S,
    multi_level_subdomain: bool,
) -> bool {
    let route = &resolved.route;
    match &route.path_match {
        PathMatch::Exact { path: exact } => {
            if path != exact {
                return false;
            }
        },
        PathMatch::Prefix { path_prefix } => {
            if !crate::path_match::path_prefix_matches(path, path_prefix) {
                return false;
            }
        },
    }
    let host_ok = match &route.host {
        Some(h) => host.is_some_and(|req_host| {
            let req_host = strip_port(req_host);
            host_matches(h, resolved.wildcard_suffix.as_deref(), req_host, multi_level_subdomain)
        }),
        None => true,
    };
    host_ok && headers_match(route.headers.as_ref(), req_headers)
}

/// Update the best match if the current route has more constraints.
/// Match specificity: `(is_exact, path_len, constraint_count)`.
pub(super) type Specificity = (bool, usize, usize);

/// Computes the specificity of a route for comparison.
fn route_specificity(route: &Route) -> Specificity {
    let is_exact = route.path_match.is_exact();
    let path_len = match &route.path_match {
        PathMatch::Exact { path } => path.len(),
        PathMatch::Prefix { path_prefix } => crate::path_match::path_prefix_specificity(path_prefix),
    };
    let constraints = usize::from(route.host.is_some()) + route.headers.as_ref().map_or(0, HashMap::len);
    (is_exact, path_len, constraints)
}

/// Update the best match if the current route has higher specificity.
///
/// Exact matches dominate prefix matches. Among the same type, longer
/// paths win. Among equal-length paths, more constraints win.
pub(super) fn update_best_match<'a>(
    best: Option<(Specificity, &'a Route)>,
    route: &'a Route,
) -> Option<(Specificity, &'a Route)> {
    let spec = route_specificity(route);
    let dominated = best.is_some_and(|(bs, _)| spec <= bs);
    if dominated { best } else { Some((spec, route)) }
}

/// Return `true` if shorter prefixes cannot improve on the current best.
pub(super) fn should_stop_early(best: Option<(Specificity, &Route)>, route: &Route) -> bool {
    let route_len = match &route.path_match {
        PathMatch::Exact { path } => path.len(),
        PathMatch::Prefix { path_prefix } => crate::path_match::path_prefix_specificity(path_prefix),
    };
    best.is_some_and(|((_, bp, _), _)| route_len < bp)
}

// -----------------------------------------------------------------------------
// Wildcard Host Matching
// -----------------------------------------------------------------------------

/// Check whether a request host matches a route host pattern.
///
/// When `wildcard_suffix` is `Some`, the pattern is a wildcard
/// (e.g. `*.example.com`) and `wildcard_suffix` holds the
/// pre-lowercased suffix (`.example.com`). `None` for exact hosts
/// or routes without a host constraint.
///
/// By default, wildcards match single-level subdomains only
/// (`*.example.com` matches `foo.example.com` but not
/// `foo.bar.example.com`). When `multi_level` is `true`, wildcards
/// use suffix matching at any depth.
fn host_matches(pattern: &str, wildcard_suffix: Option<&str>, host: &str, multi_level: bool) -> bool {
    if let Some(suffix) = wildcard_suffix {
        if host.len() <= suffix.len() {
            return false;
        }
        let host_suffix = host.get(host.len() - suffix.len()..).unwrap_or_default();
        if !host_suffix.eq_ignore_ascii_case(suffix) {
            return false;
        }
        let subdomain = host.get(..host.len() - suffix.len()).unwrap_or_default();
        !subdomain.is_empty() && (multi_level || !subdomain.contains('.'))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

// -----------------------------------------------------------------------------
// Header Matching
// -----------------------------------------------------------------------------

/// Returns `true` if the request headers satisfy all route header constraints.
fn headers_match<S: RouteHeaderSource>(required: Option<&HashMap<String, String>>, actual: &S) -> bool {
    let Some(required) = required else {
        return true;
    };
    required.iter().all(|(key, val)| actual.has_value(key, val))
}

use crate::builtins::http::traffic_management::strip_port;
