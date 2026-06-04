// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Path, host, and header matching logic for the router filter.

use std::collections::HashMap;

use http::HeaderMap;
use praxis_core::config::{PathMatch, Route};

use super::ResolvedRoute;

// -----------------------------------------------------------------------------
// Route Matching
// -----------------------------------------------------------------------------

/// Check whether a resolved route matches the request path, host, and headers.
pub(super) fn route_matches_request(
    resolved: &ResolvedRoute,
    path: &str,
    host: Option<&str>,
    req_headers: &HeaderMap,
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
    host_ok && headers_match(&route.headers, req_headers)
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
        let host_suffix = &host[host.len() - suffix.len()..];
        if !host_suffix.eq_ignore_ascii_case(suffix) {
            return false;
        }
        let subdomain = &host[..host.len() - suffix.len()];
        !subdomain.is_empty() && (multi_level || !subdomain.contains('.'))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

// -----------------------------------------------------------------------------
// Header Matching
// -----------------------------------------------------------------------------

/// Returns `true` if the request headers satisfy all route header constraints.
fn headers_match(required: &Option<HashMap<String, String>>, actual: &HeaderMap) -> bool {
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
