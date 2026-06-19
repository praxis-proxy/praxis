// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Origin extraction and matching logic for the CSRF filter.

use std::collections::HashSet;

use http::HeaderMap;

use super::super::origin_normalize::normalize_origin;

// -----------------------------------------------------------------------------
// TrustedOrigins
// -----------------------------------------------------------------------------

/// Pre-computed set of trusted origins for fast per-request matching.
///
/// Built at config parse time. Supports exact matches and
/// wildcard subdomain patterns (`https://*.example.com`).
///
/// # Example
///
/// ```ignore
/// let origins = build_trusted_origins(&[
///     "https://example.com".to_owned(),
///     "https://*.example.com".to_owned(),
/// ]);
///
/// assert!(origins.is_trusted("https://example.com"));
/// assert!(origins.is_trusted("https://app.example.com"));
/// assert!(!origins.is_trusted("https://evil.com"));
/// ```
pub(super) enum TrustedOrigins {
    /// `trusted_origins: ["*"]`: trust any origin.
    Any,

    /// Explicit list plus optional wildcard subdomains.
    List {
        /// Exact origin strings (e.g. `https://example.com`).
        exact: HashSet<String>,

        /// Wildcard subdomain suffixes stored as
        /// `(scheme, suffix)`. For `https://*.example.com`,
        /// stored as `("https", ".example.com")`.
        wildcard_suffixes: Vec<(String, String)>,
    },
}

impl TrustedOrigins {
    /// Check whether `origin` is trusted.
    ///
    /// The input is normalized before comparison so that
    /// default ports do not cause false negatives.
    pub(super) fn is_trusted(&self, origin: &str) -> bool {
        match self {
            Self::Any => true,
            Self::List {
                exact,
                wildcard_suffixes,
            } => {
                let normalized = normalize_origin(origin);
                exact.contains(normalized.as_str()) || match_wildcard_subdomain(&normalized, wildcard_suffixes)
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Build the [`TrustedOrigins`] from the configured origins list.
///
/// Configured origins are normalized so that default ports
/// (`:443` for HTTPS, `:80` for HTTP) are stripped before
/// insertion, ensuring [RFC 6454] equivalence.
///
/// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
pub(super) fn build_trusted_origins(origins: &[String]) -> TrustedOrigins {
    if origins.len() == 1 && origins.first().is_some_and(|o| o == "*") {
        return TrustedOrigins::Any;
    }

    let mut exact = HashSet::new();
    let mut wildcard_suffixes = Vec::new();

    for origin in origins {
        let normalized = normalize_origin(origin);
        if let Some((scheme, host)) = normalized.split_once("://")
            && host.starts_with("*.")
        {
            let suffix = host.get(1..).unwrap_or("").to_owned();
            wildcard_suffixes.push((scheme.to_owned(), suffix));
        } else {
            exact.insert(normalized);
        }
    }

    TrustedOrigins::List {
        exact,
        wildcard_suffixes,
    }
}

// -----------------------------------------------------------------------------
// Origin Extraction
// -----------------------------------------------------------------------------

/// Extract the origin from request headers.
///
/// Prefers the `Origin` header. Falls back to parsing
/// the `Referer` header's scheme+host+port. The result
/// is normalized to strip default ports ([RFC 6454]).
///
/// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
pub(super) fn extract_origin(headers: &HeaderMap) -> Option<String> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && origin != "null"
    {
        return Some(normalize_origin(origin));
    }

    headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_origin_from_url)
        .map(|o| normalize_origin(&o))
}

/// Parse `scheme://host[:port]` from a full URL.
fn extract_origin_from_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host_port = rest.split('/').next()?;
    if host_port.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host_port}"))
}

// -----------------------------------------------------------------------------
// Wildcard Subdomain Matching
// -----------------------------------------------------------------------------

/// Check if `origin` matches any wildcard subdomain entry.
///
/// Only single-level subdomains match: `https://app.example.com`
/// matches but `https://a.b.example.com` does not.
fn match_wildcard_subdomain(origin: &str, suffixes: &[(String, String)]) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };

    suffixes.iter().any(|(s, suffix)| {
        if scheme != s || !rest.ends_with(suffix.as_str()) || rest.len() <= suffix.len() {
            return false;
        }
        let subdomain = rest.get(..rest.len() - suffix.len()).unwrap_or_default();
        !subdomain.contains('.')
    })
}
