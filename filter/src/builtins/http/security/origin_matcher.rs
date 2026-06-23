// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared origin matching for CORS and CSRF security filters.
//!
//! Supports exact origins and single-level wildcard subdomain
//! patterns (`https://*.example.com`). Origins are normalized
//! per [RFC 6454] before comparison.
//!
//! [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454

use std::collections::HashSet;

use super::origin_normalize::normalize_origin;

// ---------------------------------------------------------------------------
// OriginMatcher
// ---------------------------------------------------------------------------

/// Pre-computed origin matching policy.
///
/// Built at config parse time. Supports exact matches and
/// wildcard subdomain patterns (`https://*.example.com`).
pub(crate) enum OriginMatcher {
    /// Wildcard `*`: match any non-null origin.
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

impl OriginMatcher {
    /// Check whether `origin` is allowed/trusted by this policy.
    ///
    /// The incoming origin is normalized per [RFC 6454] before
    /// comparison so that case differences and default ports do
    /// not cause false negatives.
    ///
    /// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
    pub(crate) fn is_allowed(&self, origin: &str) -> bool {
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

    /// Check whether `Vary: Origin` is needed.
    ///
    /// Static wildcard (`*`) produces a fixed response, so no
    /// `Vary` is needed. All other policies vary by origin.
    pub(crate) fn needs_vary(&self) -> bool {
        !matches!(self, Self::Any)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build an [`OriginMatcher`] from a configured origins list.
///
/// Configured origins are normalized so that default ports
/// (`:443` for HTTPS, `:80` for HTTP) are stripped before
/// insertion, ensuring [RFC 6454] equivalence.
///
/// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
pub(crate) fn build_origin_matcher(origins: &[String]) -> OriginMatcher {
    if origins.len() == 1 && origins.first().is_some_and(|o| o == "*") {
        return OriginMatcher::Any;
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

    OriginMatcher::List {
        exact,
        wildcard_suffixes,
    }
}

// ---------------------------------------------------------------------------
// Wildcard Subdomain Matching
// ---------------------------------------------------------------------------

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
