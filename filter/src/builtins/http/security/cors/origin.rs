// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Origin matching logic and wildcard subdomain support for the CORS filter.

use std::collections::HashSet;

use super::super::origin_normalize::normalize_origin;

// -----------------------------------------------------------------------------
// OriginPolicy
// -----------------------------------------------------------------------------

/// Pre-computed origin matching policy.
///
/// Built at config parse time for per-request matching.
///
/// # Example
///
/// ```ignore
/// # // OriginPolicy is private, but we test via CorsFilter.
/// use praxis_filter::CorsFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// allow_origins: ["*"]
/// "#,
/// )
/// .unwrap();
/// let filter = CorsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "cors");
/// ```
pub(super) enum OriginPolicy {
    /// `allow_origins: ["*"]`: reflect any non-null origin.
    Any,

    /// Explicit list plus optional wildcard subdomains.
    List {
        /// Exact origin strings (e.g. `https://example.com`).
        exact: HashSet<String>,

        /// Wildcard subdomain suffixes (e.g. `.example.com` from
        /// `https://*.example.com`), stored as `(scheme, suffix)`.
        wildcard_suffixes: Vec<(String, String)>,
    },
}

impl OriginPolicy {
    /// Check whether the response `Vary: Origin` header is needed.
    ///
    /// Static wildcard (`*`) without credentials produces a fixed
    /// `Access-Control-Allow-Origin: *` so no `Vary` is needed.
    pub(super) fn needs_vary(&self) -> bool {
        !matches!(self, Self::Any)
    }

    /// Check whether `origin` is allowed by this policy.
    ///
    /// The incoming origin is normalized per [RFC 6454] before
    /// comparison so that case differences and default ports
    /// do not cause false negatives.
    ///
    /// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
    pub(super) fn is_allowed(&self, origin: &str) -> bool {
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
// Origin Policy Builder
// -----------------------------------------------------------------------------

/// Build the [`OriginPolicy`] from the configured origins list.
pub(super) fn build_origin_policy(origins: &[String]) -> OriginPolicy {
    if origins.len() == 1 && origins.first().is_some_and(|o| o == "*") {
        return OriginPolicy::Any;
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

    OriginPolicy::List {
        exact,
        wildcard_suffixes,
    }
}

// -----------------------------------------------------------------------------
// Wildcard Subdomain Matching
// -----------------------------------------------------------------------------

/// Check if `origin` matches any wildcard subdomain entry.
///
/// Each entry is `(scheme, suffix)` where suffix is e.g.
/// `.example.com`. Only single-level subdomains match:
/// `https://app.example.com` matches but
/// `https://a.b.example.com` does not.
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
