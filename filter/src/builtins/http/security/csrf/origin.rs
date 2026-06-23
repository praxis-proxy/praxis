// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Origin extraction and matching logic for the CSRF filter.

use http::HeaderMap;

use super::super::{
    origin_matcher::{OriginMatcher, build_origin_matcher},
    origin_normalize::normalize_origin,
};

// ---------------------------------------------------------------------------
// TrustedOrigins
// ---------------------------------------------------------------------------

/// CSRF-specific wrapper around [`OriginMatcher`].
///
/// Exposes `is_trusted()` for CSRF semantics while
/// delegating matching to the shared implementation.
///
/// [`OriginMatcher`]: super::super::origin_matcher::OriginMatcher
pub(super) struct TrustedOrigins(OriginMatcher);

impl TrustedOrigins {
    /// Check whether `origin` is trusted.
    pub(super) fn is_trusted(&self, origin: &str) -> bool {
        self.0.is_allowed(origin)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build the [`TrustedOrigins`] from the configured origins list.
///
/// Configured origins are normalized so that default ports
/// (`:443` for HTTPS, `:80` for HTTP) are stripped before
/// insertion, ensuring [RFC 6454] equivalence.
///
/// [RFC 6454]: https://datatracker.ietf.org/doc/html/rfc6454
pub(super) fn build_trusted_origins(origins: &[String]) -> TrustedOrigins {
    TrustedOrigins(build_origin_matcher(origins))
}

// ---------------------------------------------------------------------------
// Origin Extraction
// ---------------------------------------------------------------------------

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
