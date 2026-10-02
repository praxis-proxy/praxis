// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Origin extraction logic for the CSRF filter.

use http::HeaderMap;

use super::super::origin_normalize::normalize_origin;

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
pub(super) fn extract_origin(headers: &HeaderMap) -> Option<std::borrow::Cow<'_, str>> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && origin != "null"
    {
        // Already-normalized origins (the browser common case) borrow
        // straight from the header instead of allocating.
        return Some(normalize_origin(origin));
    }

    headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_origin_from_url)
        .map(|o| match normalize_origin(&o) {
            // Already normalized: reuse the extracted String as-is.
            std::borrow::Cow::Borrowed(_) => std::borrow::Cow::Owned(o),
            std::borrow::Cow::Owned(normalized) => std::borrow::Cow::Owned(normalized),
        })
}

/// Parse `scheme://host[:port]` from a full URL.
///
/// The authority ends at the first `/`, `?`, or `#` (RFC 3986 §3.2), so a
/// path-less URL such as `https://example.com#frag` still yields a bare origin.
fn extract_origin_from_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host_port = rest.split(['/', '?', '#']).next()?;
    if host_port.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host_port}"))
}
