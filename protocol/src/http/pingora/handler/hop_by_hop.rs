// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Shared hop-by-hop header stripping logic ([RFC 9110]).
//!
//! Both request and response paths need to remove hop-by-hop headers
//! before forwarding. This module provides the common implementation;
//! callers supply the static header list appropriate for their direction.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use http::HeaderMap;

// -----------------------------------------------------------------------------
// Hop-by-hop Header Lists
// -----------------------------------------------------------------------------

/// [RFC 9110] hop-by-hop headers for upstream requests.
///
/// Includes `proxy-authorization` (request-only credential header).
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
pub(crate) const REQUEST_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// [RFC 9110] hop-by-hop headers for upstream responses.
///
/// Omits `proxy-authorization` (request-only header).
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
pub(crate) const RESPONSE_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

// -----------------------------------------------------------------------------
// Strip Logic
// -----------------------------------------------------------------------------

/// Collect extra header names declared in `Connection` values.
///
/// Parses comma-separated tokens from the `Connection` header and
/// returns any that are not already in the static list.
pub(crate) fn connection_tokens(headers: &HeaderMap, static_list: &[&str]) -> Vec<String> {
    let mut extra = Vec::new();
    for val in headers.get_all("connection") {
        let Ok(s) = val.to_str() else { continue };
        for token in s.split(',') {
            let trimmed = token.trim();
            if !trimmed.is_empty() && !static_list.iter().any(|h| trimmed.eq_ignore_ascii_case(h)) {
                extra.push(trimmed.to_owned());
            }
        }
    }
    extra
}
