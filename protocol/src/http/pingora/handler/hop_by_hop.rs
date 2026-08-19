// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared hop-by-hop header stripping logic ([RFC 9110]).
//!
//! Both request and response paths need to remove hop-by-hop headers
//! before forwarding. This module provides the common implementation;
//! callers supply the static header list appropriate for their direction.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use http::HeaderMap;
use tracing::debug;

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

/// Whether `Upgrade` and `Connection` should be preserved.
///
/// Returns `true` when a header name is `upgrade` or `connection`
/// and the request is a `WebSocket` upgrade. Only `WebSocket` upgrades
/// are preserved; other upgrade types (notably `h2c`) are stripped
/// to prevent h2c smuggling attacks that bypass proxy access
/// controls.
pub(crate) fn preserve_for_upgrade(name: &str, is_websocket_upgrade: bool) -> bool {
    is_websocket_upgrade && (name == "upgrade" || name == "connection")
}

/// Whether the `Upgrade` header value indicates a `WebSocket` upgrade.
///
/// Returns `true` only when the value is exactly `websocket`
/// (case-insensitive per [RFC 6455 Section 4.1]). Mixed values
/// like `h2c, websocket` are rejected because they could allow
/// the upstream to negotiate a non-WebSocket protocol.
///
/// [RFC 6455 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
pub(crate) fn is_websocket_upgrade(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("websocket")
}

/// Snapshot `Connection` header values before they are removed.
///
/// Call this before stripping hop-by-hop headers, then pass the
/// result to [`strip_connection_tokens`].
///
/// [RFC 9110 Section 7.6.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1
pub(crate) fn snapshot_connection_values(headers: &HeaderMap) -> Vec<http::HeaderValue> {
    headers.get_all("connection").iter().cloned().collect()
}

/// Remove headers declared in `Connection` tokens that are not in
/// the static hop-by-hop list (those are already removed by the caller)
/// and are not proxy-owned headers (see [`is_proxy_owned`]).
///
/// [RFC 9110 Section 7.6.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-7.6.1
pub(crate) fn strip_connection_tokens<R: RemoveHeader>(
    msg: &mut R,
    values: &[http::HeaderValue],
    static_list: &[&str],
) {
    for val in values {
        let Ok(s) = val.to_str() else { continue };
        for token in s.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() || static_list.iter().any(|h| trimmed.eq_ignore_ascii_case(h)) {
                continue;
            }
            if is_proxy_owned(trimmed) {
                debug!(
                    header = trimmed,
                    "refusing to strip proxy-owned header named in Connection token"
                );
                continue;
            }
            msg.remove_header_by_name(trimmed);
        }
    }
}

/// Strip static hop-by-hop headers and headers nominated by `Connection`
/// from a standalone [`HeaderMap`].
///
/// Terminal responses are created outside Pingora's normal upstream response
/// path, so they use this helper before downstream commitment.
pub(crate) fn strip_hop_by_hop_header_map(headers: &mut HeaderMap, static_list: &[&str]) {
    let connection_values = snapshot_connection_values(headers);
    for name in static_list {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            if !static_list.iter().any(|name| token.eq_ignore_ascii_case(name)) {
                headers.remove(token);
            }
        }
    }
}

/// Trait abstracting header removal for both request and response types.
pub(crate) trait RemoveHeader {
    /// direction i.e. request or response
    const DIRECTION: &'static str;

    /// Return all headers
    fn headers(&self) -> &HeaderMap;
    /// Remove a header by name, discarding the value.
    fn remove_header_by_name(&mut self, name: &str);

    /// Strip reserved internal headers before forwarding to upstream.
    /// Remove proxy-internal routing metadata that should not leak to
    /// backends and that may echo back from backends.
    fn strip_reserved_internal(&mut self) {
        let to_remove: Vec<http::HeaderName> = self
            .headers()
            .keys()
            .filter(|name| super::reserved_headers::is_reserved_internal_header(name))
            .cloned()
            .collect();

        for name in &to_remove {
            self.remove_header_by_name(name.as_str());
        }

        if !to_remove.is_empty() {
            debug!(
                count = to_remove.len(),
                direction = Self::DIRECTION,
                "stripped reserved internal headers"
            );
        }
    }
}

impl RemoveHeader for pingora_http::RequestHeader {
    const DIRECTION: &'static str = "request";

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn remove_header_by_name(&mut self, name: &str) {
        drop(self.remove_header(name));
    }
}

impl RemoveHeader for pingora_http::ResponseHeader {
    const DIRECTION: &'static str = "response";

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn remove_header_by_name(&mut self, name: &str) {
        drop(self.remove_header(name));
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Whether a header name is owned by Praxis and must never be removed
/// on the say-so of a client `Connection` token.
///
/// Covers the `x-forwarded-*` family (injected by the forwarded-headers
/// filter) and the reserved internal namespaces. Without this, a client
/// sending `Connection: x-forwarded-for` would make Praxis delete its
/// own trust header before forwarding upstream — erasing the client
/// address any upstream relies on for rate limiting, audit logging, or
/// IP allow-listing.
fn is_proxy_owned(name: &str) -> bool {
    name.get(..12).is_some_and(|p| p.eq_ignore_ascii_case("x-forwarded-"))
        || praxis_core::reserved_headers::is_reserved(&name.to_ascii_lowercase())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_lowercase_is_upgrade() {
        assert!(
            is_websocket_upgrade("websocket"),
            "lowercase 'websocket' should be recognized"
        );
    }

    #[test]
    fn websocket_uppercase_is_upgrade() {
        assert!(
            is_websocket_upgrade("WEBSOCKET"),
            "uppercase 'WEBSOCKET' should be recognized"
        );
    }

    #[test]
    fn websocket_mixed_case_is_upgrade() {
        assert!(
            is_websocket_upgrade("WebSocket"),
            "mixed-case 'WebSocket' should be recognized per RFC 6455"
        );
    }

    #[test]
    fn websocket_with_whitespace_is_upgrade() {
        assert!(
            is_websocket_upgrade("  websocket  "),
            "whitespace-padded 'websocket' should be recognized"
        );
    }

    #[test]
    fn h2c_is_not_websocket_upgrade() {
        assert!(
            !is_websocket_upgrade("h2c"),
            "h2c upgrade must be rejected to prevent smuggling"
        );
    }

    #[test]
    fn mixed_h2c_websocket_is_not_upgrade() {
        assert!(
            !is_websocket_upgrade("h2c, websocket"),
            "mixed upgrade values must be rejected"
        );
    }

    #[test]
    fn empty_value_is_not_upgrade() {
        assert!(
            !is_websocket_upgrade(""),
            "empty upgrade value should not be recognized"
        );
    }

    #[test]
    fn arbitrary_protocol_is_not_upgrade() {
        assert!(
            !is_websocket_upgrade("SMTP"),
            "arbitrary protocol should not be recognized"
        );
    }

    #[test]
    fn proxy_owned_headers_are_recognized() {
        assert!(is_proxy_owned("x-forwarded-for"), "x-forwarded-* is proxy-owned");
        assert!(is_proxy_owned("X-Forwarded-Proto"), "matching is case-insensitive");
        assert!(is_proxy_owned("x-praxis-route"), "reserved x-praxis-* is proxy-owned");
        assert!(
            !is_proxy_owned("x-request-id"),
            "ordinary x-* headers are not proxy-owned"
        );
        assert!(!is_proxy_owned("cache-control"), "standard headers are not proxy-owned");
    }

    #[test]
    fn strip_removes_custom_but_keeps_proxy_owned() {
        let mut rec = Recorder {
            removed: vec![],
            headers: HeaderMap::new(),
        };
        // A client asks to strip its own X-App-State and Praxis's X-Forwarded-For.
        let values = vec![http::HeaderValue::from_static(
            "x-app-state, x-forwarded-for, x-praxis-route",
        )];
        strip_connection_tokens(&mut rec, &values, REQUEST_HOP_BY_HOP);
        assert!(
            rec.removed.contains(&"x-app-state".to_owned()),
            "custom header should be stripped"
        );
        assert!(
            !rec.removed.iter().any(|h| h == "x-forwarded-for"),
            "x-forwarded-for must not be strippable via a Connection token"
        );
        assert!(
            !rec.removed.iter().any(|h| h == "x-praxis-route"),
            "reserved x-praxis-* must not be strippable via a Connection token"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal [`RemoveHeader`] double recording removals.
    struct Recorder {
        removed: Vec<String>,
        headers: HeaderMap,
    }

    impl RemoveHeader for Recorder {
        const DIRECTION: &'static str = "request";

        fn headers(&self) -> &HeaderMap {
            &self.headers
        }

        fn remove_header_by_name(&mut self, name: &str) {
            self.removed.push(name.to_ascii_lowercase());
        }
    }
}
