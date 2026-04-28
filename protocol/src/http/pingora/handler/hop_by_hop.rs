// SPDX-License-Identifier: MIT
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
/// the static hop-by-hop list (those are already removed by the caller).
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
            if !trimmed.is_empty() && !static_list.iter().any(|h| trimmed.eq_ignore_ascii_case(h)) {
                msg.remove_header_by_name(trimmed);
            }
        }
    }
}

/// Trait abstracting header removal for both request and response types.
pub(crate) trait RemoveHeader {
    /// Remove a header by name, discarding the value.
    fn remove_header_by_name(&mut self, name: &str);
}

impl RemoveHeader for pingora_http::RequestHeader {
    fn remove_header_by_name(&mut self, name: &str) {
        drop(self.remove_header(name));
    }
}

impl RemoveHeader for pingora_http::ResponseHeader {
    fn remove_header_by_name(&mut self, name: &str) {
        drop(self.remove_header(name));
    }
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
}
