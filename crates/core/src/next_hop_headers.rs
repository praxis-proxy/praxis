// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Hop-by-hop and reserved-header stripping for the next HTTP hop ([RFC 9110]).
//!
//! Shared by the protocol adapter and filtered sub-requests so Connection-token
//! handling, WebSocket preserve rules, and chunked framing restore cannot drift.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use http::HeaderMap;
use tracing::debug;

use crate::reserved_headers::{
    RESPONSE_HOP_BY_HOP_HEADERS, connection_tokens, is_connection_token_protected, is_reserved,
};

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/// Whether to preserve `Upgrade` and `Connection` for a clean WebSocket hop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradePreserve {
    /// Never preserve hop-by-hop upgrade headers.
    None,
    /// Preserve only when this is an upgrade request and headers show WebSocket.
    IfUpgradeRequest {
        /// Downstream request is an HTTP upgrade (e.g. WebSocket handshake).
        is_upgrade_request: bool,
    },
    /// Preserve only on a 101 response whose `Upgrade` is WebSocket.
    If101 {
        /// Upstream returned switching protocols.
        is_101: bool,
    },
}

/// Controls how [`strip_hop_by_hop`] removes connection-scoped headers.
#[derive(Clone, Copy, Debug)]
pub struct StripHopByHopOptions<'list> {
    /// Static hop-by-hop set ([`crate::reserved_headers::HOP_BY_HOP_HEADERS`] or
    /// [`crate::reserved_headers::RESPONSE_HOP_BY_HOP_HEADERS`]).
    pub static_headers: &'list [&'list str],
    /// WebSocket preserve policy for `upgrade` / `connection`.
    pub upgrade: UpgradePreserve,
    /// Re-insert `Transfer-Encoding: chunked` when the message declared chunked
    /// framing before strip and no `Content-Length` remains.
    pub restore_chunked_framing: bool,
    /// When `restore_chunked_framing` is set, skip restore on a WebSocket
    /// upgrade hop (upstream response 101 path).
    pub suppress_chunked_restore_on_websocket: bool,
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Mutable header surface for [`strip_hop_by_hop_target`].
///
/// Implemented for [`HeaderMap`] in this crate and for Pingora header types
/// in `praxis-protocol`.
pub trait HopByHopTarget {
    /// Current headers (read-only).
    fn headers(&self) -> &HeaderMap;

    /// Remove a header by name, ignoring the value.
    fn remove_by_name(&mut self, name: &str);

    /// Re-insert `Transfer-Encoding: chunked` after hop-by-hop strip.
    fn insert_transfer_encoding_chunked(&mut self);
}

impl HopByHopTarget for HeaderMap {
    fn headers(&self) -> &HeaderMap {
        self
    }

    fn remove_by_name(&mut self, name: &str) {
        self.remove(name);
    }

    fn insert_transfer_encoding_chunked(&mut self) {
        self.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
    }
}

/// Remove hop-by-hop headers using a Pingora-safe mutation surface.
///
/// Prefer this over [`strip_hop_by_hop`] when the target is not a plain
/// [`HeaderMap`] (for example Pingora request/response headers).
pub fn strip_hop_by_hop_target<T: HopByHopTarget>(target: &mut T, options: StripHopByHopOptions<'_>) {
    let is_ws = websocket_preserve_active(target.headers(), options.upgrade);
    let connection_values = snapshot_connection_values(target.headers());
    let was_chunked = if options.restore_chunked_framing {
        declares_chunked_framing(target.headers())
    } else {
        false
    };

    for name in options.static_headers {
        if preserve_for_upgrade(name, is_ws) {
            continue;
        }
        target.remove_by_name(name);
    }

    strip_connection_tokens_target(target, &connection_values, options.static_headers);

    if options.restore_chunked_framing {
        let allow_restore = !(options.suppress_chunked_restore_on_websocket && is_ws);
        if allow_restore && should_restore_chunked_framing(target.headers(), was_chunked) {
            target.insert_transfer_encoding_chunked();
        }
    }

    log_non_websocket_upgrade_strip(options.upgrade, is_ws);
}

/// Remove hop-by-hop headers and Connection-nominated fields from `headers`.
pub fn strip_hop_by_hop(headers: &mut HeaderMap, options: StripHopByHopOptions<'_>) {
    strip_hop_by_hop_target(headers, options);
}

/// Remove all reserved internal headers (`x-praxis-*`, `x-ext-protocol-*`,
/// `x-ext-agent-*`) using a Pingora-safe mutation surface.
///
/// Prefer this over [`strip_reserved`] when the target is not a plain
/// [`HeaderMap`] (for example Pingora request/response headers).
pub fn strip_reserved_target<T: HopByHopTarget>(target: &mut T) {
    let to_remove: Vec<http::HeaderName> = target
        .headers()
        .keys()
        .filter(|name| is_reserved(name.as_str()))
        .cloned()
        .collect();

    for name in &to_remove {
        target.remove_by_name(name.as_str());
    }

    if !to_remove.is_empty() {
        debug!(count = to_remove.len(), "stripped reserved internal headers");
    }
}

/// Remove all reserved internal headers (`x-praxis-*`, `x-ext-protocol-*`,
/// `x-ext-agent-*`) from a header map.
pub fn strip_reserved(headers: &mut HeaderMap) {
    strip_reserved_target(headers);
}

/// Whether a filter-supplied client response header must be withheld:
/// reserved internal names or response hop-by-hop names.
pub fn is_forbidden_client_response_header(name: &str) -> bool {
    is_reserved(name)
        || RESPONSE_HOP_BY_HOP_HEADERS
            .iter()
            .any(|hop| name.eq_ignore_ascii_case(hop))
}

// -----------------------------------------------------------------------------
// WebSocket upgrade detection
// -----------------------------------------------------------------------------

/// Whether the upgrade policy and headers call for WebSocket preserve.
fn websocket_preserve_active(headers: &HeaderMap, upgrade: UpgradePreserve) -> bool {
    match upgrade {
        UpgradePreserve::None => false,
        UpgradePreserve::IfUpgradeRequest { is_upgrade_request } => {
            is_upgrade_request && has_websocket_upgrade(headers)
        },
        UpgradePreserve::If101 { is_101 } => is_101 && has_websocket_upgrade(headers),
    }
}

/// Whether `Upgrade` and `Connection` should be preserved for WebSocket.
fn preserve_for_upgrade(name: &str, is_websocket_upgrade: bool) -> bool {
    is_websocket_upgrade && (name == "upgrade" || name == "connection")
}

/// Whether the `Upgrade` header value indicates a `WebSocket` upgrade.
fn is_websocket_upgrade(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("websocket")
}

/// Whether the map has exactly one `Upgrade` value that is WebSocket.
pub fn has_websocket_upgrade(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(http::header::UPGRADE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().is_ok_and(is_websocket_upgrade),
        _ => false,
    }
}

/// Log when non-WebSocket upgrade headers are stripped on an upgrade hop.
fn log_non_websocket_upgrade_strip(upgrade: UpgradePreserve, is_ws: bool) {
    let strip = match upgrade {
        UpgradePreserve::IfUpgradeRequest { is_upgrade_request } => is_upgrade_request && !is_ws,
        UpgradePreserve::If101 { is_101 } => is_101 && !is_ws,
        UpgradePreserve::None => false,
    };
    if strip {
        debug!("stripping non-WebSocket upgrade headers to prevent h2c smuggling");
    }
}

// -----------------------------------------------------------------------------
// Chunked framing
// -----------------------------------------------------------------------------

/// Whether headers declare chunked transfer framing (Pingora-compatible).
fn declares_chunked_framing(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .next_back()
        .and_then(|value| value.as_bytes().rsplit(|byte| *byte == b',').next())
        .is_some_and(|token| trim_ascii(token).eq_ignore_ascii_case(b"chunked"))
}

/// Trim ASCII whitespace from both ends of a byte slice.
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index.saturating_add(1));
    bytes.get(start..end).unwrap_or(&[])
}

/// Whether chunked framing should be re-inserted after hop-by-hop strip.
fn should_restore_chunked_framing(headers: &HeaderMap, was_chunked: bool) -> bool {
    was_chunked && !headers.contains_key(http::header::CONTENT_LENGTH)
}

// -----------------------------------------------------------------------------
// Connection tokens
// -----------------------------------------------------------------------------

/// Snapshot `Connection` header values before they are removed.
fn snapshot_connection_values(headers: &HeaderMap) -> Vec<http::HeaderValue> {
    headers.get_all("connection").iter().cloned().collect()
}

/// Remove headers nominated by `Connection` tokens on `target`.
fn strip_connection_tokens_target<T: HopByHopTarget>(
    target: &mut T,
    values: &[http::HeaderValue],
    static_list: &[&str],
) {
    for val in values {
        for trimmed in connection_tokens(val) {
            if static_list
                .iter()
                .any(|static_name| trimmed.eq_ignore_ascii_case(static_name))
            {
                continue;
            }
            if is_connection_token_protected(trimmed) {
                debug!(
                    header = trimmed,
                    "refusing to strip proxy-owned or essential header named in Connection token"
                );
                continue;
            }
            target.remove_by_name(trimmed);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::reserved_headers::HOP_BY_HOP_HEADERS;

    fn terminal_options(static_headers: &'static [&'static str]) -> StripHopByHopOptions<'static> {
        StripHopByHopOptions {
            static_headers,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        }
    }

    fn request_hop_strip_options() -> StripHopByHopOptions<'static> {
        StripHopByHopOptions {
            static_headers: HOP_BY_HOP_HEADERS,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        }
    }

    fn headers_with_mixed_connection_tokens() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static(
                "x-app-state, x-forwarded-for, forwarded, x-praxis-route, host, content-length",
            ),
        );
        headers.insert("x-app-state", http::HeaderValue::from_static("gone"));
        headers.insert("x-forwarded-for", http::HeaderValue::from_static("client"));
        headers.insert("forwarded", http::HeaderValue::from_static("for=1.2.3.4"));
        headers.insert("x-praxis-route", http::HeaderValue::from_static("internal"));
        headers.insert(http::header::HOST, http::HeaderValue::from_static("example.com"));
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        headers
    }

    fn assert_connection_protected_headers(headers: &HeaderMap) {
        for protected in [
            "x-forwarded-for",
            "forwarded",
            "x-praxis-route",
            "host",
            "content-length",
        ] {
            assert!(
                headers.contains_key(protected),
                "{protected} must not be strippable via a Connection token"
            );
        }
    }

    #[test]
    fn strip_reserved_removes_reserved_keeps_others() {
        let mut headers = HeaderMap::new();
        headers.insert("x-praxis-route", http::HeaderValue::from_static("internal-cluster"));
        headers.insert("x-ext-protocol-foo", http::HeaderValue::from_static("meta"));
        headers.insert("content-type", http::HeaderValue::from_static("text/plain"));

        strip_reserved(&mut headers);

        assert!(!headers.contains_key("x-praxis-route"));
        assert!(!headers.contains_key("x-ext-protocol-foo"));
        assert_eq!(
            headers.get("content-type").map(http::HeaderValue::as_bytes),
            Some(b"text/plain".as_slice())
        );
    }

    #[test]
    fn strip_reserved_cleans_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-praxis-foo", http::HeaderValue::from_static("leak"));
        trailers.insert("x-ext-agent-x", http::HeaderValue::from_static("leak"));
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));

        strip_reserved(&mut trailers);

        assert_eq!(trailers.len(), 1);
        assert_eq!(
            trailers.get("grpc-status").map(http::HeaderValue::as_bytes),
            Some(b"0".as_slice())
        );
    }

    #[test]
    fn forbidden_client_response_header_names() {
        assert!(is_forbidden_client_response_header("x-praxis-x"));
        assert!(is_forbidden_client_response_header("Connection"));
        assert!(!is_forbidden_client_response_header("x-custom"));
    }

    #[test]
    fn declares_chunked_framing_matches_plain_and_compound() {
        let mut plain = HeaderMap::new();
        plain.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        assert!(declares_chunked_framing(&plain));

        let mut compound = HeaderMap::new();
        compound.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("gzip, chunked"),
        );
        assert!(declares_chunked_framing(&compound));
    }

    #[test]
    fn declares_chunked_framing_rejects_non_chunked() {
        let mut gzip = HeaderMap::new();
        gzip.insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("gzip"));
        assert!(!declares_chunked_framing(&gzip));
        assert!(!declares_chunked_framing(&HeaderMap::new()));
    }

    #[test]
    fn declares_chunked_framing_handles_obs_text_bytes() {
        let mut obs = HeaderMap::new();
        obs.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_bytes(b"\xa0x, chunked").unwrap(),
        );
        assert!(declares_chunked_framing(&obs));
    }

    #[test]
    fn websocket_lowercase_is_upgrade() {
        assert!(is_websocket_upgrade("websocket"));
    }

    #[test]
    fn websocket_uppercase_is_upgrade() {
        assert!(is_websocket_upgrade("WEBSOCKET"));
    }

    #[test]
    fn h2c_is_not_websocket_upgrade() {
        assert!(!is_websocket_upgrade("h2c"));
    }

    #[test]
    fn has_websocket_upgrade_duplicate_headers_rejected() {
        let mut headers = HeaderMap::new();
        headers.append("upgrade", "websocket".parse().unwrap());
        headers.append("upgrade", "h2c".parse().unwrap());
        assert!(!has_websocket_upgrade(&headers));
    }

    #[test]
    fn strip_removes_custom_but_keeps_protected_connection_tokens() {
        let mut headers = headers_with_mixed_connection_tokens();
        strip_hop_by_hop(&mut headers, request_hop_strip_options());
        assert!(!headers.contains_key("x-app-state"));
        assert_connection_protected_headers(&headers);
    }

    #[test]
    fn connection_token_survives_obs_text_sibling() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_bytes(b"x-backend-internal, \x80").unwrap(),
        );
        headers.insert("x-backend-internal", http::HeaderValue::from_static("secret"));
        strip_hop_by_hop(&mut headers, terminal_options(RESPONSE_HOP_BY_HOP_HEADERS));
        assert!(!headers.contains_key("x-backend-internal"));
    }

    #[test]
    fn upstream_response_restores_chunked_framing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        headers.insert("x-real-header", http::HeaderValue::from_static("keep"));
        strip_hop_by_hop(
            &mut headers,
            StripHopByHopOptions {
                static_headers: RESPONSE_HOP_BY_HOP_HEADERS,
                upgrade: UpgradePreserve::None,
                restore_chunked_framing: true,
                suppress_chunked_restore_on_websocket: true,
            },
        );
        assert_eq!(headers.get(http::header::TRANSFER_ENCODING).unwrap(), "chunked");
    }
}
