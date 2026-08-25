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

/// Whether a message's headers declare chunked transfer framing.
///
/// Mirrors Pingora's framing detection (`is_chunked_encoding_from_headers`):
/// the last `Transfer-Encoding` header value's last comma-separated token
/// must be `chunked` ([RFC 9112 Section 6.1]).
///
/// [RFC 9112 Section 6.1]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1
pub(crate) fn declares_chunked_framing(headers: &HeaderMap) -> bool {
    // Operate on raw bytes, not to_str(): Pingora's detection accepts
    // obs-text (0x80-0xFF) header bytes, and a value it frames as chunked
    // must not read as non-chunked here, or the body would be dropped.
    headers
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .next_back()
        .and_then(|value| value.as_bytes().rsplit(|&b| b == b',').next())
        .is_some_and(|token| trim_ascii(token).eq_ignore_ascii_case(b"chunked"))
}

/// Trim ASCII whitespace from both ends of a byte slice.
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    bytes.get(start..end).unwrap_or(&[])
}

/// Whether chunked framing must be re-established after hop-by-hop stripping.
///
/// `Transfer-Encoding` is nominally hop-by-hop, but it is also the header
/// Pingora's body writers key on to frame the next hop's body
/// (`init_body_writer_comm`: chunked beats `Content-Length`; with neither,
/// requests are framed as zero-length and responses fall back to
/// close-delimited). Stripping it without re-framing silently drops chunked
/// request bodies and breaks response keep-alive, so callers re-insert a
/// normalized `chunked` value whenever the original message declared chunked
/// framing and no `Content-Length` replaced it. The next hop's writer
/// re-frames the already-dechunked stream; H2 legs remove the header again
/// before sending.
pub(crate) fn should_restore_chunked_framing(headers: &HeaderMap, was_chunked: bool) -> bool {
    was_chunked && !headers.contains_key(http::header::CONTENT_LENGTH)
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

/// Whether a header map's `Upgrade` header indicates a `WebSocket` upgrade.
///
/// Returns `true` only when there is exactly one `Upgrade` header whose
/// value is exactly `websocket` (via [`is_websocket_upgrade`]). Zero
/// headers, or two or more `Upgrade` headers, yield `false` so the strip
/// path removes them.
///
/// Reading only the first value (e.g. via [`HeaderMap::get`]) would let a
/// client smuggle a second protocol past the WebSocket check: a request
/// carrying `Upgrade: websocket` followed by `Upgrade: h2c` would be seen
/// as a clean WebSocket upgrade, and [`preserve_for_upgrade`] would then
/// forward the entire (multi-valued) `Upgrade` header — including the
/// `h2c` token — to the backend, defeating the h2c-smuggling protection.
pub(crate) fn has_websocket_upgrade(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(http::header::UPGRADE).iter();
    match (values.next(), values.next()) {
        // Exactly one Upgrade header; value must be exactly `websocket`.
        (Some(value), None) => value.to_str().is_ok_and(is_websocket_upgrade),
        // Zero, or two or more Upgrade headers: not a clean WebSocket
        // upgrade, so let the caller strip every Upgrade value.
        _ => false,
    }
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
            if is_essential(trimmed) {
                debug!(
                    header = trimmed,
                    "refusing to strip essential header named in Connection token"
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
            if !static_list.iter().any(|name| token.eq_ignore_ascii_case(name))
                && !is_proxy_owned(token)
                && !is_essential(token)
            {
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
/// Covers the `x-forwarded-*` family and the RFC 7239 `Forwarded`
/// header (both injected by the forwarded-headers filter) plus the
/// reserved internal namespaces. Without this, a client sending
/// `Connection: x-forwarded-for` or `Connection: forwarded` would make
/// Praxis delete its own trust header before forwarding upstream —
/// erasing the client address any upstream relies on for rate limiting,
/// audit logging, or IP allow-listing.
fn is_proxy_owned(name: &str) -> bool {
    name.get(..12).is_some_and(|p| p.eq_ignore_ascii_case("x-forwarded-"))
        || name.eq_ignore_ascii_case("forwarded")
        || praxis_core::reserved_headers::is_reserved(&name.to_ascii_lowercase())
}

/// Whether a header is essential to message routing or framing and must
/// never be removed on the say-so of a `Connection` token.
///
/// A client sending `Connection: host` would otherwise make Praxis forward
/// an HTTP/1.1 request with no `Host` header (malformed per [RFC 9112], and
/// a vhost-selection bypass at the backend); `Connection: content-length`
/// would erase the framing header, making Pingora forward a zero-length
/// body. Mainstream proxies ignore Connection tokens naming these headers.
///
/// [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
fn is_essential(name: &str) -> bool {
    name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

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
        // A value with an obs-text byte in an earlier token must still be
        // detected as chunked, matching Pingora's byte-level framing.
        let mut obs = HeaderMap::new();
        obs.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_bytes(b"\xa0x, chunked").unwrap(),
        );
        assert!(
            declares_chunked_framing(&obs),
            "obs-text in an earlier token must not hide the trailing chunked token"
        );
    }

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
    fn has_websocket_upgrade_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        assert!(
            has_websocket_upgrade(&headers),
            "should detect mixed-case WebSocket in header map"
        );
    }

    #[test]
    fn has_websocket_upgrade_missing_header() {
        let headers = HeaderMap::new();
        assert!(
            !has_websocket_upgrade(&headers),
            "should return false when upgrade header is missing"
        );
    }

    #[test]
    fn has_websocket_upgrade_non_websocket() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "h2c".parse().unwrap());
        assert!(
            !has_websocket_upgrade(&headers),
            "should return false for non-websocket upgrade"
        );
    }

    #[test]
    fn duplicate_upgrade_headers_are_not_websocket() {
        // A client sending `Upgrade: websocket` followed by `Upgrade: h2c`
        // must not be treated as a clean WebSocket upgrade: reading only the
        // first value would preserve the whole (multi-valued) Upgrade header
        // and smuggle the h2c token to the backend.
        let mut headers = HeaderMap::new();
        headers.append("upgrade", "websocket".parse().unwrap());
        headers.append("upgrade", "h2c".parse().unwrap());
        assert!(
            !has_websocket_upgrade(&headers),
            "duplicate Upgrade headers must not be recognized as a WebSocket upgrade (h2c smuggling)"
        );
    }

    #[test]
    fn duplicate_upgrade_headers_websocket_first_or_last() {
        // Order must not matter: h2c before or after websocket both fail.
        let mut headers = HeaderMap::new();
        headers.append("upgrade", "h2c".parse().unwrap());
        headers.append("upgrade", "websocket".parse().unwrap());
        assert!(
            !has_websocket_upgrade(&headers),
            "duplicate Upgrade headers must not be recognized regardless of order"
        );
    }

    #[test]
    fn proxy_owned_headers_are_recognized() {
        assert!(is_proxy_owned("x-forwarded-for"), "x-forwarded-* is proxy-owned");
        assert!(is_proxy_owned("X-Forwarded-Proto"), "matching is case-insensitive");
        assert!(is_proxy_owned("forwarded"), "RFC 7239 Forwarded is proxy-owned");
        assert!(is_proxy_owned("Forwarded"), "Forwarded matching is case-insensitive");
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
            "x-app-state, x-forwarded-for, forwarded, x-praxis-route",
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
            !rec.removed.iter().any(|h| h == "forwarded"),
            "Forwarded must not be strippable via a Connection token"
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
