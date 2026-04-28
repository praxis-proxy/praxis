// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Upstream request transformations: hop-by-hop header stripping
//! and path rewriting ([RFC 9110]).
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use http::Uri;
use pingora_http::RequestHeader;
use tracing::debug;

use super::{
    super::context::PingoraRequestCtx,
    hop_by_hop::{self, REQUEST_HOP_BY_HOP},
};

// -----------------------------------------------------------------------------
// Hop-by-hop Header Stripping
// -----------------------------------------------------------------------------

/// Strip hop-by-hop headers from an upstream request.
///
/// Removes all RFC-defined hop-by-hop headers plus any custom
/// headers declared in the `Connection` header value.
///
/// Preserves the `Upgrade` and `Connection` headers only for
/// `WebSocket` upgrades ([RFC 6455]). Other upgrade types such
/// as `h2c` are always stripped to prevent smuggling attacks.
///
/// [RFC 6455]: https://datatracker.ietf.org/doc/html/rfc6455
pub(crate) fn strip_hop_by_hop(req: &mut RequestHeader, is_upgrade: bool) {
    let is_ws = is_upgrade && is_websocket_request(&req.headers);
    let conn_values = hop_by_hop::snapshot_connection_values(&req.headers);

    for name in REQUEST_HOP_BY_HOP {
        if hop_by_hop::preserve_for_upgrade(name, is_ws) {
            continue;
        }
        let _remove = req.remove_header(*name);
    }
    hop_by_hop::strip_connection_tokens(req, &conn_values, REQUEST_HOP_BY_HOP);

    if is_upgrade && !is_ws {
        debug!("stripping non-WebSocket upgrade headers to prevent h2c smuggling");
    }
}

/// Check whether the request's `Upgrade` header is `WebSocket`.
fn is_websocket_request(headers: &http::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(hop_by_hop::is_websocket_upgrade)
}

// -----------------------------------------------------------------------------
// Path Rewriting
// -----------------------------------------------------------------------------

/// Apply a rewritten path from the filter pipeline to the upstream request.
///
/// Validates that the path starts with `/`, contains no scheme or
/// authority components, and has no `..` traversal segments before
/// applying. Returns an error on invalid paths rather than silently
/// ignoring them, because a filter producing an invalid path is a
/// pipeline configuration bug.
///
/// # Errors
///
/// Returns a Pingora error if the rewritten path is malformed,
/// contains traversal, or includes a scheme/authority.
pub(crate) fn apply_rewritten_path(req: &mut RequestHeader, ctx: &mut PingoraRequestCtx) -> pingora_core::Result<()> {
    let Some(new_path) = ctx.rewritten_path.take() else {
        return Ok(());
    };

    if !new_path.starts_with('/') || new_path.starts_with("//") {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path must start with / but not //: {new_path}"),
        ));
    }

    let uri = new_path.parse::<Uri>().map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("invalid rewritten path: {new_path}: {e}"),
        )
    })?;

    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path contains scheme or authority: {new_path}"),
        ));
    }

    if uri.path().split('/').any(|seg| seg == "..") {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path contains '..' traversal: {new_path}"),
        ));
    }

    debug!(rewritten_path = %new_path, "applying path rewrite to upstream request");
    req.set_uri(uri);
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn strips_standard_hop_by_hop() {
        let mut req = make_request(&[
            ("connection", "close"),
            ("keep-alive", "300"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("trailer", "X-Checksum"),
            ("proxy-authorization", "Basic abc"),
            ("proxy-authenticate", "Basic"),
            ("x-real-header", "keep-me"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            req.headers.get("keep-alive").is_none(),
            "keep-alive header should be stripped"
        );
        assert!(
            req.headers.get("transfer-encoding").is_none(),
            "transfer-encoding header should be stripped"
        );
        assert!(
            req.headers.get("upgrade").is_none(),
            "upgrade header should be stripped"
        );
        assert!(req.headers.get("te").is_none(), "te header should be stripped");
        assert!(
            req.headers.get("trailer").is_none(),
            "trailer header should be stripped"
        );
        assert!(
            req.headers.get("proxy-authorization").is_none(),
            "proxy-authorization header should be stripped"
        );
        assert!(
            req.headers.get("proxy-authenticate").is_none(),
            "proxy-authenticate header should be stripped"
        );
        assert_eq!(
            req.headers.get("x-real-header").unwrap(),
            "keep-me",
            "end-to-end header should be preserved"
        );
    }

    #[test]
    fn strips_custom_connection_headers() {
        let mut req = make_request(&[
            ("connection", "X-Custom, X-Debug"),
            ("x-custom", "secret"),
            ("x-debug", "true"),
            ("x-safe", "keep"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            req.headers.get("x-custom").is_none(),
            "custom connection-listed header should be stripped"
        );
        assert!(
            req.headers.get("x-debug").is_none(),
            "custom connection-listed header should be stripped"
        );
        assert_eq!(
            req.headers.get("x-safe").unwrap(),
            "keep",
            "header not listed in connection should be preserved"
        );
    }

    #[test]
    fn no_hop_by_hop_headers_is_noop() {
        let mut req = make_request(&[
            ("host", "example.com"),
            ("accept", "text/html"),
            ("authorization", "Bearer tok"),
            ("content-type", "application/json"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert_eq!(
            req.headers.get("host").unwrap(),
            "example.com",
            "host header should be preserved"
        );
        assert_eq!(
            req.headers.get("accept").unwrap(),
            "text/html",
            "accept header should be preserved"
        );
        assert_eq!(
            req.headers.get("authorization").unwrap(),
            "Bearer tok",
            "authorization header should be preserved"
        );
        assert_eq!(
            req.headers.get("content-type").unwrap(),
            "application/json",
            "content-type header should be preserved"
        );
    }

    #[test]
    fn connection_header_with_single_value() {
        let mut req = make_request(&[("connection", "X-Only"), ("x-only", "gone"), ("x-keep", "stay")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            req.headers.get("x-only").is_none(),
            "single connection-listed header should be stripped"
        );
        assert_eq!(
            req.headers.get("x-keep").unwrap(),
            "stay",
            "header not listed in connection should be preserved"
        );
    }

    #[test]
    fn connection_value_with_whitespace_variations() {
        let mut req = make_request(&[
            ("connection", " X-A ,  X-B  , X-C "),
            ("x-a", "1"),
            ("x-b", "2"),
            ("x-c", "3"),
            ("x-d", "4"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("x-a").is_none(),
            "x-a should be stripped despite whitespace"
        );
        assert!(
            req.headers.get("x-b").is_none(),
            "x-b should be stripped despite whitespace"
        );
        assert!(
            req.headers.get("x-c").is_none(),
            "x-c should be stripped despite whitespace"
        );
        assert_eq!(
            req.headers.get("x-d").unwrap(),
            "4",
            "x-d not in connection list should be preserved"
        );
    }

    #[test]
    fn connection_value_case_insensitive() {
        let mut req = make_request(&[("connection", "X-MiXeD-CaSe"), ("x-mixed-case", "stripped")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("x-mixed-case").is_none(),
            "connection header matching should be case-insensitive"
        );
    }

    #[test]
    fn connection_value_referencing_standard_hop_by_hop() {
        let mut req = make_request(&[("connection", "keep-alive"), ("keep-alive", "timeout=5")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            req.headers.get("keep-alive").is_none(),
            "keep-alive referenced in connection should be stripped"
        );
    }

    #[test]
    fn empty_connection_header_value() {
        let mut req = make_request(&[("connection", ""), ("x-safe", "keep")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "empty connection header should be stripped"
        );
        assert_eq!(
            req.headers.get("x-safe").unwrap(),
            "keep",
            "unrelated header should be preserved with empty connection"
        );
    }

    #[test]
    fn only_hop_by_hop_headers_all_removed() {
        let mut req = make_request(&[("connection", "close"), ("keep-alive", "300"), ("upgrade", "h2c")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert!(
            req.headers.get("keep-alive").is_none(),
            "keep-alive header should be stripped"
        );
        assert!(
            req.headers.get("upgrade").is_none(),
            "upgrade header should be stripped"
        );
        assert_eq!(req.headers.len(), 0, "all hop-by-hop headers should be removed");
    }

    #[test]
    fn preserves_standard_end_to_end_headers() {
        let mut req = make_request(&[
            ("connection", "close"),
            ("host", "example.com"),
            ("accept", "*/*"),
            ("user-agent", "test/1.0"),
            ("content-length", "42"),
            ("cache-control", "no-cache"),
            ("authorization", "Bearer xyz"),
            ("cookie", "session=abc"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("connection").is_none(),
            "connection header should be stripped"
        );
        assert_eq!(
            req.headers.get("host").unwrap(),
            "example.com",
            "host should be preserved"
        );
        assert_eq!(req.headers.get("accept").unwrap(), "*/*", "accept should be preserved");
        assert_eq!(
            req.headers.get("user-agent").unwrap(),
            "test/1.0",
            "user-agent should be preserved"
        );
        assert_eq!(
            req.headers.get("content-length").unwrap(),
            "42",
            "content-length should be preserved"
        );
        assert_eq!(
            req.headers.get("cache-control").unwrap(),
            "no-cache",
            "cache-control should be preserved"
        );
        assert_eq!(
            req.headers.get("authorization").unwrap(),
            "Bearer xyz",
            "authorization should be preserved"
        );
        assert_eq!(
            req.headers.get("cookie").unwrap(),
            "session=abc",
            "cookie should be preserved"
        );
    }

    #[test]
    fn empty_request_no_panic() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        strip_hop_by_hop(&mut req, false);
    }

    #[test]
    fn apply_rewritten_path_sets_uri() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/rewritten".to_owned());

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(req.uri.path(), "/rewritten", "URI should be rewritten");
        assert!(ctx.rewritten_path.is_none(), "rewritten_path should be taken");
    }

    #[test]
    fn apply_rewritten_path_preserves_query() {
        let mut req = RequestHeader::build("GET", b"/original?x=1", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/new?x=1".to_owned());

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(req.uri.path(), "/new", "path should be rewritten");
        assert_eq!(req.uri.query(), Some("x=1"), "query should be preserved");
    }

    #[test]
    fn apply_rewritten_path_noop_when_none() {
        let mut req = RequestHeader::build("GET", b"/keep", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(req.uri.path(), "/keep", "URI should be unchanged when no rewrite");
    }

    #[test]
    fn apply_rewritten_path_rejects_absolute_uri() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("http://evil.com/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "absolute URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_path_without_leading_slash() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("relative/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "path without leading slash should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_scheme_only() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("https:///path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "scheme-only URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_authority_only() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("//evil.com/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "authority-only URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_accepts_valid_absolute_path() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/valid/path".to_owned());

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(req.uri.path(), "/valid/path", "valid absolute path should be accepted");
    }

    #[test]
    fn apply_rewritten_path_rejects_dot_dot_traversal() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/../admin".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "path with '..' traversal should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_trailing_dot_dot() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/..".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &mut ctx).is_err(),
            "path ending with '..' should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_allows_dot_dot_in_segment_name() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/..config".to_owned());

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(
            req.uri.path(),
            "/api/..config",
            "segment containing '..' as prefix should be allowed"
        );
    }

    #[test]
    fn apply_rewritten_path_accepts_root() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/".to_owned());

        apply_rewritten_path(&mut req, &mut ctx).unwrap();

        assert_eq!(req.uri.path(), "/", "root path should be accepted");
    }

    #[test]
    fn upgrade_preserves_upgrade_and_connection() {
        let mut req = make_request(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("keep-alive", "300"),
        ]);

        strip_hop_by_hop(&mut req, true);

        assert_eq!(
            req.headers.get("upgrade").unwrap(),
            "websocket",
            "upgrade header should be preserved for upgrade requests"
        );
        assert_eq!(
            req.headers.get("connection").unwrap(),
            "Upgrade",
            "connection header should be preserved for upgrade requests"
        );
        assert_eq!(
            req.headers.get("sec-websocket-key").unwrap(),
            "dGhlIHNhbXBsZSBub25jZQ==",
            "websocket headers should be preserved"
        );
        assert!(
            req.headers.get("keep-alive").is_none(),
            "other hop-by-hop headers should still be stripped"
        );
    }

    #[test]
    fn non_upgrade_strips_upgrade_and_connection() {
        let mut req = make_request(&[("upgrade", "websocket"), ("connection", "Upgrade")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("upgrade").is_none(),
            "upgrade should be stripped for non-upgrade requests"
        );
        assert!(
            req.headers.get("connection").is_none(),
            "connection should be stripped for non-upgrade requests"
        );
    }

    #[test]
    fn h2c_upgrade_strips_all_hop_by_hop() {
        let mut req = make_request(&[
            ("upgrade", "h2c"),
            ("connection", "Upgrade"),
            ("http2-settings", "AAMAAABkAAQCAAAAAAIAAAAA"),
        ]);

        strip_hop_by_hop(&mut req, true);

        assert!(
            req.headers.get("upgrade").is_none(),
            "h2c upgrade header must be stripped to prevent smuggling"
        );
        assert!(
            req.headers.get("connection").is_none(),
            "connection header must be stripped for h2c upgrades"
        );
    }

    #[test]
    fn mixed_upgrade_strips_all() {
        let mut req = make_request(&[("upgrade", "h2c, websocket"), ("connection", "Upgrade")]);

        strip_hop_by_hop(&mut req, true);

        assert!(
            req.headers.get("upgrade").is_none(),
            "mixed upgrade values must be stripped to prevent protocol negotiation abuse"
        );
        assert!(
            req.headers.get("connection").is_none(),
            "connection must be stripped when upgrade value is not purely websocket"
        );
    }

    #[test]
    fn websocket_case_insensitive() {
        let mut req = make_request(&[("upgrade", "WEBSOCKET"), ("connection", "Upgrade")]);

        strip_hop_by_hop(&mut req, true);

        assert_eq!(
            req.headers.get("upgrade").unwrap(),
            "WEBSOCKET",
            "case-insensitive WebSocket upgrade should be preserved"
        );
        assert_eq!(
            req.headers.get("connection").unwrap(),
            "Upgrade",
            "connection should be preserved for WebSocket upgrades"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a GET request with the given headers for tests.
    fn make_request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            let _inserted = req.insert_header((*name).to_owned(), (*value).to_owned());
        }
        req
    }
}
