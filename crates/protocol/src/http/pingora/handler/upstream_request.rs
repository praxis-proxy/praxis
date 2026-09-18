// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Upstream request transformations: hop-by-hop header stripping
//! and path rewriting ([RFC 9110]).
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110

use http::Uri;
use pingora_http::RequestHeader;
use praxis_filter::has_dot_dot_traversal;
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
    let is_ws = is_upgrade && hop_by_hop::has_websocket_upgrade(&req.headers);
    let conn_values = hop_by_hop::snapshot_connection_values(&req.headers);
    let was_chunked = hop_by_hop::declares_chunked_framing(&req.headers);

    for name in REQUEST_HOP_BY_HOP {
        if hop_by_hop::preserve_for_upgrade(name, is_ws) {
            continue;
        }
        let _remove = req.remove_header(*name);
    }
    hop_by_hop::strip_connection_tokens(req, &conn_values, REQUEST_HOP_BY_HOP);
    if hop_by_hop::should_restore_chunked_framing(&req.headers, was_chunked) {
        let _insert = req.insert_header(http::header::TRANSFER_ENCODING, "chunked");
    }

    if is_upgrade && !is_ws {
        debug!("stripping non-WebSocket upgrade headers to prevent h2c smuggling");
    }
}

// -----------------------------------------------------------------------------
// Path Rewriting
// -----------------------------------------------------------------------------

/// Apply a rewritten path from the filter pipeline to the upstream request.
///
/// Reads `rewritten_path` without consuming it so the rewrite is
/// re-applied on every upstream attempt. Pingora restarts each retry
/// from a fresh clone of the original downstream request, so a consumed
/// path would leave retried attempts forwarding the original,
/// un-rewritten path.
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
pub(crate) fn apply_rewritten_path(req: &mut RequestHeader, ctx: &PingoraRequestCtx) -> pingora_core::Result<()> {
    let Some(new_path) = ctx.rewritten_path.as_deref() else {
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

    if has_dot_dot_traversal(uri.path()) {
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
// gRPC Deadline
// -----------------------------------------------------------------------------

/// Rewrite `grpc-timeout` with the budget left for this attempt.
///
/// Pingora replays the buffered request header on every retry, so a
/// value written once during the request phase would tell the upstream
/// on the third attempt the same deadline it heard on the first. This
/// runs per attempt and re-encodes what is actually left.
///
/// A request with no gRPC deadline installed is untouched, so pipelines
/// without the `grpc_timeout` filter pay one type lookup.
pub(crate) fn apply_grpc_deadline_header(req: &mut RequestHeader, ctx: &PingoraRequestCtx) {
    let Some(deadline) = ctx.extensions.get::<praxis_core::grpc::GrpcDeadline>() else {
        return;
    };
    // `propagate: false` forwards the client's header untouched; the proxy
    // still bounds the attempt through the shrunk transport timeouts.
    if !deadline.propagate() {
        return;
    }
    let Some(remaining) = deadline.remaining() else {
        return;
    };
    let encoded = praxis_core::grpc::GrpcTimeout::encode(remaining);
    if let Err(error) = req.insert_header("grpc-timeout", encoded.as_str()) {
        debug!(%error, "could not set grpc-timeout on the upstream request");
    }
}

// -----------------------------------------------------------------------------
// Authority Override
// -----------------------------------------------------------------------------

/// Apply the per-cluster upstream authority override.
///
/// When the selected upstream carries a configured authority, this
/// replaces the request's `Host` header and normalizes the URI
/// authority component. Both updates are required:
///
/// - **Host header**: on an HTTP/1.1 upstream leg the `Host` header is sent directly. On an HTTP/2 leg (`clusters[].
///   http.version: h2`) Pingora's `proxy_h2.rs` removes `Host` and rebuilds the URI `:authority` from it, so setting
///   `Host` here covers both protocols.
///
/// - **URI authority**: Defence-in-depth for absolute-form requests whose URI already contains an authority. Without
///   this, a pre-existing URI authority could survive into the upstream request if Pingora's internal flow changes.
///
/// The authority `HeaderValue` is pre-parsed at cluster build time.
///
/// Called after hop-by-hop and reserved-header stripping so that
/// a downstream-supplied `Host` value cannot survive into the
/// upstream request when an override is configured.
///
/// # Errors
///
/// Returns a Pingora error if the URI cannot be rebuilt with the
/// new authority (should not happen with a pre-validated value).
pub(crate) fn apply_authority_override(req: &mut RequestHeader, ctx: &PingoraRequestCtx) -> pingora_core::Result<()> {
    let Some(authority) = ctx.upstream_for_retry.as_ref().and_then(|u| u.authority.as_ref()) else {
        return Ok(());
    };

    debug!(authority = ?authority, "applying upstream authority override");

    req.insert_header(http::header::HOST, authority).map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("failed to set Host header for authority override: {e}"),
        )
    })?;

    normalize_uri_authority(req, authority)?;

    Ok(())
}

/// Replace the authority component of the request URI.
///
/// Rebuilds the URI preserving scheme, path, and query while
/// substituting the authority. This prevents absolute-form
/// requests from retaining an outdated authority in the URI.
fn normalize_uri_authority(req: &mut RequestHeader, authority: &http::header::HeaderValue) -> pingora_core::Result<()> {
    let uri = &req.uri;
    if uri.authority().is_none() && uri.scheme().is_none() {
        return Ok(());
    }

    let authority_str = authority.to_str().map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("authority override is not valid UTF-8: {e}"),
        )
    })?;

    let scheme = uri.scheme_str().unwrap_or("https");
    let path_and_query = uri.path_and_query().map_or("/", http::uri::PathAndQuery::as_str);
    let rebuilt = format!("{scheme}://{authority_str}{path_and_query}");

    let new_uri: Uri = rebuilt.parse().map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("failed to rebuild URI with authority override: {e}"),
        )
    })?;

    req.set_uri(new_uri);
    Ok(())
}

// -----------------------------------------------------------------------------
// Content-Length Repair
// -----------------------------------------------------------------------------

/// Repair request framing after `StreamBuffer` body mutation.
///
/// Pingora forwards upstream headers after `StreamBuffer` pre-read, so a
/// body-mutating filter must update `Content-Length` before those headers
/// are sent to the backend. The pre-read fully dechunks the body, so the
/// mutated length is authoritative: remove any `Transfer-Encoding` that
/// hop-by-hop stripping re-established for a chunked inbound request, since
/// emitting both `Content-Length` and `Transfer-Encoding: chunked` violates
/// [RFC 9112 Section 6.2] and is the canonical request-smuggling ambiguity.
///
/// When the selected-upstream phase adapted the body (#1139),
/// `adapted_request_body_len` is authoritative and takes precedence over the
/// pre-read `mutated_request_body_len`.
///
/// [RFC 9112 Section 6.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-6.2
pub(crate) fn apply_mutated_content_length(req: &mut RequestHeader, ctx: &PingoraRequestCtx) {
    let Some(new_len) = ctx.adapted_request_body_len.or(ctx.mutated_request_body_len) else {
        return;
    };
    let _remove = req.remove_header(&http::header::TRANSFER_ENCODING);
    let _result = req.insert_header(http::header::CONTENT_LENGTH, new_len.to_string());
}

// -----------------------------------------------------------------------------
// Retry Body Replay
// -----------------------------------------------------------------------------

/// Re-seed the mutated request body before a retry attempt replays it.
///
/// The first attempt forwards the post-filter body from `pre_read_body`
/// (or `adapted_request_body` when the selected-upstream phase ran), which
/// drains as it is written. A retry replays from Pingora's fixed retry buffer
/// (the ORIGINAL bytes) while [`apply_mutated_content_length`] re-stamps the
/// authoritative length; without re-seeding, the replayed body would not match
/// its `Content-Length` (a request-smuggling gadget). Restore the retained copy
/// so each replay matches the stamped length.
///
/// When the selected-upstream phase adapted the body (#1139), only the adapted
/// representation is replayed; the canonical body is never reseeded once
/// adaptation ran (preserves the #1138 isolation invariant). A no-op on the
/// first attempt and when no body writer ran.
pub(crate) fn reseed_retry_body(ctx: &mut PingoraRequestCtx) {
    if ctx.retained_adapted_request_body.is_some() {
        if ctx.adapted_request_body.is_none() {
            ctx.adapted_request_body = ctx.retained_adapted_request_body.clone();
        }
        return;
    }
    if ctx.pre_read_body.is_none() && ctx.retained_pre_read_body.is_some() {
        ctx.pre_read_body = ctx.retained_pre_read_body.clone();
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    use std::sync::Arc;

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
        assert_eq!(
            req.headers.get("transfer-encoding").unwrap(),
            "chunked",
            "chunked framing must be re-established for the upstream body writer"
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

        apply_rewritten_path(&mut req, &ctx).unwrap();

        assert_eq!(req.uri.path(), "/rewritten", "URI should be rewritten");
        assert_eq!(
            ctx.rewritten_path.as_deref(),
            Some("/rewritten"),
            "rewritten_path is retained so retried attempts re-apply it"
        );
    }

    #[test]
    fn apply_rewritten_path_reapplies_on_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/rewritten".to_owned());

        let mut attempt1 = RequestHeader::build("GET", b"/original", None).unwrap();
        apply_rewritten_path(&mut attempt1, &ctx).unwrap();
        assert_eq!(attempt1.uri.path(), "/rewritten", "first attempt is rewritten");

        let mut attempt2 = RequestHeader::build("GET", b"/original", None).unwrap();
        apply_rewritten_path(&mut attempt2, &ctx).unwrap();
        assert_eq!(
            attempt2.uri.path(),
            "/rewritten",
            "retried attempt must also carry the rewritten path"
        );
    }

    #[test]
    fn grpc_deadline_header_propagates_when_enabled() {
        let mut req = RequestHeader::build("POST", b"/pkg.Svc/Method", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.extensions.insert(praxis_core::grpc::GrpcDeadline::new(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            false,
            true,
        ));

        apply_grpc_deadline_header(&mut req, &ctx);

        assert!(
            req.headers.get("grpc-timeout").is_some(),
            "propagate: true should rewrite grpc-timeout with the remaining budget"
        );
    }

    #[test]
    fn grpc_deadline_header_left_untouched_when_propagation_disabled() {
        let mut req = RequestHeader::build("POST", b"/pkg.Svc/Method", None).unwrap();
        let _prev = req.insert_header("grpc-timeout", "5S");
        let mut ctx = PingoraRequestCtx::default();
        ctx.extensions.insert(praxis_core::grpc::GrpcDeadline::new(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            false,
            false,
        ));

        apply_grpc_deadline_header(&mut req, &ctx);

        assert_eq!(
            req.headers.get("grpc-timeout").unwrap(),
            "5S",
            "propagate: false must forward the client's header untouched"
        );
    }

    #[test]
    fn apply_rewritten_path_preserves_query() {
        let mut req = RequestHeader::build("GET", b"/original?x=1", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/new?x=1".to_owned());

        apply_rewritten_path(&mut req, &ctx).unwrap();

        assert_eq!(req.uri.path(), "/new", "path should be rewritten");
        assert_eq!(req.uri.query(), Some("x=1"), "query should be preserved");
    }

    #[test]
    fn apply_rewritten_path_noop_when_none() {
        let mut req = RequestHeader::build("GET", b"/keep", None).unwrap();
        let ctx = PingoraRequestCtx::default();

        apply_rewritten_path(&mut req, &ctx).unwrap();

        assert_eq!(req.uri.path(), "/keep", "URI should be unchanged when no rewrite");
    }

    #[test]
    fn apply_rewritten_path_rejects_absolute_uri() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("http://evil.com/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "absolute URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_path_without_leading_slash() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("relative/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "path without leading slash should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_scheme_only() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("https:///path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "scheme-only URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_authority_only() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("//evil.com/path".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "authority-only URI should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_accepts_valid_absolute_path() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/valid/path".to_owned());

        apply_rewritten_path(&mut req, &ctx).unwrap();

        assert_eq!(req.uri.path(), "/valid/path", "valid absolute path should be accepted");
    }

    #[test]
    fn apply_rewritten_path_rejects_dot_dot_traversal() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/../admin".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "path with '..' traversal should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_trailing_dot_dot() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/..".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "path ending with '..' should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_allows_dot_dot_in_segment_name() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/..config".to_owned());

        apply_rewritten_path(&mut req, &ctx).unwrap();

        assert_eq!(
            req.uri.path(),
            "/api/..config",
            "segment containing '..' as prefix should be allowed"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_percent_encoded_traversal() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/%2e%2e/admin".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "percent-encoded '..' (%2e%2e) should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_rejects_mixed_encoded_traversal() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/api/.%2e/admin".to_owned());

        assert!(
            apply_rewritten_path(&mut req, &ctx).is_err(),
            "mixed-encoded '..' (.%2e) should be rejected"
        );
    }

    #[test]
    fn apply_rewritten_path_accepts_root() {
        let mut req = RequestHeader::build("GET", b"/original", None).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.rewritten_path = Some("/".to_owned());

        apply_rewritten_path(&mut req, &ctx).unwrap();

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
    fn duplicate_upgrade_headers_strip_all() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        let _ws = req.append_header("upgrade".to_owned(), "websocket".to_owned());
        let _h2c = req.append_header("upgrade".to_owned(), "h2c".to_owned());
        let _conn = req.insert_header("connection".to_owned(), "Upgrade".to_owned());

        strip_hop_by_hop(&mut req, true);

        assert!(
            req.headers.get("upgrade").is_none(),
            "duplicate Upgrade headers must all be stripped to prevent h2c smuggling"
        );
        assert!(
            req.headers.get("connection").is_none(),
            "connection must be stripped when Upgrade is not a single websocket value"
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

    #[test]
    fn chunked_framing_preserved_without_content_length() {
        let mut req = make_request(&[("transfer-encoding", "chunked"), ("content-type", "text/plain")]);

        strip_hop_by_hop(&mut req, false);

        assert_eq!(
            req.headers.get("transfer-encoding").unwrap(),
            "chunked",
            "chunked request bodies must stay framed for Pingora's upstream writer"
        );
    }

    #[test]
    fn chunked_framing_normalized_from_compound_value() {
        let mut req = make_request(&[("transfer-encoding", "gzip, chunked")]);

        strip_hop_by_hop(&mut req, false);

        assert_eq!(
            req.headers.get("transfer-encoding").unwrap(),
            "chunked",
            "compound transfer codings ending in chunked are normalized to plain chunked"
        );
    }

    #[test]
    fn non_chunked_transfer_encoding_stripped() {
        let mut req = make_request(&[("transfer-encoding", "gzip")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("transfer-encoding").is_none(),
            "non-chunked transfer codings are hop-by-hop and must not be re-added"
        );
    }

    #[test]
    fn chunked_framing_not_restored_over_content_length() {
        let mut req = make_request(&[("transfer-encoding", "chunked"), ("content-length", "5")]);

        strip_hop_by_hop(&mut req, false);

        assert!(
            req.headers.get("transfer-encoding").is_none(),
            "content-length framing wins once transfer-encoding is stripped"
        );
        assert_eq!(
            req.headers.get("content-length").unwrap(),
            "5",
            "content-length must survive"
        );
    }

    #[test]
    fn connection_token_cannot_strip_host_or_content_length() {
        let mut req = make_request(&[
            ("connection", "host, content-length"),
            ("host", "backend.internal"),
            ("content-length", "5"),
        ]);

        strip_hop_by_hop(&mut req, false);

        assert_eq!(
            req.headers.get("host").unwrap(),
            "backend.internal",
            "Host must not be strippable via a Connection token"
        );
        assert_eq!(
            req.headers.get("content-length").unwrap(),
            "5",
            "Content-Length must not be strippable via a Connection token"
        );
    }

    #[test]
    fn apply_authority_override_sets_host() {
        let mut req = make_request(&[("host", "original.example.com")]);
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:443"),
            authority: Some(http::header::HeaderValue::from_static("api.example.com")),
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "api.example.com",
            "Host header should be overridden"
        );
    }

    #[test]
    fn apply_authority_override_with_port() {
        let mut req = make_request(&[("host", "original.example.com")]);
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:8443"),
            authority: Some(http::header::HeaderValue::from_static("api.example.com:8443")),
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "api.example.com:8443",
            "Host header should include port"
        );
    }

    #[test]
    fn apply_authority_override_noop_when_none() {
        let mut req = make_request(&[("host", "original.example.com")]);
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:443"),
            authority: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "original.example.com",
            "Host header should be unchanged when no authority override"
        );
    }

    #[test]
    fn apply_authority_override_noop_when_no_upstream() {
        let mut req = make_request(&[("host", "original.example.com")]);
        let ctx = PingoraRequestCtx::default();

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "original.example.com",
            "Host header should be unchanged when no upstream"
        );
    }

    #[test]
    fn apply_authority_override_replaces_downstream_host() {
        let mut req = make_request(&[("host", "attacker.evil.com")]);
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:443"),
            authority: Some(http::header::HeaderValue::from_static("api.example.com")),
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "api.example.com",
            "configured authority must override downstream Host"
        );
    }

    #[test]
    fn apply_authority_override_replaces_absolute_form_uri() {
        let mut req = RequestHeader::build("GET", b"/v1/chat", None).unwrap();
        req.set_uri("http://original.example.com/v1/chat".parse::<Uri>().unwrap());
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:443"),
            authority: Some(http::header::HeaderValue::from_static("api.example.com")),
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "api.example.com",
            "Host header should be overridden"
        );
        assert_eq!(
            req.uri.authority().unwrap().as_str(),
            "api.example.com",
            "URI authority should be replaced for absolute-form requests"
        );
        assert_eq!(req.uri.path(), "/v1/chat", "URI path should be preserved");
    }

    #[test]
    fn apply_authority_override_preserves_origin_form_uri() {
        let mut req = RequestHeader::build("GET", b"/v1/chat", None).unwrap();
        req.insert_header("host", "original.example.com").unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_for_retry = Some(praxis_core::connectivity::Upstream {
            address: Arc::from("10.0.0.1:443"),
            authority: Some(http::header::HeaderValue::from_static("api.example.com")),
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });

        apply_authority_override(&mut req, &ctx).unwrap();

        assert_eq!(
            req.headers.get("host").unwrap(),
            "api.example.com",
            "Host header should be overridden"
        );
        assert!(
            req.uri.authority().is_none(),
            "origin-form URI should not gain an authority component"
        );
    }

    #[test]
    fn apply_mutated_content_length_updates_header() {
        let mut req = make_request(&[("content-length", "1024")]);
        let mut ctx = PingoraRequestCtx::default();
        ctx.mutated_request_body_len = Some(512);
        apply_mutated_content_length(&mut req, &ctx);
        assert_eq!(
            req.headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("512")
        );
    }

    #[test]
    fn mutated_content_length_strips_restored_chunked_framing() {
        let mut req = make_request(&[("transfer-encoding", "chunked")]);
        strip_hop_by_hop(&mut req, false);
        assert_eq!(
            req.headers.get("transfer-encoding").unwrap(),
            "chunked",
            "framing is restored before the length is known"
        );

        let mut ctx = PingoraRequestCtx::default();
        ctx.mutated_request_body_len = Some(42);
        apply_mutated_content_length(&mut req, &ctx);

        assert!(
            req.headers.get("transfer-encoding").is_none(),
            "content-length framing must remove the transfer-encoding header"
        );
        assert_eq!(
            req.headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("42"),
            "the mutated length is authoritative"
        );
    }

    #[test]
    fn apply_mutated_content_length_noop_when_none() {
        let mut req = make_request(&[("content-length", "1024")]);
        let ctx = PingoraRequestCtx::default();
        apply_mutated_content_length(&mut req, &ctx);
        assert_eq!(
            req.headers.get("content-length").and_then(|v| v.to_str().ok()),
            Some("1024")
        );
    }

    #[test]
    fn apply_mutated_content_length_prefers_adapted_length() {
        let mut req = make_request(&[("transfer-encoding", "chunked")]);
        let mut ctx = PingoraRequestCtx::default();
        // Pre-read mutation reported 512, but the selected-upstream phase produced 7.
        ctx.mutated_request_body_len = Some(512);
        ctx.adapted_request_body_len = Some(7);

        apply_mutated_content_length(&mut req, &ctx);

        assert_eq!(
            req.headers.get(http::header::CONTENT_LENGTH).unwrap(),
            "7",
            "adapted length wins over the pre-read mutated length"
        );
        assert!(
            req.headers.get(http::header::TRANSFER_ENCODING).is_none(),
            "stale Transfer-Encoding is stripped"
        );
    }

    #[test]
    fn reseed_retry_body_restores_mutated_body_on_retry_only() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.pre_read_body = Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
            b"live-body",
        )]));
        ctx.retained_pre_read_body = Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
            b"mutated-body",
        )]));
        reseed_retry_body(&mut ctx);
        assert_eq!(
            ctx.pre_read_body.as_ref().and_then(|c| c.front()),
            Some(&bytes::Bytes::from_static(b"live-body")),
            "the first attempt must not overwrite the live pre_read_body"
        );

        ctx.pre_read_body = None;
        reseed_retry_body(&mut ctx);
        assert_eq!(
            ctx.pre_read_body.as_ref().and_then(|c| c.front()),
            Some(&bytes::Bytes::from_static(b"mutated-body")),
            "a retry must replay the retained mutated body"
        );

        let mut empty = PingoraRequestCtx::default();
        empty.retained_pre_read_body = Some(std::collections::VecDeque::new());
        reseed_retry_body(&mut empty);
        assert_eq!(
            empty.pre_read_body.as_ref().map(std::collections::VecDeque::len),
            Some(0),
            "an empty retained body restores an empty pre_read_body"
        );

        let mut plain = PingoraRequestCtx::default();
        plain.retained_pre_read_body = None;
        reseed_retry_body(&mut plain);
        assert!(
            plain.pre_read_body.is_none(),
            "with no retained body, a retry must not fabricate one"
        );
    }

    #[test]
    fn reseed_retry_body_restores_adapted_only() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.retained_adapted_request_body = Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
            b"ADAPTED",
        )]));
        // A stale canonical retained copy must NOT be reseeded once adaptation ran.
        ctx.retained_pre_read_body = Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
            b"canonical",
        )]));
        // Both drained on the previous attempt.
        ctx.adapted_request_body = None;
        ctx.pre_read_body = None;

        reseed_retry_body(&mut ctx);

        assert_eq!(
            ctx.adapted_request_body,
            Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
                b"ADAPTED"
            )])),
            "adapted body is reseeded from its retained copy"
        );
        assert!(
            ctx.pre_read_body.is_none(),
            "canonical body is never reseeded once adaptation ran"
        );
    }

    #[test]
    fn reseed_retry_body_restores_canonical_when_no_adaptation() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.retained_pre_read_body = Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
            b"canonical",
        )]));
        ctx.pre_read_body = None;

        reseed_retry_body(&mut ctx);

        assert_eq!(
            ctx.pre_read_body,
            Some(std::collections::VecDeque::from([bytes::Bytes::from_static(
                b"canonical"
            )])),
            "canonical body is reseeded when adaptation did not run"
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
