// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The upstream request head, built from the filtered request.
//!
//! What the Pingora handler's `upstream_request_filter` does to the
//! forwarded head, per attempt: hop-by-hop stripping (upgrade headers
//! included, since this backend does not tunnel upgrades), `te: trailers`
//! kept on an HTTP/2 leg, reserved headers stripped, the cluster's
//! authority, the rewritten path and base path, the length of a rewritten
//! body, the remaining gRPC deadline, `Via`, and the trace context.

use http::{HeaderMap, HeaderValue, Version, header, uri::PathAndQuery};
use praxis_core::egress::RequestHead;
use tracing::debug;

use super::failure::{Failure, FailureKind};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    handler::{
        hop_by_hop::{REQUEST_HOP_BY_HOP, strip_hop_by_hop_header_map, strip_reserved_internal_header_map},
        upstream_request::rewritten_origin_form,
        via::append_map_via,
    },
};

// -----------------------------------------------------------------------------
// Request Head
// -----------------------------------------------------------------------------

/// The head to send this attempt's upstream, `h2` when the connection
/// speaks HTTP/2.
///
/// # Errors
///
/// Returns a [`Failure`] when the request was never snapshotted, a filter
/// rewrote the path into something that is not an origin form, or the
/// cluster's base path cannot be applied to the target.
pub(super) fn request_head(ctx: &PingoraRequestCtx, h2: bool) -> Result<RequestHead, Failure> {
    let request = ctx
        .request_snapshot
        .as_ref()
        .ok_or_else(|| Failure::internal("request snapshot not set when forwarding upstream"))?;
    let mut headers = request.headers.clone();
    strip_hop_by_hop_header_map(&mut headers, REQUEST_HOP_BY_HOP);
    if h2 && wants_trailers(&request.headers) {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
    strip_reserved_internal_header_map(&mut headers);
    apply_host(&mut headers, ctx, request.uri.authority());

    let target = target(ctx, &request.uri, &request.method)?;
    apply_body_length(&mut headers, ctx);
    apply_grpc_deadline(&mut headers, ctx);
    append_map_via(&mut headers, ctx.client_http_version.unwrap_or(Version::HTTP_11));
    #[cfg(feature = "otel")]
    inject_trace_context(&mut headers, &ctx.upstream_client_span);

    Ok(RequestHead {
        headers,
        method: request.method.clone(),
        target,
    })
}

/// Whether the client asked for trailers, which an HTTP/2 upstream (gRPC)
/// requires to see ([RFC 9113 Section 8.2.2]).
///
/// [RFC 9113 Section 8.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.2.2
fn wants_trailers(downstream: &HeaderMap) -> bool {
    downstream.get_all(header::TE).iter().any(|value| {
        praxis_core::reserved_headers::connection_tokens(value).any(|token| token.eq_ignore_ascii_case("trailers"))
    })
}

/// Set `Host`: the cluster's authority override when it has one, else the
/// HTTP/2 client's `:authority` when the request carried no `Host`.
fn apply_host(headers: &mut HeaderMap, ctx: &PingoraRequestCtx, authority: Option<&http::uri::Authority>) {
    if let Some(authority) = ctx.upstream_for_retry.as_ref().and_then(|u| u.authority.as_ref()) {
        debug!(authority = ?authority, "applying upstream authority override");
        headers.insert(header::HOST, authority.clone());
        return;
    }
    if !headers.contains_key(header::HOST)
        && let Some(value) = authority.and_then(|authority| HeaderValue::try_from(authority.as_str()).ok())
    {
        headers.insert(header::HOST, value);
    }
}

/// The origin-form target: the rewritten path, else the client's, with the
/// cluster's base path in front.
fn target(ctx: &PingoraRequestCtx, uri: &http::Uri, method: &http::Method) -> Result<String, Failure> {
    let rewritten = ctx
        .rewritten_path
        .as_deref()
        .map(|path| {
            debug!(rewritten_path = %path, "applying path rewrite to upstream request");
            rewritten_origin_form(path).map_err(Failure::internal)
        })
        .transpose()?;
    let path = rewritten
        .as_ref()
        .and_then(http::Uri::path_and_query)
        .or_else(|| uri.path_and_query())
        .map_or("/", PathAndQuery::as_str);

    let Some(base) = ctx.upstream_for_retry.as_ref().and_then(|u| u.base_path.as_deref()) else {
        return Ok(path.to_owned());
    };
    with_base_path(path, base, method)
}

/// Prefix `path` with the cluster's base path; a target that names no
/// resource (`*`, `CONNECT`) is left alone.
fn with_base_path(path: &str, base: &str, method: &http::Method) -> Result<String, Failure> {
    if path == "*" || method == http::Method::CONNECT {
        return Ok(path.to_owned());
    }
    let prefixed = if path.starts_with('?') {
        format!("{base}/{path}")
    } else if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        // Forwarding it unprefixed would reach the upstream root.
        return Err(Failure::new(
            FailureKind::BadRequest,
            "request target cannot carry the cluster's base path",
        ));
    };
    debug!(base_path = %base, "applying upstream base path");
    PathAndQuery::try_from(prefixed.as_str())
        .map(|_valid| prefixed)
        .map_err(|err| {
            Failure::new(
                FailureKind::BadRequest,
                format!("request target is not valid with base path {base} prepended: {err}"),
            )
        })
}

/// Frame a body a filter rewrote: its length is authoritative, so the
/// declared length is replaced and any chunked framing dropped.
fn apply_body_length(headers: &mut HeaderMap, ctx: &PingoraRequestCtx) {
    let Some(length) = ctx.adapted_request_body_len.or(ctx.mutated_request_body_len) else {
        return;
    };
    headers.remove(header::TRANSFER_ENCODING);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
}

/// Rewrite `grpc-timeout` with what is left of the gRPC deadline for this
/// attempt, when the deadline filter asks for propagation.
fn apply_grpc_deadline(headers: &mut HeaderMap, ctx: &PingoraRequestCtx) {
    let Some(deadline) = ctx.extensions.get::<praxis_core::grpc::GrpcDeadline>() else {
        return;
    };
    if !deadline.propagate() {
        return;
    }
    let Some(remaining) = deadline.remaining() else {
        return;
    };
    let encoded = praxis_core::grpc::GrpcTimeout::encode(remaining);
    match HeaderValue::try_from(encoded.as_str()) {
        Ok(value) => {
            headers.insert("grpc-timeout", value);
        },
        Err(err) => debug!(error = %err, "could not set grpc-timeout on the upstream request"),
    }
}

/// Inject the exported client span of this attempt, replacing whatever
/// trace context the client or a filter set.
#[cfg(feature = "otel")]
fn inject_trace_context(headers: &mut HeaderMap, client_span: &tracing::Span) {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let mut propagated = HeaderMap::new();
    if praxis_core::trace_context::inject_context(&mut propagated, &client_span.context()) {
        headers.remove("traceparent");
        headers.remove("tracestate");
        for name in ["traceparent", "tracestate"] {
            if let Some(value) = propagated.remove(name) {
                headers.insert(name, value);
            }
        }
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
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::connectivity::{ConnectionOptions, Upstream};
    use praxis_filter::Request;

    use super::*;

    #[test]
    fn hop_by_hop_and_reserved_headers_are_stripped() {
        let ctx = ctx_for(
            "/a?b=1",
            &[
                ("host", "client.example"),
                ("connection", "x-hop"),
                ("x-hop", "1"),
                ("keep-alive", "5"),
                ("upgrade", "websocket"),
                ("te", "trailers"),
                ("x-praxis-internal", "1"),
                ("x-kept", "yes"),
            ],
        );

        let head = request_head(&ctx, false).unwrap();

        for gone in [
            "connection",
            "x-hop",
            "keep-alive",
            "upgrade",
            "te",
            "x-praxis-internal",
        ] {
            assert!(head.headers.get(gone).is_none(), "{gone} must not reach the upstream");
        }
        assert_eq!(
            head.headers.get("x-kept").unwrap(),
            "yes",
            "end-to-end headers are kept"
        );
        assert_eq!(
            head.headers.get("via").unwrap(),
            "1.1 praxis",
            "the request Via is appended"
        );
        assert_eq!(head.target, "/a?b=1", "the client's target is forwarded");
    }

    #[test]
    fn te_trailers_survives_on_http2() {
        let ctx = ctx_for("/", &[("host", "a"), ("te", "trailers")]);

        let head = request_head(&ctx, true).unwrap();

        assert_eq!(
            head.headers.get("te").unwrap(),
            "trailers",
            "gRPC needs te: trailers on h2"
        );
    }

    #[test]
    fn rewritten_and_base_paths_build_the_target() {
        let mut ctx = ctx_for("/old?q=1", &[("host", "a")]);
        ctx.rewritten_path = Some("/new?q=2".to_owned());
        ctx.upstream_for_retry = Some(upstream(Some("/base"), None));

        let head = request_head(&ctx, false).unwrap();

        assert_eq!(head.target, "/base/new?q=2", "base path in front of the rewritten path");
    }

    #[test]
    fn traversal_in_a_rewritten_path_is_refused() {
        let mut ctx = ctx_for("/", &[("host", "a")]);
        ctx.rewritten_path = Some("/a/../etc".to_owned());

        let failure = request_head(&ctx, false).unwrap_err();

        assert_eq!(
            failure.kind,
            FailureKind::Internal,
            "a filter that rewrites badly is a proxy fault"
        );
    }

    #[test]
    fn authority_override_replaces_host() {
        let mut ctx = ctx_for("/", &[("host", "client.example")]);
        ctx.upstream_for_retry = Some(upstream(None, Some("backend.internal")));

        let head = request_head(&ctx, false).unwrap();

        assert_eq!(
            head.headers.get("host").unwrap(),
            "backend.internal",
            "the override wins"
        );
    }

    #[test]
    fn rewritten_body_length_replaces_framing() {
        let mut ctx = ctx_for("/", &[("host", "a"), ("content-length", "10")]);
        ctx.mutated_request_body_len = Some(4);

        let head = request_head(&ctx, false).unwrap();

        assert_eq!(
            head.headers.get("content-length").unwrap(),
            "4",
            "the rewritten length is sent"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A context whose request snapshot is `GET target` with `headers`.
    fn ctx_for(target: &str, headers: &[(&'static str, &'static str)]) -> PingoraRequestCtx {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(*name, HeaderValue::from_static(value));
        }
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(Request {
            method: http::Method::GET,
            uri: target.parse().unwrap(),
            headers: map,
        });
        ctx
    }

    /// An upstream with an optional base path and authority override.
    fn upstream(base_path: Option<&str>, authority: Option<&'static str>) -> Upstream {
        Upstream {
            address: Arc::from("127.0.0.1:80"),
            authority: authority.map(HeaderValue::from_static),
            base_path: base_path.map(Arc::from),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        }
    }
}
