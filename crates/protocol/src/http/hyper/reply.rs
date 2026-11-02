// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Responses the proxy answers itself: rejections, proxy errors and
//! buffered terminal responses.
//!
//! Each mirrors a Pingora writer: a rejection keeps the three gRPC paths of
//! `send_rejection_for` and the header hygiene of `send_rejection`; a proxy
//! error is the RFC 9457 problem document (or an installed formatter's
//! envelope, or a gRPC Trailers-Only response) of `fail_to_proxy`; a terminal
//! response runs the response filters first, like `run_terminal_response`.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Version};
use praxis_core::{
    grpc::{GrpcStatusCode, encode_grpc_message},
    next_hop_headers::is_forbidden_client_response_header,
};
use praxis_filter::{
    ErrorResponseFormatterHandle, FormattedErrorResponse, GrpcErrorMapping, Rejection, TerminalResponse,
};
use tracing::{debug, error, warn};

use super::{body::ProxyBody, failure::Failure, service::Flight};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    convert::grpc_error_message,
    handler::{
        fail_to_proxy::{ProxyError as ClassifiedError, format_error_response, rejection_message},
        hop_by_hop::{RESPONSE_HOP_BY_HOP, strip_hop_by_hop_header_map, strip_reserved_internal_header_map},
        request_filter::terminal_responses::{prepare_terminal_response, run_parent_terminal_body_filters},
    },
};

// -----------------------------------------------------------------------------
// LocalReply
// -----------------------------------------------------------------------------

/// A response the proxy writes without an upstream.
#[derive(Debug)]
pub(super) struct LocalReply {
    /// The body, if any.
    pub(super) body: Option<Bytes>,

    /// Whether `body` must be dropped while keeping its framing headers
    /// (a `HEAD` request or a body-prohibited status).
    pub(super) body_suppressed: bool,

    /// The response headers.
    pub(super) headers: HeaderMap,

    /// Whether the client connection may serve another request after it.
    pub(super) keepalive: bool,

    /// The status.
    pub(super) status: StatusCode,
}

impl LocalReply {
    /// The hyper response; a `HEAD` request gets the headers alone.
    pub(super) fn into_response(self, is_head: bool) -> Response<ProxyBody> {
        let body = match self.body {
            Some(body) if !is_head && !self.body_suppressed => ProxyBody::full(body),
            Some(_) | None => ProxyBody::empty(),
        };
        let mut response = Response::new(body);
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }

    /// A bodyless reply with `status`, closing the connection after it.
    pub(super) fn status(status: u16) -> Self {
        Self {
            body: None,
            body_suppressed: false,
            headers: HeaderMap::new(),
            keepalive: false,
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

// -----------------------------------------------------------------------------
// Rejections
// -----------------------------------------------------------------------------

/// Render a filter rejection, in gRPC's shape when the pipeline armed one.
///
/// A rejection that carries its own `grpc-status` is framed as is; with a
/// [`GrpcErrorMapping`] armed, an error status becomes a Trailers-Only
/// response; anything else is a plain HTTP response. Only error statuses
/// become gRPC statuses: a successful short-circuit is a real response.
pub(super) fn rejection(rejection: Rejection, ctx: &PingoraRequestCtx, version: Version) -> LocalReply {
    if rejection
        .headers
        .iter()
        .any(|(name, _value)| name.eq_ignore_ascii_case("grpc-status"))
    {
        return grpc_rejection(&rejection, version);
    }
    if let Some(mapping) = ctx
        .extensions
        .get::<GrpcErrorMapping>()
        .filter(|_mapping| rejection.status >= 400)
    {
        return trailers_only(mapping, rejection.status, grpc_error_message(&rejection), version);
    }
    plain_rejection(rejection)
}

/// Render a rejection raised in the response phase, which the Pingora
/// handler delivers from `fail_to_proxy`.
pub(super) fn pending_rejection(rejection: Rejection, ctx: &PingoraRequestCtx, version: Version) -> LocalReply {
    if let Some(mapping) = ctx
        .extensions
        .get::<GrpcErrorMapping>()
        .filter(|_mapping| rejection.status >= 400)
    {
        return trailers_only(mapping, rejection.status, rejection_message(&rejection), version);
    }
    plain_rejection(rejection)
}

/// Render a rejection as a plain HTTP response.
///
/// A status that cannot end a response becomes 500, reserved and
/// hop-by-hop headers a filter supplied are dropped, the body sets the
/// length, and the connection closes afterwards unless the rejection
/// preserves it.
pub(super) fn plain_rejection(rejection: Rejection) -> LocalReply {
    debug!(status = rejection.status, "sending rejection response");
    let status = if (200..=599).contains(&rejection.status) {
        rejection.status
    } else {
        error!(status = rejection.status, "non-final rejection status; using 500");
        500
    };
    let mut reply = LocalReply::status(status);
    reply.keepalive = rejection.preserve_keepalive;
    append_allowed(&mut reply.headers, &rejection);
    if let Some(body) = rejection.body {
        reply
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        reply.body = Some(body);
    }
    reply
}

/// A gRPC Trailers-Only response for an HTTP `http_status`: status 200 and
/// a `grpc-status` in one header block, with an explicit zero length on
/// HTTP/1.1 so a keep-alive client does not wait for a body.
pub(super) fn trailers_only(
    mapping: &GrpcErrorMapping,
    http_status: u16,
    message: &str,
    version: Version,
) -> LocalReply {
    let grpc_status = GrpcStatusCode::from_http_status(http_status);
    let mut reply = LocalReply::status(200);
    reply.keepalive = true;
    let headers = &mut reply.headers;
    headers.insert(http::header::CONTENT_TYPE, mapping.content_type().clone());
    headers.insert("grpc-status", grpc_status.as_header_value());
    if mapping.include_message() && !message.is_empty() {
        match HeaderValue::try_from(encode_grpc_message(message).as_ref()) {
            Ok(value) => {
                headers.insert("grpc-message", value);
            },
            Err(err) => debug!(error = %err, "dropping unencodable grpc-message"),
        }
    }
    if version != Version::HTTP_2 {
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
    debug!(
        http_status,
        grpc_status = grpc_status.as_u32(),
        "sending gRPC trailers-only response"
    );
    reply
}

/// Append a rejection's headers, dropping reserved and hop-by-hop ones.
fn append_allowed(headers: &mut HeaderMap, rejection: &Rejection) {
    for (name, value) in &rejection.headers {
        if is_forbidden_client_response_header(name) {
            debug!(header = %name, "dropping reserved or hop-by-hop header from rejection response");
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            headers.append(name, value);
        }
    }
    for (name, value) in rejection.header_map.iter().flat_map(|map| map.iter()) {
        if is_forbidden_client_response_header(name.as_str()) {
            debug!(header = %name, "dropping reserved or hop-by-hop header from rejection response");
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
}

/// Frame a rejection that already carries its gRPC headers as a header
/// block that ends the stream.
fn grpc_rejection(rejection: &Rejection, version: Version) -> LocalReply {
    let mut reply = LocalReply::status(rejection.status);
    reply.keepalive = true;
    for (name, value) in &rejection.headers {
        // On HTTP/2, END_STREAM on the header block already says the body
        // is empty; a content-length would be redundant.
        if version == Version::HTTP_2 && name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        match (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            (Ok(name), Ok(value)) => {
                reply.headers.append(name, value);
            },
            (Err(_), _) | (_, Err(_)) => debug!(name, "dropping unencodable gRPC rejection header"),
        }
    }
    debug!("sending gRPC rejection as a trailers-only response");
    reply
}

// -----------------------------------------------------------------------------
// Proxy Errors
// -----------------------------------------------------------------------------

/// The error response for `failure`, or `None` when the client is gone and
/// nothing can be written. A client that stalled or broke the request still
/// gets the proxy's `400`, as on Pingora.
pub(super) fn failure(failure: &Failure, ctx: &PingoraRequestCtx, version: Version) -> Option<LocalReply> {
    if failure.kind == super::failure::FailureKind::DownstreamClosed {
        debug!(error = %failure, "downstream connection dead, skipping error response");
        return None;
    }
    if failure.is_timeout()
        && let Some(deadline) = crate::http::pingora::handler::fail_to_proxy::deadline_exceeded_rejection(ctx)
    {
        warn!("upstream attempt cancelled by the gRPC deadline");
        return Some(grpc_rejection(&deadline, version));
    }
    let classified = failure.classified();
    let upstream_address = ctx
        .upstream_for_retry
        .as_ref()
        .map_or("unknown", |u| u.address.as_ref());
    error!(
        error_code = classified.code,
        error_message = classified.message,
        status = classified.status,
        upstream_address,
        detail = %failure,
        "upstream error"
    );
    Some(classified_error(&classified, ctx, version))
}

/// The response for a classified proxy error: gRPC Trailers-Only when the
/// pipeline armed gRPC, else the installed formatter's or the RFC 9457
/// envelope, marked `no-transform`.
pub(super) fn classified_error(error: &ClassifiedError, ctx: &PingoraRequestCtx, version: Version) -> LocalReply {
    if let Some(mapping) = ctx.extensions.get::<GrpcErrorMapping>() {
        return trailers_only(mapping, error.status, error.message, version);
    }
    let formatter = ctx.extensions.get::<ErrorResponseFormatterHandle>();
    let FormattedErrorResponse { body, content_type } = format_error_response(error, formatter);
    let mut reply = LocalReply::status(error.status);
    let headers = &mut reply.headers;
    headers.insert(http::header::CONTENT_TYPE, content_type);
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    headers.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-transform"));
    reply.body = Some(body);
    reply
}

// -----------------------------------------------------------------------------
// Terminal Responses
// -----------------------------------------------------------------------------

/// Run the response filters over a filter's buffered terminal response and
/// build it; a filter that rejects it is answered instead.
pub(super) async fn terminal(flight: &mut Flight, terminal: TerminalResponse) -> LocalReply {
    let prepared = Box::pin(prepare_terminal_response(
        &flight.pipeline,
        &mut flight.ctx,
        terminal.status,
        terminal.headers,
    ))
    .await;
    let mut response = match prepared {
        Ok(response) => response,
        Err(refusal) => return rejection(refusal, &flight.ctx, flight.version),
    };
    let mut body = terminal.body;
    let is_bodyless = flight
        .ctx
        .request_snapshot
        .as_ref()
        .is_some_and(|request| praxis_filter::bodyless_response(response.status, &request.method));
    if is_bodyless {
        flight.ctx.response_delivery_complete = true;
    } else if let Err(refusal) =
        run_parent_terminal_body_filters(&flight.pipeline, &mut flight.ctx, &response, &mut body, true)
    {
        return rejection(refusal, &flight.ctx, flight.version);
    }
    strip_hop_by_hop_header_map(&mut response.headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_internal_header_map(&mut response.headers);
    terminal_reply(response, body, flight.is_head())
}

/// Build a terminal response: the length comes from the body, except on a
/// `HEAD`, which keeps the filters' length and sends no body.
fn terminal_reply(response: praxis_filter::Response, body: Option<Bytes>, is_head: bool) -> LocalReply {
    let code = response.status.as_u16();
    if !(200..=599).contains(&code) {
        warn!(status = code, "terminal response status outside 200..=599; sending 500");
        return plain_rejection(Rejection::status(500));
    }
    let body_prohibited = matches!(response.status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED);
    let mut headers = response.headers;
    if !is_head {
        headers.remove(http::header::CONTENT_LENGTH);
    }
    if !body_prohibited && !is_head {
        let length = body.as_ref().map_or(0, Bytes::len);
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    LocalReply {
        body,
        body_suppressed: body_prohibited,
        headers,
        keepalive: true,
        status: response.status,
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
    reason = "tests"
)]
mod tests {
    use praxis_core::grpc::GrpcKind;

    use super::*;

    #[test]
    fn plain_rejection_drops_forbidden_headers_and_sets_length() {
        let mut refusal = Rejection::status(403)
            .with_header("x-praxis-internal", "secret")
            .with_header("connection", "keep-alive")
            .with_header("x-reason", "denied");
        refusal.body = Some(Bytes::from_static(b"nope"));

        let reply = plain_rejection(refusal);

        assert_eq!(reply.status, StatusCode::FORBIDDEN, "the status is kept");
        assert!(
            reply.headers.get("x-praxis-internal").is_none(),
            "reserved headers are dropped"
        );
        assert!(
            reply.headers.get("connection").is_none(),
            "hop-by-hop headers are dropped"
        );
        assert_eq!(
            reply.headers.get("x-reason").unwrap(),
            "denied",
            "other headers are kept"
        );
        assert_eq!(
            reply.headers.get("content-length").unwrap(),
            "4",
            "the body sets the length"
        );
        assert!(!reply.keepalive, "a rejection closes the connection by default");
    }

    #[test]
    fn informational_rejection_status_becomes_500() {
        assert_eq!(
            plain_rejection(Rejection::status(101)).status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a status that cannot end a response is replaced"
        );
    }

    #[test]
    fn grpc_mapping_turns_error_rejections_into_trailers_only() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.extensions.insert(GrpcErrorMapping::new(GrpcKind::Grpc, true));

        let reply = rejection(Rejection::status(429), &ctx, Version::HTTP_2);
        let success = rejection(Rejection::status(204), &ctx, Version::HTTP_2);

        assert_eq!(reply.status, StatusCode::OK, "gRPC errors travel as HTTP 200");
        assert!(reply.headers.get("grpc-status").is_some(), "the gRPC status is set");
        assert!(reply.headers.get("content-length").is_none(), "no length on HTTP/2");
        assert_eq!(
            success.status,
            StatusCode::NO_CONTENT,
            "a success short-circuit stays HTTP"
        );
    }

    #[test]
    fn proxy_errors_are_problem_documents() {
        let ctx = PingoraRequestCtx::default();
        let error = ClassifiedError {
            code: "upstream_connect_refused",
            message: "Upstream connection refused",
            status: 502,
        };

        let reply = classified_error(&error, &ctx, Version::HTTP_11);

        assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "the classified status is used");
        assert_eq!(
            reply.headers.get("content-type").unwrap(),
            "application/problem+json",
            "RFC 9457 envelope by default"
        );
        assert_eq!(
            reply.headers.get("cache-control").unwrap(),
            "no-transform",
            "marked no-transform"
        );
        let body = reply.body.unwrap();
        assert_eq!(
            reply.headers.get("content-length").unwrap(),
            body.len().to_string().as_str(),
            "the length matches the body"
        );
    }

    #[test]
    fn head_reply_keeps_headers_without_a_body() {
        let reply = terminal_reply(
            praxis_filter::Response {
                headers: HeaderMap::new(),
                status: StatusCode::OK,
            },
            Some(Bytes::from_static(b"body")),
            true,
        );

        let response = reply.into_response(true);

        assert!(
            hyper::body::Body::is_end_stream(response.body()),
            "a HEAD response carries no body"
        );
    }
}
