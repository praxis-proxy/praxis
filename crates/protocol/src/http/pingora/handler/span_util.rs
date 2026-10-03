// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Span attribute recording for request tracing.
//!
//! Records response-phase attributes (status, route, upstream, cluster)
//! on the root request span and upstream exchange span. Extracted from
//! `mod.rs` to keep the handler module focused on lifecycle hooks.

use pingora_proxy::Session;

use crate::http::pingora::context::PingoraRequestCtx;

/// Map an [`http::Version`] to the [OTel `network.protocol.version`] value.
///
/// [OTel `network.protocol.version`]: https://opentelemetry.io/docs/specs/semconv/attributes-registry/network/
pub(super) fn http_version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "0.9",
        http::Version::HTTP_10 => "1.0",
        http::Version::HTTP_11 => "1.1",
        http::Version::HTTP_2 => "2",
        http::Version::HTTP_3 => "3",
        _ => "unknown",
    }
}

/// Record response-phase span attributes that are only available after
/// the upstream exchange.
///
/// Called from the `logging` hook to fill in `http.response.status_code`,
/// `otel.status_code` and `error.type` (5xx only), `http.route` and the
/// `otel.name` upgrade to `{method} {route}` (when a route matched),
/// `upstream.address`, and `upstream.cluster` on the root request span,
/// and response attributes on the upstream exchange span.
pub(super) fn record_response_span_attributes(session: &Session, ctx: &PingoraRequestCtx) {
    if ctx.request_span.is_disabled() {
        return;
    }
    let response = session.response_written();
    let status = response.map(|resp| resp.status);
    let method = session.req_header().method.as_str();
    record_response_span_fields(status, method, response, ctx);
}

/// Record the response-phase fields once the status and method have been extracted.
///
/// Split from [`record_response_span_attributes`] so the recording logic is
/// unit-testable without constructing a live Pingora session.
pub(super) fn record_response_span_fields(
    status: Option<http::StatusCode>,
    method: &str,
    response: Option<&pingora_http::ResponseHeader>,
    ctx: &PingoraRequestCtx,
) {
    if let Some(status) = status {
        let code = status.as_u16();
        if code > 0 {
            ctx.request_span.record("http.response.status_code", code);
        }
        if status.is_server_error() {
            ctx.request_span.record("otel.status_code", "ERROR");
            // OTel semconv: error.type for an HTTP status is the numeric code
            // as a string, not StatusCode's "{code} {reason}" Display form.
            ctx.request_span.record("error.type", code.to_string().as_str());
        }
    }

    if let Some(route) = &ctx.metrics_route {
        ctx.request_span.record("http.route", route.as_ref());
        ctx.request_span
            .record("otel.name", format!("{method} {route}").as_str());
    }

    if let Some(upstream) = &ctx.upstream_for_retry {
        ctx.request_span.record("upstream.address", upstream.address.as_ref());
    }

    if let Some(cluster) = &ctx.metrics_cluster {
        ctx.request_span.record("upstream.cluster", cluster.as_ref());
    }

    record_upstream_exchange_span(ctx, response);
}

/// Record the upstream-exchange child span's response fields.
fn record_upstream_exchange_span(ctx: &PingoraRequestCtx, response: Option<&pingora_http::ResponseHeader>) {
    if ctx.upstream_exchange_span.is_disabled() {
        return;
    }
    // Prefer the upstream's own status (captured before any response-phase
    // rewrite); fall back to the written response when it was not captured.
    if let Some(status) = ctx
        .upstream_response_status
        .or_else(|| response.map(|resp| resp.status.as_u16()))
    {
        ctx.upstream_exchange_span.record("http.response.status_code", status);
        record_client_status(&ctx.upstream_client_span, status);
    }
    ctx.upstream_exchange_span
        .record("http.response.body.size", ctx.response_body_bytes);
}

/// Record the upstream response on its HTTP client span, including retry responses.
pub(super) fn record_client_status(span: &tracing::Span, status: u16) {
    if span.is_disabled() {
        return;
    }
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
        span.record("error.type", status.to_string().as_str());
    }
}
