// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-phase utilities for span creation, snapshotting, and validation.
//!
//! Provides helpers for OpenTelemetry span creation, request snapshot
//! population, reserved header validation, and route template matching.

use pingora_proxy::Session;
use praxis_core::connectivity::normalize_mapped_ipv4;
use praxis_filter::{FilterPipeline, Rejection};
use tracing::warn;

use super::super::{
    super::{context::PingoraRequestCtx, convert::request_header_from_session},
    span_util::http_version_label,
};

/// Populate the request snapshot and client address for a pre-pipeline exit.
///
/// The fallback access record built during the logging phase needs a
/// request snapshot; rejections issued before the pipeline runs (Host
/// validation, header normalization, reserved-header and Max-Forwards
/// handling) would otherwise leave it unset and the record silently
/// skipped: precisely the requests operators most want logged.
pub(super) fn snapshot_for_early_exit(session: &mut Session, ctx: &mut PingoraRequestCtx) {
    if ctx.request_snapshot.is_none() {
        ctx.request_snapshot = Some(request_header_from_session(session));
    }
    if ctx.client_addr.is_none() {
        ctx.client_addr = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(std::net::SocketAddr::ip)
            .map(normalize_mapped_ipv4);
    }
}

/// Reject client-supplied reserved internal headers before special handling
/// or filter execution can observe them.
pub(super) fn reject_reserved_internal_headers(session: &Session) -> Option<Rejection> {
    let reserved_count = session
        .req_header()
        .headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()))
        .count();

    if reserved_count == 0 {
        return None;
    }

    warn!(
        count = reserved_count,
        "rejecting request with client-supplied reserved internal headers"
    );
    Some(Rejection::status(400))
}

/// Collapse the route label to a configured path template when one matches.
///
/// Falls back to the router's path-match pattern when no template matches,
/// so an unmatched path never widens cardinality. Returns immediately when
/// no templates are configured, which is the default.
pub(super) fn templated_route(
    pipeline: &FilterPipeline,
    ctx: &PingoraRequestCtx,
    metrics_route: Option<::metrics::SharedString>,
) -> Option<::metrics::SharedString> {
    let templates = pipeline.route_templates();
    if templates.is_empty() {
        return metrics_route;
    }
    ctx.request_snapshot
        .as_ref()
        .and_then(|request| templates.match_path(request.uri.path()))
        .map(|label| ::metrics::SharedString::from(label.to_owned()))
        .or(metrics_route)
}

/// Build the root tracing span for a request with `OTel` HTTP semantic
/// convention attributes.
///
/// Creates an [`info_span!`] named `"http_request"` with the
/// [OTel span name] initially set to `{method}`, upgraded to
/// `{method} {route}` when a route is matched. Span kind is `SERVER`.
/// Response-phase attributes (`http.response.status_code`,
/// `http.route`, `error.type`, `upstream.address`, `upstream.cluster`,
/// `otel.status_code`) are declared as [`Empty`] and recorded later
/// via [`record_response_span_attributes`].
///
/// [`info_span!`]: tracing::info_span
/// [OTel span name]: https://opentelemetry.io/docs/specs/semconv/http/http-spans/
/// [`Empty`]: tracing::field::Empty
/// [`record_response_span_attributes`]: super::super::span_util::record_response_span_attributes
#[expect(
    clippy::too_many_lines,
    reason = "OTel semantic convention attributes require many span fields"
)]
pub(super) fn create_request_span(session: &Session, ctx: &PingoraRequestCtx) -> tracing::Span {
    let method = session.req_header().method.as_str();
    let path = session.req_header().uri.path();
    let path = if path.is_empty() { "/" } else { path };
    let protocol_version = http_version_label(ctx.client_http_version.unwrap_or(http::Version::HTTP_11));
    let host = session.req_header().headers.get("host").and_then(|v| v.to_str().ok());
    let server_address = host.map(|h| h.split(':').next().unwrap_or(h));
    let server_port = host.and_then(|h| h.split_once(':').and_then(|(_, p)| p.parse::<u16>().ok()));
    let url_scheme = if ctx.downstream_tls { "https" } else { "http" };
    let user_agent = session
        .req_header()
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok());

    let span = tracing::info_span!(
        "http_request",
        "otel.name" = method,
        "otel.kind" = "server",
        "otel.status_code" = tracing::field::Empty,
        "http.request.method" = method,
        "http.route" = tracing::field::Empty,
        "url.scheme" = url_scheme,
        "url.path" = path,
        "http.response.status_code" = tracing::field::Empty,
        "error.type" = tracing::field::Empty,
        "server.address" = server_address,
        "server.port" = server_port,
        "client.address" = tracing::field::Empty,
        "upstream.address" = tracing::field::Empty,
        "network.protocol.version" = protocol_version,
        "user_agent.original" = user_agent,
        "upstream.cluster" = tracing::field::Empty,
        request_id = tracing::field::Empty,
    );

    if let Some(addr) = &ctx.client_addr {
        span.record("client.address", tracing::field::display(addr));
    }

    span
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_filter::FilterRegistry;

    use super::*;

    fn empty_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
    }

    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    #[test]
    fn templated_route_no_templates() {
        let pipeline = empty_pipeline();
        let ctx = make_ctx();
        let input_route = Some(::metrics::SharedString::from("raw-route".to_owned()));

        let result = templated_route(&pipeline, &ctx, input_route.clone());

        assert_eq!(result, input_route, "no templates should return input unchanged");
    }

    #[test]
    fn templated_route_no_request_snapshot() {
        let pipeline = empty_pipeline();
        let ctx = make_ctx();

        let result = templated_route(&pipeline, &ctx, None);

        assert!(result.is_none(), "no snapshot should return None");
    }
}
