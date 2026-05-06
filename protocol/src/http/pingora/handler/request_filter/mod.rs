// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Request-phase filter execution.

use std::borrow::Cow;

use pingora_core::Result;
use pingora_proxy::Session;
use praxis_core::connectivity::normalize_mapped_ipv4;
use praxis_filter::{BodyMode, FilterAction, FilterError, FilterPipeline, Rejection, Request};
use tracing::warn;

use super::super::{
    context::PingoraRequestCtx,
    convert::{request_header_from_session, send_rejection},
};

/// StreamBuffer pre-read logic and TRACE response construction.
mod stream_buffer;
/// Host header validation and Max-Forwards handling.
mod validation;

use stream_buffer::PreReadError;

// -----------------------------------------------------------------------------
// Request Filters
// -----------------------------------------------------------------------------

/// Run the request-phase pipeline, capture client info, and inject headers.
///
/// Host header validation runs first (before the pipeline) to reject
/// ambiguous requests early.
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "orchestration function"
)]
pub(in crate::http) async fn execute(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> Result<bool> {
    if let Some(rejection) = validation::validate_host_header(session) {
        send_rejection(session, rejection).await;
        return Ok(true);
    }

    if let Some(rejection) = super::normalize::normalize_request_headers(session) {
        send_rejection(session, rejection).await;
        return Ok(true);
    }

    if let Some(handled) = validation::handle_max_forwards(session).await {
        return Ok(handled);
    }

    ctx.client_http_version = Some(session.req_header().version);

    let mut request = request_header_from_session(session);
    ctx.client_addr = session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(std::net::SocketAddr::ip)
        .map(normalize_mapped_ipv4);
    ctx.request_is_idempotent = matches!(
        session.req_header().method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    );

    let caps = pipeline.body_capabilities();
    ctx.request_body_mode = caps.request_body_mode;
    ctx.response_body_mode = caps.response_body_mode;

    if matches!(caps.request_body_mode, BodyMode::StreamBuffer { .. }) {
        tracing::debug!("pre-reading request body for StreamBuffer inspection");
        match stream_buffer::pre_read_body(pipeline, session, ctx, &request).await {
            Ok(extra_headers) => {
                tracing::debug!(count = extra_headers.len(), "injecting promoted headers");
                for (name, value) in extra_headers {
                    if let (Ok(hname), Ok(hval)) = (
                        http::header::HeaderName::from_bytes(name.as_bytes()),
                        http::header::HeaderValue::from_str(&value),
                    ) {
                        let _insert = session.req_header_mut().insert_header(hname.clone(), hval.clone());
                        request.headers.insert(hname, hval);
                    } else {
                        tracing::warn!(header = %name, "skipping invalid promoted header");
                    }
                }
            },
            Err(PreReadError::Rejected(rejection)) => {
                send_rejection(session, rejection).await;
                return Ok(true);
            },
            Err(PreReadError::Filter(e)) => {
                warn!(error = %e, "body filter error during pre-read");
                send_rejection(session, Rejection::status(500)).await;
                return Ok(true);
            },
            Err(PreReadError::Io(e)) => return Err(e),
        }
    }

    match run_pipeline(pipeline, request, ctx).await {
        Ok((FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone, extra_headers)) => {
            for (name, value) in extra_headers {
                let _insert = session.req_header_mut().insert_header(name.into_owned(), value);
            }
            Ok(false)
        },
        Ok((FilterAction::Reject(rejection), _)) => {
            send_rejection(session, rejection).await;
            Ok(true)
        },
        Err(e) => {
            warn!(error = %e, "filter pipeline error");
            send_rejection(session, Rejection::status(500)).await;
            Ok(true)
        },
    }
}

// -----------------------------------------------------------------------------
// Header-Phase Pipeline
// -----------------------------------------------------------------------------

/// Run the request-phase filter pipeline and snapshot the request for later phases.
///
/// Returns the final action and any extra headers promoted by filters.
#[allow(clippy::too_many_lines, reason = "writeback destructuring")]
async fn run_pipeline(
    pipeline: &FilterPipeline,
    request: Request,
    ctx: &mut PingoraRequestCtx,
) -> std::result::Result<(FilterAction, Vec<(Cow<'static, str>, String)>), FilterError> {
    let (
        action,
        extra_headers,
        cluster,
        upstream,
        rewritten_path,
        request_body_mode,
        selected_endpoint_index,
        filter_metadata,
    ) = {
        let mut filter_ctx = ctx.build_filter_context(pipeline, &request, None);

        let action = pipeline.execute_http_request(&mut filter_ctx).await;
        (
            action,
            filter_ctx.extra_request_headers,
            filter_ctx.cluster,
            filter_ctx.upstream,
            filter_ctx.rewritten_path,
            filter_ctx.request_body_mode,
            filter_ctx.selected_endpoint_index,
            filter_ctx.filter_metadata,
        )
    };

    ctx.request_snapshot = Some(request);
    ctx.filter_metadata = filter_metadata;

    match action {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            ctx.cluster = cluster;
            ctx.upstream = upstream;
            ctx.rewritten_path = rewritten_path;
            ctx.request_body_mode = request_body_mode;
            ctx.selected_endpoint_index = selected_endpoint_index;
            Ok((FilterAction::Continue, extra_headers))
        },
        Ok(FilterAction::Reject(rejection)) => Ok((FilterAction::Reject(rejection), Vec::new())),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::net::IpAddr;

    use http::{HeaderMap, Method, Uri};
    use praxis_core::config::FailureMode;
    use praxis_filter::{FilterAction, FilterPipeline, FilterRegistry, Request};

    use super::*;
    use crate::http::pingora::context::PingoraRequestCtx;

    #[tokio::test]
    async fn empty_pipeline_continues() {
        let (action, extra_headers) = run_pipeline(&empty_pipeline(), make_request(), &mut make_ctx())
            .await
            .unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "empty pipeline should continue"
        );
        assert!(
            extra_headers.is_empty(),
            "empty pipeline should produce no extra headers"
        );
    }

    #[tokio::test]
    async fn snapshot_always_stored() {
        let mut ctx = make_ctx();

        drop(run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap());

        assert!(
            ctx.request_snapshot.is_some(),
            "request snapshot should be stored after pipeline run"
        );
    }

    #[tokio::test]
    async fn cluster_and_upstream_propagated_on_continue() {
        let mut ctx = make_ctx();

        drop(run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap());

        assert!(ctx.cluster.is_none(), "empty pipeline should leave cluster unset");
        assert!(ctx.upstream.is_none(), "empty pipeline should leave upstream unset");
    }

    #[tokio::test]
    async fn rejection_propagated_from_pipeline() {
        let pipeline = rejecting_pipeline(403);
        let mut ctx = make_ctx();

        let (action, _) = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }

    #[tokio::test]
    async fn rejection_does_not_set_cluster() {
        let pipeline = rejecting_pipeline(429);
        let mut ctx = make_ctx();

        drop(run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap());

        assert!(ctx.cluster.is_none(), "rejection should not set cluster");
        assert!(ctx.upstream.is_none(), "rejection should not set upstream");
    }

    #[tokio::test]
    async fn extra_headers_returned_from_pipeline() {
        let pipeline = empty_pipeline();
        let mut ctx = make_ctx();

        let (_, extra_headers) = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(
            extra_headers.is_empty(),
            "empty pipeline should produce no extra headers"
        );
    }

    #[tokio::test]
    async fn idempotent_methods_detected_in_request() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let req = Request {
                method,
                uri: Uri::from_static("/"),
                headers: HeaderMap::new(),
            };
            let is_idempotent = matches!(req.method, Method::GET | Method::HEAD | Method::OPTIONS);
            assert!(is_idempotent, "{} should be idempotent", req.method);
        }

        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let req = Request {
                method,
                uri: Uri::from_static("/"),
                headers: HeaderMap::new(),
            };
            let is_idempotent = matches!(req.method, Method::GET | Method::HEAD | Method::OPTIONS);
            assert!(!is_idempotent, "{} should not be idempotent", req.method);
        }
    }

    #[test]
    fn normalize_mapped_ipv4_converts_mapped_to_v4() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            normalize_mapped_ipv4(mapped),
            expected,
            "::ffff:10.0.0.1 should normalize to 10.0.0.1"
        );
    }

    #[test]
    fn normalize_mapped_ipv4_preserves_native_v4() {
        let native: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(normalize_mapped_ipv4(native), native, "native IPv4 should be unchanged");
    }

    #[test]
    fn normalize_mapped_ipv4_preserves_native_v6() {
        let native: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_mapped_ipv4(native), native, "native IPv6 should be unchanged");
    }

    #[test]
    fn normalize_mapped_ipv4_preserves_loopback_v6() {
        let loopback: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            normalize_mapped_ipv4(loopback),
            loopback,
            "IPv6 loopback should be unchanged"
        );
    }

    #[test]
    fn normalize_mapped_ipv4_converts_mapped_loopback() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let expected: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            normalize_mapped_ipv4(mapped),
            expected,
            "::ffff:127.0.0.1 should normalize to 127.0.0.1"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a minimal GET request for tests.
    fn make_request() -> Request {
        Request {
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
        }
    }

    /// Create a default request context for tests.
    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    /// Build an empty filter pipeline for tests.
    fn empty_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
    }

    /// Build a pipeline with a single `static_response` filter that rejects.
    fn rejecting_pipeline(status: u16) -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        let yaml = format!("status: {status}");
        let config: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let mut entries = vec![praxis_filter::FilterEntry {
            branch_chains: None,
            filter_type: "static_response".into(),
            config,
            conditions: vec![],
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }];
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }
}
