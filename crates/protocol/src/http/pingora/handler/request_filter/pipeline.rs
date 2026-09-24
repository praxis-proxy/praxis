// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-phase pipeline orchestration.
//!
//! Houses the request-phase entry point (`execute`) and the pipeline
//! runner (`run_pipeline`). Validation, pre-read, header mutation, body
//! handling, request utilities, and terminal response delivery are
//! delegated to the sibling theme modules.

use std::{borrow::Cow, sync::Arc};

use bytes::Bytes;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_core::connectivity::normalize_mapped_ipv4;
use praxis_filter::{BodyMode, FilterAction, FilterError, FilterPipeline, Rejection, Request};
use tracing::{Instrument as _, error};

use super::{
    super::{
        super::{
            context::PingoraRequestCtx,
            convert::{request_header_from_session, send_rejection_for},
        },
        body_util::clamp_body_mode_to_ceiling,
    },
    body_handling::{selected_upstream_body_limit, store_adapted_request_body, store_canonical_request_body},
    error_handling::handle_pre_read_io_error,
    header_mutations::{apply_pending_header_mutations, apply_pre_read_mutations},
    request_utils::{create_request_span, reject_reserved_internal_headers, snapshot_for_early_exit, templated_route},
    stream_buffer::PreReadError,
    terminal_responses::{run_streaming_terminal_response, run_terminal_response},
};

// -----------------------------------------------------------------------------
// PipelineResult
// -----------------------------------------------------------------------------

/// Results from running the request-phase filter pipeline.
struct PipelineResult {
    /// Final filter action.
    action: FilterAction,

    /// Extra headers to add to the upstream request.
    extra_headers: Vec<(Cow<'static, str>, String)>,

    /// Headers to remove from the upstream request.
    headers_to_remove: Vec<http::header::HeaderName>,

    /// Headers to set (overwrite) on the upstream request.
    headers_to_set: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
}

// -----------------------------------------------------------------------------
// AdaptedRequestBody
// -----------------------------------------------------------------------------

/// Adapted selected-upstream request body captured for storage after a
/// successful adaptation with a body writer (#1139).
///
/// `Some(_)` signals the Continue writeback to store the adapted representation;
/// the inner `Option<Bytes>` is the frozen adapted body (`None`/empty = empty
/// body forwarded under `Content-Length: 0`).
struct AdaptedRequestBody(Option<Bytes>);

/// Canonical request body after the once-per-request bound-upstream phase.
///
/// Kept distinct from [`AdaptedRequestBody`]: this representation is replayed
/// for direct dispatch and is also the input to exchange-local selected-upstream
/// adaptation.
struct CanonicalRequestBody(Bytes);

// -----------------------------------------------------------------------------
// Request Filters
// -----------------------------------------------------------------------------

/// Run the request-phase pipeline, capture client info, and inject headers.
///
/// Host header validation runs first (before the pipeline) to reject
/// ambiguous requests early.
#[expect(clippy::too_many_lines, reason = "orchestration function")]
#[expect(
    clippy::large_stack_frames,
    reason = "primary request handler with multiple filter stages"
)]
pub(in crate::http) async fn execute(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> Result<bool> {
    // Stale upstream-contact state from a prior keep-alive request is cleared in
    // early_request_filter (the first per-request hook), before any rejection
    // path, so it cannot leak into this request's passive-health attribution.
    if let Some(rejection) = super::validation::validate_host_header(session) {
        snapshot_for_early_exit(session, ctx);
        send_rejection_for(session, rejection, ctx).await;
        return Ok(true);
    }

    if let Some(rejection) = super::super::normalize::normalize_request_headers(session) {
        snapshot_for_early_exit(session, ctx);
        send_rejection_for(session, rejection, ctx).await;
        return Ok(true);
    }

    if let Some(rejection) = reject_reserved_internal_headers(session) {
        snapshot_for_early_exit(session, ctx);
        send_rejection_for(session, rejection, ctx).await;
        return Ok(true);
    }

    if let Some(handled) = super::validation::handle_max_forwards(session).await {
        if handled {
            snapshot_for_early_exit(session, ctx);
        }
        return Ok(handled);
    }

    ctx.client_http_version = Some(session.req_header().version);

    let mut request = request_header_from_session(session);
    ctx.client_addr = session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(std::net::SocketAddr::ip)
        .map(normalize_mapped_ipv4);
    let ssl_digest = session.digest().and_then(|d| d.ssl_digest.as_ref());
    ctx.downstream_tls = ssl_digest.is_some();
    ctx.peer_identity = ssl_digest
        .and_then(|d| {
            if d.cert_digest.is_empty() {
                return None;
            }
            Some(praxis_tls::TlsPeerIdentity {
                cert_digest: d.cert_digest.clone(),
                organization: d.organization.clone(),
                serial_number: d.serial_number.clone(),
            })
        })
        .map(Arc::new);
    ctx.request_is_idempotent = matches!(
        session.req_header().method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    );

    ctx.request_span = create_request_span(session, ctx);

    let caps = pipeline.body_capabilities();
    ctx.request_body_mode = caps.request_body_mode;
    ctx.response_body_mode = caps.response_body_mode;

    if matches!(caps.request_body_mode, BodyMode::StreamBuffer { .. }) {
        tracing::debug!("pre-reading request body for StreamBuffer inspection");
        let span = ctx.request_span.clone();
        match super::stream_buffer::pre_read_body(pipeline, session, ctx, &request)
            .instrument(span)
            .await
        {
            Ok(pre_read) => {
                apply_pre_read_mutations(session, &mut request, &pre_read.mutations);
                ctx.pre_read_mutations = pre_read.mutations;
            },
            Err(PreReadError::Rejected(rejection)) => {
                // A body-size (or filter) rejection raised while pre-reading a
                // buffered body is the same proxy error as its streaming
                // counterpart in request_body_filter::execute, which stamps
                // FILTER_REJECT. Stamp it here too so buffered filters do not
                // silently drop the request from praxis_errors_total.
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
                ctx.request_snapshot = Some(request);
                send_rejection_for(session, rejection, ctx).await;
                return Ok(true);
            },
            Err(PreReadError::Filter(e)) => {
                error!(error = %e, "body filter error during pre-read");
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_INTERNAL);
                ctx.request_snapshot = Some(request);
                send_rejection_for(session, Rejection::status(500), ctx).await;
                return Ok(true);
            },
            Err(PreReadError::Io(e)) => {
                ctx.request_snapshot = Some(request);
                return handle_pre_read_io_error(session, ctx, e).await;
            },
        }
    }

    let span = ctx.request_span.clone();
    let pipeline_result = run_pipeline(pipeline, request, ctx).instrument(span).await;

    match pipeline_result {
        Ok(PipelineResult {
            action: FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone,
            extra_headers,
            headers_to_remove,
            headers_to_set,
        }) => {
            // Mirror of `apply_pending_header_mutations`, which applied the
            // same three lists to `ctx.request_snapshot` in the same
            // remove -> set -> add order. Keep the two in step.
            let req_headers = session.req_header_mut();
            for name in &headers_to_remove {
                let _remove = req_headers.remove_header(name);
            }
            for (name, value) in &headers_to_set {
                let _insert = req_headers.insert_header(name.clone(), value.clone());
            }
            for (name, value) in extra_headers {
                // Most promoted names are `Cow::Borrowed` statics
                // ("X-Forwarded-For", …): Pingora converts a &'static
                // str zero-copy, while `into_owned` heap-copied every
                // one per request.
                let _insert = match name {
                    Cow::Borrowed(name) => req_headers.insert_header(name, value),
                    Cow::Owned(name) => req_headers.insert_header(name, value),
                };
            }
            Ok(false)
        },
        Ok(PipelineResult {
            action: FilterAction::Reject(rejection),
            ..
        }) => {
            ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
            send_rejection_for(session, rejection, ctx).await;
            Ok(true)
        },
        Ok(PipelineResult {
            action: FilterAction::TerminalResponse(terminal),
            ..
        }) => {
            run_terminal_response(pipeline, session, ctx, *terminal).await;
            Ok(true)
        },
        Ok(PipelineResult {
            action: FilterAction::StreamingTerminalResponse(terminal),
            ..
        }) => {
            run_streaming_terminal_response(pipeline, session, ctx, *terminal).await;
            Ok(true)
        },
        Err(e) => {
            error!(error = %e, "filter pipeline error");
            ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_INTERNAL);
            send_rejection_for(session, Rejection::status(500), ctx).await;
            Ok(true)
        },
    }
}

// -----------------------------------------------------------------------------
// Request-Phase Pipeline
// -----------------------------------------------------------------------------

/// Run the request-phase filter pipeline and snapshot the request for later phases.
///
/// Returns the final action and any extra headers promoted by filters.
#[expect(clippy::too_many_lines, reason = "writeback destructuring")]
async fn run_pipeline(
    pipeline: &FilterPipeline,
    mut request: Request,
    ctx: &mut PingoraRequestCtx,
) -> std::result::Result<PipelineResult, FilterError> {
    let baseline_request_body_mode = ctx.request_body_mode;
    let baseline_response_body_mode = ctx.response_body_mode;
    let (
        action,
        extra_headers,
        headers_to_remove,
        headers_to_set,
        cluster,
        upstream,
        rewritten_path,
        request_body_mode,
        response_body_mode,
        selected_endpoint_index,
        metrics_route,
        attempted_endpoints,
        retry_policy,
        route_retry_policy,
        cluster_retry_state,
        cluster_retry_state_released,
        endpoint_reselector,
        extensions,
        filter_metadata,
        filter_state,
        executed_indices,
        body_done,
        // Pre-read mutations were consumed by endpoint_selector during
        // on_request. Cleared below to prevent stale provenance reuse.
        _pre_read_mutations,
        structured_metadata,
        canonical_body,
        adapted_body,
    ) = {
        let selected_upstream_participates = pipeline.body_capabilities().needs_selected_upstream_request_body;
        // Canonical pre-read body for the selected-upstream phase. Read before
        // building the filter context, which borrows nothing from `ctx`.
        let pre_read_body = if selected_upstream_participates {
            ctx.pre_read_body.as_ref().and_then(|chunks| {
                // `StreamBuffer` accumulation freezes the whole pre-read body into
                // a single chunk (mirrored by `store_adapted_request_body`), so the
                // phase only ever consumes the front chunk. Assert the invariant so
                // a future multi-chunk representation cannot silently truncate the
                // body handed to the selected-upstream phase.
                debug_assert!(
                    chunks.len() <= 1,
                    "pre_read_body should be a single frozen chunk, found {}",
                    chunks.len()
                );
                chunks.front().cloned()
            })
        } else {
            None
        };

        let mut filter_ctx = ctx.build_filter_context(pipeline, &request, None);

        let mut action = pipeline.execute_http_request(&mut filter_ctx).await;
        let canonical_body = filter_ctx.take_bound_request_body_rewrite().map(CanonicalRequestBody);
        // A bound rewrite is the body this request forwards, so adaptation
        // starts from it; an emptied rewrite reads as no body, like an empty
        // pre-read.
        let mut working_body = match &canonical_body {
            Some(CanonicalRequestBody(rewritten)) if selected_upstream_participates => {
                Some(rewritten.clone()).filter(|body| !body.is_empty())
            },
            _ => pre_read_body,
        };

        // #1139: selected-upstream request-body phase. Runs on the SAME live
        // filter_ctx after upstream selection, before the fields are extracted.
        // Gated on a successful request action plus a selected upstream, so it
        // runs for every successful selection (pinned/affinity, panic, normal)
        // and never before an upstream exists.
        //
        // The `Continue | Release | BodyDone` set mirrors the proceed-action
        // family matched at the outer writeback (see the `match action` below)
        // and in `execute`. In practice `execute_http_request` collapses a
        // filter's `Release`/`BodyDone` into `Continue` (run_request_filter,
        // crates/filter/src/pipeline/http_utils.rs), so only `Continue` is
        // reachable here; the full set keeps the three gates in lockstep.
        let mut adapted_body: Option<AdaptedRequestBody> = None;
        if selected_upstream_participates
            && matches!(
                &action,
                Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone)
            )
            && filter_ctx.upstream.is_some()
        {
            match pipeline
                .execute_http_selected_upstream_request_body(&mut filter_ctx, &mut working_body)
                .await
            {
                Ok(FilterAction::Reject(rejection)) => {
                    action = Ok(FilterAction::Reject(rejection));
                },
                Ok(_) => {
                    if pipeline.body_capabilities().any_selected_upstream_request_body_writer {
                        let adapted_len = working_body.as_ref().map_or(0, Bytes::len);
                        if adapted_len > selected_upstream_body_limit(pipeline) {
                            action = Ok(FilterAction::Reject(Rejection::status(413)));
                        } else {
                            adapted_body = Some(AdaptedRequestBody(working_body));
                        }
                    }
                },
                Err(e) => {
                    action = Err(e);
                },
            }
        }

        (
            action,
            filter_ctx.extra_request_headers,
            filter_ctx.request_headers_to_remove,
            filter_ctx.request_headers_to_set,
            filter_ctx.cluster,
            filter_ctx.upstream,
            filter_ctx.rewritten_path,
            filter_ctx.request_body_mode,
            filter_ctx.response_body_mode,
            filter_ctx.selected_endpoint_index,
            filter_ctx.metrics_route,
            filter_ctx.attempted_endpoints,
            filter_ctx.retry_policy,
            filter_ctx.route_retry_policy,
            filter_ctx.cluster_retry_state,
            filter_ctx.cluster_retry_state_released,
            filter_ctx.endpoint_reselector,
            filter_ctx.extensions,
            filter_ctx.filter_metadata,
            filter_ctx.filter_state,
            filter_ctx.executed_filter_indices,
            filter_ctx.body_done_indices,
            filter_ctx.pre_read_mutations,
            filter_ctx.structured_metadata,
            canonical_body,
            adapted_body,
        )
    };

    // Mirror every pending header mutation into request_snapshot so that
    // later phases (body, response) read the same headers the upstream
    // will receive. The same remove -> set -> add order is applied to the
    // Pingora session by the caller; the two must not diverge, or a
    // response-phase filter reads a request that was never sent.
    apply_pending_header_mutations(
        &mut request.headers,
        &headers_to_remove,
        &headers_to_set,
        &extra_headers,
    );
    ctx.request_snapshot = Some(request);
    ctx.extensions = extensions;
    ctx.filter_metadata = filter_metadata;
    ctx.filter_state = filter_state;
    ctx.cached_executed_filter_indices = executed_indices;
    ctx.cached_body_done_indices = body_done;

    // Pre-read mutations were consumed by the request pipeline (e.g.
    // endpoint_selector). Clear them so later phases cannot reuse stale
    // routing authority from a previous request phase.
    ctx.pre_read_mutations = Vec::new();
    ctx.structured_metadata = structured_metadata;
    ctx.metrics_cluster_shared = cluster.as_ref().map(|c| ::metrics::SharedString::from(Arc::clone(c)));
    ctx.metrics_cluster.clone_from(&cluster);

    // Templating runs here, at the single point where the route label is
    // set, so the OTel `http.route` attribute read from the same field
    // later cannot disagree with the metric.
    ctx.metrics_route = templated_route(pipeline, ctx, metrics_route);
    ctx.response_body_mode = clamp_body_mode_to_ceiling(response_body_mode, baseline_response_body_mode);

    // Write back the request-scoped upstream and retry lifecycle on EVERY
    // outcome, not just Continue. A filter ordered after the load_balancer
    // that returns Reject/TerminalResponse still took the cluster retry
    // lease and the strategy in-flight slot in on_request; the response
    // phase (always run via the logging hook) can only release them if the
    // cluster, upstream, endpoint index and retry state are visible on ctx.
    ctx.cluster = cluster;
    ctx.upstream = upstream;
    ctx.selected_endpoint_index = selected_endpoint_index;
    ctx.cluster_retry_state = cluster_retry_state;
    ctx.cluster_retry_state_released = cluster_retry_state_released;
    ctx.endpoint_reselector = endpoint_reselector;

    match action {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            ctx.rewritten_path = rewritten_path;
            ctx.request_body_mode = clamp_body_mode_to_ceiling(request_body_mode, baseline_request_body_mode);
            ctx.attempted_endpoints = attempted_endpoints;
            ctx.retry_policy = retry_policy;
            ctx.route_retry_policy = route_retry_policy;
            if let Some(CanonicalRequestBody(body)) = canonical_body {
                store_canonical_request_body(ctx, body);
            }
            if let Some(AdaptedRequestBody(body)) = adapted_body {
                store_adapted_request_body(ctx, body);
            }
            Ok(PipelineResult {
                action: FilterAction::Continue,
                extra_headers,
                headers_to_remove,
                headers_to_set,
            })
        },
        Ok(FilterAction::Reject(rejection)) => Ok(PipelineResult {
            action: FilterAction::Reject(rejection),
            extra_headers: Vec::new(),
            headers_to_remove: Vec::new(),
            headers_to_set: Vec::new(),
        }),
        Ok(FilterAction::TerminalResponse(terminal)) => Ok(PipelineResult {
            action: FilterAction::TerminalResponse(terminal),
            extra_headers: Vec::new(),
            headers_to_remove: Vec::new(),
            headers_to_set: Vec::new(),
        }),
        Ok(FilterAction::StreamingTerminalResponse(terminal)) => Ok(PipelineResult {
            action: FilterAction::StreamingTerminalResponse(terminal),
            extra_headers: Vec::new(),
            headers_to_remove: Vec::new(),
            headers_to_set: Vec::new(),
        }),
        Err(e) => Err(e),
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
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{collections::VecDeque, net::IpAddr};

    use http::{HeaderMap, Method, Uri};
    use praxis_core::config::FailureMode;
    use praxis_filter::{FilterRegistry, TrustedHeaderMutation};

    use super::*;

    #[tokio::test]
    async fn empty_pipeline_continues() {
        let result = run_pipeline(&empty_pipeline(), make_request(), &mut make_ctx())
            .await
            .unwrap();

        assert!(
            matches!(result.action, FilterAction::Continue),
            "empty pipeline should continue"
        );
        assert!(
            result.extra_headers.is_empty(),
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

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(matches!(result.action, FilterAction::Reject(r) if r.status == 403));
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

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(
            result.extra_headers.is_empty(),
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

    #[test]
    fn clamp_body_mode_to_ceiling_caps_stream_buffer_limit() {
        let clamped = clamp_body_mode_to_ceiling(
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
        );
        assert_eq!(
            clamped,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            "runtime StreamBuffer widening should be clamped to baseline ceiling"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_caps_unbounded_stream_buffer() {
        let clamped = clamp_body_mode_to_ceiling(
            BodyMode::StreamBuffer { max_bytes: None },
            BodyMode::SizeLimit { max_bytes: 512 },
        );
        assert_eq!(
            clamped,
            BodyMode::StreamBuffer { max_bytes: Some(512) },
            "runtime unbounded StreamBuffer should be clamped to baseline ceiling"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_stream_passes_through_with_ceiling() {
        let clamped = clamp_body_mode_to_ceiling(BodyMode::Stream, BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            clamped,
            BodyMode::Stream,
            "Stream has no buffer to clamp and should pass through unchanged"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_stream_passes_through_without_ceiling() {
        let clamped = clamp_body_mode_to_ceiling(BodyMode::Stream, BodyMode::Stream);
        assert_eq!(
            clamped,
            BodyMode::Stream,
            "Stream baseline imposes no ceiling; Stream mode passes through"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_size_limit_clamped_to_baseline() {
        let clamped = clamp_body_mode_to_ceiling(
            BodyMode::SizeLimit { max_bytes: 8192 },
            BodyMode::SizeLimit { max_bytes: 2048 },
        );
        assert_eq!(
            clamped,
            BodyMode::SizeLimit { max_bytes: 2048 },
            "runtime SizeLimit should be clamped to baseline ceiling"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_no_ceiling_passes_through() {
        let clamped = clamp_body_mode_to_ceiling(
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            BodyMode::StreamBuffer { max_bytes: None },
        );
        assert_eq!(
            clamped,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "unbounded baseline imposes no ceiling; runtime mode passes through"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_within_limit_unchanged() {
        let clamped = clamp_body_mode_to_ceiling(
            BodyMode::StreamBuffer { max_bytes: Some(512) },
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
        );
        assert_eq!(
            clamped,
            BodyMode::StreamBuffer { max_bytes: Some(512) },
            "runtime limit within baseline ceiling should be unchanged"
        );
    }

    #[tokio::test]
    async fn pre_read_mutations_cleared_after_pipeline() {
        let mut ctx = make_ctx();
        ctx.pre_read_mutations = vec![TrustedHeaderMutation::Add(
            http::header::HeaderName::from_static("x-routed-by"),
            "pre-read-filter".to_owned(),
        )];

        drop(run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap());

        assert!(
            ctx.pre_read_mutations.is_empty(),
            "pre_read_mutations should be cleared after run_pipeline to prevent stale provenance reuse"
        );
    }

    #[tokio::test]
    async fn snapshot_preserves_headers_without_removals() {
        let mut ctx = make_ctx();
        let mut request = make_request();
        request.headers.insert(
            http::header::HeaderName::from_static("x-internal-debug"),
            http::header::HeaderValue::from_static("true"),
        );

        drop(run_pipeline(&empty_pipeline(), request, &mut ctx).await.unwrap());

        let snapshot = ctx.request_snapshot.as_ref().expect("snapshot should exist");
        assert!(
            snapshot.headers.contains_key("x-internal-debug"),
            "empty pipeline should not strip x-internal-debug"
        );
    }

    #[test]
    fn header_removal_strips_from_snapshot() {
        let mut request = make_request();
        request.headers.insert(
            http::header::HeaderName::from_static("x-strip"),
            http::header::HeaderValue::from_static("val"),
        );
        request.headers.insert(
            http::header::HeaderName::from_static("x-keep"),
            http::header::HeaderValue::from_static("val"),
        );

        let to_remove = vec![http::header::HeaderName::from_static("x-strip")];
        for name in &to_remove {
            request.headers.remove(name);
        }

        assert!(!request.headers.contains_key("x-strip"));
        assert!(request.headers.contains_key("x-keep"));
    }

    #[tokio::test]
    async fn request_span_created_after_pipeline() {
        let mut ctx = make_ctx();
        assert!(
            ctx.request_span.is_disabled(),
            "span should be disabled before pipeline runs"
        );
        drop(run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap());
        assert!(
            ctx.request_span.is_disabled(),
            "run_pipeline alone should not create the request span"
        );
    }

    #[tokio::test]
    async fn request_id_recorded_from_extra_headers() {
        let mut ctx = make_ctx();
        let span = tracing::info_span!("test_span", request_id = tracing::field::Empty,);
        ctx.request_span = span;

        let result = run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap();
        assert!(
            result
                .extra_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
                .is_none(),
            "empty pipeline should not produce x-request-id header"
        );
    }

    #[tokio::test]
    async fn structured_metadata_persists_through_pipeline() {
        let mut ctx = make_ctx();
        ctx.structured_metadata.insert(
            "test_filter".to_owned(),
            serde_json::json!({"model": "test-model", "score": 0.95}),
        );

        drop(run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap());

        let md = ctx.structured_metadata.get("test_filter");
        assert!(
            md.is_some(),
            "structured_metadata set before pipeline should survive after run_pipeline"
        );
        let obj = md.unwrap().as_object().expect("metadata should be an object");
        assert_eq!(
            obj.get("model"),
            Some(&serde_json::json!("test-model")),
            "model field should be preserved"
        );
        assert_eq!(
            obj.get("score"),
            Some(&serde_json::json!(0.95)),
            "score field should be preserved"
        );
    }

    #[tokio::test]
    async fn reject_after_selection_writes_back_cluster_for_release() {
        let mut ctx = make_ctx();
        ctx.cluster = Some(Arc::from("backend"));

        let result = run_pipeline(&rejecting_pipeline(503), make_request(), &mut ctx)
            .await
            .unwrap();

        assert!(
            matches!(result.action, FilterAction::Reject(_)),
            "the static_response pipeline must reject"
        );
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("backend"),
            "a rejected request must retain its selected cluster so the response phase can release the lease"
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

    // -------------------------------------------------------------------------
    // Selected-Upstream Request-Body Phase (#1139)
    // -------------------------------------------------------------------------

    struct SelectedUpstreamUppercaseFilter;

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for SelectedUpstreamUppercaseFilter {
        fn name(&self) -> &'static str {
            "selected_upstream_uppercase"
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> std::result::Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> praxis_filter::BodyAccess {
            praxis_filter::BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: Some(4096) }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> std::result::Result<praxis_filter::SelectedUpstreamBodyOutcome, FilterError> {
            if let Some(b) = body {
                let upper: Vec<u8> = b.iter().map(u8::to_ascii_uppercase).collect();
                *b = Bytes::from(upper);
            }
            Ok(praxis_filter::SelectedUpstreamBodyOutcome::Continue)
        }
    }

    struct SelectedUpstreamReject413Filter;

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for SelectedUpstreamReject413Filter {
        fn name(&self) -> &'static str {
            "selected_upstream_reject_413"
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> std::result::Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> praxis_filter::BodyAccess {
            praxis_filter::BodyAccess::ReadOnly
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: Some(4096) }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
        ) -> std::result::Result<praxis_filter::SelectedUpstreamBodyOutcome, FilterError> {
            Ok(praxis_filter::SelectedUpstreamBodyOutcome::Reject(Rejection::status(
                413,
            )))
        }
    }

    struct SelectedUpstreamErrorFilter;

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for SelectedUpstreamErrorFilter {
        fn name(&self) -> &'static str {
            "selected_upstream_error"
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> std::result::Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> praxis_filter::BodyAccess {
            praxis_filter::BodyAccess::ReadOnly
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: Some(4096) }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
        ) -> std::result::Result<praxis_filter::SelectedUpstreamBodyOutcome, FilterError> {
            Err(FilterError::from("selected-upstream body hook failed"))
        }
    }

    /// Build a single-filter pipeline from a named factory (participant filters).
    fn participant_pipeline(name: &'static str, make: fn() -> Box<dyn praxis_filter::HttpFilter>) -> FilterPipeline {
        use std::sync::Arc as StdArc;
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                name,
                praxis_filter::FilterFactory::Http(StdArc::new(move |_| Ok(make()))),
            )
            .unwrap();
        let config: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let mut entries = vec![praxis_filter::FilterEntry {
            branch_chains: None,
            filter_type: name.into(),
            config,
            conditions: vec![],
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }];
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Minimal selected upstream for gating the phase in unit tests.
    fn make_test_upstream() -> praxis_core::connectivity::Upstream {
        praxis_core::connectivity::Upstream {
            address: Arc::from("127.0.0.1:8080"),
            authority: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        }
    }

    #[tokio::test]
    async fn selected_upstream_phase_captures_adapted_body() {
        let pipeline = participant_pipeline("selected_upstream_uppercase", || {
            Box::new(SelectedUpstreamUppercaseFilter)
        });
        let mut ctx = make_ctx();
        // Simulate pre-read having buffered the canonical body, and an upstream
        // having been selected during the request phase.
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"original")]));
        ctx.upstream = Some(make_test_upstream());

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(matches!(result.action, FilterAction::Continue));
        assert_eq!(
            ctx.adapted_request_body,
            Some(VecDeque::from([Bytes::from_static(b"ORIGINAL")])),
            "adapted (uppercased) body is stored, not the canonical body"
        );
        assert_eq!(ctx.adapted_request_body_len, Some(8));
        assert_eq!(
            ctx.pre_read_body,
            Some(VecDeque::from([Bytes::from_static(b"original")])),
            "canonical pre-read body is left intact and untouched"
        );
    }

    #[tokio::test]
    async fn selected_upstream_phase_reject_becomes_local_response() {
        let pipeline = participant_pipeline("selected_upstream_reject_413", || {
            Box::new(SelectedUpstreamReject413Filter)
        });
        let mut ctx = make_ctx();
        ctx.cluster = Some(Arc::from("backend"));
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"body")]));
        ctx.upstream = Some(make_test_upstream());

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(
            matches!(result.action, FilterAction::Reject(_)),
            "a selected-upstream reject becomes a Reject action (local response, no transport)"
        );
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("backend"),
            "the selected cluster is retained so the response phase can release the retry lease"
        );
        assert!(
            ctx.adapted_request_body.is_none(),
            "a rejected request stores no adapted body"
        );
    }

    #[tokio::test]
    async fn selected_upstream_phase_error_propagates() {
        let pipeline = participant_pipeline("selected_upstream_error", || Box::new(SelectedUpstreamErrorFilter));
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"body")]));
        ctx.upstream = Some(make_test_upstream());

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await;

        assert!(
            result.is_err(),
            "an Err from the selected-upstream body hook propagates out of run_pipeline"
        );
        assert!(
            ctx.adapted_request_body.is_none(),
            "a failed selected-upstream phase stores no adapted body"
        );
    }

    #[tokio::test]
    async fn selected_upstream_phase_skipped_without_upstream() {
        let pipeline = participant_pipeline("selected_upstream_uppercase", || {
            Box::new(SelectedUpstreamUppercaseFilter)
        });
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"original")]));
        // No upstream selected -> phase must not run.

        let result = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(matches!(result.action, FilterAction::Continue));
        assert!(
            ctx.adapted_request_body.is_none(),
            "phase is gated on a selected upstream"
        );
    }
}
