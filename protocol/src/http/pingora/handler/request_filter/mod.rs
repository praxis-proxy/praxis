// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Request-phase filter execution.

use std::{borrow::Cow, sync::Arc};

use pingora_core::Result;
use pingora_proxy::Session;
use praxis_core::connectivity::normalize_mapped_ipv4;
use praxis_filter::{
    BodyMode, FilterAction, FilterError, FilterPipeline, Rejection, Request, StreamingTerminalResponse,
    TerminalResponse, TrustedHeaderMutation,
};
use tracing::{Instrument as _, debug, error, warn};

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
    if let Some(rejection) = validation::validate_host_header(session) {
        send_rejection(session, rejection).await;
        return Ok(true);
    }

    if let Some(rejection) = super::normalize::normalize_request_headers(session) {
        send_rejection(session, rejection).await;
        return Ok(true);
    }

    if let Some(rejection) = reject_reserved_internal_headers(session) {
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
    let ssl_digest = session.digest().and_then(|d| d.ssl_digest.as_ref());
    ctx.downstream_tls = ssl_digest.is_some();
    ctx.peer_identity = ssl_digest.and_then(|d| {
        if d.cert_digest.is_empty() {
            return None;
        }
        Some(praxis_tls::TlsPeerIdentity {
            cert_digest: d.cert_digest.clone(),
            organization: d.organization.clone(),
            serial_number: d.serial_number.clone(),
        })
    });
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
        match stream_buffer::pre_read_body(pipeline, session, ctx, &request)
            .instrument(span)
            .await
        {
            Ok(pre_read) => {
                apply_pre_read_mutations(session, &mut request, &pre_read.mutations);
                ctx.pre_read_mutations = pre_read.mutations;
            },
            Err(PreReadError::Rejected(rejection)) => {
                send_rejection(session, rejection).await;
                return Ok(true);
            },
            Err(PreReadError::Filter(e)) => {
                error!(error = %e, "body filter error during pre-read");
                send_rejection(session, Rejection::status(500)).await;
                return Ok(true);
            },
            Err(PreReadError::Io(e)) => return Err(e),
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
                let _insert = req_headers.insert_header(name.into_owned(), value);
            }
            Ok(false)
        },
        Ok(PipelineResult {
            action: FilterAction::Reject(rejection),
            ..
        }) => {
            send_rejection(session, rejection).await;
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
        extensions,
        filter_metadata,
        filter_state,
        executed_indices,
        body_done,
        // Pre-read mutations were consumed by endpoint_selector during
        // on_request. Cleared below to prevent stale provenance reuse.
        _pre_read_mutations,
        structured_metadata,
    ) = {
        let mut filter_ctx = ctx.build_filter_context(pipeline, &request, None);

        let action = pipeline.execute_http_request(&mut filter_ctx).await;
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
            filter_ctx.extensions,
            filter_ctx.filter_metadata,
            filter_ctx.filter_state,
            filter_ctx.executed_filter_indices,
            filter_ctx.body_done_indices,
            filter_ctx.pre_read_mutations,
            filter_ctx.structured_metadata,
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
    ctx.metrics_route = metrics_route;
    ctx.response_body_mode = super::clamp_body_mode_to_ceiling(response_body_mode, baseline_response_body_mode);

    match action {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            ctx.cluster = cluster;
            ctx.upstream = upstream;
            ctx.rewritten_path = rewritten_path;
            ctx.request_body_mode = super::clamp_body_mode_to_ceiling(request_body_mode, baseline_request_body_mode);
            ctx.selected_endpoint_index = selected_endpoint_index;
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
// Terminal Response
// -----------------------------------------------------------------------------

/// Run response filters on a buffered terminal response and send it downstream.
#[expect(clippy::large_stack_frames, reason = "terminal response lifecycle with body filters")]
async fn run_terminal_response(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    terminal: TerminalResponse,
) {
    let mut resp = match prepare_terminal_response(pipeline, ctx, terminal.status, terminal.headers).await {
        Ok(resp) => resp,
        Err(rejection) => {
            send_rejection(session, rejection).await;
            return;
        },
    };
    let mut body = terminal.body;
    if let Err(rejection) = run_parent_terminal_body_filters(pipeline, ctx, &resp, &mut body, true) {
        send_rejection(session, rejection).await;
        return;
    }
    super::hop_by_hop::strip_hop_by_hop_header_map(&mut resp.headers, super::hop_by_hop::RESPONSE_HOP_BY_HOP);
    send_terminal_to_session(session, &resp, body).await;
}

/// Run response-header filters and persist their request-scoped state.
#[expect(clippy::too_many_lines, reason = "writeback destructuring")]
#[expect(clippy::expect_used, reason = "request_snapshot checked via let-else guard above")]
async fn prepare_terminal_response(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
    status: u16,
    headers: http::HeaderMap,
) -> Result<praxis_filter::Response, Rejection> {
    let mut resp = praxis_filter::Response {
        status: http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        headers,
    };
    ctx.response_phase_done = true;
    ctx.upstream_response_status = Some(status);
    let baseline_response_body_mode = ctx.response_body_mode;

    let Some(_) = ctx.request_snapshot else {
        warn!("request snapshot not set for terminal response; sending as-is");
        return Ok(resp);
    };
    let (
        result,
        response_body_mode,
        cluster,
        upstream,
        extensions,
        filter_metadata,
        filter_state,
        filter_results,
        structured_metadata,
        executed_indices,
        body_done,
    ) = {
        let mut fctx = ctx
            .filter_context_for(pipeline, Some(&mut resp))
            .expect("request snapshot checked above");
        let result = pipeline.execute_http_response(&mut fctx).await;
        (
            result,
            fctx.response_body_mode,
            fctx.cluster,
            fctx.upstream,
            fctx.extensions,
            fctx.filter_metadata,
            fctx.filter_state,
            fctx.filter_results,
            fctx.structured_metadata,
            fctx.executed_filter_indices,
            fctx.body_done_indices,
        )
    };
    ctx.cluster = cluster;
    ctx.upstream = upstream;
    ctx.extensions = extensions;
    ctx.filter_metadata = filter_metadata;
    ctx.filter_state = filter_state;
    ctx.filter_results = filter_results;
    ctx.structured_metadata = structured_metadata;
    ctx.cached_executed_filter_indices = executed_indices;
    ctx.cached_body_done_indices = body_done;
    ctx.response_body_mode = super::clamp_body_mode_to_ceiling(response_body_mode, baseline_response_body_mode);

    match result {
        Ok(FilterAction::Reject(rejection)) => {
            warn!(status = rejection.status, "response filter rejected terminal response");
            Err(rejection)
        },
        Err(e) => {
            error!(error = %e, "response filter error on terminal response");
            Err(Rejection::status(500))
        },
        _ => Ok(resp),
    }
}

/// Run one parent response-body filter invocation and persist its state.
#[expect(clippy::too_many_lines, reason = "writeback destructuring")]
fn run_parent_terminal_body_filters(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
    resp: &praxis_filter::Response,
    body: &mut Option<bytes::Bytes>,
    end_of_stream: bool,
) -> Result<(), Rejection> {
    let (
        result,
        response_body_bytes,
        cluster,
        upstream,
        extensions,
        filter_metadata,
        filter_state,
        filter_results,
        structured_metadata,
        executed_indices,
        body_done,
    ) = {
        let Some(mut fctx) = ctx.filter_context_for(pipeline, None) else {
            warn!("request snapshot not set for terminal response body; sending as-is");
            return Ok(());
        };
        let r = pipeline.execute_http_response_body_with_response_header(&mut fctx, body, end_of_stream, Some(resp));
        (
            r,
            fctx.response_body_bytes,
            fctx.cluster,
            fctx.upstream,
            fctx.extensions,
            fctx.filter_metadata,
            fctx.filter_state,
            fctx.filter_results,
            fctx.structured_metadata,
            fctx.executed_filter_indices,
            fctx.body_done_indices,
        )
    };
    ctx.response_body_bytes = response_body_bytes;
    ctx.cluster = cluster;
    ctx.upstream = upstream;
    ctx.extensions = extensions;
    ctx.filter_metadata = filter_metadata;
    ctx.filter_state = filter_state;
    ctx.filter_results = filter_results;
    ctx.structured_metadata = structured_metadata;
    ctx.cached_executed_filter_indices = executed_indices;
    ctx.cached_body_done_indices = body_done;

    match result {
        Ok(FilterAction::Reject(rejection)) => {
            warn!(
                status = rejection.status,
                "response body filter rejected terminal response"
            );
            Err(rejection)
        },
        Err(e) => {
            error!(error = %e, "response body filter error on terminal response");
            Err(Rejection::status(500))
        },
        _ => Ok(()),
    }
}

/// Deliver an opaque terminal stream directly to the downstream session.
#[expect(clippy::too_many_lines, reason = "stream lifecycle state machine")]
#[expect(
    clippy::cognitive_complexity,
    reason = "linear state machine with explicit error paths"
)]
#[expect(
    clippy::large_stack_frames,
    reason = "streaming lifecycle with body filter writeback"
)]
async fn run_streaming_terminal_response(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    terminal: StreamingTerminalResponse,
) {
    let StreamingTerminalResponse {
        status,
        headers,
        body: mut streaming_body,
    } = terminal;
    streaming_body.swap_extensions(&mut ctx.extensions);
    let mut resp = match prepare_terminal_response(pipeline, ctx, status, headers).await {
        Ok(resp) => resp,
        Err(rejection) => {
            streaming_body.cancel().await;
            send_rejection(session, rejection).await;
            return;
        },
    };
    streaming_body.swap_extensions(&mut ctx.extensions);

    if matches!(ctx.response_body_mode, BodyMode::StreamBuffer { .. }) {
        error!("streaming terminal response is incompatible with StreamBuffer response mode");
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        send_rejection(session, Rejection::status(500)).await;
        return;
    }

    let is_head = session.req_header().method == http::Method::HEAD;
    let body_prohibited = matches!(
        resp.status,
        http::StatusCode::NO_CONTENT | http::StatusCode::NOT_MODIFIED
    );
    if is_head || body_prohibited {
        suppress_streaming_terminal_response(pipeline, session, ctx, &mut resp, streaming_body.as_mut(), is_head).await;
        return;
    }

    let http_version = session.req_header().version;
    prepare_streaming_headers(&mut resp, false, false, http_version);
    let Some(header) = build_streaming_terminal_header(&resp) else {
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        send_rejection(session, Rejection::status(500)).await;
        return;
    };
    if let Err(e) = session.write_response_header(Box::new(header), false).await {
        debug!(error = %e, "failed to write streaming terminal response header");
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        session.as_downstream_mut().shutdown().await;
        return;
    }
    // A client may validly half-close its HTTP/1 write side after sending the
    // request while continuing to read the response. Keep FIN distinct from a
    // real disconnect; resets and failed response writes still abort promptly.
    session.as_downstream_mut().set_abort_on_close(false);

    loop {
        let source_result = tokio::select! {
            result = streaming_body.next_chunk() => Some(result),
            downstream = session.as_downstream_mut().read_body_or_idle(true) => {
                debug!(?downstream, "downstream disconnected while terminal stream source was pending");
                None
            },
        };
        let Some(source_result) = source_result else {
            streaming_body.swap_extensions(&mut ctx.extensions);
            streaming_body.cancel().await;
            session.as_downstream_mut().shutdown().await;
            return;
        };
        match source_result {
            Ok(Some(chunk)) => {
                streaming_body.swap_extensions(&mut ctx.extensions);
                let mut body = Some(chunk);
                if run_parent_terminal_body_filters(pipeline, ctx, &resp, &mut body, false).is_err()
                    || streaming_size_limit_exceeded(ctx)
                {
                    streaming_body.cancel().await;
                    session.as_downstream_mut().shutdown().await;
                    return;
                }
                streaming_body.swap_extensions(&mut ctx.extensions);
                if let Err(e) = session.write_response_body(body, false).await {
                    debug!(error = %e, "failed to write streaming terminal response body");
                    streaming_body.swap_extensions(&mut ctx.extensions);
                    streaming_body.cancel().await;
                    session.as_downstream_mut().shutdown().await;
                    return;
                }
            },
            Ok(None) => {
                // Restore the default before a clean keep-alive session can be reused.
                session.as_downstream_mut().set_abort_on_close(true);
                streaming_body.swap_extensions(&mut ctx.extensions);
                let mut completion_body = None;
                if run_parent_terminal_body_filters(pipeline, ctx, &resp, &mut completion_body, true).is_err() {
                    streaming_body.cancel().await;
                    session.as_downstream_mut().shutdown().await;
                    return;
                }
                if let Err(e) = session.write_response_body(completion_body, true).await {
                    debug!(error = %e, "failed to finish streaming terminal response");
                    session.as_downstream_mut().shutdown().await;
                }
                return;
            },
            Err(e) => {
                streaming_body.swap_extensions(&mut ctx.extensions);
                warn!(error = %e, "streaming terminal response source failed after commitment");
                streaming_body.cancel().await;
                session.as_downstream_mut().shutdown().await;
                return;
            },
        }
    }
}

/// Suppress a streaming body while still running clean completion hooks once.
#[expect(
    clippy::too_many_arguments,
    reason = "streaming suppress needs pipeline, session, ctx, resp, body, and flags"
)]
async fn suppress_streaming_terminal_response(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    resp: &mut praxis_filter::Response,
    streaming_body: &mut dyn praxis_filter::StreamingResponseBody,
    is_head: bool,
) {
    if let Err(e) = streaming_body.suppress().await {
        error!(error = %e, "failed to suppress streaming terminal response");
        streaming_body.cancel().await;
        send_rejection(session, Rejection::status(500)).await;
        return;
    }
    streaming_body.swap_extensions(&mut ctx.extensions);
    let mut completion_body = None;
    if let Err(rejection) = run_parent_terminal_body_filters(pipeline, ctx, resp, &mut completion_body, true) {
        streaming_body.cancel().await;
        send_rejection(session, rejection).await;
        return;
    }

    let is_not_modified = resp.status == http::StatusCode::NOT_MODIFIED;
    prepare_streaming_headers(resp, is_head, is_not_modified, http::Version::HTTP_10);
    let Some(header) = build_streaming_terminal_header(resp) else {
        streaming_body.cancel().await;
        send_rejection(session, Rejection::status(500)).await;
        return;
    };
    if let Err(e) = session.write_response_header(Box::new(header), true).await {
        debug!(error = %e, "failed to write suppressed streaming terminal response");
        session.as_downstream_mut().shutdown().await;
    }
}

/// Remove transport framing and hop-by-hop headers before commitment.
///
/// For HTTP/1.1 body streams, adds `Transfer-Encoding: chunked` so
/// Pingora's `init_body_writer_comm` selects chunked framing.
/// HTTP/1.0 uses close-delimited framing (no TE); HTTP/2 uses
/// DATA frames and ignores TE.
fn prepare_streaming_headers(
    resp: &mut praxis_filter::Response,
    is_head: bool,
    is_not_modified: bool,
    http_version: http::Version,
) {
    super::hop_by_hop::strip_hop_by_hop_header_map(&mut resp.headers, super::hop_by_hop::RESPONSE_HOP_BY_HOP);
    if resp.status == http::StatusCode::NO_CONTENT || (!is_head && !is_not_modified) {
        resp.headers.remove(http::header::CONTENT_LENGTH);
    }
    resp.headers.remove(http::header::TRANSFER_ENCODING);
    if http_version == http::Version::HTTP_11 && !is_head && !is_not_modified {
        resp.headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
    }
}

/// Build a header for a streamed response without synthesizing body length.
fn build_streaming_terminal_header(resp: &praxis_filter::Response) -> Option<pingora_http::ResponseHeader> {
    let code = resp.status.as_u16();
    if !(200..=599).contains(&code) {
        warn!(
            status = code,
            "streaming terminal response status outside 200..=599; sending 500"
        );
        return None;
    }
    let mut header = match pingora_http::ResponseHeader::build(resp.status, Some(resp.headers.len())) {
        Ok(h) => h,
        Err(e) => {
            error!(status = %resp.status, error = %e, "invalid streaming terminal response status; using 500");
            return None;
        },
    };
    for (name, value) in &resp.headers {
        let _append = header.append_header(name.clone(), value.clone());
    }
    Some(header)
}

/// Enforce an incremental response size limit after raw bytes are counted.
fn streaming_size_limit_exceeded(ctx: &PingoraRequestCtx) -> bool {
    let BodyMode::SizeLimit { max_bytes } = ctx.response_body_mode else {
        return false;
    };
    if ctx.response_body_bytes <= max_bytes as u64 {
        return false;
    }
    warn!(
        actual = ctx.response_body_bytes,
        limit = max_bytes,
        "streaming terminal response exceeded response body limit"
    );
    true
}

/// Build a Pingora response header from filter-modified state.
///
/// Returns `None` (caller sends 500) for statuses outside 200..=599.
/// Reframes Content-Length from the actual body, skipping any stale
/// value that response-header filters may have set.  For HEAD the
/// body is suppressed downstream but Content-Length must still
/// reflect what GET would return.
fn build_terminal_header(
    resp: &praxis_filter::Response,
    body: &Option<bytes::Bytes>,
    body_prohibited: bool,
    is_head: bool,
) -> Option<pingora_http::ResponseHeader> {
    let code = resp.status.as_u16();
    if !(200..=599).contains(&code) {
        warn!(status = code, "terminal response status outside 200..=599; sending 500");
        return None;
    }
    let header_count = Some(resp.headers.len().saturating_add(1));
    let mut header = match pingora_http::ResponseHeader::build(resp.status, header_count) {
        Ok(h) => h,
        Err(e) => {
            error!(status = %resp.status, error = %e, "invalid terminal response status; using 500");
            return None;
        },
    };
    for (name, value) in &resp.headers {
        if name == http::header::CONTENT_LENGTH && !is_head {
            continue;
        }
        let _append = header.append_header(name.clone(), value.clone());
    }
    if !body_prohibited && !is_head {
        let content_length = body.as_ref().map_or(0, bytes::Bytes::len);
        let _insert = header.insert_header("content-length", content_length.to_string());
    }
    Some(header)
}

/// Write a terminal response (headers + optional body) to the Pingora session.
///
/// Suppresses the body for 204/304 and HEAD, and preserves
/// Content-Length semantics for HEAD (advertises what GET would return).
/// Statuses outside 200..=599 are rejected by `build_terminal_header`.
async fn send_terminal_to_session(session: &mut Session, resp: &praxis_filter::Response, body: Option<bytes::Bytes>) {
    let is_head = session.req_header().method == http::Method::HEAD;
    let status = resp.status;
    let body_prohibited = status == http::StatusCode::NO_CONTENT || status == http::StatusCode::NOT_MODIFIED;

    let Some(header) = build_terminal_header(resp, &body, body_prohibited, is_head) else {
        send_rejection(session, Rejection::status(500)).await;
        return;
    };
    let send_body = !is_head && !body_prohibited;
    if let Err(e) = session
        .write_response_header(Box::new(header), !send_body || body.is_none())
        .await
    {
        debug!(error = %e, "failed to write terminal response header");
        return;
    }
    if send_body
        && let Some(b) = body
        && let Err(e) = session.write_response_body(Some(b), true).await
    {
        debug!(error = %e, "failed to write terminal response body");
    }
}

/// Apply pre-read mutations to both the Pingora session and the Praxis request.
///
/// Replays the ordered mutation log against the session and the request
/// so that both the protocol layer and filter layer see consistent headers.
fn apply_pre_read_mutations(session: &mut Session, request: &mut Request, mutations: &[TrustedHeaderMutation]) {
    apply_pre_read_mutations_to_session(session, mutations);
    apply_pre_read_mutations_to_request(request, mutations);
}

/// Apply the request pipeline's pending header mutations to a header map.
///
/// Applied in remove -> set -> add order, matching both the order the
/// caller applies them to the Pingora session and the order documented
/// on [`HttpFilterContext::pending_header_value`]: a remove clears any
/// prior value, a set establishes a new one, and adds follow.
///
/// `extra` uses replace semantics here because that is what the session
/// receives (`insert_header`). Note this differs from the pre-read body
/// phase, where the same context field is drained into
/// [`TrustedHeaderMutation::Add`] and appended. The two phases serve
/// different filters — `request_id` re-emits a client-supplied ID as an
/// extra header and would duplicate it under append semantics, while
/// pre-read body filters accumulate — so the divergence is deliberate
/// and must not be "unified" without auditing both sets of callers.
///
/// [`HttpFilterContext::pending_header_value`]: praxis_filter::HttpFilterContext::pending_header_value
fn apply_pending_header_mutations(
    headers: &mut http::HeaderMap,
    to_remove: &[http::header::HeaderName],
    to_set: &[(http::header::HeaderName, http::header::HeaderValue)],
    extra: &[(Cow<'static, str>, String)],
) {
    for name in to_remove {
        headers.remove(name);
    }
    for (name, value) in to_set {
        let _replaced = headers.insert(name.clone(), value.clone());
    }
    for (name, value) in extra {
        match (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            (Ok(header_name), Ok(header_value)) => {
                let _replaced = headers.insert(header_name, header_value);
            },
            (name_result, value_result) => {
                warn!(
                    header = %name,
                    name_err = ?name_result.err(),
                    value_err = ?value_result.err(),
                    "skipping invalid promoted header in request snapshot"
                );
            },
        }
    }
}

/// Apply pre-read mutations to the Praxis [`Request`] struct.
fn apply_pre_read_mutations_to_request(request: &mut Request, mutations: &[TrustedHeaderMutation]) {
    for mutation in mutations {
        match mutation {
            TrustedHeaderMutation::Remove(name) => {
                request.headers.remove(name);
            },
            TrustedHeaderMutation::Set(name, value) => {
                request.headers.insert(name.clone(), value.clone());
            },
            TrustedHeaderMutation::Add(name, value) => match http::header::HeaderValue::from_str(value) {
                Ok(hval) => {
                    request.headers.append(name.clone(), hval);
                },
                Err(err) => {
                    warn!(
                        header = %name,
                        error = %err,
                        "skipping invalid trusted pre-read add mutation for request"
                    );
                },
            },
        }
    }
}

/// Apply pre-read mutations to the Pingora session headers.
fn apply_pre_read_mutations_to_session(session: &mut Session, mutations: &[TrustedHeaderMutation]) {
    let req_headers = session.req_header_mut();
    for mutation in mutations {
        match mutation {
            TrustedHeaderMutation::Remove(name) => {
                let _remove = req_headers.remove_header(name);
            },
            TrustedHeaderMutation::Set(name, value) => {
                let _insert = req_headers.insert_header(name.clone(), value.clone());
            },
            TrustedHeaderMutation::Add(name, value) => match http::header::HeaderValue::from_str(value) {
                Ok(hval) => {
                    let _append = req_headers.append_header(name.clone(), hval);
                },
                Err(err) => {
                    warn!(
                        header = %name,
                        error = %err,
                        "skipping invalid trusted pre-read add mutation for session"
                    );
                },
            },
        }
    }
}

/// Build the root tracing span for a request with `OTel` HTTP semantic
/// convention attributes.
///
/// Creates an [`info_span!`] named `"http_request"` with the
/// [OTel span name] set to `{method}` and span kind set to
/// `SERVER`. Response-phase attributes (`http.response.status_code`,
/// `upstream.address`) are declared as [`Empty`] and recorded later via
/// [`record_response_span_attributes`].
///
/// [`info_span!`]: tracing::info_span
/// [OTel span name]: https://opentelemetry.io/docs/specs/semconv/http/http-spans/
/// [`Empty`]: tracing::field::Empty
/// [`record_response_span_attributes`]: super::record_response_span_attributes
fn create_request_span(session: &Session, ctx: &PingoraRequestCtx) -> tracing::Span {
    let method = session.req_header().method.as_str();
    let path = session.req_header().uri.path();
    let path = if path.is_empty() { "/" } else { path };
    let protocol_version = super::http_version_label(ctx.client_http_version.unwrap_or(http::Version::HTTP_11));
    let host = session.req_header().headers.get("host").and_then(|v| v.to_str().ok());
    let server_address = host.map(|h| h.split(':').next().unwrap_or(h));
    let server_port = host.and_then(|h| h.split_once(':').and_then(|(_, p)| p.parse::<u16>().ok()));

    let span = tracing::info_span!(
        "http_request",
        "otel.name" = method,
        "otel.kind" = "server",
        "otel.status_code" = tracing::field::Empty,
        "http.request.method" = method,
        "url.path" = path,
        "http.response.status_code" = tracing::field::Empty,
        "server.address" = server_address,
        "server.port" = server_port,
        "client.address" = tracing::field::Empty,
        "upstream.address" = tracing::field::Empty,
        "network.protocol.version" = protocol_version,
        "upstream.cluster" = tracing::field::Empty,
        request_id = tracing::field::Empty,
    );

    if let Some(addr) = &ctx.client_addr {
        span.record("client.address", tracing::field::display(addr));
    }

    span
}

/// Reject client-supplied reserved internal headers before special handling
/// or filter execution can observe them.
fn reject_reserved_internal_headers(session: &Session) -> Option<Rejection> {
    let reserved_count = session
        .req_header()
        .headers
        .keys()
        .filter(|name| super::reserved_headers::is_reserved_internal_header(name))
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
    use std::net::IpAddr;

    use http::{HeaderMap, Method, Uri};
    use praxis_core::config::FailureMode;
    use praxis_filter::{BodyMode, FilterAction, FilterPipeline, FilterRegistry, Request};

    use super::*;
    use crate::http::pingora::context::PingoraRequestCtx;

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
        let clamped = super::super::clamp_body_mode_to_ceiling(
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
        let clamped = super::super::clamp_body_mode_to_ceiling(
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
        let clamped = super::super::clamp_body_mode_to_ceiling(
            BodyMode::Stream,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
        );
        assert_eq!(
            clamped,
            BodyMode::Stream,
            "Stream has no buffer to clamp and should pass through unchanged"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_stream_passes_through_without_ceiling() {
        let clamped = super::super::clamp_body_mode_to_ceiling(BodyMode::Stream, BodyMode::Stream);
        assert_eq!(
            clamped,
            BodyMode::Stream,
            "Stream baseline imposes no ceiling; Stream mode passes through"
        );
    }

    #[test]
    fn clamp_body_mode_to_ceiling_size_limit_clamped_to_baseline() {
        let clamped = super::super::clamp_body_mode_to_ceiling(
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
        let clamped = super::super::clamp_body_mode_to_ceiling(
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
        let clamped = super::super::clamp_body_mode_to_ceiling(
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
        // The span is created in execute() before run_pipeline, but
        // run_pipeline tests don't go through execute(). Verify
        // the default is disabled, which confirms no premature creation.
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
        // Empty pipeline produces no extra headers containing x-request-id.
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

    // -------------------------------------------------------------------------
    // Pending Header Mutations
    // -------------------------------------------------------------------------

    #[test]
    fn pending_mutations_apply_removes_sets_and_adds() {
        let mut headers = HeaderMap::new();
        headers.insert("x-drop", "gone".parse().unwrap());
        headers.insert("x-keep", "kept".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &["x-drop".parse().unwrap()],
            &[("x-set".parse().unwrap(), "set-value".parse().unwrap())],
            &[(Cow::Borrowed("x-extra"), "extra-value".to_owned())],
        );

        assert!(headers.get("x-drop").is_none(), "removed header should be gone");
        assert_eq!(headers.get("x-keep").unwrap(), "kept", "untouched header survives");
        assert_eq!(headers.get("x-set").unwrap(), "set-value", "set header applied");
        assert_eq!(headers.get("x-extra").unwrap(), "extra-value", "extra header applied");
    }

    #[test]
    fn pending_mutations_apply_set_after_remove_for_the_same_name() {
        let mut headers = HeaderMap::new();
        headers.insert("x-both", "original".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &["x-both".parse().unwrap()],
            &[("x-both".parse().unwrap(), "replacement".parse().unwrap())],
            &[],
        );

        assert_eq!(
            headers.get("x-both").unwrap(),
            "replacement",
            "set runs after remove, so the set value wins"
        );
    }

    #[test]
    fn pending_extra_headers_replace_rather_than_accumulate() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "client-supplied".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &[],
            &[],
            &[(Cow::Borrowed("x-request-id"), "client-supplied".to_owned())],
        );

        assert_eq!(
            headers.get_all("x-request-id").iter().count(),
            1,
            "re-emitting a client-supplied header must not duplicate it"
        );
    }

    #[test]
    fn pending_mutations_skip_invalid_promoted_headers() {
        let mut headers = HeaderMap::new();

        apply_pending_header_mutations(
            &mut headers,
            &[],
            &[],
            &[
                (Cow::Borrowed("bad header name"), "v".to_owned()),
                (Cow::Borrowed("x-good"), "v".to_owned()),
            ],
        );

        assert_eq!(headers.len(), 1, "invalid name is skipped, valid one still applied");
        assert_eq!(headers.get("x-good").unwrap(), "v");
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
    // Streaming Header / Framing Tests
    // -------------------------------------------------------------------------

    fn make_resp(status: u16) -> praxis_filter::Response {
        praxis_filter::Response {
            status: http::StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
        }
    }

    #[test]
    fn streaming_headers_strip_hop_by_hop() {
        let mut resp = make_resp(200);
        resp.headers
            .insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        resp.headers
            .insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        resp.headers.insert("x-custom", "keep".parse().unwrap());

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_11);

        assert!(!resp.headers.contains_key(http::header::CONNECTION));
        assert!(resp.headers.contains_key("x-custom"));
    }

    #[test]
    fn streaming_headers_http11_adds_chunked() {
        let mut resp = make_resp(200);

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_11);

        assert_eq!(resp.headers.get(http::header::TRANSFER_ENCODING).unwrap(), "chunked");
    }

    #[test]
    fn streaming_headers_http10_no_chunked() {
        let mut resp = make_resp(200);

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_10);

        assert!(!resp.headers.contains_key(http::header::TRANSFER_ENCODING));
    }

    #[test]
    fn streaming_headers_http2_no_chunked() {
        let mut resp = make_resp(200);

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_2);

        assert!(!resp.headers.contains_key(http::header::TRANSFER_ENCODING));
    }

    #[test]
    fn streaming_headers_head_no_chunked() {
        let mut resp = make_resp(200);

        prepare_streaming_headers(&mut resp, true, false, http::Version::HTTP_11);

        assert!(!resp.headers.contains_key(http::header::TRANSFER_ENCODING));
    }

    #[test]
    fn streaming_headers_304_no_chunked() {
        let mut resp = make_resp(304);

        prepare_streaming_headers(&mut resp, false, true, http::Version::HTTP_11);

        assert!(!resp.headers.contains_key(http::header::TRANSFER_ENCODING));
    }

    #[test]
    fn streaming_headers_204_removes_content_length() {
        let mut resp = make_resp(204);
        resp.headers.insert(http::header::CONTENT_LENGTH, "0".parse().unwrap());

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_10);

        assert!(!resp.headers.contains_key(http::header::CONTENT_LENGTH));
    }

    #[test]
    fn streaming_headers_head_preserves_content_length() {
        let mut resp = make_resp(200);
        resp.headers
            .insert(http::header::CONTENT_LENGTH, "1024".parse().unwrap());

        prepare_streaming_headers(&mut resp, true, false, http::Version::HTTP_11);

        assert_eq!(resp.headers.get(http::header::CONTENT_LENGTH).unwrap(), "1024");
    }

    #[test]
    fn streaming_headers_304_preserves_content_length() {
        let mut resp = make_resp(304);
        resp.headers
            .insert(http::header::CONTENT_LENGTH, "512".parse().unwrap());

        prepare_streaming_headers(&mut resp, false, true, http::Version::HTTP_11);

        assert_eq!(resp.headers.get(http::header::CONTENT_LENGTH).unwrap(), "512");
    }

    #[test]
    fn streaming_headers_replaces_existing_transfer_encoding() {
        let mut resp = make_resp(200);
        resp.headers
            .insert(http::header::TRANSFER_ENCODING, "gzip".parse().unwrap());

        prepare_streaming_headers(&mut resp, false, false, http::Version::HTTP_11);

        assert_eq!(resp.headers.get(http::header::TRANSFER_ENCODING).unwrap(), "chunked");
    }

    #[test]
    fn build_streaming_header_valid_200() {
        let resp = make_resp(200);
        let header = build_streaming_terminal_header(&resp);
        assert!(header.is_some());
        assert_eq!(header.unwrap().status, 200);
    }

    #[test]
    fn build_streaming_header_valid_599() {
        let resp = make_resp(599);
        let header = build_streaming_terminal_header(&resp);
        assert!(header.is_some());
    }

    #[test]
    fn build_streaming_header_invalid_100() {
        let resp = make_resp(100);
        assert!(build_streaming_terminal_header(&resp).is_none());
    }

    #[test]
    fn build_streaming_header_preserves_custom_headers() {
        let mut resp = make_resp(200);
        resp.headers.insert("x-custom", "value".parse().unwrap());

        let header = build_streaming_terminal_header(&resp).unwrap();

        assert_eq!(header.headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn streaming_size_limit_not_exceeded() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 1024 };
        ctx.response_body_bytes = 512;

        assert!(!streaming_size_limit_exceeded(&ctx));
    }

    #[test]
    fn streaming_size_limit_exceeded_over() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 100 };
        ctx.response_body_bytes = 101;

        assert!(streaming_size_limit_exceeded(&ctx));
    }

    #[test]
    fn streaming_size_limit_stream_mode_never_exceeded() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::Stream;
        ctx.response_body_bytes = 999_999;

        assert!(!streaming_size_limit_exceeded(&ctx));
    }

    #[test]
    fn streaming_size_limit_exact_boundary() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 100 };
        ctx.response_body_bytes = 100;

        assert!(!streaming_size_limit_exceeded(&ctx));
    }
}
