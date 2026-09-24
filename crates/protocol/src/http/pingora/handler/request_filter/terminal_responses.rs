// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Terminal response delivery for buffered and streaming responses.
//!
//! Handles filter execution, header preparation, and downstream
//! delivery for both buffered terminal responses and streaming
//! terminal responses, including bodyless response suppression and
//! response size limit enforcement.

use bytes::Bytes;
use pingora_proxy::Session;
use praxis_filter::{BodyMode, FilterAction, FilterPipeline, Rejection, StreamingTerminalResponse, TerminalResponse};
use tracing::{debug, error, warn};

use super::super::{
    super::{
        context::PingoraRequestCtx,
        convert::{send_rejection, send_rejection_for},
    },
    body_util::clamp_body_mode_to_ceiling,
    hop_by_hop::{RESPONSE_HOP_BY_HOP, strip_hop_by_hop_header_map, strip_reserved_internal_header_map},
};

/// Run response filters on a buffered terminal response and send it downstream.
pub(super) async fn run_terminal_response(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    terminal: TerminalResponse,
) {
    let prepared = Box::pin(prepare_terminal_response(
        pipeline,
        ctx,
        terminal.status,
        terminal.headers,
    ))
    .await;
    let mut resp = match prepared {
        Ok(resp) => resp,
        Err(rejection) => {
            Box::pin(send_rejection_for(session, rejection, ctx)).await;
            return;
        },
    };
    let mut body = terminal.body;
    let is_bodyless = ctx
        .request_snapshot
        .as_ref()
        .is_some_and(|request| praxis_filter::bodyless_response(resp.status, &request.method));
    if is_bodyless {
        ctx.response_delivery_complete = true;
    } else if let Err(rejection) = run_parent_terminal_body_filters(pipeline, ctx, &resp, &mut body, true) {
        send_rejection_for(session, rejection, ctx).await;
        return;
    }
    strip_hop_by_hop_header_map(&mut resp.headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_internal_header_map(&mut resp.headers);
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
        executed_branch_filters,
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
            fctx.executed_branch_filters,
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
    ctx.cached_executed_branch_filters = executed_branch_filters;
    ctx.cached_executed_filter_indices = executed_indices;
    ctx.cached_body_done_indices = body_done;
    ctx.response_body_mode = clamp_body_mode_to_ceiling(response_body_mode, baseline_response_body_mode);

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
    body: &mut Option<Bytes>,
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
        executed_branch_filters,
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
            fctx.executed_branch_filters,
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
    ctx.cached_executed_branch_filters = executed_branch_filters;
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
        _ => {
            if end_of_stream {
                ctx.response_delivery_complete = true;
            }
            Ok(())
        },
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
pub(super) async fn run_streaming_terminal_response(
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
            send_rejection_for(session, rejection, ctx).await;
            return;
        },
    };
    streaming_body.swap_extensions(&mut ctx.extensions);

    if matches!(ctx.response_body_mode, BodyMode::StreamBuffer { .. }) {
        error!("streaming terminal response is incompatible with StreamBuffer response mode");
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        send_rejection_for(session, Rejection::status(500), ctx).await;
        return;
    }

    let is_head = session.req_header().method == http::Method::HEAD;
    let body_prohibited = matches!(
        resp.status,
        http::StatusCode::NO_CONTENT | http::StatusCode::NOT_MODIFIED
    );
    if is_head || body_prohibited {
        suppress_streaming_terminal_response(session, ctx, &mut resp, streaming_body.as_mut(), is_head).await;
        return;
    }

    let http_version = session.req_header().version;
    prepare_streaming_headers(&mut resp, false, false, http_version);
    let Some(header) = build_streaming_terminal_header(&resp) else {
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        send_rejection_for(session, Rejection::status(500), ctx).await;
        return;
    };
    if let Err(e) = session.write_response_header(Box::new(header), false).await {
        debug!(error = %e, "failed to write streaming terminal response header");
        streaming_body.swap_extensions(&mut ctx.extensions);
        streaming_body.cancel().await;
        session.as_downstream_mut().shutdown().await;
        return;
    }
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
                    || streaming_size_limit_exceeded(ctx, pipeline)
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

/// Suppress a bodyless streaming terminal response (HEAD, 204, 304).
async fn suppress_streaming_terminal_response(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    resp: &mut praxis_filter::Response,
    streaming_body: &mut dyn praxis_filter::StreamingResponseBody,
    is_head: bool,
) {
    if let Err(e) = streaming_body.suppress().await {
        error!(error = %e, "failed to suppress streaming terminal response");
        streaming_body.cancel().await;
        send_rejection_for(session, Rejection::status(500), ctx).await;
        return;
    }
    ctx.response_delivery_complete = true;

    let is_not_modified = resp.status == http::StatusCode::NOT_MODIFIED;
    prepare_streaming_headers(resp, is_head, is_not_modified, http::Version::HTTP_10);
    let Some(header) = build_streaming_terminal_header(resp) else {
        streaming_body.cancel().await;
        send_rejection_for(session, Rejection::status(500), ctx).await;
        return;
    };
    if let Err(e) = session.write_response_header(Box::new(header), true).await {
        debug!(error = %e, "failed to write suppressed streaming terminal response");
        session.as_downstream_mut().shutdown().await;
    }
}

/// Remove transport framing and hop-by-hop headers before commitment.
fn prepare_streaming_headers(
    resp: &mut praxis_filter::Response,
    is_head: bool,
    is_not_modified: bool,
    http_version: http::Version,
) {
    strip_hop_by_hop_header_map(&mut resp.headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_internal_header_map(&mut resp.headers);
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
fn streaming_size_limit_exceeded(ctx: &PingoraRequestCtx, pipeline: &FilterPipeline) -> bool {
    let max_bytes = match ctx.response_body_mode {
        BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        BodyMode::Stream => pipeline.response_body_ceiling(),
        _ => None,
    };
    let Some(max_bytes) = max_bytes else {
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
fn build_terminal_header(
    resp: &praxis_filter::Response,
    body: Option<&Bytes>,
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
        let content_length = body.map_or(0, Bytes::len);
        let _insert = header.insert_header("content-length", content_length.to_string());
    }
    Some(header)
}

/// Write a terminal response (headers + optional body) to the Pingora session.
async fn send_terminal_to_session(session: &mut Session, resp: &praxis_filter::Response, body: Option<Bytes>) {
    let is_head = session.req_header().method == http::Method::HEAD;
    let status = resp.status;
    let body_prohibited = status == http::StatusCode::NO_CONTENT || status == http::StatusCode::NOT_MODIFIED;

    let Some(header) = build_terminal_header(resp, body.as_ref(), body_prohibited, is_head) else {
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
    use http::HeaderMap;
    use praxis_filter::FilterRegistry;

    use super::*;

    fn make_resp(status: u16) -> praxis_filter::Response {
        praxis_filter::Response {
            status: http::StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
        }
    }

    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    fn empty_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
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

        assert!(!streaming_size_limit_exceeded(&ctx, &empty_pipeline()));
    }

    #[test]
    fn streaming_size_limit_exceeded_over() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 100 };
        ctx.response_body_bytes = 101;

        assert!(streaming_size_limit_exceeded(&ctx, &empty_pipeline()));
    }

    #[test]
    fn streaming_size_limit_stream_mode_never_exceeded() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::Stream;
        ctx.response_body_bytes = 999_999;

        assert!(!streaming_size_limit_exceeded(&ctx, &empty_pipeline()));
    }

    #[test]
    fn streaming_size_limit_exact_boundary() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 100 };
        ctx.response_body_bytes = 100;

        assert!(!streaming_size_limit_exceeded(&ctx, &empty_pipeline()));
    }

    #[test]
    fn build_terminal_header_head_preserves_content_length() {
        let mut resp = make_resp(200);
        resp.headers
            .insert(http::header::CONTENT_LENGTH, "1024".parse().unwrap());
        let body = Some(Bytes::from_static(b"body"));

        let header = build_terminal_header(&resp, body.as_ref(), false, true).expect("should build header for HEAD");

        // For HEAD, the original Content-Length should be preserved
        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "1024",
            "HEAD responses preserve original Content-Length"
        );
    }

    #[test]
    fn build_terminal_header_body_prohibited_no_content() {
        let mut resp = make_resp(204);
        resp.headers
            .insert(http::header::CONTENT_LENGTH, "100".parse().unwrap());
        let body = Some(Bytes::from_static(b"should be ignored"));

        let header = build_terminal_header(&resp, body.as_ref(), true, false).expect("should build header for 204");

        // For 204, no Content-Length should be set even if body exists
        assert!(
            !header.headers.contains_key(http::header::CONTENT_LENGTH),
            "204 responses should not have Content-Length"
        );
    }

    #[test]
    fn build_terminal_header_body_prohibited_not_modified() {
        let resp = make_resp(304);
        let body = None;

        let header = build_terminal_header(&resp, body.as_ref(), true, false).expect("should build header for 304");

        assert!(
            !header.headers.contains_key(http::header::CONTENT_LENGTH),
            "304 with body_prohibited should not add Content-Length"
        );
    }

    #[test]
    fn build_terminal_header_empty_body() {
        let resp = make_resp(200);
        let body = None;

        let header =
            build_terminal_header(&resp, body.as_ref(), false, false).expect("should build header for empty body");

        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "0",
            "empty body should have Content-Length: 0"
        );
    }

    #[test]
    fn build_terminal_header_with_body() {
        let resp = make_resp(200);
        let body = Some(Bytes::from_static(b"response body"));

        let header = build_terminal_header(&resp, body.as_ref(), false, false).expect("should build header with body");

        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "13",
            "body length should match actual bytes"
        );
    }

    #[test]
    fn build_terminal_header_removes_stale_content_length_except_head() {
        let mut resp = make_resp(200);
        resp.headers
            .insert(http::header::CONTENT_LENGTH, "9999".parse().unwrap());
        let body = Some(Bytes::from_static(b"real"));

        let header = build_terminal_header(&resp, body.as_ref(), false, false).expect("should build header");

        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            "4",
            "stale Content-Length should be replaced with actual body length"
        );
    }

    #[test]
    fn build_terminal_header_invalid_status_out_of_range_low() {
        let resp = make_resp(199);

        let header = build_terminal_header(&resp, None, false, false);

        assert!(header.is_none(), "status 199 should be rejected");
    }

    #[test]
    fn build_terminal_header_invalid_status_out_of_range_high() {
        let resp = make_resp(600);

        let header = build_terminal_header(&resp, None, false, false);

        assert!(header.is_none(), "status 600 should be rejected");
    }

    #[test]
    fn build_terminal_header_boundary_status_200() {
        let resp = make_resp(200);

        let header = build_terminal_header(&resp, None, false, false);

        assert!(header.is_some(), "status 200 is valid");
    }

    #[test]
    fn build_terminal_header_boundary_status_599() {
        let resp = make_resp(599);

        let header = build_terminal_header(&resp, None, false, false);

        assert!(header.is_some(), "status 599 is valid");
    }

    #[test]
    fn streaming_size_limit_stream_buffer_mode_no_limit() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(1000) };
        ctx.response_body_bytes = 1001;

        // StreamBuffer mode doesn't enforce limit during streaming terminal responses
        // The limit is enforced during pre-read phase, not here
        assert!(
            !streaming_size_limit_exceeded(&ctx, &empty_pipeline()),
            "StreamBuffer mode does not enforce limit in streaming terminal context"
        );
    }

    #[test]
    fn streaming_size_limit_size_limit_mode_enforced() {
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 500 };
        ctx.response_body_bytes = 501;

        assert!(
            streaming_size_limit_exceeded(&ctx, &empty_pipeline()),
            "SizeLimit mode should enforce limit"
        );
    }
}
