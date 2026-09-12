// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request body filter: buffers or streams body chunks through the
//! pipeline, enforcing size limits.
//!
//! Implements Pingora's `request_body_filter` hook. Chunks are
//! accumulated or streamed based on the pipeline's [`BodyMode`];
//! the absolute ceiling ([`ABSOLUTE_MAX_BODY_BYTES`]) is enforced
//! regardless of per-filter declarations. Rejections from body
//! filters are converted to downstream error responses.
//!
//! [`BodyMode`]: praxis_filter::BodyMode
//! [`ABSOLUTE_MAX_BODY_BYTES`]: praxis_core::config::ABSOLUTE_MAX_BODY_BYTES

use bytes::Bytes;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_filter::{BodyMode, FilterAction, FilterPipeline, Rejection};
use tracing::error;

use super::{
    super::{context::PingoraRequestCtx, convert::send_rejection},
    BodyFilterOutput, accumulate_stream_buffer, check_body_size_limit, release_stream_buffer,
    suppress_stream_buffer_chunk,
};

// -----------------------------------------------------------------------------
// Request Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a request body chunk, enforcing size limits.
#[expect(clippy::large_stack_frames, clippy::too_many_lines, reason = "body filter dispatch")]
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut PingoraRequestCtx,
) -> Result<()> {
    if ctx.connection_upgraded {
        return Ok(());
    }

    if let Some(chunks) = &mut ctx.pre_read_body {
        tracing::trace!("forwarding pre-read body chunks from StreamBuffer mode");

        *body = chunks.pop_front();
        if chunks.is_empty() {
            ctx.pre_read_body = None;
        }
        return Ok(());
    }

    let caps = pipeline.body_capabilities();

    if !caps.needs_request_body {
        return Ok(());
    }

    let is_stream_buffer = matches!(ctx.request_body_mode, BodyMode::StreamBuffer { .. });

    match ctx.request_body_mode {
        BodyMode::SizeLimit { max_bytes } => {
            if check_body_size_limit(body.as_ref(), &mut ctx.request_body_bytes, max_bytes) {
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
                send_rejection(session, Rejection::status(413)).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "request body exceeds maximum size",
                ));
            }
            return Ok(());
        },

        BodyMode::StreamBuffer { max_bytes } if !ctx.request_body_released => {
            if accumulate_stream_buffer(body, &mut ctx.request_body_buffer, end_of_stream, max_bytes) {
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
                send_rejection(session, Rejection::status(413)).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "request body exceeds stream_buffer size limit",
                ));
            }
            if end_of_stream {
                // Mid-stream chunks were counted incrementally; `body` now
                // holds the frozen full buffer the pipeline counts again.
                // Reset so the final total is the buffer size, not double it.
                ctx.request_body_bytes = 0;
            }
        },

        BodyMode::Stream => {
            // The global body_limits ceiling applies to streamed bodies too;
            // Stream mode just counts instead of buffering. The projection
            // does not mutate the counter — the filter pipeline below is
            // the accumulator. `None` is only reachable with
            // allow_unbounded_body.
            let chunk_len = body.as_ref().map_or(0, Bytes::len) as u64;
            if let Some(max) = pipeline.request_body_ceiling()
                && ctx.request_body_bytes.saturating_add(chunk_len) > max as u64
            {
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
                send_rejection(session, Rejection::status(413)).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "streamed request body exceeds global body limit",
                ));
            }
        },

        // After Release the body streams unbuffered; the global ceiling
        // still applies (StreamBuffer's own cap no longer runs).
        BodyMode::StreamBuffer { .. } => {
            let chunk_len = body.as_ref().map_or(0, Bytes::len) as u64;
            if let Some(max) = pipeline.request_body_ceiling()
                && ctx.request_body_bytes.saturating_add(chunk_len) > max as u64
            {
                ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
                send_rejection(session, Rejection::status(413)).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "released request body exceeds global body limit",
                ));
            }
        },
        _ => tracing::error!("unhandled BodyMode variant in request body filter"),
    }

    let (result, request_body_bytes, output) = {
        let mut fctx = ctx.filter_context_for(pipeline, None).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set when request body hooks are active",
            )
        })?;
        let r = pipeline.execute_http_request_body(&mut fctx, body, end_of_stream).await;
        (r, fctx.request_body_bytes, BodyFilterOutput::take_from(&mut fctx))
    };
    ctx.request_body_bytes = request_body_bytes;
    output.write_back(ctx);

    match result {
        Ok(
            FilterAction::Continue
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => {
            suppress_stream_buffer_chunk(body, is_stream_buffer, ctx.request_body_released, end_of_stream);
            Ok(())
        },
        Ok(FilterAction::Release) => {
            release_stream_buffer(
                body,
                is_stream_buffer,
                &mut ctx.request_body_released,
                &mut ctx.request_body_buffer,
                end_of_stream,
            );
            Ok(())
        },
        Ok(FilterAction::Reject(rejection)) => {
            let status = rejection.status;
            ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
            send_rejection(session, rejection).await;
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "request body rejected by filter pipeline",
            ))
        },
        Err(e) => {
            error!(error = %e, "filter pipeline error during request body");
            ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_INTERNAL);
            send_rejection(session, Rejection::status(500)).await;
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("request body filter error: {e}"),
            ))
        },
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
    use std::collections::VecDeque;

    use bytes::Bytes;
    use praxis_filter::{BodyMode, FilterPipeline, FilterRegistry};

    use super::{Session, execute};
    use crate::http::pingora::context::PingoraRequestCtx;

    /// Global request-body ceiling used by the released-buffer tests.
    const CEILING: usize = 8;

    #[tokio::test]
    async fn released_stream_buffer_request_body_enforces_global_ceiling() {
        let pipeline = ceiling_pipeline();
        let (mut session, _client) = session_for("POST / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = released_stream_buffer_ctx();
        let mut body = Some(Bytes::from_static(b"0123456789"));

        let result = execute(&pipeline, &mut session, &mut body, false, &mut ctx).await;
        assert!(
            result.is_err(),
            "a released stream buffer must still honor the global request body ceiling"
        );
    }

    #[tokio::test]
    async fn released_stream_buffer_request_body_accumulates_across_chunks() {
        let pipeline = ceiling_pipeline();
        let (mut session, _client) = session_for("POST / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = released_stream_buffer_ctx();

        let mut first = Some(Bytes::from_static(b"01234"));
        let result = execute(&pipeline, &mut session, &mut first, false, &mut ctx).await;
        assert!(result.is_ok(), "a chunk below the ceiling must pass through");
        assert_eq!(ctx.request_body_bytes, 5, "the released chunk must be counted");

        let mut second = Some(Bytes::from_static(b"56789"));
        let result = execute(&pipeline, &mut session, &mut second, true, &mut ctx).await;
        assert!(
            result.is_err(),
            "chunks must accumulate so a released body cannot exceed the ceiling in pieces"
        );
    }

    #[test]
    fn pre_read_body_drains_chunks_in_order() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
        ]));

        let chunks = ctx.pre_read_body.as_mut().unwrap();
        assert_eq!(
            chunks.pop_front().unwrap(),
            Bytes::from_static(b"first"),
            "first chunk should drain first"
        );
        assert_eq!(
            chunks.pop_front().unwrap(),
            Bytes::from_static(b"second"),
            "second chunk should drain second"
        );
        assert_eq!(
            chunks.pop_front().unwrap(),
            Bytes::from_static(b"third"),
            "third chunk should drain third"
        );
        assert!(chunks.is_empty(), "deque should be empty after draining all chunks");
    }

    #[test]
    fn pre_read_body_empty_deque_yields_none() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::new());

        let chunks = ctx.pre_read_body.as_ref().unwrap();
        assert!(chunks.is_empty(), "empty deque should report is_empty");
    }

    #[test]
    fn pre_read_body_cleared_after_last_pop() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"only")]));

        let chunks = ctx.pre_read_body.as_mut().unwrap();
        let popped = chunks.pop_front();
        assert_eq!(
            popped.unwrap(),
            Bytes::from_static(b"only"),
            "single chunk should drain"
        );
        assert!(chunks.is_empty(), "deque should be empty after last pop");

        if chunks.is_empty() {
            ctx.pre_read_body = None;
        }
        assert!(
            ctx.pre_read_body.is_none(),
            "pre_read_body should be None after draining all chunks"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a default request context for body filter tests.
    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    /// Build an empty pipeline carrying a global request body ceiling.
    fn ceiling_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        let mut pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        pipeline.apply_body_limits(Some(CEILING), None, false).unwrap();
        pipeline
    }

    /// Context for a `StreamBuffer` request body that a filter released.
    fn released_stream_buffer_ctx() -> PingoraRequestCtx {
        let mut ctx = make_ctx();
        ctx.request_body_mode = BodyMode::StreamBuffer {
            max_bytes: Some(CEILING),
        };
        ctx.request_body_released = true;
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::POST,
            uri: "/upload".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        ctx
    }

    /// Build a proxy session that has read the given raw HTTP/1.1
    /// request. The client half must stay alive for response writes.
    async fn session_for(raw: &str) -> (Session, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tokio::io::duplex(1_048_576);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        let read = session.read_request().await.unwrap();
        assert!(read, "the session must parse the request header");
        (session, client)
    }
}
