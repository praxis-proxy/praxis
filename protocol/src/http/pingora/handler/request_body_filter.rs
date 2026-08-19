// SPDX-License-Identifier: MIT
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
                send_rejection(session, Rejection::status(413)).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "request body exceeds stream_buffer size limit",
                ));
            }
        },

        BodyMode::StreamBuffer { .. } | BodyMode::Stream => {},
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
            send_rejection(session, rejection).await;
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "request body rejected by filter pipeline",
            ))
        },
        Err(e) => {
            error!(error = %e, "filter pipeline error during request body");
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

    use crate::http::pingora::context::PingoraRequestCtx;

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
}
