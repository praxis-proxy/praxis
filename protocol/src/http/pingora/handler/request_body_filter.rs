// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Request body filter: buffers or streams body chunks through the pipeline, enforcing size limits.

use bytes::Bytes;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_filter::{BodyBuffer, BodyMode, FilterAction, FilterPipeline, Rejection};
use tracing::warn;

use super::super::{context::PingoraRequestCtx, convert::send_rejection};

// -----------------------------------------------------------------------------
// Request Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a request body chunk, enforcing size limits.
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "body filter dispatch"
)]
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

    if let Some(ref mut chunks) = ctx.pre_read_body {
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

    let is_stream_buffer = matches!(caps.request_body_mode, BodyMode::StreamBuffer { .. });

    match caps.request_body_mode {
        BodyMode::Buffer { max_bytes } => {
            if let Some(chunk) = body.take() {
                let buf = ctx
                    .request_body_buffer
                    .get_or_insert_with(|| BodyBuffer::new(max_bytes));

                if buf.push(chunk).is_err() {
                    send_rejection(session, Rejection::status(413)).await;
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(413),
                        "request body exceeds maximum size",
                    ));
                }
            }

            if !end_of_stream {
                *body = None;
                return Ok(());
            }

            let buf = ctx.request_body_buffer.take();
            *body = buf.map(BodyBuffer::freeze);
        },

        BodyMode::SizeLimit { max_bytes } => {
            if let Some(ref chunk) = *body {
                #[allow(clippy::cast_possible_truncation, reason = "chunk length fits u64")]
                let chunk_len = chunk.len() as u64;
                ctx.request_body_bytes += chunk_len;

                #[allow(clippy::cast_possible_truncation, reason = "max_bytes fits u64")]
                let limit = max_bytes as u64;
                if ctx.request_body_bytes > limit {
                    send_rejection(session, Rejection::status(413)).await;
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(413),
                        "request body exceeds maximum size",
                    ));
                }
            }
            return Ok(());
        },

        BodyMode::StreamBuffer { max_bytes } if !ctx.request_body_released => {
            if let Some(ref chunk) = *body {
                let limit = max_bytes.unwrap_or(usize::MAX);
                let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(limit));

                if buf.push(chunk.clone()).is_err() {
                    send_rejection(session, Rejection::status(413)).await;
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(413),
                        "request body exceeds stream_buffer size limit",
                    ));
                }
            }
            tracing::trace!("stream buffer: filters see the original chunk");
        },

        BodyMode::StreamBuffer { .. } | BodyMode::Stream => {},
    }

    let (result, body_bytes, cluster, upstream) = {
        let mut fctx = ctx.filter_context_for(pipeline, None).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set when request body hooks are active",
            )
        })?;
        let r = pipeline.execute_http_request_body(&mut fctx, body, end_of_stream).await;
        (r, fctx.request_body_bytes, fctx.cluster, fctx.upstream)
    };
    ctx.request_body_bytes = body_bytes;
    ctx.cluster = cluster;
    ctx.upstream = upstream;

    match result {
        Ok(FilterAction::Continue) => {
            if is_stream_buffer && !ctx.request_body_released {
                if end_of_stream {
                    tracing::debug!("auto-releasing StreamBuffer on end-of-stream");
                    *body = ctx.request_body_buffer.take().map(BodyBuffer::freeze);
                } else {
                    *body = None; // Suppress: don't forward yet.
                }
            }
            Ok(())
        },
        Ok(FilterAction::Release) => {
            if is_stream_buffer && !ctx.request_body_released {
                ctx.request_body_released = true;
                *body = ctx.request_body_buffer.take().map(BodyBuffer::freeze);
            }
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
            warn!(error = %e, "filter pipeline error during request body");
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
    use praxis_filter::BodyBuffer;

    use crate::http::pingora::context::PingoraRequestCtx;

    #[test]
    fn buffer_accumulates_chunks() {
        let mut ctx = make_ctx();

        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"hello "), 100),
            "first chunk should succeed"
        );
        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"world"), 100),
            "second chunk should succeed"
        );

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"hello world"),
            "chunks should be concatenated"
        );
    }

    #[test]
    fn buffer_overflow_is_detected() {
        let mut ctx = make_ctx();
        assert!(
            !buffer_chunk(&mut ctx, Bytes::from_static(b"too long"), 3),
            "chunk exceeding limit should fail"
        );
    }

    #[test]
    fn buffer_exact_limit_is_accepted() {
        let mut ctx = make_ctx();
        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"abc"), 3),
            "chunk at exact limit should succeed"
        );
    }

    #[test]
    fn stream_buffer_accumulates_and_clones() {
        let mut ctx = make_ctx();
        let max_bytes = 100;

        let chunk = Bytes::from_static(b"hello ");
        let buf = ctx
            .request_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        assert!(
            buf.push(chunk.clone()).is_ok(),
            "first stream chunk push should succeed"
        );

        let chunk2 = Bytes::from_static(b"world");
        let buf = ctx.request_body_buffer.as_mut().unwrap();
        assert!(
            buf.push(chunk2.clone()).is_ok(),
            "second stream chunk push should succeed"
        );

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"hello world"),
            "stream buffer should contain concatenated chunks"
        );
    }

    #[test]
    fn stream_buffer_overflow_detected() {
        let mut ctx = make_ctx();
        let chunk = Bytes::from_static(b"too long");
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));
        assert!(
            buf.push(chunk).is_err(),
            "stream buffer push exceeding limit should fail"
        );
    }

    #[test]
    fn stream_buffer_release_flag_persists() {
        let mut ctx = make_ctx();
        assert!(!ctx.request_body_released, "release flag should start false");
        ctx.request_body_released = true;
        assert!(ctx.request_body_released, "release flag should be true after setting");
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

    #[test]
    fn buffer_empty_body_at_end_of_stream() {
        let mut ctx = make_ctx();
        let buf = ctx.request_body_buffer.take();
        let body: Option<Bytes> = buf.map(BodyBuffer::freeze);
        assert!(body.is_none(), "taking from empty buffer should yield None");
    }

    #[test]
    fn buffer_single_chunk_freeze_avoids_copy() {
        let mut ctx = make_ctx();
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(100));
        buf.push(Bytes::from_static(b"only")).unwrap();

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"only"),
            "single chunk should freeze without copy"
        );
    }

    #[test]
    fn buffer_multiple_chunks_concatenate_correctly() {
        let mut ctx = make_ctx();
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(1024));
        buf.push(Bytes::from_static(b"a")).unwrap();
        buf.push(Bytes::from_static(b"b")).unwrap();
        buf.push(Bytes::from_static(b"c")).unwrap();

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"abc"),
            "multiple chunks should concatenate in order"
        );
    }

    #[test]
    fn buffer_incremental_overflow_on_second_push() {
        let mut ctx = make_ctx();
        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"aa"), 5),
            "first 2 bytes should fit"
        );
        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"bb"), 5),
            "next 2 bytes should fit"
        );
        assert!(
            buffer_chunk(&mut ctx, Bytes::from_static(b"c"), 5),
            "total of 5 should fit exact limit"
        );
        let buf = ctx.request_body_buffer.as_mut().unwrap();
        assert!(
            buf.push(Bytes::from_static(b"d")).is_err(),
            "6th byte should overflow the 5-byte limit"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a default request context for body filter tests.
    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    /// Push `chunk` into `ctx.request_body_buffer` bounded by `max_bytes`.
    /// Returns `true` on success, `false` on overflow.
    fn buffer_chunk(ctx: &mut PingoraRequestCtx, chunk: Bytes, max_bytes: usize) -> bool {
        let buf = ctx
            .request_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        buf.push(chunk).is_ok()
    }
}
