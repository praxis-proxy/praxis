//! Request body filter: buffers or streams body chunks through the pipeline,
//! enforcing size limits.

use bytes::Bytes;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_filter::{BodyBuffer, BodyMode, FilterAction, FilterContext, FilterPipeline, Rejection};
use tracing::warn;

use super::super::{context::RequestCtx, convert::send_rejection};

// -----------------------------------------------------------------------------
// Request Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a request body chunk, enforcing size limits.
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut RequestCtx,
) -> Result<()> {
    // When the body was pre-read during request_filter (StreamBuffer
    // mode), forward the stored chunks instead of reading from session.
    if let Some(ref mut chunks) = ctx.pre_read_body {
        *body = chunks.pop_front();
        return Ok(());
    }

    let caps = pipeline.body_capabilities();

    if !caps.needs_request_body {
        return Ok(());
    }

    let is_stream_buffer = matches!(caps.request_body_mode, BodyMode::StreamBuffer { .. });

    match caps.request_body_mode {
        // --- Buffer: accumulate all chunks, deliver complete body on EOS ---
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

        // --- StreamBuffer: accumulate AND deliver each chunk to filters ---
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
            // Fall through: filters see the original chunk below.
        },

        // StreamBuffer post-release or Stream: pass through directly.
        BodyMode::StreamBuffer { .. } | BodyMode::Stream => {},
    }

    // ---------------------------------------------------------
    // Run Filter Pipeline
    // ---------------------------------------------------------

    let request = ctx.request_snapshot.as_ref().ok_or_else(|| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "request snapshot not set when request body hooks are active",
        )
    })?;

    // Move cluster/upstream into the filter context instead of cloning.
    // Body filters never modify these fields, so we move them out, run
    // the pipeline, then move them back. Zero allocations per chunk.
    let cluster = ctx.cluster.take();
    let upstream = ctx.upstream.take();

    let mut filter_ctx = FilterContext {
        client_addr: ctx.client_addr,
        cluster,
        extra_request_headers: Vec::new(),
        request,
        request_body_bytes: ctx.request_body_bytes,
        request_start: ctx.request_start,
        response_body_bytes: ctx.response_body_bytes,
        response_header: None,
        upstream,
    };

    let result = pipeline
        .execute_http_request_body(&mut filter_ctx, body, end_of_stream)
        .await;
    ctx.request_body_bytes = filter_ctx.request_body_bytes;
    ctx.cluster = filter_ctx.cluster;
    ctx.upstream = filter_ctx.upstream;

    match result {
        Ok(FilterAction::Continue) => {
            if is_stream_buffer && !ctx.request_body_released {
                if end_of_stream {
                    // Auto-release on EOS.
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
mod tests {
    use std::collections::VecDeque;

    use bytes::Bytes;
    use praxis_filter::BodyBuffer;

    use crate::http::pingora::context::RequestCtx;

    fn make_ctx() -> RequestCtx {
        RequestCtx::default()
    }

    /// Push `chunk` into `ctx.request_body_buffer` bounded by `max_bytes`.
    /// Returns `true` on success, `false` on overflow.
    fn buffer_chunk(ctx: &mut RequestCtx, chunk: Bytes, max_bytes: usize) -> bool {
        let buf = ctx
            .request_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        buf.push(chunk).is_ok()
    }

    #[test]
    fn buffer_accumulates_chunks() {
        let mut ctx = make_ctx();

        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"hello "), 100));
        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"world"), 100));

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn buffer_overflow_is_detected() {
        let mut ctx = make_ctx();
        assert!(!buffer_chunk(&mut ctx, Bytes::from_static(b"too long"), 3));
    }

    #[test]
    fn buffer_exact_limit_is_accepted() {
        let mut ctx = make_ctx();
        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"abc"), 3));
    }

    // -------------------------------------------------------------------------
    // StreamBuffer tests
    // -------------------------------------------------------------------------

    #[test]
    fn stream_buffer_accumulates_and_clones() {
        let mut ctx = make_ctx();
        let max_bytes = 100;

        // Simulate StreamBuffer: clone chunk into buffer.
        let chunk = Bytes::from_static(b"hello ");
        let buf = ctx
            .request_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        assert!(buf.push(chunk.clone()).is_ok());

        let chunk2 = Bytes::from_static(b"world");
        let buf = ctx.request_body_buffer.as_mut().unwrap();
        assert!(buf.push(chunk2.clone()).is_ok());

        // Buffer accumulated both chunks.
        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn stream_buffer_overflow_detected() {
        let mut ctx = make_ctx();
        let chunk = Bytes::from_static(b"too long");
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));
        assert!(buf.push(chunk).is_err());
    }

    #[test]
    fn stream_buffer_release_flag_persists() {
        let mut ctx = make_ctx();
        assert!(!ctx.request_body_released);
        ctx.request_body_released = true;
        assert!(ctx.request_body_released);
    }

    // -------------------------------------------------------------------------
    // Pre-read body forwarding
    // -------------------------------------------------------------------------

    #[test]
    fn pre_read_body_drains_chunks_in_order() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"third"),
        ]));

        // Simulate draining: each call pops the front chunk.
        let chunks = ctx.pre_read_body.as_mut().unwrap();
        assert_eq!(chunks.pop_front().unwrap(), Bytes::from_static(b"first"));
        assert_eq!(chunks.pop_front().unwrap(), Bytes::from_static(b"second"));
        assert_eq!(chunks.pop_front().unwrap(), Bytes::from_static(b"third"));
        assert!(chunks.is_empty());
    }

    #[test]
    fn pre_read_body_empty_deque_yields_none() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::new());

        let chunks = ctx.pre_read_body.as_ref().unwrap();
        assert!(chunks.is_empty());
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn buffer_empty_body_at_end_of_stream() {
        let mut ctx = make_ctx();
        // No chunks pushed; buffer is None. On EOS, body should be None.
        let buf = ctx.request_body_buffer.take();
        let body: Option<Bytes> = buf.map(BodyBuffer::freeze);
        assert!(body.is_none());
    }

    #[test]
    fn buffer_single_chunk_freeze_avoids_copy() {
        let mut ctx = make_ctx();
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(100));
        buf.push(Bytes::from_static(b"only")).unwrap();

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"only"));
    }

    #[test]
    fn buffer_multiple_chunks_concatenate_correctly() {
        let mut ctx = make_ctx();
        let buf = ctx.request_body_buffer.get_or_insert_with(|| BodyBuffer::new(1024));
        buf.push(Bytes::from_static(b"a")).unwrap();
        buf.push(Bytes::from_static(b"b")).unwrap();
        buf.push(Bytes::from_static(b"c")).unwrap();

        let frozen = ctx.request_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"abc"));
    }

    #[test]
    fn buffer_incremental_overflow_on_second_push() {
        let mut ctx = make_ctx();
        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"aa"), 5));
        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"bb"), 5));
        // Total is 4; one more byte pushes to 5 (at limit).
        assert!(buffer_chunk(&mut ctx, Bytes::from_static(b"c"), 5));
        // Now at 5, next push overflows.
        let buf = ctx.request_body_buffer.as_mut().unwrap();
        assert!(buf.push(Bytes::from_static(b"d")).is_err());
    }
}
