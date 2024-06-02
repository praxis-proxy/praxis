//! Response body filter: buffers or streams response body chunks through
//! the pipeline (synchronous, per Pingora constraint).

use std::time::Duration;

use bytes::Bytes;
use pingora_core::Result;
use praxis_filter::{BodyBuffer, BodyMode, FilterAction, FilterContext, FilterPipeline};
use tracing::{debug, warn};

use super::super::context::RequestCtx;

// -----------------------------------------------------------------------------
// Response Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a response body chunk (synchronous; Pingora constraint).
pub(super) fn execute(
    pipeline: &FilterPipeline,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut RequestCtx,
) -> Result<Option<Duration>> {
    let caps = pipeline.body_capabilities();

    if !caps.needs_response_body {
        return Ok(None);
    }

    let is_stream_buffer = matches!(caps.response_body_mode, BodyMode::StreamBuffer { .. });

    match caps.response_body_mode {
        // --- Buffer: accumulate all chunks, deliver complete body on EOS ---
        BodyMode::Buffer { max_bytes } => {
            if let Some(chunk) = body.take() {
                let buf = ctx
                    .response_body_buffer
                    .get_or_insert_with(|| BodyBuffer::new(max_bytes));

                if buf.push(chunk).is_err() {
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::InternalError,
                        "response body exceeds maximum size",
                    ));
                }
            }

            if !end_of_stream {
                *body = None;
                return Ok(None);
            }

            let buf = ctx.response_body_buffer.take();
            *body = buf.map(BodyBuffer::freeze);
        },

        // --- StreamBuffer: accumulate AND deliver each chunk to filters ---
        BodyMode::StreamBuffer { max_bytes } if !ctx.response_body_released => {
            if let Some(ref chunk) = *body {
                let limit = max_bytes.unwrap_or(usize::MAX);
                let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(limit));

                if buf.push(chunk.clone()).is_err() {
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::InternalError,
                        "response body exceeds stream_buffer size limit",
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
            "request snapshot not set when response body hooks are active",
        )
    })?;

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

    let result = pipeline.execute_http_response_body(&mut filter_ctx, body, end_of_stream);
    ctx.response_body_bytes = filter_ctx.response_body_bytes;
    ctx.cluster = filter_ctx.cluster;
    ctx.upstream = filter_ctx.upstream;
    match result {
        Ok(FilterAction::Continue) => {
            if is_stream_buffer && !ctx.response_body_released {
                if end_of_stream {
                    *body = ctx.response_body_buffer.take().map(BodyBuffer::freeze);
                } else {
                    *body = None;
                }
            }
            Ok(None)
        },
        Ok(FilterAction::Release) => {
            if is_stream_buffer && !ctx.response_body_released {
                ctx.response_body_released = true;
                *body = ctx.response_body_buffer.take().map(BodyBuffer::freeze);
            }
            Ok(None)
        },
        Ok(FilterAction::Reject(rejection)) => {
            // A response body filter rejected the response. Abort the connection so the
            // downstream client does not receive a partial or forbidden response body.
            debug!(
                status = rejection.status,
                "response body filter rejected response; aborting connection"
            );
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!(
                    "response body filter rejected response with status {}",
                    rejection.status
                ),
            ))
        },
        Err(e) => {
            warn!(error = %e, "filter pipeline error during response body");
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("response body filter error: {e}"),
            ))
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use praxis_filter::{FilterPipeline, FilterRegistry};

    use super::*;
    use crate::http::pingora::context::RequestCtx;

    fn make_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&[], &registry).unwrap()
    }

    fn make_ctx() -> RequestCtx {
        RequestCtx::default()
    }

    #[test]
    fn no_body_capabilities_returns_none() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, true, &mut ctx);

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn body_untouched_when_no_capabilities() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"response data"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut body, false, &mut ctx).unwrap();

        assert_eq!(body, Some(Bytes::from_static(b"response data")));
    }

    // -------------------------------------------------------------------------
    // StreamBuffer tests
    // -------------------------------------------------------------------------

    #[test]
    fn response_stream_buffer_accumulates_and_clones() {
        let mut ctx = make_ctx();
        let max_bytes = 100;

        let chunk = Bytes::from_static(b"response ");
        let buf = ctx
            .response_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        assert!(buf.push(chunk.clone()).is_ok());

        let chunk2 = Bytes::from_static(b"data");
        let buf = ctx.response_body_buffer.as_mut().unwrap();
        assert!(buf.push(chunk2.clone()).is_ok());

        let frozen = ctx.response_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"response data"));
    }

    #[test]
    fn response_stream_buffer_release_flag_persists() {
        let mut ctx = make_ctx();
        assert!(!ctx.response_body_released);
        ctx.response_body_released = true;
        assert!(ctx.response_body_released);
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn empty_body_none_passes_through() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, false, &mut ctx);
        assert!(result.is_ok());
        assert!(body.is_none());
    }

    #[test]
    fn empty_body_at_end_of_stream() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, true, &mut ctx);
        assert!(result.is_ok());
        assert!(body.is_none());
    }

    #[test]
    fn response_buffer_overflow_detected() {
        let mut ctx = make_ctx();
        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));

        let result = buf.push(Bytes::from_static(b"too long data"));
        assert!(result.is_err());
    }

    #[test]
    fn response_buffer_exact_limit_succeeds() {
        let mut ctx = make_ctx();
        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));

        assert!(buf.push(Bytes::from_static(b"exact")).is_ok());
        assert_eq!(ctx.response_body_buffer.unwrap().total_bytes(), 5);
    }

    #[test]
    fn response_buffer_empty_freeze() {
        let buf = BodyBuffer::new(100);
        let frozen = buf.freeze();
        assert!(frozen.is_empty());
    }

    #[test]
    fn multiple_chunks_accumulated_correctly() {
        let mut ctx = make_ctx();

        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(1024));
        buf.push(Bytes::from_static(b"chunk1 ")).unwrap();
        buf.push(Bytes::from_static(b"chunk2 ")).unwrap();
        buf.push(Bytes::from_static(b"chunk3")).unwrap();

        let frozen = ctx.response_body_buffer.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"chunk1 chunk2 chunk3"));
    }
}
