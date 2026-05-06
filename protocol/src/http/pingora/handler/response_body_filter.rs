// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Response body filter execution.

use std::time::Duration;

use bytes::Bytes;
use pingora_core::Result;
use praxis_filter::{BodyBuffer, BodyMode, FilterAction, FilterPipeline};
use tracing::{debug, warn};

use super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Response Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a response body chunk (synchronous; Pingora constraint).
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "body filter dispatch"
)]
pub(super) fn execute(
    pipeline: &FilterPipeline,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut PingoraRequestCtx,
) -> Result<Option<Duration>> {
    if ctx.connection_upgraded {
        return Ok(None);
    }

    let caps = pipeline.body_capabilities();

    if !caps.needs_response_body {
        return Ok(None);
    }

    let is_stream_buffer = matches!(ctx.response_body_mode, BodyMode::StreamBuffer { .. });

    match ctx.response_body_mode {
        BodyMode::SizeLimit { max_bytes } => {
            if let Some(ref chunk) = *body {
                #[allow(clippy::cast_possible_truncation, reason = "chunk length fits u64")]
                let chunk_len = chunk.len() as u64;
                ctx.response_body_bytes += chunk_len;

                #[allow(clippy::cast_possible_truncation, reason = "max_bytes fits u64")]
                let limit = max_bytes as u64;
                if ctx.response_body_bytes > limit {
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::InternalError,
                        "response body exceeds maximum size",
                    ));
                }
            }
            return Ok(None);
        },

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

            if end_of_stream {
                tracing::trace!("stream buffer: freezing accumulated body before pipeline at EOS");
                *body = ctx.response_body_buffer.take().map(BodyBuffer::freeze);
            } else {
                tracing::trace!("stream buffer: filters see the original chunk");
            }
        },

        BodyMode::StreamBuffer { .. } | BodyMode::Stream | _ => {},
    }

    let (result, body_bytes, cluster, upstream, filter_metadata) = {
        let mut fctx = ctx.filter_context_for(pipeline, None).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set when response body hooks are active",
            )
        })?;
        let r = pipeline.execute_http_response_body(&mut fctx, body, end_of_stream);
        (
            r,
            fctx.response_body_bytes,
            fctx.cluster,
            fctx.upstream,
            fctx.filter_metadata,
        )
    };
    ctx.response_body_bytes = body_bytes;
    ctx.cluster = cluster;
    ctx.upstream = upstream;
    ctx.filter_metadata = filter_metadata;
    match result {
        Ok(FilterAction::Continue | FilterAction::BodyDone) => {
            if is_stream_buffer && !ctx.response_body_released && !end_of_stream {
                *body = None;
            }
            Ok(None)
        },
        Ok(FilterAction::Release) => {
            if is_stream_buffer && !ctx.response_body_released {
                ctx.response_body_released = true;
                if !end_of_stream {
                    *body = ctx.response_body_buffer.take().map(BodyBuffer::freeze);
                }
            }
            Ok(None)
        },
        Ok(FilterAction::Reject(rejection)) => {
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use bytes::Bytes;
    use praxis_filter::{FilterPipeline, FilterRegistry};

    use super::*;
    use crate::http::pingora::context::PingoraRequestCtx;

    #[test]
    fn no_body_capabilities_returns_none() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, true, &mut ctx);

        assert_eq!(result.unwrap(), None, "should return None when no body capabilities");
    }

    #[test]
    fn body_untouched_when_no_capabilities() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"response data"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut body, false, &mut ctx).unwrap();

        assert_eq!(
            body,
            Some(Bytes::from_static(b"response data")),
            "body should be unchanged without capabilities"
        );
    }

    #[test]
    fn response_stream_buffer_accumulates_and_clones() {
        let mut ctx = make_ctx();
        let max_bytes = 100;

        let chunk = Bytes::from_static(b"response ");
        let buf = ctx
            .response_body_buffer
            .get_or_insert_with(|| BodyBuffer::new(max_bytes));
        assert!(buf.push(chunk.clone()).is_ok(), "first chunk push should succeed");

        let chunk2 = Bytes::from_static(b"data");
        let buf = ctx.response_body_buffer.as_mut().unwrap();
        assert!(buf.push(chunk2.clone()).is_ok(), "second chunk push should succeed");

        let frozen = ctx.response_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"response data"),
            "frozen buffer should contain concatenated chunks"
        );
    }

    #[test]
    fn response_stream_buffer_release_flag_persists() {
        let mut ctx = make_ctx();
        assert!(!ctx.response_body_released, "release flag should start false");
        ctx.response_body_released = true;
        assert!(ctx.response_body_released, "release flag should be true after setting");
    }

    #[test]
    fn empty_body_none_passes_through() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, false, &mut ctx);
        assert!(result.is_ok(), "execute should succeed with None body");
        assert!(body.is_none(), "body should remain None");
    }

    #[test]
    fn empty_body_at_end_of_stream() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, true, &mut ctx);
        assert!(result.is_ok(), "execute should succeed at end of stream");
        assert!(body.is_none(), "body should remain None at end of stream");
    }

    #[test]
    fn response_buffer_overflow_detected() {
        let mut ctx = make_ctx();
        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));

        let result = buf.push(Bytes::from_static(b"too long data"));
        assert!(result.is_err(), "push exceeding limit should return error");
    }

    #[test]
    fn response_buffer_exact_limit_succeeds() {
        let mut ctx = make_ctx();
        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(5));

        assert!(
            buf.push(Bytes::from_static(b"exact")).is_ok(),
            "push at exact limit should succeed"
        );
        assert_eq!(
            ctx.response_body_buffer.unwrap().total_bytes(),
            5,
            "total bytes should match exact limit"
        );
    }

    #[test]
    fn response_buffer_empty_freeze() {
        let buf = BodyBuffer::new(100);
        let frozen = buf.freeze();
        assert!(frozen.is_empty(), "freezing empty buffer should produce empty bytes");
    }

    #[test]
    fn multiple_chunks_accumulated_correctly() {
        let mut ctx = make_ctx();

        let buf = ctx.response_body_buffer.get_or_insert_with(|| BodyBuffer::new(1024));
        buf.push(Bytes::from_static(b"chunk1 ")).unwrap();
        buf.push(Bytes::from_static(b"chunk2 ")).unwrap();
        buf.push(Bytes::from_static(b"chunk3")).unwrap();

        let frozen = ctx.response_body_buffer.take().unwrap().freeze();
        assert_eq!(
            frozen,
            Bytes::from_static(b"chunk1 chunk2 chunk3"),
            "chunks should be concatenated in order"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an empty filter pipeline for tests.
    fn make_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
    }

    /// Create a default request context for tests.
    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }
}
