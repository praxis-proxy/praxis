// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Response body filter execution.
//!
//! Implements Pingora's synchronous `response_body_filter` hook.
//! Runs the pipeline's response-body filters on each chunk,
//! buffering or streaming per the pipeline's [`BodyMode`]. The
//! synchronous constraint (no `.await`) is a Pingora API limitation;
//! body filters must complete without async I/O.
//!
//! [`BodyMode`]: praxis_filter::BodyMode

use std::time::Duration;

use bytes::Bytes;
use pingora_core::Result;
use praxis_filter::{BodyMode, FilterAction, FilterPipeline};
use tracing::{debug, error};

use super::{
    super::context::PingoraRequestCtx, BodyFilterOutput, accumulate_stream_buffer, check_body_size_limit,
    release_stream_buffer, suppress_stream_buffer_chunk,
};

// -----------------------------------------------------------------------------
// Response Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a response body chunk (synchronous; Pingora constraint).
#[expect(clippy::too_many_lines, reason = "body filter dispatch")]
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
        mark_delivered_at_eos(ctx, end_of_stream);
        return Ok(None);
    }

    let is_stream_buffer = matches!(ctx.response_body_mode, BodyMode::StreamBuffer { .. });

    match ctx.response_body_mode {
        BodyMode::SizeLimit { max_bytes } => {
            if check_body_size_limit(body.as_ref(), &mut ctx.response_body_bytes, max_bytes) {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "response body exceeds maximum size",
                ));
            }
            mark_delivered_at_eos(ctx, end_of_stream);
            return Ok(None);
        },

        BodyMode::Stream => {
            // The global body_limits ceiling applies to streamed bodies too;
            // Stream mode just counts instead of buffering. The projection
            // does not mutate the counter — the filter pipeline below is
            // the accumulator. `None` is only reachable with
            // allow_unbounded_body.
            let chunk_len = body.as_ref().map_or(0, Bytes::len) as u64;
            if let Some(max) = pipeline.response_body_ceiling()
                && ctx.response_body_bytes.saturating_add(chunk_len) > max as u64
            {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "streamed response body exceeds global body limit",
                ));
            }
        },

        BodyMode::StreamBuffer { max_bytes } if !ctx.response_body_released => {
            if accumulate_stream_buffer(body, &mut ctx.response_body_buffer, end_of_stream, max_bytes) {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "response body exceeds stream_buffer size limit",
                ));
            }
            if end_of_stream {
                // The mid-stream chunks were already counted incrementally,
                // and `body` now holds the frozen full buffer the pipeline
                // will count again below. Reset so the final total is the
                // buffer size, not double it.
                ctx.response_body_bytes = 0;
            }
        },

        // After Release the body streams unbuffered; the global ceiling
        // still applies (StreamBuffer's own cap no longer runs).
        BodyMode::StreamBuffer { .. } => {
            let chunk_len = body.as_ref().map_or(0, Bytes::len) as u64;
            if let Some(max) = pipeline.response_body_ceiling()
                && ctx.response_body_bytes.saturating_add(chunk_len) > max as u64
            {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "released response body exceeds global body limit",
                ));
            }
        },
        _ => tracing::error!("unhandled BodyMode variant in response body filter"),
    }

    let (result, response_body_bytes, output) = {
        let (mut fctx, response_header) = ctx.response_body_context_for(pipeline).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set when response body hooks are active",
            )
        })?;
        let r =
            pipeline.execute_http_response_body_with_response_header(&mut fctx, body, end_of_stream, response_header);
        (r, fctx.response_body_bytes, BodyFilterOutput::take_from(&mut fctx))
    };
    ctx.response_body_bytes = response_body_bytes;
    output.write_back(ctx);

    match result {
        Ok(
            FilterAction::Continue
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => {
            suppress_stream_buffer_chunk(body, is_stream_buffer, ctx.response_body_released, end_of_stream);
            mark_delivered_at_eos(ctx, end_of_stream);
            Ok(None)
        },
        Ok(FilterAction::Release) => {
            release_stream_buffer(
                body,
                is_stream_buffer,
                &mut ctx.response_body_released,
                &mut ctx.response_body_buffer,
                end_of_stream,
            );
            mark_delivered_at_eos(ctx, end_of_stream);
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
            error!(error = %e, "filter pipeline error during response body");
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("response body filter error: {e}"),
            ))
        },
    }
}

/// Record that the response was delivered to completion.
///
/// Called only on success exits: setting the flag before the size checks
/// and filter runs in the same invocation would mark responses aborted at
/// end-of-stream as delivered, suppressing the fallback access record.
fn mark_delivered_at_eos(ctx: &mut PingoraRequestCtx, end_of_stream: bool) {
    if end_of_stream {
        ctx.response_delivery_complete = true;
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
    use praxis_filter::FilterRegistry;

    use super::*;

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
