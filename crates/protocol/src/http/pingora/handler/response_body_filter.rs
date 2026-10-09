// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Response body filter execution.
//!
//! Backs Pingora's `response_body_filter` hook. Runs the pipeline's
//! response-body filters on each chunk, buffering or streaming per the
//! pipeline's [`BodyMode`]. The Pingora hook is async, but this runs
//! synchronously because [`HttpFilter::on_response_body`] is a plain
//! `fn`: body filters must complete without async I/O.
//!
//! [`BodyMode`]: praxis_filter::BodyMode
//! [`HttpFilter::on_response_body`]: praxis_filter::HttpFilter::on_response_body

use std::time::Duration;

use bytes::Bytes;
use pingora_core::Result;
use praxis_filter::{BodyMode, FilterAction, FilterPipeline};
use tracing::{debug, error};

use super::{
    super::context::PingoraRequestCtx,
    body_util::{
        BodyFilterOutput, accumulate_stream_buffer, check_body_size_limit, exceeds_body_ceiling, release_stream_buffer,
        suppress_stream_buffer_chunk,
    },
};

// -----------------------------------------------------------------------------
// Response Body Filters
// -----------------------------------------------------------------------------

/// Run body filters on a response body chunk (synchronous, like [`HttpFilter::on_response_body`]).
///
/// [`HttpFilter::on_response_body`]: praxis_filter::HttpFilter::on_response_body
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

    // The global body_limits ceiling applies in every mode but SizeLimit,
    // which carries its own cap. StreamBuffer's buffering cap applies only
    // while accumulating; after Release, Stream still obeys this ceiling.
    // The projection does not mutate the counter; the filter pipeline below
    // is the accumulator. `None` is only reachable with allow_unbounded_body.
    if !matches!(ctx.response_body_mode, BodyMode::SizeLimit { .. })
        && exceeds_body_ceiling(pipeline.response_body_ceiling(), ctx.response_body_bytes, body.as_ref())
    {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "response body exceeds global body limit",
        ));
    }

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

        BodyMode::Stream | BodyMode::StreamBuffer { .. } => {},
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
                &mut ctx.response_body_mode,
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

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

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
    use std::sync::Arc;

    use praxis_filter::{
        BodyAccess, FilterEntry, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, Request,
    };

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

    #[test]
    fn connection_upgraded_returns_early() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"should be ignored"));
        let mut ctx = make_ctx();
        ctx.connection_upgraded = true;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert_eq!(result.unwrap(), None, "should return None when connection upgraded");
        assert_eq!(
            body,
            Some(Bytes::from_static(b"should be ignored")),
            "body should be untouched when connection upgraded"
        );
    }

    #[test]
    fn delivery_complete_marked_at_eos() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();
        assert!(!ctx.response_delivery_complete, "should start as false");

        execute(&pipeline, &mut body, true, &mut ctx).unwrap();

        assert!(ctx.response_delivery_complete, "should mark complete at end of stream");
    }

    #[test]
    fn delivery_complete_not_marked_mid_stream() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"chunk"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut body, false, &mut ctx).unwrap();

        assert!(!ctx.response_delivery_complete, "should not mark complete mid-stream");
    }

    #[test]
    fn size_limit_mode_returns_early_when_no_capabilities() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"data"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 1024 };

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_ok(), "should succeed without body capabilities");
        assert_eq!(body, Some(Bytes::from_static(b"data")), "body should be unchanged");
    }

    #[test]
    #[ignore]
    fn size_limit_mode_tracks_bytes() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"test"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 1024 };
        ctx.response_body_bytes = 0;

        execute(&pipeline, &mut body, false, &mut ctx).unwrap();

        assert_eq!(ctx.response_body_bytes, 4, "should track 4 bytes");
    }

    #[ignore]
    #[test]
    fn size_limit_mode_exceeds_limit() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"too much data"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 5 };
        ctx.response_body_bytes = 0;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_err(), "should fail when exceeding size limit");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "error should mention size limit"
        );
    }
    #[ignore]
    #[test]
    fn size_limit_mode_cumulative_exceeds() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"more"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 10 };
        ctx.response_body_bytes = 8;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_err(), "should fail when cumulative size exceeds limit");
    }

    #[test]
    fn stream_mode_with_none_body() {
        let pipeline = make_pipeline();
        let mut body: Option<Bytes> = None;
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::Stream;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_ok(), "should succeed with None body in Stream mode");
    }

    #[test]
    fn stream_buffer_mode_accumulates_chunks() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"chunk1"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(1024) };
        ctx.response_body_released = false;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_ok(), "should succeed accumulating chunk");
    }

    #[test]
    #[ignore]
    fn stream_buffer_mode_exceeds_limit() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"way too much data"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(5) };
        ctx.response_body_released = false;
        ctx.response_body_buffer = None;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_err(), "should fail when stream buffer exceeds limit");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("stream_buffer size limit"),
            "error should mention stream_buffer limit"
        );
    }

    #[test]
    #[ignore]
    fn stream_buffer_mode_at_eos_resets_byte_counter() {
        let pipeline = make_pipeline();
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(1024) };
        ctx.response_body_released = false;
        ctx.response_body_bytes = 100;

        let mut body1 = Some(Bytes::from_static(b"chunk1"));
        execute(&pipeline, &mut body1, false, &mut ctx).unwrap();

        let mut body2 = Some(Bytes::from_static(b"chunk2"));
        execute(&pipeline, &mut body2, true, &mut ctx).unwrap();

        assert_eq!(
            ctx.response_body_bytes, 0,
            "should reset counter at EOS before final count"
        );
    }

    #[test]
    fn stream_buffer_mode_after_release() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"data"));
        let mut ctx = make_ctx();
        ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: Some(1024) };
        ctx.response_body_released = true;

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_ok(), "should succeed after release");
    }

    #[test]
    fn unhandled_body_mode_logs_error() {
        let pipeline = make_pipeline();
        let mut body = Some(Bytes::from_static(b"data"));
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut body, false, &mut ctx);

        assert!(result.is_ok(), "should not fail on unhandled mode (logs only)");
    }

    #[test]
    fn marks_delivered_only_at_eos() {
        let pipeline = make_pipeline();
        let mut ctx = make_ctx();

        let mut body1 = Some(Bytes::from_static(b"chunk1"));
        execute(&pipeline, &mut body1, false, &mut ctx).unwrap();
        assert!(!ctx.response_delivery_complete, "not complete mid-stream");

        let mut body2 = Some(Bytes::from_static(b"chunk2"));
        execute(&pipeline, &mut body2, false, &mut ctx).unwrap();
        assert!(!ctx.response_delivery_complete, "still not complete");

        let mut body3: Option<Bytes> = None;
        execute(&pipeline, &mut body3, true, &mut ctx).unwrap();
        assert!(ctx.response_delivery_complete, "complete at EOS");
    }

    #[test]
    fn release_exposes_stream_on_nonempty_final_chunk() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = release_pipeline(6, false)?;
        let mut ctx = release_ctx(BodyMode::StreamBuffer { max_bytes: Some(2) });
        let mut prefix = Some(Bytes::from_static(b"ab"));
        execute(&pipeline, &mut prefix, false, &mut ctx)?;
        assert_eq!(prefix, Some(Bytes::from_static(b"ab")), "release flushes the prefix");
        assert_observed_mode(&ctx, "buffered");

        let mut tail = Some(Bytes::from_static(b"cdef"));
        execute(&pipeline, &mut tail, true, &mut ctx)?;
        assert_observed_mode(&ctx, "stream");
        assert_eq!(
            tail,
            Some(Bytes::from_static(b"cdef")),
            "repeated Release preserves the tail"
        );
        assert_eq!(ctx.response_body_bytes, 6, "each byte is counted once");
        assert!(ctx.response_body_buffer.is_none(), "released buffering never restarts");
        Ok(())
    }

    #[test]
    fn released_response_still_enforces_global_ceiling() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = release_pipeline(5, false)?;
        let mut ctx = release_ctx(BodyMode::StreamBuffer { max_bytes: Some(2) });
        let mut prefix = Some(Bytes::from_static(b"ab"));
        execute(&pipeline, &mut prefix, false, &mut ctx)?;
        let mut tail = Some(Bytes::from_static(b"cdef"));

        let result = execute(&pipeline, &mut tail, true, &mut ctx);
        assert!(
            matches!(&result, Err(error) if error.to_string().contains("global body limit")),
            "a streamed tail cannot bypass the global ceiling"
        );
        assert_eq!(ctx.response_body_bytes, 2, "rejected bytes are not counted");
        assert!(!ctx.response_delivery_complete, "rejected EOS is not delivered");
        Ok(())
    }

    #[test]
    fn release_at_eos_preserves_frozen_aggregate() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = release_pipeline(6, true)?;
        let mut ctx = release_ctx(BodyMode::StreamBuffer { max_bytes: Some(2) });
        let mut prefix = Some(Bytes::from_static(b"a"));
        execute(&pipeline, &mut prefix, false, &mut ctx)?;
        assert!(prefix.is_none(), "buffered prefix is withheld before Release");
        let mut body = Some(Bytes::from_static(b"b"));
        execute(&pipeline, &mut body, true, &mut ctx)?;
        assert_eq!(body, Some(Bytes::from_static(b"ab")), "EOS aggregate is preserved");
        assert_eq!(ctx.response_body_mode, BodyMode::Stream, "EOS Release ends buffering");
        assert_eq!(ctx.response_body_bytes, 2, "EOS counts the aggregate once");
        assert_eq!(
            pipeline.body_capabilities().response_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(2) },
            "declared capabilities remain unchanged"
        );
        Ok(())
    }

    #[test]
    fn release_leaves_original_stream_unchanged() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = release_pipeline(6, false)?;
        let mut ctx = release_ctx(BodyMode::Stream);
        for (chunk, end_of_stream) in [(b"ab".as_slice(), false), (b"cdef".as_slice(), true)] {
            let mut body = Some(Bytes::copy_from_slice(chunk));
            execute(&pipeline, &mut body, end_of_stream, &mut ctx)?;
            assert_eq!(body.as_deref(), Some(chunk), "Release leaves streamed bytes untouched");
            assert_observed_mode(&ctx, "stream");
        }
        assert_eq!(ctx.response_body_bytes, 6, "every streamed byte is counted once");
        assert!(!ctx.response_body_released, "original Stream never releases a buffer");
        Ok(())
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

    /// Build a body-capable pipeline with a release probe and a global ceiling.
    fn release_pipeline(
        ceiling: usize,
        release_at_eos: bool,
    ) -> Result<FilterPipeline, Box<dyn std::error::Error + Send + Sync>> {
        let mut registry = FilterRegistry::with_builtins();
        registry.register(
            "release_probe",
            FilterFactory::Http(Arc::new(move |_| Ok(Box::new(ReleaseProbe { release_at_eos })))),
        )?;
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str("- filter: release_probe")?;
        let mut pipeline = FilterPipeline::build(&mut entries, &registry)?;
        pipeline.apply_body_limits(None, Some(ceiling), false)?;
        Ok(pipeline)
    }

    /// Create a body context with the required request snapshot.
    fn release_ctx(mode: BodyMode) -> PingoraRequestCtx {
        let mut ctx = make_ctx();
        ctx.response_body_mode = mode;
        ctx.request_snapshot = Some(Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
        });
        ctx
    }

    /// Check the mode recorded by the body hook itself.
    fn assert_observed_mode(ctx: &PingoraRequestCtx, expected: &str) {
        assert_eq!(
            ctx.filter_metadata.get("release.mode").map(String::as_str),
            Some(expected),
            "the body hook sees the actual delivery mode"
        );
    }

    /// Records the response delivery mode and releases every body invocation.
    struct ReleaseProbe {
        /// Whether to hold the buffer until its EOS aggregate is delivered.
        release_at_eos: bool,
    }

    #[async_trait::async_trait]
    impl HttpFilter for ReleaseProbe {
        fn name(&self) -> &'static str {
            "release_probe"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> std::result::Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn response_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        fn response_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: Some(2) }
        }

        fn on_response_body(
            &self,
            ctx: &mut HttpFilterContext<'_>,
            _body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> std::result::Result<FilterAction, FilterError> {
            let mode = if ctx.response_body_mode == BodyMode::Stream {
                "stream"
            } else {
                "buffered"
            };
            ctx.filter_metadata.insert("release.mode".to_owned(), mode.to_owned());
            Ok(if self.release_at_eos && !end_of_stream {
                FilterAction::Continue
            } else {
                FilterAction::Release
            })
        }
    }
}
