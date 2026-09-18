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

use std::collections::VecDeque;

use bytes::Bytes;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_filter::{BodyMode, FilterAction, FilterPipeline, Rejection};
use tracing::error;

use super::{
    super::{context::PingoraRequestCtx, convert::send_rejection_for},
    BodyFilterOutput, accumulate_stream_buffer, check_body_size_limit, release_stream_buffer,
    suppress_stream_buffer_chunk,
};

// -----------------------------------------------------------------------------
// Request Body Filters
// -----------------------------------------------------------------------------

/// Forward the next pre-read request-body chunk, preferring the adapted
/// selected-upstream body (#1139) when adaptation ran.
///
/// Returns `true` when a pre-read/adapted drain is active and `*body` was set
/// (the caller must return immediately); `false` when no pre-read drain applies
/// and normal body-mode processing should proceed.
///
/// Once adaptation ran (`retained_adapted_request_body` is `Some`, a marker that
/// persists for the whole request), the adapted representation is drained
/// exclusively. After it is exhausted this forwards nothing and NEVER falls back
/// to the canonical `pre_read_body` — falling back would corrupt framing and
/// violate the #1138 iteration-isolation invariant.
fn drain_pre_read_body(ctx: &mut PingoraRequestCtx, body: &mut Option<Bytes>) -> bool {
    if ctx.retained_adapted_request_body.is_some() {
        *body = ctx.adapted_request_body.as_mut().and_then(VecDeque::pop_front);
        if ctx.adapted_request_body.as_ref().is_none_or(VecDeque::is_empty) {
            ctx.adapted_request_body = None;
        }
        return true;
    }
    if let Some(chunks) = &mut ctx.pre_read_body {
        *body = chunks.pop_front();
        if chunks.is_empty() {
            ctx.pre_read_body = None;
        }
        return true;
    }
    false
}

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

    if drain_pre_read_body(ctx, body) {
        tracing::trace!("forwarding pre-read (or adapted selected-upstream) body chunks");
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
                send_rejection_for(session, Rejection::status(413), ctx).await;
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
                send_rejection_for(session, Rejection::status(413), ctx).await;
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
                send_rejection_for(session, Rejection::status(413), ctx).await;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(413),
                    "streamed request body exceeds global body limit",
                ));
            }
        },

        BodyMode::StreamBuffer { .. } => {},
        _ => tracing::error!("unhandled BodyMode variant in request body filter"),
    }

    let (result, request_body_bytes, rewritten_path, output) = {
        let mut fctx = ctx.filter_context_for(pipeline, None).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set when request body hooks are active",
            )
        })?;
        let r = pipeline.execute_http_request_body(&mut fctx, body, end_of_stream).await;
        (
            r,
            fctx.request_body_bytes,
            fctx.rewritten_path.take(),
            BodyFilterOutput::take_from(&mut fctx),
        )
    };
    ctx.request_body_bytes = request_body_bytes;
    // Restore the rewritten path that filter_context! took from ctx (the
    // pre-read path restores it too). Request-body filters never set it, so this
    // round-trips the value unchanged, letting a later retry re-apply the
    // rewrite instead of forwarding the original path.
    ctx.rewritten_path = rewritten_path;
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
            send_rejection_for(session, rejection, ctx).await;
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "request body rejected by filter pipeline",
            ))
        },
        Err(e) => {
            error!(error = %e, "filter pipeline error during request body");
            ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_INTERNAL);
            send_rejection_for(session, Rejection::status(500), ctx).await;
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

    use super::drain_pre_read_body;
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

    #[test]
    fn drain_prefers_adapted_body_when_adaptation_ran() {
        let mut ctx = make_ctx();
        // Canonical pre-read is present but must be ignored once adaptation ran.
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"canonical")]));
        ctx.adapted_request_body = Some(VecDeque::from([Bytes::from_static(b"ADAPTED")]));
        ctx.retained_adapted_request_body = Some(VecDeque::from([Bytes::from_static(b"ADAPTED")]));

        let mut body = None;
        assert!(drain_pre_read_body(&mut ctx, &mut body), "drain is active");
        assert_eq!(body, Some(Bytes::from_static(b"ADAPTED")), "adapted body forwarded");

        // Exhausted: forwards nothing, never falls back to the canonical body.
        let mut next = None;
        assert!(
            drain_pre_read_body(&mut ctx, &mut next),
            "drain stays active after exhaustion"
        );
        assert_eq!(next, None, "no fallback to canonical bytes once adapted is drained");
        assert!(
            ctx.pre_read_body.is_some(),
            "canonical pre-read body is left intact but bypassed"
        );
    }

    #[test]
    fn drain_uses_canonical_body_when_no_adaptation() {
        let mut ctx = make_ctx();
        ctx.pre_read_body = Some(VecDeque::from([Bytes::from_static(b"canonical")]));

        let mut body = None;
        assert!(drain_pre_read_body(&mut ctx, &mut body), "drain is active");
        assert_eq!(body, Some(Bytes::from_static(b"canonical")), "canonical body forwarded");
        assert!(ctx.pre_read_body.is_none(), "canonical body cleared after draining");
    }

    #[test]
    fn drain_inactive_when_no_pre_read() {
        let mut ctx = make_ctx();
        let mut body = Some(Bytes::from_static(b"streamed"));
        assert!(!drain_pre_read_body(&mut ctx, &mut body), "no drain, normal processing");
        assert_eq!(body, Some(Bytes::from_static(b"streamed")), "body untouched");
    }

    #[test]
    fn drain_empty_adapted_body_forwards_nothing() {
        let mut ctx = make_ctx();
        ctx.adapted_request_body = Some(VecDeque::new());
        ctx.retained_adapted_request_body = Some(VecDeque::new());

        let mut body = Some(Bytes::from_static(b"stale"));
        assert!(
            drain_pre_read_body(&mut ctx, &mut body),
            "drain is active for empty adapted body"
        );
        assert_eq!(body, None, "empty adapted body forwards nothing (Content-Length: 0)");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a default request context for body filter tests.
    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }
}
