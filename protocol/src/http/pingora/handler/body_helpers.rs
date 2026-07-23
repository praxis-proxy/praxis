// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Shared helpers for request and response body filter execution.

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use praxis_core::{config::ABSOLUTE_MAX_BODY_BYTES, connectivity::Upstream};
use praxis_filter::{BodyBuffer, HttpFilterContext, RequestExtensions};

use super::super::context::PingoraRequestCtx;

/// Accumulate `chunk.len()` into `accumulated_bytes` and return `true` when
/// the total exceeds `max_bytes`. Returns `false` when the body is `None`.
pub(super) fn check_body_size_limit(body: &Option<Bytes>, accumulated_bytes: &mut u64, max_bytes: usize) -> bool {
    if let Some(chunk) = body {
        #[expect(clippy::allow_attributes, reason = "cast lint is platform-dependent")]
        #[allow(clippy::cast_possible_truncation, reason = "chunk length fits u64")]
        let chunk_len = chunk.len() as u64;
        *accumulated_bytes += chunk_len;

        #[expect(clippy::allow_attributes, reason = "cast lint is platform-dependent")]
        #[allow(clippy::cast_possible_truncation, reason = "max_bytes fits u64")]
        let limit = max_bytes as u64;
        return *accumulated_bytes > limit;
    }
    false
}

/// Push `chunk` into the stream buffer, creating it if absent. At end-of-stream
/// the buffer is frozen into `body`. Returns `true` when the push overflows.
pub(super) fn accumulate_stream_buffer(
    body: &mut Option<Bytes>,
    body_buffer: &mut Option<BodyBuffer>,
    end_of_stream: bool,
    max_bytes: Option<usize>,
) -> bool {
    if let Some(chunk) = &*body {
        let limit = max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES);
        let buf = body_buffer.get_or_insert_with(|| BodyBuffer::new(limit));

        if buf.push(chunk.clone()).is_err() {
            return true;
        }
    }

    if end_of_stream {
        tracing::trace!("stream buffer: freezing accumulated body before pipeline at EOS");
        *body = body_buffer.take().map(BodyBuffer::freeze);
    } else {
        tracing::trace!("stream buffer: filters see the original chunk");
    }
    false
}

/// Suppress the body chunk while the stream buffer is still accumulating
/// (i.e. `Continue`/`BodyDone` before release).
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "mirrors the caller's existing condition flags"
)]
pub(super) fn suppress_stream_buffer_chunk(
    body: &mut Option<Bytes>,
    is_stream_buffer: bool,
    released: bool,
    end_of_stream: bool,
) {
    if is_stream_buffer && !released && !end_of_stream {
        *body = None;
    }
}

/// Release the accumulated stream buffer on `FilterAction::Release`.
pub(super) fn release_stream_buffer(
    body: &mut Option<Bytes>,
    is_stream_buffer: bool,
    released: &mut bool,
    body_buffer: &mut Option<BodyBuffer>,
    end_of_stream: bool,
) {
    if is_stream_buffer && !*released {
        *released = true;
        if !end_of_stream {
            *body = body_buffer.take().map(BodyBuffer::freeze);
        }
    }
}

/// Shared fields extracted from an `HttpFilterContext` after body filter
/// execution. Written back to `PingoraRequestCtx` via [`write_back`].
///
/// [`write_back`]: BodyFilterOutput::write_back
pub(super) struct BodyFilterOutput {
    /// Cluster selected by the filter pipeline.
    pub cluster: Option<Arc<str>>,
    /// Upstream endpoint selected by the load balancer.
    pub upstream: Option<Upstream>,
    /// Type-safe request-scoped extension container.
    pub extensions: RequestExtensions,
    /// Durable per-request metadata that persists across phases.
    pub filter_metadata: HashMap<String, String>,
    /// Typed per-filter state keyed by stable filter invocation ID.
    pub filter_state: HashMap<usize, Box<dyn std::any::Any + Send + Sync>>,
    /// Per-filter execution tracking indices.
    pub executed_filter_indices: Vec<bool>,
    /// Per-filter body-done tracking indices.
    pub body_done_indices: Vec<bool>,
}

impl BodyFilterOutput {
    /// Move the shared fields out of the filter context, replacing each
    /// with its `Default` value (zero-allocation no-ops for the types involved).
    pub(super) fn take_from(fctx: &mut HttpFilterContext<'_>) -> Self {
        Self {
            cluster: fctx.cluster.take(),
            upstream: fctx.upstream.take(),
            extensions: std::mem::take(&mut fctx.extensions),
            filter_metadata: std::mem::take(&mut fctx.filter_metadata),
            filter_state: std::mem::take(&mut fctx.filter_state),
            executed_filter_indices: std::mem::take(&mut fctx.executed_filter_indices),
            body_done_indices: std::mem::take(&mut fctx.body_done_indices),
        }
    }

    /// Write the shared fields back to the protocol context.
    pub(super) fn write_back(self, ctx: &mut PingoraRequestCtx) {
        ctx.cluster = self.cluster;
        ctx.upstream = self.upstream;
        ctx.extensions = self.extensions;
        ctx.filter_metadata = self.filter_metadata;
        ctx.filter_state = self.filter_state;
        ctx.cached_executed_filter_indices = self.executed_filter_indices;
        ctx.cached_body_done_indices = self.body_done_indices;
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
    use bytes::Bytes;
    use praxis_filter::BodyBuffer;

    use super::*;

    #[test]
    fn size_limit_none_body_returns_false() {
        let mut bytes = 0_u64;
        assert!(!check_body_size_limit(&None, &mut bytes, 100));
        assert_eq!(bytes, 0, "accumulated bytes unchanged for None body");
    }

    #[test]
    fn size_limit_within_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"hello"));
        assert!(!check_body_size_limit(&body, &mut bytes, 10));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_at_exact_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"exact"));
        assert!(!check_body_size_limit(&body, &mut bytes, 5));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_exceeds_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"toolong"));
        assert!(check_body_size_limit(&body, &mut bytes, 3));
    }

    #[test]
    fn size_limit_cumulative_overflow() {
        let mut bytes = 0_u64;
        let first = Some(Bytes::from_static(b"aaa"));
        assert!(!check_body_size_limit(&first, &mut bytes, 5));

        let second = Some(Bytes::from_static(b"bbb"));
        assert!(check_body_size_limit(&second, &mut bytes, 5));
        assert_eq!(bytes, 6);
    }

    #[test]
    fn stream_buffer_accumulates_chunks() {
        let mut body = Some(Bytes::from_static(b"hello "));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));
        assert!(buf.is_some());

        body = Some(Bytes::from_static(b"world"));
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));

        let frozen = buf.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn stream_buffer_freezes_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));

        body = Some(Bytes::from_static(b" end"));
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, true, Some(100)));
        assert!(buf.is_none(), "buffer should be taken at EOS");
        assert_eq!(body.unwrap(), Bytes::from_static(b"data end"));
    }

    #[test]
    fn stream_buffer_overflow() {
        let mut body = Some(Bytes::from_static(b"too long"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(accumulate_stream_buffer(&mut body, &mut buf, false, Some(5)));
    }

    #[test]
    fn stream_buffer_none_body() {
        let mut body: Option<Bytes> = None;
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));
        assert!(buf.is_none());
    }

    #[test]
    fn stream_buffer_uses_absolute_max_when_none() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, None));
        assert!(buf.is_some(), "should create buffer with absolute max");
    }

    #[test]
    fn suppress_clears_body_when_buffering() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, false, false);
        assert!(body.is_none());
    }

    #[test]
    fn suppress_noop_when_not_stream_buffer() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, false, false, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_when_released() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, true, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, false, true);
        assert!(body.is_some());
    }

    #[test]
    fn release_sets_flag_and_flushes_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"buffered")).unwrap();

        release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(released);
        assert_eq!(body.unwrap(), Bytes::from_static(b"buffered"));
        assert!(buf.is_none());
    }

    #[test]
    fn release_noop_when_already_released() {
        let mut body: Option<Bytes> = None;
        let mut released = true;
        let mut buf: Option<BodyBuffer> = None;

        release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(body.is_none(), "body should be unchanged when already released");
    }

    #[test]
    fn release_noop_when_not_stream_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf: Option<BodyBuffer> = None;

        release_stream_buffer(&mut body, false, &mut released, &mut buf, false);
        assert!(!released, "released flag should be unchanged for non-stream-buffer");
    }

    #[test]
    fn release_at_eos_sets_flag_but_no_flush() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"data")).unwrap();

        release_stream_buffer(&mut body, true, &mut released, &mut buf, true);
        assert!(released);
        assert!(body.is_none(), "body should not be overwritten at EOS");
        assert!(buf.is_some(), "buffer should not be taken at EOS");
    }

    #[test]
    fn write_back_transfers_fields() {
        let mut ctx = PingoraRequestCtx::default();
        let output = BodyFilterOutput {
            cluster: Some(Arc::from("test-cluster")),
            upstream: None,
            extensions: RequestExtensions::new(),
            filter_metadata: HashMap::from([("key".to_owned(), "val".to_owned())]),
            filter_state: HashMap::new(),
            executed_filter_indices: vec![true, false],
            body_done_indices: vec![false, true],
        };
        output.write_back(&mut ctx);

        assert_eq!(ctx.cluster.as_deref(), Some("test-cluster"));
        assert_eq!(ctx.filter_metadata.get("key").map(String::as_str), Some("val"));
        assert_eq!(ctx.cached_executed_filter_indices, vec![true, false]);
        assert_eq!(ctx.cached_body_done_indices, vec![false, true]);
    }
}
