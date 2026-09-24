// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Body mode clamping and stream buffer utilities.
//!
//! Utilities for enforcing body size limits, accumulating streaming
//! chunks into buffers, and transferring filter context state between
//! body filter invocations. Extracted from `mod.rs` to keep the handler
//! module focused on lifecycle hooks.

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use praxis_core::{config::ABSOLUTE_MAX_BODY_BYTES, connectivity::Upstream};
use praxis_filter::{BodyBuffer, BodyMode, RequestExtensions};

use crate::http::pingora::context::PingoraRequestCtx;

/// Clamp a runtime-selected body mode to the byte ceiling implied by `baseline`.
///
/// `baseline` is the mode established before request/response-phase filter hooks
/// run (typically from pipeline capabilities + global body limits). Runtime
/// `set_*_body_mode` calls may widen limits; this utility preserves the original
/// ceiling while still allowing upgrades between body mode variants.
///
/// `Stream` mode passes through unconditionally: it delivers chunks as they
/// arrive, with no buffer to cap. A runtime downgrade from `StreamBuffer` to
/// `Stream` opts out of buffering entirely. The pipeline-level body size
/// limit (enforced separately via `SizeLimit`) remains the backstop for
/// oversized payloads.
pub(super) fn clamp_body_mode_to_ceiling(mode: BodyMode, baseline: BodyMode) -> BodyMode {
    let ceiling = match baseline {
        BodyMode::StreamBuffer { max_bytes: Some(v) } | BodyMode::SizeLimit { max_bytes: v } => Some(v),
        _ => None,
    };

    match (mode, ceiling) {
        (BodyMode::StreamBuffer { max_bytes }, Some(limit)) => BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes.map_or(limit, |v| v.min(limit))),
        },
        (BodyMode::SizeLimit { max_bytes }, Some(limit)) => BodyMode::SizeLimit {
            max_bytes: max_bytes.min(limit),
        },
        // Stream has no buffer to clamp; other modes pass through when the
        // baseline imposes no ceiling (e.g. unbounded StreamBuffer).
        (m, None | Some(_)) => m,
    }
}

/// Accumulate `chunk.len()` into `accumulated_bytes` and return `true` when
/// the total exceeds `max_bytes`. Returns `false` when the body is `None`.
pub(super) fn check_body_size_limit(body: Option<&Bytes>, accumulated_bytes: &mut u64, max_bytes: usize) -> bool {
    if let Some(chunk) = body {
        let chunk_len = chunk.len() as u64;
        *accumulated_bytes += chunk_len;

        let limit = max_bytes as u64;
        return *accumulated_bytes > limit;
    }
    false
}

/// Whether `chunk` would take a body already `counted` bytes long past the
/// global `ceiling`. Does not update the count.
pub(super) fn exceeds_body_ceiling(ceiling: Option<usize>, counted: u64, chunk: Option<&Bytes>) -> bool {
    let chunk_len = chunk.map_or(0, Bytes::len) as u64;
    ceiling.is_some_and(|max| counted.saturating_add(chunk_len) > max as u64)
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
    pub(super) cluster: Option<Arc<str>>,
    /// Upstream endpoint selected by the load balancer.
    pub(super) upstream: Option<Upstream>,
    /// Type-safe request-scoped extension container.
    pub(super) extensions: RequestExtensions,
    /// Durable per-request metadata that persists across phases.
    pub(super) filter_metadata: HashMap<String, String>,
    /// Typed per-filter state keyed by stable filter invocation ID.
    pub(super) filter_state: HashMap<usize, Box<dyn std::any::Any + Send + Sync>>,
    /// Per-filter execution tracking indices.
    pub(super) executed_filter_indices: Vec<bool>,
    /// Per-filter body-done tracking indices.
    pub(super) body_done_indices: Vec<bool>,
    /// Endpoints already attempted for this request (retry exclusion set).
    pub(super) attempted_endpoints: Vec<Arc<str>>,
}

impl BodyFilterOutput {
    /// Move the shared fields out of the filter context, replacing each
    /// with its `Default` value.
    pub(super) fn take_from(fctx: &mut praxis_filter::HttpFilterContext<'_>) -> Self {
        Self {
            cluster: fctx.cluster.take(),
            upstream: fctx.upstream.take(),
            extensions: std::mem::take(&mut fctx.extensions),
            filter_metadata: std::mem::take(&mut fctx.filter_metadata),
            filter_state: std::mem::take(&mut fctx.filter_state),
            executed_filter_indices: std::mem::take(&mut fctx.executed_filter_indices),
            body_done_indices: std::mem::take(&mut fctx.body_done_indices),
            attempted_endpoints: std::mem::take(&mut fctx.attempted_endpoints),
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
        ctx.attempted_endpoints = self.attempted_endpoints;
    }
}
