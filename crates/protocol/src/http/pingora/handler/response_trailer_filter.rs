// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Response trailer hook: let filters rewrite upstream trailers.

use bytes::Bytes;
use praxis_filter::FilterPipeline;
use tracing::debug;

use crate::http::pingora::context::PingoraRequestCtx;

/// Run the pipeline's response-trailer filters.
///
/// Returning `Some(bytes)` tells Pingora to drop the trailers and send
/// those bytes as the response body's final chunk instead — the
/// conversion a browser needs, since it cannot read HTTP trailers.
pub(super) fn execute(
    pipeline: &FilterPipeline,
    trailers: &mut http::HeaderMap,
    ctx: &mut PingoraRequestCtx,
) -> Option<Bytes> {
    let mut filter_ctx = ctx.filter_context_for(pipeline, None)?;
    let produced = pipeline.execute_http_response_trailers(&mut filter_ctx, trailers);

    // Write back the durable channels, as every other phase does, so a
    // filter's metadata survives into the logging phase.
    let extensions = std::mem::take(&mut filter_ctx.extensions);
    let metadata = std::mem::take(&mut filter_ctx.filter_metadata);
    let structured = std::mem::take(&mut filter_ctx.structured_metadata);
    let state = std::mem::take(&mut filter_ctx.filter_state);
    let executed = std::mem::take(&mut filter_ctx.executed_filter_indices);
    let body_done = std::mem::take(&mut filter_ctx.body_done_indices);
    drop(filter_ctx);
    ctx.extensions = extensions;
    ctx.filter_metadata = metadata;
    ctx.structured_metadata = structured;
    ctx.filter_state = state;
    ctx.cached_executed_filter_indices = executed;
    ctx.cached_body_done_indices = body_done;

    match produced {
        Ok(bytes) => bytes,
        Err(error) => {
            debug!(%error, "response trailer filter failed; forwarding trailers unchanged");
            None
        },
    }
}
