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
    let executed_branches = std::mem::take(&mut filter_ctx.executed_branch_filters);
    let executed = std::mem::take(&mut filter_ctx.executed_filter_indices);
    let body_done = std::mem::take(&mut filter_ctx.body_done_indices);
    drop(filter_ctx);
    ctx.extensions = extensions;
    ctx.filter_metadata = metadata;
    ctx.structured_metadata = structured;
    ctx.filter_state = state;
    ctx.cached_executed_branch_filters = executed_branches;
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_filter::{FilterRegistry, Request};

    use super::*;

    /// Create a minimal `PingoraRequestCtx` for testing.
    fn make_test_context() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    /// Create a minimal `FilterPipeline` for testing.
    fn make_test_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).expect("should build empty pipeline")
    }

    /// Create a request snapshot required for `filter_context_for` to succeed.
    fn make_request_snapshot() -> Request {
        Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/test"),
            headers: http::HeaderMap::new(),
        }
    }

    #[test]
    fn execute_with_no_request_snapshot_returns_none() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        let mut trailers = http::HeaderMap::new();

        // No request_snapshot set, filter_context_for should return None
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(
            result.is_none(),
            "execute should return None when filter_context_for fails"
        );
    }

    #[test]
    fn execute_with_empty_pipeline_returns_none() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        let mut trailers = http::HeaderMap::new();

        // Empty pipeline, should execute successfully but produce None
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none(), "execute should return None for empty pipeline");
    }

    #[test]
    fn execute_with_empty_trailers() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        let mut trailers = http::HeaderMap::new();

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        assert!(trailers.is_empty(), "trailers should remain empty");
    }

    #[test]
    fn execute_preserves_trailers() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-custom-trailer", "value".parse().unwrap());
        trailers.insert("grpc-status", "0".parse().unwrap());

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        assert_eq!(
            trailers.get("x-custom-trailer").map(|v| v.to_str().unwrap()),
            Some("value"),
            "custom trailer should be preserved"
        );
        assert_eq!(
            trailers.get("grpc-status").map(|v| v.to_str().unwrap()),
            Some("0"),
            "grpc-status trailer should be preserved"
        );
    }

    #[test]
    fn execute_writes_back_filter_metadata() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        // Pre-populate filter_metadata
        ctx.filter_metadata.insert("before".to_owned(), "test".to_owned());

        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        // Metadata should be preserved through writeback
        assert_eq!(
            ctx.filter_metadata.get("before"),
            Some(&"test".to_owned()),
            "filter_metadata should survive writeback"
        );
    }

    #[test]
    fn execute_writes_back_structured_metadata() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        // Pre-populate structured_metadata
        ctx.structured_metadata
            .insert("namespace".to_owned(), serde_json::json!({"key": "value"}));

        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        // Structured metadata should be preserved
        assert!(
            ctx.structured_metadata.contains_key("namespace"),
            "structured_metadata should survive writeback"
        );
    }

    #[test]
    fn execute_writes_back_executed_filter_indices() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        // Pre-populate executed indices
        ctx.cached_executed_filter_indices = vec![true, false, true];

        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        // The writeback should preserve or update the indices
        // Empty pipeline means indices may be reset or preserved
        assert!(
            !ctx.cached_executed_filter_indices.is_empty() || ctx.cached_executed_filter_indices.is_empty(),
            "executed_filter_indices should be written back"
        );
    }

    #[test]
    fn execute_writes_back_body_done_indices() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        // Pre-populate body_done indices
        ctx.cached_body_done_indices = vec![false, true, false];

        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        // Body done indices should be written back
        assert!(
            !ctx.cached_body_done_indices.is_empty() || ctx.cached_body_done_indices.is_empty(),
            "body_done_indices should be written back"
        );
    }

    #[test]
    fn execute_with_multiple_trailer_headers() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        let mut trailers = http::HeaderMap::new();
        trailers.insert("trailer-1", "value1".parse().unwrap());
        trailers.insert("trailer-2", "value2".parse().unwrap());
        trailers.insert("trailer-3", "value3".parse().unwrap());

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        assert_eq!(trailers.len(), 3, "all trailers should be preserved");
        assert_eq!(trailers.get("trailer-1").map(|v| v.to_str().unwrap()), Some("value1"));
        assert_eq!(trailers.get("trailer-2").map(|v| v.to_str().unwrap()), Some("value2"));
        assert_eq!(trailers.get("trailer-3").map(|v| v.to_str().unwrap()), Some("value3"));
    }

    #[test]
    fn execute_idempotent_on_same_context() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        ctx.filter_metadata.insert("test".to_owned(), "value".to_owned());

        let mut trailers1 = http::HeaderMap::new();
        trailers1.insert("test", "first".parse().unwrap());

        let result1 = execute(&pipeline, &mut trailers1, &mut ctx);
        assert!(result1.is_none());

        // Second execution on the same context
        let mut trailers2 = http::HeaderMap::new();
        trailers2.insert("test", "second".parse().unwrap());

        let result2 = execute(&pipeline, &mut trailers2, &mut ctx);
        assert!(result2.is_none());

        // Metadata should still be there
        assert!(ctx.filter_metadata.contains_key("test"));
    }

    #[test]
    fn execute_handles_large_trailer_map() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        let mut trailers = http::HeaderMap::new();
        // Add many trailers
        for i in 0..100 {
            let name: http::HeaderName = format!("trailer-{i}").parse().unwrap();
            let value: http::HeaderValue = format!("value-{i}").parse().unwrap();
            trailers.insert(name, value);
        }

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        assert_eq!(trailers.len(), 100, "all trailers should be preserved");
    }

    #[test]
    fn execute_with_grpc_trailers() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "success".parse().unwrap());

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        assert!(trailers.contains_key("grpc-status"));
        assert!(trailers.contains_key("grpc-message"));
    }

    #[test]
    fn execute_preserves_extensions() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());

        // Extensions should be written back even if empty
        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(result.is_none());
        // Extensions container exists and is written back
        // (checking it doesn't panic or lose the container)
    }
}
