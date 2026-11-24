// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Response trailer hook: let filters rewrite upstream trailers.

use bytes::{Bytes, BytesMut};
use praxis_filter::FilterPipeline;
use tracing::debug;

use crate::http::pingora::context::PingoraRequestCtx;

/// Outcome of processing the final body callback and upstream trailers.
pub(in crate::http) enum TrailerOutcome {
    /// Forward trailers, retaining any synthetic EOF bytes for the dispatch decision.
    Forward(Option<Bytes>),
    /// Replace trailers with these final body bytes.
    Convert(Bytes),
}

/// Run the pipeline's response-trailer filters and retain both output channels.
#[expect(clippy::too_many_lines, reason = "trailer state writeback is deliberately explicit")]
pub(in crate::http) fn execute(
    pipeline: &FilterPipeline,
    trailers: &mut http::HeaderMap,
    ctx: &mut PingoraRequestCtx,
) -> Result<TrailerOutcome, String> {
    ctx.extensions.insert(praxis_filter::ResponseTrailersPending);
    let synthetic_body = dispatch_synthetic_eof(pipeline, ctx);
    let _marker = ctx.extensions.remove::<praxis_filter::ResponseTrailersPending>();
    let synthetic_body = synthetic_body?;
    let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None) else {
        return Ok(TrailerOutcome::Forward(synthetic_body));
    };
    let original_trailers = trailers.clone();
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
        Ok(Some(bytes)) => Ok(TrailerOutcome::Convert(combine_body_bytes(synthetic_body, bytes))),
        Ok(None) => Ok(TrailerOutcome::Forward(synthetic_body)),
        Err(error) => {
            *trailers = original_trailers;
            debug!(%error, "response trailer filter failed; forwarding original trailers");
            Ok(TrailerOutcome::Forward(synthetic_body))
        },
    }
}

/// Deliver the missing final response-body callback before trailers.
pub(super) fn dispatch_synthetic_eof(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
) -> Result<Option<Bytes>, String> {
    if !ctx.response_delivery_complete && pipeline.body_capabilities().needs_response_body {
        let mut body = None;
        super::response_body_filter::run_response_body(pipeline, &mut body, true, ctx)?;
        return Ok(body);
    }
    Ok(None)
}

/// Preserve body bytes produced at EOF before appending trailer replacements.
fn combine_body_bytes(prefix: Option<Bytes>, suffix: Bytes) -> Bytes {
    let Some(prefix) = prefix else {
        return suffix;
    };
    if prefix.is_empty() {
        return suffix;
    }
    if suffix.is_empty() {
        return prefix;
    }
    let mut combined = BytesMut::with_capacity(prefix.len().saturating_add(suffix.len()));
    combined.extend_from_slice(&prefix);
    combined.extend_from_slice(&suffix);
    combined.freeze()
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
    use std::sync::Arc;

    use praxis_filter::{
        BodyAccess, BodyRequirement, FilterAction, FilterEntry, FilterError, FilterFactory, FilterRegistry, HttpFilter,
        HttpFilterContext, Request,
    };

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

    #[derive(Clone, Copy)]
    enum ProbeMode {
        None,
        Convert,
        Error,
    }

    struct TrailerProbe(ProbeMode);

    #[async_trait::async_trait]
    impl HttpFilter for TrailerProbe {
        fn name(&self) -> &'static str {
            "trailer_probe"
        }

        fn response_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite(BodyRequirement::Optional)
        }

        fn response_trailer_access(&self) -> bool {
            true
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn on_response_body(
            &self,
            _ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if end_of_stream {
                *body = Some(Bytes::from_static(b"tail"));
            }
            Ok(FilterAction::Continue)
        }

        fn on_response_trailers(
            &self,
            ctx: &mut HttpFilterContext<'_>,
            trailers: &mut http::HeaderMap,
        ) -> Result<Option<Bytes>, FilterError> {
            if let Some(executed) = ctx.executed_filter_indices.first_mut() {
                *executed = false;
            }
            if let Some(done) = ctx.body_done_indices.first_mut() {
                *done = true;
            }
            match self.0 {
                ProbeMode::None => Ok(None),
                ProbeMode::Convert => Ok(Some(Bytes::from_static(b"converted"))),
                ProbeMode::Error => {
                    trailers.insert("x-partial", http::HeaderValue::from_static("leak"));
                    Err("trailer probe failed".to_owned().into())
                },
            }
        }
    }

    fn probe_pipeline(mode: ProbeMode) -> FilterPipeline {
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "trailer_probe",
                FilterFactory::Http(Arc::new(move |_| Ok(Box::new(TrailerProbe(mode))))),
            )
            .unwrap();
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str("- filter: trailer_probe").unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    fn probe_context() -> PingoraRequestCtx {
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        ctx.cached_executed_filter_indices = vec![true];
        ctx.cached_body_done_indices = vec![false];
        ctx
    }

    #[test]
    fn trailer_none_preserves_synthetic_eof_bytes() {
        let mut ctx = probe_context();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-end", http::HeaderValue::from_static("done"));
        let result = execute(&probe_pipeline(ProbeMode::None), &mut trailers, &mut ctx).unwrap();
        assert!(matches!(result, TrailerOutcome::Forward(Some(bytes)) if bytes.as_ref() == b"tail"));
        assert_eq!(trailers.get("x-end").unwrap(), "done");
    }

    #[test]
    fn trailer_error_restores_original_map_and_final_body() {
        let mut ctx = probe_context();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-end", http::HeaderValue::from_static("done"));
        let result = execute(&probe_pipeline(ProbeMode::Error), &mut trailers, &mut ctx).unwrap();
        assert!(matches!(result, TrailerOutcome::Forward(Some(bytes)) if bytes.as_ref() == b"tail"));
        assert_eq!(trailers.get("x-end").unwrap(), "done");
        assert!(!trailers.contains_key("x-partial"));
    }

    #[test]
    fn trailer_conversion_combines_final_body_before_replacement() {
        let mut ctx = probe_context();
        let mut trailers = http::HeaderMap::new();
        let result = execute(&probe_pipeline(ProbeMode::Convert), &mut trailers, &mut ctx).unwrap();
        assert!(matches!(result, TrailerOutcome::Convert(bytes) if bytes.as_ref() == b"tailconverted"));
    }

    #[test]
    fn combine_body_bytes_keeps_nonempty_side() {
        let tail = Bytes::from_static(b"tail");
        assert_eq!(combine_body_bytes(None, tail.clone()), tail);
        assert_eq!(combine_body_bytes(Some(Bytes::new()), tail.clone()), tail);
        assert_eq!(combine_body_bytes(Some(tail.clone()), Bytes::new()), tail);
    }

    #[test]
    fn execute_with_no_request_snapshot_returns_none() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        let mut trailers = http::HeaderMap::new();

        // No request_snapshot set, filter_context_for should return None
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(
            matches!(
                result.expect("empty pipeline should not fail"),
                TrailerOutcome::Forward(None)
            ),
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

        assert!(
            matches!(
                result.expect("empty pipeline should not fail"),
                TrailerOutcome::Forward(None)
            ),
            "execute should return None for empty pipeline"
        );
    }

    #[test]
    fn execute_with_empty_trailers() {
        let pipeline = make_test_pipeline();
        let mut ctx = make_test_context();
        ctx.request_snapshot = Some(make_request_snapshot());
        let mut trailers = http::HeaderMap::new();

        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(matches!(
            result.expect("empty trailers should not fail"),
            TrailerOutcome::Forward(None)
        ));
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

        assert!(matches!(
            result.expect("preserved trailers should not fail"),
            TrailerOutcome::Forward(None)
        ));
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
        ctx.filter_metadata
            .insert("before", "test")
            .expect("entry must fit in the filter's metadata");

        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx);

        assert!(matches!(
            result.expect("metadata writeback should not fail"),
            TrailerOutcome::Forward(None)
        ));
        // Metadata should be preserved through writeback
        assert_eq!(
            ctx.filter_metadata.get("before"),
            Some("test"),
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

        assert!(matches!(
            result.expect("structured metadata writeback should not fail"),
            TrailerOutcome::Forward(None)
        ));
        // Structured metadata should be preserved
        assert!(
            ctx.structured_metadata.contains_key("namespace"),
            "structured_metadata should survive writeback"
        );
    }

    #[test]
    fn execute_writes_back_executed_filter_indices() {
        let pipeline = probe_pipeline(ProbeMode::None);
        let mut ctx = probe_context();
        ctx.response_delivery_complete = true;
        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx).unwrap();
        assert!(matches!(result, TrailerOutcome::Forward(None)));
        assert_eq!(ctx.cached_executed_filter_indices, vec![false]);
    }

    #[test]
    fn execute_writes_back_body_done_indices() {
        let pipeline = probe_pipeline(ProbeMode::None);
        let mut ctx = probe_context();
        ctx.response_delivery_complete = true;
        let mut trailers = http::HeaderMap::new();
        let result = execute(&pipeline, &mut trailers, &mut ctx).unwrap();
        assert!(matches!(result, TrailerOutcome::Forward(None)));
        assert_eq!(ctx.cached_body_done_indices, vec![true]);
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

        assert!(matches!(
            result.expect("trailer map should not fail"),
            TrailerOutcome::Forward(None)
        ));
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
        ctx.filter_metadata
            .insert("test", "value")
            .expect("entry must fit in the filter's metadata");

        let mut trailers1 = http::HeaderMap::new();
        trailers1.insert("test", "first".parse().unwrap());

        let result1 = execute(&pipeline, &mut trailers1, &mut ctx);
        assert!(matches!(
            result1.expect("first execution should not fail"),
            TrailerOutcome::Forward(None)
        ));

        // Second execution on the same context
        let mut trailers2 = http::HeaderMap::new();
        trailers2.insert("test", "second".parse().unwrap());

        let result2 = execute(&pipeline, &mut trailers2, &mut ctx);
        assert!(matches!(
            result2.expect("second execution should not fail"),
            TrailerOutcome::Forward(None)
        ));

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

        assert!(matches!(
            result.expect("large trailer map should not fail"),
            TrailerOutcome::Forward(None)
        ));
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

        assert!(matches!(
            result.expect("grpc trailers should not fail"),
            TrailerOutcome::Forward(None)
        ));
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

        assert!(matches!(
            result.expect("extensions writeback should not fail"),
            TrailerOutcome::Forward(None)
        ));
        // Extensions container exists and is written back
        // (checking it doesn't panic or lose the container)
    }
}
