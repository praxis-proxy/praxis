// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request body handling utilities for the body phases that run after
//! routing.
//!
//! Manages adapted request body storage and body size limit resolution for
//! the selected-upstream request-body phase introduced in #1139, and the
//! canonical body the bound-upstream phase can produce.

use std::collections::VecDeque;

use bytes::Bytes;
use praxis_core::config::MAX_RETRY_BODY_LIMIT_BYTES;
use praxis_filter::FilterPipeline;

use super::super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Body Handling
// -----------------------------------------------------------------------------

/// Resolve the effective request-body limit for the selected-upstream phase.
///
/// Delegates to [`FilterPipeline::selected_upstream_request_body_limit`] so the
/// Pingora and filtered-subrequest paths share one definition of the limit.
pub(super) fn selected_upstream_body_limit(pipeline: &FilterPipeline) -> usize {
    pipeline.selected_upstream_request_body_limit()
}

/// A copy of a rewritten body for retry replay, or `None` when no retry can
/// replay it. `should_retry` refuses any request whose transformed body is
/// over [`MAX_RETRY_BODY_LIMIT_BYTES`], so a larger copy would only pin the
/// body, up to the request ceiling, for the whole request.
pub(super) fn retry_copy(chunks: &VecDeque<Bytes>, len: usize) -> Option<VecDeque<Bytes>> {
    u64::try_from(len)
        .is_ok_and(|len| len <= MAX_RETRY_BODY_LIMIT_BYTES)
        .then(|| chunks.clone())
}

/// Store the adapted selected-upstream request body (#1139).
///
/// Mirrors the pre-read storage: a single frozen chunk (or empty deque), a
/// retained clone for retry replay, and the authoritative length used by
/// `apply_mutated_content_length` and the retry-body guard. Empty output yields
/// an empty deque so the drain forwards nothing under `Content-Length: 0`.
pub(super) fn store_adapted_request_body(ctx: &mut PingoraRequestCtx, body: Option<Bytes>) {
    let len = body.as_ref().map_or(0, Bytes::len);
    let chunks = match body {
        Some(b) if !b.is_empty() => VecDeque::from([b]),
        _ => VecDeque::new(),
    };
    ctx.retained_adapted_request_body = Some(retry_copy(&chunks, len).unwrap_or_default());
    ctx.adapted_request_body = Some(chunks);
    ctx.adapted_request_body_len = Some(len);
}

/// Store the canonical body produced by the bound-upstream phase.
///
/// Direct dispatch drains `pre_read_body`; retries are re-seeded from the
/// retained copy. Updating the authoritative mutated length keeps framing and
/// retry replay aligned when a bound-body writer grows, shrinks, or empties
/// the body (an emptied body is stored as no chunks with a length of zero).
pub(super) fn store_canonical_request_body(ctx: &mut PingoraRequestCtx, body: Bytes) {
    let len = body.len();
    let chunks = if body.is_empty() {
        VecDeque::new()
    } else {
        VecDeque::from([body])
    };
    ctx.retained_pre_read_body = retry_copy(&chunks, len);
    ctx.pre_read_body = Some(chunks);
    ctx.mutated_request_body_len = Some(len);
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
    use praxis_core::config::{ABSOLUTE_MAX_BODY_BYTES, FailureMode};
    use praxis_filter::{BodyMode, FilterRegistry};

    use super::*;

    fn empty_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
    }

    fn stream_buffer_pipeline(max_bytes: usize) -> FilterPipeline {
        use std::sync::Arc as StdArc;
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "test_stream_buffer",
                praxis_filter::FilterFactory::Http(StdArc::new(move |_| {
                    Ok(Box::new(TestStreamBufferFilter { max_bytes }))
                })),
            )
            .unwrap();
        let config: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let mut entries = vec![praxis_filter::FilterEntry {
            branch_chains: None,
            filter_type: "test_stream_buffer".into(),
            config,
            conditions: vec![],
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }];
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    struct TestStreamBufferFilter {
        max_bytes: usize,
    }

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for TestStreamBufferFilter {
        fn name(&self) -> &'static str {
            "test_stream_buffer"
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
            Ok(praxis_filter::FilterAction::Continue)
        }

        fn request_body_access(&self) -> praxis_filter::BodyAccess {
            praxis_filter::BodyAccess::ReadWrite
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(self.max_bytes),
            }
        }
    }

    fn make_ctx() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    #[test]
    fn selected_upstream_body_limit_uses_stream_buffer_max() {
        let pipeline = stream_buffer_pipeline(4096);
        assert_eq!(selected_upstream_body_limit(&pipeline), 4096);
    }

    #[test]
    fn selected_upstream_body_limit_falls_back_to_absolute_max() {
        assert_eq!(selected_upstream_body_limit(&empty_pipeline()), ABSOLUTE_MAX_BODY_BYTES);
    }

    #[test]
    fn selected_upstream_body_limit_honors_tighter_listener_ceiling() {
        let mut pipeline = stream_buffer_pipeline(4096);
        pipeline
            .apply_body_limits(Some(1024), None, false)
            .expect("applying a tighter request-body ceiling should succeed");
        assert_eq!(
            selected_upstream_body_limit(&pipeline),
            1024,
            "the listener ceiling (1024) must override the filter's StreamBuffer max (4096)"
        );
    }

    #[test]
    fn selected_upstream_body_limit_delegates_to_pipeline_method() {
        let pipeline = empty_pipeline();
        assert_eq!(
            selected_upstream_body_limit(&pipeline),
            pipeline.selected_upstream_request_body_limit(),
            "the Pingora free fn must delegate to the shared FilterPipeline method"
        );
    }

    #[test]
    fn store_adapted_request_body_stores_frozen_chunk_and_retained_copy() {
        let mut ctx = make_ctx();
        store_adapted_request_body(&mut ctx, Some(Bytes::from_static(b"ADAPTED")));

        assert_eq!(
            ctx.adapted_request_body,
            Some(VecDeque::from([Bytes::from_static(b"ADAPTED")])),
            "adapted body is a single frozen chunk"
        );
        assert_eq!(
            ctx.retained_adapted_request_body,
            Some(VecDeque::from([Bytes::from_static(b"ADAPTED")])),
            "retained copy mirrors the adapted body for retry replay"
        );
        assert_eq!(ctx.adapted_request_body_len, Some(7), "length is authoritative");
    }

    #[test]
    fn an_unreplayable_adapted_body_keeps_only_the_marker() {
        let mut ctx = make_ctx();
        let oversized = Bytes::from(vec![b'a'; replay_cap() + 1]);
        store_adapted_request_body(&mut ctx, Some(oversized));

        assert_eq!(
            ctx.retained_adapted_request_body,
            Some(VecDeque::new()),
            "a body no retry can replay keeps the adaptation marker but not the bytes"
        );
        assert_eq!(
            ctx.adapted_request_body_len,
            Some(replay_cap() + 1),
            "the length stays authoritative so should_retry refuses the replay"
        );
    }

    #[test]
    fn an_unreplayable_canonical_body_is_not_retained() {
        let mut ctx = make_ctx();
        store_canonical_request_body(&mut ctx, Bytes::from(vec![b'a'; replay_cap() + 1]));

        assert_eq!(
            ctx.retained_pre_read_body, None,
            "a body no retry can replay must not be pinned for the request"
        );
    }

    #[test]
    fn a_body_at_the_replay_cap_is_retained() {
        let chunks = VecDeque::from([Bytes::from(vec![b'a'; replay_cap()])]);
        assert_eq!(
            retry_copy(&chunks, replay_cap()).as_ref(),
            Some(&chunks),
            "a body a retry may replay must be kept"
        );
    }

    #[test]
    fn store_adapted_request_body_empty_body_yields_empty_deques() {
        let mut ctx = make_ctx();
        store_adapted_request_body(&mut ctx, Some(Bytes::new()));

        assert_eq!(
            ctx.adapted_request_body,
            Some(VecDeque::new()),
            "empty body yields an empty deque so the drain forwards nothing"
        );
        assert_eq!(
            ctx.retained_adapted_request_body,
            Some(VecDeque::new()),
            "retained marker is still Some for an empty adapted body"
        );
        assert_eq!(ctx.adapted_request_body_len, Some(0), "empty body length is 0");
    }

    #[test]
    fn store_canonical_request_body_updates_direct_and_retry_representations() {
        let mut ctx = make_ctx();
        store_canonical_request_body(&mut ctx, Bytes::from_static(b"BOUND"));

        let expected = Some(VecDeque::from([Bytes::from_static(b"BOUND")]));
        assert_eq!(
            ctx.pre_read_body, expected,
            "the direct body should hold the canonical bytes"
        );
        assert_eq!(
            ctx.retained_pre_read_body, expected,
            "the retry body should hold the canonical bytes"
        );
        assert_eq!(
            ctx.mutated_request_body_len,
            Some(5),
            "the mutated length should match the canonical body"
        );
    }

    #[test]
    fn store_canonical_request_body_preserves_empty_replay_marker() {
        let mut ctx = make_ctx();
        store_canonical_request_body(&mut ctx, Bytes::new());

        assert_eq!(
            ctx.pre_read_body,
            Some(VecDeque::new()),
            "an absent canonical body still leaves an empty direct body"
        );
        assert_eq!(
            ctx.retained_pre_read_body,
            Some(VecDeque::new()),
            "an absent canonical body keeps the empty replay marker"
        );
        assert_eq!(
            ctx.mutated_request_body_len,
            Some(0),
            "an absent canonical body has length 0"
        );
    }

    #[test]
    fn store_adapted_request_body_none_body_yields_empty_deques() {
        let mut ctx = make_ctx();
        store_adapted_request_body(&mut ctx, None);

        assert_eq!(ctx.adapted_request_body, Some(VecDeque::new()));
        assert_eq!(ctx.retained_adapted_request_body, Some(VecDeque::new()));
        assert_eq!(ctx.adapted_request_body_len, Some(0));
    }

    #[test]
    fn store_adapted_request_body_with_content() {
        let mut ctx = make_ctx();
        let body = Some(Bytes::from_static(b"adapted content"));

        store_adapted_request_body(&mut ctx, body);

        assert_eq!(
            ctx.adapted_request_body.as_ref().unwrap().len(),
            1,
            "should store single chunk"
        );
        assert_eq!(
            ctx.adapted_request_body.as_ref().unwrap().front().unwrap(),
            &Bytes::from_static(b"adapted content")
        );
        assert_eq!(ctx.adapted_request_body_len, Some(15));
        assert_eq!(
            ctx.retained_adapted_request_body, ctx.adapted_request_body,
            "retained copy should match adapted body"
        );
    }

    #[test]
    fn store_adapted_request_body_large_content() {
        let mut ctx = make_ctx();
        let large_body = Bytes::from(vec![b'X'; 10_000]);
        let body = Some(large_body.clone());

        store_adapted_request_body(&mut ctx, body);

        assert_eq!(ctx.adapted_request_body_len, Some(10_000));
        assert_eq!(ctx.adapted_request_body.as_ref().unwrap().front().unwrap(), &large_body);
    }

    #[test]
    fn selected_upstream_body_limit_consistency() {
        let pipeline = empty_pipeline();

        assert_eq!(
            selected_upstream_body_limit(&pipeline),
            pipeline.selected_upstream_request_body_limit(),
            "wrapper must delegate to pipeline method"
        );
    }

    fn replay_cap() -> usize {
        usize::try_from(MAX_RETRY_BODY_LIMIT_BYTES).expect("the replay cap fits in usize")
    }
}
