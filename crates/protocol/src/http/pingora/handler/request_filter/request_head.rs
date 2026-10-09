// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-head phase execution for the standard Pingora path.
//!
//! Runs the opted-in `on_request_head` hooks once, after ingress
//! normalization and reserved-header validation but before any optional
//! `StreamBuffer` request-body pre-read and before the main request phase.
//! Facts a head filter publishes (extensions, metadata, filter results,
//! filter state) are written back to [`PingoraRequestCtx`] so the pre-read
//! pass and the request phase observe them; trusted header mutations are
//! applied physically to the session and request, where they are trusted by
//! construction because reserved-header validation already ran.

use pingora_proxy::Session;
use praxis_filter::{FilterAction, FilterError, FilterPipeline, Rejection, Request};
use tracing::error;

use super::{header_mutations::apply_pre_read_mutations, stream_buffer::push_grouped_queues};
use crate::http::pingora::{context::PingoraRequestCtx, convert::send_rejection_for, metrics};

// -----------------------------------------------------------------------------
// RequestHeadOutcome
// -----------------------------------------------------------------------------

/// Terminal outcome of the request-head phase, before response delivery.
///
/// `on_request_head` is restricted to Continue/Reject, so the phase either
/// proceeds or short-circuits with a local rejection.
enum RequestHeadOutcome {
    /// Proceed to pre-read and the request phase.
    Continue,

    /// Short-circuit the request with a local rejection.
    Reject(Rejection),
}

// -----------------------------------------------------------------------------
// Request-Head Phase
// -----------------------------------------------------------------------------

/// Run the request-head phase and deliver any terminal response.
///
/// Wraps [`run`] with response delivery so the request handler branches on a
/// single boolean. A head rejection is stamped and sent as a local response; a
/// closed-failure error is stamped and sent as a 500. In both cases the request
/// is snapshotted first so the response and logging phases see it.
///
/// Returns `true` when the phase sent a terminal response and the handler must
/// return early, `false` when the request should proceed to pre-read and the
/// request phase. `request` is borrowed (not moved) so the common continue path
/// keeps the large request on the caller's frame; the cold rejection and error
/// paths clone it into the snapshot.
#[expect(
    clippy::large_stack_frames,
    reason = "embeds the filter-context future, like the request-phase execute and pre_read_body; \
              the head phase does strictly less work than pre-read"
)]
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    session: &mut Session,
    request: &mut Request,
    ctx: &mut PingoraRequestCtx,
) -> bool {
    match run(pipeline, session, request, ctx).await {
        Ok(RequestHeadOutcome::Continue) => false,
        Ok(RequestHeadOutcome::Reject(rejection)) => {
            ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
            ctx.request_snapshot = Some(request.clone());
            send_rejection_for(session, rejection, ctx).await;
            true
        },
        Err(e) => {
            error!(error = %e, "request-head filter error");
            ctx.stamp_error_type(metrics::ERROR_TYPE_INTERNAL);
            ctx.request_snapshot = Some(request.clone());
            send_rejection_for(session, Rejection::status(500), ctx).await;
            true
        },
    }
}

/// Run the request-head phase against `request`.
///
/// Builds a filter context, runs every opted-in filter's `on_request_head`,
/// writes the published facts back to `ctx`, and applies any trusted header
/// mutations to both the session and `request`. Returns
/// [`RequestHeadOutcome::Reject`] when a head filter rejects.
///
/// # Errors
///
/// Returns [`FilterError`] when a head filter fails with a closed
/// `failure_mode`; the caller maps this to a 500 response.
async fn run(
    pipeline: &FilterPipeline,
    session: &mut Session,
    request: &mut Request,
    ctx: &mut PingoraRequestCtx,
) -> Result<RequestHeadOutcome, FilterError> {
    let (action, mutations) = {
        let mut filter_ctx = ctx.build_filter_context(pipeline, request, None);
        let action = pipeline.execute_http_request_head(&mut filter_ctx).await;

        // Capture trusted header mutations with the same precedence as the
        // pre-read pass: the ordered log wins, else the grouped queues.
        let mut mutations = std::mem::take(&mut filter_ctx.pre_read_mutations);
        if mutations.is_empty() {
            push_grouped_queues(&filter_ctx, &mut mutations);
        }

        // Publish head facts back to ctx before propagating any error.
        // `build_filter_context` moved these out of ctx (including the
        // per-request prepared extensions), so the write-back is required for
        // pre-read and the request phase to see them, not merely to forward
        // head-set values. A closed-failure error must not skip it: pre_read_body
        // and run_pipeline likewise restore facts before returning `Err`, so the
        // 500's fallback access record still observes head-published facts.
        ctx.extensions = filter_ctx.extensions;
        ctx.filter_metadata = filter_ctx.filter_metadata;
        ctx.filter_state = filter_ctx.filter_state;
        ctx.filter_results = filter_ctx.filter_results;
        ctx.structured_metadata = filter_ctx.structured_metadata;

        (action?, mutations)
    };

    if let FilterAction::Reject(rejection) = action {
        return Ok(RequestHeadOutcome::Reject(rejection));
    }

    // Apply head mutations physically so every later reader (pre-read
    // conditions, body filters, router matching in the request phase, and the
    // upstream) observes them. They are not threaded through
    // `ctx.pre_read_mutations`: that channel is re-applied after pre-read and
    // would double-apply Add mutations.
    if !mutations.is_empty() {
        apply_pre_read_mutations(session, request, &mutations);
    }

    Ok(RequestHeadOutcome::Continue)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use http::{
        HeaderMap, Method, Uri,
        header::{HeaderName, HeaderValue},
    };
    use praxis_core::config::FailureMode;
    use praxis_filter::{
        FilterEntry, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, TrustedHeaderMutation,
    };

    use super::*;

    /// Head filter that publishes a metadata fact and a trusted header set.
    struct PublishingHeadFilter;

    #[async_trait]
    impl HttpFilter for PublishingHeadFilter {
        fn name(&self) -> &'static str {
            "publishing_head"
        }

        fn runs_request_head(&self) -> bool {
            true
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_request_head(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            ctx.set_metadata("head_key", "head_value");
            ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
                HeaderName::from_static("x-praxis-head"),
                HeaderValue::from_static("classified"),
            ));
            Ok(FilterAction::Continue)
        }
    }

    /// Head filter that rejects with a configured status.
    struct RejectingHeadFilter(u16);

    #[async_trait]
    impl HttpFilter for RejectingHeadFilter {
        fn name(&self) -> &'static str {
            "rejecting_head"
        }

        fn runs_request_head(&self) -> bool {
            true
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_request_head(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(self.0)))
        }
    }

    /// Head filter that always errors.
    struct ErroringHeadFilter;

    #[async_trait]
    impl HttpFilter for ErroringHeadFilter {
        fn name(&self) -> &'static str {
            "erroring_head"
        }

        fn runs_request_head(&self) -> bool {
            true
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_request_head(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            // Publish a fact before failing, so the closed-failure test can assert
            // it still round-trips to ctx for the 500's fallback access record.
            ctx.set_metadata("head_key", "head_value");
            Err(FilterError::from("head hook failed"))
        }
    }

    #[tokio::test]
    async fn publishes_facts_and_applies_mutations() {
        let pipeline = head_pipeline("publishing_head", FailureMode::default(), || {
            Box::new(PublishingHeadFilter)
        });
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = PingoraRequestCtx::default();
        let mut request = make_request();

        let outcome = run(&pipeline, &mut session, &mut request, &mut ctx).await.unwrap();

        assert!(matches!(outcome, RequestHeadOutcome::Continue), "head filter continues");
        assert_eq!(
            ctx.filter_metadata.get("head_key").map(String::as_str),
            Some("head_value"),
            "head-published metadata must round-trip onto ctx for pre-read and the request phase"
        );
        assert_eq!(
            request.headers.get("x-praxis-head").map(|v| v.to_str().unwrap()),
            Some("classified"),
            "trusted head mutation must be applied to the request"
        );
        assert_eq!(
            session
                .req_header()
                .headers
                .get("x-praxis-head")
                .map(|v| v.to_str().unwrap()),
            Some("classified"),
            "trusted head mutation must be applied to the session so the upstream sees it"
        );
    }

    #[tokio::test]
    async fn reject_short_circuits() {
        let pipeline = head_pipeline("rejecting_head", FailureMode::default(), || {
            Box::new(RejectingHeadFilter(403))
        });
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = PingoraRequestCtx::default();
        let mut request = make_request();

        let outcome = run(&pipeline, &mut session, &mut request, &mut ctx).await.unwrap();

        assert!(
            matches!(outcome, RequestHeadOutcome::Reject(r) if r.status == 403),
            "a rejecting head filter must short-circuit with its status"
        );
    }

    #[tokio::test]
    async fn closed_failure_mode_propagates_error() {
        let pipeline = head_pipeline("erroring_head", FailureMode::Closed, || Box::new(ErroringHeadFilter));
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = PingoraRequestCtx::default();
        let mut request = make_request();

        let result = run(&pipeline, &mut session, &mut request, &mut ctx).await;

        assert!(
            result.is_err(),
            "a closed head failure must propagate so the caller returns 500"
        );
        assert_eq!(
            ctx.filter_metadata.get("head_key").map(String::as_str),
            Some("head_value"),
            "head-published facts must still round-trip to ctx on a closed-failure error, \
             so the 500's fallback access record sees them"
        );
    }

    #[tokio::test]
    async fn open_failure_mode_continues() {
        let pipeline = head_pipeline("erroring_head", FailureMode::Open, || Box::new(ErroringHeadFilter));
        let (mut session, _client) = session_for("GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let mut ctx = PingoraRequestCtx::default();
        let mut request = make_request();

        let outcome = run(&pipeline, &mut session, &mut request, &mut ctx).await.unwrap();

        assert!(
            matches!(outcome, RequestHeadOutcome::Continue),
            "an open head failure must be swallowed and continue"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a single-filter head pipeline from a named factory.
    fn head_pipeline(
        name: &'static str,
        failure_mode: FailureMode,
        make: fn() -> Box<dyn HttpFilter>,
    ) -> FilterPipeline {
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(name, FilterFactory::Http(Arc::new(move |_| Ok(make()))))
            .unwrap();
        let config: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let mut entries = vec![FilterEntry {
            branch_chains: None,
            filter_type: name.into(),
            config,
            conditions: vec![],
            name: None,
            response_conditions: vec![],
            failure_mode,
        }];
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Build a minimal GET request for tests.
    fn make_request() -> Request {
        Request {
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
        }
    }

    /// Parse a raw HTTP/1.1 request into a live session for tests.
    async fn session_for(raw: &str) -> (Session, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt as _;

        let (mut client, server) = tokio::io::duplex(1_048_576);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        let read = session.read_request().await.unwrap();
        assert!(read, "the session must parse the request header");
        (session, client)
    }
}
