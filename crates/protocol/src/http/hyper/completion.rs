// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request completion: what the Pingora handler's `logging` hook does.
//!
//! Runs once per request, on every path: span attributes, request metrics,
//! passive health, the cluster retry lease, the response phase a failed
//! request skipped (which is what releases a circuit breaker or least
//! connections slot), and the fallback access record.

use std::mem;

use http::StatusCode;
use tracing::{Instrument as _, Span};

use super::service::Flight;
use crate::http::pingora::handler::{
    health_util::{ended_by_client_origin, record_passive_health_outcome},
    logging_util::{logging_cleanup, maybe_emit_fallback_access_log},
    metrics_util::emit_request_metrics_for,
    retry_util::release_retry_state,
    span_util::record_response_span_status,
};

// -----------------------------------------------------------------------------
// Completion
// -----------------------------------------------------------------------------

/// Complete `flight`, in the order the Pingora `logging` hook runs.
pub(super) async fn run(flight: &mut Flight) {
    let written = (flight.written_status != 0)
        .then(|| StatusCode::from_u16(flight.written_status).ok())
        .flatten();
    if !flight.ctx.request_span.is_disabled() {
        let fallback = written.map(|status| status.as_u16());
        record_response_span_status(written, flight.method.as_str(), fallback, &flight.ctx);
    }
    // The exchange span ends before its client span, and both before the
    // request span, so children close ahead of their parents.
    close_span(&mut flight.ctx.upstream_exchange_span);
    close_span(&mut flight.ctx.upstream_client_span);
    let span = mem::replace(&mut flight.ctx.request_span, Span::none());
    finish(flight).instrument(span).await;
}

/// The metrics, health and cleanup steps, inside the request span.
async fn finish(flight: &mut Flight) {
    let pipeline = &flight.pipeline;
    let ctx = &mut flight.ctx;
    emit_request_metrics_for(flight.written_status, flight.method.as_str(), ctx);
    record_passive_health_outcome(pipeline, flight.error, ctx);
    release_retry_state(ctx);
    ctx.ended_by_client = ended_by_client_origin(flight.error, ctx.upstream_response_status);
    logging_cleanup(pipeline, ctx).await;
    maybe_emit_fallback_access_log(pipeline, flight.written_status, ctx);
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// End `span` now, leaving a disabled one in its place.
fn close_span(span: &mut Span) {
    let closed = mem::replace(span, Span::none());
    closed.in_scope(|| {});
    drop(closed);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, atomic::Ordering},
    };

    use praxis_core::{
        health::{ClusterHealthEntry, EndpointHealth, HealthRegistry},
        retry::ClusterRetryState,
    };
    use praxis_filter::FilterPipeline;
    use tracing::info_span;
    use tracing_subscriber::{Layer, layer::SubscriberExt as _, registry::LookupSpan};

    use super::*;
    use crate::http::{
        hyper::test_utils::empty_pipeline,
        metrics::{install_prometheus_recorder, render_prometheus},
        pingora::handler::health_util::ErrorOrigin,
    };

    #[tokio::test]
    async fn completion_closes_the_attempt_spans_before_the_request_span() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CloseOrder(Arc::clone(&closed)));
        let _default = tracing::subscriber::set_default(subscriber);
        let mut flight = Flight::for_tests(empty_pipeline());
        let request = info_span!("request");
        let client = info_span!(parent: &request, "client");
        flight.ctx.upstream_exchange_span = info_span!(parent: &client, "exchange");
        flight.ctx.upstream_client_span = client;
        flight.ctx.request_span = request;

        run(&mut flight).await;

        assert_eq!(
            *closed.lock().unwrap(),
            ["exchange", "client", "request"],
            "children close ahead of their parents, all before completion returns"
        );
        assert!(
            flight.ctx.request_span.is_disabled() && flight.ctx.upstream_client_span.is_disabled(),
            "the context keeps no live span"
        );
    }

    #[tokio::test]
    async fn completion_records_a_failure_against_the_selected_endpoint() {
        let mut flight = Flight::for_tests(health_pipeline(1));
        failed_attempt(&mut flight);

        flight.complete().await;

        assert!(
            !endpoint_healthy(&flight.pipeline),
            "a request that failed on the endpoint counts against its passive health"
        );
    }

    #[tokio::test]
    async fn completion_runs_once_however_often_it_is_asked() {
        let mut flight = Flight::for_tests(health_pipeline(2));
        failed_attempt(&mut flight);

        flight.complete().await;
        flight.complete().await;
        let after_repeat = endpoint_healthy(&flight.pipeline);
        run(&mut flight).await;

        assert!(
            after_repeat,
            "a second completion of the same request records nothing more"
        );
        assert!(
            !endpoint_healthy(&flight.pipeline),
            "a second real run would have tripped the threshold of two"
        );
    }

    #[tokio::test]
    async fn client_that_left_before_an_answer_ended_the_request() {
        let mut left = Flight::for_tests(empty_pipeline());
        left.error = Some(ErrorOrigin::Downstream);
        let mut answered = Flight::for_tests(empty_pipeline());
        answered.error = Some(ErrorOrigin::Downstream);
        answered.ctx.upstream_response_status = Some(200);

        run(&mut left).await;
        run(&mut answered).await;

        assert!(
            left.ctx.ended_by_client,
            "a client gone before the upstream answered ended the request"
        );
        assert!(
            !answered.ctx.ended_by_client,
            "once the upstream answered, the request did not end on the client side"
        );
    }

    #[tokio::test]
    async fn completion_releases_the_cluster_retry_lease() {
        let state = Arc::new(ClusterRetryState::new(None));
        state.enter();
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.cluster_retry_state = Some(Arc::clone(&state));

        run(&mut flight).await;

        assert_eq!(
            state.active_requests.load(Ordering::Relaxed),
            0,
            "the request no longer counts as active on its cluster"
        );
        assert!(
            flight.ctx.cluster_retry_state_released,
            "the lease is marked released so nothing releases it twice"
        );
    }

    #[tokio::test]
    async fn completion_counts_the_request_once_with_its_written_status() {
        install_prometheus_recorder();
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.metrics_cluster_shared = Some(::metrics::SharedString::from("hyper-completion-unit"));
        flight.written_status = 503;

        flight.complete().await;
        flight.complete().await;

        let rendered = render_prometheus().expect("the recorder renders");
        let counted: Vec<&str> = rendered
            .lines()
            .filter(|line| {
                line.starts_with("praxis_http_requests_total{") && line.contains("cluster=\"hyper-completion-unit\"")
            })
            .collect();
        assert_eq!(counted.len(), 1, "one series for the request: {counted:?}");
        assert!(
            counted
                .iter()
                .all(|line| line.contains("status_class=\"5xx\"") && line.ends_with(" 1")),
            "the request is counted once, under the status written to the client: {counted:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The cluster the passive health tests select.
    const CLUSTER: &str = "api";

    /// Records the names of spans as they close.
    struct CloseOrder(Arc<Mutex<Vec<&'static str>>>);

    impl<S> Layer<S> for CloseOrder
    where
        S: tracing::Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            if let Some(span) = ctx.span(&id) {
                self.0.lock().unwrap().push(span.name());
            }
        }
    }

    /// Whether [`CLUSTER`]'s only endpoint is still healthy.
    fn endpoint_healthy(pipeline: &FilterPipeline) -> bool {
        let registry = pipeline.health_registry().unwrap();
        registry.get(CLUSTER).unwrap().endpoints().first().unwrap().is_healthy()
    }

    /// Mark `flight` as having reached [`CLUSTER`]'s endpoint and failed there.
    fn failed_attempt(flight: &mut Flight) {
        flight.ctx.cluster = Some(Arc::from(CLUSTER));
        flight.ctx.selected_endpoint_index = Some(0);
        flight.ctx.upstream_contacted = true;
        flight.error = Some(ErrorOrigin::Other);
    }

    /// An empty pipeline whose health registry tracks [`CLUSTER`] with one
    /// endpoint, marked unhealthy after `threshold` failures in a row.
    fn health_pipeline(threshold: u32) -> FilterPipeline {
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("127.0.0.1:9")],
            Some(threshold),
            Some(1),
        );
        let registry: HealthRegistry = Arc::new(HashMap::from([(Arc::from(CLUSTER), Arc::new(entry))]));
        let mut pipeline = empty_pipeline();
        pipeline.set_health_registry(registry);
        pipeline
    }
}
