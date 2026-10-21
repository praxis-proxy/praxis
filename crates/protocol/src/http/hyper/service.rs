// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The per-request entry point and its lifecycle state.
//!
//! [`handle`] takes one request through the lifecycle in the Pingora
//! handler's order: admission, pinning the pipeline, the request phase, then
//! either a local answer or the upstream attempts. A [`Flight`] carries the
//! request's state all the way, including into the task that relays a
//! streamed response body, and runs completion exactly once wherever the
//! request ends: on a local answer, at the end of a relayed body, or, when
//! the client goes away and hyper drops the request, from its drop.
//!
//! [`Flight`]: crate::http::hyper::service::Flight
//! [`handle`]: crate::http::hyper::service::handle

use std::{fmt, mem, sync::Arc};

use arc_swap::ArcSwap;
use http::{HeaderValue, Method, Request, Response, Version};
use hyper::body::Incoming;
use praxis_filter::FilterPipeline;
use tracing::{Instrument as _, debug};

use super::{
    admission,
    body::ProxyBody,
    downstream::DownstreamBody,
    listener::{ConnectionFacts, ListenerShared},
    reply::LocalReply,
    request::{self, RequestPhase},
    terminal, upstream,
};
use crate::http::pingora::{context::PingoraRequestCtx, handler::health_util::ErrorOrigin};

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Serve one request.
///
/// # Errors
///
/// Returns [`ResponseAbort`] when the request ends without a response to
/// write, which tells hyper to close the connection or reset the stream.
pub(super) async fn handle(
    listener: Arc<ListenerShared>,
    connection: Arc<ConnectionFacts>,
    request: Request<Incoming>,
) -> Result<Response<ProxyBody>, ResponseAbort> {
    let mut flight = Flight::new(&listener.pipeline, request.method().clone(), request.version());
    if let Some(refusal) = admission::admit(&listener, &mut flight.ctx) {
        flight.error = Some(ErrorOrigin::Other);
        return Ok(flight.reply(refusal).await);
    }

    let (parts, body) = request.into_parts();
    let mut body = DownstreamBody::new(body, listener.read_timeout);
    let phase = Box::pin(request::run(&mut flight, &connection, parts, &mut body)).await;
    Box::pin(answer(&listener, flight, body, phase)).await
}

/// Answer the request the way its request phase decided.
async fn answer(
    listener: &ListenerShared,
    flight: Flight,
    body: DownstreamBody,
    phase: RequestPhase,
) -> Result<Response<ProxyBody>, ResponseAbort> {
    match phase {
        RequestPhase::Proxy => {
            // The filters the attempts run, and the tasks they spawn, belong
            // to the request's span, as on Pingora.
            let span = flight.ctx.request_span.clone();
            Box::pin(upstream::proxy(listener, flight, body).instrument(span)).await
        },
        RequestPhase::Reply(reply) => Ok(flight.reply(reply).await),
        RequestPhase::Stream(response) => Ok(Box::pin(terminal::stream(flight, *response)).await),
    }
}

// -----------------------------------------------------------------------------
// Flight
// -----------------------------------------------------------------------------

/// One request's state from admission to completion.
pub(super) struct Flight {
    /// Whether completion has run.
    completed: bool,

    /// The per-request context the filter pipeline reads and writes.
    pub(super) ctx: Box<PingoraRequestCtx>,

    /// Where the failure that ended the request came from, if one did.
    pub(super) error: Option<ErrorOrigin>,

    /// The request method as received, for metrics.
    pub(super) method: Method,

    /// Whether this state was handed to a background completion after the
    /// request ended early; dropped again, it is not handed on.
    orphaned: bool,

    /// The pipeline the request runs, pinned when its state starts.
    pub(super) pipeline: Arc<FilterPipeline>,

    /// The HTTP version the client spoke.
    pub(super) version: Version,

    /// The status of the response handed to the client; 0 until one is.
    pub(super) written_status: u16,
}

impl Flight {
    /// Start a request's state, pinning the current pipeline for its whole
    /// run.
    fn new(pipeline: &ArcSwap<FilterPipeline>, method: Method, version: Version) -> Self {
        let mut ctx = Box::<PingoraRequestCtx>::default();
        let pipeline = ctx.pin_pipeline(pipeline);
        Self {
            completed: false,
            ctx,
            error: None,
            method,
            orphaned: false,
            pipeline,
            version,
            written_status: 0,
        }
    }

    /// Run completion now: metrics, passive health, retry state, the
    /// skipped response phase, and the fallback access record.
    pub(super) async fn complete(&mut self) {
        if mem::replace(&mut self.completed, true) {
            return;
        }
        Box::pin(super::completion::run(self)).await;
    }

    /// A `GET` over HTTP/1.1 running `pipeline`, for the unit tests of the
    /// phases that take a request's state.
    #[cfg(test)]
    pub(super) fn for_tests(pipeline: FilterPipeline) -> Self {
        Self::new(&ArcSwap::from_pointee(pipeline), Method::GET, Version::HTTP_11)
    }

    /// Whether the client asked for a HEAD.
    pub(super) fn is_head(&self) -> bool {
        self.method == Method::HEAD
    }

    /// Turn `reply` into the client's response, recording its status.
    fn local_response(&mut self, reply: LocalReply) -> Response<ProxyBody> {
        let is_head = self.is_head();
        let closes = !reply.keepalive && self.version != Version::HTTP_2;
        let mut response = reply.into_response(is_head);
        if closes {
            response
                .headers_mut()
                .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }
        self.written_status = response.status().as_u16();
        response
    }

    /// Answer the request with `reply`, complete it, and hand back the
    /// response for hyper to write.
    pub(super) async fn reply(mut self, reply: LocalReply) -> Response<ProxyBody> {
        let response = self.local_response(reply);
        self.complete().await;
        response
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        // An orphan dropped unfinished means the runtime is shutting down
        // and cancelled its completion; handing it on again would recurse.
        if self.completed || self.orphaned {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        debug!("request ended before it completed; completing it in the background");
        let mut orphan = Self {
            completed: false,
            ctx: mem::take(&mut self.ctx),
            error: self.error.or(Some(ErrorOrigin::Downstream)),
            method: mem::replace(&mut self.method, Method::GET),
            orphaned: true,
            pipeline: Arc::clone(&self.pipeline),
            version: self.version,
            written_status: self.written_status,
        };
        self.completed = true;
        drop(runtime.spawn(async move { orphan.complete().await }));
    }
}

impl fmt::Debug for Flight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flight")
            .field("completed", &self.completed)
            .field("method", &self.method)
            .field("written_status", &self.written_status)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// ResponseAbort
// -----------------------------------------------------------------------------

/// A request that ends without a response: hyper closes the HTTP/1
/// connection or resets the HTTP/2 stream.
#[derive(Clone, Copy, Debug)]
pub(super) struct ResponseAbort;

impl fmt::Display for ResponseAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the request ended without a response")
    }
}

impl std::error::Error for ResponseAbort {}

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
    use std::{sync::atomic::Ordering, time::Duration};

    use bytes::Bytes;
    use http::StatusCode;
    use hyper::body::Body as _;
    use praxis_core::retry::ClusterRetryState;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::http::hyper::test_utils::{client_request, empty_pipeline, listener_shared};

    #[test]
    fn reply_without_keepalive_closes_an_http1_connection() {
        let mut flight = Flight::for_tests(empty_pipeline());

        let response = flight.local_response(LocalReply::status(503));

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the reply's status is kept"
        );
        assert_eq!(
            response.headers().get(http::header::CONNECTION).unwrap(),
            "close",
            "an HTTP/1 client is told the connection closes"
        );
        assert_eq!(
            flight.written_status, 503,
            "the status handed to the client is recorded"
        );
    }

    #[test]
    fn reply_never_names_the_connection_on_http2() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.version = Version::HTTP_2;

        let response = flight.local_response(LocalReply::status(503));

        assert!(
            response.headers().get(http::header::CONNECTION).is_none(),
            "HTTP/2 forbids the Connection header"
        );
    }

    #[test]
    fn keepalive_reply_leaves_the_connection_open() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let mut reply = LocalReply::status(200);
        reply.keepalive = true;

        let response = flight.local_response(reply);

        assert!(
            response.headers().get(http::header::CONNECTION).is_none(),
            "a reply that keeps the connection says nothing about it"
        );
    }

    #[test]
    fn head_reply_keeps_the_headers_and_drops_the_body() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.method = Method::HEAD;
        let mut reply = LocalReply::status(200);
        reply.body = Some(Bytes::from_static(b"hello"));
        reply
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from(5_u32));

        let response = flight.local_response(reply);

        assert!(response.body().is_end_stream(), "a HEAD gets no body");
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH).unwrap(),
            "5",
            "but keeps the length the GET would have had"
        );
    }

    #[tokio::test]
    async fn reply_completes_the_request() {
        let (flight, lease) = leased_flight();

        let response = flight.reply(LocalReply::status(200)).await;

        assert_eq!(response.status(), StatusCode::OK, "the reply is answered");
        assert_eq!(lease.active_requests.load(Ordering::Relaxed), 0, "completion ran");
    }

    #[tokio::test]
    async fn dropped_flight_completes_in_the_background() {
        let (flight, lease) = leased_flight();

        drop(flight);

        assert!(
            eventually(|| lease.active_requests.load(Ordering::Relaxed) == 0).await,
            "a request the client abandoned is still completed"
        );
    }

    #[tokio::test]
    async fn completed_flight_is_not_completed_again_when_dropped() {
        let (mut flight, lease) = leased_flight();
        flight.complete().await;
        lease.enter();

        drop(flight);
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            lease.active_requests.load(Ordering::Relaxed),
            1,
            "a completed request is not completed a second time"
        );
    }

    #[test]
    fn flight_dropped_outside_a_runtime_is_left_alone() {
        let (flight, lease) = leased_flight();

        drop(flight);

        assert_eq!(
            lease.active_requests.load(Ordering::Relaxed),
            1,
            "with no runtime to complete it on, nothing is spawned"
        );
    }

    #[test]
    fn pinned_pipeline_outlives_a_reload() {
        let original = Arc::new(empty_pipeline());
        let swap = ArcSwap::new(Arc::clone(&original));
        let flight = Flight::new(&swap, Method::GET, Version::HTTP_11);

        swap.store(Arc::new(empty_pipeline()));

        assert!(
            Arc::ptr_eq(&flight.pipeline, &original),
            "a request keeps the pipeline it started under"
        );
        assert!(
            flight
                .ctx
                .pinned_pipeline
                .as_ref()
                .is_some_and(|pinned| Arc::ptr_eq(pinned, &original)),
            "and its context pins the same one for the filters"
        );
    }

    #[tokio::test]
    async fn http11_request_without_host_is_refused() {
        let (request, _client) = client_request(b"GET / HTTP/1.1\r\n\r\n").await;

        let response = handle(Arc::new(listener_shared()), facts(), request).await;

        assert_eq!(
            response.map(|response| response.status()).ok(),
            Some(StatusCode::BAD_REQUEST),
            "an HTTP/1.1 request must carry a Host"
        );
    }

    #[tokio::test]
    async fn http10_request_without_host_is_answered() {
        let (request, _client) = client_request(b"GET / HTTP/1.0\r\n\r\n").await;

        let response = handle(Arc::new(listener_shared()), facts(), request).await;

        assert!(
            response.is_ok_and(|response| response.status().is_server_error()),
            "with no route the request is answered with a proxy error, not a panic"
        );
    }

    #[tokio::test]
    async fn full_listener_refuses_with_retry_after() {
        let mut listener = listener_shared();
        listener.connection_limit = Some(Arc::new(Semaphore::new(0)));
        let (request, _client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;

        let response = handle(Arc::new(listener), facts(), request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a listener at its connection limit refuses"
        );
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER).unwrap(),
            "1",
            "and says when to come back"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Wait up to two seconds for `condition`.
    async fn eventually<F: Fn() -> bool>(condition: F) -> bool {
        for _poll in 0..200 {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        condition()
    }

    /// The facts of a plain connection from a local client.
    fn facts() -> Arc<ConnectionFacts> {
        Arc::new(ConnectionFacts {
            peer: "127.0.0.1:40000".parse().unwrap(),
            tls: false,
        })
    }

    /// A request's state holding a cluster retry lease, which completion
    /// releases, and the lease.
    fn leased_flight() -> (Flight, Arc<ClusterRetryState>) {
        let lease = Arc::new(ClusterRetryState::new(None));
        lease.enter();
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.cluster_retry_state = Some(Arc::clone(&lease));
        (flight, lease)
    }
}
