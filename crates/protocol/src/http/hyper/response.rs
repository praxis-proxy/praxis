// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The upstream response head through the response phase, and its commit.
//!
//! What the Pingora handler's `response_filter` does: refuse a `101` (this
//! backend does not tunnel upgrades), strip hop-by-hop and reserved headers,
//! record the upstream status, capture a Trailers-Only gRPC status, retry on
//! a retriable status before anything reaches the client, then run the
//! response pipeline and add `Via`. Nothing is written to the client before
//! this phase is done.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Response, StatusCode, Version};
use praxis_core::egress::{Session as _, hyper::HyperSession};
use praxis_filter::{FilterAction, FilterError};
use tracing::{Instrument as _, error, warn};

use super::{
    body::{ProxyBody, Relay},
    failure::Failure,
    listener::ListenerShared,
    reply,
    service::Flight,
    stream::{Relaying, Start},
    upload::Upload,
    upstream::{Outcome, after_failure, record_attempt_failure, release},
};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    handler::{
        health_util::ErrorOrigin,
        hop_by_hop::{RESPONSE_HOP_BY_HOP, strip_hop_by_hop_header_map, strip_reserved_internal_header_map},
        response_body_filter::run_response_body,
        response_filter::{restore_http11_framing, run_response_filters, successful_connect_tunnel},
        response_trailers,
        retry_util::response_status_retry,
        via::append_map_via,
    },
    metrics,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long the commit waits for the first body chunk to arrive behind
/// the head: long enough for bytes that came with it, short enough not to
/// hold back a stream's head.
const FIRST_CHUNK_GRACE: Duration = Duration::from_millis(10); // 10 ms

// -----------------------------------------------------------------------------
// Answer
// -----------------------------------------------------------------------------

/// An upstream response head that passed the response phase.
pub(super) struct Answer {
    /// Whether the response carries no body (`HEAD`, `204`, `304`).
    bodyless: bool,

    /// Bound on each read of the upstream body.
    read_timeout: Option<Duration>,

    /// The filtered head the client gets.
    response: praxis_filter::Response,

    /// The exchange the body comes from.
    session: HyperSession,

    /// What was read of the body before the commit.
    start: Start,
}

// -----------------------------------------------------------------------------
// Response Head
// -----------------------------------------------------------------------------

/// Take the final response head through the response phase.
pub(super) async fn head(
    listener: &ListenerShared,
    flight: &mut Flight,
    session: HyperSession,
    upload: &Upload,
    read_timeout: Option<Duration>,
) -> Outcome {
    let mut head = match copy_head(&session, read_timeout) {
        Ok(head) => head,
        Err(failure) => {
            release(&listener.connector, session, false);
            return after_failure(flight, upload, failure);
        },
    };
    if head.response.status == StatusCode::SWITCHING_PROTOCOLS {
        error!("upstream switched protocols; the hyper backend does not tunnel upgrades");
        release(&listener.connector, session, false);
        let failure = Failure::status(502, "unsolicited 101 response from upstream");
        return after_failure(flight, upload, failure);
    }
    strip_hop_by_hop_header_map(&mut head.response.headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_internal_header_map(&mut head.response.headers);
    head.bodyless = record_upstream_head(&mut flight.ctx, &head.response);
    if response_status_retry(&mut flight.ctx, head.response.status.as_u16()) {
        release(&listener.connector, session, false);
        return status_retry(flight, upload, head.response.status);
    }

    flight.ctx.response_phase_done = true;
    let ran = Box::pin(run_filters(flight, &mut head.response)).await;
    match settle(listener, flight, session, head, ran) {
        Outcome::Answered(answer) if !answer.bodyless => Box::pin(read_first(listener, flight, *answer)).await,
        other @ (Outcome::Answered(_) | Outcome::Failed(_) | Outcome::Reply(_) | Outcome::Retry(_)) => other,
    }
}

/// Read and filter the first body chunk if it is already on its way, so a
/// body filter that fails on it is still answered with an error response,
/// as Pingora answers when the head and the bytes behind it are written
/// together. A body that is slower than [`FIRST_CHUNK_GRACE`] is relayed
/// after the head instead.
async fn read_first(listener: &ListenerShared, flight: &mut Flight, mut answer: Answer) -> Outcome {
    let read = read_chunk(&mut answer.session, answer.read_timeout);
    let Ok(first) = tokio::time::timeout(FIRST_CHUNK_GRACE, read).await else {
        return Outcome::Answered(Box::new(answer));
    };
    let chunk = match first {
        Ok(Some(chunk)) => chunk,
        Ok(None) => {
            answer.start = Start::Ended;
            return Outcome::Answered(Box::new(answer));
        },
        Err(failure) => {
            // The response phase already ran, so this is not retried.
            release(&listener.connector, answer.session, false);
            record_attempt_failure(&failure, &mut flight.ctx);
            return Outcome::Failed(failure);
        },
    };
    let ends = answer.session.response_done();
    let mut body = Some(chunk);
    if let Err(reason) = run_response_body(&flight.pipeline, &mut body, ends, &mut flight.ctx) {
        error!(
            reason = reason.as_str(),
            "response body filter failed before the response was committed"
        );
        release(&listener.connector, answer.session, false);
        return Outcome::Failed(Failure::internal(reason));
    }
    answer.start = Start::Chunk { body, ends };
    Outcome::Answered(Box::new(answer))
}

/// The upstream's head on its way to the client.
struct Head {
    /// Whether the upstream's response carries no body.
    bodyless: bool,

    /// Bound on each read of the upstream body.
    read_timeout: Option<Duration>,

    /// The head, as the filters leave it.
    response: praxis_filter::Response,

    /// The HTTP version the upstream answered with.
    version: Version,
}

/// Copy the session's head out, as the egress contract asks, before the
/// session moves on to the body.
fn copy_head(session: &HyperSession, read_timeout: Option<Duration>) -> Result<Head, Failure> {
    let head = session.response_head().map_err(|err| Failure::exchange(&err))?;
    let status = StatusCode::from_u16(head.status).map_err(|err| Failure::internal(err.to_string()))?;
    Ok(Head {
        bodyless: false,
        read_timeout,
        response: praxis_filter::Response {
            headers: head.headers.clone(),
            status,
        },
        version: head.version,
    })
}

/// Record the upstream's status for passive health and the client span,
/// and capture a Trailers-Only gRPC status; returns whether the response
/// carries no body.
fn record_upstream_head(ctx: &mut PingoraRequestCtx, response: &praxis_filter::Response) -> bool {
    let status = response.status.as_u16();
    ctx.connection_upgraded = false;
    ctx.upstream_response_status = Some(status);
    praxis_core::subrequest::record_http_client_status(&ctx.upstream_client_span, status);
    response_trailers::capture(&response.headers, ctx);
    is_bodyless(ctx, response.status)
}

/// Retry after a retriable status, unless the replay copy is truncated:
/// then the status is answered as a proxy error, as on Pingora.
fn status_retry(flight: &mut Flight, upload: &Upload, status: StatusCode) -> Outcome {
    let failure = Failure::status(status.as_u16(), "retriable upstream status");
    record_attempt_failure(&failure, &mut flight.ctx);
    if upload.is_truncated() {
        Outcome::Failed(failure)
    } else {
        Outcome::Retry(failure)
    }
}

/// Run the response pipeline inside the request, client and exchange spans.
async fn run_filters(
    flight: &mut Flight,
    response: &mut praxis_filter::Response,
) -> Option<Result<FilterAction, FilterError>> {
    let span = flight.ctx.request_span.clone();
    let client = flight.ctx.upstream_client_span.clone();
    let exchange = flight.ctx.upstream_exchange_span.clone();
    let ran = run_response_filters(&flight.pipeline, &mut flight.ctx, response)
        .instrument(exchange)
        .instrument(client)
        .instrument(span)
        .await?;
    Some(ran.0)
}

/// Act on the response pipeline's result.
fn settle(
    listener: &ListenerShared,
    flight: &mut Flight,
    session: HyperSession,
    mut head: Head,
    ran: Option<Result<FilterAction, FilterError>>,
) -> Outcome {
    let Some(result) = ran else {
        release(&listener.connector, session, false);
        return Outcome::Failed(Failure::internal("request snapshot not set during response phase"));
    };
    reframe(flight, &mut head, &result);
    match result {
        Ok(
            FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => Outcome::Answered(Box::new(answer(flight, session, head))),
        Ok(FilterAction::Reject(refusal)) => {
            warn!(status = refusal.status, "filter rejected response");
            release(&listener.connector, session, false);
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
            flight.error = Some(ErrorOrigin::Other);
            Outcome::Reply(reply::pending_rejection(refusal, &flight.ctx, flight.version))
        },
        Err(err) => {
            error!(error = %err, "filter pipeline error during response");
            release(&listener.connector, session, false);
            Outcome::Failed(Failure::internal(format!("response filter error: {err}")))
        },
    }
}

/// Restore HTTP/1.1 framing a filter's rewrite removed, re-strip reserved
/// headers a filter may have added, and keep the head for body conditions.
fn reframe(flight: &mut Flight, head: &mut Head, result: &Result<FilterAction, FilterError>) {
    let proceeds = matches!(
        result,
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone)
    );
    if proceeds {
        restore_framing(&flight.ctx, head);
    }
    if !flight.pipeline.is_empty() {
        strip_reserved_internal_header_map(&mut head.response.headers);
    }
    let continues = matches!(
        result,
        Ok(FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_))
    );
    if flight.pipeline.body_capabilities().any_response_body_condition && continues {
        flight.ctx.response_header_snapshot = Some(praxis_filter::Response {
            headers: head.response.headers.clone(),
            status: head.response.status,
        });
    }
}

/// Mark a body whose framing a filter removed as chunked for an HTTP/1.1
/// client, unless the response carries no body or opens a tunnel.
fn restore_framing(ctx: &PingoraRequestCtx, head: &mut Head) {
    let status = head.response.status;
    let tunnel = ctx
        .request_snapshot
        .as_ref()
        .is_some_and(|request| successful_connect_tunnel(&request.method, status));
    let no_body = head.bodyless || is_bodyless(ctx, status) || tunnel;
    restore_http11_framing(&mut head.response, ctx.client_http_version, no_body);
}

/// The answer for a head the response phase let through: a bodyless one
/// is delivered with its head, and `Via` names the upstream leg.
fn answer(flight: &mut Flight, session: HyperSession, mut head: Head) -> Answer {
    if head.bodyless {
        flight.ctx.response_delivery_complete = true;
    }
    // RFC 9110 Section 7.6.3: the response Via records the protocol this
    // proxy received the response over, the upstream leg.
    append_map_via(&mut head.response.headers, head.version);
    Answer {
        bodyless: head.bodyless,
        read_timeout: head.read_timeout,
        response: head.response,
        session,
        start: Start::Fresh,
    }
}

// -----------------------------------------------------------------------------
// Commit
// -----------------------------------------------------------------------------

/// Hand the response to the client: a bodyless one completes here, any
/// other is relayed by its own task, which completes the request when the
/// body ends.
pub(super) async fn commit(
    listener: &ListenerShared,
    mut flight: Flight,
    upload: Upload,
    answer: Answer,
) -> Response<ProxyBody> {
    let Answer {
        bodyless,
        read_timeout,
        response,
        mut session,
        start,
    } = answer;
    flight.written_status = response.status.as_u16();
    if bodyless {
        let keepalive = session.response_done() && upload.is_settled();
        release(&listener.connector, session, keepalive);
        flight.complete().await;
        return client_response(response.status, response.headers, ProxyBody::empty());
    }

    let (relay, body) = Relay::new();
    spawn_relay(Relaying {
        connector: listener.connector.clone(),
        flight,
        read_timeout,
        relay,
        session,
        start,
        upload,
    });
    client_response(response.status, response.headers, body)
}

/// Start the task relaying the body, inside the request span.
fn spawn_relay(relaying: Relaying) {
    let span = relaying.flight.ctx.request_span.clone();
    drop(tokio::spawn(relaying.run().instrument(span)));
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The hyper response for a status, headers and body.
fn client_response(status: StatusCode, headers: HeaderMap, body: ProxyBody) -> Response<ProxyBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// Whether a response with `status` to this request carries no body.
fn is_bodyless(ctx: &PingoraRequestCtx, status: StatusCode) -> bool {
    ctx.request_snapshot
        .as_ref()
        .is_some_and(|request| praxis_filter::bodyless_response(status, &request.method))
}

/// Read the next upstream body chunk within `read_timeout`.
async fn read_chunk(session: &mut HyperSession, read_timeout: Option<Duration>) -> Result<Option<Bytes>, Failure> {
    let read = session.read_response_body();
    let result = match read_timeout {
        Some(limit) => tokio::time::timeout(limit, read)
            .await
            .map_err(|_elapsed| Failure::read_timeout(limit))?,
        None => read.await,
    };
    result.map_err(|err| Failure::exchange(&err))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use http::{HeaderValue, Method};
    use http_body_util::BodyExt as _;
    use hyper::body::Body as _;
    use praxis_core::config::{HttpStatusCode, RetriableCondition, RetryPolicy};
    use praxis_filter::{BodyMode, FilterPipeline, Rejection};

    use super::*;
    use crate::http::hyper::{
        failure::FailureKind,
        test_utils::{
            Client, Script, Upstream, answered, conditional_pipeline, empty_pipeline, listener_shared,
            scripted_pipeline, session_to, streaming_upload, truncated_upload,
        },
    };

    #[test]
    fn heads_without_a_body_are_told_apart() {
        for (method, status, bodyless) in [
            (Method::HEAD, StatusCode::OK, true),
            (Method::GET, StatusCode::NO_CONTENT, true),
            (Method::GET, StatusCode::NOT_MODIFIED, true),
            (Method::GET, StatusCode::CONTINUE, true),
            (Method::GET, StatusCode::OK, false),
            (Method::CONNECT, StatusCode::OK, false),
        ] {
            let ctx = ctx_for(method.clone());

            assert_eq!(
                is_bodyless(&ctx, status),
                bodyless,
                "{method} answered with {status}: bodyless is {bodyless}"
            );
        }
    }

    #[test]
    fn nothing_is_bodyless_without_the_request() {
        assert!(
            !is_bodyless(&PingoraRequestCtx::default(), StatusCode::NO_CONTENT),
            "with no request recorded nothing is assumed about the body"
        );
    }

    #[test]
    fn http11_client_gets_chunked_framing_when_none_is_left() {
        let mut head = unframed_head(StatusCode::OK);

        restore_framing(&http11_ctx(Method::GET), &mut head);

        assert_eq!(
            head.response.headers.get(http::header::TRANSFER_ENCODING).unwrap(),
            "chunked",
            "an HTTP/1.1 body of unknown length is chunked"
        );
    }

    #[test]
    fn declared_length_is_kept_as_the_framing() {
        let mut head = unframed_head(StatusCode::OK);
        head.response
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("2"));

        restore_framing(&http11_ctx(Method::GET), &mut head);

        assert_eq!(
            head.response.headers.get(http::header::CONTENT_LENGTH).unwrap(),
            "2",
            "the length stays"
        );
        assert!(
            head.response.headers.get(http::header::TRANSFER_ENCODING).is_none(),
            "a body with a length is not chunked"
        );
    }

    #[test]
    fn http10_client_gets_no_chunked_framing() {
        let mut ctx = http11_ctx(Method::GET);
        ctx.client_http_version = Some(Version::HTTP_10);
        let mut head = unframed_head(StatusCode::OK);

        restore_framing(&ctx, &mut head);

        assert!(
            head.response.headers.get(http::header::TRANSFER_ENCODING).is_none(),
            "an HTTP/1.0 client reads the body to the connection's close"
        );
    }

    #[test]
    fn bodyless_response_gets_no_chunked_framing() {
        let mut upstream_bodyless = unframed_head(StatusCode::OK);
        upstream_bodyless.bodyless = true;
        for (ctx, mut head, why) in [
            (http11_ctx(Method::HEAD), unframed_head(StatusCode::OK), "a HEAD"),
            (http11_ctx(Method::GET), unframed_head(StatusCode::NO_CONTENT), "a 204"),
            (
                http11_ctx(Method::GET),
                upstream_bodyless,
                "a head the upstream sent without a body",
            ),
        ] {
            restore_framing(&ctx, &mut head);

            assert!(
                head.response.headers.get(http::header::TRANSFER_ENCODING).is_none(),
                "{why} has no body to frame"
            );
        }
    }

    #[test]
    fn connect_tunnel_gets_no_chunked_framing() {
        let mut head = unframed_head(StatusCode::OK);

        restore_framing(&http11_ctx(Method::CONNECT), &mut head);

        assert!(
            head.response.headers.get(http::header::TRANSFER_ENCODING).is_none(),
            "a successful CONNECT opens a tunnel, not a body"
        );
    }

    #[test]
    fn rejected_head_is_not_reframed() {
        let mut flight = Flight::for_tests(empty_pipeline());
        *flight.ctx = http11_ctx(Method::GET);
        let mut head = unframed_head(StatusCode::OK);

        reframe(
            &mut flight,
            &mut head,
            &Ok(FilterAction::Reject(Rejection::status(403))),
        );

        assert!(
            head.response.headers.get(http::header::TRANSFER_ENCODING).is_none(),
            "a head that is not delivered gets no framing"
        );
    }

    #[test]
    fn reserved_headers_a_filter_added_are_stripped_again() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script::default()));
        *flight.ctx = http11_ctx(Method::GET);
        let mut head = unframed_head(StatusCode::OK);
        head.response
            .headers
            .insert("x-praxis-route", HeaderValue::from_static("internal"));

        reframe(&mut flight, &mut head, &Ok(FilterAction::Continue));

        assert!(
            head.response.headers.get("x-praxis-route").is_none(),
            "an internal header never reaches the client"
        );
    }

    #[test]
    fn delivered_head_is_kept_for_response_body_conditions() {
        let mut flight = Flight::for_tests(conditional_pipeline(passing_body(), 200));
        *flight.ctx = http11_ctx(Method::GET);
        let mut head = unframed_head(StatusCode::OK);
        head.response.headers.insert("x-kept", HeaderValue::from_static("yes"));

        reframe(&mut flight, &mut head, &Ok(FilterAction::Continue));

        assert!(
            flight
                .ctx
                .response_header_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.headers.get("x-kept").is_some()),
            "a body filter with response conditions sees the head the client gets"
        );
    }

    #[test]
    fn rejected_head_is_not_kept_for_response_body_conditions() {
        let mut flight = Flight::for_tests(conditional_pipeline(passing_body(), 200));
        *flight.ctx = http11_ctx(Method::GET);
        let mut head = unframed_head(StatusCode::OK);

        reframe(
            &mut flight,
            &mut head,
            &Ok(FilterAction::Reject(Rejection::status(403))),
        );

        assert!(
            flight.ctx.response_header_snapshot.is_none(),
            "no body follows a rejected head, so nothing is kept for it"
        );
    }

    #[test]
    fn head_is_not_kept_without_response_body_conditions() {
        let mut flight = Flight::for_tests(scripted_pipeline(passing_body()));
        *flight.ctx = http11_ctx(Method::GET);
        let mut head = unframed_head(StatusCode::OK);

        reframe(&mut flight, &mut head, &Ok(FilterAction::Continue));

        assert!(
            flight.ctx.response_header_snapshot.is_none(),
            "the copy is only made when a body condition needs it"
        );
    }

    #[tokio::test]
    async fn copy_head_copies_the_status_headers_and_version() {
        let (_upstream, _connector, session) =
            answered(b"HTTP/1.1 201 Created\r\nx-made: yes\r\ncontent-length: 0\r\n\r\n").await;

        let head = copy_head(&session, Some(Duration::from_secs(1))).unwrap();

        assert_eq!(head.response.status, StatusCode::CREATED, "the status is copied");
        assert_eq!(
            head.response.headers.get("x-made").unwrap(),
            "yes",
            "the headers are copied"
        );
        assert_eq!(head.version, Version::HTTP_11, "the upstream's version is kept");
        assert_eq!(
            head.read_timeout,
            Some(Duration::from_secs(1)),
            "the read timeout travels with the head"
        );
    }

    #[test]
    fn recording_the_head_notes_the_status_and_a_trailers_only_grpc_status() {
        let mut ctx = ctx_for(Method::POST);
        ctx.connection_upgraded = true;
        let mut response = praxis_filter::Response {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        };
        response.headers.insert("grpc-status", HeaderValue::from_static("5"));

        let bodyless = record_upstream_head(&mut ctx, &response);

        assert!(!bodyless, "a 200 to a POST has a body");
        assert_eq!(ctx.upstream_response_status, Some(200), "the status is recorded");
        assert!(!ctx.connection_upgraded, "this backend never upgrades");
        assert!(ctx.grpc_completion.is_some(), "a gRPC status in the head is captured");
    }

    #[tokio::test]
    async fn response_head_passes_with_hop_by_hop_headers_stripped() {
        let mut flight = get_flight(empty_pipeline());

        let (outcome, _client) = head_outcome(
            &mut flight,
            b"HTTP/1.1 200 OK\r\nconnection: x-up\r\nx-up: 1\r\nx-kept: yes\r\ncontent-length: 0\r\n\r\n",
        )
        .await;

        let answer = answer_of(outcome).expect("a plain 200 is answered");
        assert!(
            answer.response.headers.get("x-up").is_none(),
            "a hop-by-hop header is stripped"
        );
        assert_eq!(
            answer.response.headers.get("x-kept").unwrap(),
            "yes",
            "an end-to-end header is kept"
        );
        assert_eq!(
            answer.response.headers.get(http::header::VIA).unwrap(),
            "1.1 praxis",
            "Via names the upstream leg"
        );
        assert_eq!(flight.ctx.upstream_response_status, Some(200), "the status is recorded");
        assert!(flight.ctx.response_phase_done, "the response phase ran");
    }

    #[tokio::test]
    async fn switching_protocols_is_refused_as_a_bad_gateway() {
        let mut flight = get_flight(empty_pipeline());

        let (outcome, _client) = head_outcome(
            &mut flight,
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: x\r\n\r\n",
        )
        .await;

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::Status(502)),
            "an upgrade this backend cannot tunnel is a 502"
        );
    }

    #[tokio::test]
    async fn retriable_status_under_a_policy_is_retried() {
        let mut flight = get_flight(empty_pipeline());
        flight.ctx.retry_policy = Some(retrying_503());

        let (outcome, _client) = head_outcome(
            &mut flight,
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        )
        .await;

        assert!(
            matches!(&outcome, Outcome::Retry(failure) if failure.kind == FailureKind::Status(503)),
            "a status the policy retries is retried before anything reaches the client"
        );
        assert_eq!(flight.ctx.retries, 1, "the retry is counted");
    }

    #[tokio::test]
    async fn status_without_a_policy_to_retry_it_is_answered() {
        let mut flight = get_flight(empty_pipeline());

        let (outcome, _client) = head_outcome(
            &mut flight,
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        )
        .await;

        assert!(
            matches!(&outcome, Outcome::Answered(answer) if answer.response.status == StatusCode::SERVICE_UNAVAILABLE),
            "the default policy retries no status, so the upstream's 503 is answered"
        );
    }

    #[tokio::test]
    async fn retriable_status_with_a_truncated_body_is_a_proxy_error() {
        let mut flight = get_flight(empty_pipeline());
        flight.ctx.retry_policy = Some(retrying_503());
        let (upload, _client) = truncated_upload(&mut flight).await;
        let (_upstream, _connector, session) =
            answered(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").await;

        let outcome = head(&listener_shared(), &mut flight, session, &upload, None).await;

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::Status(503)),
            "a body that cannot be replayed turns the retry into the proxy's error"
        );
    }

    #[tokio::test]
    async fn response_filter_rejection_is_answered_locally() {
        let mut flight = get_flight(scripted_pipeline(Script {
            response: Some(Arc::new(|| Ok(FilterAction::Reject(Rejection::status(403))))),
            ..Script::default()
        }));

        let (outcome, _client) = head_outcome(&mut flight, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;

        assert!(
            matches!(&outcome, Outcome::Reply(reply) if reply.status == StatusCode::FORBIDDEN),
            "the filter's rejection replaces the upstream's answer"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_FILTER_REJECT),
            "it is counted as a filter rejection"
        );
        assert_eq!(flight.error, Some(ErrorOrigin::Other), "the proxy ended the request");
    }

    #[tokio::test]
    async fn response_filter_error_is_an_internal_failure() {
        let mut flight = get_flight(scripted_pipeline(Script {
            response: Some(Arc::new(|| Err("response filter broke".into()))),
            ..Script::default()
        }));

        let (outcome, _client) = head_outcome(&mut flight, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::Internal),
            "a failing response filter is the proxy's fault"
        );
    }

    #[tokio::test]
    async fn bodyless_answer_is_delivered_with_its_head() {
        let mut flight = get_flight(empty_pipeline());

        let (outcome, _client) = head_outcome(&mut flight, b"HTTP/1.1 204 No Content\r\n\r\n").await;

        assert!(
            matches!(&outcome, Outcome::Answered(answer) if answer.bodyless && matches!(answer.start, Start::Fresh)),
            "a 204 is answered without reading a body"
        );
        assert!(
            flight.ctx.response_delivery_complete,
            "the delivery is complete with the head"
        );
    }

    #[tokio::test]
    async fn body_that_arrived_with_the_head_is_read_before_the_commit() {
        let mut flight = get_flight(empty_pipeline());

        let (outcome, _client) = head_outcome(&mut flight, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;

        let answer = answer_of(outcome).expect("a plain 200 is answered");
        assert!(
            matches!(&answer.start, Start::Chunk { body: Some(chunk), ends: true } if chunk == "ok"),
            "the whole body was read and filtered ahead of the commit: {:?}",
            answer.start
        );
    }

    #[tokio::test]
    async fn body_filter_failing_on_the_first_chunk_is_still_an_error_response() {
        let mut flight = get_flight(scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|_body, _end| Err("body filter broke".into())),
            )),
            ..Script::default()
        }));

        let (outcome, _client) = head_outcome(&mut flight, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::Internal),
            "nothing was committed, so the failure can still be answered"
        );
    }

    #[tokio::test]
    async fn failure_reading_the_first_chunk_is_not_retried() {
        let mut flight = get_flight(empty_pipeline());
        flight.ctx.retry_policy = Some(Arc::new(RetryPolicy {
            retriable_conditions: vec![RetriableCondition::Reset],
            ..RetryPolicy::legacy_default()
        }));
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let upstream = Upstream::answering_then_closing(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::GET).await;
        session.finish_request().await.unwrap();
        session.read_response_head().await.unwrap();

        let outcome = head(&listener_shared(), &mut flight, session, &upload, None).await;

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::ConnectionClosed),
            "once the response phase ran, a failed body read is answered, never retried"
        );
    }

    #[tokio::test]
    async fn committed_body_is_relayed_to_the_client() {
        let mut flight = get_flight(empty_pipeline());
        let listener = listener_shared();
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let (_upstream, _connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").await;
        let answer =
            answer_of(head(&listener, &mut flight, session, &upload, None).await).expect("a plain 200 is answered");

        let response = commit(&listener, flight, upload, *answer).await;

        assert_eq!(response.status(), StatusCode::OK, "the upstream's status is committed");
        let body = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
            .await
            .expect("the relay finishes")
            .unwrap()
            .to_bytes();
        assert_eq!(body, "hello", "the body reaches the client");
    }

    #[tokio::test]
    async fn committed_bodyless_answer_has_no_body() {
        let mut flight = get_flight(empty_pipeline());
        let listener = listener_shared();
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let (_upstream, _connector, session) = answered(b"HTTP/1.1 304 Not Modified\r\netag: \"v1\"\r\n\r\n").await;
        let answer = answer_of(head(&listener, &mut flight, session, &upload, None).await).expect("a 304 is answered");

        let response = commit(&listener, flight, upload, *answer).await;

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "the status is committed");
        assert_eq!(response.headers().get("etag").unwrap(), "\"v1\"", "with its headers");
        assert!(response.body().is_end_stream(), "and no body");
    }

    #[tokio::test]
    async fn each_upstream_read_is_bounded() {
        let (_upstream, _connector, mut session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhi\r\n").await;

        let first = read_chunk(&mut session, Some(Duration::from_millis(50))).await;
        let stalled = read_chunk(&mut session, Some(Duration::from_millis(50))).await;

        assert!(
            matches!(&first, Ok(Some(chunk)) if chunk == "hi"),
            "what arrived is read: {first:?}"
        );
        assert!(
            matches!(&stalled, Err(failure) if failure.kind == FailureKind::ReadTimeout),
            "a body that stops arriving trips the read timeout: {stalled:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The answer `outcome` carries, if it carries one.
    fn answer_of(outcome: Outcome) -> Option<Box<Answer>> {
        match outcome {
            Outcome::Answered(answer) => Some(answer),
            Outcome::Failed(_) | Outcome::Reply(_) | Outcome::Retry(_) => None,
        }
    }

    /// A context whose recorded request used `method`.
    fn ctx_for(method: Method) -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(praxis_filter::Request {
            method,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
        });
        ctx
    }

    /// A `GET` running `pipeline` from an HTTP/1.1 client.
    fn get_flight(pipeline: FilterPipeline) -> Flight {
        let mut flight = Flight::for_tests(pipeline);
        *flight.ctx = http11_ctx(Method::GET);
        flight.ctx.request_is_idempotent = true;
        flight
    }

    /// Take the head an upstream answering `reply` sends a `GET` through the
    /// response phase, with the client side of the request's upload.
    async fn head_outcome(flight: &mut Flight, reply: &'static [u8]) -> (Outcome, Client) {
        let (upload, client) = streaming_upload(&flight.ctx).await;
        let (_upstream, _connector, session) = answered(reply).await;
        (head(&listener_shared(), flight, session, &upload, None).await, client)
    }

    /// [`ctx_for`] with an HTTP/1.1 client.
    fn http11_ctx(method: Method) -> PingoraRequestCtx {
        let mut ctx = ctx_for(method);
        ctx.client_http_version = Some(Version::HTTP_11);
        ctx
    }

    /// A script whose response body hook lets every chunk through.
    fn passing_body() -> Script {
        Script {
            response_body: Some((BodyMode::Stream, Arc::new(|_body, _end| Ok(FilterAction::Continue)))),
            ..Script::default()
        }
    }

    /// A policy that retries a `503` on idempotent requests.
    fn retrying_503() -> Arc<RetryPolicy> {
        Arc::new(RetryPolicy {
            retriable_status_codes: vec![HttpStatusCode::try_from(503).unwrap()],
            ..RetryPolicy::legacy_default()
        })
    }

    /// A head with `status` and no framing headers left.
    fn unframed_head(status: StatusCode) -> Head {
        Head {
            bodyless: false,
            read_timeout: None,
            response: praxis_filter::Response {
                headers: HeaderMap::new(),
                status,
            },
            version: Version::HTTP_11,
        }
    }
}
