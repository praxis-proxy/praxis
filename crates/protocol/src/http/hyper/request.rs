// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The request phase: what the Pingora handler's `request_filter` does.
//!
//! Validation, the client facts filters read, the request span, the body
//! modes, the optional request-head phase, the `StreamBuffer` pre-read, and
//! the request pipeline. The filtered request the pipeline leaves in the
//! context's request snapshot is the request the upstream receives: every
//! header mutation is applied to it in the order Pingora applies it to the
//! forwarded head.

use http::request::Parts;
use praxis_core::connectivity::normalize_mapped_ipv4;
use praxis_filter::{BodyMode, FilterAction, Rejection, Request, StreamingTerminalResponse};
use tracing::{Instrument as _, debug, error};

use super::{
    admission,
    downstream::{DownstreamBody, DownstreamFrame},
    failure::{Failure, FailureKind},
    listener::ConnectionFacts,
    reply::{self, LocalReply},
    service::Flight,
};
use crate::http::pingora::{
    handler::request_filter::{
        header_mutations::apply_pre_read_mutations_to_request,
        pipeline::{PipelineResult, run_pipeline},
        request_head::run_head_filters,
        request_utils::create_request_span_for,
        stream_buffer::{PreReadMutations, PreReadPass, PreReadStop},
    },
    metrics,
};

// -----------------------------------------------------------------------------
// RequestPhase
// -----------------------------------------------------------------------------

/// How the request phase ended.
pub(super) enum RequestPhase {
    /// Forward the request upstream.
    Proxy,

    /// Answer locally.
    Reply(LocalReply),

    /// Answer with a filter's streaming terminal response.
    Stream(Box<StreamingTerminalResponse>),
}

/// Run the request phase over the request head and, for `StreamBuffer`,
/// its body.
pub(super) async fn run(
    flight: &mut Flight,
    connection: &ConnectionFacts,
    mut parts: Parts,
    body: &mut DownstreamBody,
) -> RequestPhase {
    if let Some(refusal) = admission::validate(&mut parts) {
        early_exit(flight, connection, parts);
        return RequestPhase::Reply(reply::rejection(refusal, &flight.ctx, flight.version));
    }
    if let Some(answer) = admission::max_forwards(&mut parts) {
        early_exit(flight, connection, parts);
        return RequestPhase::Reply(reply::plain_rejection(answer));
    }

    let mut request = capture_client(flight, connection, parts);
    if let Err(phase) = Box::pin(head_phase(flight, &mut request)).await {
        return phase;
    }
    if matches!(flight.ctx.request_body_mode, BodyMode::StreamBuffer { .. }) {
        debug!("pre-reading request body for StreamBuffer inspection");
        if let Err(phase) = Box::pin(pre_read(flight, &mut request, body)).await {
            return phase;
        }
    }
    let span = flight.ctx.request_span.clone();
    let result = Box::pin(run_pipeline(&flight.pipeline, request, &mut flight.ctx).instrument(span)).await;
    Box::pin(outcome(flight, result)).await
}

/// Record the request for a pre-pipeline exit, so the fallback access record
/// and the skipped response phase still see it.
fn early_exit(flight: &mut Flight, connection: &ConnectionFacts, parts: Parts) {
    if flight.ctx.request_snapshot.is_none() {
        flight.ctx.request_snapshot = Some(Request {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
        });
    }
    if flight.ctx.client_addr.is_none() {
        flight.ctx.client_addr = Some(normalize_mapped_ipv4(connection.peer.ip()));
    }
}

/// Capture the client facts filters read, open the request span, seed the
/// body modes, and turn the head into the pipeline's request.
fn capture_client(flight: &mut Flight, connection: &ConnectionFacts, parts: Parts) -> Request {
    flight.ctx.client_http_version = Some(parts.version);
    flight.ctx.client_addr = Some(normalize_mapped_ipv4(connection.peer.ip()));
    flight.ctx.downstream_tls = connection.tls;
    flight.ctx.peer_identity = None;
    flight.ctx.request_is_idempotent = matches!(
        parts.method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    );
    flight.ctx.request_span =
        create_request_span_for(parts.method.as_str(), parts.uri.path(), &parts.headers, &flight.ctx);

    let caps = flight.pipeline.body_capabilities();
    flight.ctx.request_body_mode = caps.request_body_mode;
    flight.ctx.response_body_mode = caps.response_body_mode;
    Request {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
    }
}

/// Prepare the request head and reject an oversized declared input body.
async fn head_phase(flight: &mut Flight, request: &mut Request) -> Result<(), RequestPhase> {
    if flight.pipeline.has_request_head_phase() {
        run_head_phase(flight, request).await?;
    }
    let rejection = flight
        .ctx
        .request_span
        .in_scope(|| crate::http::body_limit::declared_body_rejection(&request.headers, &flight.pipeline));
    if let Some(rejection) = rejection {
        flight.ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
        return Err(refuse(flight, request, rejection));
    }
    Ok(())
}

/// Run opted-in head filters and apply their trusted header mutations.
async fn run_head_phase(flight: &mut Flight, request: &mut Request) -> Result<(), RequestPhase> {
    let span = flight.ctx.request_span.clone();
    let ran = Box::pin(run_head_filters(&flight.pipeline, request, &mut flight.ctx).instrument(span)).await;
    match ran {
        Ok((FilterAction::Reject(refusal), _)) => {
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
            Err(refuse(flight, request, refusal))
        },
        Ok((_, mutations)) => {
            if !mutations.is_empty() {
                apply_pre_read_mutations_to_request(request, &mutations);
            }
            Ok(())
        },
        Err(err) => {
            error!(error = %err, "request-head filter error");
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_INTERNAL);
            Err(refuse(flight, request, Rejection::status(500)))
        },
    }
}

/// Snapshot `request` and answer it with `refusal`.
fn refuse(flight: &mut Flight, request: &Request, refusal: Rejection) -> RequestPhase {
    flight.ctx.request_snapshot = Some(request.clone());
    RequestPhase::Reply(reply::rejection(refusal, &flight.ctx, flight.version))
}

/// Pre-read the whole request body through the body filters before the
/// request pipeline runs, so body-based routing can choose the upstream.
async fn pre_read(flight: &mut Flight, request: &mut Request, body: &mut DownstreamBody) -> Result<(), RequestPhase> {
    let span = flight.ctx.request_span.clone();
    match Box::pin(read_body(flight, request, body).instrument(span)).await {
        Ok(pre_read) => {
            apply_pre_read_mutations_to_request(request, &pre_read.mutations);
            flight.ctx.pre_read_mutations = pre_read.mutations;
            Ok(())
        },
        Err(PreReadEnd::Stop(PreReadStop::Rejected(refusal))) => {
            // The same proxy error as its streaming counterpart in the request
            // body phase, so it is counted the same way.
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
            Err(refuse(flight, request, refusal))
        },
        Err(PreReadEnd::Stop(PreReadStop::Filter(err))) => {
            error!(error = %err, "body filter error during pre-read");
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_INTERNAL);
            Err(refuse(flight, request, Rejection::status(500)))
        },
        Err(PreReadEnd::Client(failure)) => Err(client_failed(flight, request, &failure)),
    }
}

/// Feed the client's body to a pre-read pass until it ends.
async fn read_body(
    flight: &mut Flight,
    request: &Request,
    body: &mut DownstreamBody,
) -> Result<PreReadMutations, PreReadEnd> {
    let Some(mut pass) = PreReadPass::new(&flight.pipeline) else {
        return Ok(PreReadMutations { mutations: Vec::new() });
    };
    loop {
        let chunk = match body.next().await.map_err(PreReadEnd::Client)? {
            DownstreamFrame::Data(chunk) => Some(chunk),
            DownstreamFrame::Trailers(trailers) => {
                body.pre_read_trailers = Some(trailers);
                None
            },
            DownstreamFrame::End => None,
        };
        let ended = Box::pin(pass.feed(&flight.pipeline, &mut flight.ctx, request, chunk))
            .await
            .map_err(PreReadEnd::Stop)?;
        if ended {
            return Ok(pass.finish(&flight.pipeline, &mut flight.ctx));
        }
    }
}

/// Why a pre-read ended early.
enum PreReadEnd {
    /// The client stalled or went away.
    Client(Failure),

    /// A filter or the buffer stopped it.
    Stop(PreReadStop),
}

/// Answer a client that failed during the pre-read: a stalled upload is a
/// `408`, a client that went away a `499`, both counted as the client's
/// doing rather than a server error.
fn client_failed(flight: &mut Flight, request: &Request, failure: &Failure) -> RequestPhase {
    flight.ctx.stamp_error_type(metrics::ERROR_TYPE_DOWNSTREAM);
    flight.error = Some(failure.origin());
    if failure.kind == FailureKind::BadRequest {
        return bad_request(flight, request, failure);
    }
    let status = if failure.kind == FailureKind::DownstreamTimeout {
        408
    } else {
        499
    };
    debug!(error = %failure, status, "client disconnected during request body pre-read");
    refuse(flight, request, Rejection::status(status))
}

/// Answer a body that broke the framing rules with the proxy's structured
/// `400`, as the streamed body path and Pingora answer it.
fn bad_request(flight: &mut Flight, request: &Request, failure: &Failure) -> RequestPhase {
    debug!(error = %failure, "malformed request body during pre-read");
    flight.ctx.request_snapshot = Some(request.clone());
    let classified = failure.classified();
    RequestPhase::Reply(reply::classified_error(&classified, &flight.ctx, flight.version))
}

/// Turn the request pipeline's result into the request phase's ending.
async fn outcome(flight: &mut Flight, result: Result<PipelineResult, praxis_filter::FilterError>) -> RequestPhase {
    match result.map(|result| result.action) {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => RequestPhase::Proxy,
        Ok(FilterAction::Reject(refusal)) => {
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_FILTER_REJECT);
            RequestPhase::Reply(reply::rejection(refusal, &flight.ctx, flight.version))
        },
        Ok(FilterAction::TerminalResponse(terminal)) => {
            RequestPhase::Reply(Box::pin(reply::terminal(flight, *terminal)).await)
        },
        Ok(FilterAction::StreamingTerminalResponse(terminal)) => RequestPhase::Stream(terminal),
        Err(err) => {
            error!(error = %err, "filter pipeline error");
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_INTERNAL);
            RequestPhase::Reply(reply::rejection(Rejection::status(500), &flight.ctx, flight.version))
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
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::{
        net::IpAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use bytes::Bytes;
    use http::{Method, StatusCode, Version};
    use praxis_filter::{FilterPipeline, TerminalResponse};

    use super::*;
    use crate::http::{
        hyper::test_utils::{
            BodyHook, Client, Pull, Script, Source, client_request, empty_pipeline, scripted_pipeline,
        },
        pingora::handler::health_util::ErrorOrigin,
    };

    #[tokio::test]
    async fn refused_head_is_answered_before_the_pipeline_runs() {
        let mut flight = Flight::for_tests(rejecting_pipeline(403));
        let (mut body, _client) = bodiless().await;

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::CONNECT, "/"),
            &mut body,
        )
        .await;

        let reply = local_reply(phase).expect("a refused head is answered locally");
        assert_eq!(reply.status, 400, "the head is refused, not the pipeline's 403");
        assert_eq!(
            flight.ctx.request_snapshot.as_ref().map(|request| &request.method),
            Some(&Method::CONNECT),
            "the refused request is recorded for the access record"
        );
        assert_eq!(
            flight.ctx.client_addr,
            Some("10.0.0.7".parse::<IpAddr>().unwrap()),
            "the client address is recorded too"
        );
    }

    #[tokio::test]
    async fn zero_max_forwards_is_answered_without_the_pipeline() {
        let mut flight = Flight::for_tests(rejecting_pipeline(403));
        let (mut body, _client) = bodiless().await;
        let mut parts = head(Method::OPTIONS, "/");
        parts.headers.insert("max-forwards", "0".parse().unwrap());

        let phase = run(&mut flight, &facts("10.0.0.7:4000", false), parts, &mut body).await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::OK),
            "OPTIONS with Max-Forwards 0 is answered here"
        );
        assert!(
            flight.ctx.request_snapshot.is_some(),
            "the answered request is recorded"
        );
    }

    #[test]
    fn early_exit_keeps_what_was_already_recorded() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_snapshot = Some(Request {
            method: Method::GET,
            uri: "/first".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        flight.ctx.client_addr = Some("192.0.2.1".parse().unwrap());

        early_exit(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::POST, "/second"),
        );

        assert_eq!(
            flight.ctx.request_snapshot.as_ref().map(|request| request.uri.path()),
            Some("/first"),
            "an earlier snapshot is not replaced"
        );
        assert_eq!(
            flight.ctx.client_addr,
            Some("192.0.2.1".parse::<IpAddr>().unwrap()),
            "an earlier client address is not replaced"
        );
    }

    #[test]
    fn capture_client_unmaps_an_ipv4_mapped_peer() {
        let mut flight = Flight::for_tests(empty_pipeline());

        let _request = capture_client(
            &mut flight,
            &facts("[::ffff:10.1.2.3]:443", false),
            head(Method::GET, "/"),
        );

        assert_eq!(
            flight.ctx.client_addr,
            Some("10.1.2.3".parse::<IpAddr>().unwrap()),
            "a dual-stack socket's mapped address is the IPv4 client"
        );
    }

    #[test]
    fn capture_client_records_the_transport_and_version() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let mut parts = head(Method::GET, "/");
        parts.version = Version::HTTP_2;

        let _request = capture_client(&mut flight, &facts("[2001:db8::1]:443", true), parts);

        assert!(flight.ctx.downstream_tls, "the connection's TLS reaches the filters");
        assert_eq!(
            flight.ctx.client_http_version,
            Some(Version::HTTP_2),
            "the client's HTTP version is recorded"
        );
        assert_eq!(
            flight.ctx.client_addr,
            Some("2001:db8::1".parse::<IpAddr>().unwrap()),
            "a native IPv6 client is kept as is"
        );
    }

    #[test]
    fn only_safe_methods_are_idempotent() {
        for (method, idempotent) in [
            (Method::GET, true),
            (Method::HEAD, true),
            (Method::OPTIONS, true),
            (Method::POST, false),
            (Method::PUT, false),
            (Method::DELETE, false),
            (Method::PATCH, false),
        ] {
            let mut flight = Flight::for_tests(empty_pipeline());

            let _request = capture_client(&mut flight, &facts("10.0.0.7:4000", false), head(method.clone(), "/"));

            assert_eq!(
                flight.ctx.request_is_idempotent, idempotent,
                "{method} idempotency as the retry policy reads it"
            );
        }
    }

    #[test]
    fn capture_client_seeds_the_body_modes_from_the_pipeline() {
        let buffered = (BodyMode::StreamBuffer { max_bytes: Some(64) }, pass_body());
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_body: Some(buffered.clone()),
            response_body: Some(buffered),
            ..Script::default()
        }));

        let _request = capture_client(&mut flight, &facts("10.0.0.7:4000", false), head(Method::POST, "/"));

        assert!(
            matches!(
                flight.ctx.request_body_mode,
                BodyMode::StreamBuffer { max_bytes: Some(64) }
            ),
            "the request body mode comes from the pipeline"
        );
        assert!(
            matches!(
                flight.ctx.response_body_mode,
                BodyMode::StreamBuffer { max_bytes: Some(64) }
            ),
            "the response body mode comes from the pipeline"
        );
    }

    #[test]
    fn capture_client_hands_the_head_to_the_pipeline() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let mut parts = head(Method::PUT, "/items/7?full=1");
        parts.headers.insert("x-trace", "abc".parse().unwrap());

        let request = capture_client(&mut flight, &facts("10.0.0.7:4000", false), parts);

        assert_eq!(request.method, Method::PUT, "the method is kept");
        assert_eq!(request.uri, "/items/7?full=1", "the target is kept");
        assert_eq!(request.headers.get("x-trace").unwrap(), "abc", "the headers are kept");
    }

    #[tokio::test]
    async fn head_phase_rejection_is_answered_and_counted() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_head: Some(Arc::new(|| Ok(FilterAction::Reject(Rejection::status(451))))),
            ..Script::default()
        }));
        let (mut body, _client) = bodiless().await;

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::GET, "/"),
            &mut body,
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status.as_u16()),
            Some(451),
            "the request-head filter's status is the answer"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_FILTER_REJECT),
            "it is counted as a filter rejection"
        );
        assert!(
            flight.ctx.request_snapshot.is_some(),
            "the rejected request is recorded"
        );
    }

    #[tokio::test]
    async fn head_phase_error_is_an_internal_error() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_head: Some(Arc::new(|| Err("head filter broke".into()))),
            ..Script::default()
        }));
        let (mut body, _client) = bodiless().await;

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::GET, "/"),
            &mut body,
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "a failing request-head filter is a 500"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_INTERNAL),
            "it is counted as an internal error"
        );
    }

    #[tokio::test]
    async fn stream_buffer_reads_the_whole_body_before_the_pipeline() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let hook: BodyHook = Arc::new(move |body, end_of_stream| {
            recorded.lock().unwrap().push((body.clone(), end_of_stream));
            Ok(FilterAction::Continue)
        });
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_body: Some((BodyMode::StreamBuffer { max_bytes: Some(1024) }, hook)),
            ..Script::default()
        }));
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\n\r\nhello").await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::POST, "/"),
            &mut body,
        )
        .await;

        assert!(matches!(phase, RequestPhase::Proxy), "the request is then proxied");
        assert!(body.is_done(), "the client's body was read before the pipeline ran");
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|(body, end)| *end && body.as_deref() == Some(b"hello".as_slice())),
            "the body filter saw the whole body at its end: {seen:?}"
        );
    }

    #[tokio::test]
    async fn stream_buffer_rejection_is_answered_and_counted() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_body: Some((
                BodyMode::StreamBuffer { max_bytes: Some(1024) },
                Arc::new(|_body, _end| Ok(FilterAction::Reject(Rejection::status(422)))),
            )),
            ..Script::default()
        }));
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\n\r\nhello").await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::POST, "/"),
            &mut body,
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status.as_u16()),
            Some(422),
            "the body filter's rejection is the answer"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_FILTER_REJECT),
            "it is counted as a filter rejection"
        );
    }

    #[tokio::test]
    async fn stream_buffer_filter_error_is_an_internal_error() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_body: Some((
                BodyMode::StreamBuffer { max_bytes: Some(1024) },
                Arc::new(|_body, _end| Err("body filter broke".into())),
            )),
            ..Script::default()
        }));
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\n\r\nhello").await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::POST, "/"),
            &mut body,
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "a failing body filter during the pre-read is a 500"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_INTERNAL),
            "it is counted as an internal error"
        );
    }

    #[tokio::test]
    async fn client_stalling_during_the_pre_read_gets_a_408() {
        let mut flight = Flight::for_tests(scripted_pipeline(Script {
            request_body: Some((BodyMode::StreamBuffer { max_bytes: Some(1024) }, pass_body())),
            ..Script::default()
        }));
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 10\r\n\r\nabc").await;
        let mut body = DownstreamBody::new(request.into_body(), Some(Duration::from_millis(50)));

        let phase = run(
            &mut flight,
            &facts("10.0.0.7:4000", false),
            head(Method::POST, "/"),
            &mut body,
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::REQUEST_TIMEOUT),
            "a stalled upload is a 408"
        );
        assert_eq!(
            flight.error,
            Some(ErrorOrigin::Downstream),
            "the stall is the client's doing"
        );
    }

    #[test]
    fn client_timeout_is_a_408() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let failure = Failure::downstream(FailureKind::DownstreamTimeout, "client stalled");

        let phase = client_failed(&mut flight, &request(), &failure);

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::REQUEST_TIMEOUT),
            "a client that stalled gets a 408"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_DOWNSTREAM),
            "it is counted as a downstream error"
        );
        assert_eq!(flight.error, Some(ErrorOrigin::Downstream), "the client caused it");
    }

    #[test]
    fn client_that_went_away_is_a_499() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let failure = Failure::downstream(FailureKind::DownstreamClosed, "client hung up");

        let phase = client_failed(&mut flight, &request(), &failure);

        assert_eq!(
            local_reply(phase).map(|reply| reply.status.as_u16()),
            Some(499),
            "a client that hung up is recorded as a 499"
        );
        assert_eq!(flight.error, Some(ErrorOrigin::Downstream), "the client caused it");
    }

    #[test]
    fn malformed_client_body_is_the_structured_400() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let failure = Failure::downstream(FailureKind::BadRequest, "bad chunk size");

        let phase = client_failed(&mut flight, &request(), &failure);

        let reply = local_reply(phase).expect("a malformed body is answered");
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "the framing error is a 400");
        assert_eq!(
            reply.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/problem+json",
            "the 400 carries the proxy's problem document"
        );
        assert!(
            reply
                .body
                .as_ref()
                .is_some_and(|body| String::from_utf8_lossy(body).contains("\"status\":400")),
            "the document names the status: {reply:?}"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_DOWNSTREAM),
            "it is counted as a downstream error"
        );
        assert!(
            flight.ctx.request_snapshot.is_some(),
            "the request is recorded for the access record"
        );
    }

    #[tokio::test]
    async fn pipeline_actions_that_go_on_proxy_the_request() {
        for action in [FilterAction::Continue, FilterAction::Release, FilterAction::BodyDone] {
            let mut flight = Flight::for_tests(empty_pipeline());
            let named = format!("{action:?}");

            let phase = outcome(&mut flight, Ok(pipeline_result(action))).await;

            assert!(matches!(phase, RequestPhase::Proxy), "{named} forwards the request");
        }
    }

    #[tokio::test]
    async fn pipeline_rejection_is_answered_and_counted() {
        let mut flight = Flight::for_tests(empty_pipeline());

        let phase = outcome(
            &mut flight,
            Ok(pipeline_result(FilterAction::Reject(Rejection::status(403)))),
        )
        .await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::FORBIDDEN),
            "the rejection's status is the answer"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_FILTER_REJECT),
            "it is counted as a filter rejection"
        );
    }

    #[tokio::test]
    async fn terminal_response_is_answered_locally() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_snapshot = Some(request());
        let mut terminal = TerminalResponse::new(201);
        terminal.body = Some(Bytes::from_static(b"made"));

        let phase = outcome(
            &mut flight,
            Ok(pipeline_result(FilterAction::TerminalResponse(Box::new(terminal)))),
        )
        .await;

        let reply = local_reply(phase).expect("a terminal response is answered locally");
        assert_eq!(reply.status, StatusCode::CREATED, "with its own status");
        assert_eq!(reply.body.as_deref(), Some(b"made".as_slice()), "and its own body");
        assert!(reply.keepalive, "a real response keeps the connection");
    }

    #[tokio::test]
    async fn streaming_terminal_response_is_streamed() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (source, _calls) = Source::new(&[Pull::End]);
        let terminal = StreamingTerminalResponse::new(200, Box::new(source));

        let phase = outcome(
            &mut flight,
            Ok(pipeline_result(FilterAction::StreamingTerminalResponse(Box::new(
                terminal,
            )))),
        )
        .await;

        assert!(
            matches!(phase, RequestPhase::Stream(terminal) if terminal.status == 200),
            "a streaming terminal response goes to the streaming path"
        );
    }

    #[tokio::test]
    async fn pipeline_error_is_an_internal_error() {
        let mut flight = Flight::for_tests(empty_pipeline());

        let phase = outcome(&mut flight, Err("pipeline broke".into())).await;

        assert_eq!(
            local_reply(phase).map(|reply| reply.status),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "a failing pipeline is a 500"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_INTERNAL),
            "it is counted as an internal error"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The body of a bodiless `GET`, with the client side of its request.
    async fn bodiless() -> (DownstreamBody, Client) {
        let (request, client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
        (DownstreamBody::new(request.into_body(), None), client)
    }

    /// The facts of a connection from `peer`.
    fn facts(peer: &str, tls: bool) -> ConnectionFacts {
        ConnectionFacts {
            peer: peer.parse().unwrap(),
            tls,
        }
    }

    /// A request head for `method` to `target` with a `Host`.
    fn head(method: Method, target: &str) -> Parts {
        http::Request::builder()
            .method(method)
            .uri(target)
            .header(http::header::HOST, "a.example")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    /// A body hook that lets every chunk through.
    fn pass_body() -> BodyHook {
        Arc::new(|_body, _end| Ok(FilterAction::Continue))
    }

    /// A pipeline result carrying `action` and no header changes.
    fn pipeline_result(action: FilterAction) -> PipelineResult {
        PipelineResult {
            action,
            extra_headers: Vec::new(),
            headers_to_remove: Vec::new(),
            headers_to_set: Vec::new(),
        }
    }

    /// A pipeline whose request phase rejects with `status`.
    fn rejecting_pipeline(status: u16) -> FilterPipeline {
        scripted_pipeline(Script {
            request: Some(Arc::new(move || Ok(FilterAction::Reject(Rejection::status(status))))),
            ..Script::default()
        })
    }

    /// The local answer `phase` ended with, if it ended with one.
    fn local_reply(phase: RequestPhase) -> Option<LocalReply> {
        match phase {
            RequestPhase::Reply(reply) => Some(reply),
            RequestPhase::Proxy | RequestPhase::Stream(_) => None,
        }
    }

    /// The pipeline's view of a `GET /`.
    fn request() -> Request {
        Request {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
        }
    }
}
