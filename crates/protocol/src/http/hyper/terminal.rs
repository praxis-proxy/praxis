// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Streaming terminal responses produced by a filter.
//!
//! Mirrors the Pingora handler's `run_streaming_terminal_response`: the
//! response filters run on the head, a bodyless response suppresses the
//! source, and otherwise the head is committed and the source's chunks are
//! pulled one at a time through the response body filters into a relayed
//! body until the source ends, fails, or the client goes away. The source
//! and the request context trade request extensions at the same points as
//! on Pingora.

use http::{Response, StatusCode, Version};
use praxis_filter::{
    BodyMode, ClientResponseHeadersCommitted, Rejection, StreamingResponseBody, StreamingTerminalResponse,
};
use tracing::{Instrument as _, debug, error, warn};

use super::{
    body::{ProxyBody, Relay},
    reply::{self, LocalReply},
    service::Flight,
};
use crate::http::pingora::handler::request_filter::terminal_responses::{
    prepare_streaming_headers, prepare_terminal_response, run_parent_terminal_body_filters,
    streaming_size_limit_exceeded,
};

/// Mark an HTTP/1 connection for close when the process is draining.
///
/// Matches [`Flight::local_response`] so a streaming terminal response cannot
/// keep a connection alive past the listener's graceful shutdown.
///
/// [`Flight::local_response`]: Flight::local_response
fn add_drain_connection_close(flight: &Flight, headers: &mut http::HeaderMap) {
    if flight.version != Version::HTTP_2 && flight.lifecycle.phase() == praxis_core::server::LifecyclePhase::Draining {
        headers.insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
    }
}

// -----------------------------------------------------------------------------
// Streaming Terminal Responses
// -----------------------------------------------------------------------------

/// Answer the request with a filter's streaming terminal response.
pub(super) async fn stream(mut flight: Flight, terminal: StreamingTerminalResponse) -> Response<ProxyBody> {
    let StreamingTerminalResponse {
        status,
        headers,
        body: mut source,
    } = terminal;
    match Box::pin(prepare(&mut flight, source.as_mut(), status, headers)).await {
        Prepared::Reply(reply) => {
            source.cancel().await;
            flight.reply(reply).await
        },
        Prepared::Bodyless(response) => bodyless(flight, source.as_mut(), response).await,
        Prepared::Stream(response) => commit(flight, source, response),
    }
}

/// What the response phase made of a streaming terminal response.
enum Prepared {
    /// Answer with this instead; the source is cancelled.
    Reply(LocalReply),

    /// A `HEAD` or body-prohibited response: suppress the source.
    Bodyless(praxis_filter::Response),

    /// Commit the head and stream the source.
    Stream(praxis_filter::Response),
}

/// Run the response filters on the head and decide how it is delivered.
async fn prepare(
    flight: &mut Flight,
    source: &mut dyn StreamingResponseBody,
    status: u16,
    headers: http::HeaderMap,
) -> Prepared {
    source.swap_extensions(&mut flight.ctx.extensions);
    let prepared = Box::pin(prepare_terminal_response(
        &flight.pipeline,
        &mut flight.ctx,
        status,
        headers,
    ))
    .await;
    let response = match prepared {
        Ok(response) => response,
        Err(refusal) => return Prepared::Reply(reply::rejection(refusal, &flight.ctx, flight.version)),
    };
    source.swap_extensions(&mut flight.ctx.extensions);
    route(flight, source, response)
}

/// Decide how a filtered streaming head is delivered.
fn route(flight: &mut Flight, source: &mut dyn StreamingResponseBody, response: praxis_filter::Response) -> Prepared {
    if matches!(flight.ctx.response_body_mode, BodyMode::StreamBuffer { .. }) {
        error!("streaming terminal response is incompatible with StreamBuffer response mode");
        source.swap_extensions(&mut flight.ctx.extensions);
        return Prepared::Reply(reply::rejection(Rejection::status(500), &flight.ctx, flight.version));
    }
    if flight.is_head() || matches!(response.status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
        return Prepared::Bodyless(response);
    }
    if !(200..=599).contains(&response.status.as_u16()) {
        warn!(
            status = response.status.as_u16(),
            "streaming terminal response status outside 200..=599; sending 500"
        );
        source.swap_extensions(&mut flight.ctx.extensions);
        return Prepared::Reply(reply::rejection(Rejection::status(500), &flight.ctx, flight.version));
    }
    Prepared::Stream(response)
}

/// Suppress the source of a bodyless response and answer with its head.
async fn bodyless(
    mut flight: Flight,
    source: &mut dyn StreamingResponseBody,
    mut response: praxis_filter::Response,
) -> Response<ProxyBody> {
    if let Err(err) = source.suppress().await {
        error!(error = %err, "failed to suppress streaming terminal response");
        source.cancel().await;
        let refusal = reply::rejection(Rejection::status(500), &flight.ctx, flight.version);
        return flight.reply(refusal).await;
    }
    flight.ctx.response_delivery_complete = true;
    let is_head = flight.is_head();
    let is_not_modified = response.status == StatusCode::NOT_MODIFIED;
    prepare_streaming_headers(&mut response, is_head, is_not_modified, Version::HTTP_10);
    add_drain_connection_close(&flight, &mut response.headers);
    if !(200..=599).contains(&response.status.as_u16()) {
        source.cancel().await;
        let refusal = reply::rejection(Rejection::status(500), &flight.ctx, flight.version);
        return flight.reply(refusal).await;
    }
    source.swap_extensions(&mut flight.ctx.extensions);
    flight.ctx.extensions.insert(ClientResponseHeadersCommitted);
    let reply = LocalReply {
        body: None,
        body_suppressed: true,
        headers: response.headers,
        keepalive: true,
        status: response.status,
    };
    flight.reply(reply).await
}

/// Commit the head and spawn the task that streams the source.
fn commit(
    mut flight: Flight,
    mut source: Box<dyn StreamingResponseBody>,
    mut response: praxis_filter::Response,
) -> Response<ProxyBody> {
    let version = flight.version;
    prepare_streaming_headers(&mut response, false, false, version);
    add_drain_connection_close(&flight, &mut response.headers);
    // The status is fixed from here even if the first pull fails; the
    // source sees that before its next step runs.
    source.swap_extensions(&mut flight.ctx.extensions);
    flight.ctx.extensions.insert(ClientResponseHeadersCommitted);
    source.swap_extensions(&mut flight.ctx.extensions);

    // Body filters with response conditions read the committed head; only
    // then is a copy of its headers kept for them.
    let head = praxis_filter::Response {
        headers: if flight.pipeline.body_capabilities().any_response_body_condition {
            response.headers.clone()
        } else {
            http::HeaderMap::new()
        },
        status: response.status,
    };
    let (relay, body) = Relay::new();
    let mut committed = Response::new(body);
    *committed.status_mut() = response.status;
    *committed.headers_mut() = response.headers;
    flight.written_status = response.status.as_u16();
    let span = flight.ctx.request_span.clone();
    drop(tokio::spawn(pump(flight, source, relay, head).instrument(span)));
    committed
}

/// Pull the source through the response body filters into the relay, then
/// complete the request.
async fn pump(
    mut flight: Flight,
    mut source: Box<dyn StreamingResponseBody>,
    relay: Relay,
    head: praxis_filter::Response,
) {
    loop {
        let pulled = tokio::select! {
            pulled = source.next_chunk() => Some(pulled),
            () = relay.closed() => None,
        };
        let step = match pulled {
            None => {
                debug!("downstream disconnected while terminal stream source was pending");
                flight.error = Some(crate::http::pingora::handler::health_util::ErrorOrigin::Downstream);
                source.swap_extensions(&mut flight.ctx.extensions);
                Step::Cancel
            },
            Some(pulled) => Box::pin(deliver(&mut flight, source.as_mut(), &relay, &head, pulled)).await,
        };
        match step {
            Step::Next => {},
            Step::Done => break,
            Step::Cancel => {
                source.cancel().await;
                if flight.error.is_none() {
                    relay.flushed().await;
                }
                break;
            },
        }
    }
    drop(relay);
    flight.complete().await;
}

/// What the stream does after one pull.
enum Step {
    /// Pull again.
    Next,

    /// The body ended; the relay was ended.
    Done,

    /// Stop and cancel the source; the response is aborted.
    Cancel,
}

/// Deliver one pull's result to the client.
async fn deliver(
    flight: &mut Flight,
    source: &mut dyn StreamingResponseBody,
    relay: &Relay,
    head: &praxis_filter::Response,
    pulled: Result<Option<bytes::Bytes>, praxis_filter::FilterError>,
) -> Step {
    source.swap_extensions(&mut flight.ctx.extensions);
    match pulled {
        Ok(Some(chunk)) => send_chunk(flight, source, relay, head, chunk).await,
        // Keep recovered extensions on the flight at EOF or cancellation.
        Ok(None) => finish(flight, relay, head).await,
        Err(err) => {
            warn!(error = %err, "streaming terminal response source failed after commitment");
            Step::Cancel
        },
    }
}

/// Filter one chunk, write it, and settle the download grant from that write.
///
/// On success the source takes the extensions back. On a failed write they
/// stay on the flight, with the grant already refunded, for request cleanup.
async fn send_chunk(
    flight: &mut Flight,
    source: &mut dyn StreamingResponseBody,
    relay: &Relay,
    head: &praxis_filter::Response,
    chunk: bytes::Bytes,
) -> Step {
    let mut body = Some(chunk);
    if run_parent_terminal_body_filters(&flight.pipeline, &mut flight.ctx, head, &mut body, false).is_err()
        || streaming_size_limit_exceeded(&flight.ctx, &flight.pipeline)
    {
        return Step::Cancel;
    }
    let wrote = super::stream::write_paced(relay, flight, body.unwrap_or_default())
        .await
        .is_ok();
    if !wrote {
        debug!("failed to write streaming terminal response body");
        flight.error = Some(crate::http::pingora::handler::health_util::ErrorOrigin::Downstream);
        return Step::Cancel;
    }
    source.swap_extensions(&mut flight.ctx.extensions);
    Step::Next
}

/// Run the end-of-stream body filters and end the relayed body.
async fn finish(flight: &mut Flight, relay: &Relay, head: &praxis_filter::Response) -> Step {
    let mut last = None;
    if run_parent_terminal_body_filters(&flight.pipeline, &mut flight.ctx, head, &mut last, true).is_err() {
        return Step::Cancel;
    }
    let wrote = if let Some(chunk) = last {
        super::stream::write_paced(relay, flight, chunk).await.is_ok()
    } else {
        true
    };
    if !wrote || relay.end().await.is_err() {
        debug!("failed to finish streaming terminal response");
        flight.error = Some(crate::http::pingora::handler::health_util::ErrorOrigin::Downstream);
        return Step::Cancel;
    }
    Step::Done
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
        sync::{Arc, Mutex},
        time::Duration,
    };

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use http_body_util::BodyExt as _;
    use hyper::body::Body as _;
    use praxis_filter::{
        BodyAccess, BodyRequirement, FilterAction, FilterEntry, FilterError, FilterFactory, FilterPipeline,
        FilterRegistry, HttpFilter, HttpFilterContext, RequestExtensions,
    };

    use super::*;
    use crate::http::hyper::test_utils::{Pull, Script, Source, empty_pipeline, scripted_pipeline};

    /// EOF completion observations: extension writeback and client classification.
    type EofCompletions = Arc<Mutex<Vec<(bool, bool)>>>;

    #[tokio::test]
    async fn chunks_are_pulled_in_order_until_the_end() {
        let (source, calls) = Source::new(&[Pull::Chunk("a"), Pull::Chunk("b"), Pull::End]);

        let response = stream(get_flight(empty_pipeline()), terminal(200, source)).await;

        assert_eq!(response.status(), StatusCode::OK, "the source's status is committed");
        let (body, aborted) = read_body(response.into_body()).await;
        assert_eq!(body, b"ab", "every chunk reaches the client in order");
        assert!(!aborted, "the body ends cleanly");
        assert_eq!(
            *calls.lock().unwrap(),
            ["pull", "pull", "pull"],
            "one pull per chunk and the end"
        );
    }

    #[tokio::test]
    async fn http11_stream_is_chunked_and_http2_is_not() {
        let (http11_source, _calls) = Source::new(&[Pull::End]);
        let (http2_source, _calls) = Source::new(&[Pull::End]);
        let mut http2 = get_flight(empty_pipeline());
        http2.version = Version::HTTP_2;

        let http11_response = stream(get_flight(empty_pipeline()), terminal(200, http11_source)).await;
        let http2_response = stream(http2, terminal(200, http2_source)).await;

        assert_eq!(
            http11_response.headers().get(http::header::TRANSFER_ENCODING).unwrap(),
            "chunked",
            "an HTTP/1.1 client gets a chunked stream of unknown length"
        );
        assert!(
            http2_response.headers().get(http::header::TRANSFER_ENCODING).is_none(),
            "HTTP/2 frames the stream itself"
        );
    }

    #[tokio::test]
    async fn draining_stream_closes_an_http1_connection() {
        let flight = get_flight(empty_pipeline());
        assert!(flight.lifecycle.begin_drain());
        let (source, _calls) = Source::new(&[Pull::End]);

        let response = stream(flight, terminal(200, source)).await;

        assert_eq!(
            response.headers().get(http::header::CONNECTION),
            Some(&HeaderValue::from_static("close")),
            "a streaming terminal response must not keep an HTTP/1 connection alive during drain"
        );
    }

    #[tokio::test]
    async fn draining_stream_never_names_the_connection_on_http2() {
        let mut flight = get_flight(empty_pipeline());
        flight.version = Version::HTTP_2;
        assert!(flight.lifecycle.begin_drain());
        let (source, _calls) = Source::new(&[Pull::End]);

        let response = stream(flight, terminal(200, source)).await;

        assert!(
            response.headers().get(http::header::CONNECTION).is_none(),
            "HTTP/2 forbids the Connection header"
        );
    }

    #[tokio::test]
    async fn rejecting_response_filter_answers_instead_and_cancels_the_source() {
        let pipeline = scripted_pipeline(Script {
            response: Some(Arc::new(|| Ok(FilterAction::Reject(Rejection::status(401))))),
            ..Script::default()
        });
        let (source, calls) = Source::new(&[Pull::Chunk("never")]);

        let response = stream(get_flight(pipeline), terminal(200, source)).await;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the response filter's rejection is the answer"
        );
        assert_eq!(*calls.lock().unwrap(), ["cancel"], "the source is cancelled unread");
    }

    #[tokio::test]
    async fn head_request_suppresses_the_source() {
        let mut flight = get_flight(empty_pipeline());
        flight.method = Method::HEAD;
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        let (source, calls) = Source::new(&[Pull::Chunk("never")]);

        let response = stream(flight, terminal(200, source).with_headers(headers)).await;

        assert_eq!(response.status(), StatusCode::OK, "the head is answered");
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH).unwrap(),
            "5",
            "a HEAD keeps the length the GET would have had"
        );
        assert!(response.body().is_end_stream(), "no body follows a HEAD");
        assert_eq!(
            *calls.lock().unwrap(),
            ["suppress"],
            "the source is suppressed, not pulled"
        );
    }

    #[tokio::test]
    async fn no_content_suppresses_the_source() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        let (source, calls) = Source::new(&[Pull::Chunk("never")]);

        let response = stream(
            get_flight(empty_pipeline()),
            terminal(204, source).with_headers(headers),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT, "the 204 is answered");
        assert!(
            response.headers().get(http::header::CONTENT_LENGTH).is_none(),
            "a 204 carries no length"
        );
        assert!(response.body().is_end_stream(), "a 204 has no body");
        assert_eq!(
            *calls.lock().unwrap(),
            ["suppress"],
            "the source is suppressed, not pulled"
        );
    }

    #[tokio::test]
    async fn failed_suppression_cancels_the_source_and_answers_500() {
        let mut flight = get_flight(empty_pipeline());
        flight.method = Method::HEAD;
        let (source, calls) = Source::new(&[]);

        let response = stream(flight, terminal(200, source.failing_suppression())).await;

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a source that cannot be suppressed is a 500"
        );
        assert_eq!(
            *calls.lock().unwrap(),
            ["suppress", "cancel"],
            "the source is cancelled after the failed suppression"
        );
    }

    #[tokio::test]
    async fn stream_buffer_response_mode_is_refused() {
        let mut flight = get_flight(empty_pipeline());
        flight.ctx.response_body_mode = BodyMode::StreamBuffer { max_bytes: None };
        let (source, calls) = Source::new(&[Pull::Chunk("never")]);

        let response = stream(flight, terminal(200, source)).await;

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a stream cannot be buffered for inspection"
        );
        assert_eq!(*calls.lock().unwrap(), ["cancel"], "the source is cancelled unread");
    }

    #[tokio::test]
    async fn status_outside_the_final_range_is_a_500() {
        let (source, calls) = Source::new(&[Pull::Chunk("never")]);
        let interim = StreamingTerminalResponse {
            status: 150,
            headers: HeaderMap::new(),
            body: Box::new(source),
        };

        let response = stream(get_flight(empty_pipeline()), interim).await;

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a non-final status cannot end the request"
        );
        assert_eq!(*calls.lock().unwrap(), ["cancel"], "the source is cancelled unread");
    }

    #[tokio::test]
    async fn source_failure_after_the_commit_aborts_the_body() {
        let (source, calls) = Source::new(&[Pull::Chunk("a"), Pull::Fail]);

        let response = stream(get_flight(empty_pipeline()), terminal(200, source)).await;

        assert_eq!(response.status(), StatusCode::OK, "the head was already committed");
        let (body, aborted) = read_body(response.into_body()).await;
        assert_eq!(body, b"a", "what was pulled before the failure is delivered");
        assert!(aborted, "the failure aborts the body rather than ending it");
        assert_eq!(
            *calls.lock().unwrap(),
            ["pull", "pull", "cancel"],
            "and cancels the source"
        );
    }

    #[tokio::test]
    async fn body_filter_error_mid_stream_aborts_the_body() {
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|body, _end| {
                    if body.as_deref() == Some(b"b".as_slice()) {
                        return Err("body filter broke".into());
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        });
        let (source, calls) = Source::new(&[Pull::Chunk("a"), Pull::Chunk("b"), Pull::Chunk("c")]);

        let response = stream(get_flight(pipeline), terminal(200, source)).await;

        let (body, aborted) = read_body(response.into_body()).await;
        assert_eq!(body, b"a", "chunks before the failing one are delivered");
        assert!(aborted, "a failing body filter aborts the body");
        assert_eq!(
            *calls.lock().unwrap(),
            ["pull", "pull", "cancel"],
            "the source is cancelled and not pulled again"
        );
    }

    #[tokio::test]
    async fn response_size_limit_exceeded_mid_stream_aborts_the_body() {
        let mut pipeline = empty_pipeline();
        pipeline.apply_body_limits(None, Some(3), false).unwrap();
        let mut flight = get_flight(pipeline);
        flight.ctx.response_body_mode = flight.pipeline.body_capabilities().response_body_mode;
        let (source, calls) = Source::new(&[Pull::Chunk("ab"), Pull::Chunk("cd"), Pull::Chunk("ef")]);

        let response = stream(flight, terminal(200, source)).await;

        let (body, aborted) = read_body(response.into_body()).await;
        assert_eq!(body, b"ab", "chunks inside the limit are delivered");
        assert!(aborted, "the chunk that crosses the limit aborts the body");
        assert_eq!(
            *calls.lock().unwrap(),
            ["pull", "pull", "cancel"],
            "the source is cancelled once the limit is crossed"
        );
    }

    #[tokio::test]
    async fn end_of_stream_filters_add_to_the_end_of_the_body() {
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|body, end_of_stream| {
                    if end_of_stream {
                        *body = Some(Bytes::from_static(b"!"));
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        });
        let (source, _calls) = Source::new(&[Pull::Chunk("ab"), Pull::End]);

        let response = stream(get_flight(pipeline), terminal(200, source)).await;

        let (body, aborted) = read_body(response.into_body()).await;
        assert_eq!(body, b"ab!", "what the end-of-stream filters release comes last");
        assert!(!aborted, "and the body ends cleanly");
    }

    #[tokio::test]
    async fn final_terminal_send_failure_records_downstream_origin() {
        for suffix in [None, Some(Bytes::from_static(b"tail"))] {
            assert_failed_terminal_eof(suffix).await;
        }
        assert_successful_terminal_eof().await;
    }

    /// Build an EOF hook that can produce final body bytes.
    fn eof_suffix_pipeline(suffix: Option<Bytes>) -> FilterPipeline {
        scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(move |body, end_of_stream| {
                    if end_of_stream {
                        *body = suffix.clone();
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        })
    }

    /// A failed final send must cancel once and classify client departure.
    async fn assert_failed_terminal_eof(suffix: Option<Bytes>) {
        let mut flight = get_flight(eof_suffix_pipeline(suffix));
        let (mut source, calls) = Source::new(&[Pull::End]);
        let head = praxis_filter::Response {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        };
        let (relay, body) = Relay::new();
        drop(body);
        let step = deliver(&mut flight, &mut source, &relay, &head, Ok(None)).await;
        assert!(matches!(step, Step::Cancel), "failed EOF send must cancel the source");
        assert!(
            matches!(
                flight.error,
                Some(crate::http::pingora::handler::health_util::ErrorOrigin::Downstream)
            ),
            "failed EOF send must retain downstream origin"
        );
        source.cancel().await;
        flight.complete().await;
        assert!(
            flight.ctx.ended_by_client,
            "terminal completion must record client departure"
        );
        assert_eq!(*calls.lock().unwrap(), ["cancel"], "source cancellation happens once");
    }

    /// A successful EOF still delivers a clean empty body.
    async fn assert_successful_terminal_eof() {
        let mut flight = get_flight(empty_pipeline());
        let head = praxis_filter::Response {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        };
        let (relay, body) = Relay::new();
        let collecting = tokio::spawn(body.collect());
        let step = finish(&mut flight, &relay, &head).await;
        assert!(matches!(step, Step::Done), "a received EOF remains successful");
        let collected = collecting.await.unwrap().unwrap().to_bytes();
        assert!(collected.is_empty(), "successful EOF reaches the body");
    }

    #[tokio::test]
    async fn final_terminal_eof_preserves_extensions_through_pump_completion() {
        for (disconnect, reject, suffix) in [
            (false, false, None),
            (false, false, Some(Bytes::from_static(b"tail"))),
            (true, false, None),
            (true, false, Some(Bytes::from_static(b"tail"))),
            (false, true, None),
        ] {
            assert_eof_pump_case(disconnect, reject, suffix).await;
        }
    }

    /// Observable effects of one real EOF pump execution.
    struct EofPumpObservation {
        /// Source, EOF and completion hook order.
        events: Arc<Mutex<Vec<&'static str>>>,
        /// Completion state for extensions and client departure.
        completions: EofCompletions,
        /// Live downstream collector, absent when the client disconnects.
        collecting: Option<tokio::task::JoinHandle<(Vec<u8>, bool)>>,
    }

    /// Run the actual pump with the chosen EOF suffix, rejection and client state.
    async fn run_eof_pump_case(disconnect: bool, reject: bool, suffix: Option<Bytes>) -> EofPumpObservation {
        let events = Arc::new(Mutex::new(Vec::new()));
        let completions = Arc::new(Mutex::new(Vec::new()));
        let pipeline = eof_pipeline(reject, suffix, &events, &completions);
        let mut flight = get_flight(pipeline);
        // Keep response_phase_done unset to exercise the completion cleanup hook.
        flight.ctx.upstream_contacted = true;
        let (relay, body) = Relay::new();
        let (close_on_pull, collecting) = if disconnect {
            (Some(body), None)
        } else {
            (None, Some(tokio::spawn(read_body(body))))
        };
        let source = eof_source(close_on_pull, &events);
        let head = praxis_filter::Response {
            headers: HeaderMap::new(),
            status: StatusCode::OK,
        };
        tokio::time::timeout(Duration::from_secs(5), pump(flight, Box::new(source), relay, head))
            .await
            .expect("the EOF path must complete");
        EofPumpObservation {
            events,
            completions,
            collecting,
        }
    }

    /// Preserve every permutation's extension, event, abort and byte assertions.
    async fn assert_eof_pump_case(disconnect: bool, reject: bool, suffix: Option<Bytes>) {
        let EofPumpObservation {
            events,
            completions,
            collecting,
        } = run_eof_pump_case(disconnect, reject, suffix.clone()).await;
        assert_eq!(
            *completions.lock().unwrap(),
            [(true, !disconnect)],
            "completion sees the EOF filter's extensions and client classification exactly once"
        );
        let expected = if disconnect || reject {
            vec!["pull", "eof", "cancel", "complete"]
        } else {
            vec!["pull", "eof", "complete"]
        };
        assert_eq!(
            *events.lock().unwrap(),
            expected,
            "no duplicate pulls, cancellation or completion"
        );
        if let Some(collecting) = collecting {
            let (bytes, aborted) = collecting.await.unwrap();
            assert_eq!(aborted, reject, "only a rejected EOF aborts a live body");
            assert_eq!(bytes, suffix.unwrap_or_default(), "successful EOF bytes arrive intact");
        }
    }

    #[tokio::test]
    async fn client_leaving_while_a_pull_is_pending_cancels_the_source() {
        let (source, calls) = Source::new(&[Pull::Hang]);

        let response = stream(get_flight(empty_pipeline()), terminal(200, source)).await;
        let pulling = eventually_called(&calls, "pull").await;
        drop(response);
        let cancelled = eventually_called(&calls, "cancel").await;

        assert!(pulling, "the source is pulled once the head is committed");
        assert!(cancelled, "the source is cancelled once the client is gone");
        assert_eq!(*calls.lock().unwrap(), ["pull", "cancel"], "and is not pulled again");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A request extension changed by the EOF filter and consumed at completion.
    struct EofMarker(u8);

    /// A real extension owner that can close the receiver during its EOF pull.
    struct ExtensionSource {
        /// Dropping this inside the selected pull forces the EOF-send race.
        close_on_pull: Option<ProxyBody>,
        /// Ordered source, filter and completion lifecycle observations.
        events: Arc<Mutex<Vec<&'static str>>>,
        /// Parent state transferred by the same swap contract as real sources.
        extensions: RequestExtensions,
    }

    /// Give the EOF source its initial extension marker and event recorder.
    fn eof_source(close_on_pull: Option<ProxyBody>, events: &Arc<Mutex<Vec<&'static str>>>) -> ExtensionSource {
        let mut extensions = RequestExtensions::default();
        extensions.insert(EofMarker(7));
        ExtensionSource {
            close_on_pull,
            events: Arc::clone(events),
            extensions,
        }
    }

    #[async_trait::async_trait]
    impl StreamingResponseBody for ExtensionSource {
        async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
            self.events.lock().unwrap().push("pull");
            drop(self.close_on_pull.take());
            Ok(None)
        }

        async fn suppress(&mut self) -> Result<(), FilterError> {
            Err("the bodyful pump must not suppress its source".into())
        }

        async fn cancel(&mut self) {
            self.events.lock().unwrap().push("cancel");
        }

        fn swap_extensions(&mut self, extensions: &mut RequestExtensions) {
            std::mem::swap(&mut self.extensions, extensions);
        }
    }

    /// Records state visible to the actual pump's completion cleanup hook.
    struct EofObserver {
        /// Whether each completion saw EOF state and considered upstream reached.
        completions: EofCompletions,
        /// Source, EOF and completion event order.
        events: Arc<Mutex<Vec<&'static str>>>,
        /// Reject from the EOF hook when testing filter cancellation.
        reject: bool,
        /// Optional bytes generated at EOF.
        suffix: Option<Bytes>,
    }

    #[async_trait::async_trait]
    impl HttpFilter for EofObserver {
        fn name(&self) -> &'static str {
            "eof_observer"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.events.lock().unwrap().push("complete");
            self.completions.lock().unwrap().push((
                ctx.extensions.get::<EofMarker>().is_some_and(|marker| marker.0 == 11),
                ctx.upstream_reached,
            ));
            Ok(FilterAction::Continue)
        }

        fn response_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite(BodyRequirement::Optional)
        }

        fn on_response_body(
            &self,
            ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            assert!(end_of_stream, "this source yields only EOF");
            assert_eq!(
                ctx.extensions.get::<EofMarker>().unwrap().0,
                7,
                "source state reaches EOF"
            );
            self.events.lock().unwrap().push("eof");
            ctx.extensions.insert(EofMarker(11));
            *body = self.suffix.clone();
            if self.reject {
                return Err("EOF rejected".into());
            }
            Ok(FilterAction::Continue)
        }
    }

    /// Build a filter that observes EOF writeback during real pump completion.
    fn eof_pipeline(
        reject: bool,
        suffix: Option<Bytes>,
        events: &Arc<Mutex<Vec<&'static str>>>,
        completions: &EofCompletions,
    ) -> FilterPipeline {
        let events = Arc::clone(events);
        let completions = Arc::clone(completions);
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "eof_observer",
                FilterFactory::Http(Arc::new(move |_config| {
                    Ok(Box::new(EofObserver {
                        completions: Arc::clone(&completions),
                        events: Arc::clone(&events),
                        reject,
                        suffix: suffix.clone(),
                    }))
                })),
            )
            .unwrap();
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str("- filter: eof_observer").unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Wait up to five seconds for the source to be asked to `call`.
    async fn eventually_called(calls: &Arc<Mutex<Vec<&'static str>>>, call: &str) -> bool {
        for _poll in 0..1000 {
            if calls.lock().unwrap().contains(&call) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// A `GET` running `pipeline`, with its request recorded as the response
    /// filters need it.
    fn get_flight(pipeline: FilterPipeline) -> Flight {
        let mut flight = Flight::for_tests(pipeline);
        flight.ctx.request_snapshot = Some(praxis_filter::Request {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
        });
        flight
    }

    /// Read `body` to its end; the bytes, and whether it was aborted.
    async fn read_body(mut body: ProxyBody) -> (Vec<u8>, bool) {
        let mut bytes = Vec::new();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
                .await
                .expect("the body makes progress");
            match frame {
                None => return (bytes, false),
                Some(Err(_aborted)) => return (bytes, true),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        bytes.extend_from_slice(&data);
                    }
                },
            }
        }
    }

    /// A streaming terminal response with `status` over `source`.
    fn terminal(status: u16, source: Source) -> StreamingTerminalResponse {
        StreamingTerminalResponse::new(status, Box::new(source))
    }
}
