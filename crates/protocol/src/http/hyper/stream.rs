// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The upstream response body, relayed to the client.
//!
//! A committed response's body is relayed by its own task: each upstream
//! chunk runs through the response body filters (what the Pingora
//! handler's `response_body_filter` does) and waits for room in the
//! client's body, so a slow client slows the upstream reads. Trailers go
//! through the trailer hooks, and the end of the body through the
//! end-of-stream body filters. The rest of a request body the client is
//! still sending is forwarded in between, for bidirectional streams. When
//! the body ends, fails, or the client goes away, the task releases the
//! upstream connection and completes the request.

use std::time::Duration;

use bytes::Bytes;
use http::Version;
use praxis_core::egress::{
    Completion, Session as _,
    hyper::{HyperConnector, HyperSession},
};
use tokio::time::Instant;
use tracing::{debug, error};

use super::{
    body::Relay,
    downstream::DownstreamFrame,
    failure::Failure,
    service::Flight,
    upload::{Flush, Upload, UploadEnd},
    upstream::record_attempt_failure,
};
use crate::http::pingora::{
    handler::{
        health_util::ErrorOrigin, hop_by_hop::strip_reserved_internal_header_map,
        response_body_filter::run_response_body, response_trailer_filter, response_trailers,
    },
    metrics,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long the relay offers a queued request body chunk to the upstream
/// before it goes back to the response.
const UPLOAD_SLICE: Duration = Duration::from_millis(1); // 1 ms

/// How long the relay waits before offering a stuck request body again when
/// nothing else happens.
const UPLOAD_RETRY: Duration = Duration::from_millis(10); // 10 ms

// -----------------------------------------------------------------------------
// Relaying
// -----------------------------------------------------------------------------

/// Everything the relay task owns.
pub(super) struct Relaying {
    /// Where the upstream connection goes back to.
    pub(super) connector: HyperConnector,

    /// The request's state, completed when the relay ends.
    pub(super) flight: Flight,

    /// Bound on each read of the upstream body.
    pub(super) read_timeout: Option<Duration>,

    /// The client's body.
    pub(super) relay: Relay,

    /// The exchange the body comes from.
    pub(super) session: HyperSession,

    /// What the response phase already read of the body.
    pub(super) start: Start,

    /// The rest of the request body, if the client is still sending it.
    pub(super) upload: Upload,
}

/// What the response phase read of the body before committing the head.
///
/// Pingora writes a response head together with the body bytes that came
/// with it, so a body filter that fails on them still turns into an error
/// response; reading the first chunk before the commit keeps that.
#[derive(Debug)]
pub(super) enum Start {
    /// The first chunk, already through the body filters; `ends` when it
    /// was the whole body and the end-of-stream filters ran on it.
    Chunk {
        /// The filtered chunk, if the filters left one.
        body: Option<Bytes>,

        /// Whether the chunk ended the body.
        ends: bool,
    },

    /// The body ended before any chunk.
    Ended,

    /// Nothing read yet.
    Fresh,
}

impl Relaying {
    /// Filter one upstream chunk and hand it to the client.
    async fn deliver(&mut self, chunk: Bytes) -> Result<(), Ended> {
        let mut body = Some(chunk);
        run_response_body(&self.flight.pipeline, &mut body, false, &mut self.flight.ctx).map_err(Ended::Filter)?;
        match body {
            Some(chunk) => self.relay.data(chunk).await.map_err(|_gone| Ended::ClientGone),
            None => Ok(()),
        }
    }

    /// The upstream body ended after its last chunk: run the trailer hooks,
    /// then the end-of-stream body filters, and end the client's body.
    ///
    /// The trailer hooks come first, as on Pingora, so a filter that turns
    /// trailers into body bytes (gRPC-Web) has done so when the end of the
    /// body reaches it. Those bytes are final: they follow whatever the
    /// end-of-stream filters release, without passing through them.
    async fn deliver_end(&mut self) -> Ended {
        let (produced, trailers) = self.take_trailers();
        let mut body = None;
        if let Err(reason) = run_response_body(&self.flight.pipeline, &mut body, true, &mut self.flight.ctx) {
            return Ended::Filter(reason);
        }
        if let Some(chunk) = body
            && self.relay.data(chunk).await.is_err()
        {
            return Ended::ClientGone;
        }
        end_with(&self.relay, produced, trailers).await
    }

    /// The upstream body ended with `last`: run the end-of-stream body
    /// filters over it and end the client's body.
    async fn deliver_last(&mut self, last: Bytes) -> Ended {
        let mut body = Some(last);
        if let Err(reason) = run_response_body(&self.flight.pipeline, &mut body, true, &mut self.flight.ctx) {
            return Ended::Filter(reason);
        }
        end_with(&self.relay, body, None).await
    }

    /// Filter and queue one more frame of the client's body.
    async fn forward(&mut self, frame: Result<DownstreamFrame, Failure>) {
        let h2 = self.session.negotiated_version() == Version::HTTP_2;
        let accepted = Box::pin(self.upload.accept(&mut self.flight, frame, h2)).await;
        if let Err(end) = accepted {
            self.stop_upload(end);
        }
    }

    /// Wait for whatever happens next: the client leaving, an upstream
    /// chunk, a client body frame when nothing is queued for the upstream,
    /// or the time to offer the queued body again.
    ///
    /// `due` is when the awaited upstream chunk is overdue. It is kept
    /// across the turns spent offering the queued body again, so those do
    /// not restart the read timeout the way every other step does.
    async fn next_step(&mut self, due: &mut Option<Due>) -> Step {
        let queued = self.upload.has_outgoing();
        if due.is_none() {
            *due = self.read_timeout.and_then(Due::within);
        }
        let step = tokio::select! {
            biased;
            () = self.relay.closed() => Step::ClientGone,
            chunk = self.session.read_response_body() => Step::Upstream(chunk.map_err(|err| Failure::exchange(&err))),
            limit = overdue(*due) => Step::Upstream(Err(Failure::read_timeout(limit))),
            frame = self.upload.next_live(), if self.upload.is_live() && !queued => Step::Client(frame),
            () = tokio::time::sleep(UPLOAD_RETRY), if queued => Step::Retry,
        };
        if !matches!(step, Step::Retry) {
            *due = None;
        }
        step
    }

    /// Relay until the body ends, fails, or the client goes away.
    async fn pump(&mut self) -> Ended {
        if let Some(ended) = self.resume().await {
            return ended;
        }
        let mut due = None;
        loop {
            if self.upload.has_outgoing() && self.push_upload().await {
                due = None;
            }
            let step = Box::pin(self.next_step(&mut due)).await;
            if let Some(ended) = Box::pin(self.take_step(step)).await {
                return ended;
            }
        }
    }

    /// Hand what is queued of the client's body to the upstream, for as long
    /// as it keeps taking it; the response is relayed in between. Returns
    /// whether the upstream took any of it.
    async fn push_upload(&mut self) -> bool {
        match self.upload.flush(&mut self.session, UPLOAD_SLICE).await {
            Ok(Flush::Done | Flush::Taken) => true,
            Ok(Flush::Blocked) => false,
            Err(end) => {
                self.stop_upload(end);
                false
            },
        }
    }

    /// Hand on what the response phase already read and filtered; `Some`
    /// when that was the whole body.
    async fn resume(&mut self) -> Option<Ended> {
        match std::mem::replace(&mut self.start, Start::Fresh) {
            Start::Fresh => None,
            Start::Chunk { body, ends: false } => {
                let chunk = body?;
                self.relay.data(chunk).await.err().map(|_gone| Ended::ClientGone)
            },
            Start::Chunk { body, ends: true } => Some(end_with(&self.relay, body, None).await),
            Start::Ended => Some(Box::pin(self.deliver_end()).await),
        }
    }

    /// Relay the body, then release the connection and complete.
    pub(super) async fn run(mut self) {
        let ended = Box::pin(self.pump()).await;
        let Self {
            connector,
            mut flight,
            relay,
            mut session,
            upload,
            ..
        } = self;
        let keepalive = settle(&mut flight, &mut session, &ended) && upload.is_settled();
        if !matches!(ended, Ended::Finished | Ended::ClientGone) {
            relay.flushed().await;
        }
        drop(relay);
        super::upstream::release(&connector, session, keepalive);
        flight.complete().await;
    }

    /// Give up forwarding the client's body; the response carries on.
    fn stop_upload(&mut self, end: UploadEnd) {
        let reason = match end {
            UploadEnd::Client(failure) | UploadEnd::Upstream(failure) => failure.detail,
            UploadEnd::Halted(halt) => halt.reason,
        };
        debug!(
            reason,
            "stopped forwarding the request body while relaying the response"
        );
        self.upload.abandon();
    }

    /// Act on one step; `Some` once the relay is over.
    async fn take_step(&mut self, step: Step) -> Option<Ended> {
        match step {
            Step::Retry => None,
            Step::ClientGone => Some(Ended::ClientGone),
            Step::Upstream(Ok(Some(chunk))) if self.session.response_done() => {
                Some(Box::pin(self.deliver_last(chunk)).await)
            },
            Step::Upstream(Ok(Some(chunk))) => self.deliver(chunk).await.err(),
            Step::Upstream(Ok(None)) => Some(Box::pin(self.deliver_end()).await),
            Step::Upstream(Err(failure)) => Some(Ended::Upstream(failure)),
            Step::Client(frame) => {
                self.forward(frame).await;
                None
            },
        }
    }

    /// The upstream's trailers after the upstream trailer hook, and the body
    /// bytes a trailer filter turned them into instead, if it did.
    fn take_trailers(&mut self) -> (Option<Bytes>, Option<http::HeaderMap>) {
        let Some(mut trailers) = self.session.take_trailers() else {
            return (None, None);
        };
        strip_reserved_internal_header_map(&mut trailers);
        response_trailers::capture(&trailers, &mut self.flight.ctx);
        if !self.flight.pipeline.needs_response_trailers() {
            return (None, Some(trailers));
        }
        let produced = response_trailer_filter::execute(&self.flight.pipeline, &mut trailers, &mut self.flight.ctx);
        strip_reserved_internal_header_map(&mut trailers);
        match produced {
            Some(body) => (Some(body), None),
            None => (None, Some(trailers)),
        }
    }
}

/// What one turn of the relay produced.
enum Step {
    /// The client stopped reading.
    ClientGone,

    /// Time to offer the queued request body to the upstream again.
    Retry,

    /// A frame of the client's body.
    Client(Result<DownstreamFrame, Failure>),

    /// The next upstream chunk, `None` at the end of the body.
    Upstream(Result<Option<Bytes>, Failure>),
}

/// How the relay ended.
enum Ended {
    /// The client stopped reading.
    ClientGone,

    /// A response body filter aborted the response.
    Filter(String),

    /// The body ended and the client has all of it.
    Finished,

    /// Reading the upstream body failed.
    Upstream(Failure),
}

/// When the awaited upstream chunk is overdue.
#[derive(Clone, Copy)]
struct Due {
    /// The instant the read timeout runs out.
    at: Instant,

    /// The read timeout it runs out on.
    limit: Duration,
}

impl Due {
    /// `limit` from now, if the clock can hold it.
    fn within(limit: Duration) -> Option<Self> {
        Instant::now().checked_add(limit).map(|at| Self { at, limit })
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Send the last bytes and trailers, ending the client's body.
async fn end_with(relay: &Relay, last: Option<Bytes>, trailers: Option<http::HeaderMap>) -> Ended {
    if let Some(chunk) = last
        && relay.data(chunk).await.is_err()
    {
        return Ended::ClientGone;
    }
    let sent = match trailers {
        Some(trailers) => relay.trailers(trailers).await,
        None => relay.end().await,
    };
    sent.map_or(Ended::ClientGone, |()| Ended::Finished)
}

/// Resolves with the read timeout once `due` passes; never without one.
async fn overdue(due: Option<Due>) -> Duration {
    match due {
        Some(due) => {
            tokio::time::sleep_until(due.at).await;
            due.limit
        },
        None => std::future::pending().await,
    }
}

/// Account for how the relay ended; returns whether the upstream
/// connection may be pooled.
fn settle(flight: &mut Flight, session: &mut HyperSession, ended: &Ended) -> bool {
    match ended {
        Ended::Finished => matches!(session.completion(), Ok(Completion::Finished)),
        Ended::ClientGone => {
            debug!("client went away before the response body ended");
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_DOWNSTREAM);
            flight.error = Some(ErrorOrigin::Downstream);
            false
        },
        Ended::Filter(reason) => {
            error!(reason = reason.as_str(), "response body filter aborted the response");
            flight.ctx.stamp_error_type(metrics::ERROR_TYPE_INTERNAL);
            flight.error = Some(ErrorOrigin::Other);
            false
        },
        Ended::Upstream(failure) => {
            record_attempt_failure(failure, &mut flight.ctx);
            if let Some(error_type) = failure.error_type() {
                flight.ctx.stamp_error_type(error_type);
            }
            error!(error = %failure, "upstream error while relaying the response body");
            flight.error = Some(failure.origin());
            false
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
    use std::sync::{Arc, Mutex};

    use http::{HeaderMap, HeaderValue, Method};
    use http_body_util::BodyExt as _;
    use praxis_core::egress::Connector as _;
    use praxis_filter::{BodyMode, FilterAction, FilterPipeline};

    use super::*;
    use crate::http::hyper::{
        body::ProxyBody,
        downstream::DownstreamBody,
        failure::FailureKind,
        test_utils::{
            Script, Upstream, answered, client_request, empty_pipeline, queue_unread_body, scripted_pipeline,
            session_to, streaming_upload,
        },
    };

    #[tokio::test]
    async fn end_with_sends_the_last_chunk_and_ends_the_body() {
        let (relay, body) = Relay::new();
        let collecting = tokio::spawn(body.collect());

        let ended = end_with(&relay, Some(Bytes::from_static(b"tail")), None).await;

        assert!(matches!(ended, Ended::Finished), "the client has the whole body");
        let collected = collecting.await.unwrap().unwrap();
        assert!(collected.trailers().is_none(), "no trailers were sent");
        assert_eq!(collected.to_bytes(), "tail", "the last chunk is the body's end");
    }

    #[tokio::test]
    async fn end_with_trailers_ends_the_body_with_them() {
        let (relay, body) = Relay::new();
        let collecting = tokio::spawn(body.collect());
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let ended = end_with(&relay, None, Some(trailers)).await;

        assert!(matches!(ended, Ended::Finished), "the client has the whole body");
        let collected = collecting.await.unwrap().unwrap();
        assert_eq!(
            collected
                .trailers()
                .and_then(|trailers| trailers.get("grpc-status"))
                .unwrap(),
            "0",
            "the trailers end the body"
        );
    }

    #[tokio::test]
    async fn end_with_a_departed_client_is_client_gone() {
        let (relay, body) = Relay::new();
        drop(body);

        let ended = end_with(&relay, Some(Bytes::from_static(b"tail")), None).await;

        assert!(matches!(ended, Ended::ClientGone), "nobody reads the end");
    }

    #[tokio::test]
    async fn clean_end_lets_the_connection_be_pooled() {
        let (_upstream, _connector, mut session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let read_all = session.read_response_body().await;

        let reusable = settle(&mut flight, &mut session, &Ended::Finished);

        assert!(matches!(read_all, Ok(Some(_))), "the body is read");
        assert!(reusable, "a body read to its end leaves the connection reusable");
        assert!(flight.error.is_none(), "nothing failed");
    }

    #[tokio::test]
    async fn end_before_the_upstream_finished_does_not_pool() {
        let (_upstream, _connector, mut session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhi\r\n").await;
        let mut flight = Flight::for_tests(empty_pipeline());

        let reusable = settle(&mut flight, &mut session, &Ended::Finished);

        assert!(
            !reusable,
            "a connection whose response body did not end cannot take another request"
        );
    }

    #[tokio::test]
    async fn departed_client_is_recorded_as_the_downstream() {
        let (_upstream, _connector, mut session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let mut flight = Flight::for_tests(empty_pipeline());

        let reusable = settle(&mut flight, &mut session, &Ended::ClientGone);

        assert!(!reusable, "an abandoned body leaves the connection unusable");
        assert_eq!(
            flight.error,
            Some(ErrorOrigin::Downstream),
            "the client ended the request"
        );
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_DOWNSTREAM),
            "it is counted as a downstream error"
        );
    }

    #[tokio::test]
    async fn failing_body_filter_is_recorded_as_internal() {
        let (_upstream, _connector, mut session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let mut flight = Flight::for_tests(empty_pipeline());

        let reusable = settle(&mut flight, &mut session, &Ended::Filter("broke".to_owned()));

        assert!(!reusable, "an aborted body leaves the connection unusable");
        assert_eq!(flight.error, Some(ErrorOrigin::Other), "the proxy ended the request");
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_INTERNAL),
            "it is counted as an internal error"
        );
    }

    #[tokio::test]
    async fn upstream_failure_mid_body_is_counted_by_its_kind() {
        let (_upstream, _connector, mut session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let failure = Failure::read_timeout(Duration::from_millis(50));

        let reusable = settle(&mut flight, &mut session, &Ended::Upstream(failure));

        assert!(!reusable, "a failed body leaves the connection unusable");
        assert_eq!(flight.error, Some(ErrorOrigin::Other), "the upstream ended the request");
        assert_eq!(
            flight.ctx.error_type,
            Some(metrics::ERROR_TYPE_TIMEOUT),
            "a read timeout is counted as a timeout"
        );
    }

    #[tokio::test]
    async fn relay_delivers_the_body_and_pools_the_connection() {
        let (upstream, connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").await;
        let (relaying, body) = relaying(connector.clone(), empty_pipeline(), session, Start::Fresh, true).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "hello", "the upstream body reaches the client");
        assert!(
            reused_after_release(&connector, &upstream).await,
            "the connection went back to the pool"
        );
    }

    #[tokio::test]
    async fn relay_resumes_after_the_chunk_read_before_the_commit() {
        let (_upstream, connector, mut session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n").await;
        let first = session.read_response_body().await.unwrap();
        let start = Start::Chunk {
            body: first,
            ends: false,
        };
        let (relaying, body) = relaying(connector, empty_pipeline(), session, start, true).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "hello", "the first chunk is followed by the rest");
    }

    #[tokio::test]
    async fn relay_of_a_body_read_whole_before_the_commit_just_ends() {
        let (_upstream, connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let start = Start::Chunk {
            body: Some(Bytes::from_static(b"ok")),
            ends: true,
        };
        let (relaying, body) = relaying(connector, empty_pipeline(), session, start, true).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "ok", "the filtered whole body is delivered and ended");
    }

    #[tokio::test]
    async fn relay_of_a_body_that_ended_runs_only_the_end() {
        let (_upstream, connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|body, end_of_stream| {
                    if end_of_stream {
                        *body = Some(Bytes::from_static(b"eos"));
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        });
        let (relaying, body) = relaying(connector, pipeline, session, Start::Ended, true).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(
            body.unwrap(),
            "eos",
            "the end-of-stream filters still run on a body that ended empty"
        );
    }

    #[tokio::test]
    async fn relay_runs_every_chunk_through_the_body_filters() {
        let (_upstream, connector, session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n").await;
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|body, _end| {
                    *body = body.take().map(|chunk| Bytes::from(chunk.to_ascii_uppercase()));
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        });
        let (relaying, body) = relaying(connector, pipeline, session, Start::Fresh, true).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "ABCD", "the client gets what the filters left");
    }

    #[tokio::test]
    async fn stream_buffer_holds_the_body_until_its_end() {
        let (_upstream, connector, session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n").await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::StreamBuffer { max_bytes: Some(1024) },
                Arc::new(move |body, end_of_stream| {
                    recorded.lock().unwrap().push((body.clone(), end_of_stream));
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        });
        let (mut relaying, body) = relaying(connector, pipeline, session, Start::Fresh, true).await;
        relaying.flight.ctx.response_body_mode = relaying.flight.pipeline.body_capabilities().response_body_mode;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "abcd", "the whole body reaches the client");
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|(body, end)| *end && body.as_deref() == Some(b"abcd".as_slice())),
            "the filter inspects the whole body at its end: {seen:?}"
        );
    }

    #[tokio::test]
    async fn response_past_the_size_limit_aborts_mid_stream() {
        let (_upstream, connector, session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n").await;
        let mut pipeline = empty_pipeline();
        pipeline.apply_body_limits(None, Some(3), false).unwrap();
        let (mut relaying, body) = relaying(connector, pipeline, session, Start::Fresh, true).await;
        relaying.flight.ctx.response_body_mode = relaying.flight.pipeline.body_capabilities().response_body_mode;

        let body = run_and_collect(relaying, body).await;

        assert!(body.is_none(), "a body that outgrows the limit is aborted, not ended");
    }

    #[tokio::test]
    async fn upstream_trailers_end_the_client_body() {
        let (_upstream, connector, session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\ngrpc-status: 0\r\n\r\n")
                .await;
        let (relaying, body) = relaying(connector, empty_pipeline(), session, Start::Fresh, true).await;

        let relayed = tokio::spawn(relaying.run());
        let collected = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .expect("the relay finishes")
            .unwrap();
        relayed.await.unwrap();

        assert_eq!(
            collected
                .trailers()
                .and_then(|trailers| trailers.get("grpc-status"))
                .unwrap(),
            "0",
            "the upstream's trailers reach the client"
        );
        assert_eq!(collected.to_bytes(), "ok", "after the body");
    }

    #[tokio::test]
    async fn failing_body_filter_aborts_the_client_body() {
        let (_upstream, connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let pipeline = scripted_pipeline(Script {
            response_body: Some((
                BodyMode::Stream,
                Arc::new(|_body, _end| Err("body filter broke".into())),
            )),
            ..Script::default()
        });
        let (relaying, body) = relaying(connector, pipeline, session, Start::Fresh, true).await;

        let body = run_and_collect(relaying, body).await;

        assert!(body.is_none(), "the client's body is aborted, not ended");
    }

    #[tokio::test]
    async fn upstream_cut_short_aborts_the_client_body() {
        let upstream = Upstream::answering_then_closing(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc").await;
        let (connector, mut session) = session_to(&upstream, Method::GET).await;
        session.finish_request().await.unwrap();
        session.read_response_head().await.unwrap();
        let (relaying, body) = relaying(connector, empty_pipeline(), session, Start::Fresh, true).await;

        let body = run_and_collect(relaying, body).await;

        assert!(
            body.is_none(),
            "a body the upstream cut short is not passed off as complete"
        );
    }

    #[tokio::test]
    async fn departed_client_stops_the_relay() {
        let (upstream, connector, session) =
            answered(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhi\r\n").await;
        let (relaying, body) = relaying(connector.clone(), empty_pipeline(), session, Start::Fresh, true).await;
        drop(body);

        let finished = tokio::time::timeout(Duration::from_secs(5), relaying.run()).await;

        assert!(finished.is_ok(), "the relay ends once the client is gone");
        assert!(
            !reused_after_release(&connector, &upstream).await,
            "the abandoned connection is not pooled"
        );
    }

    #[tokio::test]
    async fn connection_is_not_pooled_while_the_request_body_is_unsent() {
        let (upstream, connector, session) = answered(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
        let (relaying, body) = relaying(connector.clone(), empty_pipeline(), session, Start::Fresh, false).await;

        let body = run_and_collect(relaying, body).await;

        assert_eq!(body.unwrap(), "ok", "the response is relayed in full");
        assert!(
            !reused_after_release(&connector, &upstream).await,
            "a connection still owed part of the request body cannot serve another"
        );
    }

    #[tokio::test]
    async fn upstream_that_stalls_both_ways_trips_the_read_timeout() {
        let upstream = Upstream::answering_early(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n").await;
        let (connector, mut session) = session_to(&upstream, Method::POST).await;
        session
            .send_request_body(Bytes::from_static(b"ab"), false)
            .await
            .unwrap();
        session.read_response_head().await.unwrap();
        let (mut relaying, _body) = relaying(connector, empty_pipeline(), session, Start::Fresh, false).await;
        relaying.read_timeout = Some(Duration::from_millis(200));
        queue_unread_body(&mut relaying.upload, &mut relaying.flight).await;

        let ended = tokio::time::timeout(Duration::from_secs(3), relaying.pump()).await;

        assert!(
            matches!(&ended, Ok(Ended::Upstream(failure)) if failure.kind == FailureKind::ReadTimeout),
            "an upstream that neither takes the request body nor sends the response trips the read timeout"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A relay of `session`'s body through `pipeline` from `start`, and the
    /// client's body it feeds; the request had no body when `settled`, else
    /// the client is still sending it.
    async fn relaying(
        connector: HyperConnector,
        pipeline: FilterPipeline,
        session: HyperSession,
        start: Start,
        settled: bool,
    ) -> (Relaying, ProxyBody) {
        let mut flight = Flight::for_tests(pipeline);
        flight.ctx.request_snapshot = Some(praxis_filter::Request {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
        });
        let (upload, _client) = if settled {
            let (request, client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
            (
                Upload::new(DownstreamBody::new(request.into_body(), None), &flight.ctx),
                client,
            )
        } else {
            streaming_upload(&flight.ctx).await
        };
        let (relay, body) = Relay::new();
        let relaying = Relaying {
            connector,
            flight,
            read_timeout: Some(Duration::from_secs(5)),
            relay,
            session,
            start,
            upload,
        };
        (relaying, body)
    }

    /// Whether a connection to `upstream` comes from the pool once the last
    /// session's release had time to land.
    async fn reused_after_release(connector: &HyperConnector, upstream: &Upstream) -> bool {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let session = connector
            .connect(&upstream.peer(), Duration::from_secs(5))
            .await
            .unwrap();
        session.reused()
    }

    /// Run `relaying` while collecting `body`; the body, or `None` when it
    /// was aborted.
    async fn run_and_collect(relaying: Relaying, body: ProxyBody) -> Option<Bytes> {
        let relayed = tokio::spawn(relaying.run());
        let collected = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .expect("the relay finishes");
        relayed.await.unwrap();
        collected.ok().map(http_body_util::Collected::to_bytes)
    }
}
