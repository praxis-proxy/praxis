// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The request body sent upstream, with its replay copy for retries.
//!
//! A pre-read or adapted body is whole in memory and sent as is on every
//! attempt. A streamed body is read from the client chunk by chunk, run
//! through the request body filters (what the Pingora handler's
//! `request_body_filter` does), and queued for the upstream.
//!
//! The queue is handed to the session in bounded slices rather than in one
//! wait: an upstream that answers early (a `413`, a `401`) and stops reading
//! leaves the session's body channel full, and the slices let the caller
//! look for that answer in between, the way Pingora drives both directions
//! at once. The chunks taken from the client are kept, up to the retry
//! buffer limit Pingora uses, so a retry can replay them; a body past the
//! limit marks the copy truncated and the request is not retried.

use std::{collections::VecDeque, time::Duration};

use bytes::Bytes;
use http::HeaderMap;
use praxis_core::{
    config::DEFAULT_RETRY_BODY_LIMIT_BYTES,
    egress::{EgressError, Session as _, hyper::HyperSession},
};
use tokio::time::Instant;

use super::{
    downstream::{DownstreamBody, DownstreamFrame},
    failure::{Failure, FailureKind},
    service::Flight,
};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    handler::request_body_filter::{RequestBodyHalt, run_request_body},
};

// -----------------------------------------------------------------------------
// Upload
// -----------------------------------------------------------------------------

/// The request body of one request across its upstream attempts.
#[derive(Debug)]
pub(super) struct Upload {
    /// A whole body kept for every attempt, once taken from the context.
    buffered: Option<VecDeque<Bytes>>,

    /// Whether the client's body was read to its end.
    ended: bool,

    /// The client's body still to read, while streaming.
    live: Option<DownstreamBody>,

    /// How the body reaches the upstream.
    mode: Mode,

    /// What the session still has to take, in order.
    outgoing: VecDeque<Outgoing>,

    /// Streamed chunks taken from the client, kept for a replay.
    replay: Vec<Bytes>,

    /// Bytes in `replay`.
    replay_bytes: usize,

    /// When the upstream first refused the item at the front of the queue.
    stalled_since: Option<Instant>,

    /// Trailers that ended the client's body.
    trailers: Option<HeaderMap>,

    /// Whether the body outgrew the replay copy.
    truncated: bool,

    /// The cluster's bound on one write to the upstream, for this attempt.
    write_timeout: Option<Duration>,
}

/// How far a flush got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Flush {
    /// The session took nothing within the slice; everything is still
    /// queued.
    Blocked,

    /// The session took everything queued.
    Done,

    /// The session took part of the queue within the slice; the rest is
    /// still queued.
    Taken,
}

/// Why sending a request body ended early.
pub(super) enum UploadEnd {
    /// The client stalled or went away.
    Client(Failure),

    /// A request body filter stopped the request.
    Halted(RequestBodyHalt),

    /// The exchange with the upstream failed.
    Upstream(Failure),
}

impl UploadEnd {
    /// An exchange failure from the egress.
    #[expect(clippy::needless_pass_by_value, reason = "taken by value to fit `map_err`")]
    pub(super) fn upstream(err: EgressError) -> Self {
        Self::Upstream(Failure::exchange(&err))
    }
}

impl Upload {
    /// The upload of `body` for a request whose phase left `ctx`.
    pub(super) fn new(mut body: DownstreamBody, ctx: &PingoraRequestCtx) -> Self {
        let mode = if ctx.pre_read_body.is_some() || ctx.retained_adapted_request_body.is_some() {
            Mode::Buffered
        } else if body.is_done() {
            Mode::Empty
        } else {
            Mode::Streaming
        };
        Self {
            buffered: None,
            ended: mode != Mode::Streaming,
            trailers: body.pre_read_trailers.take(),
            live: (mode == Mode::Streaming).then_some(body),
            mode,
            outgoing: VecDeque::new(),
            replay: Vec::new(),
            replay_bytes: 0,
            stalled_since: None,
            truncated: false,
            write_timeout: None,
        }
    }

    /// Stop forwarding the client's body; what is left of it is not sent.
    pub(super) fn abandon(&mut self) {
        self.live = None;
        self.outgoing.clear();
    }

    /// Run one client frame through the body filters and queue what they
    /// leave; reject trailers when the upstream transport cannot carry them.
    ///
    /// # Errors
    ///
    /// Returns [`UploadEnd`] when the client failed or a body filter
    /// stopped the request.
    pub(super) async fn accept(
        &mut self,
        flight: &mut Flight,
        frame: Result<DownstreamFrame, Failure>,
        h2: bool,
    ) -> Result<(), UploadEnd> {
        let frame = frame.map_err(|failure| {
            self.live = None;
            UploadEnd::Client(failure)
        })?;
        match frame {
            DownstreamFrame::Data(chunk) => {
                let mut body = Some(chunk);
                filter(flight, &mut body, false).await?;
                if let Some(chunk) = body.filter(|chunk| !chunk.is_empty()) {
                    self.keep(&chunk);
                    self.outgoing.push_back(Outgoing::Chunk(chunk));
                }
                Ok(())
            },
            DownstreamFrame::Trailers(trailers) => {
                self.trailers = Some(trailers);
                self.validate_trailers(h2)?;
                self.accept_end(flight).await
            },
            DownstreamFrame::End => self.accept_end(flight).await,
        }
    }

    /// The client's body ended: run the end-of-stream body filters and queue
    /// the end of the upstream body.
    async fn accept_end(&mut self, flight: &mut Flight) -> Result<(), UploadEnd> {
        self.live = None;
        self.ended = true;
        let mut last = None;
        filter(flight, &mut last, true).await?;
        let last = last.filter(|chunk| !chunk.is_empty());
        if let Some(chunk) = &last {
            self.keep(chunk);
        }
        self.queue_end(last);
        Ok(())
    }

    /// Queue everything known of the body for a new attempt on a session
    /// that speaks HTTP/2 when `h2` and bounds each write by
    /// `write_timeout`: the whole in-memory body, or the streamed chunks
    /// taken so far and, once the client's body ended, its end.
    ///
    /// # Errors
    ///
    /// Refuses retained request trailers on an HTTP/1 upstream.
    pub(super) fn begin(
        &mut self,
        ctx: &mut PingoraRequestCtx,
        h2: bool,
        write_timeout: Option<Duration>,
    ) -> Result<(), UploadEnd> {
        self.validate_trailers(h2)?;
        self.outgoing.clear();
        self.stalled_since = None;
        self.write_timeout = write_timeout;
        match self.mode {
            Mode::Empty => self.queue_end(None),
            Mode::Buffered => {
                let chunks = self.take_buffered(ctx);
                self.queue_whole(chunks);
            },
            Mode::Streaming => {
                let replayed = self.replay.iter().cloned().map(Outgoing::Chunk);
                self.outgoing.extend(replayed);
                if self.ended {
                    self.queue_end(None);
                }
            },
        }
        Ok(())
    }

    /// Refuse unsupported request trailers before any clean body ending.
    fn validate_trailers(&self, h2: bool) -> Result<(), UploadEnd> {
        if self.trailers.is_some() && !h2 {
            return Err(UploadEnd::Client(Failure::new(
                FailureKind::BadRequest,
                "the Hyper backend cannot forward request trailers to HTTP/1 upstreams",
            )));
        }
        Ok(())
    }

    /// Hand the queue to the session, giving each item up to `slice`.
    ///
    /// Each slice restarts the session's own write timer, so the cluster's
    /// write timeout is enforced here, across slices, instead.
    ///
    /// # Errors
    ///
    /// Returns [`UploadEnd::Upstream`] when the session refuses an item or
    /// one waits past the write timeout.
    pub(super) async fn flush(&mut self, session: &mut HyperSession, slice: Duration) -> Result<Flush, UploadEnd> {
        let mut taken = false;
        while let Some(next) = self.outgoing.front() {
            match tokio::time::timeout(slice, push(session, next)).await {
                Ok(Ok(())) => {
                    self.outgoing.pop_front();
                    self.stalled_since = None;
                    taken = true;
                },
                Ok(Err(err)) => return Err(UploadEnd::upstream(err)),
                Err(_blocked) => {
                    let stalled = self.stalled()?;
                    return Ok(if taken { Flush::Taken } else { stalled });
                },
            }
        }
        Ok(Flush::Done)
    }

    /// Whether some of the body is queued for the session.
    pub(super) fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Whether the client's body is still being read.
    pub(super) fn is_live(&self) -> bool {
        self.live.is_some()
    }

    /// Whether the upstream has the whole body, so its connection can serve
    /// another request.
    pub(super) fn is_settled(&self) -> bool {
        self.ended && self.live.is_none() && self.outgoing.is_empty()
    }

    /// Whether a retry could not replay the body.
    pub(super) fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Keep a chunk taken from the client for a replay, or give the copy up
    /// once the body outgrows the retry limit.
    fn keep(&mut self, chunk: &Bytes) {
        if self.truncated {
            return;
        }
        let limit = usize::try_from(DEFAULT_RETRY_BODY_LIMIT_BYTES).unwrap_or(usize::MAX);
        let total = self.replay_bytes.saturating_add(chunk.len());
        if total > limit {
            self.truncated = true;
            self.replay = Vec::new();
            self.replay_bytes = 0;
            return;
        }
        self.replay.push(chunk.clone());
        self.replay_bytes = total;
    }

    /// The next frame of the client's body; never resolves once it ended.
    pub(super) async fn next_live(&mut self) -> Result<DownstreamFrame, Failure> {
        match self.live.as_mut() {
            Some(body) => body.next().await,
            None => std::future::pending().await,
        }
    }

    /// Queue the end of the body after `last`, with the client's trailers
    /// retained across buffered uploads and retries.
    fn queue_end(&mut self, last: Option<Bytes>) {
        let trailers = self.trailers.clone();
        match (last, trailers) {
            (Some(chunk), Some(trailers)) => {
                self.outgoing.push_back(Outgoing::Chunk(chunk));
                self.outgoing.push_back(Outgoing::Trailers(trailers));
            },
            (Some(chunk), None) => self.outgoing.push_back(Outgoing::Last(chunk)),
            (None, Some(trailers)) => self.outgoing.push_back(Outgoing::Trailers(trailers)),
            (None, None) => self.outgoing.push_back(Outgoing::Finish),
        }
    }

    /// Queue a whole body, ending with trailers when present or the last
    /// chunk otherwise, so a single chunk can carry a known length.
    fn queue_whole(&mut self, chunks: VecDeque<Bytes>) {
        let mut chunks = chunks.into_iter().peekable();
        while let Some(chunk) = chunks.next() {
            let item = if chunks.peek().is_some() || self.trailers.is_some() {
                Outgoing::Chunk(chunk)
            } else {
                Outgoing::Last(chunk)
            };
            self.outgoing.push_back(item);
        }
        if self.outgoing.is_empty() || self.trailers.is_some() {
            self.queue_end(None);
        }
    }

    /// The upstream did not take the front item within a slice: a stall,
    /// or a write timeout once it outlasts the cluster's bound.
    ///
    /// The session's body channel never takes back room it gave, so two
    /// refusals of one item bracket a stretch in which the upstream took
    /// nothing, even when the relay offered it nothing in between.
    fn stalled(&mut self) -> Result<Flush, UploadEnd> {
        let since = *self.stalled_since.get_or_insert_with(Instant::now);
        match self.write_timeout {
            Some(limit) if since.elapsed() >= limit => Err(UploadEnd::Upstream(Failure::write_timeout(limit))),
            Some(_) | None => Ok(Flush::Blocked),
        }
    }

    /// How long the upstream has refused the item at the front of the queue;
    /// zero while it is taking the body.
    pub(super) fn stalled_for(&self) -> Duration {
        self.stalled_since.map_or(Duration::ZERO, |since| since.elapsed())
    }

    /// The whole in-memory body for this attempt: the adapted body when
    /// adaptation ran, else the pre-read body, reseeded for the attempt, or
    /// the copy kept from an earlier one.
    fn take_buffered(&mut self, ctx: &mut PingoraRequestCtx) -> VecDeque<Bytes> {
        let taken = if ctx.retained_adapted_request_body.is_some() {
            ctx.adapted_request_body.take()
        } else {
            ctx.pre_read_body.take()
        };
        match taken {
            Some(chunks) => {
                self.buffered = Some(chunks.clone());
                chunks
            },
            None => self.buffered.clone().unwrap_or_default(),
        }
    }
}

/// How a request body reaches the upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// The request has no body.
    Empty,

    /// The body is whole in memory (pre-read or adapted).
    Buffered,

    /// The body is streamed from the client.
    Streaming,
}

/// One thing to hand the session.
#[derive(Debug)]
enum Outgoing {
    /// A body chunk more may follow.
    Chunk(Bytes),

    /// End the body with no more bytes.
    Finish,

    /// The last body chunk.
    Last(Bytes),

    /// End the body with trailers (HTTP/2 only).
    Trailers(HeaderMap),
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Run one chunk, or the end of the body, through the request body filters.
async fn filter(flight: &mut Flight, body: &mut Option<Bytes>, end_of_stream: bool) -> Result<(), UploadEnd> {
    Box::pin(run_request_body(&flight.pipeline, body, end_of_stream, &mut flight.ctx))
        .await
        .map_err(UploadEnd::Halted)
}

/// Hand one item to the session. The item stays queued until this resolves,
/// so a send cut short by the caller's slice is retried with the same bytes.
async fn push(session: &mut HyperSession, item: &Outgoing) -> Result<(), EgressError> {
    match item {
        Outgoing::Chunk(chunk) => session.send_request_body(chunk.clone(), false).await,
        Outgoing::Last(chunk) => session.send_request_body(chunk.clone(), true).await,
        Outgoing::Finish => session.finish_request().await,
        Outgoing::Trailers(trailers) => session.send_request_trailers(trailers.clone()).await,
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
    use std::sync::Arc;

    use http::{HeaderValue, Method};
    use praxis_filter::{BodyMode, FilterAction, FilterPipeline, Rejection};

    use super::*;
    use crate::http::hyper::test_utils::{
        BodyHook, Script, Upstream, client_request, empty_pipeline, scripted_pipeline, session_to, streaming_upload,
    };

    #[tokio::test]
    async fn bodiless_request_sends_only_the_end() {
        let flight = Flight::for_tests(empty_pipeline());
        let (request, _client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
        let mut upload = Upload::new(DownstreamBody::new(request.into_body(), None), &flight.ctx);
        let mut ctx = PingoraRequestCtx::default();

        assert!(upload.begin(&mut ctx, false, None).is_ok());

        assert_eq!(queued(&upload), ["finish"], "the request goes out with an empty body");
        assert!(!upload.is_live(), "there is nothing to read from the client");
        assert!(!upload.is_truncated(), "an empty body can always be replayed");
    }

    #[tokio::test]
    async fn buffered_body_is_queued_whole_on_every_attempt() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.pre_read_body = Some(chunks(&["ab", "cd"]));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());
        let first = queued(&upload);
        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());

        assert_eq!(first, ["chunk:ab", "last:cd"], "the last chunk ends the body");
        assert_eq!(
            queued(&upload),
            ["chunk:ab", "last:cd"],
            "a retry sends the same body again from the kept copy"
        );
        assert!(!upload.is_live(), "a buffered body is not read from the client");
    }

    #[tokio::test]
    async fn single_buffered_chunk_goes_with_its_length_and_an_empty_one_just_ends() {
        let mut single = Flight::for_tests(empty_pipeline());
        single.ctx.pre_read_body = Some(chunks(&["only"]));
        let mut empty = Flight::for_tests(empty_pipeline());
        empty.ctx.pre_read_body = Some(VecDeque::new());
        let (mut single_upload, _single_client) = streaming_upload(&single.ctx).await;
        let (mut empty_upload, _empty_client) = streaming_upload(&empty.ctx).await;

        assert!(single_upload.begin(&mut single.ctx, false, None).is_ok());
        assert!(empty_upload.begin(&mut empty.ctx, false, None).is_ok());

        assert_eq!(
            queued(&single_upload),
            ["last:only"],
            "one chunk is the whole body, sent with a known length"
        );
        assert_eq!(queued(&empty_upload), ["finish"], "an empty buffered body just ends");
    }

    #[tokio::test]
    async fn adapted_body_wins_over_the_pre_read_one() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.pre_read_body = Some(chunks(&["original"]));
        flight.ctx.retained_adapted_request_body = Some(chunks(&["adapted"]));
        flight.ctx.adapted_request_body = Some(chunks(&["adapted"]));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());

        assert_eq!(
            queued(&upload),
            ["last:adapted"],
            "the adapted body is what goes upstream"
        );
    }

    #[tokio::test]
    async fn streamed_chunks_are_queued_and_replayed_on_a_retry() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        accept_data(&mut upload, &mut flight, &["ab", "cd"]).await;
        let queued_live = queued(&upload);
        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());

        assert_eq!(
            queued_live,
            ["chunk:ab", "chunk:cd"],
            "each chunk is queued as it arrives"
        );
        assert_eq!(
            queued(&upload),
            ["chunk:ab", "chunk:cd"],
            "a retry replays what was taken from the client, and no end yet"
        );
        assert!(upload.is_live(), "the client is still sending");
    }

    #[tokio::test]
    async fn ended_stream_is_replayed_with_its_end() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        accept_data(&mut upload, &mut flight, &["ab"]).await;

        let ended = upload.accept(&mut flight, Ok(DownstreamFrame::End), false).await;
        let queued_live = queued(&upload);
        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());

        assert!(ended.is_ok(), "the end of the body is accepted");
        assert_eq!(queued_live, ["chunk:ab", "finish"], "the end follows the chunks");
        assert_eq!(queued(&upload), ["chunk:ab", "finish"], "and is replayed with them");
        assert!(!upload.is_live(), "nothing more is read from the client");
    }

    #[tokio::test]
    async fn trailers_are_replayed_on_http2_and_rejected_on_http1() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        accept_data(&mut upload, &mut flight, &["ab"]).await;
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("9"));

        let ended = upload
            .accept(&mut flight, Ok(DownstreamFrame::Trailers(trailers)), true)
            .await;
        let over_http2 = queued(&upload);
        let replayed_over_http1 = upload.begin(&mut flight.ctx, false, None);
        assert!(upload.begin(&mut flight.ctx, true, None).is_ok());

        assert!(ended.is_ok(), "trailers end the body");
        assert_eq!(over_http2, ["chunk:ab", "trailers"], "HTTP/2 carries the trailers");
        assert!(
            matches!(replayed_over_http1, Err(UploadEnd::Client(failure)) if failure.kind == FailureKind::BadRequest),
            "a retry over HTTP/1 must refuse trailers instead of dropping them"
        );
        assert_eq!(
            queued(&upload),
            ["chunk:ab", "trailers"],
            "a retry over HTTP/2 replays them"
        );
    }

    #[tokio::test]
    async fn pre_read_trailers_survive_empty_and_chunked_body_retries() {
        for body_chunks in [vec![], vec!["ab", "cd"]] {
            let mut flight = Flight::for_tests(empty_pipeline());
            flight.ctx.pre_read_body = Some(chunks(&body_chunks));
            let (request, _client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
            let mut body = DownstreamBody::new(request.into_body(), None);
            let mut trailers = HeaderMap::new();
            trailers.insert("x-checksum", HeaderValue::from_static("abc"));
            body.pre_read_trailers = Some(trailers);
            let mut upload = Upload::new(body, &flight.ctx);
            for _attempt in 0..2 {
                assert!(upload.begin(&mut flight.ctx, true, None).is_ok());
                let mut expected: Vec<String> = body_chunks.iter().map(|chunk| format!("chunk:{chunk}")).collect();
                expected.push("trailers".to_owned());
                assert_eq!(
                    queued(&upload),
                    expected,
                    "trailers must be the only end marker on each attempt"
                );
                assert!(
                    matches!(upload.outgoing.back(), Some(Outgoing::Trailers(map)) if map.get("x-checksum").unwrap() == "abc")
                );
            }
            assert!(
                matches!(upload.begin(&mut flight.ctx, false, None), Err(UploadEnd::Client(failure)) if failure.kind == FailureKind::BadRequest)
            );
        }
    }

    #[tokio::test]
    async fn end_of_stream_filter_output_is_the_last_chunk() {
        let mut flight = request_flight(scripted_pipeline(Script {
            request_body: Some((BodyMode::Stream, appending_at_end())),
            ..Script::default()
        }));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        let ended = upload.accept(&mut flight, Ok(DownstreamFrame::End), false).await;

        assert!(ended.is_ok(), "the end of the body is accepted");
        assert_eq!(
            queued(&upload),
            ["last:!"],
            "what the end-of-stream filters release ends the body"
        );
    }

    #[tokio::test]
    async fn end_of_stream_filter_output_precedes_http2_trailers() {
        let mut flight = request_flight(scripted_pipeline(Script {
            request_body: Some((BodyMode::Stream, appending_at_end())),
            ..Script::default()
        }));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        let ended = upload
            .accept(&mut flight, Ok(DownstreamFrame::Trailers(HeaderMap::new())), true)
            .await;

        assert!(ended.is_ok(), "trailers end the body");
        assert_eq!(
            queued(&upload),
            ["chunk:!", "trailers"],
            "the released bytes go first, then the trailers end the body"
        );
    }

    #[tokio::test]
    async fn replay_copy_is_given_up_past_the_retry_limit() {
        let flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        let limit = usize::try_from(DEFAULT_RETRY_BODY_LIMIT_BYTES).unwrap();

        upload.keep(&Bytes::from(vec![0_u8; limit]));
        let at_limit = upload.is_truncated();
        upload.keep(&Bytes::from_static(b"x"));

        assert!(!at_limit, "a body of exactly the limit can be replayed");
        assert!(upload.is_truncated(), "one byte past the limit cannot");
        assert!(upload.replay.is_empty(), "the copy is dropped rather than kept partial");
        assert_eq!(upload.replay_bytes, 0, "and its size with it");
    }

    #[tokio::test]
    async fn client_failure_ends_the_upload() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        let failure = Failure::downstream(FailureKind::DownstreamClosed, "client hung up");

        let accepted = upload.accept(&mut flight, Err(failure), false).await;

        assert!(
            matches!(accepted, Err(UploadEnd::Client(failure)) if failure.kind == FailureKind::DownstreamClosed),
            "the client's failure ends the upload as the client's"
        );
        assert!(!upload.is_live(), "the client's body is no longer read");
    }

    #[tokio::test]
    async fn size_limit_counts_every_chunk_and_refuses_past_it() {
        let mut pipeline = empty_pipeline();
        pipeline.apply_body_limits(Some(4), None, false).unwrap();
        let mut flight = Flight::for_tests(pipeline);
        flight.ctx.request_body_mode = flight.pipeline.body_capabilities().request_body_mode;
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        accept_data(&mut upload, &mut flight, &["abc"]).await;
        let over = upload
            .accept(&mut flight, Ok(DownstreamFrame::Data(Bytes::from_static(b"de"))), false)
            .await;

        assert!(
            matches!(&over, Err(UploadEnd::Halted(halt)) if halt.status == Some(413)),
            "the chunk that crosses the limit is refused with a 413"
        );
        assert_eq!(queued(&upload), ["chunk:abc"], "chunks inside the limit were queued");
    }

    #[tokio::test]
    async fn stream_mode_queues_what_the_filters_leave() {
        let mut flight = request_flight(scripted_pipeline(Script {
            request_body: Some((
                BodyMode::Stream,
                Arc::new(|body, _end| {
                    if body.is_some() {
                        *body = Some(Bytes::from_static(b"X"));
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        }));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        accept_data(&mut upload, &mut flight, &["ab"]).await;

        assert_eq!(queued(&upload), ["chunk:X"], "the filtered chunk is what goes upstream");
        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());
        assert_eq!(queued(&upload), ["chunk:X"], "and what a retry replays");
    }

    #[tokio::test]
    async fn stream_buffer_holds_chunks_until_a_filter_releases_them() {
        let mut flight = request_flight(scripted_pipeline(Script {
            request_body: Some((
                BodyMode::StreamBuffer { max_bytes: Some(1024) },
                Arc::new(|body, _end| {
                    if body.as_deref().is_some_and(|chunk| chunk.ends_with(b"go")) {
                        return Ok(FilterAction::Release);
                    }
                    Ok(FilterAction::Continue)
                }),
            )),
            ..Script::default()
        }));
        flight.ctx.request_body_mode = flight.pipeline.body_capabilities().request_body_mode;
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        accept_data(&mut upload, &mut flight, &["ab"]).await;
        let held = queued(&upload);
        accept_data(&mut upload, &mut flight, &["go"]).await;
        let released = queued(&upload);
        accept_data(&mut upload, &mut flight, &["cd"]).await;

        assert!(held.is_empty(), "a buffered chunk is held back: {held:?}");
        assert_eq!(released, ["chunk:abgo"], "the release forwards everything held");
        assert_eq!(
            queued(&upload),
            ["chunk:abgo", "chunk:cd"],
            "after the release, chunks stream through"
        );
    }

    #[tokio::test]
    async fn body_filter_rejection_halts_the_upload() {
        let mut flight = request_flight(scripted_pipeline(Script {
            request_body: Some((
                BodyMode::Stream,
                Arc::new(|_body, _end| Ok(FilterAction::Reject(Rejection::status(422)))),
            )),
            ..Script::default()
        }));
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        let refused = upload
            .accept(&mut flight, Ok(DownstreamFrame::Data(Bytes::from_static(b"ab"))), false)
            .await;

        assert!(
            matches!(&refused, Err(UploadEnd::Halted(halt)) if halt.rejection.as_ref().is_some_and(|rejection| rejection.status == 422)),
            "the filter's rejection stops the request"
        );
        assert!(!upload.has_outgoing(), "nothing of the refused chunk is queued");
    }

    #[tokio::test]
    async fn abandoned_upload_drops_what_is_queued() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        accept_data(&mut upload, &mut flight, &["ab"]).await;

        upload.abandon();

        assert!(!upload.has_outgoing(), "nothing more goes upstream");
        assert!(!upload.is_live(), "the client's body is no longer read");
        assert!(!upload.is_settled(), "an abandoned body never reached its end upstream");
    }

    #[tokio::test]
    async fn ended_body_never_yields_another_frame() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        let ended = upload.accept(&mut flight, Ok(DownstreamFrame::End), false).await;

        let next = tokio::time::timeout(Duration::from_millis(50), upload.next_live()).await;

        assert!(ended.is_ok(), "the end is accepted");
        assert!(next.is_err(), "a finished body has nothing more to read");
    }

    #[tokio::test]
    async fn flush_hands_the_whole_queue_to_the_session() {
        let upstream = Upstream::answering(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        accept_data(&mut upload, &mut flight, &["ab"]).await;
        let ended = upload.accept(&mut flight, Ok(DownstreamFrame::End), false).await;
        upload.stalled_since = Instant::now().checked_sub(Duration::from_secs(1));

        let flushed = upload.flush(&mut session, Duration::from_secs(5)).await;

        assert!(ended.is_ok(), "the end is accepted");
        assert!(matches!(flushed, Ok(Flush::Done)), "the session took everything");
        assert!(!upload.has_outgoing(), "nothing is left queued");
        assert!(upload.stalled_since.is_none(), "a successful write clears the stall");
        assert!(upload.is_settled(), "the upstream has the whole body");
    }

    #[tokio::test]
    async fn flush_stops_when_the_upstream_stops_taking_the_body() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        for _chunk in 0..64 {
            let chunk = Bytes::from(vec![0_u8; LARGE_CHUNK]);
            let accepted = upload
                .accept(&mut flight, Ok(DownstreamFrame::Data(chunk)), false)
                .await;
            assert!(accepted.is_ok(), "an unfiltered chunk is queued");
        }

        let first = upload.flush(&mut session, Duration::from_millis(50)).await;
        let second = upload.flush(&mut session, Duration::from_millis(50)).await;

        assert!(
            matches!(first, Ok(Flush::Taken)),
            "the upstream takes what its buffers hold, then stops the flush"
        );
        assert!(
            matches!(second, Ok(Flush::Blocked)),
            "a flush the upstream takes nothing of is blocked"
        );
        assert!(upload.has_outgoing(), "what it did not take stays queued");
        assert!(upload.stalled_since.is_some(), "the stall is timed from the refusal");
    }

    #[tokio::test(start_paused = true)]
    async fn write_timeout_counts_from_the_first_refusal() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        assert!(
            upload
                .begin(&mut flight.ctx, false, Some(Duration::from_millis(100)))
                .is_ok()
        );

        let first = upload.stalled();
        let since = upload.stalled_since;
        tokio::time::advance(Duration::from_millis(60)).await;
        let second = upload.stalled();
        tokio::time::advance(Duration::from_millis(60)).await;
        let third = upload.stalled();

        assert!(matches!(first, Ok(Flush::Blocked)), "the first refusal is a stall");
        assert!(
            matches!(second, Ok(Flush::Blocked)),
            "inside the bound it is still a stall"
        );
        assert_eq!(upload.stalled_since, since, "the stall is timed from the first refusal");
        assert!(
            matches!(&third, Err(UploadEnd::Upstream(failure)) if failure.kind == FailureKind::WriteTimeout),
            "past the bound it is the write timeout"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stall_without_a_write_timeout_never_fails() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        assert!(upload.begin(&mut flight.ctx, false, None).is_ok());

        let first = upload.stalled();
        tokio::time::advance(Duration::from_secs(3600)).await;
        let later = upload.stalled();

        assert!(matches!(first, Ok(Flush::Blocked)), "a refusal is a stall");
        assert!(
            matches!(later, Ok(Flush::Blocked)),
            "and stays one with no bound to cross"
        );
    }

    #[tokio::test]
    async fn a_new_attempt_restarts_the_stall_clock() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        assert!(
            upload
                .begin(&mut flight.ctx, false, Some(Duration::from_millis(100)))
                .is_ok()
        );
        let _blocked = upload.stalled();

        assert!(
            upload
                .begin(&mut flight.ctx, false, Some(Duration::from_millis(100)))
                .is_ok()
        );

        assert!(upload.stalled_since.is_none(), "each attempt times its own stalls");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A chunk large enough that a few fill the socket buffers of an
    /// upstream that stopped reading.
    const LARGE_CHUNK: usize = 1_048_576; // 1 MiB

    /// Queue each of `chunks` as a client data frame, unfiltered.
    async fn accept_data(upload: &mut Upload, flight: &mut Flight, chunks: &[&'static str]) {
        for chunk in chunks {
            let frame = DownstreamFrame::Data(Bytes::from_static(chunk.as_bytes()));
            let accepted = upload.accept(flight, Ok(frame), false).await;
            assert!(accepted.is_ok(), "the chunk {chunk} is accepted");
        }
    }

    /// A body hook that adds `!` at the end of the body.
    fn appending_at_end() -> BodyHook {
        Arc::new(|body, end_of_stream| {
            if end_of_stream {
                *body = Some(Bytes::from_static(b"!"));
            }
            Ok(FilterAction::Continue)
        })
    }

    /// `parts` as an in-memory body.
    fn chunks(parts: &[&'static str]) -> VecDeque<Bytes> {
        parts.iter().map(|part| Bytes::from_static(part.as_bytes())).collect()
    }

    /// What the upload has queued for the session, one word per item.
    fn queued(upload: &Upload) -> Vec<String> {
        upload
            .outgoing
            .iter()
            .map(|item| match item {
                Outgoing::Chunk(chunk) => format!("chunk:{}", String::from_utf8_lossy(chunk)),
                Outgoing::Finish => "finish".to_owned(),
                Outgoing::Last(chunk) => format!("last:{}", String::from_utf8_lossy(chunk)),
                Outgoing::Trailers(_) => "trailers".to_owned(),
            })
            .collect()
    }

    /// A `POST` running `pipeline`, with its request recorded for the body
    /// filters.
    fn request_flight(pipeline: FilterPipeline) -> Flight {
        let mut flight = Flight::for_tests(pipeline);
        flight.ctx.request_snapshot = Some(praxis_filter::Request {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
        });
        flight
    }
}
