// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Sending the request body while waiting for the upstream's response head.
//!
//! The egress session is one object for both directions, so the two are
//! driven in turns: the queued body is handed over in bounded slices, and
//! whenever the upstream stops taking it, the response head is looked for
//! before the next slice; while nothing is queued, the response head and
//! the client's next body frame are raced (the session keeps a pending
//! head read across turns). An upstream that answers before the body is
//! done gets its answer through, and what is left of the body is only
//! forwarded with the response body afterwards, while the upstream reads.
//!
//! The cluster's read timeout bounds the wait for the head the way it does
//! on Pingora: it restarts when the client sends another body frame or the
//! upstream takes part of the body, and trips when the upstream neither
//! answers nor takes the body for that long.

use std::time::Duration;

use http::Version;
use praxis_core::egress::{EgressError, Session as _, hyper::HyperSession};

use super::{
    downstream::DownstreamFrame,
    failure::{Failure, FailureKind},
    service::Flight,
    upload::{Flush, Upload, UploadEnd},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How long a body send may wait for the upstream to take it before the
/// response head is looked for.
const SEND_SLICE: Duration = Duration::from_millis(20); // 20 ms

/// How long a look for the response head waits while the body is stuck.
const HEAD_PEEK: Duration = Duration::from_millis(1); // 1 ms

/// How long a failed body send waits for a response head the upstream may
/// have sent before it stopped reading.
const EARLY_ANSWER_GRACE: Duration = Duration::from_secs(1); // 1 s

/// Interim (`1xx`) responses tolerated before the final head, as the
/// sub-request client allows.
const MAX_INTERIM_RESPONSES: u32 = 32; // responses

// -----------------------------------------------------------------------------
// Timeouts
// -----------------------------------------------------------------------------

/// The cluster's bounds on one exchange's reads and writes.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timeouts {
    /// Bound on each read of the response.
    pub(super) read: Option<Duration>,

    /// Bound on each write of the request body.
    pub(super) write: Option<Duration>,
}

// -----------------------------------------------------------------------------
// Sending Until The Head
// -----------------------------------------------------------------------------

/// Send the body for this attempt and read the final response head, which
/// may arrive before the body is done.
///
/// # Errors
///
/// Returns [`UploadEnd`] when sending fails with no answer to take instead,
/// the client fails, a body filter stops the request, or the head does not
/// arrive in time.
pub(super) async fn send_until_head(
    upload: &mut Upload,
    flight: &mut Flight,
    session: &mut HyperSession,
    timeouts: Timeouts,
) -> Result<(), UploadEnd> {
    let h2 = session.negotiated_version() == Version::HTTP_2;
    upload.begin(&mut flight.ctx, h2, timeouts.write);
    let read_timeout = timeouts.read;
    loop {
        if Box::pin(drain(upload, session, read_timeout)).await? {
            return Ok(());
        }
        if !upload.is_live() {
            return Box::pin(read_final_head(session, read_timeout)).await;
        }
        if Box::pin(race_head(upload, flight, session, h2, read_timeout)).await? {
            return Ok(());
        }
    }
}

/// Read heads until the final one, skipping interim (`1xx`) responses
/// except `101`, each read bounded by `read_timeout`.
///
/// # Errors
///
/// Returns [`UploadEnd::Upstream`] when a read fails or times out, or the
/// upstream sends too many interim responses.
pub(super) async fn read_final_head(
    session: &mut HyperSession,
    read_timeout: Option<Duration>,
) -> Result<(), UploadEnd> {
    for _interim in 0..=MAX_INTERIM_RESPONSES {
        if session.response_head().is_ok() && is_final(session) {
            return Ok(());
        }
        let read = session.read_response_head();
        let result = match read_timeout {
            Some(limit) => tokio::time::timeout(limit, read)
                .await
                .map_err(|_elapsed| UploadEnd::Upstream(Failure::read_timeout(limit)))?,
            None => read.await,
        };
        result.map_err(UploadEnd::upstream)?;
        if is_final(session) {
            return Ok(());
        }
    }
    Err(UploadEnd::Upstream(Failure::new(
        FailureKind::ReadError,
        "upstream sent too many 1xx interim responses",
    )))
}

/// Whether the session's current head is final: not `1xx`, or `101`.
pub(super) fn is_final(session: &HyperSession) -> bool {
    session
        .response_head()
        .is_ok_and(|head| !(100..=199).contains(&head.status) || head.status == 101)
}

/// Hand over everything queued; returns `true` when the final response head
/// arrived first. An upstream that takes nothing and answers nothing for
/// `read_timeout` is given up on.
async fn drain(
    upload: &mut Upload,
    session: &mut HyperSession,
    read_timeout: Option<Duration>,
) -> Result<bool, UploadEnd> {
    loop {
        match upload.flush(session, SEND_SLICE).await {
            Ok(Flush::Done) => return Ok(false),
            Ok(Flush::Blocked | Flush::Taken) => {
                if peek_head(session).await? {
                    return Ok(true);
                }
                if let Some(limit) = read_timeout
                    && upload.stalled_for() >= limit
                {
                    return Err(UploadEnd::Upstream(Failure::read_timeout(limit)));
                }
            },
            // An upstream that answered early may have stopped taking the
            // body; its answer is what the client gets.
            Err(UploadEnd::Upstream(failure)) => return answered_instead(session, failure).await,
            Err(end) => return Err(end),
        }
    }
}

/// One turn with nothing queued: wait for either the response head or the
/// client's next body frame, for at most `read_timeout`. Returns `true` once
/// the final head arrived.
async fn race_head(
    upload: &mut Upload,
    flight: &mut Flight,
    session: &mut HyperSession,
    h2: bool,
    read_timeout: Option<Duration>,
) -> Result<bool, UploadEnd> {
    let turn = tokio::select! {
        biased;
        head = session.read_response_head() => Turn::Head(head),
        frame = upload.next_live() => Turn::Frame(frame),
        limit = after(read_timeout) => Turn::Overdue(limit),
    };
    match turn {
        Turn::Frame(frame) => {
            Box::pin(upload.accept(flight, frame, h2)).await?;
            Ok(false)
        },
        Turn::Head(Ok(())) => Ok(is_final(session)),
        Turn::Head(Err(err)) => Err(UploadEnd::upstream(err)),
        Turn::Overdue(limit) => Err(UploadEnd::Upstream(Failure::read_timeout(limit))),
    }
}

/// What one turn produced.
enum Turn {
    /// The client's next body frame.
    Frame(Result<DownstreamFrame, Failure>),

    /// The session read a response head.
    Head(Result<(), EgressError>),

    /// Neither arrived within the read timeout.
    Overdue(Duration),
}

/// Look, briefly, for a response head while the body is stuck; `true` when
/// the final one is there.
async fn peek_head(session: &mut HyperSession) -> Result<bool, UploadEnd> {
    match tokio::time::timeout(HEAD_PEEK, session.read_response_head()).await {
        Ok(Ok(())) => Ok(is_final(session)),
        Ok(Err(err)) => Err(UploadEnd::upstream(err)),
        Err(_not_yet) => Ok(false),
    }
}

/// After a failed send, take a response head the upstream already sent;
/// otherwise the send's failure stands.
async fn answered_instead(session: &mut HyperSession, failure: Failure) -> Result<bool, UploadEnd> {
    match read_final_head(session, Some(EARLY_ANSWER_GRACE)).await {
        Ok(()) => Ok(true),
        Err(_unanswered) => Err(UploadEnd::Upstream(failure)),
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Resolves with `limit` once it has passed; never without one.
async fn after(limit: Option<Duration>) -> Duration {
    match limit {
        Some(limit) => {
            tokio::time::sleep(limit).await;
            limit
        },
        None => std::future::pending().await,
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
    use bytes::Bytes;
    use http::Method;
    use praxis_core::egress::hyper::HyperConnector;
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::http::hyper::{
        downstream::DownstreamBody,
        test_utils::{
            Upstream, answered, client_request, empty_pipeline, queue_unread_body, session_to, streaming_upload,
        },
    };

    #[tokio::test]
    async fn interim_heads_are_not_final_but_switching_protocols_is() {
        let (_interim_upstream, _interim_connector, mut interim) =
            answered(b"HTTP/1.1 103 Early Hints\r\nlink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
        let (_switch_upstream, _switch_connector, switching) =
            answered(b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: x\r\n\r\n").await;

        let first = is_final(&interim);
        interim.read_response_head().await.unwrap();

        assert!(!first, "a 103 is not the final head");
        assert!(is_final(&interim), "the 200 after it is");
        assert!(is_final(&switching), "a 101 ends the head exchange");
    }

    #[tokio::test]
    async fn no_head_is_not_final() {
        let upstream = Upstream::stalled().await;
        let (_connector, session) = session_to(&upstream, Method::GET).await;

        assert!(!is_final(&session), "with no head read there is no final head");
    }

    #[tokio::test]
    async fn final_head_is_read_past_interim_ones() {
        let (_upstream, _connector, mut session) = sent(interim_then_final(2)).await;

        let read = read_final_head(&mut session, None).await;

        assert!(read.is_ok(), "the final head arrives after the interim ones");
        assert_eq!(session.response_head().unwrap().status, 200, "and is the current head");
    }

    #[tokio::test]
    async fn thirty_two_interim_heads_are_tolerated() {
        let (_upstream, _connector, mut session) = sent(interim_then_final(32)).await;

        let read = read_final_head(&mut session, None).await;

        assert!(read.is_ok(), "32 interim heads before the final one are allowed");
        assert_eq!(session.response_head().unwrap().status, 200, "the final head is read");
    }

    #[tokio::test]
    async fn thirty_three_interim_heads_are_too_many() {
        let (_upstream, _connector, mut session) = sent(interim_then_final(33)).await;

        let read = read_final_head(&mut session, None).await;

        assert!(
            matches!(&read, Err(UploadEnd::Upstream(failure)) if failure.kind == FailureKind::ReadError && failure.detail.contains("too many")),
            "an upstream that keeps sending interim heads is given up on"
        );
    }

    #[tokio::test]
    async fn each_head_read_is_bounded_by_the_read_timeout() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::GET).await;
        session.finish_request().await.unwrap();

        let read = read_final_head(&mut session, Some(Duration::from_millis(50))).await;

        assert!(
            matches!(&read, Err(UploadEnd::Upstream(failure)) if failure.kind == FailureKind::ReadTimeout),
            "a silent upstream trips the read timeout"
        );
    }

    #[tokio::test]
    async fn unparsable_head_fails_the_read() {
        let (_upstream, _connector, mut session) = sent(b"not http at all\r\n\r\n".to_vec()).await;

        let read = read_final_head(&mut session, None).await;

        assert!(
            matches!(&read, Err(UploadEnd::Upstream(failure)) if failure.kind == FailureKind::InvalidResponse),
            "a head hyper cannot parse is an invalid response"
        );
    }

    #[tokio::test]
    async fn peek_finds_a_head_that_already_arrived() {
        let upstream = Upstream::answering_early(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        session
            .send_request_body(Bytes::from_static(b"ab"), false)
            .await
            .unwrap();

        let mut found = false;
        for _peek in 0..500 {
            if matches!(peek_head(&mut session).await, Ok(true)) {
                found = true;
                break;
            }
        }

        assert!(found, "the early answer is found while the body is still open");
        assert_eq!(session.response_head().unwrap().status, 413, "and is the current head");
    }

    #[tokio::test]
    async fn peek_gives_up_quickly_when_nothing_arrived() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        session
            .send_request_body(Bytes::from_static(b"ab"), false)
            .await
            .unwrap();

        let peeked = tokio::time::timeout(Duration::from_secs(1), peek_head(&mut session)).await;

        assert!(
            matches!(peeked, Ok(Ok(false))),
            "with no head yet the peek returns at once"
        );
    }

    #[tokio::test]
    async fn early_answer_replaces_a_failed_send() {
        let upstream = Upstream::answering_early(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        session
            .send_request_body(Bytes::from_static(b"ab"), false)
            .await
            .unwrap();

        let taken = answered_instead(&mut session, Failure::new(FailureKind::WriteError, "body refused")).await;

        assert!(matches!(taken, Ok(true)), "the upstream's answer is taken instead");
        assert_eq!(session.response_head().unwrap().status, 413, "the client gets it");
    }

    #[tokio::test]
    async fn failed_send_stands_without_an_answer() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        session
            .send_request_body(Bytes::from_static(b"ab"), false)
            .await
            .unwrap();

        let taken = answered_instead(&mut session, Failure::new(FailureKind::WriteError, "body refused")).await;

        assert!(
            matches!(&taken, Err(UploadEnd::Upstream(failure)) if failure.kind == FailureKind::WriteError),
            "with nothing to answer instead, the send's failure is what the request ends with"
        );
    }

    #[tokio::test]
    async fn bodiless_request_is_sent_and_answered() {
        let upstream = Upstream::answering(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::GET).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (request, _client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
        let mut upload = Upload::new(DownstreamBody::new(request.into_body(), None), &flight.ctx);

        let sent = send_until_head(&mut upload, &mut flight, &mut session, timeouts()).await;

        assert!(sent.is_ok(), "the request goes out and its head comes back");
        assert_eq!(session.response_head().unwrap().status, 200, "the final head is read");
        assert!(upload.is_settled(), "the upstream has the whole (empty) body");
    }

    #[tokio::test]
    async fn early_answer_comes_through_while_the_client_still_sends() {
        let upstream = Upstream::answering_early(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;

        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            send_until_head(&mut upload, &mut flight, &mut session, timeouts()),
        )
        .await;

        assert!(matches!(sent, Ok(Ok(()))), "the head arrives before the body is done");
        assert_eq!(session.response_head().unwrap().status, 401, "the early answer is read");
        assert!(upload.is_live(), "the rest of the body is left for the response phase");
    }

    #[tokio::test]
    async fn client_body_is_forwarded_until_the_head_arrives() {
        let upstream = Upstream::answering(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, mut client) = streaming_upload(&flight.ctx).await;
        let mut stream = client.stream.take().unwrap();
        stream.write_all(b"2\r\nab\r\n0\r\n\r\n").await.unwrap();

        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            send_until_head(&mut upload, &mut flight, &mut session, timeouts()),
        )
        .await;

        assert!(matches!(sent, Ok(Ok(()))), "the exchange reaches the final head");
        assert_eq!(
            session.response_head().unwrap().status,
            200,
            "the upstream's answer is read"
        );
    }

    #[tokio::test]
    async fn client_that_hangs_up_mid_body_ends_the_exchange() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, mut client) = streaming_upload(&flight.ctx).await;
        let mut stream = client.stream.take().unwrap();
        stream.write_all(b"2\r\nab\r\n").await.unwrap();
        drop(stream);

        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            send_until_head(&mut upload, &mut flight, &mut session, timeouts()),
        )
        .await;

        assert!(
            matches!(&sent, Ok(Err(UploadEnd::Client(failure))) if failure.kind == FailureKind::DownstreamClosed),
            "the client's departure ends the exchange as the client's failure"
        );
    }

    #[tokio::test]
    async fn silent_upstream_trips_the_read_timeout_while_the_client_still_sends() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, mut client) = streaming_upload(&flight.ctx).await;
        let mut stream = client.stream.take().unwrap();
        stream.write_all(b"2\r\nab\r\n").await.unwrap();

        let sent = tokio::time::timeout(
            Duration::from_secs(3),
            send_until_head(&mut upload, &mut flight, &mut session, read_within(200)),
        )
        .await;

        assert!(
            matches!(&sent, Ok(Err(UploadEnd::Upstream(failure))) if failure.kind == FailureKind::ReadTimeout),
            "an upstream that answers nothing while the client still sends trips the read timeout"
        );
    }

    #[tokio::test]
    async fn upstream_that_stops_taking_the_body_trips_the_read_timeout() {
        let upstream = Upstream::stalled().await;
        let (_connector, mut session) = session_to(&upstream, Method::POST).await;
        let mut flight = Flight::for_tests(empty_pipeline());
        let (mut upload, _client) = streaming_upload(&flight.ctx).await;
        queue_unread_body(&mut upload, &mut flight).await;

        let drained = tokio::time::timeout(
            Duration::from_secs(3),
            drain(&mut upload, &mut session, Some(Duration::from_millis(200))),
        )
        .await;

        assert!(
            matches!(&drained, Ok(Err(UploadEnd::Upstream(failure))) if failure.kind == FailureKind::ReadTimeout),
            "an upstream that neither takes the body nor answers trips the read timeout"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// `count` interim `103` heads and then a bodiless `200`.
    fn interim_then_final(count: usize) -> Vec<u8> {
        let mut reply = b"HTTP/1.1 103 Early Hints\r\n\r\n".repeat(count);
        reply.extend_from_slice(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        reply
    }

    /// A bodiless `GET` sent to an upstream answering `reply`, no head read.
    async fn sent(reply: Vec<u8>) -> (Upstream, HyperConnector, HyperSession) {
        let upstream = Upstream::answering(reply.leak()).await;
        let (connector, mut session) = session_to(&upstream, Method::GET).await;
        session.finish_request().await.unwrap();
        (upstream, connector, session)
    }

    /// Exchange bounds with a read timeout of `millis` and no write timeout.
    const fn read_within(millis: u64) -> Timeouts {
        Timeouts {
            read: Some(Duration::from_millis(millis)),
            write: None,
        }
    }

    /// Exchange bounds with neither a read nor a write timeout.
    const fn timeouts() -> Timeouts {
        Timeouts {
            read: None,
            write: None,
        }
    }
}
