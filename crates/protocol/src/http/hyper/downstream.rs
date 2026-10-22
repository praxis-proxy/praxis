// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The downstream request body, read under the listener's read timeout.
//!
//! Every frame read from the client is bounded by
//! `downstream_read_timeout_ms`, as Pingora bounds each read of the
//! downstream session, so a client that stalls mid-upload cannot hold a
//! request open.

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::BodyExt as _;
use hyper::body::{Body as _, Incoming};
use praxis_core::reserved_headers::is_reserved;

use super::failure::{Failure, FailureKind};

// -----------------------------------------------------------------------------
// DownstreamBody
// -----------------------------------------------------------------------------

/// The client's request body.
#[derive(Debug)]
pub(super) struct DownstreamBody {
    /// The body still to read; `None` once it ended.
    body: Option<Incoming>,

    /// Trailers consumed by pre-read, retained for upstream forwarding.
    pub(super) pre_read_trailers: Option<HeaderMap>,

    /// Bound on each frame read.
    read_timeout: Option<Duration>,
}

impl DownstreamBody {
    /// Read `body` with each frame bounded by `read_timeout`.
    pub(super) fn new(body: Incoming, read_timeout: Option<Duration>) -> Self {
        let body = (!body.is_end_stream()).then_some(body);
        Self {
            body,
            pre_read_trailers: None,
            read_timeout,
        }
    }

    /// Turn what the body yielded into a frame, or `None` for an empty one.
    fn accept(
        &mut self,
        frame: Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>,
    ) -> Result<Option<DownstreamFrame>, Failure> {
        let frame = match frame {
            None => {
                self.body = None;
                return Ok(Some(DownstreamFrame::End));
            },
            Some(Err(err)) => {
                self.body = None;
                return Err(Failure::downstream(
                    body_error_kind(&err),
                    format!("client request body failed: {err}"),
                ));
            },
            Some(Ok(frame)) => frame,
        };
        match frame.into_data() {
            Ok(chunk) if chunk.is_empty() => Ok(None),
            Ok(chunk) => Ok(Some(DownstreamFrame::Data(chunk))),
            Err(frame) => {
                self.body = None;
                frame.into_trailers().ok().map(accept_trailers).transpose()
            },
        }
    }

    /// Whether the request carries no body, or all of it was read.
    pub(super) fn is_done(&self) -> bool {
        self.body.is_none()
    }

    /// The next frame of the body.
    ///
    /// # Errors
    ///
    /// Returns a downstream [`Failure`] when the read timeout expires or
    /// the client breaks the body off or sends reserved trailer names.
    pub(super) async fn next(&mut self) -> Result<DownstreamFrame, Failure> {
        loop {
            let Some(body) = self.body.as_mut() else {
                return Ok(DownstreamFrame::End);
            };
            let frame = match self.read_timeout {
                Some(limit) => tokio::time::timeout(limit, body.frame())
                    .await
                    .map_err(|_elapsed| self.timed_out(limit))?,
                None => body.frame().await,
            };
            if let Some(frame) = self.accept(frame)? {
                return Ok(frame);
            }
        }
    }

    /// The failure for a read that outlasted `limit`; the body is given up.
    fn timed_out(&mut self, limit: Duration) -> Failure {
        self.body = None;
        Failure::downstream(
            FailureKind::DownstreamTimeout,
            format!("client request body read timed out after {} ms", limit.as_millis()),
        )
    }
}

/// One frame of the client's request body.
#[derive(Debug)]
pub(super) enum DownstreamFrame {
    /// A data chunk.
    Data(Bytes),

    /// The body ended.
    End,

    /// Trailers, which end the body.
    Trailers(HeaderMap),
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Reject client-controlled internal metadata before forwarding or retaining
/// request trailers for replay.
fn accept_trailers(trailers: HeaderMap) -> Result<DownstreamFrame, Failure> {
    if trailers.keys().any(|name| is_reserved(name.as_str())) {
        return Err(Failure::downstream(
            FailureKind::BadRequest,
            "client request trailers contain a reserved header name",
        ));
    }
    Ok(DownstreamFrame::Trailers(trailers))
}

/// What a failed client body read says about the client: a body that
/// broke the framing rules is a bad request, anything else a client that
/// went away.
fn body_error_kind(err: &hyper::Error) -> FailureKind {
    let io_kind = std::error::Error::source(err)
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .map(std::io::Error::kind);
    match io_kind {
        Some(std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput) => FailureKind::BadRequest,
        Some(_) | None => FailureKind::DownstreamClosed,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::http::hyper::test_utils::{client_request, client_request_h2};

    #[tokio::test]
    async fn bodiless_request_is_done_from_the_start() {
        let (request, _client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;

        let mut body = DownstreamBody::new(request.into_body(), None);

        assert!(body.is_done(), "a request without a body has nothing to read");
        assert!(
            matches!(body.next().await, Ok(DownstreamFrame::End)),
            "reading it yields the end at once"
        );
    }

    #[tokio::test]
    async fn chunks_come_through_then_the_end() {
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5\r\n\r\nhello").await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let first = body.next().await.unwrap();
        let second = body.next().await.unwrap();

        assert!(
            matches!(&first, DownstreamFrame::Data(chunk) if chunk == "hello"),
            "the body bytes come first: {first:?}"
        );
        assert!(
            matches!(second, DownstreamFrame::End),
            "the end follows the declared length: {second:?}"
        );
        assert!(body.is_done(), "the body was read to its end");
    }

    #[tokio::test]
    async fn chunked_trailers_end_the_body() {
        let (request, _client) = client_request(
            b"POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nx-checksum: 9\r\n\r\n",
        )
        .await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let data = body.next().await.unwrap();
        let trailers = body.next().await.unwrap();

        assert!(
            matches!(&data, DownstreamFrame::Data(chunk) if chunk == "abc"),
            "the chunk comes first: {data:?}"
        );
        assert!(
            matches!(&trailers, DownstreamFrame::Trailers(map) if map.get("x-checksum").is_some_and(|value| value == "9")),
            "the trailers end the body: {trailers:?}"
        );
        assert!(body.is_done(), "nothing is read after the trailers");
        assert!(
            matches!(body.next().await, Ok(DownstreamFrame::End)),
            "a read after the trailers is the end"
        );
    }

    #[tokio::test]
    async fn reserved_trailers_fail_before_they_can_be_retained() {
        for name in ["X-Praxis-Spoof", "X-Ext-Protocol-Spoof", "X-Ext-Agent-Spoof"] {
            let raw =
                format!("POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n{name}: forged\r\n\r\n");
            let (request, _client) = client_request(raw.as_bytes()).await;
            let mut body = DownstreamBody::new(request.into_body(), None);

            let failure = body
                .next()
                .await
                .expect_err("reserved trailers must never yield a frame");

            assert_eq!(failure.kind, FailureKind::BadRequest, "{name} is client input");
            assert!(body.is_done(), "rejected trailers end the body");
            assert!(
                body.pre_read_trailers.is_none(),
                "reserved trailers cannot be retained for replay"
            );
        }
    }

    #[tokio::test]
    async fn reserved_http2_trailers_are_rejected() {
        let (request, mut client) = client_request_h2().await;
        let mut body = DownstreamBody::new(request.into_body(), None);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-ext-agent-task", http::HeaderValue::from_static("forged"));
        client.h2_body.as_mut().unwrap().send_trailers(trailers).unwrap();

        let failure = body
            .next()
            .await
            .expect_err("HTTP/2 trailers have the same trust boundary");

        assert_eq!(failure.kind, FailureKind::BadRequest, "reject reserved client metadata");
        assert!(body.is_done(), "the rejected body is not read again");
    }

    #[tokio::test]
    async fn stalled_body_times_out_as_the_clients_failure() {
        let (request, _client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 10\r\n\r\nabc").await;
        let mut body = DownstreamBody::new(request.into_body(), Some(Duration::from_millis(50)));

        let first = body.next().await.unwrap();
        let stalled = body.next().await;

        assert!(
            matches!(&first, DownstreamFrame::Data(chunk) if chunk == "abc"),
            "what arrived is read: {first:?}"
        );
        let failure = stalled.expect_err("a client that stops sending trips the read timeout");
        assert_eq!(
            failure.kind,
            FailureKind::DownstreamTimeout,
            "the stall is the client's"
        );
        assert!(failure.detail.contains("50 ms"), "the timeout is named: {failure}");
        assert!(body.is_done(), "a timed-out body is given up");
    }

    #[tokio::test]
    async fn read_timeout_bounds_each_frame_not_the_whole_body() {
        let (request, mut client) = client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 6\r\n\r\nabc").await;
        let mut body = DownstreamBody::new(request.into_body(), Some(Duration::from_millis(200)));
        let first = body.next().await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut stream = client.stream.take().unwrap();
        stream.write_all(b"def").await.unwrap();

        let second = body.next().await.unwrap();

        assert!(
            matches!(&first, DownstreamFrame::Data(chunk) if chunk == "abc"),
            "the first part is read: {first:?}"
        );
        assert!(
            matches!(&second, DownstreamFrame::Data(chunk) if chunk == "def"),
            "a frame arriving inside its own bound is read: {second:?}"
        );
    }

    #[tokio::test]
    async fn malformed_chunk_size_is_a_bad_request() {
        let (request, _client) =
            client_request(b"POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n").await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let failure = body.next().await.expect_err("an unparsable chunk size fails the body");

        assert_eq!(
            failure.kind,
            FailureKind::BadRequest,
            "invalid input in the framing is the client's bad request: {failure}"
        );
        assert!(body.is_done(), "a failed body is given up");
    }

    #[tokio::test]
    async fn overflowing_chunk_size_is_a_bad_request() {
        let (request, _client) =
            client_request(b"POST / HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\nfffffffffffffffffff\r\n")
                .await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        let failure = body.next().await.expect_err("a chunk size past u64 fails the body");

        assert_eq!(
            failure.kind,
            FailureKind::BadRequest,
            "invalid data in the framing is the client's bad request: {failure}"
        );
    }

    #[tokio::test]
    async fn body_cut_short_is_a_client_that_went_away() {
        let (request, mut client) =
            client_request(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 10\r\n\r\nabc").await;
        let mut body = DownstreamBody::new(request.into_body(), None);
        let first = body.next().await.unwrap();

        drop(client.stream.take());
        let cut = body.next().await;

        assert!(
            matches!(&first, DownstreamFrame::Data(chunk) if chunk == "abc"),
            "what arrived is read: {first:?}"
        );
        let failure = cut.expect_err("a body that ends before its length fails");
        assert_eq!(
            failure.kind,
            FailureKind::DownstreamClosed,
            "an unexpected end of the stream is a client that went away: {failure}"
        );
        assert!(
            failure.detail.starts_with("client request body failed"),
            "the failure says where it came from: {failure}"
        );
    }

    #[tokio::test]
    async fn reset_http2_body_is_a_client_that_went_away() {
        let (request, mut client) = client_request_h2().await;
        let mut body = DownstreamBody::new(request.into_body(), None);

        client.h2_body.as_mut().unwrap().send_reset(h2::Reason::CANCEL);
        let reset = body.next().await;

        let failure = reset.expect_err("a reset stream fails the body");
        assert_eq!(
            failure.kind,
            FailureKind::DownstreamClosed,
            "an error that is not about the framing is a client that went away: {failure}"
        );
    }
}
