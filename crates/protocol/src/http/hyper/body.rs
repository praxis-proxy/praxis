// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The downstream response body and the relay feeding it.
//!
//! A local response carries its whole body; a proxied one is fed through a
//! small bounded channel by the task relaying the upstream body, so a slow
//! client holds back the upstream reads. The relay must say where the body
//! ends: a relay dropped before that aborts the response (an HTTP/2 stream
//! reset, an HTTP/1 connection close) instead of passing a cut-off body
//! off as complete.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Frames buffered between the relay and the client; small, so a slow
/// client applies backpressure upstream.
const RELAY_CAPACITY: usize = 2; // frames

/// How often [`Relay::flushed`] checks whether the client's body took
/// everything sent.
const FLUSH_POLL_INTERVAL: Duration = Duration::from_millis(1); // 1 ms

/// Checks [`Relay::flushed`] makes before giving up waiting.
const FLUSH_POLLS: u32 = 50; // checks, about 50 ms

// -----------------------------------------------------------------------------
// ProxyBody
// -----------------------------------------------------------------------------

/// The body hyper writes to the client.
#[derive(Debug)]
pub(super) struct ProxyBody {
    /// Where the body's frames come from.
    source: Source,
}

impl ProxyBody {
    /// No body.
    pub(super) fn empty() -> Self {
        Self {
            source: Source::Full(None),
        }
    }

    /// A whole body written at once; an empty one is no body.
    pub(super) fn full(bytes: Bytes) -> Self {
        Self {
            source: Source::Full(Some(bytes).filter(|bytes| !bytes.is_empty())),
        }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = BodyAborted;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyAborted>>> {
        match &mut self.get_mut().source {
            Source::Full(bytes) => Poll::Ready(bytes.take().map(|bytes| Ok(Frame::data(bytes)))),
            Source::Relay { ended, frames } => poll_relay(frames, ended, cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.source {
            Source::Full(bytes) => bytes.is_none(),
            Source::Relay { ended, .. } => *ended,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.source {
            Source::Full(bytes) => SizeHint::with_exact(
                bytes
                    .as_ref()
                    .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            ),
            Source::Relay { .. } => SizeHint::default(),
        }
    }
}

/// Where a [`ProxyBody`]'s frames come from.
#[derive(Debug)]
enum Source {
    /// A whole body, or none, written once.
    Full(Option<Bytes>),

    /// Frames from a [`Relay`].
    Relay {
        /// Whether the relay marked the end of the body.
        ended: bool,

        /// The frames the relay sends.
        frames: mpsc::Receiver<Piece>,
    },
}

/// One message from a [`Relay`] to its body.
#[derive(Debug)]
enum Piece {
    /// A data chunk.
    Data(Bytes),

    /// The end of the body.
    End,

    /// Trailers, which end the body.
    Trailers(HeaderMap),
}

// -----------------------------------------------------------------------------
// Relay
// -----------------------------------------------------------------------------

/// The sending half of a relayed body.
///
/// Every send waits for room, so a client that reads slowly slows down
/// whoever feeds the relay. Dropping it without [`end`] aborts the body.
///
/// [`end`]: Self::end
#[derive(Debug)]
pub(super) struct Relay {
    /// The channel to the body.
    frames: mpsc::Sender<Piece>,
}

impl Relay {
    /// A relay and the body it feeds.
    pub(super) fn new() -> (Self, ProxyBody) {
        let (sender, receiver) = mpsc::channel(RELAY_CAPACITY);
        let body = ProxyBody {
            source: Source::Relay {
                ended: false,
                frames: receiver,
            },
        };
        (Self { frames: sender }, body)
    }

    /// Resolve once the client is gone and the body was dropped.
    pub(super) async fn closed(&self) {
        self.frames.closed().await;
    }

    /// Send one data chunk; an empty one is skipped.
    ///
    /// # Errors
    ///
    /// Returns [`ClientGone`] when the client no longer reads the body.
    pub(super) async fn data(&self, chunk: Bytes) -> Result<(), ClientGone> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.send(Piece::Data(chunk)).await
    }

    /// Mark the end of the body.
    ///
    /// # Errors
    ///
    /// Returns [`ClientGone`] when the client no longer reads the body.
    pub(super) async fn end(&self) -> Result<(), ClientGone> {
        self.send(Piece::End).await
    }

    /// Wait, briefly, until the body has taken every frame sent so far, and
    /// a moment more for hyper to write them, so an abort that follows does
    /// not discard bytes already handed over.
    pub(super) async fn flushed(&self) {
        for _poll in 0..FLUSH_POLLS {
            if self.frames.capacity() == self.frames.max_capacity() {
                break;
            }
            tokio::time::sleep(FLUSH_POLL_INTERVAL).await;
        }
        tokio::time::sleep(FLUSH_POLL_INTERVAL).await;
    }

    /// Send one piece, waiting for room.
    async fn send(&self, piece: Piece) -> Result<(), ClientGone> {
        self.frames.send(piece).await.map_err(|_closed| ClientGone)
    }

    /// Send trailers, which end the body.
    ///
    /// # Errors
    ///
    /// Returns [`ClientGone`] when the client no longer reads the body.
    pub(super) async fn trailers(&self, trailers: HeaderMap) -> Result<(), ClientGone> {
        self.send(Piece::Trailers(trailers)).await
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// The client stopped reading the response body.
#[derive(Clone, Copy, Debug)]
pub(super) struct ClientGone;

/// A relayed body ended before its relay marked the end.
#[derive(Clone, Copy, Debug)]
pub(super) struct BodyAborted;

impl fmt::Display for BodyAborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the response body was aborted before it ended")
    }
}

impl std::error::Error for BodyAborted {}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Poll a relay's channel for the next frame.
fn poll_relay(
    frames: &mut mpsc::Receiver<Piece>,
    ended: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Bytes>, BodyAborted>>> {
    if *ended {
        return Poll::Ready(None);
    }
    let Poll::Ready(piece) = frames.poll_recv(cx) else {
        return Poll::Pending;
    };
    Poll::Ready(match piece {
        Some(Piece::Data(chunk)) => Some(Ok(Frame::data(chunk))),
        Some(Piece::Trailers(trailers)) => {
            *ended = true;
            Some(Ok(Frame::trailers(trailers)))
        },
        Some(Piece::End) => {
            *ended = true;
            None
        },
        None => {
            *ended = true;
            Some(Err(BodyAborted))
        },
    })
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
    use http_body_util::BodyExt as _;

    use super::*;

    #[tokio::test]
    async fn full_body_yields_its_bytes_once() {
        let body = ProxyBody::full(Bytes::from_static(b"hello"));
        assert_eq!(body.size_hint().exact(), Some(5), "a whole body has an exact size");

        let collected = body.collect().await.unwrap().to_bytes();

        assert_eq!(collected, "hello", "the whole body comes through");
    }

    #[test]
    fn empty_body_ends_with_the_head() {
        assert!(
            ProxyBody::empty().is_end_stream(),
            "no body means the stream ends with the head"
        );
        assert!(
            ProxyBody::full(Bytes::new()).is_end_stream(),
            "an empty whole body is no body"
        );
    }

    #[tokio::test]
    async fn relay_delivers_data_and_trailers() {
        let (relay, body) = Relay::new();
        let sender = tokio::spawn(async move {
            relay.data(Bytes::from_static(b"a")).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            relay.trailers(trailers).await.unwrap();
        });

        let collected = body.collect().await.unwrap();
        sender.await.unwrap();

        assert_eq!(
            collected.trailers().and_then(|t| t.get("grpc-status")).unwrap(),
            "0",
            "trailers reach the body"
        );
        assert_eq!(collected.to_bytes(), "a", "data reaches the body");
    }

    #[tokio::test]
    async fn dropped_relay_aborts_the_body() {
        let (relay, body) = Relay::new();
        relay.data(Bytes::from_static(b"part")).await.unwrap();
        drop(relay);

        let result = body.collect().await;

        assert!(result.is_err(), "a relay dropped before its end must abort the body");
    }

    #[tokio::test]
    async fn ended_relay_completes_the_body() {
        let (relay, body) = Relay::new();
        let sender = tokio::spawn(async move {
            relay.data(Bytes::from_static(b"done")).await.unwrap();
            relay.end().await.unwrap();
        });

        let collected = body.collect().await.unwrap().to_bytes();
        sender.await.unwrap();

        assert_eq!(collected, "done", "an ended relay completes the body");
    }

    #[tokio::test]
    async fn relay_reports_a_departed_client() {
        let (relay, body) = Relay::new();
        drop(body);

        relay.closed().await;

        assert!(
            relay.data(Bytes::from_static(b"x")).await.is_err(),
            "sending to a dropped body fails"
        );
    }
}
