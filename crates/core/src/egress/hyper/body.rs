// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The request body hyper reads from a session: a body known in full when
//! the request goes out, or frames a session feeds through a small bounded
//! channel so a slow upstream holds back whoever is producing the body.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Frames buffered between a session and the connection writing them.
const CHANNEL_CAPACITY: usize = 2; // frames

// -----------------------------------------------------------------------------
// RequestBody
// -----------------------------------------------------------------------------

/// The sending half of a streamed [`RequestBody`].
///
/// [`RequestBody`]: RequestBody
pub(super) type BodySender = mpsc::Sender<BodyFrame>;

/// One step of a streamed request body.
#[derive(Debug)]
pub(super) enum BodyFrame {
    /// A chunk with more to follow.
    Data(Bytes),

    /// The final chunk; empty when the body simply ends.
    Last(Bytes),

    /// Trailers, which end the body.
    Trailers(HeaderMap),
}

impl BodyFrame {
    /// Whether nothing follows this frame.
    pub(super) const fn ends_body(&self) -> bool {
        !matches!(self, Self::Data(_))
    }
}

/// A request body as hyper polls it.
///
/// A streamed body whose sender goes away before a [`BodyFrame::Last`] or
/// [`BodyFrame::Trailers`] fails with [`RequestBodyAborted`] instead of
/// ending, so a truncated upload never reaches the upstream as a complete
/// request.
///
/// [`BodyFrame::Last`]: BodyFrame::Last
/// [`BodyFrame::Trailers`]: BodyFrame::Trailers
/// [`RequestBodyAborted`]: RequestBodyAborted
#[derive(Debug)]
pub(super) enum RequestBody {
    /// A body known when the request is sent; `None` once yielded or empty.
    Full(Option<Bytes>),

    /// A body fed frame by frame through a [`BodySender`].
    ///
    /// [`BodySender`]: BodySender
    Channel {
        /// Whether the final frame has been yielded.
        ended: bool,

        /// Frames from the session.
        frames: mpsc::Receiver<BodyFrame>,
    },
}

impl RequestBody {
    /// A streamed body and the sender that feeds it.
    pub(super) fn channel() -> (BodySender, Self) {
        let (sender, frames) = mpsc::channel(CHANNEL_CAPACITY);
        (sender, Self::Channel { ended: false, frames })
    }

    /// A body with nothing in it.
    pub(super) const fn empty() -> Self {
        Self::Full(None)
    }

    /// A body of exactly `chunk`.
    pub(super) fn full(chunk: Bytes) -> Self {
        Self::Full((!chunk.is_empty()).then_some(chunk))
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = RequestBodyAborted;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full(chunk) => Poll::Ready(chunk.take().map(|chunk| Ok(Frame::data(chunk)))),
            Self::Channel { ended: true, .. } => Poll::Ready(None),
            Self::Channel { ended, frames } => {
                let frame = ready!(frames.poll_recv(cx));
                Poll::Ready(next_frame(frame, ended))
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(chunk) => chunk.is_none(),
            Self::Channel { ended, .. } => *ended,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(chunk) => {
                let length = chunk.as_ref().map_or(0, Bytes::len);
                SizeHint::with_exact(u64::try_from(length).unwrap_or(u64::MAX))
            },
            Self::Channel { ended: true, .. } => SizeHint::with_exact(0),
            Self::Channel { ended: false, .. } => SizeHint::default(),
        }
    }
}

// -----------------------------------------------------------------------------
// RequestBodyAborted
// -----------------------------------------------------------------------------

/// The session went away before it finished the request body.
#[derive(Debug, thiserror::Error)]
#[error("the request body was abandoned before it ended")]
pub(super) struct RequestBodyAborted;

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Turn what the channel delivered into the frame hyper sees, marking the
/// body `ended` once nothing can follow.
fn next_frame(frame: Option<BodyFrame>, ended: &mut bool) -> Option<Result<Frame<Bytes>, RequestBodyAborted>> {
    let Some(frame) = frame else {
        *ended = true;
        return Some(Err(RequestBodyAborted));
    };

    *ended = frame.ends_body();
    match frame {
        BodyFrame::Data(chunk) => Some(Ok(Frame::data(chunk))),
        BodyFrame::Last(chunk) => (!chunk.is_empty()).then(|| Ok(Frame::data(chunk))),
        BodyFrame::Trailers(trailers) => Some(Ok(Frame::trailers(trailers))),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::{pin::pin, time::Duration};

    use http_body_util::BodyExt as _;

    use super::*;

    #[tokio::test]
    async fn full_body_yields_its_chunk_then_ends() {
        let mut body = RequestBody::full(Bytes::from_static(b"hello"));

        assert_eq!(body.size_hint().exact(), Some(5), "a full body knows its length");
        assert!(!body.is_end_stream(), "a non-empty body has a frame to yield");
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), "hello", "the chunk comes back whole");
        assert!(body.is_end_stream(), "nothing follows the only chunk");
        assert!(body.frame().await.is_none(), "the body ends after its chunk");
    }

    #[test]
    fn empty_bodies_end_before_any_frame() {
        assert!(
            RequestBody::empty().is_end_stream(),
            "an empty body is already at its end"
        );
        assert!(
            RequestBody::full(Bytes::new()).is_end_stream(),
            "an empty chunk makes an empty body"
        );
        assert_eq!(
            RequestBody::empty().size_hint().exact(),
            Some(0),
            "an empty body has an exact zero length"
        );
    }

    #[tokio::test]
    async fn channel_body_streams_frames_until_the_last() {
        let (sender, mut body) = RequestBody::channel();

        assert_eq!(body.size_hint().exact(), None, "a streamed body has no known length");
        sender.send(BodyFrame::Data(Bytes::from_static(b"one"))).await.unwrap();
        sender.send(BodyFrame::Last(Bytes::from_static(b"two"))).await.unwrap();
        drop(sender);

        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, "one", "frames arrive in order");
        assert!(!body.is_end_stream(), "the body is open until its last frame");
        let last = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(last, "two", "the last frame still carries its chunk");
        assert!(body.is_end_stream(), "the body ends with its last frame");
        assert!(
            body.frame().await.is_none(),
            "a sender dropped after the last frame is not an abort"
        );
    }

    #[tokio::test]
    async fn channel_body_ends_with_trailers() {
        let (sender, mut body) = RequestBody::channel();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());

        sender.send(BodyFrame::Trailers(trailers)).await.unwrap();

        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_trailers().unwrap().get("grpc-status").unwrap(),
            "0",
            "trailers pass through as a trailers frame"
        );
        assert!(body.is_end_stream(), "trailers end the body");
    }

    #[tokio::test]
    async fn channel_body_without_a_last_frame_aborts() {
        let (sender, mut body) = RequestBody::channel();

        sender
            .send(BodyFrame::Data(Bytes::from_static(b"partial")))
            .await
            .unwrap();
        drop(sender);

        let delivered = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(delivered, "partial", "frames sent before the drop are still delivered");
        assert!(
            matches!(body.frame().await, Some(Err(RequestBodyAborted))),
            "a body that never ended must fail rather than look complete"
        );
        assert!(body.frame().await.is_none(), "an aborted body yields nothing more");
    }

    #[tokio::test(start_paused = true)]
    async fn channel_body_holds_two_frames_and_the_third_waits() {
        let (sender, mut body) = RequestBody::channel();
        sender.send(BodyFrame::Data(Bytes::from_static(b"one"))).await.unwrap();
        sender.send(BodyFrame::Data(Bytes::from_static(b"two"))).await.unwrap();
        let mut third = pin!(sender.send(BodyFrame::Data(Bytes::from_static(b"three"))));

        let waited = tokio::time::timeout(Duration::from_secs(1), &mut third).await.ok();
        let taken = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let resumed = tokio::time::timeout(Duration::from_secs(1), &mut third).await;

        assert!(waited.is_none(), "a third frame waits while the channel holds two");
        assert_eq!(taken, "one", "the oldest frame is taken first");
        assert!(
            matches!(resumed, Ok(Ok(()))),
            "taking a frame lets the waiting one in: {resumed:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_last_frame_just_ends_the_body() {
        let (sender, mut body) = RequestBody::channel();

        sender.send(BodyFrame::Last(Bytes::new())).await.unwrap();

        assert!(body.frame().await.is_none(), "an empty last frame yields no data frame");
        assert!(body.is_end_stream(), "the body is over");
    }
}
