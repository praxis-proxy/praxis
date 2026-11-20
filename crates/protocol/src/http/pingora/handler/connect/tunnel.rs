// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bidirectional byte pump for established CONNECT tunnels.
//!
//! One task relays both directions with `select!`: a client read, a
//! destination write, a destination read, a client write, and a wake-up at
//! the earlier of the idle and hard deadlines. Any progress resets the idle
//! deadline. The downstream side sits behind [`TunnelDownstream`] so the
//! loop is unit-testable against an in-memory duplex pair.
//!
//! Every read and write is its own `select!` arm, so a peer that stops
//! reading stalls only the direction toward it: the other direction keeps
//! moving and the deadlines keep firing. A half-close passed on to a peer
//! is one more write toward it, polled like the others: on a TLS listener
//! the client's is a `close_notify`, which a client that is not reading
//! does not accept, and its upload keeps flowing meanwhile. No arm's handler
//! awaits, so the loop is always back polling every arm. Client writes go
//! through the session's cancel-safe task writer, which keeps a partial
//! write's progress when the loop polls another arm. Each direction holds
//! at most one chunk: the next read toward a peer waits until that peer
//! accepts the last one, which passes its backpressure on to the sender.

use std::{io, pin::pin, task::Poll, time::Duration};

use bytes::{Buf as _, Bytes, BytesMut};
use pingora_core::protocols::http::HttpTask;
use pingora_proxy::Session;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::{Instant, sleep_until},
};
use tracing::warn;

/// Upstream read buffer size: one common TLS record ceiling.
const READ_BUFFER_BYTES: usize = 16_384; // 16 KiB

/// Why a tunnel closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunnelCloseReason {
    /// Both peers closed their side, each passed on to the other.
    Completed,
    /// A read or write failed mid-tunnel.
    Error,
    /// No progress in either direction for the idle timeout.
    IdleTimeout,
    /// The hard maximum duration elapsed.
    MaxDuration,
}

impl TunnelCloseReason {
    /// Stable log label, matching the TCP proxy's `connection_close` reasons.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Error => "error",
            Self::IdleTimeout => "idle_timeout",
            Self::MaxDuration => "max_duration",
        }
    }
}

/// Tunnel byte totals and close reason.
#[derive(Debug)]
pub(super) struct TunnelStats {
    /// Bytes relayed client to destination.
    pub(super) bytes_in: u64,

    /// Bytes relayed destination to client.
    pub(super) bytes_out: u64,

    /// Why the tunnel closed.
    pub(super) reason: TunnelCloseReason,
}

/// One event on the client side of a tunnel.
pub(super) enum DownstreamEvent {
    /// A client read finished: the next chunk, or `None` at client EOF.
    Read(io::Result<Option<Bytes>>),

    /// The queued write toward the client finished.
    Written(io::Result<()>),

    /// The half-close toward the client finished.
    Closed,
}

/// The downstream (client) side of a tunnel.
///
/// Factored out of the Pingora session so the pump loop can be tested
/// against an in-memory duplex pair. Reads, writes, and the half-close
/// share one session, so a single [`next_event`](Self::next_event) waits
/// on all of them.
#[async_trait::async_trait]
pub(super) trait TunnelDownstream: Send {
    /// Queue one chunk for the client. The pump queues the next write only
    /// after [`DownstreamEvent::Written`] reports this one.
    fn queue_chunk(&mut self, chunk: Bytes);

    /// Wait for the queued write to finish, for the half-close toward the
    /// client to finish when `close` is set, or, when `read` is set, for
    /// the next client read, whichever comes first.
    ///
    /// The half-close follows the destination's: no more destination bytes
    /// follow, but the client may keep sending. The pump asks for it only
    /// with no chunk queued, on every call until [`DownstreamEvent::Closed`]
    /// reports it.
    ///
    /// Cancel-safe: a write or half-close cancelled midway resumes where it
    /// stopped, and a cancelled read has consumed no bytes.
    async fn next_event(&mut self, read: bool, close: bool) -> DownstreamEvent;
}

#[async_trait::async_trait]
impl TunnelDownstream for Session {
    fn queue_chunk(&mut self, chunk: Bytes) {
        self.as_downstream_mut()
            .send_downstream_proxy_task(HttpTask::UpgradedBody(Some(chunk), false));
    }

    async fn next_event(&mut self, read: bool, close: bool) -> DownstreamEvent {
        let session = self.as_downstream_mut();
        // The write, the half-close, and the read all borrow the session, so
        // each poll builds them afresh and drops whichever is pending. None
        // loses progress: the task writer keeps a partial write in the
        // session, a shutdown polled again resumes where it stopped (TLS
        // queues its close_notify once, then flushes it), and a pending body
        // read has consumed nothing.
        std::future::poll_fn(|cx| {
            if session.has_pending_downstream_proxy_tasks()
                && let Poll::Ready(written) = pin!(session.write_downstream_proxy_tasks()).poll(cx)
            {
                return Poll::Ready(DownstreamEvent::Written(
                    written.map(|_end| ()).map_err(io::Error::other),
                ));
            }
            // A write-side shutdown of the client socket (a FIN after any
            // buffered bytes), not the end of the response body: ending the
            // body would also stop the session reading the client's upload.
            if close && pin!(session.shutdown()).poll(cx).is_ready() {
                return Poll::Ready(DownstreamEvent::Closed);
            }
            if read && let Poll::Ready(chunk) = pin!(session.read_request_body()).poll(cx) {
                return Poll::Ready(DownstreamEvent::Read(chunk.map_err(io::Error::other)));
            }
            Poll::Pending
        })
        .await
    }
}

/// How far one peer's half-close has been passed on to the other peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HalfClose {
    /// The peer is still sending.
    Open,

    /// The peer has finished sending, and the shutdown toward the other
    /// peer is under way; the other direction keeps moving meanwhile.
    Passing,

    /// The other peer has been shut down too.
    Passed,
}

/// Mutable pump state.
struct TunnelState {
    /// Bytes relayed client to destination.
    bytes_in: u64,

    /// Bytes relayed destination to client.
    bytes_out: u64,

    /// The client's half-close, passed on to the destination once the
    /// client bytes before it have drained.
    downstream_close: HalfClose,

    /// The destination's half-close, passed on to the client once its last
    /// bytes have reached the client.
    upstream_close: HalfClose,

    /// Size of the chunk toward the client the session has not finished
    /// writing, if any.
    client_write: Option<u64>,

    /// When the tunnel next goes idle; reset on any progress.
    idle_deadline: Instant,

    /// Hard close deadline, when `max_duration` is configured.
    hard_deadline: Option<Instant>,
}

impl TunnelState {
    /// When the deadline arm wakes: the earlier of the idle and hard
    /// deadlines, so a short `max_duration` is not masked by a longer idle
    /// timeout.
    fn wake(&self) -> Instant {
        self.hard_deadline
            .map_or(self.idle_deadline, |hard| self.idle_deadline.min(hard))
    }

    /// [`TunnelCloseReason::Completed`] once both half-closes have been
    /// passed on.
    fn completed(&self) -> Option<TunnelCloseReason> {
        (self.downstream_close == HalfClose::Passed && self.upstream_close == HalfClose::Passed)
            .then_some(TunnelCloseReason::Completed)
    }
}

/// Relay bytes between `downstream` and `upstream` until the tunnel closes.
pub(super) async fn pump<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    idle_timeout: Duration,
    max_duration: Option<Duration>,
) -> TunnelStats
where
    D: TunnelDownstream,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut state = TunnelState {
        bytes_in: 0,
        bytes_out: 0,
        downstream_close: HalfClose::Open,
        upstream_close: HalfClose::Open,
        client_write: None,
        idle_deadline: Instant::now() + idle_timeout,
        hard_deadline: max_duration.map(|duration| Instant::now() + duration),
    };
    let reason = relay_loop(downstream, upstream, &mut state, idle_timeout).await;
    TunnelStats {
        bytes_in: state.bytes_in,
        bytes_out: state.bytes_out,
        reason,
    }
}

/// The relay loop: one `select!` over both directions and the deadlines.
///
/// No handler awaits, so the loop is back in `select!` after every event,
/// polling both directions and the deadlines.
async fn relay_loop<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    state: &mut TunnelState,
    idle_timeout: Duration,
) -> TunnelCloseReason
where
    D: TunnelDownstream,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let mut upstream_buffer = BytesMut::with_capacity(READ_BUFFER_BYTES);
    // Client bytes read but not yet accepted by the destination. The next
    // client read waits until they drain, which bounds the buffering to one
    // chunk and passes the destination's backpressure on to the client. The
    // destination read waits the same way on `state.client_write`.
    let mut pending = Bytes::new();
    loop {
        let wake = state.wake();
        let read_client = pending.is_empty() && state.downstream_close == HalfClose::Open;
        let close_client = state.upstream_close == HalfClose::Passing;
        let closed = tokio::select! {
            event = downstream.next_event(read_client, close_client),
                if read_client || close_client || state.client_write.is_some() => {
                take_downstream_event(&mut pending, state, idle_timeout, event)
            },
            written = write_destination(&mut upstream_writer, &pending),
                if !pending.is_empty() || state.downstream_close == HalfClose::Passing => {
                take_destination_write(state, idle_timeout, written, &mut pending)
            },
            read = upstream_reader.read_buf(&mut upstream_buffer),
                if state.client_write.is_none() && state.upstream_close == HalfClose::Open => {
                relay_upstream_chunk(downstream, state, idle_timeout, read, &mut upstream_buffer)
            },
            () = sleep_until(wake) => Some(deadline_reason(state)),
        };
        if let Some(reason) = closed.or_else(|| state.completed()) {
            return reason;
        }
    }
}

/// Why the deadline arm woke: the hard deadline when it has passed, else
/// the idle deadline.
fn deadline_reason(state: &TunnelState) -> TunnelCloseReason {
    if state.hard_deadline.is_some_and(|hard| Instant::now() >= hard) {
        TunnelCloseReason::MaxDuration
    } else {
        TunnelCloseReason::IdleTimeout
    }
}

/// Take one client-side event: a client read, a finished client write, or
/// the finished half-close toward the client.
///
/// Returns `Some(reason)` when the tunnel should close.
fn take_downstream_event(
    pending: &mut Bytes,
    state: &mut TunnelState,
    idle_timeout: Duration,
    event: DownstreamEvent,
) -> Option<TunnelCloseReason> {
    match event {
        DownstreamEvent::Read(chunk) => take_downstream_chunk(pending, state, idle_timeout, chunk),
        DownstreamEvent::Written(written) => record_client_write(state, idle_timeout, written),
        DownstreamEvent::Closed => {
            state.upstream_close = HalfClose::Passed;
            state.idle_deadline = Instant::now() + idle_timeout;
            None
        },
    }
}

/// Take one downstream read: queue its bytes for the destination, or start
/// passing the client's half-close on to it.
///
/// Returns `Some(reason)` when the tunnel should close.
fn take_downstream_chunk(
    pending: &mut Bytes,
    state: &mut TunnelState,
    idle_timeout: Duration,
    chunk: io::Result<Option<Bytes>>,
) -> Option<TunnelCloseReason> {
    match chunk {
        Ok(Some(bytes)) => {
            state.idle_deadline = Instant::now() + idle_timeout;
            *pending = bytes;
        },
        Ok(None) => {
            // Client half-close: the destination write arm passes it on, so
            // the destination can finish. The client read waits on every
            // chunk before it, so no client bytes are pending.
            state.downstream_close = HalfClose::Passing;
            state.idle_deadline = Instant::now() + idle_timeout;
        },
        Err(error) => {
            warn!(error = %error, phase = "downstream_read", "tunnel_error");
            return Some(TunnelCloseReason::Error);
        },
    }
    None
}

/// One finished write toward the destination.
enum DestinationWrite {
    /// A write of pending client bytes: how many the destination accepted.
    Written(io::Result<usize>),

    /// The client's half-close, passed on.
    Closed(io::Result<()>),
}

/// Write the pending client bytes to the destination or, once the client
/// has half-closed and they have drained, pass the half-close on.
///
/// Cancel-safe: a cancelled write has written nothing, and a cancelled
/// shutdown resumes where it stopped.
async fn write_destination<W>(upstream: &mut W, pending: &[u8]) -> DestinationWrite
where
    W: AsyncWrite + Unpin,
{
    if pending.is_empty() {
        DestinationWrite::Closed(upstream.shutdown().await)
    } else {
        DestinationWrite::Written(upstream.write(pending).await)
    }
}

/// Take one finished destination write: client bytes it accepted, or the
/// client's half-close passed on.
///
/// Returns `Some(reason)` when the tunnel should close.
fn take_destination_write(
    state: &mut TunnelState,
    idle_timeout: Duration,
    written: DestinationWrite,
    pending: &mut Bytes,
) -> Option<TunnelCloseReason> {
    match written {
        DestinationWrite::Written(written) => record_destination_write(state, idle_timeout, written, pending),
        DestinationWrite::Closed(Ok(())) => {
            state.downstream_close = HalfClose::Passed;
            state.idle_deadline = Instant::now() + idle_timeout;
            None
        },
        DestinationWrite::Closed(Err(error)) => {
            warn!(error = %error, phase = "destination_shutdown", "tunnel_error");
            Some(TunnelCloseReason::Error)
        },
    }
}

/// Count one destination write and drop the bytes it accepted.
///
/// Only accepted bytes are counted, so a tunnel that closes mid-chunk
/// reports what the destination actually received. Returns `Some(reason)`
/// when the tunnel should close.
fn record_destination_write(
    state: &mut TunnelState,
    idle_timeout: Duration,
    written: io::Result<usize>,
    pending: &mut Bytes,
) -> Option<TunnelCloseReason> {
    match written {
        Ok(0) => {
            warn!(
                phase = "destination_write",
                "tunnel_error: destination accepted no bytes"
            );
            Some(TunnelCloseReason::Error)
        },
        Ok(accepted) => {
            state.idle_deadline = Instant::now() + idle_timeout;
            pending.advance(accepted.min(pending.len()));
            state.bytes_in = state.bytes_in.saturating_add(byte_count(accepted));
            None
        },
        Err(error) => {
            warn!(error = %error, phase = "destination_write", "tunnel_error");
            Some(TunnelCloseReason::Error)
        },
    }
}

/// Queue one upstream read for the client.
///
/// A destination EOF starts passing a half-close on to the client: the
/// client sees the end of the destination's bytes but may keep sending,
/// since the destination may still be reading (a request finished only
/// after its response, say). Returns `Some(reason)` when the tunnel should
/// close.
fn relay_upstream_chunk<D>(
    downstream: &mut D,
    state: &mut TunnelState,
    idle_timeout: Duration,
    read: io::Result<usize>,
    buffer: &mut BytesMut,
) -> Option<TunnelCloseReason>
where
    D: TunnelDownstream,
{
    match read {
        Ok(0) => {
            // The destination read waits on every chunk before it, so none
            // is queued and the client has received all it was sent. The
            // client event arm passes the half-close on: on a TLS listener a
            // close_notify, which a client that is not reading takes only
            // later, while its upload keeps flowing.
            state.upstream_close = HalfClose::Passing;
            state.idle_deadline = Instant::now() + idle_timeout;
            None
        },
        Ok(_) => {
            state.idle_deadline = Instant::now() + idle_timeout;
            let chunk = buffer.split().freeze();
            state.client_write = Some(byte_count(chunk.len()));
            downstream.queue_chunk(chunk);
            None
        },
        Err(error) => {
            warn!(error = %error, phase = "upstream_read", "tunnel_error");
            Some(TunnelCloseReason::Error)
        },
    }
}

/// Count one finished write toward the client.
///
/// A chunk counts only once the client accepted all of it, so a tunnel
/// that closes mid-write reports what the client received. A client that
/// stops reading makes no progress, and the idle deadline closes the
/// tunnel. Returns `Some(reason)` when the tunnel should close.
fn record_client_write(
    state: &mut TunnelState,
    idle_timeout: Duration,
    written: io::Result<()>,
) -> Option<TunnelCloseReason> {
    let len = state.client_write.take();
    if let Err(error) = written {
        warn!(error = %error, phase = "downstream_write", "tunnel_error");
        return Some(TunnelCloseReason::Error);
    }
    state.idle_deadline = Instant::now() + idle_timeout;
    state.bytes_out = state.bytes_out.saturating_add(len.unwrap_or(0));
    None
}

/// A byte length as a counter increment.
fn byte_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::pin::Pin;

    use tokio::{
        io::{DuplexStream, ReadBuf},
        time::{sleep, timeout},
    };

    use super::*;

    /// In-memory downstream: the pump side of a duplex pair.
    ///
    /// Mirrors the session's cancel-safe task writer: the unwritten rest of
    /// the queued chunk lives here, not in the write future, so a cancelled
    /// write resumes where it stopped.
    struct DuplexDownstream {
        /// The pump-facing end of the client duplex pair.
        stream: DuplexStream,

        /// The unwritten rest of the queued chunk.
        queued: Bytes,

        /// Whether a chunk is queued.
        writing: bool,

        /// Whether the half-close toward the client never finishes, as a
        /// TLS `close_notify` written to a client that stopped reading
        /// never does.
        close_blocks: bool,
    }

    impl DuplexDownstream {
        /// Wrap the pump-facing end of a duplex pair.
        fn new(stream: DuplexStream) -> Self {
            Self {
                stream,
                queued: Bytes::new(),
                writing: false,
                close_blocks: false,
            }
        }

        /// Poll the queued chunk's bytes.
        fn poll_queued(&mut self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
            while !self.queued.is_empty() {
                match Pin::new(&mut self.stream).poll_write(cx, &self.queued) {
                    Poll::Ready(Ok(written)) => self.queued.advance(written),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            self.writing = false;
            Poll::Ready(Ok(()))
        }

        /// Poll one client read.
        fn poll_read_chunk(&mut self, cx: &mut std::task::Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
            let mut storage = vec![0_u8; READ_BUFFER_BYTES];
            let mut buffer = ReadBuf::new(&mut storage);
            std::task::ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buffer))?;
            let filled = buffer.filled();
            Poll::Ready(Ok((!filled.is_empty()).then(|| Bytes::copy_from_slice(filled))))
        }

        /// Poll the half-close toward the client.
        fn poll_close(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
            if self.close_blocks {
                return Poll::Pending;
            }
            // A duplex shutdown ends only this end's writes; it keeps reading.
            Pin::new(&mut self.stream).poll_shutdown(cx).map(|_closed| ())
        }
    }

    #[async_trait::async_trait]
    impl TunnelDownstream for DuplexDownstream {
        fn queue_chunk(&mut self, chunk: Bytes) {
            self.queued = chunk;
            self.writing = true;
        }

        async fn next_event(&mut self, read: bool, close: bool) -> DownstreamEvent {
            std::future::poll_fn(|cx| {
                if self.writing
                    && let Poll::Ready(written) = self.poll_queued(cx)
                {
                    return Poll::Ready(DownstreamEvent::Written(written));
                }
                if close && self.poll_close(cx).is_ready() {
                    return Poll::Ready(DownstreamEvent::Closed);
                }
                if read && let Poll::Ready(chunk) = self.poll_read_chunk(cx) {
                    return Poll::Ready(DownstreamEvent::Read(chunk));
                }
                Poll::Pending
            })
            .await
        }
    }

    #[tokio::test]
    async fn pump_relays_both_directions_until_close() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut server = server;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_secs(10), None).await });

        client.write_all(b"ping").await.unwrap();
        let mut from_client = [0_u8; 4];
        server.read_exact(&mut from_client).await.unwrap();
        assert_eq!(&from_client, b"ping", "client bytes must reach the destination");

        server.write_all(b"pong").await.unwrap();
        let mut from_server = [0_u8; 4];
        client.read_exact(&mut from_server).await.unwrap();
        assert_eq!(&from_server, b"pong", "destination bytes must reach the client");

        // Client half-close propagates to the destination; the destination
        // close finishes the tunnel and the client sees EOF.
        client.shutdown().await.unwrap();
        let mut eof = [0_u8; 1];
        let read = server.read(&mut eof).await.unwrap();
        assert_eq!(read, 0, "destination must see the client half-close");

        server.shutdown().await.unwrap();
        let stats = pump_task.await.unwrap();
        assert_eq!(stats.reason, TunnelCloseReason::Completed);
        assert_eq!(stats.bytes_in, 4, "client-to-destination bytes counted");
        assert_eq!(stats.bytes_out, 4, "destination-to-client bytes counted");
        let read = client.read(&mut eof).await.unwrap();
        assert_eq!(read, 0, "client must see EOF after the destination closes");
    }

    #[tokio::test]
    async fn pump_closes_after_idle_timeout() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        let stats = pump(&mut downstream, &mut upstream, Duration::from_millis(50), None).await;
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        assert_eq!(stats.bytes_in, 0, "no traffic was relayed");
        assert_eq!(stats.bytes_out, 0, "no traffic was relayed");
        // Keep both peer ends alive for the pump's lifetime so neither
        // direction could have seen EOF.
        drop((client, server));
    }

    #[tokio::test]
    async fn pump_closes_at_max_duration_before_idle_timeout() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        // A max_duration shorter than the idle timeout must win the wake-up.
        let stats = pump(
            &mut downstream,
            &mut upstream,
            Duration::from_secs(10),
            Some(Duration::from_millis(50)),
        )
        .await;
        assert_eq!(stats.reason, TunnelCloseReason::MaxDuration);
        drop((client, server));
    }

    #[tokio::test]
    async fn pump_progress_resets_idle_deadline() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        // Six writes 100 ms apart span 500 ms; without an idle reset on
        // progress the 500 ms idle timeout would close the tunnel early.
        let writer = tokio::spawn(async move {
            let mut client = client;
            for _ in 0..6 {
                sleep(Duration::from_millis(100)).await;
                let _ignored = client.write_all(b"chunk").await;
            }
            drop(client);
        });

        let started = Instant::now();
        let stats = pump(&mut downstream, &mut upstream, Duration::from_millis(500), None).await;
        let elapsed = started.elapsed();
        writer.await.unwrap();
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        assert!(
            stats.bytes_in > 0,
            "the writes must have been relayed before the idle close"
        );
        assert!(
            elapsed >= Duration::from_millis(800),
            "progress must reset the idle deadline: closed after {elapsed:?}"
        );
        drop(server);
    }

    /// Bytes each peer sends in the simultaneous-send tests: far more than
    /// the 64-byte pipes hold, so both directions must keep moving at once.
    const SIMULTANEOUS_BYTES: usize = 65_536; // 64 KiB

    /// Write [`SIMULTANEOUS_BYTES`] of `fill`, then read as many back.
    async fn send_then_receive(mut stream: DuplexStream, fill: u8) -> Vec<u8> {
        stream.write_all(&vec![fill; SIMULTANEOUS_BYTES]).await.unwrap();
        let mut received = vec![0_u8; SIMULTANEOUS_BYTES];
        stream.read_exact(&mut received).await.unwrap();
        received
    }

    /// Send and receive [`SIMULTANEOUS_BYTES`] of `fill` concurrently.
    async fn send_while_receiving(stream: DuplexStream, fill: u8) -> Vec<u8> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let send = async {
            writer.write_all(&vec![fill; SIMULTANEOUS_BYTES]).await.unwrap();
            writer
        };
        let receive = async {
            let mut received = vec![0_u8; SIMULTANEOUS_BYTES];
            reader.read_exact(&mut received).await.unwrap();
            received
        };
        let (_writer, received) = tokio::join!(send, receive);
        received
    }

    #[tokio::test]
    async fn client_write_does_not_block_client_reads() {
        // The client sends everything before it reads, while the destination
        // reads and writes at once. A connection without the proxy completes
        // this; the tunnel must too, so a pending write toward the client
        // must not stop the pump reading what the client sends.
        let (client, pump_side) = tokio::io::duplex(64);
        let (mut upstream, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_secs(1), None).await });

        let (from_server, from_client) = timeout(Duration::from_secs(5), async {
            tokio::join!(send_then_receive(client, b'c'), send_while_receiving(server, b's'))
        })
        .await
        .expect("both directions must complete while the client writes before reading");
        assert!(
            from_server.iter().all(|&byte| byte == b's'),
            "destination bytes reach the client"
        );
        assert!(
            from_client.iter().all(|&byte| byte == b'c'),
            "client bytes reach the destination"
        );
        let stats = pump_task.await.unwrap();
        assert_eq!(stats.bytes_in, 65_536, "client-to-destination bytes counted");
        assert_eq!(stats.bytes_out, 65_536, "destination-to-client bytes counted");
    }

    #[tokio::test]
    async fn simultaneous_full_duplex_sends_complete() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (mut upstream, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_secs(1), None).await });

        let (from_server, from_client) = timeout(Duration::from_secs(5), async {
            tokio::join!(send_while_receiving(client, b'c'), send_while_receiving(server, b's'))
        })
        .await
        .expect("both directions must complete when both peers send at once");
        assert!(
            from_server.iter().all(|&byte| byte == b's'),
            "destination bytes reach the client"
        );
        assert!(
            from_client.iter().all(|&byte| byte == b'c'),
            "client bytes reach the destination"
        );
        pump_task.abort();
    }

    #[tokio::test]
    async fn stalled_destination_keeps_relaying_to_the_client() {
        // The destination never reads, so its 64-byte pipe fills and the
        // client-to-destination write blocks; destination bytes must still
        // reach the client meanwhile.
        let (client, pump_side) = tokio::io::duplex(1_048_576);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut server = server;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_secs(10), None).await });

        client.write_all(&[b'x'; 4096]).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        server.write_all(b"pong").await.unwrap();
        let mut from_server = [0_u8; 4];
        timeout(Duration::from_secs(2), client.read_exact(&mut from_server))
            .await
            .expect("destination bytes must not wait on the stalled destination write")
            .unwrap();
        assert_eq!(&from_server, b"pong");

        // The destination goes away without reading the rest: the pending
        // client bytes cannot be delivered, and the tunnel ends on the write.
        drop(server);
        let stats = pump_task.await.unwrap();
        assert_eq!(stats.reason, TunnelCloseReason::Error);
        assert_eq!(stats.bytes_out, 4, "destination-to-client bytes counted");
        assert!(
            stats.bytes_in < 4096,
            "only the bytes the destination accepted are counted: {}",
            stats.bytes_in
        );
    }

    #[tokio::test]
    async fn blocked_half_close_toward_the_client_closes_at_idle_timeout() {
        // On TLS the half-close writes a close_notify, which a client that
        // stopped reading never accepts. The idle timeout must still close
        // the tunnel, with no max_duration configured.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, mut server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        downstream.close_blocks = true;
        let mut upstream = upstream_side;
        server.shutdown().await.unwrap();

        let stats = timeout(
            Duration::from_secs(2),
            pump(&mut downstream, &mut upstream, Duration::from_millis(200), None),
        )
        .await
        .expect("the idle timeout must close a tunnel stuck passing on a half-close");
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        drop((client, server));
    }

    #[tokio::test]
    async fn blocked_half_close_toward_the_destination_closes_at_idle_timeout() {
        // A destination shutdown that cannot flush must not outlive the idle
        // timeout either.
        let (mut client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = ShutdownBlocks(upstream_side);
        client.shutdown().await.unwrap();

        let stats = timeout(
            Duration::from_secs(2),
            pump(&mut downstream, &mut upstream, Duration::from_millis(200), None),
        )
        .await
        .expect("the idle timeout must close a tunnel stuck passing on a half-close");
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        drop((client, server));
    }

    /// A destination stream whose shutdown never finishes, as one that must
    /// flush into a peer that stopped reading.
    struct ShutdownBlocks(DuplexStream);

    impl AsyncRead for ShutdownBlocks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ShutdownBlocks {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn pending_half_close_toward_the_client_keeps_relaying_the_upload() {
        // The destination finishes at once, but the client takes no
        // half-close (on TLS, a close_notify to a client that is not
        // reading). Its upload must still reach the destination in full, and
        // the tunnel cannot complete while the half-close is pending.
        let (mut client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        downstream.close_blocks = true;
        let mut upstream = upstream_side;
        let (mut server_reader, mut server_writer) = tokio::io::split(server);
        server_writer.shutdown().await.unwrap();
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_millis(500), None).await });

        let upload = vec![b'u'; 8192];
        let send = async {
            client
                .write_all(&upload)
                .await
                .expect("the tunnel must keep reading the upload");
            client.shutdown().await.unwrap();
        };
        let mut received = Vec::new();
        let receive = server_reader.read_to_end(&mut received);
        let ((), read) = timeout(Duration::from_secs(2), async { tokio::join!(send, receive) })
            .await
            .expect("the upload must flow while the half-close toward the client is pending");
        read.unwrap();
        assert_eq!(received.len(), upload.len(), "no client byte is dropped");
        let stats = pump_task.await.unwrap();
        assert_eq!(
            stats.reason,
            TunnelCloseReason::IdleTimeout,
            "the tunnel waits on its half-close toward the client"
        );
        assert_eq!(stats.bytes_in, 8192, "client-to-destination bytes counted");
        drop((client, server_reader, server_writer));
    }

    #[tokio::test]
    async fn pending_half_close_toward_the_destination_keeps_relaying_the_answer() {
        // The client finishes at once, but the destination's shutdown never
        // does. Its answer must still reach the client in full meanwhile.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, mut server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = ShutdownBlocks(upstream_side);
        let (mut client_reader, mut client_writer) = tokio::io::split(client);
        client_writer.shutdown().await.unwrap();
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_millis(500), None).await });

        let answer = vec![b'a'; 8192];
        let send = async {
            server
                .write_all(&answer)
                .await
                .expect("the tunnel must keep reading the answer");
            server.shutdown().await.unwrap();
        };
        let mut received = Vec::new();
        let receive = client_reader.read_to_end(&mut received);
        let ((), read) = timeout(Duration::from_secs(2), async { tokio::join!(send, receive) })
            .await
            .expect("the answer must flow while the half-close toward the destination is pending");
        read.unwrap();
        assert_eq!(received.len(), answer.len(), "no destination byte is dropped");
        let stats = pump_task.await.unwrap();
        assert_eq!(
            stats.reason,
            TunnelCloseReason::IdleTimeout,
            "the tunnel waits on its half-close toward the destination"
        );
        assert_eq!(stats.bytes_out, 8192, "destination-to-client bytes counted");
        drop((client_reader, client_writer, server));
    }

    #[tokio::test]
    async fn destination_half_close_keeps_relaying_the_client_upload() {
        // The destination answers and closes its write side, then keeps
        // reading: the client's upload must still reach it in full.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;
        let pump_task =
            tokio::spawn(async move { pump(&mut downstream, &mut upstream, Duration::from_secs(2), None).await });

        let (mut server_reader, mut server_writer) = tokio::io::split(server);
        server_writer.write_all(b"answer").await.unwrap();
        server_writer.shutdown().await.unwrap();
        let (mut client_reader, mut client_writer) = tokio::io::split(client);
        let mut answer = Vec::new();
        timeout(Duration::from_secs(2), client_reader.read_to_end(&mut answer))
            .await
            .expect("the client must see the destination's EOF")
            .unwrap();
        assert_eq!(answer, b"answer", "the half-close reaches the client after the answer");

        let upload = vec![b'u'; 8192];
        let send = async {
            client_writer.write_all(&upload).await.unwrap();
            client_writer.shutdown().await.unwrap();
        };
        let mut received = Vec::new();
        let receive = server_reader.read_to_end(&mut received);
        let ((), read) = timeout(Duration::from_secs(2), async { tokio::join!(send, receive) })
            .await
            .expect("the upload must reach the destination after its half-close");
        read.unwrap();
        assert_eq!(received.len(), upload.len(), "no client byte is dropped");
        let stats = pump_task.await.unwrap();
        assert_eq!(stats.reason, TunnelCloseReason::Completed, "both sides closed");
        assert_eq!((stats.bytes_in, stats.bytes_out), (8192, 6));
    }

    #[tokio::test]
    async fn stalled_destination_cannot_outlive_max_duration() {
        let (client, pump_side) = tokio::io::duplex(1_048_576);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;
        // Keep the client busy so the idle deadline never fires first.
        let writer = tokio::spawn(async move {
            for _ in 0..40 {
                if client.write_all(&[b'x'; 1024]).await.is_err() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
            client
        });

        let stats = timeout(
            Duration::from_secs(2),
            pump(
                &mut downstream,
                &mut upstream,
                Duration::from_secs(10),
                Some(Duration::from_millis(200)),
            ),
        )
        .await
        .expect("max_duration must close a tunnel whose destination stopped reading");
        assert_eq!(stats.reason, TunnelCloseReason::MaxDuration);
        drop((writer.await.unwrap(), server));
    }

    #[tokio::test]
    async fn stalled_destination_closes_at_idle_timeout() {
        let (client, pump_side) = tokio::io::duplex(1_048_576);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        client.write_all(&[b'x'; 4096]).await.unwrap();
        let stats = timeout(
            Duration::from_secs(2),
            pump(&mut downstream, &mut upstream, Duration::from_millis(200), None),
        )
        .await
        .expect("the idle timeout must close a tunnel stalled on a destination write");
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        drop((client, server));
    }

    #[tokio::test]
    async fn stalled_client_closes_at_idle_timeout() {
        // The client never reads, so the write toward it stays pending and
        // nothing progresses; the idle deadline must close the tunnel even
        // with no hard deadline.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(1_048_576);
        let mut server = server;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        server.write_all(&[b'y'; 4096]).await.unwrap();
        let stats = timeout(
            Duration::from_secs(2),
            pump(&mut downstream, &mut upstream, Duration::from_millis(200), None),
        )
        .await
        .expect("the idle timeout must close a tunnel stalled on a client write");
        assert_eq!(stats.reason, TunnelCloseReason::IdleTimeout);
        drop((client, server));
    }

    #[tokio::test]
    async fn stalled_client_cannot_outlive_max_duration() {
        // A client write that never finishes must not hold the tunnel open
        // past a max_duration shorter than the idle timeout.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(1_048_576);
        let mut server = server;
        let mut downstream = DuplexDownstream::new(pump_side);
        let mut upstream = upstream_side;

        server.write_all(&[b'y'; 4096]).await.unwrap();
        let stats = timeout(
            Duration::from_secs(2),
            pump(
                &mut downstream,
                &mut upstream,
                Duration::from_secs(10),
                Some(Duration::from_millis(200)),
            ),
        )
        .await
        .expect("max_duration must close a tunnel whose client stopped reading");
        assert_eq!(stats.reason, TunnelCloseReason::MaxDuration);
        drop((client, server));
    }
}
