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
//! moving and the deadlines keep firing. Client writes go through the
//! session's cancel-safe task writer, which keeps a partial write's
//! progress when the loop polls another arm. Each direction holds at most
//! one chunk: the next read toward a peer waits until that peer accepts
//! the last one, which passes its backpressure on to the sender.

use std::{io, pin::pin, task::Poll, time::Duration};

use bytes::{Buf as _, Bytes, BytesMut};
use pingora_core::protocols::http::HttpTask;
use pingora_proxy::Session;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::{Instant, sleep_until, timeout_at},
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
}

/// The downstream (client) side of a tunnel.
///
/// Factored out of the Pingora session so the pump loop can be tested
/// against an in-memory duplex pair. Reads and writes share one session,
/// so a single [`next_event`](Self::next_event) waits on both.
#[async_trait::async_trait]
pub(super) trait TunnelDownstream: Send {
    /// Queue one chunk for the client. The pump queues the next write only
    /// after [`DownstreamEvent::Written`] reports this one.
    fn queue_chunk(&mut self, chunk: Bytes);

    /// Half-close toward the client after the destination's: no more
    /// destination bytes follow, but the client may keep sending. Called
    /// only with no chunk queued.
    async fn close_write(&mut self);

    /// Wait for the queued write to finish or, when `read` is set, for the
    /// next client read, whichever comes first.
    ///
    /// Cancel-safe: a write cancelled mid-chunk resumes where it stopped,
    /// and a cancelled read has consumed no bytes.
    async fn next_event(&mut self, read: bool) -> DownstreamEvent;
}

#[async_trait::async_trait]
impl TunnelDownstream for Session {
    fn queue_chunk(&mut self, chunk: Bytes) {
        self.as_downstream_mut()
            .send_downstream_proxy_task(HttpTask::UpgradedBody(Some(chunk), false));
    }

    async fn close_write(&mut self) {
        // A write-side shutdown of the client socket (a FIN after any
        // buffered bytes), not the end of the response body: ending the
        // body would also stop the session reading the client's upload.
        self.as_downstream_mut().shutdown().await;
    }

    async fn next_event(&mut self, read: bool) -> DownstreamEvent {
        let session = self.as_downstream_mut();
        // The read and the write both borrow the session, so each poll
        // builds both futures afresh and drops whichever is pending. Neither
        // loses progress: the task writer keeps a partial write in the
        // session, and a pending body read has consumed nothing.
        std::future::poll_fn(|cx| {
            if session.has_pending_downstream_proxy_tasks()
                && let Poll::Ready(written) = pin!(session.write_downstream_proxy_tasks()).poll(cx)
            {
                return Poll::Ready(DownstreamEvent::Written(
                    written.map(|_end| ()).map_err(io::Error::other),
                ));
            }
            if read && let Poll::Ready(chunk) = pin!(session.read_request_body()).poll(cx) {
                return Poll::Ready(DownstreamEvent::Read(chunk.map_err(io::Error::other)));
            }
            Poll::Pending
        })
        .await
    }
}

/// Mutable pump state.
struct TunnelState {
    /// Bytes relayed client to destination.
    bytes_in: u64,

    /// Bytes relayed destination to client.
    bytes_out: u64,

    /// Whether the client half-closed.
    downstream_done: bool,

    /// Whether the destination half-closed, once its last bytes reached
    /// the client.
    upstream_done: bool,

    /// Size of the chunk toward the client the session has not finished
    /// writing, if any.
    client_write: Option<u64>,

    /// When the tunnel next goes idle; reset on any progress.
    idle_deadline: Instant,

    /// Hard close deadline, when `max_duration` is configured.
    hard_deadline: Option<Instant>,
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
        downstream_done: false,
        upstream_done: false,
        client_write: None,
        idle_deadline: Instant::now() + idle_timeout,
        hard_deadline: max_duration.map(|duration| Instant::now() + duration),
    };
    let hard_deadline = state.hard_deadline;
    let relay = relay_loop(downstream, upstream, &mut state, idle_timeout);
    // The loop's deadline arm cannot fire while an arm's handler awaits (a
    // half-close passed on to either peer); bounding the whole loop keeps
    // the hard deadline there too.
    let reason = match hard_deadline {
        Some(deadline) => timeout_at(deadline, relay)
            .await
            .unwrap_or(TunnelCloseReason::MaxDuration),
        None => relay.await,
    };
    let TunnelState {
        bytes_in, bytes_out, ..
    } = state;
    TunnelStats {
        bytes_in,
        bytes_out,
        reason,
    }
}

/// The relay loop: one `select!` over both directions and the deadlines.
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
        // Wake at the earlier of the idle and hard deadlines so a short
        // max_duration is not masked by a longer idle timeout.
        let wake = state
            .hard_deadline
            .map_or(state.idle_deadline, |hard| state.idle_deadline.min(hard));
        let read_client = pending.is_empty() && !state.downstream_done;
        let closed = tokio::select! {
            event = downstream.next_event(read_client), if read_client || state.client_write.is_some() => {
                take_downstream_event(&mut upstream_writer, &mut pending, state, idle_timeout, event).await
            },
            written = upstream_writer.write(&pending), if !pending.is_empty() => {
                record_destination_write(state, idle_timeout, written, &mut pending)
            },
            read = upstream_reader.read_buf(&mut upstream_buffer),
                if state.client_write.is_none() && !state.upstream_done => {
                relay_upstream_chunk(downstream, state, idle_timeout, read, &mut upstream_buffer).await
            },
            () = sleep_until(wake) => Some(deadline_reason(state)),
        };
        if let Some(reason) = closed {
            return reason;
        }
        if state.downstream_done && state.upstream_done {
            return TunnelCloseReason::Completed;
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

/// Take one client-side event: a client read, or a finished client write.
///
/// Returns `Some(reason)` when the tunnel should close.
async fn take_downstream_event<W>(
    upstream: &mut W,
    pending: &mut Bytes,
    state: &mut TunnelState,
    idle_timeout: Duration,
    event: DownstreamEvent,
) -> Option<TunnelCloseReason>
where
    W: AsyncWrite + Unpin,
{
    match event {
        DownstreamEvent::Read(chunk) => take_downstream_chunk(upstream, pending, state, idle_timeout, chunk).await,
        DownstreamEvent::Written(written) => record_client_write(state, idle_timeout, written),
    }
}

/// Take one downstream read: queue its bytes for the destination, or pass
/// on the client's half-close.
///
/// Returns `Some(reason)` when the tunnel should close.
async fn take_downstream_chunk<W>(
    upstream: &mut W,
    pending: &mut Bytes,
    state: &mut TunnelState,
    idle_timeout: Duration,
    chunk: io::Result<Option<Bytes>>,
) -> Option<TunnelCloseReason>
where
    W: AsyncWrite + Unpin,
{
    match chunk {
        Ok(Some(bytes)) => {
            state.idle_deadline = Instant::now() + idle_timeout;
            *pending = bytes;
        },
        Ok(None) => {
            // Client half-close: propagate it so the destination can finish.
            state.downstream_done = true;
            state.idle_deadline = Instant::now() + idle_timeout;
            if let Err(error) = upstream.shutdown().await {
                warn!(error = %error, phase = "destination_shutdown", "tunnel_error");
                return Some(TunnelCloseReason::Error);
            }
        },
        Err(error) => {
            warn!(error = %error, phase = "downstream_read", "tunnel_error");
            return Some(TunnelCloseReason::Error);
        },
    }
    None
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
/// A destination EOF is passed on as a half-close: the client sees the end
/// of the destination's bytes but may keep sending, since the destination
/// may still be reading (a request finished only after its response, say).
/// Returns `Some(reason)` when the tunnel should close.
async fn relay_upstream_chunk<D>(
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
            // is queued and the client has received all it was sent.
            state.upstream_done = true;
            state.idle_deadline = Instant::now() + idle_timeout;
            downstream.close_write().await;
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
    }

    impl DuplexDownstream {
        /// Wrap the pump-facing end of a duplex pair.
        fn new(stream: DuplexStream) -> Self {
            Self {
                stream,
                queued: Bytes::new(),
                writing: false,
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
    }

    #[async_trait::async_trait]
    impl TunnelDownstream for DuplexDownstream {
        fn queue_chunk(&mut self, chunk: Bytes) {
            self.queued = chunk;
            self.writing = true;
        }

        async fn close_write(&mut self) {
            // A duplex shutdown ends only this end's writes; it keeps reading.
            let _closed = self.stream.shutdown().await;
        }

        async fn next_event(&mut self, read: bool) -> DownstreamEvent {
            std::future::poll_fn(|cx| {
                if self.writing
                    && let Poll::Ready(written) = self.poll_queued(cx)
                {
                    return Poll::Ready(DownstreamEvent::Written(written));
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
