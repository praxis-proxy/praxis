// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bidirectional byte pump for established CONNECT tunnels.
//!
//! One task relays both directions with `select!`: a downstream read
//! (client to destination), an upstream read (destination to client), and
//! a wake-up at the earlier of the idle and hard deadlines. Any progress
//! resets the idle deadline. The downstream side sits behind
//! [`TunnelDownstream`] so the loop is unit-testable against an in-memory
//! duplex pair.
//!
//! Destination writes are their own `select!` arm over a split stream, so a
//! destination that stops reading stalls only the client-to-destination
//! direction: destination bytes keep reaching the client and the deadlines
//! keep firing. Client writes go through the one session that also reads,
//! so each runs under the idle timeout, and the whole loop under the hard
//! deadline. A peer that stops reading cannot hold a tunnel open past
//! either limit.

use std::{io, time::Duration};

use bytes::{Buf as _, Bytes, BytesMut};
use pingora_proxy::Session;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tracing::warn;

/// Upstream read buffer size: one common TLS record ceiling.
const READ_BUFFER_BYTES: usize = 16_384; // 16 KiB

/// Why a tunnel closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunnelCloseReason {
    /// The destination closed its side and the client was notified.
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

/// The downstream (client) side of a tunnel.
///
/// Factored out of the Pingora session so the pump loop can be tested
/// against an in-memory duplex pair. Reads are cancel-safe: the session's
/// body reader buffers partial reads, so a read cancelled by the other
/// direction's readiness loses no bytes.
#[async_trait::async_trait]
pub(super) trait TunnelDownstream: Send {
    /// Read the next client chunk; `Ok(None)` at client EOF.
    async fn read_chunk(&mut self) -> io::Result<Option<Bytes>>;

    /// Relay one chunk toward the client.
    async fn write_chunk(&mut self, chunk: Bytes) -> io::Result<()>;

    /// Finish the client write side after the destination closes.
    async fn finish(&mut self) -> io::Result<()>;
}

#[async_trait::async_trait]
impl TunnelDownstream for Session {
    async fn read_chunk(&mut self) -> io::Result<Option<Bytes>> {
        self.as_downstream_mut()
            .read_request_body()
            .await
            .map_err(io::Error::other)
    }

    async fn write_chunk(&mut self, chunk: Bytes) -> io::Result<()> {
        self.as_downstream_mut()
            .write_response_body(chunk, false)
            .await
            .map_err(io::Error::other)
    }

    async fn finish(&mut self) -> io::Result<()> {
        self.as_downstream_mut()
            .write_response_body(Bytes::new(), true)
            .await
            .map_err(io::Error::other)
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
        idle_deadline: Instant::now() + idle_timeout,
        hard_deadline: max_duration.map(|duration| Instant::now() + duration),
    };
    let hard_deadline = state.hard_deadline;
    let relay = relay_loop(downstream, upstream, &mut state, idle_timeout);
    // The loop checks the hard deadline only between relays; bounding the
    // whole loop also cuts off a write blocked on a peer that stopped reading.
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
#[expect(
    clippy::too_many_lines,
    reason = "one select! whose arms each need explicit error and EOF handling"
)]
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
    // chunk and passes the destination's backpressure on to the client.
    let mut pending = Bytes::new();
    loop {
        // Wake at the earlier of the idle and hard deadlines so a short
        // max_duration is not masked by a longer idle timeout.
        let wake = state
            .hard_deadline
            .map_or(state.idle_deadline, |hard| state.idle_deadline.min(hard));
        tokio::select! {
            chunk = downstream.read_chunk(), if pending.is_empty() && !state.downstream_done => {
                if let Some(reason) =
                    take_downstream_chunk(&mut upstream_writer, &mut pending, state, idle_timeout, chunk).await
                {
                    return reason;
                }
            },
            written = upstream_writer.write(&pending), if !pending.is_empty() => {
                if let Some(reason) = record_destination_write(state, idle_timeout, written, &mut pending) {
                    return reason;
                }
            },
            read = upstream_reader.read_buf(&mut upstream_buffer) => {
                if let Some(reason) =
                    relay_upstream_chunk(downstream, state, idle_timeout, read, &mut upstream_buffer).await
                {
                    return reason;
                }
            },
            () = sleep_until(wake) => {
                return if state.hard_deadline.is_some_and(|hard| Instant::now() >= hard) {
                    TunnelCloseReason::MaxDuration
                } else {
                    TunnelCloseReason::IdleTimeout
                };
            },
        }
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

/// Forward one upstream read to the client.
///
/// Returns `Some(reason)` when the tunnel should close. A destination EOF
/// finishes the client side and completes the tunnel: ending the response
/// closes the session, so the client-to-destination direction cannot
/// usefully continue.
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
        Ok(0) => Some(
            client_write(idle_timeout, "downstream_finish", downstream.finish())
                .await
                .unwrap_or(TunnelCloseReason::Completed),
        ),
        Ok(_) => {
            state.idle_deadline = Instant::now() + idle_timeout;
            let chunk = buffer.split().freeze();
            let len = byte_count(chunk.len());
            if let Some(reason) = client_write(idle_timeout, "downstream_write", downstream.write_chunk(chunk)).await {
                return Some(reason);
            }
            state.bytes_out = state.bytes_out.saturating_add(len);
            None
        },
        Err(error) => {
            warn!(error = %error, phase = "upstream_read", "tunnel_error");
            Some(TunnelCloseReason::Error)
        },
    }
}

/// Run one write toward the client under the idle timeout.
///
/// Client writes share the session with client reads, so they cannot be a
/// separate `select!` arm the way destination writes are; the timeout keeps
/// a client that stopped reading from stalling the tunnel. Returns
/// `Some(reason)` when the tunnel should close.
async fn client_write(
    idle_timeout: Duration,
    phase: &'static str,
    write: impl Future<Output = io::Result<()>>,
) -> Option<TunnelCloseReason> {
    match timeout(idle_timeout, write).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            warn!(error = %error, phase, "tunnel_error");
            Some(TunnelCloseReason::Error)
        },
        Err(_elapsed) => Some(TunnelCloseReason::IdleTimeout),
    }
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
    use tokio::{io::DuplexStream, time::sleep};

    use super::*;

    /// In-memory downstream: the pump side of a duplex pair.
    struct DuplexDownstream {
        /// The pump-facing end of the client duplex pair.
        stream: DuplexStream,
    }

    #[async_trait::async_trait]
    impl TunnelDownstream for DuplexDownstream {
        async fn read_chunk(&mut self) -> io::Result<Option<Bytes>> {
            let mut buffer = BytesMut::with_capacity(READ_BUFFER_BYTES);
            match self.stream.read_buf(&mut buffer).await? {
                0 => Ok(None),
                _ => Ok(Some(buffer.freeze())),
            }
        }

        async fn write_chunk(&mut self, chunk: Bytes) -> io::Result<()> {
            self.stream.write_all(&chunk).await
        }

        async fn finish(&mut self) -> io::Result<()> {
            self.stream.shutdown().await
        }
    }

    #[tokio::test]
    async fn pump_relays_both_directions_until_close() {
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut server = server;
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        let mut downstream = DuplexDownstream { stream: pump_side };
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

    #[tokio::test]
    async fn stalled_destination_keeps_relaying_to_the_client() {
        // The destination never reads, so its 64-byte pipe fills and the
        // client-to-destination write blocks; destination bytes must still
        // reach the client meanwhile.
        let (client, pump_side) = tokio::io::duplex(1_048_576);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut server = server;
        let mut downstream = DuplexDownstream { stream: pump_side };
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

        server.shutdown().await.unwrap();
        let stats = pump_task.await.unwrap();
        assert_eq!(stats.reason, TunnelCloseReason::Completed);
        assert_eq!(stats.bytes_out, 4, "destination-to-client bytes counted");
        assert!(
            stats.bytes_in < 4096,
            "only the bytes the destination accepted are counted: {}",
            stats.bytes_in
        );
    }

    #[tokio::test]
    async fn stalled_destination_cannot_outlive_max_duration() {
        let (client, pump_side) = tokio::io::duplex(1_048_576);
        let (upstream_side, server) = tokio::io::duplex(64);
        let mut client = client;
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        // The client never reads, so writes toward it block; the write
        // timeout must close the tunnel even with no hard deadline.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(1_048_576);
        let mut server = server;
        let mut downstream = DuplexDownstream { stream: pump_side };
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
        // A blocked client write holds the loop inside one relay, so only
        // the bound around the whole loop can enforce a max_duration shorter
        // than the idle timeout.
        let (client, pump_side) = tokio::io::duplex(64);
        let (upstream_side, server) = tokio::io::duplex(1_048_576);
        let mut server = server;
        let mut downstream = DuplexDownstream { stream: pump_side };
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
