// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Pingora-backed bidirectional TCP proxy application.

use std::{borrow::Cow, future::Future, io, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use praxis_filter::{FilterAction, FilterPipeline, TcpFilterContext};
use praxis_tls::sni;
use tokio::{
    io::AsyncReadExt as _,
    net::TcpStream,
    sync::{Semaphore, watch},
};
use tracing::{debug, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Initial peek buffer size for SNI extraction.
const PEEK_INITIAL: usize = 1024;

/// Maximum peek buffer size before giving up on SNI extraction.
const PEEK_MAX: usize = 16384; // 16 KiB

/// Timeout for upstream TCP connect (including DNS resolution).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for SNI peek phase.
///
/// Bounds the time a client can hold a connection during the initial
/// TLS `ClientHello` read. Without this, a slow-drip client could
/// hold a connection (and semaphore permit) indefinitely.
const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// PingoraTcpProxy
// -----------------------------------------------------------------------------

/// Pingora-backed bidirectional TCP proxy.
///
/// Supports two modes:
/// - **Static upstream**: the listener config provides a fixed `upstream` address.
/// - **Filter-routed**: the upstream is unset; filters (e.g. `sni_router`) set [`TcpFilterContext::upstream_addr`]
///   during `on_connect`.
///
/// When the proxy has no static upstream, it reads the first bytes of each
/// connection, extracts the TLS `ClientHello` SNI, and makes it available
/// to filters before connecting upstream.
///
/// The pipeline is held behind [`ArcSwap`] so it can be
/// atomically replaced by hot config reload without
/// disrupting in-flight connections.
///
/// [`TcpFilterContext::upstream_addr`]: praxis_filter::TcpFilterContext::upstream_addr
/// [`ArcSwap`]: arc_swap::ArcSwap
pub(crate) struct PingoraTcpProxy {
    /// Cluster name for load-balanced TCP connections.
    cluster: Option<Arc<str>>,

    /// Per-listener connection semaphore for max connections.
    connection_semaphore: Option<Arc<Semaphore>>,

    /// Optional session timeout for the bidirectional forwarding phase.
    session_timeout: Option<Duration>,

    /// Optional maximum total session duration.
    max_duration: Option<Duration>,

    /// Swappable filter pipeline for TCP filter hooks.
    pipeline: Arc<ArcSwap<FilterPipeline>>,

    /// Static upstream address, if configured on the listener.
    upstream_addr: Option<String>,
}

impl PingoraTcpProxy {
    /// Create a TCP proxy, optionally targeting a fixed upstream address.
    #[expect(clippy::too_many_arguments, reason = "per-listener configuration")]
    pub(super) fn new(
        upstream_addr: Option<String>,
        cluster: Option<Arc<str>>,
        pipeline: Arc<ArcSwap<FilterPipeline>>,
        session_timeout: Option<Duration>,
        max_duration: Option<Duration>,
        connection_semaphore: Option<Arc<Semaphore>>,
    ) -> Self {
        Self {
            cluster,
            connection_semaphore,
            session_timeout,
            max_duration,
            pipeline,
            upstream_addr,
        }
    }

    /// Run bidirectional forwarding, returning `(bytes_in, bytes_out)`.
    async fn forward(
        &self,
        session: &mut Stream,
        upstream: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
        upstream_addr: &str,
    ) -> (u64, u64) {
        let result = self.forward_inner(session, upstream, shutdown_rx, upstream_addr).await;

        match result {
            Some(Ok((c2s, s2c))) => (c2s, s2c),
            Some(Err(e)) => {
                debug!(upstream = %upstream_addr, error = %e, "TCP session ended");
                (0, 0)
            },
            None => (0, 0),
        }
    }

    /// Inner forwarding logic, optionally wrapped in a max-duration timeout.
    async fn forward_inner(
        &self,
        session: &mut Stream,
        upstream: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
        upstream_addr: &str,
    ) -> Option<io::Result<(u64, u64)>> {
        let copy_fut = async {
            let copy_future = tokio::io::copy_bidirectional(session, upstream);
            match self.session_timeout {
                Some(timeout) => forward_with_timeout(copy_future, shutdown_rx, timeout, upstream_addr).await,
                None => forward_no_timeout(copy_future, shutdown_rx).await,
            }
        };

        if let Some(max_dur) = self.max_duration {
            if let Ok(r) = tokio::time::timeout(max_dur, copy_fut).await {
                r
            } else {
                warn!(
                    upstream = %upstream_addr,
                    max_duration_secs = max_dur.as_secs(),
                    "TCP session exceeded maximum duration"
                );
                None
            }
        } else {
            copy_fut.await
        }
    }

    /// Run TCP connect filters; returns the resolved upstream address if allowed.
    async fn run_connect_filters(
        &self,
        remote_addr: &str,
        local_addr: &str,
        sni: Option<&str>,
        connect_time: std::time::Instant,
    ) -> Option<String> {
        let pipeline = self.pipeline.load();
        let upstream_cow = self.upstream_addr.as_deref().map(Cow::Borrowed);
        let health_registry = pipeline.health_registry().cloned();

        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            sni,
            upstream_addr: upstream_cow,
            cluster: self.cluster.clone(),
            health_registry: health_registry.as_ref(),
            kv_stores: pipeline.kv_stores(),
            connect_time,
            bytes_in: 0,
            bytes_out: 0,
        };

        resolve_connect_result(&pipeline, &mut ctx, remote_addr).await
    }

    /// Run TCP disconnect filters for logging.
    #[expect(clippy::too_many_arguments, reason = "per-connection metrics")]
    async fn run_disconnect_filters(
        &self,
        remote_addr: &str,
        local_addr: &str,
        upstream_addr: &str,
        sni_hostname: Option<&str>,
        connect_time: std::time::Instant,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let pipeline = self.pipeline.load();
        let health_registry = pipeline.health_registry().cloned();
        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            sni: sni_hostname,
            upstream_addr: Some(Cow::Borrowed(upstream_addr)),
            cluster: self.cluster.clone(),
            health_registry: health_registry.as_ref(),
            kv_stores: pipeline.kv_stores(),
            connect_time,
            bytes_in,
            bytes_out,
        };
        let _result = pipeline.execute_tcp_disconnect(&mut ctx).await;
    }
}

#[async_trait]
impl ServerApp for PingoraTcpProxy {
    #[expect(
        clippy::large_stack_frames,
        clippy::too_many_lines,
        reason = "linear connection lifecycle"
    )]
    async fn process_new(self: &Arc<Self>, mut session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let connect_time = std::time::Instant::now();
        let (remote_addr, local_addr) = extract_addrs(&session);

        if praxis_core::memory::is_exceeded() {
            warn!(remote = %remote_addr, "memory pressure threshold exceeded, closing TCP connection");
            return None;
        }

        let (exceeded, _global_permit) = crate::connections::try_acquire_global();
        if exceeded {
            warn!(remote = %remote_addr, "global max connections reached, closing TCP connection");
            return None;
        }

        let _permit = if let Some(sem) = &self.connection_semaphore {
            if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                Some(permit)
            } else {
                warn!(remote = %remote_addr, "max TCP connections reached, closing connection");
                return None;
            }
        } else {
            None
        };

        let (sni_hostname, peeked_bytes) = if self.upstream_addr.is_none() {
            let Ok(result) = tokio::time::timeout(SNI_PEEK_TIMEOUT, peek_sni(&mut session)).await else {
                warn!(remote = %remote_addr, "SNI peek timed out, closing connection");
                return None;
            };
            result
        } else {
            (None, Vec::new())
        };

        let upstream_addr = self
            .run_connect_filters(&remote_addr, &local_addr, sni_hostname.as_deref(), connect_time)
            .await?;

        let mut upstream = connect_upstream(&upstream_addr).await?;

        if !peeked_bytes.is_empty()
            && let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut upstream, &peeked_bytes).await
        {
            warn!(upstream = %upstream_addr, error = %e, "failed to write peeked bytes to upstream");
            self.run_disconnect_filters(
                &remote_addr,
                &local_addr,
                &upstream_addr,
                sni_hostname.as_deref(),
                connect_time,
                0,
                0,
            )
            .await;
            return None;
        }

        let mut shutdown_rx: watch::Receiver<bool> = shutdown.clone();
        let (bytes_in, bytes_out) = self
            .forward(&mut session, &mut upstream, &mut shutdown_rx, &upstream_addr)
            .await;

        self.run_disconnect_filters(
            &remote_addr,
            &local_addr,
            &upstream_addr,
            sni_hostname.as_deref(),
            connect_time,
            bytes_in,
            bytes_out,
        )
        .await;

        debug!(remote = %remote_addr, upstream = %upstream_addr, "closing TCP session (connections not pooled)");
        None
    }
}

// -----------------------------------------------------------------------------
// Connect Filter Resolution
// -----------------------------------------------------------------------------

/// Execute connect filters and resolve the upstream address.
async fn resolve_connect_result(
    pipeline: &FilterPipeline,
    ctx: &mut TcpFilterContext<'_>,
    remote_addr: &str,
) -> Option<String> {
    match pipeline.execute_tcp_connect(ctx).await {
        Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {
            if let Some(addr) = &ctx.upstream_addr {
                Some(addr.clone().into_owned())
            } else {
                warn!(remote = %remote_addr, "no upstream address resolved for TCP connection");
                None
            }
        },
        Ok(FilterAction::Reject(r)) => {
            warn!(remote = %remote_addr, status = r.status, "TCP connection rejected by filter");
            None
        },
        Err(e) => {
            warn!(remote = %remote_addr, error = %e, "TCP connect filter error");
            None
        },
    }
}

// -----------------------------------------------------------------------------
// SNI Peeking
// -----------------------------------------------------------------------------

/// Action returned by [`handle_sni_read`].
enum PeekAction {
    /// Parsing complete; contains the SNI hostname (or `None`).
    Done(Option<String>),

    /// Need more data from the socket.
    ReadMore,
}

/// Result of a single SNI parse attempt.
enum SniPeekResult {
    /// Successfully parsed; contains extracted info.
    Parsed(sni::ClientHelloInfo),

    /// Need more data to complete parsing.
    NeedMore,

    /// Buffer is not a TLS `ClientHello`.
    NotTls,
}

/// Peek at the first bytes of a connection to extract the SNI hostname.
///
/// Returns `(sni_hostname, peeked_bytes)`. The peeked bytes must be
/// forwarded to the upstream before starting bidirectional copy.
#[expect(clippy::indexing_slicing, reason = "filled <= buf.len() maintained by loop")]
async fn peek_sni(session: &mut Stream) -> (Option<String>, Vec<u8>) {
    let mut buf = vec![0_u8; PEEK_INITIAL];
    let mut filled = 0;

    loop {
        match session.read(&mut buf[filled..]).await {
            Ok(0) => {
                trace!(filled, "connection closed during SNI peek");
                break;
            },
            Ok(n) => {
                filled += n;
                if let PeekAction::Done(sni) = handle_sni_read(&mut buf, filled) {
                    return (sni, buf);
                }
            },
            Err(e) => {
                trace!(error = %e, "read error during SNI peek");
                break;
            },
        }
    }

    buf.truncate(filled);
    (None, buf)
}

/// Process a read chunk during SNI peeking.
fn handle_sni_read(buf: &mut Vec<u8>, filled: usize) -> PeekAction {
    match try_parse_sni(buf, filled) {
        SniPeekResult::Parsed(info) => {
            buf.truncate(filled);
            PeekAction::Done(info.sni)
        },
        SniPeekResult::NeedMore => {
            if filled >= PEEK_MAX {
                trace!("SNI peek reached max buffer size");
                buf.truncate(filled);
                return PeekAction::Done(None);
            }
            if filled == buf.len() {
                buf.resize((buf.len() * 2).min(PEEK_MAX), 0);
            }
            PeekAction::ReadMore
        },
        SniPeekResult::NotTls => {
            buf.truncate(filled);
            PeekAction::Done(None)
        },
    }
}

/// Attempt to parse SNI from the filled portion of the buffer.
#[expect(clippy::indexing_slicing, reason = "filled <= buf.len() maintained by caller")]
fn try_parse_sni(buf: &[u8], filled: usize) -> SniPeekResult {
    let data = &buf[..filled];
    match sni::parse_sni(data) {
        Ok(info) => SniPeekResult::Parsed(info),
        Err(sni::SniParseError::TooShort | sni::SniParseError::NeedMoreData) => SniPeekResult::NeedMore,
        Err(_) => {
            trace!(filled, "not a TLS ClientHello, skipping SNI extraction");
            SniPeekResult::NotTls
        },
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Extract remote and local address strings from a session.
fn extract_addrs(session: &Stream) -> (String, String) {
    let digest = session.get_socket_digest();
    let remote = digest
        .as_ref()
        .and_then(|d| d.peer_addr())
        .map_or_else(|| "unknown".to_owned(), ToString::to_string);
    let local = digest
        .as_ref()
        .and_then(|d| d.local_addr())
        .map_or_else(|| "unknown".to_owned(), ToString::to_string);
    (remote, local)
}

/// Forward with an idle timeout, returning `None` on shutdown or timeout.
async fn forward_with_timeout(
    copy_future: impl Future<Output = io::Result<(u64, u64)>>,
    shutdown_rx: &mut watch::Receiver<bool>,
    timeout: Duration,
    upstream_addr: &str,
) -> Option<io::Result<(u64, u64)>> {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => None,
        r = tokio::time::timeout(timeout, copy_future) => if let Ok(inner) = r {
            Some(inner)
        } else {
            #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
            let timeout_ms = timeout.as_millis() as u64;
            warn!(upstream = %upstream_addr, timeout_ms, "TCP session timed out");
            None
        },
    }
}

/// Forward without timeout, returning `None` on shutdown.
async fn forward_no_timeout(
    copy_future: impl Future<Output = io::Result<(u64, u64)>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<io::Result<(u64, u64)>> {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => None,
        r = copy_future => Some(r),
    }
}

/// Connect to the upstream TCP address with a timeout.
async fn connect_upstream(upstream_addr: &str) -> Option<TcpStream> {
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(upstream_addr)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            warn!(upstream = %upstream_addr, error = %e, "failed to connect to TCP upstream");
            None
        },
        Err(_) => {
            warn!(
                upstream = %upstream_addr,
                timeout_secs = UPSTREAM_CONNECT_TIMEOUT.as_secs(),
                "TCP upstream connect timed out"
            );
            None
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
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn try_parse_sni_valid_client_hello_with_sni() {
        let sni_ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);
        let filled = record.len();

        let result = try_parse_sni(&record, filled);
        assert!(
            matches!(&result, SniPeekResult::Parsed(info) if info.sni.as_deref() == Some("example.com")),
            "valid TLS ClientHello with SNI should return Parsed"
        );
    }

    #[test]
    fn try_parse_sni_empty_buffer() {
        let buf = [];
        let result = try_parse_sni(&buf, 0);
        assert!(
            matches!(result, SniPeekResult::NeedMore),
            "empty buffer should return NeedMore"
        );
    }

    #[test]
    fn try_parse_sni_non_tls_data() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_sni(buf, buf.len());
        assert!(
            matches!(result, SniPeekResult::NotTls),
            "HTTP request should return NotTls"
        );
    }

    #[test]
    fn try_parse_sni_truncated_client_hello() {
        let sni_ext = build_sni_extension("example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);
        let truncated = &record[..5];

        let result = try_parse_sni(truncated, 5);
        assert!(
            matches!(result, SniPeekResult::NeedMore),
            "truncated ClientHello (first 5 bytes) should return NeedMore"
        );
    }

    #[test]
    fn try_parse_sni_filled_less_than_buf_len() {
        let sni_ext = build_sni_extension("test.example.org");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);
        let filled = record.len();
        let mut padded = record.clone();
        padded.resize(filled + 512, 0);

        let result = try_parse_sni(&padded, filled);
        assert!(
            matches!(&result, SniPeekResult::Parsed(info) if info.sni.as_deref() == Some("test.example.org")),
            "should parse correctly using filled as slice bound"
        );
    }

    #[test]
    fn handle_sni_read_parsed_truncates_and_returns_done() {
        let sni_ext = build_sni_extension("parsed.example.com");
        let hello = build_client_hello(&[], &[0x00, 0xFF], &[0x00], &sni_ext);
        let record = wrap_in_record(&hello);
        let filled = record.len();
        let mut buf = record.clone();
        buf.resize(filled + 256, 0xAA);

        let action = handle_sni_read(&mut buf, filled);
        assert!(
            matches!(&action, PeekAction::Done(Some(sni)) if sni == "parsed.example.com"),
            "Parsed result should yield Done with SNI hostname"
        );
        assert_eq!(buf.len(), filled, "buf should be truncated to filled length");
    }

    #[test]
    fn handle_sni_read_need_more_below_peek_max_resizes_when_full() {
        let mut buf = vec![22, 3, 3, 0, 100, 1];
        let filled = buf.len();

        let action = handle_sni_read(&mut buf, filled);
        assert!(
            matches!(action, PeekAction::ReadMore),
            "NeedMore below PEEK_MAX should return ReadMore"
        );
        assert_eq!(
            buf.len(),
            filled * 2,
            "buf should double in size when filled == buf.len()"
        );
    }

    #[test]
    fn handle_sni_read_need_more_below_peek_max_no_resize_when_not_full() {
        let raw = [22_u8, 3, 3, 0, 100, 1];
        let mut buf = vec![0_u8; 1024];
        buf[..raw.len()].copy_from_slice(&raw);
        let filled = raw.len();

        let action = handle_sni_read(&mut buf, filled);
        assert!(
            matches!(action, PeekAction::ReadMore),
            "NeedMore below PEEK_MAX should return ReadMore"
        );
        assert_eq!(buf.len(), 1024, "buf should not resize when filled < buf.len()");
    }

    #[test]
    fn handle_sni_read_need_more_at_peek_max_returns_done_none() {
        let raw = [22_u8, 3, 3, 0, 100, 1];
        let mut buf = vec![0_u8; PEEK_MAX];
        buf[..raw.len()].copy_from_slice(&raw);
        let filled = PEEK_MAX;

        let action = handle_sni_read(&mut buf, filled);
        assert!(
            matches!(action, PeekAction::Done(None)),
            "NeedMore at PEEK_MAX should return Done(None)"
        );
        assert_eq!(
            buf.len(),
            PEEK_MAX,
            "buf should be truncated to filled (which equals PEEK_MAX)"
        );
    }

    #[test]
    fn handle_sni_read_not_tls_returns_done_none() {
        let mut buf = b"GET / HTTP/1.1\r\n".to_vec();
        let filled = buf.len();

        let action = handle_sni_read(&mut buf, filled);
        assert!(
            matches!(action, PeekAction::Done(None)),
            "NotTls should return Done(None)"
        );
        assert_eq!(buf.len(), filled, "buf should be truncated to filled length");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// TLS `ContentType` for Handshake records.
    const CONTENT_TYPE_HANDSHAKE: u8 = 22;

    /// TLS `HandshakeType` for `ClientHello`.
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

    /// SNI `NameType` for DNS hostnames.
    const SNI_NAME_TYPE_HOST: u8 = 0;

    /// Build an SNI extension payload (type 0x0000).
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let entry_len = 1 + 2 + name_len;
        let list_len = entry_len;

        let mut ext = Vec::new();
        ext.extend_from_slice(&0_u16.to_be_bytes());
        let ext_data_len = 2 + list_len;
        ext.extend_from_slice(&ext_data_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(SNI_NAME_TYPE_HOST);
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(name_bytes);
        ext
    }

    /// Build a `ClientHello` body from components.
    fn build_client_hello(session_id: &[u8], cipher_suites: &[u8], compression: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0_u8; 32]);

        hello.push(session_id.len() as u8);
        hello.extend_from_slice(session_id);

        let cs_len = cipher_suites.len() as u16;
        hello.extend_from_slice(&cs_len.to_be_bytes());
        hello.extend_from_slice(cipher_suites);

        hello.push(compression.len() as u8);
        hello.extend_from_slice(compression);

        if !extensions.is_empty() {
            let ext_len = extensions.len() as u16;
            hello.extend_from_slice(&ext_len.to_be_bytes());
            hello.extend_from_slice(extensions);
        }

        hello
    }

    /// Wrap a `ClientHello` body in handshake + TLS record headers.
    fn wrap_in_record(hello_body: &[u8]) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let hs_len = hello_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(hello_body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        let rec_len = handshake.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }
}
