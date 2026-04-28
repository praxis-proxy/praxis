// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pingora-backed bidirectional TCP proxy application.

use std::{borrow::Cow, future::Future, io, sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use praxis_core::health::HealthRegistry;
use praxis_filter::{FilterAction, FilterPipeline, TcpFilterContext};
use praxis_tls::sni;
use tokio::{
    io::AsyncReadExt,
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
/// [`TcpFilterContext::upstream_addr`]: praxis_filter::TcpFilterContext::upstream_addr
pub(crate) struct PingoraTcpProxy {
    /// Cluster name for load-balanced TCP connections.
    cluster: Option<Arc<str>>,

    /// Per-listener connection semaphore for max connections.
    connection_semaphore: Option<Arc<Semaphore>>,

    /// Shared health registry for endpoint health lookups.
    health_registry: Option<HealthRegistry>,

    /// Optional idle timeout for the bidirectional forwarding session.
    idle_timeout: Option<Duration>,

    /// Optional maximum total session duration.
    max_duration: Option<Duration>,

    /// Shared filter pipeline for TCP filter hooks.
    pipeline: Arc<FilterPipeline>,

    /// Static upstream address, if configured on the listener.
    upstream_addr: Option<String>,
}

impl PingoraTcpProxy {
    /// Create a TCP proxy, optionally targeting a fixed upstream address.
    #[allow(clippy::too_many_arguments, reason = "per-listener configuration")]
    pub(super) fn new(
        upstream_addr: Option<String>,
        cluster: Option<Arc<str>>,
        pipeline: Arc<FilterPipeline>,
        idle_timeout: Option<Duration>,
        max_duration: Option<Duration>,
        connection_semaphore: Option<Arc<Semaphore>>,
    ) -> Self {
        let health_registry = pipeline.health_registry().cloned();
        Self {
            cluster,
            connection_semaphore,
            health_registry,
            idle_timeout,
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
            match self.idle_timeout {
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
        let upstream_cow = self.upstream_addr.as_deref().map(Cow::Borrowed);

        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            sni,
            upstream_addr: upstream_cow,
            cluster: self.cluster.clone(),
            health_registry: self.health_registry.as_ref(),
            connect_time,
            bytes_in: 0,
            bytes_out: 0,
        };

        resolve_connect_result(&self.pipeline, &mut ctx, remote_addr).await
    }

    /// Run TCP disconnect filters for logging.
    #[allow(clippy::too_many_arguments, reason = "per-connection metrics")]
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
        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            sni: sni_hostname,
            upstream_addr: Some(Cow::Borrowed(upstream_addr)),
            cluster: self.cluster.clone(),
            health_registry: self.health_registry.as_ref(),
            connect_time,
            bytes_in,
            bytes_out,
        };
        let _result = self.pipeline.execute_tcp_disconnect(&mut ctx).await;
    }
}

#[async_trait]
impl ServerApp for PingoraTcpProxy {
    #[allow(clippy::too_many_lines, reason = "linear connection lifecycle")]
    async fn process_new(self: &Arc<Self>, mut session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let _permit = if let Some(ref sem) = self.connection_semaphore {
            if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                Some(permit)
            } else {
                warn!("max TCP connections reached, closing connection");
                return None;
            }
        } else {
            None
        };

        let connect_time = std::time::Instant::now();
        let (remote_addr, local_addr) = extract_addrs(&session);

        let (sni_hostname, peeked_bytes) = if self.upstream_addr.is_none() {
            peek_sni(&mut session).await
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

        debug!("closing TCP session (connections not pooled)");
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
        Ok(FilterAction::Continue | FilterAction::Release) => {
            if let Some(ref addr) = ctx.upstream_addr {
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
#[allow(clippy::indexing_slicing, reason = "filled <= buf.len() maintained by loop")]
async fn peek_sni(session: &mut Stream) -> (Option<String>, Vec<u8>) {
    let mut buf = vec![0u8; PEEK_INITIAL];
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
                buf.resize(buf.len() * 2, 0);
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
#[allow(clippy::indexing_slicing, reason = "filled <= buf.len() maintained by caller")]
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
            #[allow(clippy::cast_possible_truncation, reason = "millis fit u64")]
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
