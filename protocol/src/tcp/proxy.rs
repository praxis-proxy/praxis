// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Pingora-backed bidirectional TCP proxy application.

use std::{borrow::Cow, collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use praxis_core::connectivity::is_private_ip;
use praxis_filter::{FilterAction, FilterPipeline, TcpFilterContext};
use praxis_tls::sni;
use tokio::{
    io::AsyncReadExt as _,
    net::TcpStream,
    sync::{Semaphore, watch},
};
use tracing::{Instrument as _, Span, error, info, info_span, trace, warn};

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
    /// Allow upstream connections to private/reserved IP addresses.
    allow_private_upstreams: bool,

    /// Cluster name for load-balanced TCP connections.
    cluster: Option<Arc<str>>,

    /// Per-listener connection semaphore for max connections.
    connection_semaphore: Option<Arc<Semaphore>>,

    /// Fallback listener label when local-address lookup misses.
    ///
    /// Preserves the historical "first listener in the group" behavior
    /// for rare unmatched digests, without relying on `HashMap` iteration
    /// order.
    default_listener_name: ::metrics::SharedString,

    /// Bind-address → listener name for connection metrics.
    ///
    /// Grouped TCP listeners share one service; looking up by the
    /// connection's local address keeps the `listener` label accurate.
    listener_names: HashMap<String, ::metrics::SharedString>,

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
        allow_private_upstreams: bool,
        listener_names: HashMap<String, ::metrics::SharedString>,
        default_listener_name: ::metrics::SharedString,
    ) -> Self {
        Self {
            allow_private_upstreams,
            cluster,
            connection_semaphore,
            default_listener_name,
            listener_names,
            session_timeout,
            max_duration,
            pipeline,
            upstream_addr,
        }
    }

    /// Resolve the metrics `listener` label for this connection's local address.
    fn listener_label_for(&self, local_addr: &str) -> ::metrics::SharedString {
        resolve_listener_label(&self.listener_names, &self.default_listener_name, local_addr)
    }

    /// Cluster label for upstream connect metrics.
    fn metrics_cluster_label(&self) -> ::metrics::SharedString {
        self.cluster
            .as_ref()
            .map_or_else(crate::http::pingora::metrics::cluster_none, |c| {
                ::metrics::SharedString::from(Arc::clone(c))
            })
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
                warn!(upstream = %upstream_addr, error = %e, phase = "forward", "connection_error");
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
    #[expect(clippy::too_many_arguments, reason = "pipeline generation pinned by caller")]
    async fn run_connect_filters(
        &self,
        pipeline: &FilterPipeline,
        remote_addr: &str,
        local_addr: &str,
        sni: Option<&str>,
        connect_time: std::time::Instant,
    ) -> Option<String> {
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

        let result = resolve_connect_result(pipeline, &mut ctx, remote_addr).await;
        if result.is_none() {
            log_early_close(connect_time, "filter_rejection");
        }
        result
    }

    /// Run TCP disconnect filters for logging.
    #[expect(clippy::too_many_arguments, reason = "per-connection metrics")]
    async fn run_disconnect_filters(
        &self,
        pipeline: &FilterPipeline,
        remote_addr: &str,
        local_addr: &str,
        upstream_addr: &str,
        sni_hostname: Option<&str>,
        connect_time: std::time::Instant,
        bytes_in: u64,
        bytes_out: u64,
    ) {
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
        clippy::too_many_lines,
        clippy::large_stack_frames,
        reason = "linear connection lifecycle"
    )]
    async fn process_new(self: &Arc<Self>, mut session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let connect_time = std::time::Instant::now();
        let (remote_addr, local_addr) = extract_addrs(&session);

        let span = info_span!(
            "tcp_connection",
            client.address = %remote_addr,
            network.transport = "tcp",
            upstream.address = tracing::field::Empty,
        );

        async {
            if praxis_core::memory::is_exceeded() {
                warn!(remote = %remote_addr, "memory pressure threshold exceeded, closing TCP connection");
                crate::http::pingora::metrics::record_overload_reject(
                    crate::http::pingora::metrics::OVERLOAD_REASON_MEMORY,
                );
                return None;
            }

            let (exceeded, _global_permit) = crate::connections::try_acquire_global();
            if exceeded {
                warn!(remote = %remote_addr, "global max connections reached, closing TCP connection");
                crate::http::pingora::metrics::record_overload_reject(
                    crate::http::pingora::metrics::OVERLOAD_REASON_GLOBAL_CONNECTIONS,
                );
                return None;
            }

            let _permit = if let Some(sem) = &self.connection_semaphore {
                if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                    Some(permit)
                } else {
                    warn!(remote = %remote_addr, "max TCP connections reached, closing connection");
                    crate::http::pingora::metrics::record_overload_reject(
                        crate::http::pingora::metrics::OVERLOAD_REASON_LISTENER_CONNECTIONS,
                    );
                    return None;
                }
            } else {
                None
            };

            let _active_connection =
                crate::http::pingora::metrics::ActiveConnectionGuard::acquire(self.listener_label_for(&local_addr));

            info!("connection_accepted");

            let (sni_hostname, peeked_bytes) = if self.upstream_addr.is_none() {
                let Ok(result) = tokio::time::timeout(SNI_PEEK_TIMEOUT, peek_sni(&mut session)).await else {
                    warn!(remote = %remote_addr, "SNI peek timed out, closing connection");
                    log_early_close(connect_time, "sni_timeout");
                    return None;
                };
                result
            } else {
                (None, Vec::new())
            };

            // Pin one pipeline generation for the whole connection so paired
            // connect/disconnect filter state (e.g. least-connections counters)
            // stays on the same instance across a hot reload.
            let pipeline = self.pipeline.load_full();

            let upstream_addr = self
                .run_connect_filters(
                    &pipeline,
                    &remote_addr,
                    &local_addr,
                    sni_hostname.as_deref(),
                    connect_time,
                )
                .await?;

            Span::current().record("upstream.address", upstream_addr.as_str());

            let upstream_connect_start = std::time::Instant::now();
            let cluster_label = self.metrics_cluster_label();
            let mut upstream =
                if let Some(stream) = connect_upstream(&upstream_addr, self.allow_private_upstreams).await {
                    crate::http::pingora::metrics::record_upstream_connect_duration(
                        cluster_label,
                        upstream_connect_start.elapsed().as_secs_f64(),
                    );
                    stream
                } else {
                    crate::http::pingora::metrics::record_upstream_connect_failure(cluster_label);
                    // Connect filters already ran (least-connections/P2C counters
                    // were incremented on selection), so the paired disconnect
                    // filters must run on this exit path too or the in-flight
                    // counters leak permanently.
                    self.run_disconnect_filters(
                        &pipeline,
                        &remote_addr,
                        &local_addr,
                        &upstream_addr,
                        sni_hostname.as_deref(),
                        connect_time,
                        0,
                        0,
                    )
                    .await;
                    log_early_close(connect_time, "connect_failure");
                    return None;
                };

            if !peeked_bytes.is_empty()
                && let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut upstream, &peeked_bytes).await
            {
                warn!(
                    upstream = %upstream_addr,
                    error = %e,
                    phase = "peeked_write",
                    "connection_error"
                );
                self.run_disconnect_filters(
                    &pipeline,
                    &remote_addr,
                    &local_addr,
                    &upstream_addr,
                    sni_hostname.as_deref(),
                    connect_time,
                    0,
                    0,
                )
                .await;
                log_early_close(connect_time, "peeked_write_error");
                return None;
            }

            let mut shutdown_rx: watch::Receiver<bool> = shutdown.clone();
            let (bytes_in, bytes_out) = self
                .forward(&mut session, &mut upstream, &mut shutdown_rx, &upstream_addr)
                .await;

            self.run_disconnect_filters(
                &pipeline,
                &remote_addr,
                &local_addr,
                &upstream_addr,
                sni_hostname.as_deref(),
                connect_time,
                bytes_in,
                bytes_out,
            )
            .await;

            let duration = connect_time.elapsed();
            #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
            let duration_ms = duration.as_millis() as u64;
            info!(
                bytes_in,
                bytes_out,
                duration_ms,
                reason = "completed",
                "connection_close"
            );

            None
        }
        .instrument(span)
        .await
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
        Ok(
            FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => {
            if let Some(addr) = &ctx.upstream_addr {
                Some(addr.clone().into_owned())
            } else {
                error!(remote = %remote_addr, "no upstream address resolved for TCP connection");
                None
            }
        },
        Ok(FilterAction::Reject(r)) => {
            warn!(remote = %remote_addr, status = r.status, "TCP connection rejected by filter");
            release_selected_endpoint(pipeline, ctx).await;
            None
        },
        Err(e) => {
            error!(remote = %remote_addr, error = %e, "TCP connect filter error");
            release_selected_endpoint(pipeline, ctx).await;
            None
        },
    }
}

/// Run disconnect filters when the connect phase selected an endpoint but
/// the connection will not proceed.
///
/// A rejection or error from a filter after `tcp_load_balancer` leaves the
/// selected endpoint's in-flight counter incremented; only the disconnect
/// hook releases it.
async fn release_selected_endpoint(pipeline: &FilterPipeline, ctx: &mut TcpFilterContext<'_>) {
    if ctx.upstream_addr.is_none() {
        return;
    }
    if let Err(e) = pipeline.execute_tcp_disconnect(ctx).await {
        error!(error = %e, "TCP disconnect filter error while releasing rejected connection");
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

/// Log a `connection_close` event for early-exit paths that fire after
/// `connection_accepted` but before the happy-path close.
fn log_early_close(connect_time: std::time::Instant, reason: &str) {
    #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
    let duration_ms = connect_time.elapsed().as_millis() as u64;
    info!(
        bytes_in = 0_u64,
        bytes_out = 0_u64,
        duration_ms,
        reason,
        "connection_close"
    );
}

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
async fn forward_with_timeout<F: Future<Output = io::Result<(u64, u64)>>>(
    copy_future: F,
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
            let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            warn!(upstream = %upstream_addr, timeout_ms, "TCP session timed out");
            None
        },
    }
}

/// Forward without timeout, returning `None` on shutdown.
async fn forward_no_timeout<F: Future<Output = io::Result<(u64, u64)>>>(
    copy_future: F,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<io::Result<(u64, u64)>> {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => None,
        r = copy_future => Some(r),
    }
}

/// Connect to the upstream TCP address with a timeout.
///
/// Resolves DNS before connecting so that the resolved IPs can be
/// checked against private/reserved ranges (loopback, RFC 1918,
/// link-local, CGNAT, IPv6 unique-local). This prevents DNS
/// rebinding attacks where a hostname resolves to a public IP at
/// config time but a private IP at connection time. The check is
/// skipped when `allow_private` is `true`
/// (`insecure_options.allow_private_upstreams`).
async fn connect_upstream(upstream_addr: &str, allow_private: bool) -> Option<TcpStream> {
    if let Ok(result) = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        resolve_and_connect(upstream_addr, allow_private),
    )
    .await
    {
        return result;
    }
    warn!(
        upstream = %upstream_addr,
        timeout_secs = UPSTREAM_CONNECT_TIMEOUT.as_secs(),
        phase = "connect_timeout",
        "connection_error"
    );
    None
}

/// Resolve, SSRF-check, and connect to an upstream address.
///
/// Resolution is deliberately uncached and per-connection: the SSRF /
/// DNS-rebinding check below must see fresh addresses, so reusing the HTTP
/// path's positive DNS cache (which pins a resolution for its TTL) would
/// weaken rebinding protection. See `docs/architecture/tcp-proxy.md`.
async fn resolve_and_connect(upstream_addr: &str, allow_private: bool) -> Option<TcpStream> {
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(upstream_addr).await {
        Ok(iter) => iter.collect(),
        Err(e) => {
            warn!(upstream = %upstream_addr, error = %e, "failed to resolve TCP upstream");
            return None;
        },
    };

    if !allow_private && let Some(bad_ip) = find_private_addr(&addrs) {
        warn!(
            upstream = %upstream_addr,
            resolved_ip = %bad_ip,
            "TCP upstream resolved to private/reserved IP address; \
             set insecure_options.allow_private_upstreams to allow"
        );
        return None;
    }

    match TcpStream::connect(addrs.as_slice()).await {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(upstream = %upstream_addr, error = %e, phase = "connect", "connection_error");
            None
        },
    }
}

/// Return the first private/reserved IP among resolved socket addresses.
///
/// Uses [`is_private_ip`] which handles IPv4-mapped IPv6 normalization
/// internally, so `::ffff:10.0.0.1` is correctly identified.
///
/// [`is_private_ip`]: praxis_core::connectivity::is_private_ip
fn find_private_addr(addrs: &[SocketAddr]) -> Option<std::net::IpAddr> {
    addrs.iter().map(SocketAddr::ip).find(is_private_ip)
}

/// Resolve a listener metrics label from the connection local address.
///
/// Prefers an exact bind-address match, then a same-port match (so
/// `0.0.0.0:5432` config can label traffic seen as `127.0.0.1:5432`),
/// then the group default.
fn resolve_listener_label(
    listener_names: &HashMap<String, ::metrics::SharedString>,
    default_listener_name: &::metrics::SharedString,
    local_addr: &str,
) -> ::metrics::SharedString {
    if let Some(name) = listener_names.get(local_addr) {
        return name.clone();
    }
    // Config may use `0.0.0.0:port` while the socket digest reports a
    // concrete interface address; fall back to matching on port.
    if let Some(port) = local_addr.rsplit_once(':').map(|(_, p)| p) {
        for (bind_addr, name) in listener_names {
            if bind_addr.rsplit_once(':').is_some_and(|(_, p)| p == port) {
                return name.clone();
            }
        }
    }
    default_listener_name.clone()
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
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// Rejects every TCP connection; stands in for a policy filter placed
    /// after the load balancer.
    struct RejectingTcpFilter;

    #[async_trait]
    impl praxis_filter::TcpFilter for RejectingTcpFilter {
        fn name(&self) -> &'static str {
            "test_tcp_reject"
        }

        async fn on_connect(
            &self,
            _ctx: &mut TcpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            Ok(FilterAction::Reject(praxis_filter::Rejection::status(403)))
        }
    }

    /// Stands in for `tcp_load_balancer`: picks an upstream on connect and
    /// records how many times its connect and disconnect hooks run. The real
    /// load balancer increments its least-connections counter on connect and
    /// releases it on disconnect, so proving the disconnect hook runs on the
    /// reject path is exactly what guarantees the counter is released.
    struct CountingSelectorFilter {
        connects: Arc<AtomicUsize>,
        disconnects: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl praxis_filter::TcpFilter for CountingSelectorFilter {
        fn name(&self) -> &'static str {
            "test_counting_selector"
        }

        async fn on_connect(&self, ctx: &mut TcpFilterContext<'_>) -> Result<FilterAction, praxis_filter::FilterError> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            ctx.upstream_addr = Some(Cow::Borrowed("10.0.0.1:5432"));
            Ok(FilterAction::Continue)
        }

        async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), praxis_filter::FilterError> {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Build a `[test_counting_selector, test_tcp_reject]` pipeline: the
    /// selector stands in for the load balancer (picks an upstream and records
    /// hook calls), and the rejecting filter after it forces the release path.
    fn counting_selector_reject_pipeline(
        connects: &Arc<AtomicUsize>,
        disconnects: &Arc<AtomicUsize>,
    ) -> FilterPipeline {
        let mut entries: Vec<praxis_core::config::FilterEntry> =
            serde_yaml::from_str("- filter: test_counting_selector\n- filter: test_tcp_reject\n").unwrap();
        let (connects, disconnects) = (Arc::clone(connects), Arc::clone(disconnects));
        let mut registry = praxis_filter::FilterRegistry::with_builtins();
        registry
            .register(
                "test_counting_selector",
                praxis_filter::FilterFactory::Tcp(Arc::new(move |_config| {
                    Ok(Box::new(CountingSelectorFilter {
                        connects: Arc::clone(&connects),
                        disconnects: Arc::clone(&disconnects),
                    }))
                })),
            )
            .unwrap();
        registry
            .register(
                "test_tcp_reject",
                praxis_filter::FilterFactory::Tcp(Arc::new(|_config| Ok(Box::new(RejectingTcpFilter)))),
            )
            .unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    fn make_tcp_ctx<'a>(cluster: &str) -> TcpFilterContext<'a> {
        TcpFilterContext {
            remote_addr: "192.0.2.7:9999",
            local_addr: "127.0.0.1:5432",
            sni: None,
            upstream_addr: None,
            cluster: Some(Arc::from(cluster)),
            health_registry: None,
            kv_stores: None,
            connect_time: std::time::Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[tokio::test]
    async fn rejected_connection_runs_disconnect_release_hooks() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = counting_selector_reject_pipeline(&connects, &disconnects);

        // The selector picks an upstream (the real load balancer would
        // increment its in-flight counter here); the ACL filter after it then
        // rejects the connection.
        let result = resolve_connect_result(&pipeline, &mut make_tcp_ctx("db"), "192.0.2.7:9999").await;

        assert!(result.is_none(), "the ACL filter should reject the connection");
        assert_eq!(
            connects.load(Ordering::SeqCst),
            1,
            "the selecting filter must run its connect hook exactly once"
        );
        // The release path must run the paired disconnect hook; that is what
        // decrements the least-connections counter the selector incremented.
        // Asserting on the hook (rather than a follow-up selection) keeps the
        // test independent of the load balancer's tie-break ordering.
        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            1,
            "a rejected connection must run the disconnect hook so the selected endpoint's in-flight counter is released"
        );
    }

    #[test]
    fn resolve_listener_label_exact_bind_address() {
        let mut names = HashMap::new();
        names.insert("127.0.0.1:5432".to_owned(), ::metrics::SharedString::const_str("db1"));
        names.insert("127.0.0.1:5433".to_owned(), ::metrics::SharedString::const_str("db2"));
        let default = ::metrics::SharedString::const_str("db1");
        assert_eq!(
            resolve_listener_label(&names, &default, "127.0.0.1:5433").as_ref(),
            "db2",
            "exact local address should select the matching listener"
        );
    }

    #[test]
    fn resolve_listener_label_matches_by_port_when_bind_is_wildcard() {
        let mut names = HashMap::new();
        names.insert("0.0.0.0:5432".to_owned(), ::metrics::SharedString::const_str("db1"));
        names.insert("0.0.0.0:5433".to_owned(), ::metrics::SharedString::const_str("db2"));
        let default = ::metrics::SharedString::const_str("db1");
        assert_eq!(
            resolve_listener_label(&names, &default, "127.0.0.1:5433").as_ref(),
            "db2",
            "wildcard bind should still label by destination port"
        );
    }

    #[test]
    fn resolve_listener_label_falls_back_to_default() {
        let mut names = HashMap::new();
        names.insert("127.0.0.1:5432".to_owned(), ::metrics::SharedString::const_str("db1"));
        let default = ::metrics::SharedString::const_str("db1");
        assert_eq!(
            resolve_listener_label(&names, &default, "unknown").as_ref(),
            "db1",
            "unmatched local address should use the group default"
        );
    }

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

    #[test]
    fn find_private_addr_flags_loopback_v4() {
        let addrs = vec![SocketAddr::from(([127, 0, 0, 1], 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "127.0.0.1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_loopback_v6() {
        let addrs = vec![SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "::1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_link_local_v4() {
        let addrs = vec![SocketAddr::from(([169, 254, 169, 254], 80))];
        let result = find_private_addr(&addrs);
        assert!(
            result.is_some(),
            "169.254.169.254 (link-local) should be flagged as private"
        );
    }

    #[test]
    fn find_private_addr_flags_ipv4_mapped_loopback() {
        let v6 = "::ffff:127.0.0.1".parse::<std::net::Ipv6Addr>().unwrap();
        let addrs = vec![SocketAddr::from((v6, 80))];
        let result = find_private_addr(&addrs);
        assert!(
            result.is_some(),
            "::ffff:127.0.0.1 should be flagged after normalization"
        );
    }

    #[test]
    fn find_private_addr_allows_public_ip() {
        let addrs = vec![SocketAddr::from(([8, 8, 8, 8], 443))];
        let result = find_private_addr(&addrs);
        assert!(result.is_none(), "8.8.8.8 should not be flagged");
    }

    #[test]
    fn find_private_addr_flags_rfc1918() {
        let addrs = vec![SocketAddr::from(([10, 0, 0, 1], 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "RFC 1918 10.0.0.1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_rfc1918_172() {
        let addrs = vec![SocketAddr::from(([172, 16, 5, 1], 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "RFC 1918 172.16.5.1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_rfc1918_192() {
        let addrs = vec![SocketAddr::from(([192, 168, 1, 1], 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "RFC 1918 192.168.1.1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_cgnat() {
        let addrs = vec![SocketAddr::from(([100, 64, 0, 1], 80))];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "CGNAT 100.64.0.1 should be flagged as private");
    }

    #[test]
    fn find_private_addr_flags_any_private_in_list() {
        let addrs = vec![
            SocketAddr::from(([8, 8, 8, 8], 80)),
            SocketAddr::from(([127, 0, 0, 1], 80)),
        ];
        let result = find_private_addr(&addrs);
        assert!(result.is_some(), "should flag when any address in the list is private");
    }

    #[test]
    fn find_private_addr_returns_none_for_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let result = find_private_addr(&addrs);
        assert!(result.is_none(), "empty list should return None");
    }

    // -------------------------------------------------------------------------
    // TCP Connection Lifecycle Span Tests
    // -------------------------------------------------------------------------

    #[test]
    fn tcp_connection_span_has_correct_name_and_fields() {
        let (spans, _events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "192.168.1.10:54321",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
        });
        assert_eq!(spans.len(), 1, "should create exactly one span");
        assert_eq!(spans[0].name, "tcp_connection", "span name should be tcp_connection");
        assert_eq!(
            spans[0].fields.get("client.address").map(String::as_str),
            Some("192.168.1.10:54321"),
            "span should contain client.address"
        );
        assert_eq!(
            spans[0].fields.get("network.transport").map(String::as_str),
            Some("tcp"),
            "span should contain network.transport = tcp"
        );
    }

    #[test]
    fn tcp_connection_span_records_upstream_address() {
        let (spans, _events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "10.0.0.5:12345",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
            span.record("upstream.address", "10.0.0.1:5432");
        });
        assert_eq!(spans.len(), 1, "should create exactly one span");
        assert_eq!(
            spans[0].fields.get("upstream.address").map(String::as_str),
            Some("10.0.0.1:5432"),
            "upstream.address should be recorded after span creation"
        );
    }

    #[test]
    fn tcp_connection_emits_connection_accepted_event() {
        let (_spans, events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "10.0.0.5:12345",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
            info!("connection_accepted");
        });
        assert!(
            events.iter().any(|e| e.message == "connection_accepted"),
            "should emit connection_accepted event: {events:?}"
        );
    }

    #[test]
    fn tcp_connection_emits_connection_close_event_with_metrics() {
        let (_spans, events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "10.0.0.5:12345",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
            info!(
                bytes_in = 1024_u64,
                bytes_out = 2048_u64,
                duration_ms = 500_u64,
                "connection_close"
            );
        });
        let close_event = events
            .iter()
            .find(|e| e.message == "connection_close")
            .expect("should emit connection_close event");
        assert_eq!(
            close_event.fields.get("bytes_in").map(String::as_str),
            Some("1024"),
            "connection_close should include bytes_in"
        );
        assert_eq!(
            close_event.fields.get("bytes_out").map(String::as_str),
            Some("2048"),
            "connection_close should include bytes_out"
        );
        assert_eq!(
            close_event.fields.get("duration_ms").map(String::as_str),
            Some("500"),
            "connection_close should include duration_ms"
        );
    }

    #[test]
    fn tcp_connection_emits_connection_error_event() {
        let (_spans, events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "10.0.0.5:12345",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
            warn!(
                upstream = "10.0.0.1:5432",
                error = "connection refused",
                "connection_error"
            );
        });
        let error_event = events
            .iter()
            .find(|e| e.message == "connection_error")
            .expect("should emit connection_error event");
        assert_eq!(
            error_event.fields.get("upstream").map(String::as_str),
            Some("10.0.0.1:5432"),
            "connection_error should include upstream"
        );
        assert_eq!(
            error_event.fields.get("error").map(String::as_str),
            Some("connection refused"),
            "connection_error should include error"
        );
    }

    #[test]
    fn tcp_connection_span_events_are_within_span() {
        let (spans, events) = capture_tracing(|| {
            let span = info_span!(
                "tcp_connection",
                client.address = "10.0.0.5:12345",
                network.transport = "tcp",
                upstream.address = tracing::field::Empty,
            );
            let _guard = span.enter();
            info!("connection_accepted");
            span.record("upstream.address", "10.0.0.1:5432");
            info!(
                bytes_in = 100_u64,
                bytes_out = 200_u64,
                duration_ms = 50_u64,
                "connection_close"
            );
        });
        assert_eq!(spans.len(), 1, "should have exactly one span");
        assert_eq!(
            events.len(),
            2,
            "should have connection_accepted and connection_close events"
        );
        for event in &events {
            assert_eq!(
                event.span_name.as_deref(),
                Some("tcp_connection"),
                "event '{}' should be within tcp_connection span",
                event.message
            );
        }
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

    // -------------------------------------------------------------------------
    // Tracing Capture Utilities
    // -------------------------------------------------------------------------

    /// Captured span data.
    #[derive(Debug)]
    struct CapturedSpan {
        name: String,
        fields: HashMap<String, String>,
    }

    /// Captured event data.
    #[derive(Debug)]
    struct CapturedEvent {
        fields: HashMap<String, String>,
        message: String,
        span_name: Option<String>,
    }

    /// Run `f` under a test subscriber and return captured spans and events.
    fn capture_tracing<F: FnOnce()>(f: F) -> (Vec<CapturedSpan>, Vec<CapturedEvent>) {
        let spans = Arc::new(Mutex::new(Vec::<CapturedSpan>::new()));
        let events = Arc::new(Mutex::new(Vec::<CapturedEvent>::new()));
        let layer = SpanCapture {
            events: Arc::clone(&events),
            spans: Arc::clone(&spans),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        let spans = std::mem::take(&mut *spans.lock().unwrap());
        let events = std::mem::take(&mut *events.lock().unwrap());
        (spans, events)
    }

    /// Layer that captures span and event data for test assertions.
    struct SpanCapture {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
        spans: Arc<Mutex<Vec<CapturedSpan>>>,
    }

    impl<S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>>
        tracing_subscriber::Layer<S> for SpanCapture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = HashMap::new();
            let mut visitor = FieldCapture(&mut fields);
            attrs.record(&mut visitor);
            let name = attrs.metadata().name().to_owned();
            self.spans.lock().unwrap().push(CapturedSpan {
                fields: fields.clone(),
                name,
            });
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(SpanFields(fields));
            }
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if let Some(span) = ctx.span(id) {
                let mut ext = span.extensions_mut();
                if let Some(fields) = ext.get_mut::<SpanFields>() {
                    let mut visitor = FieldCapture(&mut fields.0);
                    values.record(&mut visitor);
                    // Update the captured span in the list.
                    let mut spans = self.spans.lock().unwrap();
                    let name = span.name();
                    if let Some(captured) = spans.iter_mut().find(|s| s.name == name) {
                        captured.fields = fields.0.clone();
                    }
                }
            }
        }

        fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
            let mut fields = HashMap::new();
            let mut visitor = FieldCapture(&mut fields);
            event.record(&mut visitor);
            let message = fields.remove("message").unwrap_or_default();
            let span_name = ctx.event_span(event).map(|s| s.name().to_owned());
            self.events.lock().unwrap().push(CapturedEvent {
                fields,
                message,
                span_name,
            });
        }
    }

    /// Extension stored on span to track recorded fields.
    struct SpanFields(HashMap<String, String>);

    /// Visitor that captures field values as strings.
    struct FieldCapture<'a>(&'a mut HashMap<String, String>);

    impl tracing::field::Visit for FieldCapture<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }
    }
}
