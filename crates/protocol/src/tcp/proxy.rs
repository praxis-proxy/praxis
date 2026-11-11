// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! The bidirectional TCP proxy every backend runs.
//!
//! A backend accepts the connection (and terminates TLS where the listener
//! asks for it); everything after that, from admission to the disconnect
//! filters, is the shared [`PingoraTcpProxy::serve_connection`].
//!
//! [`PingoraTcpProxy::serve_connection`]: crate::tcp::proxy::PingoraTcpProxy::serve_connection

use std::{
    borrow::Cow,
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
#[cfg(any(feature = "pingora", test))]
use async_trait::async_trait;
#[cfg(feature = "pingora")]
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use praxis_core::{
    config::{Config, Listener},
    connectivity::is_private_upstream_ip,
};
use praxis_filter::{FilterAction, FilterPipeline, TcpFilterContext};
use praxis_tls::sni;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use tracing::{Instrument as _, Span, debug, error, info, info_span, trace, warn};

use super::groups::TcpGroupKey;
#[cfg(feature = "pingora")]
use super::pending::{PendingAdmissions, PreTlsAdmission};
use crate::ListenerPipelines;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Initial peek buffer size for SNI extraction.
const PEEK_INITIAL: usize = 1_024; // 1 KiB

/// Maximum peek buffer size before giving up on SNI extraction.
const PEEK_MAX: usize = 16_384; // 16 KiB

/// Timeout for upstream TCP connect (including DNS resolution).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for SNI peek phase.
///
/// Bounds the time a client can hold a connection during the initial
/// TLS `ClientHello` read. Without this, a slow-drip client could
/// hold a connection (and semaphore permit) indefinitely.
const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Claims held from TCP admission until upstream and downstream close.
pub(super) struct TcpAdmission {
    /// Descriptor forecast claim, settled on upstream connection.
    fd: praxis_core::fd::Admission<'static>,
    /// Process-wide slot, if configured.
    _global: Option<OwnedSemaphorePermit>,
    /// TCP group slot, if configured.
    _group: Option<OwnedSemaphorePermit>,
    /// Admission instant, including TLS time where the adapter can observe it.
    started: tokio::time::Instant,
    /// Absolute maximum session deadline, if configured.
    deadline: Option<tokio::time::Instant>,
}

impl TcpAdmission {
    /// Return the timestamp used for connection metrics and filter context.
    fn connect_time(&self) -> Instant {
        self.started.into_std()
    }

    /// Return the absolute maximum session deadline.
    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

/// Shared admission gate for TLS callbacks and plain TCP sessions.
pub(super) struct TcpAdmissionGate {
    /// TCP group capacity shared across all listeners in the group.
    group: Option<Arc<Semaphore>>,
    /// Maximum duration counted from admission.
    max_duration: Option<Duration>,
}

impl TcpAdmissionGate {
    /// Construct the group's gate from its configured limits.
    pub(super) fn new(group: Option<Arc<Semaphore>>, max_duration: Option<Duration>) -> Self {
        Self { group, max_duration }
    }

    /// Admit a connection immediately or reject it with its overload metric.
    pub(super) fn try_admit(&self, remote: &str) -> Option<TcpAdmission> {
        if praxis_core::memory::is_exceeded() {
            record_tcp_overload(remote, crate::http::pingora::metrics::OVERLOAD_REASON_MEMORY);
            return None;
        }
        let fd = praxis_core::fd::try_admit().or_else(|| {
            record_tcp_overload(remote, crate::http::pingora::metrics::OVERLOAD_REASON_FILE_DESCRIPTORS);
            None
        })?;
        let (exceeded, global) = crate::connections::try_acquire_global();
        if exceeded {
            record_tcp_overload(
                remote,
                crate::http::pingora::metrics::OVERLOAD_REASON_GLOBAL_CONNECTIONS,
            );
            return None;
        }
        let group = self.try_group_slot(remote).ok()?;
        let started = tokio::time::Instant::now();
        Some(TcpAdmission {
            fd,
            _global: global,
            _group: group,
            started,
            deadline: self.max_duration.and_then(|duration| started.checked_add(duration)),
        })
    }

    /// Acquire the TCP group slot, if a group cap exists.
    fn try_group_slot(&self, remote: &str) -> Result<Option<OwnedSemaphorePermit>, tokio::sync::TryAcquireError> {
        let Some(group) = &self.group else {
            return Ok(None);
        };
        Arc::clone(group).try_acquire_owned().map(Some).inspect_err(|_| {
            record_tcp_overload(
                remote,
                crate::http::pingora::metrics::OVERLOAD_REASON_LISTENER_CONNECTIONS,
            );
        })
    }
}

/// Record one rejected TCP admission using the shared overload labels.
fn record_tcp_overload(remote: &str, reason: &'static str) {
    warn!(remote, reason, "TCP connection admission rejected");
    crate::http::pingora::metrics::record_overload_reject(reason);
}

// -----------------------------------------------------------------------------
// PingoraTcpProxy
// -----------------------------------------------------------------------------

/// Bidirectional TCP proxy, shared by every backend.
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
    /// Owning server overload signal, shared with its pre-TLS admission gate.
    pub(super) overload: Arc<praxis_core::overload::Signal>,
    /// Allow upstream connections to private/reserved IP addresses.
    allow_private_upstreams: bool,

    /// Cluster name for load-balanced TCP connections.
    cluster: Option<Arc<str>>,

    /// Shared group, process and descriptor admission gate.
    admission_gate: Arc<TcpAdmissionGate>,

    /// TLS handshakes admitted before Pingora's shared serving callback.
    #[cfg(feature = "pingora")]
    pending: Arc<PendingAdmissions>,

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

    /// Port → listener name fallback for wildcard binds, precomputed
    /// from `listener_names` (the fallback runs per connection).
    listener_ports: HashMap<String, ::metrics::SharedString>,

    /// Optional session timeout for the bidirectional forwarding phase.
    session_timeout: Option<Duration>,

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
            overload: Arc::default(),
            allow_private_upstreams,
            cluster,
            admission_gate: Arc::new(TcpAdmissionGate::new(connection_semaphore, max_duration)),
            #[cfg(feature = "pingora")]
            pending: Arc::new(PendingAdmissions::new()),
            default_listener_name,
            listener_ports: ports_by_listener(&listener_names),
            listener_names,
            session_timeout,
            pipeline,
            upstream_addr,
        }
    }

    /// Admit before TLS or plain serving, using the same group gate.
    pub(super) fn try_admit(&self, remote: &str) -> Option<TcpAdmission> {
        self.admission_gate.try_admit(remote)
    }

    /// Build the callback that admits TLS before Pingora handshakes.
    #[cfg(feature = "pingora")]
    pub(super) fn pre_tls_callback(&self) -> pingora_core::listeners::PreTlsCallback {
        Arc::new(PreTlsAdmission {
            gate: Arc::clone(&self.admission_gate),
            pending: Arc::clone(&self.pending),
        })
    }

    /// Resolve the metrics `listener` label for this connection's local address.
    fn listener_label_for(&self, local_addr: &str) -> ::metrics::SharedString {
        resolve_listener_label(
            &self.listener_names,
            &self.listener_ports,
            &self.default_listener_name,
            local_addr,
        )
    }

    /// Cluster label for upstream connect metrics.
    fn metrics_cluster_label(&self) -> ::metrics::SharedString {
        self.cluster
            .as_ref()
            .map_or_else(crate::http::pingora::metrics::cluster_none, |c| {
                ::metrics::SharedString::from(Arc::clone(c))
            })
    }

    /// Record a connection stopped during setup by its absolute duration.
    fn record_early_duration(&self, local_addr: &str, connect_time: Instant, reason: &'static str) {
        super::metrics::record_tcp_connection_duration(
            self.listener_label_for(local_addr),
            reason,
            connect_time.elapsed().as_secs_f64(),
        );
        log_early_close(connect_time, reason);
    }

    /// Run bidirectional forwarding, returning the close reason.
    ///
    /// The reason lets the `connection_close` log distinguish a force-close
    /// from a genuine completion. The copy is optionally wrapped in a
    /// max-duration timeout.
    async fn forward<S>(
        &self,
        session: &mut S,
        upstream: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
        state: ForwardState<'_>,
    ) -> TcpCloseReason
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut counted = CountingStream {
            inner: session,
            counters: state.counters,
        };
        let copy_fut = async {
            let copy_future = tokio::io::copy_bidirectional(&mut counted, upstream);
            match self.session_timeout {
                Some(timeout) => forward_with_timeout(copy_future, shutdown_rx, timeout, state.upstream_addr).await,
                // Config validation applies a default session timeout to every
                // TCP listener, so this arm is reachable only for a proxy
                // constructed programmatically without one.
                None => forward_no_timeout(copy_future, shutdown_rx, state.upstream_addr).await,
            }
        };

        if let Some(deadline) = state.deadline {
            if let Ok(r) = tokio::time::timeout_at(deadline, copy_fut).await {
                r
            } else {
                warn!(
                    upstream = %state.upstream_addr,
                    "TCP session exceeded maximum duration"
                );
                TcpCloseReason::MaxDuration
            }
        } else {
            copy_fut.await
        }
    }

    /// Run TCP connect filters with caller-owned state for timeout cleanup.
    async fn run_connect_filters(&self, pipeline: &FilterPipeline, ctx: &mut TcpFilterContext<'_>) -> Option<String> {
        let remote_addr = ctx.remote_addr;
        let result = resolve_connect_result(pipeline, ctx, remote_addr).await;
        if result.is_none() {
            super::metrics::record_tcp_connection_duration(
                self.listener_label_for(ctx.local_addr),
                "filter_rejection",
                ctx.connect_time.elapsed().as_secs_f64(),
            );
            log_early_close(ctx.connect_time, "filter_rejection");
        }
        result
    }

    /// Run paired disconnect filters on the pinned context and pipeline.
    async fn run_disconnect_filters(
        &self,
        pipeline: &FilterPipeline,
        ctx: &mut TcpFilterContext<'_>,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        ctx.bytes_in = bytes_in;
        ctx.bytes_out = bytes_out;
        let _result = pipeline.execute_tcp_disconnect(ctx).await;
    }

    /// Serve one accepted connection to completion, through the proxy's whole
    /// lifecycle.
    ///
    /// `addresses` contains the client and listener socket addresses;
    /// forwarding ends early once `shutdown` flips.
    #[expect(
        clippy::too_many_lines,
        clippy::large_stack_frames,
        reason = "linear connection lifecycle"
    )]
    pub(super) async fn serve_connection<S>(
        &self,
        mut session: S,
        addresses: (&str, &str),
        shutdown: &watch::Receiver<bool>,
        mut admission: TcpAdmission,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (remote_addr, local_addr) = addresses;
        let connect_time = admission.connect_time();
        let max_deadline = admission.deadline();

        let span = info_span!(
            "tcp_connection",
            client.address = %remote_addr,
            network.transport = "tcp",
            upstream.address = tracing::field::Empty,
        );

        async {
            if self.overload.is_saturated() {
                crate::http::metrics::record_overload_reject("pressure");
                return;
            }
            if admission
                .deadline()
                .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
            {
                self.record_early_duration(local_addr, connect_time, "max_duration");
                return;
            }

            let listener_label = self.listener_label_for(local_addr);
            let _active_tcp_connection = super::metrics::TcpActiveConnectionGuard::acquire(listener_label.clone());
            super::metrics::record_tcp_connection_accepted(listener_label);

            info!("connection_accepted");

            let (sni_hostname, peeked_bytes) = if self.upstream_addr.is_none() {
                let deadline = phase_deadline(max_deadline, self.overload.scale_timeout(SNI_PEEK_TIMEOUT));
                let Ok(result) = tokio::time::timeout_at(deadline, peek_sni(&mut session)).await else {
                    let reason = if max_deadline.is_some_and(|max| max <= deadline) {
                        "max_duration"
                    } else {
                        "sni_timeout"
                    };
                    self.record_early_duration(local_addr, connect_time, reason);
                    return;
                };
                result
            } else {
                (None, Vec::new())
            };
            let peeked_len = u64::try_from(peeked_bytes.len()).unwrap_or(u64::MAX);

            // Pin one generation so connect and disconnect use the same LB state.
            let pipeline = self.pipeline.load_full();
            let health_registry = pipeline.health_registry().cloned();
            let mut ctx = TcpFilterContext {
                remote_addr,
                local_addr,
                sni: sni_hostname.as_deref(),
                upstream_addr: self.upstream_addr.as_deref().map(Cow::Borrowed),
                lb_selection: None,
                cluster: self.cluster.clone(),
                health_registry: health_registry.as_ref(),
                kv_stores: pipeline.kv_stores(),
                connect_time,
                bytes_in: 0,
                bytes_out: 0,
            };
            let upstream_addr = match before_deadline(max_deadline, self.run_connect_filters(&pipeline, &mut ctx)).await
            {
                Some(Some(address)) => address,
                Some(None) => {
                    drop(session);
                    release_selected_endpoint(&pipeline, &mut ctx).await;
                    return;
                },
                None => {
                    drop(session);
                    release_selected_endpoint(&pipeline, &mut ctx).await;
                    self.record_early_duration(local_addr, connect_time, "max_duration");
                    return;
                },
            };

            Span::current().record("upstream.address", upstream_addr.as_str());

            let upstream_connect_start = Instant::now();
            let cluster_label = self.metrics_cluster_label();
            let connect_result = before_deadline(
                max_deadline,
                connect_upstream(
                    &upstream_addr,
                    self.allow_private_upstreams,
                    self.overload.scale_timeout(UPSTREAM_CONNECT_TIMEOUT),
                ),
            )
            .await;
            let mut upstream = match connect_result {
                Some(Some(stream)) => {
                    admission.fd.connected(true);
                    crate::http::pingora::metrics::record_upstream_connect_duration(
                        cluster_label,
                        upstream_connect_start.elapsed().as_secs_f64(),
                    );
                    stream
                },
                failed => {
                    if failed.is_some() {
                        crate::http::pingora::metrics::record_upstream_connect_failure(cluster_label);
                    }
                    drop(session);
                    self.run_disconnect_filters(&pipeline, &mut ctx, 0, 0).await;
                    let reason = if failed.is_none() {
                        "max_duration"
                    } else {
                        "connect_failure"
                    };
                    self.record_early_duration(local_addr, connect_time, reason);
                    return;
                },
            };

            if !peeked_bytes.is_empty() {
                let replay = replay_peeked(&mut upstream, &peeked_bytes, max_deadline).await;
                if !matches!(&replay, Some(Ok(()))) {
                    if let Some(Err(error)) = replay.as_ref() {
                        warn!(upstream = %upstream_addr, %error, phase = "peeked_write", "connection_error");
                    }
                    drop(upstream);
                    drop(session);
                    self.run_disconnect_filters(&pipeline, &mut ctx, 0, 0).await;
                    let reason = if replay.is_none() {
                        "max_duration"
                    } else {
                        "peeked_write_error"
                    };
                    self.record_early_duration(local_addr, connect_time, reason);
                    return;
                }
            }

            // The peeked hello has been forwarded; a long-lived session
            // must not pin up to 16 KiB of dead peek buffer for its
            // whole lifetime.
            drop(peeked_bytes);

            let mut shutdown_rx: watch::Receiver<bool> = shutdown.clone();
            let counters = ByteCounters::default();
            let close_reason = self
                .forward(
                    &mut session,
                    &mut upstream,
                    &mut shutdown_rx,
                    ForwardState {
                        upstream_addr: &upstream_addr,
                        counters: &counters,
                        deadline: max_deadline,
                    },
                )
                .await;
            let (copied_in, bytes_out) = counters.totals();
            // The peeked ClientHello bytes were read from the client and
            // written to the upstream before copy_bidirectional started, so
            // they are client->upstream ingress and belong in bytes_in.
            let bytes_in = copied_in.saturating_add(peeked_len);

            drop(upstream);
            drop(session);
            self.run_disconnect_filters(&pipeline, &mut ctx, bytes_in, bytes_out)
                .await;

            let duration = connect_time.elapsed();
            #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
            let duration_ms = duration.as_millis() as u64;
            info!(
                bytes_in,
                bytes_out,
                duration_ms,
                reason = close_reason.as_str(),
                "connection_close"
            );
            let listener_label = self.listener_label_for(local_addr);
            super::metrics::record_tcp_bytes(listener_label.clone(), bytes_in, bytes_out);
            super::metrics::record_tcp_connection_duration(
                listener_label,
                close_reason.as_str(),
                connect_time.elapsed().as_secs_f64(),
            );
        }
        .instrument(span)
        .await;
    }
}

/// Inputs shared by forwarding and its absolute session deadline.
struct ForwardState<'a> {
    /// Upstream used in close and timeout diagnostics.
    upstream_addr: &'a str,
    /// Byte counts retained when a copy future is cancelled.
    counters: &'a ByteCounters,
    /// Maximum duration counted from connection admission.
    deadline: Option<tokio::time::Instant>,
}

#[cfg(feature = "pingora")]
#[async_trait]
impl ServerApp for PingoraTcpProxy {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the owned admission is moved into serving and must retain its permits until that future ends"
    )]
    async fn process_new(self: &Arc<Self>, session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let (remote_addr, local_addr) = extract_addrs(&session);
        let admission = if session.get_ssl().is_some() {
            session
                .get_socket_digest()
                .and_then(|digest| self.pending.take(&digest))
        } else {
            self.try_admit(&remote_addr)
        };
        let Some(admission) = admission else {
            warn!(remote = %remote_addr, "TLS admission handoff missing or TCP admission rejected");
            return None;
        };
        self.serve_connection(session, (&remote_addr, &local_addr), shutdown, admission)
            .await;
        None
    }
}

// -----------------------------------------------------------------------------
// Listener Groups
// -----------------------------------------------------------------------------

/// Build the proxy that serves one TCP listener group.
///
/// The group runs the first listener's pipeline (`fallback_pipeline` when
/// it has none) and connection limit; config validation keeps those the
/// same across the group.
pub(super) fn build_group_proxy(
    group_key: &TcpGroupKey,
    listeners: &[&Listener],
    pipelines: &ListenerPipelines,
    fallback_pipeline: &Arc<ArcSwap<FilterPipeline>>,
    config: &Config,
) -> PingoraTcpProxy {
    let (upstream_opt, cluster_opt, timeout_ms, max_dur_secs) = group_key;
    let pipeline = listeners
        .first()
        .and_then(|l| pipelines.get(&l.name))
        .map_or_else(|| Arc::clone(fallback_pipeline), Arc::clone);
    let session_timeout = timeout_ms.map(Duration::from_millis);
    let max_duration = max_dur_secs.map(Duration::from_secs);
    let connection_semaphore = listeners
        .first()
        .and_then(|l| l.max_connections)
        .map(|max| Arc::new(Semaphore::new(max as usize)));
    let (listener_names, default_listener_name) = build_listener_labels(listeners);
    let mut proxy = PingoraTcpProxy::new(
        upstream_opt.clone(),
        cluster_opt.clone().map(Arc::from),
        pipeline,
        session_timeout,
        max_duration,
        connection_semaphore,
        config.insecure_options.allow_private_upstreams,
        listener_names,
        default_listener_name,
    );
    proxy.overload = pipelines.overload();
    proxy
}

/// Derive the service name for a TCP listener group.
pub(super) fn tcp_service_name(upstream: Option<&str>, cluster: Option<&str>) -> String {
    match (upstream, cluster) {
        (Some(addr), _) => format!("tcp-proxy:{addr}"),
        (_, Some(cluster)) => format!("tcp-proxy:cluster:{cluster}"),
        _ => "tcp-proxy:filter-routed".to_owned(),
    }
}

/// Build the per-address metric label map and the default listener label.
fn build_listener_labels(
    listeners: &[&Listener],
) -> (HashMap<String, ::metrics::SharedString>, ::metrics::SharedString) {
    // `from_shared` keeps labels as refcounted `Arc<str>`s: they are cloned
    // per connection, and owned `String` labels would deep-copy on every clone.
    let by_address = listeners
        .iter()
        .map(|l| {
            (
                l.address.clone(),
                ::metrics::SharedString::from_shared(Arc::from(l.name.as_str())),
            )
        })
        .collect();
    let default = listeners.first().map_or_else(
        || ::metrics::SharedString::const_str("unknown"),
        |l| ::metrics::SharedString::from_shared(Arc::from(l.name.as_str())),
    );
    (by_address, default)
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
            if let Some(addr) = ctx.upstream_addr.as_deref() {
                Some(addr.to_owned())
            } else {
                error!(remote = %remote_addr, "no upstream address resolved for TCP connection");
                None
            }
        },
        Ok(FilterAction::Reject(r)) => {
            warn!(remote = %remote_addr, status = r.status, "TCP connection rejected by filter");
            None
        },
        Err(e) => {
            error!(remote = %remote_addr, error = %e, "TCP connect filter error");
            None
        },
    }
}

/// Run disconnect filters when the connect phase selected an endpoint but
/// the connection will not proceed.
///
/// Called once outside the connect deadline, after closing the socket.
/// Built-in load-balancer claims also release when the context is dropped.
async fn release_selected_endpoint(pipeline: &FilterPipeline, ctx: &mut TcpFilterContext<'_>) {
    if ctx.lb_selection.is_none() && ctx.upstream_addr.is_none() {
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
async fn peek_sni<S: AsyncRead + Unpin>(session: &mut S) -> (Option<String>, Vec<u8>) {
    let mut buf = vec![0_u8; PEEK_INITIAL];
    let mut filled = 0;
    // Engaged after the first incomplete parse: resumes record scanning
    // where the previous read stopped, so each buffered byte is examined
    // once. Re-running the stateless parse per read let a client
    // trickling a fragmented hello in tiny segments force quadratic
    // re-reassembly work against the peek cap.
    let mut reassembler: Option<sni::SniReassembler> = None;

    loop {
        match session.read(&mut buf[filled..]).await {
            Ok(0) => {
                trace!(filled, "connection closed during SNI peek");
                break;
            },
            Ok(n) => {
                filled += n;
                if let PeekAction::Done(sni) = handle_sni_read(&mut buf, filled, &mut reassembler) {
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
fn handle_sni_read(buf: &mut Vec<u8>, filled: usize, reassembler: &mut Option<sni::SniReassembler>) -> PeekAction {
    match try_parse_sni(buf, filled, reassembler) {
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
///
/// The first attempt uses the stateless parser; an incomplete result
/// then switches to the resumable reassembler for later reads.
#[expect(clippy::indexing_slicing, reason = "filled <= buf.len() maintained by caller")]
fn try_parse_sni(buf: &[u8], filled: usize, reassembler: &mut Option<sni::SniReassembler>) -> SniPeekResult {
    let data = &buf[..filled];

    if let Some(active) = reassembler {
        return reassembler_step(active, data, filled);
    }

    match sni::parse_sni(data) {
        Ok(info) => SniPeekResult::Parsed(info),
        Err(sni::SniParseError::TooShort | sni::SniParseError::NeedMoreData) => {
            // Catch the state up over what is already buffered; complete
            // records are consumed now and never rescanned.
            let mut active = sni::SniReassembler::new();
            let result = reassembler_step(&mut active, data, filled);
            *reassembler = Some(active);
            result
        },
        Err(error) => {
            trace!(filled, ?error, "not a TLS ClientHello, skipping SNI extraction");
            SniPeekResult::NotTls
        },
    }
}

/// Feed the buffered bytes into the resumable reassembler and map its
/// outcome onto the peek-state machine.
fn reassembler_step(active: &mut sni::SniReassembler, data: &[u8], filled: usize) -> SniPeekResult {
    match active.advance(data) {
        Ok(Some(info)) => SniPeekResult::Parsed(info),
        Ok(None) => SniPeekResult::NeedMore,
        Err(error) => {
            trace!(filled, ?error, "not a TLS ClientHello, skipping SNI extraction");
            SniPeekResult::NotTls
        },
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Use the earlier of a phase's own timeout and the total session deadline.
fn phase_deadline(maximum: Option<tokio::time::Instant>, phase_timeout: Duration) -> tokio::time::Instant {
    let phase = tokio::time::Instant::now() + phase_timeout;
    maximum.map_or(phase, |deadline| deadline.min(phase))
}

/// Poll setup work only while the absolute session deadline remains.
async fn before_deadline<F: Future>(deadline: Option<tokio::time::Instant>, future: F) -> Option<F::Output> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future).await.ok(),
        None => Some(future.await),
    }
}

/// Replay SNI-peeked bytes within the same absolute connection budget.
async fn replay_peeked<Output: AsyncWrite + Unpin>(
    output: &mut Output,
    bytes: &[u8],
    deadline: Option<tokio::time::Instant>,
) -> Option<io::Result<()>> {
    before_deadline(deadline, output.write_all(bytes)).await
}

/// Log a `connection_close` event for early-exit paths that fire after
/// `connection_accepted` but before the happy-path close.
fn log_early_close(connect_time: Instant, reason: &str) {
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
#[cfg(feature = "pingora")]
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

/// Why a forwarded TCP connection closed, for the `connection_close` log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpCloseReason {
    /// `copy_bidirectional` completed normally (both directions saw EOF).
    Completed,
    /// The copy returned an I/O error.
    Error,
    /// The server shut down while forwarding.
    Shutdown,
    /// The hard `session_timeout` deadline elapsed.
    SessionTimeout,
    /// The overall `max_duration` elapsed and the session was force-closed.
    MaxDuration,
}

impl TcpCloseReason {
    /// Stable log label.
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Error => "error",
            Self::Shutdown => "shutdown",
            Self::SessionTimeout => "session_timeout",
            Self::MaxDuration => "max_duration",
        }
    }
}

/// Forward under a hard session deadline, returning the close reason on shutdown or timeout.
async fn forward_with_timeout<F: Future<Output = io::Result<(u64, u64)>>>(
    copy_future: F,
    shutdown_rx: &mut watch::Receiver<bool>,
    timeout: Duration,
    upstream_addr: &str,
) -> TcpCloseReason {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => TcpCloseReason::Shutdown,
        r = tokio::time::timeout(timeout, copy_future) => match r {
            Ok(Ok(_)) => TcpCloseReason::Completed,
            Ok(Err(e)) => {
                warn!(upstream = %upstream_addr, error = %e, phase = "forward", "connection_error");
                TcpCloseReason::Error
            },
            Err(_) => {
                let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
                warn!(upstream = %upstream_addr, timeout_ms, "TCP session timed out");
                TcpCloseReason::SessionTimeout
            },
        },
    }
}

/// Forward without timeout, returning the close reason on shutdown.
async fn forward_no_timeout<F: Future<Output = io::Result<(u64, u64)>>>(
    copy_future: F,
    shutdown_rx: &mut watch::Receiver<bool>,
    upstream_addr: &str,
) -> TcpCloseReason {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => TcpCloseReason::Shutdown,
        r = copy_future => match r {
            Ok(_) => TcpCloseReason::Completed,
            Err(e) => {
                warn!(upstream = %upstream_addr, error = %e, phase = "forward", "connection_error");
                TcpCloseReason::Error
            },
        },
    }
}

// -----------------------------------------------------------------------------
// Byte Accounting
// -----------------------------------------------------------------------------

/// Bytes forwarded in each direction, accumulated as the copy progresses.
///
/// `copy_bidirectional` only reports its totals on a clean return, so a
/// cancelled session (shutdown, session deadline, max-duration force-close)
/// would otherwise report zero for exactly the long-lived sessions whose
/// throughput matters most. Counting inside the stream adapter keeps the
/// totals exact on every close path.
#[derive(Debug, Default)]
struct ByteCounters {
    /// Bytes read from the downstream client (client to upstream).
    received: AtomicU64,

    /// Bytes written to the downstream client (upstream to client).
    sent: AtomicU64,
}

impl ByteCounters {
    /// Current `(received, sent)` totals.
    fn totals(&self) -> (u64, u64) {
        (self.received.load(Ordering::Relaxed), self.sent.load(Ordering::Relaxed))
    }
}

/// Downstream stream wrapper that tallies bytes as they pass through.
///
/// Wrapping only the client side is sufficient: bytes read from the client
/// are the client-to-upstream direction and bytes written to the client are
/// the upstream-to-client direction.
struct CountingStream<'a, S> {
    /// The wrapped downstream session.
    inner: &'a mut S,

    /// Shared totals updated on every successful poll.
    counters: &'a ByteCounters,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if poll.is_ready() {
            let read = buf.filled().len().saturating_sub(before);
            self.counters.received.fetch_add(read as u64, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &poll {
            self.counters.sent.fetch_add(*written as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
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
async fn connect_upstream(upstream_addr: &str, allow_private: bool, timeout: Duration) -> Option<TcpStream> {
    if let Ok(result) = tokio::time::timeout(timeout, resolve_and_connect(upstream_addr, allow_private)).await {
        return result;
    }
    warn!(
        upstream = %upstream_addr,
        timeout_secs = timeout.as_secs(),
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
        Ok(s) => {
            // A proxy forwards bytes as they arrive; Nagle plus delayed ACK
            // can stall each exchange of a request/response protocol (Redis,
            // Postgres) by up to about 40 ms.
            if let Err(e) = s.set_nodelay(true) {
                debug!(upstream = %upstream_addr, error = %e, "could not set TCP_NODELAY on the upstream");
            }
            Some(s)
        },
        Err(e) => {
            warn!(upstream = %upstream_addr, error = %e, phase = "connect", "connection_error");
            None
        },
    }
}

/// Return the first private/reserved IP among resolved socket addresses.
///
/// Uses [`is_private_upstream_ip`], which normalizes IPv4-mapped IPv6 and
/// unwraps NAT64 (`64:ff9b::/96`) answers, so `::ffff:10.0.0.1` and
/// `64:ff9b::a00:1` are both identified as private.
///
/// [`is_private_upstream_ip`]: praxis_core::connectivity::is_private_upstream_ip
fn find_private_addr(addrs: &[SocketAddr]) -> Option<std::net::IpAddr> {
    addrs.iter().map(SocketAddr::ip).find(is_private_upstream_ip)
}

/// Resolve a listener metrics label from the connection local address.
///
/// Prefers an exact bind-address match, then a same-port match (so
/// `0.0.0.0:5432` config can label traffic seen as `127.0.0.1:5432`),
/// then the group default.
fn resolve_listener_label(
    listener_names: &HashMap<String, ::metrics::SharedString>,
    listener_ports: &HashMap<String, ::metrics::SharedString>,
    default_listener_name: &::metrics::SharedString,
    local_addr: &str,
) -> ::metrics::SharedString {
    if let Some(name) = listener_names.get(local_addr) {
        return name.clone();
    }
    // Config may use `0.0.0.0:port` while the socket digest reports a
    // concrete interface address; fall back to matching on port. Under
    // a wildcard bind this fallback runs on every connection, so it
    // probes a precomputed port map instead of scanning the bind map.
    if let Some((_, port)) = local_addr.rsplit_once(':')
        && let Some(name) = listener_ports.get(port)
    {
        return name.clone();
    }
    default_listener_name.clone()
}

/// Derive the port → listener-name fallback map from the bind map.
fn ports_by_listener(names: &HashMap<String, ::metrics::SharedString>) -> HashMap<String, ::metrics::SharedString> {
    let mut ports = HashMap::with_capacity(names.len());
    for (bind_addr, name) in names {
        if let Some((_, port)) = bind_addr.rsplit_once(':') {
            ports.entry(port.to_owned()).or_insert_with(|| name.clone());
        }
    }
    ports
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
    use std::sync::{Mutex, atomic::AtomicUsize};

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[tokio::test]
    async fn forward_completed_returns_completed_reason() {
        let (_tx, mut rx) = watch::channel(false);
        let reason = forward_no_timeout(async { Ok((5_u64, 7_u64)) }, &mut rx, "10.0.0.1:5432").await;
        assert_eq!(reason, TcpCloseReason::Completed, "clean completion is 'completed'");
    }

    #[tokio::test]
    async fn forward_error_returns_error_reason() {
        let (_tx, mut rx) = watch::channel(false);
        let reason = forward_no_timeout(
            async { Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")) },
            &mut rx,
            "10.0.0.1:5432",
        )
        .await;
        assert_eq!(
            reason,
            TcpCloseReason::Error,
            "an I/O error must not be logged as 'completed'"
        );
    }

    #[tokio::test]
    async fn forward_shutdown_returns_shutdown_reason() {
        let (tx, mut rx) = watch::channel(false);
        tx.send(true).expect("send shutdown");
        let reason = forward_no_timeout(
            std::future::pending::<io::Result<(u64, u64)>>(),
            &mut rx,
            "10.0.0.1:5432",
        )
        .await;
        assert_eq!(
            reason,
            TcpCloseReason::Shutdown,
            "a server-shutdown close must not be logged as 'completed'"
        );
    }

    #[tokio::test]
    async fn forward_idle_timeout_returns_session_timeout_reason() {
        let (_tx, mut rx) = watch::channel(false);
        let reason = forward_with_timeout(
            std::future::pending::<io::Result<(u64, u64)>>(),
            &mut rx,
            Duration::from_millis(5),
            "10.0.0.1:5432",
        )
        .await;
        assert_eq!(
            reason,
            TcpCloseReason::SessionTimeout,
            "an idle-timeout close must not be logged as 'completed'"
        );
    }

    #[tokio::test]
    async fn counting_stream_tallies_both_directions() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let counters = ByteCounters::default();
        let (mut client, mut peer) = tokio::io::duplex(64);
        let mut counted = CountingStream {
            inner: &mut client,
            counters: &counters,
        };

        peer.write_all(b"12345").await.expect("peer write");
        let mut buf = [0_u8; 5];
        counted.read_exact(&mut buf).await.expect("counted read");
        counted.write_all(b"abc").await.expect("counted write");
        peer.read_exact(&mut [0_u8; 3]).await.expect("peer read");

        assert_eq!(
            counters.totals(),
            (5, 3),
            "reads from the client count as received and writes to it as sent"
        );
    }

    #[tokio::test]
    async fn byte_counters_survive_a_cancelled_copy() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let counters = ByteCounters::default();
        let (mut client, mut peer) = tokio::io::duplex(64);
        let mut counted = CountingStream {
            inner: &mut client,
            counters: &counters,
        };

        peer.write_all(b"partial").await.expect("peer write");
        let mut buf = [0_u8; 7];
        counted.read_exact(&mut buf).await.expect("counted read");

        let cancelled = tokio::time::timeout(Duration::from_millis(5), counted.read_u8()).await;
        assert!(cancelled.is_err(), "the read should time out with nothing further sent");
        assert_eq!(
            counters.totals().0,
            7,
            "bytes already forwarded must survive a cancelled copy; reporting zero here is the \
             regression these counters exist to prevent"
        );
    }

    #[test]
    fn tcp_close_reason_labels_are_stable() {
        assert_eq!(TcpCloseReason::Completed.as_str(), "completed");
        assert_eq!(TcpCloseReason::Error.as_str(), "error");
        assert_eq!(TcpCloseReason::Shutdown.as_str(), "shutdown");
        assert_eq!(TcpCloseReason::SessionTimeout.as_str(), "session_timeout");
        assert_eq!(TcpCloseReason::MaxDuration.as_str(), "max_duration");
    }

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
            lb_selection: None,
            cluster: Some(Arc::from(cluster)),
            health_registry: None,
            kv_stores: None,
            connect_time: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    #[tokio::test]
    async fn rejected_connection_runs_disconnect_release_hooks() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = counting_selector_reject_pipeline(&connects, &disconnects);

        let mut ctx = make_tcp_ctx("db");
        let result = resolve_connect_result(&pipeline, &mut ctx, "192.0.2.7:9999").await;

        assert!(result.is_none(), "the ACL filter should reject the connection");
        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            0,
            "resolution leaves cleanup to its caller"
        );
        release_selected_endpoint(&pipeline, &mut ctx).await;
        assert_eq!(
            connects.load(Ordering::SeqCst),
            1,
            "the selecting filter must run its connect hook exactly once"
        );
        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            1,
            "a rejected connection must run the disconnect hook so the selected endpoint's in-flight counter is released"
        );
    }

    #[tokio::test]
    async fn static_upstream_rejection_keeps_custom_disconnect_hook() {
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let pipeline = counting_selector_reject_pipeline(&connects, &disconnects);
        let mut ctx = make_tcp_ctx("db");
        ctx.upstream_addr = Some(Cow::Borrowed("127.0.0.1:5432"));

        let result = resolve_connect_result(&pipeline, &mut ctx, "192.0.2.7:9999").await;

        assert!(result.is_none(), "a later filter rejects the static upstream");
        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            0,
            "resolution must not start cleanup"
        );
        release_selected_endpoint(&pipeline, &mut ctx).await;
        assert_eq!(connects.load(Ordering::SeqCst), 1, "custom connect hook ran");
        assert_eq!(
            disconnects.load(Ordering::SeqCst),
            1,
            "custom disconnect hook still runs"
        );
    }

    #[test]
    fn resolve_listener_label_exact_bind_address() {
        let mut names = HashMap::new();
        names.insert("127.0.0.1:5432".to_owned(), ::metrics::SharedString::const_str("db1"));
        names.insert("127.0.0.1:5433".to_owned(), ::metrics::SharedString::const_str("db2"));
        let default = ::metrics::SharedString::const_str("db1");
        assert_eq!(
            resolve_listener_label(&names, &ports_by_listener(&names), &default, "127.0.0.1:5433").as_ref(),
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
            resolve_listener_label(&names, &ports_by_listener(&names), &default, "127.0.0.1:5433").as_ref(),
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
            resolve_listener_label(&names, &ports_by_listener(&names), &default, "unknown").as_ref(),
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

        let result = try_parse_sni(&record, filled, &mut None);
        assert!(
            matches!(&result, SniPeekResult::Parsed(info) if info.sni.as_deref() == Some("example.com")),
            "valid TLS ClientHello with SNI should return Parsed"
        );
    }

    #[test]
    fn try_parse_sni_empty_buffer() {
        let buf = [];
        let result = try_parse_sni(&buf, 0, &mut None);
        assert!(
            matches!(result, SniPeekResult::NeedMore),
            "empty buffer should return NeedMore"
        );
    }

    #[test]
    fn try_parse_sni_non_tls_data() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_sni(buf, buf.len(), &mut None);
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

        let result = try_parse_sni(truncated, 5, &mut None);
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

        let result = try_parse_sni(&padded, filled, &mut None);
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

        let action = handle_sni_read(&mut buf, filled, &mut None);
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

        let action = handle_sni_read(&mut buf, filled, &mut None);
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

        let action = handle_sni_read(&mut buf, filled, &mut None);
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

        let action = handle_sni_read(&mut buf, filled, &mut None);
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

        let action = handle_sni_read(&mut buf, filled, &mut None);
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

    mod tcp_duration_regressions {
        use super::*;

        #[tokio::test]
        async fn total_duration_includes_sni_setup() {
            let proxy = test_proxy(None, None, Duration::from_millis(80));
            let admission = proxy.try_admit("client").expect("admission");
            let (session, mut peer) = tokio::io::duplex(64);
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::time::timeout(
                Duration::from_millis(300),
                proxy.serve_connection(session, ("client", "listener"), &shutdown_rx, admission),
            )
            .await
            .expect("absolute duration must interrupt SNI peek before its 5-second limit");
            let mut byte = [0_u8; 1];
            assert_eq!(
                peer.read(&mut byte).await.expect("peer read"),
                0,
                "expired setup closes the socket"
            );
        }

        #[tokio::test]
        async fn total_duration_bounds_stalled_peek_replay() {
            let (mut output, _reader) = tokio::io::duplex(1);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
            let replay = tokio::time::timeout(
                Duration::from_millis(200),
                replay_peeked(&mut output, &[7_u8; 1_024], Some(deadline)),
            )
            .await
            .expect("absolute budget must interrupt a blocked replay");
            assert!(replay.is_none(), "replay consumes the original session budget");
        }

        #[tokio::test]
        async fn early_peer_close_finishes_before_duration_budget() {
            let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("backend bind");
            let upstream = backend.local_addr().expect("backend address").to_string();
            let proxy = test_proxy(Some(upstream), None, Duration::from_secs(2));
            let admission = proxy.try_admit("client").expect("admission");
            let (session, peer) = tokio::io::duplex(64);
            drop(peer);
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let backend_task = tokio::spawn(async move {
                let (stream, _) = backend.accept().await.expect("backend accepted");
                drop(stream);
            });
            tokio::time::timeout(
                Duration::from_millis(500),
                proxy.serve_connection(session, ("client", "listener"), &shutdown_rx, admission),
            )
            .await
            .expect("closed peer and backend should finish before max duration");
            backend_task.await.expect("backend task joined");
        }

        #[tokio::test]
        async fn duration_closes_sockets_before_stalled_disconnect_hook() {
            let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("backend bind");
            let upstream = backend.local_addr().expect("backend address").to_string();
            let pipeline = pending_disconnect_pipeline();
            let proxy = Arc::new(test_proxy(Some(upstream), Some(pipeline), Duration::from_millis(80)));
            let admission = proxy.try_admit("client").expect("admission");
            let (session, mut peer) = tokio::io::duplex(64);
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let serving = tokio::spawn(async move {
                proxy
                    .serve_connection(session, ("client", "listener"), &shutdown_rx, admission)
                    .await;
            });
            let (backend_stream, _) = tokio::time::timeout(Duration::from_millis(150), backend.accept())
                .await
                .expect("upstream connect before deadline")
                .expect("backend accepted");
            let mut byte = [0_u8; 1];
            let count = tokio::time::timeout(Duration::from_millis(300), peer.read(&mut byte))
                .await
                .expect("client socket closes before a stalled disconnect hook")
                .expect("peer read");
            assert_eq!(count, 0, "deadline closes downstream before hook completion");
            assert!(!serving.is_finished(), "custom disconnect hook remains pending");
            serving.abort();
            drop(backend_stream);
        }

        #[tokio::test]
        async fn total_duration_does_not_restart_after_connect() {
            let backend = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("backend bind");
            let upstream = backend.local_addr().expect("backend address").to_string();
            let proxy = Arc::new(test_proxy(Some(upstream), None, Duration::from_millis(600)));
            let admission = proxy.try_admit("client").expect("admission");
            tokio::time::sleep(Duration::from_millis(350)).await;
            let (session, _peer) = tokio::io::duplex(64);
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let serving = tokio::spawn(async move {
                proxy
                    .serve_connection(session, ("client", "listener"), &shutdown_rx, admission)
                    .await;
            });
            let (_upstream_socket, _) = tokio::time::timeout(Duration::from_millis(120), backend.accept())
                .await
                .expect("upstream connected before deadline")
                .expect("backend accepted");
            tokio::time::timeout(Duration::from_millis(350), serving)
                .await
                .expect("remaining budget must close forwarding")
                .expect("serve task joined");
        }

        #[tokio::test]
        async fn duration_expiry_releases_connect_filter_state() {
            let connects = Arc::new(AtomicUsize::new(0));
            let disconnects = Arc::new(AtomicUsize::new(0));
            let pipeline = pending_selector_pipeline(&connects, &disconnects);
            let proxy = test_proxy(None, Some(pipeline), Duration::from_millis(120));
            let admission = proxy.try_admit("client").expect("admission");
            let (session, mut peer) = tokio::io::duplex(1024);
            let hello = wrap_in_record(&build_client_hello(
                &[],
                &[0, 0xFF],
                &[0],
                &build_sni_extension("example.com"),
            ));
            peer.write_all(&hello).await.expect("complete ClientHello");
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::time::timeout(
                Duration::from_millis(350),
                proxy.serve_connection(session, ("client", "listener"), &shutdown_rx, admission),
            )
            .await
            .expect("connect filter must observe the same absolute deadline");
            assert_eq!(connects.load(Ordering::SeqCst), 1, "selector ran before pending filter");
            assert_eq!(
                disconnects.load(Ordering::SeqCst),
                1,
                "timed connect releases selected state"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn rejected_connect_cleanup_runs_once_across_deadline() {
            for fail in [false, true] {
                let disconnects = Arc::new(AtomicUsize::new(0));
                let entered = Arc::new(tokio::sync::Notify::new());
                let pipeline = rejecting_cleanup_pipeline(&disconnects, &entered, fail);
                let proxy = Arc::new(test_proxy(
                    Some("127.0.0.1:9".to_owned()),
                    Some(pipeline),
                    Duration::from_secs(1),
                ));
                let admission = proxy.try_admit("client").expect("admission");
                let (session, mut peer) = tokio::io::duplex(64);
                let (_shutdown_tx, shutdown_rx) = watch::channel(false);
                let serving = tokio::spawn(async move {
                    proxy
                        .serve_connection(session, ("client", "listener"), &shutdown_rx, admission)
                        .await;
                });
                entered.notified().await;
                assert_eq!(disconnects.load(Ordering::SeqCst), 1, "reverse counting hook completed");
                let mut byte = [0_u8; 1];
                assert_eq!(
                    peer.read(&mut byte).await.expect("peer EOF"),
                    0,
                    "socket closes before stalled cleanup"
                );
                tokio::time::advance(Duration::from_secs(2)).await;
                tokio::task::yield_now().await;
                assert_eq!(
                    disconnects.load(Ordering::SeqCst),
                    1,
                    "deadline must not restart rejection or error cleanup"
                );
                assert!(
                    !serving.is_finished(),
                    "cleanup remains pending outside the connect timeout"
                );
                serving.abort();
                assert!(serving.await.expect_err("task cancelled").is_cancelled());
            }
        }

        struct StalledCleanup {
            entered: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl praxis_filter::TcpFilter for StalledCleanup {
            fn name(&self) -> &'static str {
                "test_stalled_cleanup"
            }

            async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), praxis_filter::FilterError> {
                self.entered.notify_one();
                std::future::pending().await
            }
        }

        struct RejectWithCleanup {
            disconnects: Arc<AtomicUsize>,
            fail: bool,
        }

        #[async_trait]
        impl praxis_filter::TcpFilter for RejectWithCleanup {
            fn name(&self) -> &'static str {
                "test_reject_cleanup"
            }

            async fn on_connect(
                &self,
                _ctx: &mut TcpFilterContext<'_>,
            ) -> Result<FilterAction, praxis_filter::FilterError> {
                if self.fail {
                    Err("connect failed".into())
                } else {
                    Ok(FilterAction::Reject(praxis_filter::Rejection::status(403)))
                }
            }

            async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), praxis_filter::FilterError> {
                self.disconnects.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        fn rejecting_cleanup_pipeline(
            disconnects: &Arc<AtomicUsize>,
            entered: &Arc<tokio::sync::Notify>,
            fail: bool,
        ) -> FilterPipeline {
            let mut entries = serde_yaml::from_str::<Vec<praxis_core::config::FilterEntry>>(
                "- filter: test_stalled_cleanup\n- filter: test_reject_cleanup\n",
            )
            .expect("cleanup entries");
            let mut registry = praxis_filter::FilterRegistry::with_builtins();
            let entered = Arc::clone(entered);
            registry
                .register(
                    "test_stalled_cleanup",
                    praxis_filter::FilterFactory::Tcp(Arc::new(move |_| {
                        Ok(Box::new(StalledCleanup {
                            entered: Arc::clone(&entered),
                        }))
                    })),
                )
                .expect("stalled cleanup registered");
            let disconnects = Arc::clone(disconnects);
            registry
                .register(
                    "test_reject_cleanup",
                    praxis_filter::FilterFactory::Tcp(Arc::new(move |_| {
                        Ok(Box::new(RejectWithCleanup {
                            disconnects: Arc::clone(&disconnects),
                            fail,
                        }))
                    })),
                )
                .expect("reject cleanup registered");
            FilterPipeline::build(&mut entries, &registry).expect("cleanup pipeline")
        }

        struct PendingFilter;

        struct PendingDisconnectFilter;

        #[async_trait]
        impl praxis_filter::TcpFilter for PendingDisconnectFilter {
            fn name(&self) -> &'static str {
                "test_pending_disconnect"
            }

            async fn on_disconnect(&self, _ctx: &mut TcpFilterContext<'_>) -> Result<(), praxis_filter::FilterError> {
                std::future::pending().await
            }
        }

        fn pending_disconnect_pipeline() -> FilterPipeline {
            let mut entries: Vec<praxis_core::config::FilterEntry> =
                serde_yaml::from_str("- filter: test_pending_disconnect\n").expect("entry");
            let mut registry = praxis_filter::FilterRegistry::with_builtins();
            registry
                .register(
                    "test_pending_disconnect",
                    praxis_filter::FilterFactory::Tcp(Arc::new(|_| Ok(Box::new(PendingDisconnectFilter)))),
                )
                .expect("pending disconnect registered");
            FilterPipeline::build(&mut entries, &registry).expect("pipeline")
        }

        #[async_trait]
        impl praxis_filter::TcpFilter for PendingFilter {
            fn name(&self) -> &'static str {
                "test_pending_filter"
            }

            async fn on_connect(
                &self,
                _ctx: &mut TcpFilterContext<'_>,
            ) -> Result<FilterAction, praxis_filter::FilterError> {
                std::future::pending().await
            }
        }

        fn pending_selector_pipeline(connects: &Arc<AtomicUsize>, disconnects: &Arc<AtomicUsize>) -> FilterPipeline {
            let mut entries: Vec<praxis_core::config::FilterEntry> =
                serde_yaml::from_str("- filter: test_counting_selector\n- filter: test_pending_filter\n")
                    .expect("entries");
            let mut registry = praxis_filter::FilterRegistry::with_builtins();
            let connects = Arc::clone(connects);
            let disconnects = Arc::clone(disconnects);
            registry
                .register(
                    "test_counting_selector",
                    praxis_filter::FilterFactory::Tcp(Arc::new(move |_| {
                        Ok(Box::new(CountingSelectorFilter {
                            connects: Arc::clone(&connects),
                            disconnects: Arc::clone(&disconnects),
                        }))
                    })),
                )
                .expect("selector registered");
            registry
                .register(
                    "test_pending_filter",
                    praxis_filter::FilterFactory::Tcp(Arc::new(|_| Ok(Box::new(PendingFilter)))),
                )
                .expect("pending filter registered");
            FilterPipeline::build(&mut entries, &registry).expect("pipeline")
        }

        fn test_proxy(
            upstream: Option<String>,
            pipeline: Option<FilterPipeline>,
            maximum: Duration,
        ) -> PingoraTcpProxy {
            let pipeline = pipeline.unwrap_or_else(|| {
                FilterPipeline::build(&mut [], &praxis_filter::FilterRegistry::with_builtins()).expect("empty pipeline")
            });
            PingoraTcpProxy::new(
                upstream,
                None,
                Arc::new(ArcSwap::from_pointee(pipeline)),
                Some(Duration::from_secs(10)),
                Some(maximum),
                None,
                true,
                HashMap::new(),
                ::metrics::SharedString::const_str("test"),
            )
        }
    }
}
