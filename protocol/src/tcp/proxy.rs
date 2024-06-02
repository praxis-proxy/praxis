// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Pingora-backed bidirectional TCP proxy application.

use std::{future::Future, io, sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};
use praxis_filter::{FilterAction, FilterPipeline, TcpFilterContext};
use tokio::{net::TcpStream, sync::watch};
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// PingoraTcpProxy
// -----------------------------------------------------------------------------

/// Pingora-backed bidirectional TCP proxy: forwards every new connection to a fixed upstream.
pub(crate) struct PingoraTcpProxy {
    /// Optional idle timeout for the bidirectional forwarding session.
    idle_timeout: Option<Duration>,

    /// Optional maximum total session duration.
    max_duration: Option<Duration>,

    /// Shared filter pipeline for TCP filter hooks.
    pipeline: Arc<FilterPipeline>,

    /// Upstream address this proxy forwards to (e.g. "10.0.0.1:5432").
    upstream_addr: String,
}

impl PingoraTcpProxy {
    /// Create a TCP proxy targeting the given upstream address.
    pub(super) fn new(
        upstream_addr: String,
        pipeline: Arc<FilterPipeline>,
        idle_timeout: Option<Duration>,
        max_duration: Option<Duration>,
    ) -> Self {
        Self {
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
    ) -> (u64, u64) {
        let result = self.forward_inner(session, upstream, shutdown_rx).await;

        match result {
            Some(Ok((c2s, s2c))) => (c2s, s2c),
            Some(Err(e)) => {
                debug!(upstream = %self.upstream_addr, error = %e, "TCP session ended");
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
    ) -> Option<io::Result<(u64, u64)>> {
        let copy_fut = async {
            let copy_future = tokio::io::copy_bidirectional(session, upstream);
            match self.idle_timeout {
                Some(timeout) => forward_with_timeout(copy_future, shutdown_rx, timeout, &self.upstream_addr).await,
                None => forward_no_timeout(copy_future, shutdown_rx).await,
            }
        };

        if let Some(max_dur) = self.max_duration {
            if let Ok(r) = tokio::time::timeout(max_dur, copy_fut).await {
                r
            } else {
                warn!(
                    upstream = %self.upstream_addr,
                    max_duration_secs = max_dur.as_secs(),
                    "TCP session exceeded maximum duration"
                );
                None
            }
        } else {
            copy_fut.await
        }
    }

    /// Run TCP connect filters; returns `true` if the connection is allowed.
    async fn run_connect_filters(&self, remote_addr: &str, local_addr: &str, connect_time: std::time::Instant) -> bool {
        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            upstream_addr: &self.upstream_addr,
            connect_time,
            bytes_in: 0,
            bytes_out: 0,
        };
        match self.pipeline.execute_tcp_connect(&mut ctx).await {
            Ok(FilterAction::Continue | FilterAction::Release) => true,
            Ok(FilterAction::Reject(r)) => {
                warn!(remote = %remote_addr, status = r.status, "TCP connection rejected by filter");
                false
            },
            Err(e) => {
                warn!(remote = %remote_addr, error = %e, "TCP connect filter error");
                false
            },
        }
    }

    /// Run TCP disconnect filters for logging.
    #[allow(clippy::too_many_arguments, reason = "per-connection metrics")]
    async fn run_disconnect_filters(
        &self,
        remote_addr: &str,
        local_addr: &str,
        connect_time: std::time::Instant,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let mut ctx = TcpFilterContext {
            remote_addr,
            local_addr,
            upstream_addr: &self.upstream_addr,
            connect_time,
            bytes_in,
            bytes_out,
        };
        let _result = self.pipeline.execute_tcp_disconnect(&mut ctx).await;
    }
}

#[async_trait]
impl ServerApp for PingoraTcpProxy {
    async fn process_new(self: &Arc<Self>, mut session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let connect_time = std::time::Instant::now();
        let (remote_addr, local_addr) = extract_addrs(&session);

        if !self.run_connect_filters(&remote_addr, &local_addr, connect_time).await {
            return None;
        }

        let mut upstream = match TcpStream::connect(&self.upstream_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(upstream = %self.upstream_addr, error = %e, "failed to connect to TCP upstream");
                return None;
            },
        };

        let mut shutdown_rx: watch::Receiver<bool> = shutdown.clone();
        let (bytes_in, bytes_out) = self.forward(&mut session, &mut upstream, &mut shutdown_rx).await;

        self.run_disconnect_filters(&remote_addr, &local_addr, connect_time, bytes_in, bytes_out)
            .await;

        debug!("closing TCP session (connections not pooled)");
        None
    }
}

// -----------------------------------------------------------------------------
// Forwarding Utilities
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
