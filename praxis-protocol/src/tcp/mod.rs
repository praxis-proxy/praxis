//! Raw TCP/L4 bidirectional forwarding protocol.
//!
//! Each TCP listener forwards connections to a fixed upstream address
//! using `tokio::io::copy_bidirectional`. Implements [`Protocol`]
//! for `protocol: tcp` listeners.
//!
//! [`Protocol`]: crate::Protocol

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch, services::listening::Service};
use praxis_core::{
    ProxyError,
    config::{Config, ProtocolKind},
};
use praxis_filter::{FilterAction, FilterPipeline, FilterRegistry, TcpFilterContext};
use tokio::{net::TcpStream, sync::watch};
use tracing::{info, warn};

use crate::{ListenerPipelines, Protocol};

// -----------------------------------------------------------------------------
// TcpProxy
// -----------------------------------------------------------------------------

/// Bidirectional TCP proxy: forwards every new connection to a fixed upstream.
pub(crate) struct TcpProxy {
    /// Upstream address this proxy forwards to (e.g. "10.0.0.1:5432").
    upstream_addr: String,

    /// Shared filter pipeline for TCP filter hooks.
    pipeline: Arc<FilterPipeline>,

    /// Optional idle timeout for the bidirectional forwarding session.
    idle_timeout: Option<Duration>,
}

impl TcpProxy {
    /// Create a TCP proxy targeting the given upstream address.
    fn new(upstream_addr: String, pipeline: Arc<FilterPipeline>, idle_timeout: Option<Duration>) -> Self {
        Self {
            upstream_addr,
            pipeline,
            idle_timeout,
        }
    }

    /// Run bidirectional forwarding, returning `(bytes_in, bytes_out)`.
    ///
    /// Respects the configured idle timeout and the server-wide shutdown
    /// signal. When shutdown fires the connection is dropped gracefully.
    async fn forward(
        &self,
        session: &mut Stream,
        upstream: &mut TcpStream,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> (u64, u64) {
        let copy_future = tokio::io::copy_bidirectional(session, upstream);

        let result = match self.idle_timeout {
            Some(timeout) => {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => return (0, 0),
                    r = tokio::time::timeout(timeout, copy_future) => match r {
                        Ok(inner) => inner,
                        Err(_) => {
                            warn!(
                                upstream = %self.upstream_addr,
                                timeout_ms = timeout.as_millis() as u64,
                                "TCP session timed out"
                            );
                            return (0, 0);
                        },
                    },
                }
            },
            None => {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => return (0, 0),
                    r = copy_future => r,
                }
            },
        };

        match result {
            Ok((client_to_server, server_to_client)) => (client_to_server, server_to_client),
            Err(e) => {
                // BrokenPipe / ConnectionReset are normal when either side disconnects.
                tracing::debug!(upstream = %self.upstream_addr, error = %e, "TCP session ended");
                (0, 0)
            },
        }
    }
}

#[async_trait]
impl ServerApp for TcpProxy {
    async fn process_new(self: &Arc<Self>, mut session: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let connect_time = std::time::Instant::now();
        let digest = session.get_socket_digest();
        let remote_addr = digest
            .as_ref()
            .and_then(|d| d.peer_addr())
            .map_or_else(|| "unknown".to_owned(), std::string::ToString::to_string);
        let local_addr = digest
            .as_ref()
            .and_then(|d| d.local_addr())
            .map_or_else(|| "unknown".to_owned(), std::string::ToString::to_string);
        let mut connect_ctx = TcpFilterContext {
            remote_addr: &remote_addr,
            local_addr: &local_addr,
            upstream_addr: &self.upstream_addr,
            connect_time,
            bytes_in: 0,
            bytes_out: 0,
        };
        match self.pipeline.execute_tcp_connect(&mut connect_ctx).await {
            Ok(FilterAction::Continue | FilterAction::Release) => {},
            Ok(FilterAction::Reject(r)) => {
                warn!(
                    remote = %remote_addr,
                    status = r.status,
                    "TCP connection rejected by filter"
                );
                return None;
            },
            Err(e) => {
                warn!(remote = %remote_addr, error = %e, "TCP connect filter error");
                return None;
            },
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

        let mut disconnect_ctx = TcpFilterContext {
            remote_addr: &remote_addr,
            local_addr: &local_addr,
            upstream_addr: &self.upstream_addr,
            connect_time,
            bytes_in,
            bytes_out,
        };
        let _ = self.pipeline.execute_tcp_disconnect(&mut disconnect_ctx).await;

        // Connections are not pooled, so close session
        None
    }
}

// -----------------------------------------------------------------------------
// PingoraTcp
// -----------------------------------------------------------------------------

/// Pingora-backed raw TCP/L4 protocol implementation.
///
/// Groups TCP listeners by `(upstream address, idle timeout)`, creating
/// one bidirectional forwarder per unique combination. Implements
/// [`Protocol`].
///
/// [`Protocol`]: crate::Protocol
pub struct PingoraTcp;

impl Protocol for PingoraTcp {
    fn register(
        self: Box<Self>,
        server: &mut praxis_core::ServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<(), ProxyError> {
        // Group listeners by (upstream address, idle timeout) so listeners
        // with different timeouts get separate TcpProxy instances.
        let mut groups: HashMap<(String, Option<u64>), Vec<&praxis_core::config::Listener>> = HashMap::new();

        for listener in &config.listeners {
            if listener.protocol != ProtocolKind::Tcp {
                continue;
            }
            if let Some(ref upstream) = listener.upstream {
                let key = (upstream.clone(), listener.tcp_idle_timeout_ms);
                groups.entry(key).or_default().push(listener);
            }
        }

        // Build a shared fallback pipeline once, rather than per group.
        let fallback_pipeline =
            Arc::new(FilterPipeline::build(&[], &FilterRegistry::with_builtins()).expect("empty pipeline is valid"));

        for ((upstream_addr, timeout_ms), listeners) in groups {
            // Get pipeline from first listener, or use the shared fallback.
            let pipeline = listeners
                .first()
                .and_then(|l| pipelines.get(&l.name))
                .cloned()
                .unwrap_or_else(|| Arc::clone(&fallback_pipeline));

            let idle_timeout = timeout_ms.map(Duration::from_millis);

            let app = TcpProxy::new(upstream_addr.clone(), pipeline, idle_timeout);
            let mut service = Service::new(format!("tcp-proxy:{upstream_addr}"), app);

            for listener in listeners {
                if let Some(ref tls) = listener.tls {
                    let tls_settings =
                        pingora_core::listeners::tls::TlsSettings::intermediate(&tls.cert_path, &tls.key_path)
                            .map_err(|e| ProxyError::Config(format!("TLS for {}: {e}", listener.address)))?;
                    service.add_tls_with_settings(&listener.address, None, tls_settings);
                } else {
                    service.add_tcp(&listener.address);
                }

                info!(
                    name = %listener.name,
                    address = %listener.address,
                    upstream = %upstream_addr,
                    "TCP listener registered"
                );
            }

            server.server_mut().add_service(service);
        }

        Ok(())
    }
}
