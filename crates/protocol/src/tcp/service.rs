// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TCP protocol service construction and registration.

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use pingora_core::services::listening::Service;
use praxis_core::{ProxyError, config::Config};
use praxis_filter::{FilterPipeline, FilterRegistry};
use tokio::sync::{Semaphore, watch};

use super::{proxy, tls};
use crate::{ListenerPipelines, Protocol};

// -----------------------------------------------------------------------------
// PingoraTcp
// -----------------------------------------------------------------------------

/// Pingora-backed raw TCP/L4 protocol implementation.
///
/// Groups TCP listeners by `(upstream address, idle timeout, max duration)`,
/// creating one bidirectional forwarder per unique combination. Implements [`Protocol`].
///
/// [`Protocol`]: crate::Protocol
pub struct PingoraTcp;

impl Protocol for PingoraTcp {
    fn register(
        self: Box<Self>,
        server: &mut praxis_core::PingoraServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        let groups = tls::group_tcp_listeners(config);
        tls::validate_tcp_group_consistency(&groups)?;
        #[expect(clippy::expect_used, reason = "empty pipeline is infallible")]
        let fallback_pipeline = Arc::new(ArcSwap::from_pointee(
            FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).expect("empty pipeline is valid"),
        ));

        let mut cert_watcher_shutdowns = Vec::new();
        for (group_key, listeners) in groups {
            let mut service = build_tcp_service(&group_key, &listeners, pipelines, &fallback_pipeline, config);
            cert_watcher_shutdowns.extend(tls::register_tcp_listeners(
                &mut service,
                &listeners,
                group_key.0.as_deref(),
            )?);
            server.server_mut().add_service(service);
        }

        Ok(cert_watcher_shutdowns)
    }
}

// -----------------------------------------------------------------------------
// Service Construction
// -----------------------------------------------------------------------------

/// The listener group key: shared upstream address, cluster, idle timeout
/// (ms), and max session duration (secs).
type TcpGroupKey = (Option<String>, Option<String>, Option<u64>, Option<u64>);

/// Build the TCP proxy service for one listener group.
fn build_tcp_service(
    group_key: &TcpGroupKey,
    listeners: &[&praxis_core::config::Listener],
    pipelines: &ListenerPipelines,
    fallback_pipeline: &Arc<ArcSwap<FilterPipeline>>,
    config: &Config,
) -> Service<proxy::PingoraTcpProxy> {
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
    let app = proxy::PingoraTcpProxy::new(
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
    Service::new(tcp_service_name(upstream_opt.as_deref(), cluster_opt.as_deref()), app)
}

/// Derive the Pingora service name for a TCP listener group.
fn tcp_service_name(upstream: Option<&str>, cluster: Option<&str>) -> String {
    match (upstream, cluster) {
        (Some(addr), _) => format!("tcp-proxy:{addr}"),
        (_, Some(cluster)) => format!("tcp-proxy:cluster:{cluster}"),
        _ => "tcp-proxy:filter-routed".to_owned(),
    }
}

/// Build the per-address metric label map and the default listener label.
fn build_listener_labels(
    listeners: &[&praxis_core::config::Listener],
) -> (
    std::collections::HashMap<String, ::metrics::SharedString>,
    ::metrics::SharedString,
) {
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
