// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TCP protocol service construction and registration.

use std::{collections::BTreeMap, sync::Arc};

use arc_swap::ArcSwap;
use pingora_core::services::listening::Service;
use praxis_core::{ProxyError, config::Config};
use praxis_filter::{FilterPipeline, FilterRegistry};
use tokio::sync::watch;

use super::{
    groups::{self, TcpGroupKey},
    proxy, tls,
};
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
        server: &mut praxis_core::backend::Runtime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        let grouped = groups::group_tcp_listeners(config);
        groups::validate_tcp_group_consistency(&grouped)?;
        #[expect(clippy::expect_used, reason = "empty pipeline is infallible")]
        let fallback_pipeline = Arc::new(ArcSwap::from_pointee(
            FilterPipeline::build(&mut [], &FilterRegistry::with_builtins()).expect("empty pipeline is valid"),
        ));

        let mut cert_watcher_shutdowns = crate::cert_watcher_shutdowns::RegistrationWatchers::default();
        let ordered: BTreeMap<_, _> = grouped.into_iter().collect();
        for (group_key, listeners) in ordered {
            let mut service = build_tcp_service(&group_key, &listeners, pipelines, &fallback_pipeline, config);
            tls::register_tcp_listeners(
                &mut service,
                &listeners,
                group_key.0.as_deref(),
                cert_watcher_shutdowns.senders_mut(),
            )?;
            server.server_mut().add_service(service);
        }

        Ok(cert_watcher_shutdowns.finish())
    }
}

// -----------------------------------------------------------------------------
// Service Construction
// -----------------------------------------------------------------------------

/// Build the TCP proxy service for one listener group.
fn build_tcp_service(
    group_key: &TcpGroupKey,
    listeners: &[&praxis_core::config::Listener],
    pipelines: &ListenerPipelines,
    fallback_pipeline: &Arc<ArcSwap<FilterPipeline>>,
    config: &Config,
) -> Service<proxy::PingoraTcpProxy> {
    let (upstream_opt, cluster_opt, ..) = group_key;
    let app = proxy::build_group_proxy(group_key, listeners, pipelines, fallback_pipeline, config);
    let callback = app.pre_tls_callback();
    let mut service = Service::new(
        proxy::tcp_service_name(upstream_opt.as_deref(), cluster_opt.as_deref()),
        app,
    );
    service.endpoints().set_pre_tls_callback(callback);
    service
}
