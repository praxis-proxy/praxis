// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! TLS and plain listener registration for the Pingora TCP service.

use pingora_core::services::listening::Service;
use praxis_core::ProxyError;
use tracing::info;

use super::proxy::PingoraTcpProxy;

// -----------------------------------------------------------------------------
// Listener Registration
// -----------------------------------------------------------------------------

/// Add TCP or TLS listeners to a service.
///
/// Returns any TLS certificate watcher shutdown senders. The
/// caller must keep these alive; dropping them signals the
/// watcher tasks to stop.
pub(super) fn register_tcp_listeners(
    service: &mut Service<PingoraTcpProxy>,
    listeners: &[&praxis_core::config::Listener],
    upstream: Option<&str>,
) -> Result<Vec<tokio::sync::watch::Sender<bool>>, ProxyError> {
    let display_upstream = upstream.unwrap_or("filter-routed");
    let mut shutdown_senders = Vec::new();
    for listener in listeners {
        if let Some(tls) = &listener.tls {
            let (tls_settings, watcher_shutdown) = build_tcp_tls_settings(tls, &listener.address)?;
            if let Some(tx) = watcher_shutdown {
                shutdown_senders.push(tx);
            }
            service.add_tls_with_settings(&listener.address, None, tls_settings);
        } else {
            service.add_tcp(&listener.address);
        }
        info!(
            name = %listener.name,
            address = %listener.address,
            upstream = %display_upstream,
            "TCP listener registered"
        );
    }
    Ok(shutdown_senders)
}

// -----------------------------------------------------------------------------
// TLS
// -----------------------------------------------------------------------------

/// Build [`TlsSettings`] for a TCP listener.
///
/// Delegates to the shared [`build_tls_settings`] with a `"TCP"`
/// context label.
///
/// [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
/// [`build_tls_settings`]: crate::tls_setup::build_tls_settings
fn build_tcp_tls_settings(
    tls: &praxis_tls::ListenerTls,
    address: &str,
) -> Result<
    (
        pingora_core::listeners::tls::TlsSettings,
        Option<tokio::sync::watch::Sender<bool>>,
    ),
    ProxyError,
> {
    crate::tls_setup::build_tls_settings(tls, address, "TCP", false)
}
