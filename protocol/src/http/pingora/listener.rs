// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Adds TCP or TLS listeners to a Pingora HTTP proxy service.

use pingora_core::services::listening::Service;
use pingora_proxy::HttpProxy;
use praxis_core::ProxyError;
use tokio::sync::watch;
use tracing::info;

// -----------------------------------------------------------------------------
// Listener Handlers
// -----------------------------------------------------------------------------

/// Add a single HTTP listener to an HTTP proxy service.
///
/// Returns an optional shutdown sender for the TLS certificate
/// watcher. The caller must keep this sender alive; dropping it
/// signals the watcher task to stop.
pub(crate) fn add_listener<H>(
    service: &mut Service<HttpProxy<H>>,
    listener: &praxis_core::config::Listener,
) -> Result<Option<watch::Sender<bool>>, ProxyError> {
    let tls_enabled = listener.tls.is_some();
    let mut shutdown_tx = None;

    if let Some(tls) = &listener.tls {
        let (tls_settings, watcher_shutdown) = crate::tls_setup::build_tls_settings(tls, &listener.address, "HTTP")?;
        shutdown_tx = watcher_shutdown;
        service.add_tls_with_settings(&listener.address, None, tls_settings);
    } else {
        service.add_tcp(&listener.address);
    }

    info!(
        name = %listener.name,
        address = %listener.address,
        tls = tls_enabled,
        "HTTP listener registered"
    );

    Ok(shutdown_tx)
}
