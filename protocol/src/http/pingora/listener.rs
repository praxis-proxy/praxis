// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Adds TCP or TLS listeners to a Pingora HTTP proxy service.

use pingora_core::services::listening::Service;
use pingora_proxy::HttpProxy;
use praxis_core::ProxyError;
use praxis_tls::ListenerTls;
use tracing::info;

// -----------------------------------------------------------------------------
// Listener Handlers
// -----------------------------------------------------------------------------

/// Add a single HTTP listener to an HTTP proxy service.
pub(crate) fn add_listener<H>(
    service: &mut Service<HttpProxy<H>>,
    listener: &praxis_core::config::Listener,
) -> Result<(), ProxyError> {
    let tls_enabled = listener.tls.is_some();

    if let Some(tls) = &listener.tls {
        let tls_settings = build_tls_settings(tls, &listener.address)?;
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

    Ok(())
}

/// Build [`TlsSettings`] for a listener.
///
/// Always builds a [`ServerConfig`] via [`build_server_config`]
/// and injects it with `with_server_config`, giving Praxis full
/// control over TLS configuration (ALPN, protocol versions,
/// crypto provider).
///
/// [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
/// [`ServerConfig`]: rustls::ServerConfig
/// [`build_server_config`]: praxis_tls::tls_setup::build_server_config
fn build_tls_settings(
    tls: &ListenerTls,
    address: &str,
) -> Result<pingora_core::listeners::tls::TlsSettings, ProxyError> {
    tracing::debug!(address, "building TLS ServerConfig");
    let server_config = praxis_tls::setup::build_server_config(tls)
        .map_err(|e| ProxyError::Config(format!("TLS for {address}: {e}")))?;
    pingora_core::listeners::tls::TlsSettings::with_server_config(server_config)
        .map_err(|e| ProxyError::Config(format!("TLS for {address}: {e}")))
}
