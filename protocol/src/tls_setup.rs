// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shared TLS settings builder for HTTP and TCP listeners.

use pingora_core::listeners::tls::TlsSettings;
use praxis_core::ProxyError;
use praxis_tls::ListenerTls;
use tokio::sync::watch;

// -----------------------------------------------------------------------------
// TLS Settings Builder
// -----------------------------------------------------------------------------

/// Build [`TlsSettings`] for a listener.
///
/// When `hot_reload` is enabled, uses a [`ReloadableCertResolver`]
/// and spawns a [`CertWatcher`] background task. Otherwise builds
/// a static [`ServerConfig`] via [`build_server_config`].
///
/// `context_label` appears in debug tracing to distinguish HTTP
/// from TCP callers (e.g. `"HTTP"`, `"TCP"`).
///
/// Returns the settings and an optional shutdown sender for the
/// cert watcher. The caller must keep the sender alive; dropping
/// it signals the watcher task to stop.
///
/// [`TlsSettings`]: pingora_core::listeners::tls::TlsSettings
/// [`ServerConfig`]: rustls::ServerConfig
/// [`build_server_config`]: praxis_tls::setup::build_server_config
/// [`ReloadableCertResolver`]: praxis_tls::reload::ReloadableCertResolver
/// [`CertWatcher`]: praxis_tls::watcher::CertWatcher
pub(crate) fn build_tls_settings(
    tls: &ListenerTls,
    address: &str,
    context_label: &str,
) -> Result<(TlsSettings, Option<watch::Sender<bool>>), ProxyError> {
    macro_rules! tls_err {
        ($e:expr) => {
            ProxyError::Config(format!("TLS for {address}: {}", $e))
        };
    }

    if tls.is_hot_reload() {
        tracing::debug!(address, context_label, "building TLS ServerConfig with hot-reload");
        let (server_config, swap_handle) = praxis_tls::setup::build_reloadable_server_config(tls)
            .map_err(|e| ProxyError::Config(format!("TLS hot-reload for {address}: {e}")))?;

        let pair =
            tls.certificates.first().cloned().ok_or_else(|| {
                ProxyError::Config(format!("TLS hot-reload for {address}: no certificate configured"))
            })?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        praxis_tls::watcher::CertWatcher::spawn(swap_handle, pair, shutdown_rx);

        let settings = TlsSettings::with_server_config(server_config).map_err(|e| tls_err!(e))?;
        return Ok((settings, Some(shutdown_tx)));
    }

    tracing::debug!(address, context_label, "building TLS ServerConfig");
    let server_config = praxis_tls::setup::build_server_config(tls).map_err(|e| tls_err!(e))?;
    let settings = TlsSettings::with_server_config(server_config).map_err(|e| tls_err!(e))?;
    Ok((settings, None))
}
