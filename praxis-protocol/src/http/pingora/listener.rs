//! Adds TCP or TLS listeners to a Pingora HTTP proxy service.

use pingora_core::services::listening::Service;
use pingora_proxy::HttpProxy;
use praxis_core::ProxyError;
use tracing::info;

// -----------------------------------------------------------------------------
// Listener Handlers
// -----------------------------------------------------------------------------

/// Add a single HTTP listener to an HTTP proxy service.
///
/// Generic over the handler type so both [`HTTPHandler`]
/// and [`HTTPHandlerNoBody`] can use this function.
///
/// [`HTTPHandler`]: super::handler::HTTPHandler
/// [`HTTPHandlerNoBody`]: super::handler::HTTPHandlerNoBody
pub(crate) fn add_listener<H>(
    service: &mut Service<HttpProxy<H>>,
    listener: &praxis_core::config::Listener,
) -> Result<(), ProxyError> {
    let tls_enabled = listener.tls.is_some();

    if let Some(tls) = &listener.tls {
        let tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate(&tls.cert_path, &tls.key_path)
            .map_err(|e| ProxyError::Config(format!("failed to load TLS for {}: {e}", listener.address)))?;
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
