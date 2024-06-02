//! Pingora HTTP integration: handler, listener setup, health endpoints.
//!
//! Implements [`Protocol`] for HTTP listeners by
//! wiring Pingora's `ProxyHttp` trait to the Praxis filter pipeline.
//!
//! [`Protocol`]: crate::Protocol

use praxis_core::{
    ProxyError, ServerRuntime,
    config::{Config, ProtocolKind},
};

use crate::{ListenerPipelines, Protocol};

/// Per-request context for filter pipeline results.
pub mod context;
pub(crate) mod convert;
/// HTTP proxy handler and Pingora integration.
pub mod handler;
/// Health check HTTP endpoints.
pub mod health;
pub(crate) mod json;
/// Listener configuration and TLS setup.
pub mod listener;

// -----------------------------------------------------------------------------
// PingoraHttp
// -----------------------------------------------------------------------------

/// Pingora-backed HTTP/1.1 + HTTP/2 protocol implementation.
pub struct PingoraHttp;

impl Protocol for PingoraHttp {
    fn register(
        self: Box<Self>,
        server: &mut ServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<(), ProxyError> {
        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        if http_listeners.is_empty() {
            return Ok(());
        }

        for listener in &http_listeners {
            let pipeline = pipelines
                .get(&listener.name)
                .cloned()
                .ok_or_else(|| ProxyError::Config(format!("no pipeline for listener '{}'", listener.name)))?;

            handler::load_http_handler(server.server_mut(), listener, pipeline)?;
        }

        if let Some(admin_addr) = &config.admin_address {
            health::add_health_endpoint_to_pingora_server(server.server_mut(), admin_addr);
        }

        Ok(())
    }
}
