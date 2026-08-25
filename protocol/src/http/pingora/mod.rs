// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Pingora HTTP integration: handler, listener setup, health endpoints.
//!
//! This module adapts Praxis's filter pipeline to Pingora's HTTP proxy
//! service. Pingora owns request-smuggling prevention, HTTP/2
//! backpressure, connection-pool safety, and HTTP/1.1 upgrade detection
//! with bidirectional forwarding (WebSocket and similar). Praxis code
//! layered on top, here and in the [`handler`] submodule, owns
//! hop-by-hop header stripping (with conditional preservation for
//! upgrade requests), Host validation, `X-Forwarded-*` injection, and
//! retry logic.

use std::sync::Arc;

use praxis_core::{
    PingoraServerRuntime, ProxyError,
    config::{Config, ProtocolKind},
};

use crate::{ListenerPipelines, Protocol};

/// Per-request context for filter pipeline results.
pub mod context;
pub(crate) mod convert;
/// HTTP proxy handler and Pingora integration.
pub mod handler;
/// Health check infrastructure: admin endpoints, probes, and background runner.
pub mod health;
pub(crate) mod json;
/// Admin endpoints for runtime key-value store CRUD.
pub mod kv;
/// Listener configuration and TLS setup.
pub mod listener;
/// Prometheus metrics: recorder, HTTP request counters, and scrape endpoint.
pub mod metrics;

// -----------------------------------------------------------------------------
// PingoraHttp
// -----------------------------------------------------------------------------

/// Pingora-backed HTTP protocol implementation.
pub struct PingoraHttp;

impl Protocol for PingoraHttp {
    fn register(
        self: Box<Self>,
        server: &mut PingoraServerRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<tokio::sync::watch::Sender<bool>>, ProxyError> {
        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        if http_listeners.is_empty() {
            return Ok(Vec::new());
        }

        let mut cert_watcher_shutdowns = Vec::new();
        for listener in &http_listeners {
            let pipeline = pipelines.get(&listener.name).map(Arc::clone).ok_or_else(|| {
                ProxyError::Config(format!("no pipeline for listener '{name}'", name = listener.name))
            })?;

            handler::load_http_handler(server.server_mut(), listener, pipeline, &mut cert_watcher_shutdowns)?;
        }

        Ok(cert_watcher_shutdowns)
    }
}
