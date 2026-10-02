// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora HTTP integration: handler, listener setup, health endpoints.
//!
//! This module adapts Praxis's filter pipeline to Pingora's HTTP proxy
//! service. Pingora owns request-smuggling prevention, HTTP/2
//! backpressure, connection-pool safety, and HTTP/1.1 upgrade detection
//! with bidirectional forwarding (WebSocket and similar). Praxis code
//! layered on top, here and in the [`handler`](crate::http::pingora::handler) submodule, owns
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
/// Trailers-Only responses for proxy-generated gRPC errors.
pub(crate) mod grpc_trailers;
/// HTTP proxy handler and Pingora integration.
pub mod handler;
/// Health check infrastructure: admin endpoints, probes, and background runner.
pub mod health;
#[cfg(feature = "admin-api")]
pub(crate) mod json;
/// Admin endpoints for runtime key-value store CRUD.
#[cfg(feature = "admin-api")]
pub mod kv;
/// Listener configuration and TLS setup.
pub mod listener;
/// Prometheus metrics: recorder, HTTP request counters, and scrape endpoint.
pub mod metrics;

// -----------------------------------------------------------------------------
// PingoraHttp
// -----------------------------------------------------------------------------

/// Pingora-backed HTTP protocol implementation.
///
/// Registers HTTP listeners from the configuration, binding them to Pingora
/// HTTP proxy services with filter pipelines. Delegates to
/// [`handler::load_http_handler`] for each listener. Implements [`Protocol`].
///
/// [`Protocol`]: crate::Protocol
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

            handler::load_http_handler_on_runtime(server, listener, pipeline, &mut cert_watcher_shutdowns)?;
        }

        Ok(cert_watcher_shutdowns)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::use_self,
    clippy::missing_panics_doc,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::config::{
        AdminConfig, BodyLimitsConfig, InsecureOptions, Listener, MetricsConfig, RuntimeConfig, TelemetryConfig,
    };
    use praxis_filter::{FilterPipeline, FilterRegistry};

    use super::*;

    /// Build a minimal Config with the given listeners.
    fn make_config(listeners: Vec<Listener>) -> Config {
        Config {
            admin: AdminConfig::default(),
            body_limits: BodyLimitsConfig::default(),
            clusters: vec![],
            filter_chains: vec![],
            insecure_options: InsecureOptions::default(),
            listeners,
            metrics: MetricsConfig::default(),
            runtime: RuntimeConfig::default(),
            shutdown_timeout_secs: 30,
            telemetry: TelemetryConfig::default(),
        }
    }

    /// Build a Listener with the given name and protocol.
    fn make_listener(name: &str, protocol: ProtocolKind) -> Listener {
        Listener {
            name: name.to_owned(),
            address: "127.0.0.1:8080".to_owned(),
            protocol,
            cluster: None,
            downstream_keepalive_timeout_ms: None,
            downstream_read_timeout_ms: None,
            filter_chains: vec![],
            max_connections: None,
            tcp_max_duration_secs: None,
            tcp_session_timeout_ms: None,
            tls: None,
            upstream: None,
        }
    }

    /// Build `ListenerPipelines` with empty pipelines for the given listener names.
    fn make_pipelines(names: &[&str]) -> ListenerPipelines {
        let registry = FilterRegistry::with_builtins();
        let mut map = HashMap::new();
        for name in names {
            let pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
            map.insert((*name).to_owned(), pipeline);
        }
        ListenerPipelines::new(map)
    }

    #[test]
    fn register_returns_empty_vec_when_no_http_listeners() {
        // Config with only TCP listeners
        let listeners = vec![
            make_listener("tcp1", ProtocolKind::Tcp),
            make_listener("tcp2", ProtocolKind::Tcp),
        ];
        let config = make_config(listeners);

        // PingoraServerRuntime is not easily mockable, so we test just the filtering logic
        // by checking what listeners would be processed
        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        assert!(
            http_listeners.is_empty(),
            "should have no HTTP listeners when all are TCP"
        );
    }

    #[test]
    fn register_returns_empty_vec_when_no_listeners_at_all() {
        let config = make_config(vec![]);

        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        assert!(
            http_listeners.is_empty(),
            "should have no HTTP listeners in empty config"
        );
    }

    #[test]
    fn register_filters_http_listeners_correctly() {
        let listeners = vec![
            make_listener("http1", ProtocolKind::Http),
            make_listener("tcp1", ProtocolKind::Tcp),
            make_listener("http2", ProtocolKind::Http),
        ];
        let config = make_config(listeners);

        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        assert_eq!(http_listeners.len(), 2, "should have exactly 2 HTTP listeners");
        assert_eq!(http_listeners[0].name, "http1");
        assert_eq!(http_listeners[1].name, "http2");
    }

    #[test]
    fn register_fails_when_pipeline_missing_for_listener() {
        let listeners = vec![
            make_listener("http1", ProtocolKind::Http),
            make_listener("http2", ProtocolKind::Http),
        ];
        let config = make_config(listeners);

        // Only provide pipeline for http1, not http2
        let pipelines = make_pipelines(&["http1"]);

        // Simulate the error path
        let listener = &config.listeners[1]; // http2
        let result = pipelines
            .get(&listener.name)
            .ok_or_else(|| ProxyError::Config(format!("no pipeline for listener '{name}'", name = listener.name)));

        assert!(result.is_err(), "should fail when pipeline is missing");
        if let Err(ProxyError::Config(msg)) = result {
            assert!(
                msg.contains("no pipeline for listener"),
                "error should mention missing pipeline"
            );
            assert!(msg.contains("http2"), "error should include listener name");
        } else {
            panic!("expected ProxyError::Config");
        }
    }

    #[test]
    fn register_finds_pipeline_for_matching_listener() {
        let listeners = vec![make_listener("web", ProtocolKind::Http)];
        let config = make_config(listeners);
        let pipelines = make_pipelines(&["web"]);

        let listener = &config.listeners[0];
        let result = pipelines.get(&listener.name);

        assert!(result.is_some(), "should find pipeline for matching listener");
    }

    #[test]
    fn register_processes_multiple_http_listeners() {
        let listeners = vec![
            make_listener("http1", ProtocolKind::Http),
            make_listener("http2", ProtocolKind::Http),
            make_listener("http3", ProtocolKind::Http),
        ];
        let config = make_config(listeners);
        let pipelines = make_pipelines(&["http1", "http2", "http3"]);

        // Verify all listeners have matching pipelines
        for listener in &config.listeners {
            assert!(
                pipelines.get(&listener.name).is_some(),
                "should have pipeline for {name}",
                name = listener.name
            );
        }
    }

    #[test]
    fn register_error_message_format() {
        let listener_name = "my-http-listener";
        let error = ProxyError::Config(format!("no pipeline for listener '{listener_name}'"));

        match error {
            ProxyError::Config(msg) => {
                assert_eq!(msg, "no pipeline for listener 'my-http-listener'");
                assert!(msg.starts_with("no pipeline"));
            },
        }
    }

    #[test]
    fn protocol_kind_http_equality() {
        assert_eq!(ProtocolKind::Http, ProtocolKind::Http);
        assert_ne!(ProtocolKind::Http, ProtocolKind::Tcp);
    }

    #[test]
    fn pingora_http_can_be_boxed() {
        let protocol: Box<dyn Protocol> = Box::new(PingoraHttp);
        // Just verify it can be created and boxed
        drop(protocol);
    }

    #[test]
    fn listener_name_used_for_pipeline_lookup() {
        let listener1 = make_listener("listener-one", ProtocolKind::Http);
        let listener2 = make_listener("listener-two", ProtocolKind::Http);

        let pipelines = make_pipelines(&["listener-one"]);

        assert!(
            pipelines.get(&listener1.name).is_some(),
            "should find pipeline by exact name match"
        );
        assert!(
            pipelines.get(&listener2.name).is_none(),
            "should not find pipeline for non-existent name"
        );
    }

    #[test]
    fn empty_pipeline_lookup_returns_none() {
        let pipelines = make_pipelines(&[]);
        assert!(
            pipelines.get("any-name").is_none(),
            "empty pipelines should return None"
        );
    }

    #[test]
    fn protocol_error_config_variant() {
        let error = ProxyError::Config("test error".to_owned());
        match error {
            ProxyError::Config(msg) => assert_eq!(msg, "test error"),
        }
    }

    #[test]
    fn http_listener_filtering_with_mixed_protocols() {
        let listeners = vec![
            make_listener("http1", ProtocolKind::Http),
            make_listener("tcp1", ProtocolKind::Tcp),
            make_listener("http2", ProtocolKind::Http),
            make_listener("tcp2", ProtocolKind::Tcp),
            make_listener("http3", ProtocolKind::Http),
        ];
        let config = make_config(listeners);

        let http_listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|l| l.protocol == ProtocolKind::Http)
            .collect();

        assert_eq!(http_listeners.len(), 3);
        assert!(http_listeners.iter().all(|l| l.protocol == ProtocolKind::Http));
    }
}
