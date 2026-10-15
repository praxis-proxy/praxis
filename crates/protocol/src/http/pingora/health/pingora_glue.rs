// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Pingora glue for the admin, health and metrics listeners.
//!
//! Everything here is what a backend supplies for the management surface:
//! an [`AdminRequest`] view of its parsed request, a service per listener
//! that hands requests to the backend-neutral handlers in [`service`], and
//! the registration of those listeners and the recorder upkeep task on its
//! runtime.
//!
//! [`service`]: crate::http::pingora::health::service

use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderMap, Method, Response, Uri};
use pingora_core::{
    apps::http_app::ServeHttp,
    protocols::http::ServerSession,
    server::{Server, ShutdownWatch},
    services::{
        background::{BackgroundService, background_service},
        listening::Service,
    },
};
use praxis_core::{PingoraServerRuntime, health::HealthRegistry};
use tracing::info;

use super::{
    admin_host,
    admin_request::{AdminRequest, BodyReadError},
    listener_meta::ListenerMetaStore,
    service::{
        AdminEndpointOptions, PROMETHEUS_UPKEEP_INTERVAL, PingoraAdminService, PingoraHealthService,
        PrometheusAdminRecorder, install_prometheus_admin_recorder, run_prometheus_upkeep,
    },
};

// -----------------------------------------------------------------------------
// AdminRequest
// -----------------------------------------------------------------------------

impl AdminRequest for ServerSession {
    fn method(&self) -> &Method {
        &self.req_header().method
    }

    fn uri(&self) -> &Uri {
        &self.req_header().uri
    }

    fn headers(&self) -> &HeaderMap {
        &self.req_header().headers
    }

    async fn read_body(&mut self, limit: usize) -> Result<Vec<u8>, BodyReadError> {
        let mut buf = Vec::new();

        loop {
            match self.read_request_body().await {
                Ok(Some(chunk)) => {
                    if buf.len().saturating_add(chunk.len()) > limit {
                        return Err(BodyReadError::TooLarge);
                    }
                    buf.extend_from_slice(&chunk);
                },
                Ok(None) => break,
                Err(error) => return Err(BodyReadError::Io(error.to_string())),
            }
        }

        Ok(buf)
    }
}

// -----------------------------------------------------------------------------
// Services
// -----------------------------------------------------------------------------

#[async_trait]
impl ServeHttp for PingoraHealthService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        self.respond(http_session)
    }
}

#[async_trait]
impl ServeHttp for PingoraAdminService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        self.respond(http_session).await
    }
}

// -----------------------------------------------------------------------------
// Runtime Registration
// -----------------------------------------------------------------------------

/// Bind the `/api/*` admin listener on the runtime.
///
/// When `admin_addr` is loopback, requests with a non-loopback `Host` are
/// rejected. Register recorder upkeep separately if `/api/stats` is enabled.
pub fn add_admin_api(runtime: &mut PingoraServerRuntime, admin_addr: &str, options: AdminEndpointOptions) {
    add_admin_api_to_pingora_server(runtime.server_mut(), admin_addr, options);
}

/// Add the health and metrics listener on the runtime, installing the
/// Prometheus recorder and its upkeep.
pub fn add_health_endpoint(
    runtime: &mut PingoraServerRuntime,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
) {
    add_health_endpoint_to_pingora_server(runtime.server_mut(), metrics_addr, registry, verbose);
}

/// Add the health and metrics listener on the runtime with live pipeline
/// readiness, leaving the recorder lifecycle to the caller.
pub fn add_health_endpoint_with_pipelines(
    runtime: &mut PingoraServerRuntime,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
    pipelines: Option<(Arc<crate::ListenerPipelines>, ListenerMetaStore)>,
) {
    add_health_endpoint_to_pingora_server_with_pipelines(
        runtime.server_mut(),
        metrics_addr,
        registry,
        verbose,
        pipelines,
    );
}

/// Register recorder upkeep on the runtime.
pub fn add_prometheus_upkeep(runtime: &mut PingoraServerRuntime, recorder: PrometheusAdminRecorder) {
    add_prometheus_upkeep_to_pingora_server(runtime.server_mut(), recorder);
}

// -----------------------------------------------------------------------------
// Pingora Server Registration
// -----------------------------------------------------------------------------

/// Bind only the `/api/*` admin listener without installing a metrics recorder.
///
/// When `admin_addr` is loopback, requests with a non-loopback `Host` are
/// rejected. Register recorder upkeep separately if `/api/stats` is enabled.
pub fn add_admin_api_to_pingora_server(server: &mut Server, admin_addr: &str, options: AdminEndpointOptions) {
    let verbose = options.verbose;
    let require_loopback_host = admin_host::is_loopback_host(admin_addr);
    let admin = PingoraAdminService::from_options(admin_addr, options);
    let mut service = Service::new("admin".to_owned(), admin);
    service.add_tcp(admin_addr);
    info!(
        address = %admin_addr,
        verbose,
        require_loopback_host,
        "admin endpoints enabled (kv + pipelines + log-level + stats)"
    );
    server.add_service(service);
}

/// Add the health and metrics listener to a Pingora server.
///
/// Installs the Prometheus recorder and registers its upkeep service. Use
/// [`add_health_endpoint_to_pingora_server_with_pipelines`] when the caller
/// already owns that lifecycle.
pub fn add_health_endpoint_to_pingora_server(
    server: &mut Server,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
) {
    let recorder = install_prometheus_admin_recorder();
    add_prometheus_upkeep_to_pingora_server(server, recorder);
    add_health_endpoint_to_pingora_server_with_pipelines(server, metrics_addr, registry, verbose, None);
}

/// Add the health and metrics listener with live pipeline readiness.
///
/// This does not install the Prometheus recorder or its upkeep service; use it
/// when the caller already manages that lifecycle.
pub fn add_health_endpoint_to_pingora_server_with_pipelines(
    server: &mut Server,
    metrics_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
    pipelines: Option<(Arc<crate::ListenerPipelines>, ListenerMetaStore)>,
) {
    let require_loopback_host = admin_host::is_loopback_host(metrics_addr);
    let health = PingoraHealthService::new(registry, verbose).require_loopback_host(require_loopback_host);
    let health = match pipelines {
        Some((pipelines, meta)) => health.with_live_pipelines(pipelines, meta),
        None => health,
    };

    let mut service = Service::new("metrics".to_owned(), health);
    service.add_tcp(metrics_addr);
    info!(address = %metrics_addr, verbose, "metrics endpoints enabled (health + metrics)");
    server.add_service(service);
}

/// Register recorder upkeep after installing the recorder before startup
/// instrumentation begins.
pub fn add_prometheus_upkeep_to_pingora_server(server: &mut Server, recorder: PrometheusAdminRecorder) {
    let handle = recorder.handle;
    let upkeep = PrometheusUpkeepService { handle };
    server.add_service(background_service("Prometheus upkeep", upkeep));
}

// -----------------------------------------------------------------------------
// PrometheusUpkeepService
// -----------------------------------------------------------------------------

/// Pingora-managed recorder maintenance service.
struct PrometheusUpkeepService {
    /// Exporter handle used by each recorder maintenance pass.
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

#[async_trait]
impl BackgroundService for PrometheusUpkeepService {
    async fn start(&self, shutdown: ShutdownWatch) {
        let handle = self.handle.clone();
        run_prometheus_upkeep(
            shutdown,
            PROMETHEUS_UPKEEP_INTERVAL,
            Arc::new(move || handle.run_upkeep()),
        )
        .await;
    }
}
