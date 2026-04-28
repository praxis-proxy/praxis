// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pingora `ProxyHttp` implementation: the main HTTP reverse-proxy handler.

use std::{sync::Arc, time::Duration};

use pingora_core::{Result, apps::HttpServerOptions, server::Server, services::listening::Service};
use pingora_proxy::{Session, http_proxy};
use praxis_filter::{CompressionConfig, FilterPipeline};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use super::context::PingoraRequestCtx;

/// Shared hop-by-hop header stripping logic.
mod hop_by_hop;
/// HTTP handler without body filter hooks.
mod no_body;
/// Request header normalization (duplicate headers, obs-fold).
mod normalize;
/// Request body filter hook.
mod request_body_filter;
/// Request filter hook.
mod request_filter;
/// Response body filter hook.
mod response_body_filter;
/// Response filter hook.
mod response_filter;
/// Upstream peer selection hook.
mod upstream_peer;
/// Upstream request transformation hook.
mod upstream_request;
/// Upstream response hop-by-hop stripping hook.
mod upstream_response;
/// Via header injection hook.
mod via;
/// HTTP handler with body filter hooks.
mod with_body;

pub use no_body::PingoraHttpHandlerNoBody;
pub use with_body::PingoraHttpHandler;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of upstream connection retries for idempotent requests.
const MAX_RETRIES: usize = 3;

// -----------------------------------------------------------------------------
// Load Handler
// -----------------------------------------------------------------------------

/// Load an HTTP handler for a single listener.
///
/// Any TLS certificate watcher shutdown senders are appended to
/// `cert_watcher_shutdowns`. The caller must keep this `Vec` alive
/// until server shutdown; dropping the senders signals the watcher
/// tasks to stop.
///
/// ```ignore
/// use std::sync::Arc;
///
/// use pingora_core::server::Server;
/// use praxis_core::config::Listener;
/// use praxis_filter::{FilterPipeline, FilterRegistry};
/// use praxis_protocol::http::pingora::handler::load_http_handler;
///
/// let mut server = Server::new(None).unwrap();
/// server.bootstrap();
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = Arc::new(FilterPipeline::build(&mut [], &registry).unwrap());
/// let listener = Listener {
///     name: "http".into(),
///     address: "127.0.0.1:8080".into(),
///     cluster: None,
///     downstream_read_timeout_ms: None,
///     filter_chains: vec![],
///     max_connections: None,
///     protocol: Default::default(),
///     tcp_idle_timeout_ms: None,
///     tcp_max_duration_secs: None,
///     tls: None,
///     upstream: None,
/// };
/// let mut shutdowns = Vec::new();
/// load_http_handler(&mut server, &listener, pipeline, &mut shutdowns).unwrap();
/// ```
///
/// # Errors
///
/// Returns [`ProxyError`] if the listener fails to bind.
///
/// [`ProxyError`]: praxis_core::ProxyError
pub fn load_http_handler(
    server: &mut Server,
    listener: &praxis_core::config::Listener,
    pipeline: Arc<FilterPipeline>,
    cert_watcher_shutdowns: &mut Vec<tokio::sync::watch::Sender<bool>>,
) -> Result<(), praxis_core::ProxyError> {
    let downstream_read_timeout = listener.downstream_read_timeout_ms.map(Duration::from_millis);
    let connection_semaphore = listener
        .max_connections
        .map(|max| Arc::new(Semaphore::new(max as usize)));

    if pipeline.needs_body_filters() {
        debug!(listener = %listener.name, "loading HTTP handler with body filters");
        let handler = PingoraHttpHandler::new(pipeline, downstream_read_timeout, connection_semaphore);
        wire_service(server, listener, handler, cert_watcher_shutdowns)?;
    } else {
        debug!(listener = %listener.name, "loading HTTP handler (no body filters)");
        let handler = PingoraHttpHandlerNoBody::new(pipeline, downstream_read_timeout, connection_semaphore);
        wire_service(server, listener, handler, cert_watcher_shutdowns)?;
    }
    Ok(())
}

/// Create a Pingora HTTP proxy service, bind the listener, and add it to the server.
fn wire_service<H>(
    server: &mut Server,
    listener: &praxis_core::config::Listener,
    handler: H,
    cert_watcher_shutdowns: &mut Vec<tokio::sync::watch::Sender<bool>>,
) -> Result<(), praxis_core::ProxyError>
where
    H: pingora_proxy::ProxyHttp + Send + Sync + 'static,
    H::CTX: Send + Sync,
{
    let service_name = format!("http-proxy:{name}", name = listener.name);
    let mut proxy = http_proxy(&server.configuration, handler);
    proxy.server_options = Some(h2c_server_options());
    let mut service = Service::new(service_name, proxy);
    if let Some(tx) = super::listener::add_listener(&mut service, listener)? {
        cert_watcher_shutdowns.push(tx);
    }
    server.add_service(service);
    Ok(())
}

// -----------------------------------------------------------------------------
// Shared Utilities
// -----------------------------------------------------------------------------

/// Apply compression settings from the pipeline config to the Pingora response.
fn adjust_compression(
    session: &mut Session,
    upstream_response: &pingora_http::ResponseHeader,
    compression: Option<&CompressionConfig>,
) {
    use pingora_core::{modules::http::compression::ResponseCompression, protocols::http::compression::Algorithm};

    let Some(cfg) = compression else {
        return;
    };

    let Some(module) = session.downstream_modules_ctx.get_mut::<ResponseCompression>() else {
        return;
    };

    let headers = &upstream_response.headers;

    if !cfg.should_compress(headers) {
        debug!("disabling compression: response does not qualify");
        module.adjust_level(0);
        return;
    }

    for (enabled, level, algo) in [
        (cfg.gzip_enabled, cfg.gzip_level, Algorithm::Gzip),
        (cfg.brotli_enabled, cfg.brotli_level, Algorithm::Brotli),
        (cfg.zstd_enabled, cfg.zstd_level, Algorithm::Zstd),
    ] {
        if !enabled {
            module.adjust_algorithm_level(algo, 0);
        } else if let Some(lvl) = level {
            module.adjust_algorithm_level(algo, lvl);
        }
    }
}

/// Handle upstream connect failures with retry logic.
fn handle_connect_failure(ctx: &mut PingoraRequestCtx, e: Box<pingora_core::Error>) -> Box<pingora_core::Error> {
    if ctx.request_is_idempotent {
        if (ctx.retries as usize) < MAX_RETRIES {
            ctx.retries += 1;
            debug!(
                retries = ctx.retries,
                max = MAX_RETRIES,
                "retrying idempotent request after connect failure"
            );
            let mut e = e;
            e.set_retry(true);
            return e;
        }
        warn!(
            retries = ctx.retries,
            max = MAX_RETRIES,
            "retry limit reached for idempotent request"
        );
    }
    e
}

/// Run response filters during the logging phase if the
/// response phase never executed (upstream error, filter
/// rejection, etc.).
async fn logging_cleanup(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    if !ctx.response_phase_done
        && let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None)
    {
        let _result = pipeline.execute_http_response(&mut filter_ctx).await;
    }
}

/// Build [`HttpServerOptions`] with h2c enabled.
///
/// [`HttpServerOptions`]: pingora_core::apps::HttpServerOptions
fn h2c_server_options() -> HttpServerOptions {
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn first_failure_idempotent_sets_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "first failure should set retry flag");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn max_retries_exhausted_does_not_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retries = MAX_RETRIES as u32;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry after MAX_RETRIES");
        assert_eq!(ctx.retries as usize, MAX_RETRIES);
    }

    #[test]
    fn counter_increments_across_calls() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        for expected in 1..=MAX_RETRIES {
            let _result = handle_connect_failure(&mut ctx, make_error());
            assert_eq!(ctx.retries as usize, expected);
        }
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry after reaching MAX_RETRIES");
        assert_eq!(ctx.retries as usize, MAX_RETRIES);
    }

    #[test]
    fn non_idempotent_request_never_retries() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = false;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "non-idempotent request should never retry");
        assert_eq!(ctx.retries, 0);
    }

    #[tokio::test]
    async fn logging_cleanup_noop_when_response_phase_done() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = true;
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        logging_cleanup(&pipeline, &mut ctx).await;
    }

    #[tokio::test]
    async fn logging_cleanup_noop_when_no_snapshot() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = false;
        ctx.request_snapshot = None;
        logging_cleanup(&pipeline, &mut ctx).await;
    }

    #[tokio::test]
    async fn logging_cleanup_runs_response_pipeline_when_needed() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = false;
        ctx.cluster = Some(Arc::from("test-cluster"));
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::GET,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        logging_cleanup(&pipeline, &mut ctx).await;
        assert!(ctx.cluster.is_none(), "cluster should be taken by logging_cleanup");
        assert!(ctx.upstream.is_none(), "upstream should be taken by logging_cleanup");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a connect error for tests.
    fn make_error() -> Box<pingora_core::Error> {
        pingora_core::Error::explain(pingora_core::ErrorType::ConnectError, "test connect failure")
    }
}
