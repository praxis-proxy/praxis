// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora `ProxyHttp` implementation: the main HTTP reverse-proxy
//! handler.
//!
//! Bridges Pingora's hook-based lifecycle (`request_filter`,
//! `upstream_peer`, `upstream_request_filter`, etc.) to the Praxis
//! filter pipeline via `PingoraHttpHandler` (body-capable). Body
//! hooks are always available so hot reload can add body filters and
//! Pingora compression init remains one-shot.
//!
//! Each submodule implements one Pingora hook. The pipeline is held
//! behind `Arc<ArcSwap<FilterPipeline>>` for lock-free hot reload.

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use pingora_core::{Result, server::Server, services::listening::Service};
use pingora_proxy::http_proxy;
use praxis_filter::FilterPipeline;
use tokio::sync::Semaphore;
use tracing::debug;

use super::metrics;

/// Safe per-request compression configuration.
mod compression;
/// Upstream connection established hook.
mod connected_to_upstream;
/// Structured error responses for fatal proxy errors.
mod fail_to_proxy;
/// Shared hop-by-hop header stripping logic.
mod hop_by_hop;
/// Request header normalization (duplicate headers, obs-fold).
mod normalize;
/// Request body filter hook.
mod request_body_filter;
/// Request filter hook.
mod request_filter;
/// Reserved internal header utilities.
mod reserved_headers;
/// Response body filter hook.
mod response_body_filter;
/// Response filter hook.
mod response_filter;
/// Response trailer hook: filter-driven trailer rewriting.
mod response_trailer_filter;
/// Response trailer hook: gRPC completion capture.
mod response_trailers;
/// Policy-aware retry decision engine.
mod retry;
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

/// Body mode clamping and stream buffer utilities.
mod body_util;
/// Passive health checking utilities.
mod health_util;
/// Fallback access log emission and response filter cleanup.
mod logging_util;
/// Request metrics emission utilities.
mod metrics_util;
/// Retry decision logic and state management.
mod retry_util;
/// Pingora HTTP/2 server option builders.
mod server_options;
/// Span attribute recording for request tracing.
mod span_util;

pub use upstream_peer::{UpstreamRetryGateRelease, arm_upstream_retry_gate, lock_upstream_retry_gate_tests};
pub use with_body::PingoraHttpHandler;

// -----------------------------------------------------------------------------
// Load Handler
// -----------------------------------------------------------------------------

/// Load an HTTP handler for a single listener.
///
/// Any TLS certificate watcher shutdown senders are appended to
/// `cert_watcher_shutdowns`. The watcher tasks run for the process
/// lifetime; the caller keeps this `Vec` to stop them early via
/// `send(true)` (dropping the senders does not stop them).
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
///     tcp_session_timeout_ms: None,
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
    pipeline: Arc<ArcSwap<FilterPipeline>>,
    cert_watcher_shutdowns: &mut Vec<tokio::sync::watch::Sender<bool>>,
) -> Result<(), praxis_core::ProxyError> {
    let downstream_read_timeout = listener.downstream_read_timeout_ms.map(Duration::from_millis);
    let connection_semaphore = listener
        .max_connections
        .map(|max| Arc::new(Semaphore::new(max as usize)));

    // Always use the body-capable handler: a reload may add body
    // filters, and compression init is one-shot in Pingora.
    debug!(listener = %listener.name, "loading HTTP handler with body filters");
    let handler = PingoraHttpHandler::new(
        pipeline,
        downstream_read_timeout,
        connection_semaphore,
        // `from_shared` keeps the label as a refcounted `Arc<str>`: the
        // handler clones it per connection, and an owned `String` label
        // would deep-copy on every clone.
        ::metrics::SharedString::from_shared(Arc::from(listener.name.as_str())),
    );
    wire_service(server, listener, handler, cert_watcher_shutdowns)?;
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
    proxy.server_options = Some(server_options::h2c_server_options());
    proxy.h2_options = Some(server_options::h2_server_options());
    let mut service = Service::new(service_name, proxy);
    if let Some(tx) = super::listener::add_listener(&mut service, listener)? {
        cert_watcher_shutdowns.push(tx);
    }
    server.add_service(service);
    Ok(())
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
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use bytes::Bytes;
    use praxis_core::{
        connectivity::{ConnectionOptions, Upstream},
        health::{ClusterHealthEntry, EndpointHealth},
    };
    use praxis_filter::{BodyBuffer, BodyMode, RequestExtensions};

    use super::*;
    use crate::http::pingora::context::PingoraRequestCtx;

    /// Maximum number of upstream connection retries for the legacy default policy.
    const MAX_RETRIES: usize = praxis_core::config::DEFAULT_MAX_RETRIES as usize;

    /// Default Pingora retry body buffer limit (64 `KiB`).
    const RETRY_BODY_LIMIT: u64 = praxis_core::config::DEFAULT_RETRY_BODY_LIMIT_BYTES;

    #[test]
    fn first_failure_idempotent_sets_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "first failure should set retry flag");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn large_body_skips_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = RETRY_BODY_LIMIT + 1;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry when body exceeds retry buffer limit");
        assert_eq!(ctx.retries, 0, "retry counter should not increment");
    }

    #[test]
    fn mutated_body_exceeding_limit_skips_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = 1024;
        ctx.mutated_request_body_len = Some((RETRY_BODY_LIMIT + 1) as usize);
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(
            !e.retry(),
            "should not retry when mutated body exceeds retry buffer limit"
        );
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn body_at_limit_allows_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = RETRY_BODY_LIMIT;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "body exactly at limit should allow retry");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn zero_body_allows_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = 0;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "zero-length body should allow retry");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn max_retries_exhausted_does_not_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retries = MAX_RETRIES as u32;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry after MAX_RETRIES");
        assert_eq!(ctx.retries as usize, MAX_RETRIES);
    }

    #[test]
    fn counter_increments_across_calls() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        for expected in 1..=MAX_RETRIES {
            let _result = retry_util::handle_connect_failure(&mut ctx, make_error());
            assert_eq!(ctx.retries as usize, expected);
        }
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry after reaching MAX_RETRIES");
        assert_eq!(ctx.retries as usize, MAX_RETRIES);
    }

    #[test]
    fn non_idempotent_request_never_retries() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = false;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "non-idempotent request should never retry");
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn connect_failure_clears_upstream_connect_start() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_connect_start = Some(std::time::Instant::now());
        let _e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(
            ctx.upstream_connect_start.is_none(),
            "failed connect should consume upstream_connect_start for duration recording"
        );
    }

    #[test]
    fn response_503_retries_when_status5xx_enabled() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retry_policy = Some(Arc::new(praxis_core::config::RetryPolicy {
            configured: true,
            retriable_conditions: vec![praxis_core::config::RetriableCondition::Status5xx],
            ..praxis_core::config::RetryPolicy::legacy_default()
        }));
        let e = retry_util::maybe_retry_response(&mut ctx, 503).expect("503 should be retriable");
        assert!(e.retry(), "503 under Status5xx should set retry");
        assert_eq!(ctx.retries, 1);
        assert!(ctx.reselect_on_retry);
        assert!(ctx.pending_backoff.is_some());
    }

    #[test]
    fn response_404_does_not_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retry_policy = Some(Arc::new(praxis_core::config::RetryPolicy {
            retriable_conditions: vec![praxis_core::config::RetriableCondition::Status5xx],
            ..praxis_core::config::RetryPolicy::legacy_default()
        }));
        assert!(
            retry_util::maybe_retry_response(&mut ctx, 404).is_none(),
            "404 must never trigger status-based retry"
        );
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn response_502_does_not_retry_under_legacy_default() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        assert!(
            retry_util::maybe_retry_response(&mut ctx, 502).is_none(),
            "legacy default must forward 5xx without retry"
        );
    }

    #[test]
    fn max_retries_zero_disables_connect_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retry_policy = Some(Arc::new(praxis_core::config::RetryPolicy {
            max_retries: Some(0),
            ..praxis_core::config::RetryPolicy::legacy_default()
        }));
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "max_retries: 0 must disable retries");
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn non_idempotent_clears_pingora_default_retry_flag() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = false;
        let mut e = make_error();
        e.set_retry(true);
        let e = retry_util::handle_connect_failure(&mut ctx, e);
        assert!(!e.retry(), "policy denial must clear Pingora's default retry flag");
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
        logging_util::logging_cleanup(&pipeline, &mut ctx).await;
    }

    #[tokio::test]
    async fn logging_cleanup_noop_when_no_snapshot() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = false;
        ctx.request_snapshot = None;
        logging_util::logging_cleanup(&pipeline, &mut ctx).await;
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
        logging_util::logging_cleanup(&pipeline, &mut ctx).await;
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("test-cluster"),
            "cluster must be restored so the fallback access record can attribute the failure"
        );
    }

    #[tokio::test]
    async fn logging_cleanup_preserves_filter_metadata() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = false;
        ctx.filter_metadata
            .insert("json_rpc.method".to_owned(), "service/invoke".to_owned());
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::POST,
            uri: "/api".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        logging_util::logging_cleanup(&pipeline, &mut ctx).await;
        assert_eq!(
            ctx.filter_metadata.get("json_rpc.method").map(String::as_str),
            Some("service/invoke"),
            "filter_metadata should survive logging_cleanup"
        );
    }

    #[tokio::test]
    async fn logging_cleanup_preserves_extensions() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.response_phase_done = false;
        ctx.extensions.insert(42_u32);
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::POST,
            uri: "/test".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        logging_util::logging_cleanup(&pipeline, &mut ctx).await;
        assert_eq!(
            ctx.extensions.get::<u32>(),
            Some(&42),
            "extensions should survive logging_cleanup"
        );
    }

    #[test]
    fn passive_health_error_is_failure() {
        let (pipeline, ctx) = make_passive_scenario(Some(3), Some(2));
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            entry.endpoints()[0].is_healthy(),
            "single failure should not yet mark unhealthy (threshold=3)"
        );
    }

    #[test]
    fn passive_health_downstream_error_is_not_failure() {
        let (pipeline, ctx) = make_passive_scenario(Some(1), Some(1));
        let error = make_error().into_down();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            entry.endpoints()[0].is_healthy(),
            "a downstream/client error must not mark the endpoint unhealthy"
        );
    }

    #[test]
    fn passive_health_downstream_error_with_5xx_still_counts_as_failure() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.upstream_response_status = Some(503);
        let error = make_error().into_down();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "a downstream error with an upstream 503 must still mark the endpoint unhealthy"
        );
    }

    #[test]
    fn passive_health_downstream_error_does_not_reset_failure_streak() {
        let (pipeline, ctx) = make_passive_scenario(Some(2), Some(1));
        let mut upstream_err = make_error();
        upstream_err.as_up();
        let downstream_err = make_error().into_down();

        health_util::record_passive_health(&pipeline, Some(&upstream_err), &ctx);
        health_util::record_passive_health(&pipeline, Some(&downstream_err), &ctx);
        health_util::record_passive_health(&pipeline, Some(&upstream_err), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "two upstream failures must eject the endpoint even with an interleaved client error"
        );
    }

    #[test]
    fn passive_health_upstream_error_is_failure() {
        let (pipeline, ctx) = make_passive_scenario(Some(1), Some(1));
        let mut error = make_error();
        error.as_up();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "an upstream error at unhealthy-threshold 1 must mark the endpoint unhealthy"
        );
    }

    #[test]
    fn passive_health_skips_observations_without_upstream_contact() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(2), Some(1));
        let mut upstream_err = make_error();
        upstream_err.as_up();

        health_util::record_passive_health(&pipeline, Some(&upstream_err), &ctx);

        ctx.upstream_contacted = false;
        health_util::record_passive_health(&pipeline, None, &ctx);

        ctx.upstream_response_status = Some(200);
        health_util::record_passive_health(&pipeline, None, &ctx);
        ctx.upstream_response_status = None;

        ctx.upstream_contacted = true;
        health_util::record_passive_health(&pipeline, Some(&upstream_err), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "observations without upstream contact must not reset the failure streak"
        );
    }

    #[test]
    fn passive_health_records_connect_failure_after_reselect_clears_upstream() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.upstream_for_retry = None;
        ctx.upstream_contacted = true;
        let mut error = make_error();
        error.as_up();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "a connect failure after reselection cleared upstream_for_retry must still count"
        );
    }

    #[test]
    fn passive_health_status_500_is_failure() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(3), Some(2));
        ctx.upstream_response_status = Some(500);
        health_util::record_passive_health(&pipeline, None, &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            entry.endpoints()[0].is_healthy(),
            "single 500 should not yet mark unhealthy (threshold=3)"
        );
    }

    #[test]
    fn passive_health_status_below_500_is_success() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(2), Some(1));
        ctx.upstream_response_status = Some(499);
        health_util::record_passive_health(&pipeline, None, &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(entry.endpoints()[0].is_healthy(), "status 499 should count as success");
    }

    #[test]
    fn passive_unhealthy_threshold_transition() {
        let (pipeline, ctx) = make_passive_scenario(Some(2), Some(1));
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "2 consecutive failures should mark unhealthy (threshold=2)"
        );
    }

    #[test]
    fn passive_healthy_threshold_recovery() {
        let (pipeline, ctx) = make_passive_scenario(Some(1), Some(2));
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "should be unhealthy after 1 failure"
        );

        let ctx_ok = make_passive_ctx("test-cluster", 0, Some(200));
        health_util::record_passive_health(&pipeline, None, &ctx_ok);
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "one success should not recover (threshold=2)"
        );

        health_util::record_passive_health(&pipeline, None, &ctx_ok);
        assert!(
            entry.endpoints()[0].is_healthy(),
            "2 consecutive successes should recover (threshold=2)"
        );
    }

    #[test]
    fn passive_health_no_thresholds_is_noop() {
        let (pipeline, ctx) = make_passive_scenario(None, None);
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            entry.endpoints()[0].is_healthy(),
            "no passive thresholds means failures are no-op"
        );
    }

    #[test]
    fn passive_health_endpoint_index_out_of_bounds() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.selected_endpoint_index = Some(999);
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(entry.endpoints()[0].is_healthy(), "out-of-bounds index should be no-op");
    }

    #[test]
    fn passive_health_missing_cluster_is_noop() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.cluster = None;
        ctx.metrics_cluster = None;
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_falls_back_to_metrics_cluster() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(2), Some(1));
        ctx.cluster = None;
        ctx.metrics_cluster = Some(Arc::from("test-cluster"));
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "fallback to metrics_cluster should still record passive health"
        );
    }

    #[test]
    fn passive_health_missing_endpoint_index_is_noop() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.selected_endpoint_index = None;
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_missing_registry_is_noop() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.cluster = Some(Arc::from("test-cluster"));
        ctx.selected_endpoint_index = Some(0);
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_unknown_cluster_is_noop() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.cluster = Some(Arc::from("nonexistent"));
        let error = make_error();
        health_util::record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn size_limit_none_body_returns_false() {
        let mut bytes = 0_u64;
        assert!(!body_util::check_body_size_limit(None, &mut bytes, 100));
        assert_eq!(bytes, 0, "accumulated bytes unchanged for None body");
    }

    #[test]
    fn size_limit_within_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"hello"));
        assert!(!body_util::check_body_size_limit(body.as_ref(), &mut bytes, 10));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_at_exact_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"exact"));
        assert!(!body_util::check_body_size_limit(body.as_ref(), &mut bytes, 5));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_exceeds_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"toolong"));
        assert!(body_util::check_body_size_limit(body.as_ref(), &mut bytes, 3));
    }

    #[test]
    fn size_limit_cumulative_overflow() {
        let mut bytes = 0_u64;
        let first = Some(Bytes::from_static(b"aaa"));
        assert!(!body_util::check_body_size_limit(first.as_ref(), &mut bytes, 5));

        let second = Some(Bytes::from_static(b"bbb"));
        assert!(body_util::check_body_size_limit(second.as_ref(), &mut bytes, 5));
        assert_eq!(bytes, 6);
    }

    #[test]
    fn stream_buffer_accumulates_chunks() {
        let mut body = Some(Bytes::from_static(b"hello "));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!body_util::accumulate_stream_buffer(
            &mut body,
            &mut buf,
            false,
            Some(100)
        ));
        assert!(buf.is_some());

        body = Some(Bytes::from_static(b"world"));
        assert!(!body_util::accumulate_stream_buffer(
            &mut body,
            &mut buf,
            false,
            Some(100)
        ));

        let frozen = buf.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn stream_buffer_freezes_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!body_util::accumulate_stream_buffer(
            &mut body,
            &mut buf,
            false,
            Some(100)
        ));

        body = Some(Bytes::from_static(b" end"));
        assert!(!body_util::accumulate_stream_buffer(
            &mut body,
            &mut buf,
            true,
            Some(100)
        ));
        assert!(buf.is_none(), "buffer should be taken at EOS");
        assert_eq!(body.unwrap(), Bytes::from_static(b"data end"));
    }

    #[test]
    fn stream_buffer_overflow() {
        let mut body = Some(Bytes::from_static(b"too long"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(body_util::accumulate_stream_buffer(&mut body, &mut buf, false, Some(5)));
    }

    #[test]
    fn stream_buffer_none_body() {
        let mut body: Option<Bytes> = None;
        let mut buf: Option<BodyBuffer> = None;
        assert!(!body_util::accumulate_stream_buffer(
            &mut body,
            &mut buf,
            false,
            Some(100)
        ));
        assert!(buf.is_none());
    }

    #[test]
    fn stream_buffer_uses_absolute_max_when_none() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!body_util::accumulate_stream_buffer(&mut body, &mut buf, false, None));
        assert!(buf.is_some(), "should create buffer with absolute max");
    }

    #[test]
    fn suppress_clears_body_when_buffering() {
        let mut body = Some(Bytes::from_static(b"data"));
        body_util::suppress_stream_buffer_chunk(&mut body, true, false, false);
        assert!(body.is_none());
    }

    #[test]
    fn suppress_noop_when_not_stream_buffer() {
        let mut body = Some(Bytes::from_static(b"data"));
        body_util::suppress_stream_buffer_chunk(&mut body, false, false, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_when_released() {
        let mut body = Some(Bytes::from_static(b"data"));
        body_util::suppress_stream_buffer_chunk(&mut body, true, true, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        body_util::suppress_stream_buffer_chunk(&mut body, true, false, true);
        assert!(body.is_some());
    }

    #[test]
    fn release_sets_flag_and_flushes_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"buffered")).unwrap();

        body_util::release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(released);
        assert_eq!(body.unwrap(), Bytes::from_static(b"buffered"));
        assert!(buf.is_none());
    }

    #[test]
    fn release_noop_when_already_released() {
        let mut body: Option<Bytes> = None;
        let mut released = true;
        let mut buf: Option<BodyBuffer> = None;

        body_util::release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(body.is_none(), "body should be unchanged when already released");
    }

    #[test]
    fn release_noop_when_not_stream_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf: Option<BodyBuffer> = None;

        body_util::release_stream_buffer(&mut body, false, &mut released, &mut buf, false);
        assert!(!released, "released flag should be unchanged for non-stream-buffer");
    }

    #[test]
    fn release_at_eos_sets_flag_but_no_flush() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"data")).unwrap();

        body_util::release_stream_buffer(&mut body, true, &mut released, &mut buf, true);
        assert!(released);
        assert!(body.is_none(), "body should not be overwritten at EOS");
        assert!(buf.is_some(), "buffer should not be taken at EOS");
    }

    #[test]
    fn write_back_transfers_fields() {
        let mut ctx = PingoraRequestCtx::default();

        let mut extensions = RequestExtensions::new();
        extensions.insert(42_u32);

        let state_val: Box<dyn std::any::Any + Send + Sync> = Box::new(99_i32);
        let filter_state = HashMap::from([(0_usize, state_val)]);

        let output = body_util::BodyFilterOutput {
            cluster: Some(Arc::from("test-cluster")),
            upstream: Some(Upstream {
                address: Arc::from("10.0.0.1:80"),
                authority: None,
                connection: Arc::new(ConnectionOptions::default()),
                tls: None,
            }),
            extensions,
            attempted_endpoints: Vec::new(),
            filter_metadata: HashMap::from([("key".to_owned(), "val".to_owned())]),
            filter_state,
            executed_branch_filters: vec![false, true, true],
            executed_filter_indices: vec![true, false],
            body_done_indices: vec![false, true],
        };
        output.write_back(&mut ctx);

        assert_eq!(ctx.cluster.as_deref(), Some("test-cluster"));
        assert!(ctx.upstream.is_some(), "upstream should transfer");
        assert_eq!(ctx.upstream.as_ref().unwrap().address.as_ref(), "10.0.0.1:80");
        assert_eq!(ctx.extensions.get::<u32>(), Some(&42));
        assert_eq!(ctx.filter_metadata.get("key").map(String::as_str), Some("val"));
        assert_eq!(ctx.filter_state.len(), 1, "filter_state should transfer");
        assert_eq!(
            ctx.filter_state.get(&0).and_then(|v| v.downcast_ref::<i32>()),
            Some(&99)
        );
        assert_eq!(ctx.cached_executed_branch_filters, vec![false, true, true]);
        assert_eq!(ctx.cached_executed_filter_indices, vec![true, false]);
        assert_eq!(ctx.cached_body_done_indices, vec![false, true]);
    }

    // -------------------------------------------------------------------------
    // Fallback Access Log
    // -------------------------------------------------------------------------

    #[test]
    fn fallback_access_log_emits_for_incomplete_request() {
        let pipeline = access_log_pipeline();
        let mut ctx = make_fallback_ctx();

        let events = capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut ctx));
        assert_eq!(
            events.len(),
            1,
            "incomplete request must produce a fallback access record"
        );
    }

    #[test]
    fn fallback_access_log_skips_completed_delivery() {
        let pipeline = access_log_pipeline();
        let mut ctx = make_fallback_ctx();
        ctx.response_delivery_complete = true;

        let events = capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 200, &mut ctx));
        assert!(events.is_empty(), "completed delivery already logged via the filter");
    }

    #[test]
    fn fallback_access_log_skips_upgraded_connections() {
        let pipeline = access_log_pipeline();
        let mut ctx = make_fallback_ctx();
        ctx.connection_upgraded = true;

        let events = capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 101, &mut ctx));
        assert!(events.is_empty(), "upgraded connections have no body completion");
    }

    #[test]
    fn fallback_access_log_skips_without_access_log_filter() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = make_fallback_ctx();

        let events = capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut ctx));
        assert!(events.is_empty(), "no access_log filter means no fallback record");
    }

    #[test]
    fn fallback_access_log_honors_entry_conditions() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let mut entries = vec![praxis_filter::FilterEntry {
            branch_chains: None,
            conditions: vec![serde_yaml::from_str("when:\n  path_prefix: /api\n").unwrap()],
            failure_mode: praxis_filter::FailureMode::default(),
            filter_type: "access_log".to_owned(),
            config: serde_yaml::Value::Null,
            name: None,
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();

        let mut excluded = make_fallback_ctx();
        let events =
            capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut excluded));
        assert!(
            events.is_empty(),
            "requests the operator scoped out must not gain fallback records"
        );

        let mut included = make_fallback_ctx();
        if let Some(snapshot) = included.request_snapshot.as_mut() {
            snapshot.uri = "/api/users".parse().unwrap();
        }
        let events =
            capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut included));
        assert_eq!(events.len(), 1, "in-scope incomplete requests still get a record");
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn fallback_access_log_honors_a_bound_upstream_condition() {
        for (axis, bound_records, unbound_records) in [("when", 1, 0), ("unless", 0, 1)] {
            let pipeline = access_log_pipeline_gated_on_binding(axis);
            let mut bound = make_fallback_ctx();
            bind_through_the_pipeline(&pipeline, &mut bound);
            let mut unbound = make_fallback_ctx();

            let bound_events =
                capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut bound));
            let unbound_events =
                capture_access_events(|| logging_util::maybe_emit_fallback_access_log(&pipeline, 502, &mut unbound));

            assert_eq!(
                bound_events.len(),
                bound_records,
                "{axis}: a request the router bound to openai is matched against its real binding"
            );
            assert_eq!(
                unbound_events.len(),
                unbound_records,
                "{axis}: a request that failed before routing has no binding to match"
            );
        }
    }

    #[test]
    fn aborted_response_body_at_eos_is_not_marked_delivered() {
        let pipeline = access_log_pipeline();
        let mut ctx = make_fallback_ctx();
        ctx.response_body_mode = BodyMode::SizeLimit { max_bytes: 4 };
        let mut body = Some(Bytes::from_static(b"exceeds the limit"));

        let result = response_body_filter::execute(&pipeline, &mut body, true, &mut ctx);
        assert!(result.is_err(), "over-limit body must abort");
        assert!(
            !ctx.response_delivery_complete,
            "a response aborted at end-of-stream was not delivered; the fallback record must fire"
        );
    }

    #[test]
    fn response_body_eos_marks_delivery_complete() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        let mut body: Option<Bytes> = None;

        let _timeout = response_body_filter::execute(&pipeline, &mut body, false, &mut ctx).unwrap();
        assert!(
            !ctx.response_delivery_complete,
            "mid-stream chunks must not mark delivery complete"
        );

        let _timeout = response_body_filter::execute(&pipeline, &mut body, true, &mut ctx).unwrap();
        assert!(ctx.response_delivery_complete, "end-of-stream marks delivery complete");
    }

    // -------------------------------------------------------------------------
    // Span Attribute Utilities
    // -------------------------------------------------------------------------

    #[test]
    fn http_version_label_http_09() {
        assert_eq!(
            span_util::http_version_label(http::Version::HTTP_09),
            "0.9",
            "HTTP/0.9 should map to '0.9'"
        );
    }

    #[test]
    fn http_version_label_http_10() {
        assert_eq!(
            span_util::http_version_label(http::Version::HTTP_10),
            "1.0",
            "HTTP/1.0 should map to '1.0'"
        );
    }

    #[test]
    fn http_version_label_http_11() {
        assert_eq!(
            span_util::http_version_label(http::Version::HTTP_11),
            "1.1",
            "HTTP/1.1 should map to '1.1'"
        );
    }

    #[test]
    fn http_version_label_http_2() {
        assert_eq!(
            span_util::http_version_label(http::Version::HTTP_2),
            "2",
            "HTTP/2 should map to '2'"
        );
    }

    #[test]
    fn http_version_label_http_3() {
        assert_eq!(
            span_util::http_version_label(http::Version::HTTP_3),
            "3",
            "HTTP/3 should map to '3'"
        );
    }

    #[test]
    fn record_response_span_attributes_noop_for_disabled_span() {
        let ctx = PingoraRequestCtx::default();
        assert!(ctx.request_span.is_disabled(), "default span should be disabled");
    }

    /// Layer that captures every `Span::record` call as `(field, value)` pairs.
    #[derive(Clone, Default)]
    struct RecordCapture(Arc<std::sync::Mutex<Vec<(String, String)>>>);

    impl<S> tracing_subscriber::Layer<S> for RecordCapture
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'a>(&'a mut Vec<(String, String)>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    self.0.push((field.name().to_owned(), format!("{value:?}")));
                }
            }
            let mut captured = self.0.lock().expect("capture lock");
            values.record(&mut Visitor(&mut captured));
        }
    }

    #[test]
    fn record_response_span_fields_records_status_upstream_and_cluster() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = RecordCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut ctx = PingoraRequestCtx::default();
        ctx.metrics_cluster = Some(Arc::from("api-cluster"));
        ctx.upstream_for_retry = Some(Upstream {
            address: Arc::from("10.0.0.1:80"),
            authority: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        });
        ctx.request_span = tracing::info_span!(
            "test_span",
            "http.response.status_code" = tracing::field::Empty,
            "otel.status_code" = tracing::field::Empty,
            "upstream.address" = tracing::field::Empty,
            "upstream.cluster" = tracing::field::Empty,
        );

        span_util::record_response_span_fields(Some(http::StatusCode::SERVICE_UNAVAILABLE), "GET", None, &ctx);

        let captured = capture.0.lock().expect("capture lock");
        let get = |name: &str| {
            let value = captured.iter().find(|(f, _)| f == name).map(|(_, v)| v.clone());
            assert!(value.is_some(), "field {name} not recorded; got {captured:?}");
            value.unwrap_or_default()
        };
        assert_eq!(get("http.response.status_code"), "503");
        assert_eq!(get("otel.status_code"), "\"ERROR\"", "5xx must set otel error status");
        assert_eq!(get("upstream.address"), "\"10.0.0.1:80\"");
        assert_eq!(get("upstream.cluster"), "\"api-cluster\"");
    }

    #[test]
    fn record_response_span_fields_success_has_no_error_status() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = RecordCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!(
            "test_span",
            "http.response.status_code" = tracing::field::Empty,
            "otel.status_code" = tracing::field::Empty,
        );

        span_util::record_response_span_fields(Some(http::StatusCode::OK), "GET", None, &ctx);

        let captured = capture.0.lock().expect("capture lock");
        assert!(
            captured
                .iter()
                .any(|(f, v)| f == "http.response.status_code" && v == "200"),
            "status should be recorded: {captured:?}"
        );
        assert!(
            !captured.iter().any(|(f, _)| f == "otel.status_code"),
            "2xx must not set otel error status: {captured:?}"
        );
    }

    #[test]
    fn record_response_span_attributes_records_exchange_span_fields() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!(
            "test_request",
            "http.response.status_code" = tracing::field::Empty,
            "server.address" = tracing::field::Empty,
            "upstream.cluster" = tracing::field::Empty,
        );
        ctx.upstream_exchange_span = tracing::info_span!(
            parent: &ctx.request_span,
            "upstream_exchange",
            "http.response.status_code" = tracing::field::Empty,
            "http.response.body.size" = tracing::field::Empty,
        );
        ctx.response_body_bytes = 4096;

        ctx.upstream_exchange_span.record("http.response.status_code", 200_u16);
        ctx.upstream_exchange_span.record("http.response.body.size", 4096_u64);
    }

    #[test]
    fn record_response_span_attributes_skips_exchange_when_disabled() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_span = tracing::info_span!(
            "test_request",
            "http.response.status_code" = tracing::field::Empty,
            "server.address" = tracing::field::Empty,
            "upstream.cluster" = tracing::field::Empty,
        );
        assert!(
            ctx.upstream_exchange_span.is_disabled(),
            "exchange span should be disabled by default"
        );
    }

    // -------------------------------------------------------------------------
    // Span Event Tests
    // -------------------------------------------------------------------------

    #[test]
    fn retry_with_upstream_address_sets_retry_flag() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.upstream_for_retry = Some(Upstream {
            address: Arc::from("10.0.0.1:8080"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
            authority: None,
        });
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "should retry with upstream address present");
        assert_eq!(ctx.retries, 1, "retry counter should increment to 1");
    }

    #[test]
    fn retry_without_upstream_address_uses_fallback() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.upstream_for_retry = None;
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(
            e.retry(),
            "should retry even when upstream_for_retry is None (address defaults to unknown)"
        );
        assert_eq!(ctx.retries, 1, "retry counter should increment to 1");
    }

    #[test]
    fn retry_exhausted_with_upstream_address_does_not_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.retries = MAX_RETRIES as u32;
        ctx.upstream_for_retry = Some(Upstream {
            address: Arc::from("10.0.0.2:443"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
            authority: None,
        });
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(
            !e.retry(),
            "should not retry after MAX_RETRIES even with upstream address"
        );
    }

    #[test]
    fn large_body_skip_with_upstream_address() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = RETRY_BODY_LIMIT + 1;
        ctx.upstream_for_retry = Some(Upstream {
            address: Arc::from("10.0.0.3:8080"),
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
            authority: None,
        });
        let e = retry_util::handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry large body even with upstream address");
        assert_eq!(ctx.retries, 0, "retry counter should not increment");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a connect error for tests.
    fn make_error() -> Box<pingora_core::Error> {
        pingora_core::Error::explain(pingora_core::ErrorType::ConnectError, "test connect failure")
    }

    /// Build a pipeline containing an `access_log` filter.
    fn access_log_pipeline() -> FilterPipeline {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let mut entries = vec![praxis_filter::FilterEntry {
            branch_chains: None,
            conditions: vec![],
            failure_mode: praxis_filter::FailureMode::default(),
            filter_type: "access_log".to_owned(),
            config: serde_yaml::Value::Null,
            name: None,
            response_conditions: vec![],
        }];
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Build a context with a request snapshot for fallback logging tests.
    /// A router, an `access_log` gated on the openai binding with `axis`, and a
    /// load balancer whose cluster carries the openai tag.
    #[cfg(feature = "upstream-binding")]
    fn access_log_pipeline_gated_on_binding(axis: &str) -> FilterPipeline {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str(&format!(
            r#"
- filter: router
  routes: [{{path_prefix: "/", cluster: backend}}]
- filter: access_log
  conditions: [{{{axis}: {{bound_upstream: {{application_provider: openai}}}}}}]
- filter: load_balancer
  clusters: [{{name: backend, http: {{application_provider: openai}}, endpoints: ["127.0.0.1:9"]}}]
"#
        ))
        .unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Run the request phase so the router publishes the binding into `ctx`,
    /// the way the handler leaves it for a request that later fails.
    #[cfg(feature = "upstream-binding")]
    fn bind_through_the_pipeline(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let extensions = {
            let mut filter_ctx = ctx.filter_context_for(pipeline, None).expect("the snapshot is present");
            drop(
                runtime
                    .block_on(pipeline.execute_http_request(&mut filter_ctx))
                    .expect("the router binds the catch-all route"),
            );
            std::mem::take(&mut filter_ctx.extensions)
        };
        ctx.extensions = extensions;
    }

    fn make_fallback_ctx() -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(praxis_filter::Request {
            method: http::Method::GET,
            uri: "/incomplete".parse().unwrap(),
            headers: http::HeaderMap::new(),
        });
        ctx
    }

    /// Capture `access` info events emitted while running `f`.
    fn capture_access_events<F: FnOnce()>(f: F) -> Vec<String> {
        use tracing_subscriber::layer::SubscriberExt as _;

        let messages = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let capture = AccessCapture(Arc::clone(&messages));
        let subscriber = tracing_subscriber::registry().with(capture);
        tracing::subscriber::with_default(subscriber, f);
        let mut guard = messages.lock().unwrap();
        std::mem::take(&mut *guard)
    }

    /// Layer capturing `access` records for assertions.
    struct AccessCapture(Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AccessCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            let mut visitor = AccessMessageVisitor(String::new());
            event.record(&mut visitor);
            if visitor.0.contains("access") {
                self.0.lock().unwrap().push(visitor.0);
            }
        }
    }

    /// Visitor extracting the `message` field from an event.
    struct AccessMessageVisitor(String);

    impl tracing::field::Visit for AccessMessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    /// Build a [`PingoraRequestCtx`] for passive health testing.
    fn make_passive_ctx(cluster: &str, endpoint_idx: usize, status: Option<u16>) -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx::default();
        ctx.cluster = Some(Arc::from(cluster));
        ctx.selected_endpoint_index = Some(endpoint_idx);
        ctx.upstream_response_status = status;
        // A passive-health observation implies the upstream was contacted.
        ctx.upstream_contacted = true;
        ctx
    }

    /// Build a pipeline with a health registry and a matching context
    /// for passive health testing.
    fn make_passive_scenario(
        passive_unhealthy: Option<u32>,
        passive_healthy: Option<u32>,
    ) -> (FilterPipeline, PingoraRequestCtx) {
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80")],
            passive_unhealthy,
            passive_healthy,
        );
        let mut map = HashMap::new();
        map.insert(Arc::from("test-cluster"), Arc::new(entry));
        let health_registry = Arc::new(map);

        let registry = praxis_filter::FilterRegistry::with_builtins();
        let mut pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        pipeline.set_health_registry(health_registry);

        let ctx = make_passive_ctx("test-cluster", 0, None);

        (pipeline, ctx)
    }
}
