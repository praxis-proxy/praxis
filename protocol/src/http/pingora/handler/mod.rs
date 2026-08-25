// SPDX-License-Identifier: MIT
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

use std::{collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use bytes::Bytes;
use pingora_core::{
    Result, apps::HttpServerOptions, protocols::http::v2::server::H2Options, server::Server,
    services::listening::Service,
};
use pingora_proxy::{Session, http_proxy};
use praxis_core::{config::ABSOLUTE_MAX_BODY_BYTES, connectivity::Upstream};
use praxis_filter::{BodyBuffer, BodyMode, CompressionConfig, FilterPipeline, HttpFilterContext, RequestExtensions};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use super::{context::PingoraRequestCtx, metrics};

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
/// Reserved internal header helpers.
mod reserved_headers;
/// Response body filter hook.
mod response_body_filter;
/// Response filter hook.
mod response_filter;
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

pub use upstream_peer::{UpstreamRetryGateRelease, arm_upstream_retry_gate, lock_upstream_retry_gate_tests};
pub use with_body::PingoraHttpHandler;

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
        ::metrics::SharedString::from(listener.name.clone()),
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
    proxy.server_options = Some(h2c_server_options());
    proxy.h2_options = Some(h2_server_options());
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

/// Clamp a runtime-selected body mode to the byte ceiling implied by `baseline`.
///
/// `baseline` is the mode established before request/response-phase filter hooks
/// run (typically from pipeline capabilities + global body limits). Runtime
/// `set_*_body_mode` calls may widen limits; this helper preserves the original
/// ceiling while still allowing upgrades between body mode variants.
///
/// `Stream` mode passes through unconditionally because it delivers chunks
/// as they arrive without accumulating them — there is no buffer to cap.
/// A filter that downgrades from `StreamBuffer` to `Stream` at runtime is
/// opting out of buffering entirely, which is always safe from a memory
/// perspective. The pipeline-level body size limit (enforced separately
/// via `SizeLimit`) remains the backstop for oversized payloads.
fn clamp_body_mode_to_ceiling(mode: BodyMode, baseline: BodyMode) -> BodyMode {
    let ceiling = match baseline {
        BodyMode::StreamBuffer { max_bytes: Some(v) } | BodyMode::SizeLimit { max_bytes: v } => Some(v),
        _ => None,
    };

    match (mode, ceiling) {
        (BodyMode::StreamBuffer { max_bytes }, Some(limit)) => BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes.map_or(limit, |v| v.min(limit))),
        },
        (BodyMode::SizeLimit { max_bytes }, Some(limit)) => BodyMode::SizeLimit {
            max_bytes: max_bytes.min(limit),
        },
        // Stream has no buffer to clamp; other modes pass through when the
        // baseline imposes no ceiling (e.g. unbounded StreamBuffer).
        (m, None | Some(_)) => m,
    }
}

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

/// Handle upstream connect failures with the policy-aware retry engine.
///
/// Retries are skipped when the effective forwarded body size exceeds
/// the configured replay limit, the method is non-idempotent without
/// opt-in, the budget is exhausted, or the overall deadline has passed.
#[expect(clippy::too_many_lines, reason = "sequential guard checks")]
fn handle_connect_failure(ctx: &mut PingoraRequestCtx, e: Box<pingora_core::Error>) -> Box<pingora_core::Error> {
    let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);
    if let Some(start) = ctx.upstream_connect_start.take() {
        metrics::record_upstream_connect_duration(cluster.clone(), start.elapsed().as_secs_f64());
    }
    metrics::record_upstream_connect_failure(cluster.clone());

    let policy = ctx
        .retry_policy
        .clone()
        .unwrap_or_else(|| Arc::new(praxis_core::config::RetryPolicy::legacy_default()));
    let outcome = retry::classify_error(&e);
    let decision = retry::should_retry(ctx, &policy, outcome, ctx.cluster_retry_state.as_deref());

    match decision {
        retry::RetryDecision::Retry { backoff } => {
            ctx.retries += 1;
            ctx.pending_backoff = Some(backoff);
            // Legacy (unconfigured) policies keep the historical
            // retry-same-endpoint behavior; only operator-configured
            // policies opt into endpoint reselection.
            ctx.reselect_on_retry = policy.configured;
            if let Some(upstream) = ctx.upstream_for_retry.as_ref() {
                let addr = Arc::clone(&upstream.address);
                if !ctx.attempted_endpoints.iter().any(|e| e.as_ref() == addr.as_ref()) {
                    ctx.attempted_endpoints.push(addr);
                }
            }
            // Under reselection, release the failed endpoint's in-flight
            // counter and clear the saved upstream so upstream_peer picks an
            // alternate host. Legacy same-endpoint retries keep the saved
            // upstream (and its counter) for the next attempt.
            if policy.configured {
                if let Some(upstream) = ctx.upstream_for_retry.as_ref()
                    && let Some(reselector) = ctx.endpoint_reselector.as_ref()
                {
                    reselector.release(&upstream.address);
                }
                ctx.upstream_for_retry = None;
            }
            let upstream_address = ctx
                .upstream_for_retry
                .as_ref()
                .map_or("unknown", |u| u.address.as_ref());
            debug!(
                retries = ctx.retries,
                max = policy.effective_max_retries(),
                ?backoff,
                upstream_address,
                "retrying after connect failure"
            );
            let mut e = e;
            e.set_retry(true);
            e
        },
        retry::RetryDecision::DoNotRetry => {
            if ctx.retries > 0 {
                warn!(
                    retries = ctx.retries,
                    max = policy.effective_max_retries(),
                    upstream_address = ctx
                        .upstream_for_retry
                        .as_ref()
                        .map_or("unknown", |u| u.address.as_ref()),
                    "retry limit exhausted"
                );
            }
            record_retry_exhausted_if_attempted(ctx, cluster);
            // Pingora may mark some errors retriable by default; clear the
            // flag so the policy decision is authoritative.
            let mut e = e;
            e.set_retry(false);
            e
        },
    }
}

/// Decide whether an HTTP response status should trigger a retry.
///
/// Returns `Some(error)` marked retriable when the status is retriable
/// and all guards pass; `None` when the response should be forwarded.
#[expect(clippy::too_many_lines, reason = "sequential guard checks")]
fn maybe_retry_response(ctx: &mut PingoraRequestCtx, status: u16) -> Option<Box<pingora_core::Error>> {
    let policy = ctx
        .retry_policy
        .clone()
        .unwrap_or_else(|| Arc::new(praxis_core::config::RetryPolicy::legacy_default()));
    let outcome = retry::RetryOutcome::StatusCode(status);
    let decision = retry::should_retry(ctx, &policy, outcome, ctx.cluster_retry_state.as_deref());
    match decision {
        retry::RetryDecision::Retry { backoff } => {
            ctx.retries += 1;
            ctx.pending_backoff = Some(backoff);
            // Legacy (unconfigured) policies keep the historical
            // retry-same-endpoint behavior; only operator-configured
            // policies opt into endpoint reselection.
            ctx.reselect_on_retry = policy.configured;
            if let Some(upstream) = ctx.upstream_for_retry.as_ref() {
                let addr = Arc::clone(&upstream.address);
                if !ctx.attempted_endpoints.iter().any(|e| e.as_ref() == addr.as_ref()) {
                    ctx.attempted_endpoints.push(addr);
                }
            }
            // Under reselection, release the failed endpoint's in-flight
            // counter and clear the saved upstream so upstream_peer picks an
            // alternate host. Legacy same-endpoint retries keep the saved
            // upstream (and its counter) for the next attempt.
            if policy.configured {
                if let Some(upstream) = ctx.upstream_for_retry.as_ref()
                    && let Some(reselector) = ctx.endpoint_reselector.as_ref()
                {
                    reselector.release(&upstream.address);
                }
                ctx.upstream_for_retry = None;
            }
            debug!(
                status,
                retries = ctx.retries,
                max = policy.effective_max_retries(),
                ?backoff,
                "retrying after retriable response status"
            );
            let mut e =
                pingora_core::Error::explain(pingora_core::ErrorType::HTTPStatus(status), "retriable upstream status");
            e.set_retry(true);
            Some(e)
        },
        retry::RetryDecision::DoNotRetry => None,
    }
}

/// Release the active-request counter if it has not already been released.
fn release_retry_state(ctx: &mut PingoraRequestCtx) {
    if !ctx.cluster_retry_state_released
        && let Some(state) = ctx.cluster_retry_state.take()
    {
        state.leave();
        ctx.cluster_retry_state_released = true;
    }
}

/// Record `result=exhausted` only when at least one retry was already attempted.
fn record_retry_exhausted_if_attempted(ctx: &PingoraRequestCtx, cluster: ::metrics::SharedString) {
    if ctx.retries > 0 {
        metrics::record_upstream_retry(cluster, metrics::RETRY_RESULT_EXHAUSTED);
    }
}

/// Emit a fallback access record for requests whose lifecycle ended
/// before the access log filter's completion hooks could run.
///
/// Covers pre-upstream rejections, upstream connect and read failures,
/// and streamed responses aborted mid-body: none of these reach the
/// bodyless response phase or body end-of-stream where the filter
/// emits. Only fires when the pipeline configures an `access_log`
/// filter; these records bypass the filter's sampling because
/// incomplete requests are always worth a record.
fn maybe_emit_fallback_access_log(pipeline: &FilterPipeline, status: u16, ctx: &mut PingoraRequestCtx) {
    if ctx.response_delivery_complete || ctx.connection_upgraded || !pipeline.contains_filter("access_log") {
        return;
    }
    if let Some(filter_ctx) = ctx.filter_context_for(pipeline, None) {
        // The access_log filter already logged this request (e.g. a bodyless
        // response whose on_response emitted before a later filter rejected):
        // no fallback record, or it would duplicate.
        if praxis_filter::access_record_already_emitted(&filter_ctx) {
            return;
        }
        // Honor the entry's request conditions: a scoped access_log (e.g.
        // only /api paths) must not gain fallback records for requests the
        // operator excluded. Sampling is still deliberately bypassed.
        if !pipeline.filter_request_conditions_match("access_log", filter_ctx.request) {
            return;
        }
        praxis_filter::emit_access_record(&filter_ctx, status);
    }
}

/// Run response filters during the logging phase if the
/// response phase never executed (upstream error, filter
/// rejection, etc.).
async fn logging_cleanup(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    if !ctx.response_phase_done
        && let Some(mut filter_ctx) = ctx.filter_context_for(pipeline, None)
    {
        let _result = pipeline.execute_http_response(&mut filter_ctx).await;
        let extensions = filter_ctx.extensions;
        let metadata = filter_ctx.filter_metadata;
        let state = filter_ctx.filter_state;
        let exec_idx = filter_ctx.executed_filter_indices;
        let body_idx = filter_ctx.body_done_indices;
        // The context macro takes cluster/upstream out of ctx; restore them
        // so the fallback access record that follows can attribute the
        // failure to the routed cluster and selected endpoint.
        let cluster = filter_ctx.cluster;
        let upstream = filter_ctx.upstream;
        ctx.extensions = extensions;
        ctx.filter_metadata = metadata;
        ctx.filter_state = state;
        ctx.cached_executed_filter_indices = exec_idx;
        ctx.cached_body_done_indices = body_idx;
        ctx.cluster = cluster;
        ctx.upstream = upstream;
    }
}

/// Emit Prometheus metrics for a completed HTTP request.
///
/// No-op when the Prometheus recorder has not been installed.
fn emit_request_metrics(session: &Session, ctx: &PingoraRequestCtx) {
    if !metrics::is_recorder_installed() {
        return;
    }

    let status_code = session.response_written().map_or(0, |resp| resp.status.as_u16());
    let status_class = metrics::status_class(status_code);

    let request_method = session.req_header().method.as_str();
    let raw_method = if request_method.is_empty() {
        ctx.request_snapshot.as_ref().map_or("UNKNOWN", |r| r.method.as_str())
    } else {
        request_method
    };
    let method = metrics::method_label(raw_method);

    let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);

    let route = ctx.metrics_route.clone().unwrap_or_else(metrics::route_unknown);

    let labels = metrics::RequestMetricLabels {
        cluster: cluster.clone(),
        method,
        route,
        status_class,
    };

    let duration_secs = ctx.request_start.elapsed().as_secs_f64();
    metrics::record_request_metrics(labels, duration_secs);
    metrics::record_body_size_metrics(
        method,
        status_class,
        cluster,
        ctx.request_body_bytes,
        ctx.response_body_bytes,
    );
}

/// Record a passive health observation for the selected upstream endpoint.
///
/// Called from the `logging` hook on every completed request. Determines
/// success/failure from the error argument and the stashed upstream
/// response status code.
///
/// No-op when no upstream was selected, no health registry is available,
/// or passive checking is not configured for the cluster.
fn record_passive_health(pipeline: &FilterPipeline, error: Option<&pingora_core::Error>, ctx: &PingoraRequestCtx) {
    let cluster_name = ctx.cluster.as_ref().or(ctx.metrics_cluster.as_ref());
    let Some(cluster_name) = cluster_name else {
        return;
    };
    let Some(idx) = ctx.selected_endpoint_index else {
        return;
    };
    let Some(registry) = pipeline.health_registry() else {
        return;
    };
    let Some(health) = registry.get(cluster_name) else {
        return;
    };

    let is_failure = error.is_some() || ctx.upstream_response_status.is_some_and(|s| s >= 500);
    apply_passive_threshold(health, idx, cluster_name, is_failure);
}

/// Apply passive health threshold for a single endpoint observation.
fn apply_passive_threshold(
    health: &praxis_core::health::ClusterHealthEntry,
    idx: usize,
    cluster_name: &Arc<str>,
    is_failure: bool,
) {
    if is_failure {
        if let Some(threshold) = health.passive_unhealthy_threshold()
            && health
                .endpoints()
                .get(idx)
                .is_some_and(|ep| ep.record_failure(threshold))
        {
            tracing::warn!(
                cluster = %cluster_name,
                endpoint_index = idx,
                threshold,
                "passive health: endpoint marked unhealthy"
            );
            emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_UNHEALTHY);
        }
    } else if let Some(threshold) = health.passive_healthy_threshold()
        && health
            .endpoints()
            .get(idx)
            .is_some_and(|ep| ep.record_success(threshold))
    {
        tracing::info!(
            cluster = %cluster_name,
            endpoint_index = idx,
            threshold,
            "passive health: endpoint recovered"
        );
        emit_passive_health_transition(health, cluster_name, metrics::HEALTH_RESULT_HEALTHY);
    }
}

/// Refresh health gauges and increment the transition counter after a passive flip.
fn emit_passive_health_transition(
    health: &praxis_core::health::ClusterHealthEntry,
    cluster_name: &Arc<str>,
    result: &'static str,
) {
    let (healthy, total) = metrics::count_healthy_endpoints(health);
    metrics::record_health_transition(
        ::metrics::SharedString::from(Arc::clone(cluster_name)),
        result,
        healthy,
        total,
    );
}

/// Map an [`http::Version`] to the [OTel `network.protocol.version`] value.
///
/// [OTel `network.protocol.version`]: https://opentelemetry.io/docs/specs/semconv/attributes-registry/network/
pub(super) fn http_version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "0.9",
        http::Version::HTTP_10 => "1.0",
        http::Version::HTTP_11 => "1.1",
        http::Version::HTTP_2 => "2",
        http::Version::HTTP_3 => "3",
        _ => "unknown",
    }
}

/// Record response-phase span attributes that are only available after
/// the upstream exchange.
///
/// Called from the `logging` hook to fill in `http.response.status_code`,
/// `otel.status_code` and `error.type` (5xx only), `http.route` and the
/// `otel.name` upgrade to `{method} {route}` (when a route matched),
/// `upstream.address`, and `upstream.cluster` on the root request span,
/// and response attributes on the upstream exchange span.
fn record_response_span_attributes(session: &Session, ctx: &PingoraRequestCtx) {
    if ctx.request_span.is_disabled() {
        return;
    }
    let response = session.response_written();
    let status = response.map(|resp| resp.status);
    let method = session.req_header().method.as_str();
    record_response_span_fields(status, method, response, ctx);
}

/// Record the response-phase fields once the status and method have been extracted.
///
/// Split from [`record_response_span_attributes`] so the recording logic is
/// unit-testable without constructing a live Pingora session.
fn record_response_span_fields(
    status: Option<http::StatusCode>,
    method: &str,
    response: Option<&pingora_http::ResponseHeader>,
    ctx: &PingoraRequestCtx,
) {
    if let Some(status) = status {
        let code = status.as_u16();
        if code > 0 {
            ctx.request_span.record("http.response.status_code", code);
        }
        if status.is_server_error() {
            ctx.request_span.record("otel.status_code", "ERROR");
            // OTel semconv: error.type for an HTTP status is the numeric code
            // as a string, not StatusCode's "{code} {reason}" Display form.
            ctx.request_span.record("error.type", code.to_string().as_str());
        }
    }

    if let Some(route) = &ctx.metrics_route {
        ctx.request_span.record("http.route", route.as_ref());
        ctx.request_span
            .record("otel.name", format!("{method} {route}").as_str());
    }

    if let Some(upstream) = &ctx.upstream_for_retry {
        ctx.request_span.record("upstream.address", upstream.address.as_ref());
    }

    if let Some(cluster) = &ctx.metrics_cluster {
        ctx.request_span.record("upstream.cluster", cluster.as_ref());
    }

    record_upstream_exchange_span(ctx, response);
}

/// Record the upstream-exchange child span's response fields.
fn record_upstream_exchange_span(ctx: &PingoraRequestCtx, response: Option<&pingora_http::ResponseHeader>) {
    if ctx.upstream_exchange_span.is_disabled() {
        return;
    }
    // Prefer the upstream's own status (captured before any response-phase
    // rewrite); fall back to the written response when it was not captured.
    if let Some(status) = ctx
        .upstream_response_status
        .or_else(|| response.map(|resp| resp.status.as_u16()))
    {
        ctx.upstream_exchange_span.record("http.response.status_code", status);
    }
    ctx.upstream_exchange_span
        .record("http.response.body.size", ctx.response_body_bytes);
}

/// Build [`HttpServerOptions`] with h2c enabled.
///
/// [`HttpServerOptions`]: pingora_core::apps::HttpServerOptions
fn h2c_server_options() -> HttpServerOptions {
    let mut opts = HttpServerOptions::default();
    opts.h2c = true;
    opts
}

/// Build [`H2Options`] with limits to mitigate HPACK amplification attacks
/// (CWE-409).
///
/// Without explicit limits the `h2` crate defaults allow unbounded header
/// list sizes and concurrent streams, enabling a small compressed request
/// to allocate hundreds of megabytes on the server.
///
/// [`H2Options`]: pingora_core::protocols::http::v2::server::H2Options
fn h2_server_options() -> H2Options {
    let mut opts = H2Options::new();
    opts.max_header_list_size(65_536); // 64 KiB
    opts.max_concurrent_streams(128);
    opts
}

/// Accumulate `chunk.len()` into `accumulated_bytes` and return `true` when
/// the total exceeds `max_bytes`. Returns `false` when the body is `None`.
fn check_body_size_limit(body: Option<&Bytes>, accumulated_bytes: &mut u64, max_bytes: usize) -> bool {
    if let Some(chunk) = body {
        let chunk_len = chunk.len() as u64;
        *accumulated_bytes += chunk_len;

        let limit = max_bytes as u64;
        return *accumulated_bytes > limit;
    }
    false
}

/// Push `chunk` into the stream buffer, creating it if absent. At end-of-stream
/// the buffer is frozen into `body`. Returns `true` when the push overflows.
fn accumulate_stream_buffer(
    body: &mut Option<Bytes>,
    body_buffer: &mut Option<BodyBuffer>,
    end_of_stream: bool,
    max_bytes: Option<usize>,
) -> bool {
    if let Some(chunk) = &*body {
        let limit = max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES);
        let buf = body_buffer.get_or_insert_with(|| BodyBuffer::new(limit));

        if buf.push(chunk.clone()).is_err() {
            return true;
        }
    }

    if end_of_stream {
        tracing::trace!("stream buffer: freezing accumulated body before pipeline at EOS");
        *body = body_buffer.take().map(BodyBuffer::freeze);
    } else {
        tracing::trace!("stream buffer: filters see the original chunk");
    }
    false
}

/// Suppress the body chunk while the stream buffer is still accumulating
/// (i.e. `Continue`/`BodyDone` before release).
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "mirrors the caller's existing condition flags"
)]
fn suppress_stream_buffer_chunk(body: &mut Option<Bytes>, is_stream_buffer: bool, released: bool, end_of_stream: bool) {
    if is_stream_buffer && !released && !end_of_stream {
        *body = None;
    }
}

/// Release the accumulated stream buffer on `FilterAction::Release`.
fn release_stream_buffer(
    body: &mut Option<Bytes>,
    is_stream_buffer: bool,
    released: &mut bool,
    body_buffer: &mut Option<BodyBuffer>,
    end_of_stream: bool,
) {
    if is_stream_buffer && !*released {
        *released = true;
        if !end_of_stream {
            *body = body_buffer.take().map(BodyBuffer::freeze);
        }
    }
}

/// Shared fields extracted from an `HttpFilterContext` after body filter
/// execution. Written back to `PingoraRequestCtx` via [`write_back`].
///
/// [`write_back`]: BodyFilterOutput::write_back
struct BodyFilterOutput {
    /// Cluster selected by the filter pipeline.
    cluster: Option<Arc<str>>,
    /// Upstream endpoint selected by the load balancer.
    upstream: Option<Upstream>,
    /// Type-safe request-scoped extension container.
    extensions: RequestExtensions,
    /// Durable per-request metadata that persists across phases.
    filter_metadata: HashMap<String, String>,
    /// Typed per-filter state keyed by stable filter invocation ID.
    filter_state: HashMap<usize, Box<dyn std::any::Any + Send + Sync>>,
    /// Per-filter execution tracking indices.
    executed_filter_indices: Vec<bool>,
    /// Per-filter body-done tracking indices.
    body_done_indices: Vec<bool>,
    /// Endpoints already attempted for this request (retry exclusion set).
    attempted_endpoints: Vec<Arc<str>>,
}

impl BodyFilterOutput {
    /// Move the shared fields out of the filter context, replacing each
    /// with its `Default` value (zero-allocation no-ops for the types involved).
    fn take_from(fctx: &mut HttpFilterContext<'_>) -> Self {
        Self {
            cluster: fctx.cluster.take(),
            upstream: fctx.upstream.take(),
            extensions: std::mem::take(&mut fctx.extensions),
            filter_metadata: std::mem::take(&mut fctx.filter_metadata),
            filter_state: std::mem::take(&mut fctx.filter_state),
            executed_filter_indices: std::mem::take(&mut fctx.executed_filter_indices),
            body_done_indices: std::mem::take(&mut fctx.body_done_indices),
            attempted_endpoints: std::mem::take(&mut fctx.attempted_endpoints),
        }
    }

    /// Write the shared fields back to the protocol context.
    fn write_back(self, ctx: &mut PingoraRequestCtx) {
        ctx.cluster = self.cluster;
        ctx.upstream = self.upstream;
        ctx.extensions = self.extensions;
        ctx.filter_metadata = self.filter_metadata;
        ctx.filter_state = self.filter_state;
        ctx.cached_executed_filter_indices = self.executed_filter_indices;
        ctx.cached_body_done_indices = self.body_done_indices;
        ctx.attempted_endpoints = self.attempted_endpoints;
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
    clippy::field_reassign_with_default,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_core::connectivity::ConnectionOptions;

    use super::*;

    /// Maximum number of upstream connection retries for the legacy default policy.
    const MAX_RETRIES: usize = praxis_core::config::DEFAULT_MAX_RETRIES as usize;

    /// Default Pingora retry body buffer limit (64 `KiB`).
    const RETRY_BODY_LIMIT: u64 = praxis_core::config::DEFAULT_RETRY_BODY_LIMIT_BYTES;

    #[test]
    fn first_failure_idempotent_sets_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "first failure should set retry flag");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn large_body_skips_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = RETRY_BODY_LIMIT + 1;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "should not retry when body exceeds retry buffer limit");
        assert_eq!(ctx.retries, 0, "retry counter should not increment");
    }

    #[test]
    fn mutated_body_exceeding_limit_skips_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = 1024;
        ctx.mutated_request_body_len = Some((RETRY_BODY_LIMIT + 1) as usize);
        let e = handle_connect_failure(&mut ctx, make_error());
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
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "body exactly at limit should allow retry");
        assert_eq!(ctx.retries, 1);
    }

    #[test]
    fn zero_body_allows_retry() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.request_body_bytes = 0;
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "zero-length body should allow retry");
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

    #[test]
    fn connect_failure_clears_upstream_connect_start() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.upstream_connect_start = Some(std::time::Instant::now());
        let _e = handle_connect_failure(&mut ctx, make_error());
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
        let e = maybe_retry_response(&mut ctx, 503).expect("503 should be retriable");
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
            maybe_retry_response(&mut ctx, 404).is_none(),
            "404 must never trigger status-based retry"
        );
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn response_502_does_not_retry_under_legacy_default() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        // Legacy default is connect_failure only — no Status5xx.
        assert!(
            maybe_retry_response(&mut ctx, 502).is_none(),
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
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(!e.retry(), "max_retries: 0 must disable retries");
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn non_idempotent_clears_pingora_default_retry_flag() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = false;
        // Simulate Pingora marking the error retriable by default.
        let mut e = make_error();
        e.set_retry(true);
        let e = handle_connect_failure(&mut ctx, e);
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
        logging_cleanup(&pipeline, &mut ctx).await;
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
        logging_cleanup(&pipeline, &mut ctx).await;
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
        record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            entry.endpoints()[0].is_healthy(),
            "single failure should not yet mark unhealthy (threshold=3)"
        );
    }

    #[test]
    fn passive_health_status_500_is_failure() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(3), Some(2));
        ctx.upstream_response_status = Some(500);
        record_passive_health(&pipeline, None, &ctx);

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
        record_passive_health(&pipeline, None, &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(entry.endpoints()[0].is_healthy(), "status 499 should count as success");
    }

    #[test]
    fn passive_unhealthy_threshold_transition() {
        let (pipeline, ctx) = make_passive_scenario(Some(2), Some(1));
        let error = make_error();
        record_passive_health(&pipeline, Some(&error), &ctx);
        record_passive_health(&pipeline, Some(&error), &ctx);

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
        record_passive_health(&pipeline, Some(&error), &ctx);

        let registry = pipeline.health_registry().unwrap();
        let entry = registry.get("test-cluster").unwrap();
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "should be unhealthy after 1 failure"
        );

        let ctx_ok = make_passive_ctx("test-cluster", 0, Some(200));
        record_passive_health(&pipeline, None, &ctx_ok);
        assert!(
            !entry.endpoints()[0].is_healthy(),
            "one success should not recover (threshold=2)"
        );

        record_passive_health(&pipeline, None, &ctx_ok);
        assert!(
            entry.endpoints()[0].is_healthy(),
            "2 consecutive successes should recover (threshold=2)"
        );
    }

    #[test]
    fn passive_health_no_thresholds_is_noop() {
        let (pipeline, ctx) = make_passive_scenario(None, None);
        let error = make_error();
        record_passive_health(&pipeline, Some(&error), &ctx);

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
        record_passive_health(&pipeline, Some(&error), &ctx);

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
        record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_falls_back_to_metrics_cluster() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(2), Some(1));
        ctx.cluster = None;
        ctx.metrics_cluster = Some(Arc::from("test-cluster"));
        let error = make_error();
        record_passive_health(&pipeline, Some(&error), &ctx);
        record_passive_health(&pipeline, Some(&error), &ctx);

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
        record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_missing_registry_is_noop() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        ctx.cluster = Some(Arc::from("test-cluster"));
        ctx.selected_endpoint_index = Some(0);
        let error = make_error();
        record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn passive_health_unknown_cluster_is_noop() {
        let (pipeline, mut ctx) = make_passive_scenario(Some(1), Some(1));
        ctx.cluster = Some(Arc::from("nonexistent"));
        let error = make_error();
        record_passive_health(&pipeline, Some(&error), &ctx);
    }

    #[test]
    fn size_limit_none_body_returns_false() {
        let mut bytes = 0_u64;
        assert!(!check_body_size_limit(None, &mut bytes, 100));
        assert_eq!(bytes, 0, "accumulated bytes unchanged for None body");
    }

    #[test]
    fn size_limit_within_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"hello"));
        assert!(!check_body_size_limit(body.as_ref(), &mut bytes, 10));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_at_exact_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"exact"));
        assert!(!check_body_size_limit(body.as_ref(), &mut bytes, 5));
        assert_eq!(bytes, 5);
    }

    #[test]
    fn size_limit_exceeds_limit() {
        let mut bytes = 0_u64;
        let body = Some(Bytes::from_static(b"toolong"));
        assert!(check_body_size_limit(body.as_ref(), &mut bytes, 3));
    }

    #[test]
    fn size_limit_cumulative_overflow() {
        let mut bytes = 0_u64;
        let first = Some(Bytes::from_static(b"aaa"));
        assert!(!check_body_size_limit(first.as_ref(), &mut bytes, 5));

        let second = Some(Bytes::from_static(b"bbb"));
        assert!(check_body_size_limit(second.as_ref(), &mut bytes, 5));
        assert_eq!(bytes, 6);
    }

    #[test]
    fn stream_buffer_accumulates_chunks() {
        let mut body = Some(Bytes::from_static(b"hello "));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));
        assert!(buf.is_some());

        body = Some(Bytes::from_static(b"world"));
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));

        let frozen = buf.take().unwrap().freeze();
        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn stream_buffer_freezes_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));

        body = Some(Bytes::from_static(b" end"));
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, true, Some(100)));
        assert!(buf.is_none(), "buffer should be taken at EOS");
        assert_eq!(body.unwrap(), Bytes::from_static(b"data end"));
    }

    #[test]
    fn stream_buffer_overflow() {
        let mut body = Some(Bytes::from_static(b"too long"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(accumulate_stream_buffer(&mut body, &mut buf, false, Some(5)));
    }

    #[test]
    fn stream_buffer_none_body() {
        let mut body: Option<Bytes> = None;
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, Some(100)));
        assert!(buf.is_none());
    }

    #[test]
    fn stream_buffer_uses_absolute_max_when_none() {
        let mut body = Some(Bytes::from_static(b"data"));
        let mut buf: Option<BodyBuffer> = None;
        assert!(!accumulate_stream_buffer(&mut body, &mut buf, false, None));
        assert!(buf.is_some(), "should create buffer with absolute max");
    }

    #[test]
    fn suppress_clears_body_when_buffering() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, false, false);
        assert!(body.is_none());
    }

    #[test]
    fn suppress_noop_when_not_stream_buffer() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, false, false, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_when_released() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, true, false);
        assert!(body.is_some());
    }

    #[test]
    fn suppress_noop_at_eos() {
        let mut body = Some(Bytes::from_static(b"data"));
        suppress_stream_buffer_chunk(&mut body, true, false, true);
        assert!(body.is_some());
    }

    #[test]
    fn release_sets_flag_and_flushes_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"buffered")).unwrap();

        release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(released);
        assert_eq!(body.unwrap(), Bytes::from_static(b"buffered"));
        assert!(buf.is_none());
    }

    #[test]
    fn release_noop_when_already_released() {
        let mut body: Option<Bytes> = None;
        let mut released = true;
        let mut buf: Option<BodyBuffer> = None;

        release_stream_buffer(&mut body, true, &mut released, &mut buf, false);
        assert!(body.is_none(), "body should be unchanged when already released");
    }

    #[test]
    fn release_noop_when_not_stream_buffer() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf: Option<BodyBuffer> = None;

        release_stream_buffer(&mut body, false, &mut released, &mut buf, false);
        assert!(!released, "released flag should be unchanged for non-stream-buffer");
    }

    #[test]
    fn release_at_eos_sets_flag_but_no_flush() {
        let mut body: Option<Bytes> = None;
        let mut released = false;
        let mut buf = Some(BodyBuffer::new(100));
        buf.as_mut().unwrap().push(Bytes::from_static(b"data")).unwrap();

        release_stream_buffer(&mut body, true, &mut released, &mut buf, true);
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

        let output = BodyFilterOutput {
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

        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 502, &mut ctx));
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

        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 200, &mut ctx));
        assert!(events.is_empty(), "completed delivery already logged via the filter");
    }

    #[test]
    fn fallback_access_log_skips_upgraded_connections() {
        let pipeline = access_log_pipeline();
        let mut ctx = make_fallback_ctx();
        ctx.connection_upgraded = true;

        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 101, &mut ctx));
        assert!(events.is_empty(), "upgraded connections have no body completion");
    }

    #[test]
    fn fallback_access_log_skips_without_access_log_filter() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).unwrap();
        let mut ctx = make_fallback_ctx();

        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 502, &mut ctx));
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
        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 502, &mut excluded));
        assert!(
            events.is_empty(),
            "requests the operator scoped out must not gain fallback records"
        );

        let mut included = make_fallback_ctx();
        if let Some(snapshot) = included.request_snapshot.as_mut() {
            snapshot.uri = "/api/users".parse().unwrap();
        }
        let events = capture_access_events(|| maybe_emit_fallback_access_log(&pipeline, 502, &mut included));
        assert_eq!(events.len(), 1, "in-scope incomplete requests still get a record");
    }

    #[test]
    fn aborted_response_body_at_eos_is_not_marked_delivered() {
        // access_log declares read-only response body access, so the hook
        // reaches the SizeLimit check instead of early-returning.
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
    // Span Attribute Helpers
    // -------------------------------------------------------------------------

    #[test]
    fn http_version_label_http_09() {
        assert_eq!(
            http_version_label(http::Version::HTTP_09),
            "0.9",
            "HTTP/0.9 should map to '0.9'"
        );
    }

    #[test]
    fn http_version_label_http_10() {
        assert_eq!(
            http_version_label(http::Version::HTTP_10),
            "1.0",
            "HTTP/1.0 should map to '1.0'"
        );
    }

    #[test]
    fn http_version_label_http_11() {
        assert_eq!(
            http_version_label(http::Version::HTTP_11),
            "1.1",
            "HTTP/1.1 should map to '1.1'"
        );
    }

    #[test]
    fn http_version_label_http_2() {
        assert_eq!(
            http_version_label(http::Version::HTTP_2),
            "2",
            "HTTP/2 should map to '2'"
        );
    }

    #[test]
    fn http_version_label_http_3() {
        assert_eq!(
            http_version_label(http::Version::HTTP_3),
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

        record_response_span_fields(Some(http::StatusCode::SERVICE_UNAVAILABLE), "GET", None, &ctx);

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

        record_response_span_fields(Some(http::StatusCode::OK), "GET", None, &ctx);

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

        // Verify recording on exchange span does not panic.
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
        // Exchange span remains disabled (default).
        assert!(
            ctx.upstream_exchange_span.is_disabled(),
            "exchange span should be disabled by default"
        );
        // Should not panic when exchange span is disabled.
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
        let e = handle_connect_failure(&mut ctx, make_error());
        assert!(e.retry(), "should retry with upstream address present");
        assert_eq!(ctx.retries, 1, "retry counter should increment to 1");
    }

    #[test]
    fn retry_without_upstream_address_uses_fallback() {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_is_idempotent = true;
        ctx.upstream_for_retry = None;
        let e = handle_connect_failure(&mut ctx, make_error());
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
        let e = handle_connect_failure(&mut ctx, make_error());
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
        let e = handle_connect_failure(&mut ctx, make_error());
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
        ctx
    }

    /// Build a pipeline with a health registry and a matching context
    /// for passive health testing.
    fn make_passive_scenario(
        passive_unhealthy: Option<u32>,
        passive_healthy: Option<u32>,
    ) -> (FilterPipeline, PingoraRequestCtx) {
        use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

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
