// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora HTTP handler with body filter hooks enabled.
//!
//! [`PingoraHttpHandler`] is the full-featured `ProxyHttp` implementation
//! used when the pipeline's [`BodyCapabilities`] declare request or
//! response body access. It delegates each Pingora lifecycle hook to
//! the corresponding submodule and enables Pingora's compression
//! module when a compression filter is configured.
//!
//! [`BodyCapabilities`]: praxis_filter::body::BodyCapabilities

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{
    Result,
    modules::http::{HttpModules, compression::ResponseCompressionBuilder},
    upstreams::peer::HttpPeer,
};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use praxis_filter::{CompressionConfig, FilterPipeline};
use tokio::sync::Semaphore;
use tracing::{Instrument as _, debug};

use super::{
    adjust_compression, connected_to_upstream, emit_request_metrics, fail_to_proxy, handle_connect_failure,
    hop_by_hop::RemoveHeader as _, logging_cleanup, record_passive_health, record_response_span_attributes,
    release_retry_state, request_body_filter, request_filter, response_body_filter, response_filter, upstream_peer,
    upstream_request, via,
};
use crate::http::pingora::{context::PingoraRequestCtx, metrics};

// -----------------------------------------------------------------------------
// PingoraHttpHandler
// -----------------------------------------------------------------------------

/// Pingora HTTP handler that overrides body filter hooks.
///
/// Used when the pipeline contains filters that declare
/// body access via [`BodyAccess`].
///
/// The pipeline is held behind [`ArcSwap`] so it can be
/// atomically replaced by hot config reload without
/// disrupting in-flight requests.
///
/// ```ignore
/// // Requires a `FilterPipeline` and Pingora server runtime.
/// use std::sync::Arc;
///
/// use arc_swap::ArcSwap;
/// use praxis_protocol::http::pingora::handler::PingoraHttpHandler;
///
/// let handler = PingoraHttpHandler::new(
///     Arc::new(ArcSwap::from_pointee(pipeline)),
///     None,
///     None,
///     ::metrics::SharedString::const_str("http"),
/// );
/// ```
///
/// [`BodyAccess`]: praxis_filter::BodyAccess
/// [`ArcSwap`]: arc_swap::ArcSwap
pub struct PingoraHttpHandler {
    /// Compression configuration snapshot for module registration.
    ///
    /// Used only by [`init_downstream_modules`] to register the
    /// compression module at startup. Per-request compression
    /// levels are read from the live pipeline via [`ArcSwap`]
    /// so that hot-reload updates take effect immediately.
    ///
    /// Module registration itself is one-shot in Pingora;
    /// adding compression to a listener that had none at
    /// startup requires a restart.
    ///
    /// [`init_downstream_modules`]: Self::init_downstream_modules
    /// [`ArcSwap`]: arc_swap::ArcSwap
    compression: Option<CompressionConfig>,

    /// Per-listener connection semaphore for max connections.
    connection_semaphore: Option<Arc<Semaphore>>,

    /// Per-listener downstream read timeout.
    downstream_read_timeout: Option<Duration>,

    /// Listener name for connection metrics.
    listener_name: ::metrics::SharedString,

    /// Swappable filter pipeline.
    pipeline: Arc<ArcSwap<FilterPipeline>>,
}

impl PingoraHttpHandler {
    /// Create a handler with body filter support.
    pub(super) fn new(
        pipeline: Arc<ArcSwap<FilterPipeline>>,
        downstream_read_timeout: Option<Duration>,
        connection_semaphore: Option<Arc<Semaphore>>,
        listener_name: ::metrics::SharedString,
    ) -> Self {
        let compression = pipeline.load().compression_config().cloned();
        Self {
            compression,
            connection_semaphore,
            downstream_read_timeout,
            listener_name,
            pipeline,
        }
    }
}

/// Resolve retry safety for a stale (`ReusedOnly`) upstream connection.
///
/// A pooled connection that closed while idle is not a real attempt, but the
/// request bytes were already written upstream, so replay must be safe: an
/// idempotent method (or explicit opt-in) and an intact buffered body.
fn resolve_reused_only_retry(
    ctx: &PingoraRequestCtx,
    session: &Session,
    client_reused: bool,
    mut e: Box<pingora_core::Error>,
) -> Box<pingora_core::Error> {
    let policy = ctx.retry_policy.clone().unwrap_or_else(super::legacy_default_policy);
    let replay_safe = client_reused
        && !session.as_ref().retry_buffer_truncated()
        && (ctx.request_is_idempotent || policy.allow_non_idempotent());
    if !replay_safe {
        debug!("clearing reused-connection retry: replay is not safe for this request");
    }
    e.set_retry(replay_safe);
    e
}

#[async_trait]
impl ProxyHttp for PingoraHttpHandler {
    type CTX = PingoraRequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        PingoraRequestCtx::default()
    }

    /// Registers Pingora's compression module when compression is
    /// configured. Otherwise skips module registration to avoid
    /// per-request `Box` allocation overhead.
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        if let Some(cfg) = &self.compression {
            debug!(level = cfg.default_level, "registering compression module");
            modules.add_module(ResponseCompressionBuilder::enable(cfg.default_level));
        }
    }

    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if praxis_core::memory::is_exceeded() {
            metrics::record_overload_reject(metrics::OVERLOAD_REASON_MEMORY);
            return reject_503(session, "5", "memory pressure exceeded").await;
        }

        let (exceeded, permit) = crate::connections::try_acquire_global();
        ctx._global_connection_permit = permit;
        if exceeded {
            metrics::record_overload_reject(metrics::OVERLOAD_REASON_GLOBAL_CONNECTIONS);
            return reject_503(session, "1", "global max connections exceeded").await;
        }

        if let Some(sem) = &self.connection_semaphore {
            if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                ctx._connection_permit = Some(permit);
            } else {
                metrics::record_overload_reject(metrics::OVERLOAD_REASON_LISTENER_CONNECTIONS);
                return reject_503(session, "1", "max connections exceeded").await;
            }
        }

        ctx._active_connection = Some(metrics::ActiveConnectionGuard::acquire(self.listener_name.clone()));

        if let Some(timeout) = self.downstream_read_timeout {
            debug!(
                timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                "applying downstream read timeout"
            );
            session.set_read_timeout(Some(timeout));
        }
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let pipeline = ctx.pin_pipeline(&self.pipeline);
        request_filter::execute(&pipeline, session, ctx).await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Pure no-op fast path (mirroring execute's own early returns,
        // which emit nothing): skip the pipeline Arc clone, span clone,
        // and future instrumentation per chunk when no body filter can
        // run — the default configuration for proxied bodies.
        if ctx.connection_upgraded {
            return Ok(());
        }
        if ctx.pre_read_body.is_none()
            && let Some(pinned) = &ctx.pinned_pipeline
            && !pinned.body_capabilities().needs_request_body
        {
            return Ok(());
        }
        let pipeline = ctx.pipeline(&self.pipeline);
        let span = ctx.request_span.clone();
        request_body_filter::execute(&pipeline, session, body, end_of_stream, ctx)
            .instrument(span)
            .await
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Same silent fast path as the request side, keeping execute's
        // delivery-complete bookkeeping.
        if ctx.connection_upgraded {
            return Ok(None);
        }
        if let Some(pinned) = &ctx.pinned_pipeline
            && !pinned.body_capabilities().needs_response_body
        {
            if end_of_stream {
                ctx.response_delivery_complete = true;
            }
            return Ok(None);
        }
        let span = ctx.request_span.clone();
        let _entered = span.enter();
        let pipeline = ctx.pipeline(&self.pipeline);
        response_body_filter::execute(&pipeline, body, end_of_stream, ctx)
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        let span = ctx.request_span.clone();
        let _entered = span.enter();
        // A truncated replay buffer means a retry would resend a partial
        // request body — refuse rather than corrupt the request upstream.
        if session.as_mut().retry_buffer_truncated() {
            let mut e = e;
            e.set_retry(false);
            return e;
        }
        handle_connect_failure(ctx, e)
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora_core::Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<pingora_core::Error> {
        // Never retry once a final response reached the client: a second
        // attempt cannot rewrite the response line, so its body would be
        // spliced after whatever was already sent. A non-final 1xx (e.g.
        // 100 Continue) does not commit the final response, so it must not
        // block a retry; mirror fail_to_proxy's final-response predicate.
        if session.response_written().is_some_and(fail_to_proxy::is_final_response) {
            let mut e = e;
            e.set_retry(false);
            return e;
        }
        // A truncated replay buffer means a retry would resend a partial
        // request body — silent request corruption.
        let truncated = session.as_mut().retry_buffer_truncated();
        // Preserve an explicit retry decision from the response-status path
        // (already validated by the policy engine) — but still refuse it if the
        // replay buffer was truncated. should_retry's body-size guard makes
        // this unreachable while retry_body_limit_bytes stays capped at
        // Pingora's replay-buffer size, but that invariant lives in config
        // validation, not here; guarding locally keeps the two other retry
        // paths' replay-safety property from resting on an external cap.
        if matches!(e.retry, pingora_core::RetryType::Decided(true)) {
            if truncated {
                let mut e = e;
                e.set_retry(false);
                return e;
            }
            return e;
        }
        // Stale-connection (ReusedOnly) errors skip the retry budget but still
        // require replay safety; see resolve_reused_only_retry.
        // See docs/architecture/http-correctness.md.
        if matches!(e.retry, pingora_core::RetryType::ReusedOnly) {
            return resolve_reused_only_retry(ctx, session, client_reused, e);
        }
        let e = e.more_context(format!("Peer: {peer}"));
        if truncated {
            let mut e = e;
            e.set_retry(false);
            return e;
        }
        // Mid-proxy errors (reset, refused stream, etc.) go through the same
        // policy engine as connect failures — Pingora's decide_reuse must not
        // bypass idempotency / budget / max_retries guards.
        handle_connect_failure(ctx, e)
    }

    async fn fail_to_proxy(&self, session: &mut Session, e: &pingora_core::Error, ctx: &mut Self::CTX) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let span = ctx.request_span.clone();
        fail_to_proxy::execute(session, e, ctx).instrument(span).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let span = ctx.request_span.clone();
        let _entered = span.enter();
        let is_upgrade = session.is_upgrade_req();
        upstream_request::strip_hop_by_hop(upstream_request, is_upgrade);
        upstream_request.strip_reserved_internal();
        upstream_request::apply_authority_override(upstream_request, ctx)?;
        upstream_request::apply_rewritten_path(upstream_request, ctx)?;
        upstream_request::apply_mutated_content_length(upstream_request, ctx);
        let client_ver = ctx.client_http_version.unwrap_or(http::Version::HTTP_11);
        via::append_request_via(upstream_request, client_ver);
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let pipeline = ctx.pipeline(&self.pipeline);
        let span = ctx.request_span.clone();
        let exchange_span = ctx.upstream_exchange_span.clone();
        let result = response_filter::execute(&pipeline, upstream_response, ctx)
            .instrument(exchange_span)
            .instrument(span)
            .await;
        if result.is_ok() {
            // RFC 9110 §7.6.3: the response Via received-protocol is the leg this
            // proxy received the response on — the upstream connection — not the
            // downstream client's version.
            let upstream_ver = upstream_response.version;
            via::append_response_via(upstream_response, upstream_ver);
            adjust_compression(session, upstream_response, pipeline.compression_config());
        }
        result
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let span = ctx.request_span.clone();
        upstream_peer::execute(ctx).instrument(span).await
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let span = ctx.request_span.clone();
        let _entered = span.enter();
        let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);
        if !reused && let Some(start) = ctx.upstream_connect_start.take() {
            metrics::record_upstream_connect_duration(cluster.clone(), start.elapsed().as_secs_f64());
        }
        if ctx.retries > 0 {
            metrics::record_upstream_retry(cluster, metrics::RETRY_RESULT_SUCCESS);
        }
        connected_to_upstream::execute(reused, peer, digest, ctx);
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        record_response_span_attributes(session, ctx);
        // Drop the exchange span before the request span so child
        // ends before parent in tracing output.
        let _exchange_span = std::mem::replace(&mut ctx.upstream_exchange_span, tracing::Span::none());
        drop(_exchange_span);
        let span = std::mem::replace(&mut ctx.request_span, tracing::Span::none());
        let written_status = session.response_written().map_or(0, |resp| resp.status.as_u16());
        async {
            let pipeline = ctx.pipeline(&self.pipeline);
            emit_request_metrics(session, ctx);
            record_passive_health(&pipeline, e, ctx);
            release_retry_state(ctx);
            logging_cleanup(&pipeline, ctx).await;
            super::maybe_emit_fallback_access_log(&pipeline, written_status, ctx);
        }
        .instrument(span)
        .await;
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Write a 503 response with `Retry-After` and return the corresponding error.
async fn reject_503(session: &mut Session, retry_after: &'static str, reason: &'static str) -> Result<()> {
    tracing::warn!(reason, "rejecting request");
    let mut header = pingora_http::ResponseHeader::build(503, None)?;
    header.append_header("Retry-After", retry_after)?;
    session.write_response_header(Box::new(header), true).await?;
    Err(pingora_core::Error::explain(
        pingora_core::ErrorType::HTTPStatus(503),
        reason,
    ))
}
