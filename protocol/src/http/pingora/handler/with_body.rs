// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Pingora HTTP handler with body filter hooks enabled.

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{
    Result,
    modules::http::{HttpModules, compression::ResponseCompressionBuilder},
    upstreams::peer::HttpPeer,
};
use pingora_proxy::{ProxyHttp, Session};
use praxis_filter::{CompressionConfig, FilterPipeline};
use tokio::sync::Semaphore;
use tracing::debug;

use super::{
    adjust_compression, emit_request_metrics, handle_connect_failure, logging_cleanup, record_passive_health,
    request_body_filter, request_filter, response_body_filter, response_filter, upstream_peer, upstream_request, via,
};
use crate::http::pingora::context::PingoraRequestCtx;

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

    /// Swappable filter pipeline.
    pipeline: Arc<ArcSwap<FilterPipeline>>,
}

impl PingoraHttpHandler {
    /// Create a handler with body filter support.
    pub(super) fn new(
        pipeline: Arc<ArcSwap<FilterPipeline>>,
        downstream_read_timeout: Option<Duration>,
        connection_semaphore: Option<Arc<Semaphore>>,
    ) -> Self {
        let compression = pipeline.load().compression_config().cloned();
        Self {
            compression,
            connection_semaphore,
            downstream_read_timeout,
            pipeline,
        }
    }
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

    #[expect(clippy::cast_possible_truncation, reason = "millis fit u64")]
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if praxis_core::memory::is_exceeded() {
            return reject_503(session, "5", "memory pressure exceeded").await;
        }

        let (exceeded, permit) = crate::connections::try_acquire_global();
        ctx._global_connection_permit = permit;
        if exceeded {
            return reject_503(session, "1", "global max connections exceeded").await;
        }

        if let Some(sem) = &self.connection_semaphore {
            if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                ctx._connection_permit = Some(permit);
            } else {
                return reject_503(session, "1", "max connections exceeded").await;
            }
        }

        if let Some(timeout) = self.downstream_read_timeout {
            debug!(
                timeout_ms = timeout.as_millis() as u64,
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
        let pipeline = ctx.pipeline(&self.pipeline);
        request_body_filter::execute(&pipeline, session, body, end_of_stream, ctx).await
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
        let pipeline = ctx.pipeline(&self.pipeline);
        response_body_filter::execute(&pipeline, body, end_of_stream, ctx)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        handle_connect_failure(ctx, e)
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
        let is_upgrade = session.is_upgrade_req();
        upstream_request::strip_hop_by_hop(upstream_request, is_upgrade);
        upstream_request::strip_reserved_internal(upstream_request);
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
        let result = response_filter::execute(&pipeline, upstream_response, ctx).await;
        if result.is_ok() {
            let client_ver = ctx.client_http_version.unwrap_or(http::Version::HTTP_11);
            via::append_response_via(upstream_response, client_ver);
            adjust_compression(session, upstream_response, pipeline.compression_config());
        }
        result
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        upstream_peer::execute(ctx).await
    }

    async fn logging(&self, session: &mut Session, e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        let pipeline = ctx.pipeline(&self.pipeline);
        emit_request_metrics(session, ctx);
        record_passive_health(&pipeline, e, ctx);
        logging_cleanup(&pipeline, ctx).await;
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

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
