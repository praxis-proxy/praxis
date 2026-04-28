// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pingora HTTP handler that skips body filter hooks for zero-overhead forwarding.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_core::{
    Result,
    modules::http::{HttpModules, compression::ResponseCompressionBuilder},
    upstreams::peer::HttpPeer,
};
use pingora_proxy::{ProxyHttp, Session};
use praxis_filter::{CompressionConfig, FilterPipeline};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use super::{
    adjust_compression, handle_connect_failure, logging_cleanup, request_filter, response_filter, upstream_peer,
    upstream_request, via,
};
use crate::http::pingora::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// PingoraHttpHandlerNoBody
// -----------------------------------------------------------------------------

/// Pingora HTTP handler that skips body filter hooks.
///
/// Used when no filter in the pipeline declares body
/// access. Pingora's default no-op body hooks forward
/// bytes with zero overhead, avoiding the cost of
/// building [`HttpFilterContext`] on every chunk.
///
/// [`HttpFilterContext`]: praxis_filter::HttpFilterContext
pub struct PingoraHttpHandlerNoBody {
    /// Compression configuration, if enabled.
    compression: Option<CompressionConfig>,

    /// Per-listener connection semaphore for max connections.
    connection_semaphore: Option<Arc<Semaphore>>,

    /// Per-listener downstream read timeout.
    downstream_read_timeout: Option<Duration>,

    /// Shared filter pipeline.
    pipeline: Arc<FilterPipeline>,
}

impl PingoraHttpHandlerNoBody {
    /// Create a handler without body filter support.
    pub(super) fn new(
        pipeline: Arc<FilterPipeline>,
        downstream_read_timeout: Option<Duration>,
        connection_semaphore: Option<Arc<Semaphore>>,
    ) -> Self {
        let compression = pipeline.compression_config().cloned();
        Self {
            compression,
            connection_semaphore,
            downstream_read_timeout,
            pipeline,
        }
    }
}

#[async_trait]
impl ProxyHttp for PingoraHttpHandlerNoBody {
    type CTX = PingoraRequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        PingoraRequestCtx::default()
    }

    /// Registers Pingora's compression module when compression is
    /// configured.
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        if let Some(ref cfg) = self.compression {
            debug!(level = cfg.default_level, "registering compression module");
            modules.add_module(ResponseCompressionBuilder::enable(cfg.default_level));
        }
    }

    #[allow(clippy::cast_possible_truncation, reason = "millis fit u64")]
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(ref sem) = self.connection_semaphore {
            if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
                ctx._connection_permit = Some(permit);
            } else {
                warn!("max connections reached, rejecting request");
                let mut header = pingora_http::ResponseHeader::build(503, None)?;
                header.append_header("Retry-After", "1")?;
                session.write_response_header(Box::new(header), true).await?;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(503),
                    "max connections exceeded",
                ));
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
        request_filter::execute(&self.pipeline, session, ctx).await
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
        let result = response_filter::execute(&self.pipeline, upstream_response, ctx).await;
        if result.is_ok() {
            let client_ver = ctx.client_http_version.unwrap_or(http::Version::HTTP_11);
            via::append_response_via(upstream_response, client_ver);
            adjust_compression(session, upstream_response, self.compression.as_ref());
        }
        result
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
        upstream_request::apply_rewritten_path(upstream_request, ctx)?;
        via::append_request_via(upstream_request, http::Version::HTTP_11);
        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        upstream_peer::execute(ctx)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        logging_cleanup(&self.pipeline, ctx).await;
    }
}
