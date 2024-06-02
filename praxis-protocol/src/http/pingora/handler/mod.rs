//! Pingora `ProxyHttp` implementation: the main HTTP reverse-proxy handler.
//!
//! Delegates each lifecycle hook (request, response, body, upstream selection)
//! to focused submodules.
//!
//! Two handler variants exist:
//! - [`HTTPHandler`]: overrides body filter hooks (used when the pipeline
//!   contains filters that declare body access).
//! - [`HTTPHandlerNoBody`]: skips body hooks entirely, letting Pingora
//!   forward body bytes with zero Praxis overhead.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{Result, server::Server, upstreams::peer::HttpPeer};
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use praxis_filter::FilterPipeline;
use tracing::{debug, warn};

use super::context::RequestCtx;

/// Maximum number of upstream connection retries for idempotent requests.
const MAX_RETRIES: usize = 3;

mod request_body_filter;
mod request_filter;
mod response_body_filter;
mod response_filter;
mod upstream_peer;
mod upstream_request;

// -----------------------------------------------------------------------------
// Shared Helpers
// -----------------------------------------------------------------------------

/// Handle upstream connect failures with retry logic.
fn handle_connect_failure(ctx: &mut RequestCtx, e: Box<pingora_core::Error>) -> Box<pingora_core::Error> {
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
async fn logging_cleanup(pipeline: &FilterPipeline, ctx: &mut RequestCtx) {
    if !ctx.response_phase_done
        && let Some(request) = ctx.request_snapshot.as_ref()
    {
        let mut filter_ctx = praxis_filter::FilterContext {
            client_addr: ctx.client_addr,
            cluster: ctx.cluster.take(),
            extra_request_headers: Vec::new(),
            request,
            request_body_bytes: ctx.request_body_bytes,
            request_start: ctx.request_start,
            response_body_bytes: ctx.response_body_bytes,
            response_header: None,
            upstream: ctx.upstream.take(),
        };
        let _ = pipeline.execute_http_response(&mut filter_ctx).await;
    }
}

// -----------------------------------------------------------------------------
// HTTPHandler (with body hooks)
// -----------------------------------------------------------------------------

/// HTTP handler that overrides body filter hooks.
///
/// Used when the pipeline contains filters that declare
/// body access via [`BodyAccess`].
///
/// [`BodyAccess`]: praxis_filter::BodyAccess
pub struct HTTPHandler {
    /// Shared filter pipeline.
    pipeline: Arc<FilterPipeline>,
}

impl HTTPHandler {
    /// Create a handler with body filter support.
    fn new(pipeline: Arc<FilterPipeline>) -> Self {
        Self { pipeline }
    }
}

#[async_trait]
impl ProxyHttp for HTTPHandler {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        request_filter::execute(&self.pipeline, session, ctx).await
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        response_filter::execute(&self.pipeline, upstream_response, ctx).await
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
        request_body_filter::execute(&self.pipeline, session, body, end_of_stream, ctx).await
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
        response_body_filter::execute(&self.pipeline, body, end_of_stream, ctx)
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
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_request::strip_hop_by_hop(upstream_request);
        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        upstream_peer::execute(ctx)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        logging_cleanup(&self.pipeline, ctx).await;
    }
}

// -----------------------------------------------------------------------------
// HTTPHandlerNoBody (no body hooks)
// -----------------------------------------------------------------------------

/// HTTP handler that skips body filter hooks.
///
/// Used when no filter in the pipeline declares body
/// access. Pingora's default no-op body hooks forward
/// bytes with zero overhead, avoiding the cost of
/// building [`FilterContext`] on every chunk.
///
/// [`FilterContext`]: praxis_filter::FilterContext
pub struct HTTPHandlerNoBody {
    /// Shared filter pipeline.
    pipeline: Arc<FilterPipeline>,
}

impl HTTPHandlerNoBody {
    /// Create a handler without body filter support.
    fn new(pipeline: Arc<FilterPipeline>) -> Self {
        Self { pipeline }
    }
}

#[async_trait]
impl ProxyHttp for HTTPHandlerNoBody {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        request_filter::execute(&self.pipeline, session, ctx).await
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        response_filter::execute(&self.pipeline, upstream_response, ctx).await
    }

    // Body hooks intentionally NOT overridden. Pingora's
    // defaults pass body bytes through with zero overhead.
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
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_request::strip_hop_by_hop(upstream_request);
        Ok(())
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        upstream_peer::execute(ctx)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        logging_cleanup(&self.pipeline, ctx).await;
    }
}

// -----------------------------------------------------------------------------
// Load Handler
// -----------------------------------------------------------------------------

/// Load an HTTP handler for a single listener.
///
/// Chooses [`HTTPHandler`] (with body hooks) or
/// [`HTTPHandlerNoBody`] (no body hooks) based on whether
/// the pipeline contains filters that need body access.
pub fn load_http_handler(
    server: &mut Server,
    listener: &praxis_core::config::Listener,
    pipeline: Arc<FilterPipeline>,
) -> Result<(), praxis_core::ProxyError> {
    if pipeline.needs_body_filters() {
        debug!("loading HTTP handler with body filters");
        let proxy = HTTPHandler::new(pipeline);
        let mut service = http_proxy_service(&server.configuration, proxy);
        super::listener::add_listener(&mut service, listener)?;
        server.add_service(service);
    } else {
        debug!("loading HTTP handler (no body filters)");
        let proxy = HTTPHandlerNoBody::new(pipeline);
        let mut service = http_proxy_service(&server.configuration, proxy);
        super::listener::add_listener(&mut service, listener)?;
        server.add_service(service);
    }
    Ok(())
}
