//! Response-phase filter execution: runs the pipeline on upstream response
//! headers and syncs modifications back to Pingora.

use pingora_core::Result;
use praxis_filter::{FilterAction, FilterContext, FilterPipeline};
use tracing::warn;

use super::super::{
    context::RequestCtx,
    convert::{response_header_from_pingora, sync_response_to_pingora},
};

// -----------------------------------------------------------------------------
// Response Filters
// -----------------------------------------------------------------------------

/// Run the response-phase pipeline and sync header changes to Pingora.
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    upstream_response: &mut pingora_http::ResponseHeader,
    ctx: &mut RequestCtx,
) -> Result<()> {
    let request = ctx.request_snapshot.as_ref().ok_or_else(|| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "request snapshot not set during response phase",
        )
    })?;

    let mut resp = response_header_from_pingora(upstream_response);

    let mut filter_ctx = FilterContext {
        client_addr: ctx.client_addr,
        cluster: ctx.cluster.take(),
        extra_request_headers: Vec::new(),
        request,
        request_body_bytes: ctx.request_body_bytes,
        request_start: ctx.request_start,
        response_body_bytes: ctx.response_body_bytes,
        response_header: Some(&mut resp),
        upstream: ctx.upstream.take(),
    };

    // Mark the response phase as complete in ALL exit paths so
    // the `logging()` hook does not re-run response filters.
    ctx.response_phase_done = true;

    match pipeline.execute_http_response(&mut filter_ctx).await {
        Ok(FilterAction::Continue | FilterAction::Release) => {
            // Skip the expensive header sync when no filter modified the response.
            if resp.headers != upstream_response.headers {
                sync_response_to_pingora(&resp, upstream_response);
            }

            Ok(())
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(status = rejection.status, "filter rejected response");
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(rejection.status),
                "response rejected by filter pipeline",
            ))
        },
        Err(e) => {
            warn!(error = %e, "filter pipeline error during response");
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("response filter error: {e}"),
            ))
        },
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_filter::{FilterPipeline, FilterRegistry, Request};

    use super::*;
    use crate::http::pingora::context::RequestCtx;

    fn make_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&[], &registry).unwrap()
    }

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            request_snapshot: Some(Request {
                method: http::Method::GET,
                uri: http::Uri::from_static("/"),
                headers: http::HeaderMap::new(),
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn empty_pipeline_passes_through() {
        let pipeline = make_pipeline();
        let mut upstream_response = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut upstream_response, &mut ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn response_status_preserved() {
        let pipeline = make_pipeline();
        let mut upstream_response = pingora_http::ResponseHeader::build(404, None).unwrap();
        let mut ctx = make_ctx();

        execute(&pipeline, &mut upstream_response, &mut ctx).await.unwrap();

        assert_eq!(upstream_response.status, 404);
    }

    #[tokio::test]
    async fn unmodified_headers_skip_sync() {
        let pipeline = make_pipeline();
        let mut upstream_response = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
        let _ = upstream_response.insert_header("x-original", "keep-me");
        let _ = upstream_response.insert_header("content-type", "text/plain");
        let mut ctx = make_ctx();

        execute(&pipeline, &mut upstream_response, &mut ctx).await.unwrap();

        // Headers must survive unchanged when no filter touches them.
        assert_eq!(upstream_response.headers.get("x-original").unwrap(), "keep-me");
        assert_eq!(upstream_response.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(upstream_response.headers.len(), 2);
    }
}
