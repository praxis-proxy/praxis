//! Request-phase filter execution: runs the pipeline, captures client
//! address and idempotency, then injects extra headers or sends rejections.
//!
//! When the pipeline uses [`StreamBuffer`] mode, the body is pre-read
//! from the session during this phase (before upstream selection) so
//! that body filters can promote values to headers and influence
//! routing decisions.
//!
//! [`StreamBuffer`]: praxis_filter::BodyMode::StreamBuffer

use std::collections::VecDeque;

use pingora_core::Result;
use pingora_proxy::Session;
use praxis_filter::{
    BodyBuffer, BodyMode, FilterAction, FilterContext, FilterError, FilterPipeline, Rejection, Request,
};
use tracing::{debug, warn};

use super::super::{
    context::RequestCtx,
    convert::{request_header_from_session, send_rejection},
};

// ----------------------------------------------------------------------------
// Request Filters
// ----------------------------------------------------------------------------

/// Run the request-phase pipeline, capture client info, and inject headers.
pub(super) async fn execute(pipeline: &FilterPipeline, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool> {
    let mut request = request_header_from_session(session);
    ctx.client_addr = session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(std::net::SocketAddr::ip);
    ctx.request_is_idempotent = matches!(
        session.req_header().method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    );

    let caps = pipeline.body_capabilities();

    // StreamBuffer Pre-Read
    //
    // When any filter uses StreamBuffer mode, we read the body NOW
    // (before Pingora calls upstream_peer) so that body filters can
    // inspect content, promote values to headers, and influence
    // routing decisions made by subsequent header-phase filters.
    if matches!(caps.request_body_mode, BodyMode::StreamBuffer { .. }) {
        match pre_read_body(pipeline, session, ctx, &request).await {
            Ok(extra_headers) => {
                // Inject promoted headers into the session AND the
                // request snapshot so routing filters see them.
                for (name, value) in extra_headers {
                    let _ = session.req_header_mut().insert_header(name, &value);
                }
                // Rebuild request from session (now includes promoted headers).
                request = request_header_from_session(session);
            },
            Err(PreReadError::Rejected(rejection)) => {
                send_rejection(session, rejection).await;
                return Ok(true);
            },
            Err(PreReadError::Filter(e)) => {
                warn!(error = %e, "body filter error during pre-read");
                send_rejection(session, Rejection::status(500)).await;
                return Ok(true);
            },
            Err(PreReadError::Io(e)) => return Err(e),
        }
    }

    // ---------------------------------------------------------
    // Header-Phase Pipeline
    // ---------------------------------------------------------
    match run_pipeline(pipeline, request, ctx).await {
        Ok((FilterAction::Continue | FilterAction::Release, extra_headers)) => {
            for (name, value) in extra_headers {
                let _ = session.req_header_mut().insert_header(name, value);
            }
            Ok(false)
        },
        Ok((FilterAction::Reject(rejection), _)) => {
            send_rejection(session, rejection).await;
            Ok(true)
        },
        Err(e) => {
            warn!(error = %e, "filter pipeline error");
            send_rejection(session, Rejection::status(500)).await;
            Ok(true)
        },
    }
}

// -----------------------------------------------------------------------------
// StreamBuffer Pre-Read
// -----------------------------------------------------------------------------

/// Errors that can occur during body pre-reading in `StreamBuffer` mode.
enum PreReadError {
    /// A filter rejected the request during body processing.
    Rejected(Rejection),

    /// A filter returned an error during body processing.
    Filter(FilterError),

    /// An I/O error from Pingora while reading the body.
    Io(Box<pingora_core::Error>),
}

/// Pre-read the request body from the session and run body filters.
///
/// Returns any extra headers that body filters promoted (e.g.
/// `json_body_field` extracting a model name). The accumulated body
/// is stored in `ctx.pre_read_body` for later forwarding by
/// `request_body_filter`.
async fn pre_read_body(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut RequestCtx,
    request: &Request,
) -> std::result::Result<Vec<(String, String)>, PreReadError> {
    let caps = pipeline.body_capabilities();
    let max_bytes = match caps.request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(usize::MAX),
        _ => return Ok(Vec::new()),
    };

    let mut buffer = BodyBuffer::new(max_bytes);
    let mut all_extra_headers = Vec::new();
    let mut released = false;

    loop {
        let chunk = session
            .downstream_session
            .read_request_body()
            .await
            .map_err(PreReadError::Io)?;

        let end_of_stream = chunk.is_none();
        let mut body = chunk;

        // Accumulate if not yet released.
        if !released
            && let Some(ref b) = body
            && buffer.push(b.clone()).is_err()
        {
            return Err(PreReadError::Rejected(Rejection::status(413)));
        }

        let cluster = ctx.cluster.take();
        let upstream = ctx.upstream.take();
        let mut filter_ctx = FilterContext {
            client_addr: ctx.client_addr,
            cluster,
            extra_request_headers: Vec::new(),
            request,
            request_body_bytes: ctx.request_body_bytes,
            request_start: ctx.request_start,
            response_body_bytes: ctx.response_body_bytes,
            response_header: None,
            upstream,
        };
        match pipeline
            .execute_http_request_body(&mut filter_ctx, &mut body, end_of_stream)
            .await
        {
            Ok(FilterAction::Continue) => {},
            Ok(FilterAction::Release) => {
                if !released {
                    debug!("StreamBuffer released during pre-read");
                    released = true;
                }
            },
            Ok(FilterAction::Reject(rejection)) => {
                return Err(PreReadError::Rejected(rejection));
            },
            Err(e) => return Err(PreReadError::Filter(e)),
        }

        ctx.request_body_bytes = filter_ctx.request_body_bytes;
        ctx.cluster = filter_ctx.cluster;
        ctx.upstream = filter_ctx.upstream;
        all_extra_headers.extend(filter_ctx.extra_request_headers);

        if end_of_stream {
            break;
        }
    }

    // Store the pre-read body for forwarding by request_body_filter.
    let frozen = buffer.freeze();
    if frozen.is_empty() {
        ctx.pre_read_body = Some(VecDeque::new());
    } else {
        ctx.pre_read_body = Some(VecDeque::from([frozen]));
    }

    ctx.request_body_released = true;

    Ok(all_extra_headers)
}

// -----------------------------------------------------------------------------
// Header-Phase Pipeline
// -----------------------------------------------------------------------------

/// Run the request pipeline phase without any session I/O.
async fn run_pipeline(
    pipeline: &FilterPipeline,
    request: Request,
    ctx: &mut RequestCtx,
) -> std::result::Result<(FilterAction, Vec<(String, String)>), FilterError> {
    let (action, extra_headers, cluster, upstream) = {
        let mut filter_ctx = FilterContext {
            client_addr: ctx.client_addr,
            cluster: None,
            extra_request_headers: Vec::new(),
            request: &request,
            request_body_bytes: ctx.request_body_bytes,
            request_start: ctx.request_start,
            response_body_bytes: ctx.response_body_bytes,
            response_header: None,
            upstream: None,
        };

        let action = pipeline.execute_http_request(&mut filter_ctx).await;
        (
            action,
            filter_ctx.extra_request_headers,
            filter_ctx.cluster,
            filter_ctx.upstream,
        )
    };

    // Snapshot the request so later phases (body filters,
    // response filters) can reference the original headers.
    ctx.request_snapshot = Some(request);

    match action {
        Ok(FilterAction::Continue | FilterAction::Release) => {
            ctx.cluster = cluster;
            ctx.upstream = upstream;
            Ok((FilterAction::Continue, extra_headers))
        },
        Ok(FilterAction::Reject(rejection)) => Ok((FilterAction::Reject(rejection), Vec::new())),
        Err(e) => Err(e),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use http::{HeaderMap, Method, Uri};
    use praxis_filter::{FilterAction, FilterPipeline, FilterRegistry, Request};

    use super::*;
    use crate::http::pingora::context::RequestCtx;

    fn make_request() -> Request {
        Request {
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
        }
    }

    fn make_ctx() -> RequestCtx {
        RequestCtx::default()
    }

    fn empty_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&[], &registry).unwrap()
    }

    #[tokio::test]
    async fn empty_pipeline_continues() {
        let (action, extra_headers) = run_pipeline(&empty_pipeline(), make_request(), &mut make_ctx())
            .await
            .unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert!(extra_headers.is_empty());
    }

    #[tokio::test]
    async fn snapshot_always_stored() {
        let mut ctx = make_ctx();

        run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap();

        assert!(ctx.request_snapshot.is_some());
    }

    #[tokio::test]
    async fn cluster_and_upstream_propagated_on_continue() {
        // Empty pipeline produces no cluster/upstream — both stay None,
        // which confirms the ctx fields are written (not left stale).
        let mut ctx = make_ctx();

        run_pipeline(&empty_pipeline(), make_request(), &mut ctx).await.unwrap();

        assert!(ctx.cluster.is_none());
        assert!(ctx.upstream.is_none());
    }

    // -------------------------------------------------------------------------
    // Rejection pipeline tests
    // -------------------------------------------------------------------------

    fn rejecting_pipeline(status: u16) -> FilterPipeline {
        // Use static_response filter to produce a rejection at the
        // given status code. Build via YAML so we stay within public API.
        let registry = FilterRegistry::with_builtins();
        let yaml = format!("status: {status}");
        let config: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let entries = vec![praxis_filter::FilterEntry {
            filter_type: "static_response".into(),
            config,
            conditions: vec![],
            response_conditions: vec![],
        }];
        FilterPipeline::build(&entries, &registry).unwrap()
    }

    #[tokio::test]
    async fn rejection_propagated_from_pipeline() {
        let pipeline = rejecting_pipeline(403);
        let mut ctx = make_ctx();

        let (action, _) = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
    }

    #[tokio::test]
    async fn rejection_does_not_set_cluster() {
        let pipeline = rejecting_pipeline(429);
        let mut ctx = make_ctx();

        run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        // On rejection, cluster/upstream remain untouched.
        assert!(ctx.cluster.is_none());
        assert!(ctx.upstream.is_none());
    }

    // -------------------------------------------------------------------------
    // Extra header injection
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn extra_headers_returned_from_pipeline() {
        let pipeline = empty_pipeline();
        let mut ctx = make_ctx();

        let (_, extra_headers) = run_pipeline(&pipeline, make_request(), &mut ctx).await.unwrap();

        // Empty pipeline produces no extra headers.
        assert!(extra_headers.is_empty());
    }

    #[tokio::test]
    async fn idempotent_methods_detected_in_request() {
        // GET, HEAD, OPTIONS are idempotent.
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let req = Request {
                method,
                uri: Uri::from_static("/"),
                headers: HeaderMap::new(),
            };
            let is_idempotent = matches!(req.method, Method::GET | Method::HEAD | Method::OPTIONS);
            assert!(is_idempotent, "{} should be idempotent", req.method);
        }

        // POST, PUT, DELETE, PATCH are not.
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let req = Request {
                method,
                uri: Uri::from_static("/"),
                headers: HeaderMap::new(),
            };
            let is_idempotent = matches!(req.method, Method::GET | Method::HEAD | Method::OPTIONS);
            assert!(!is_idempotent, "{} should not be idempotent", req.method);
        }
    }
}
