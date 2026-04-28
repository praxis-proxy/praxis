// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Response-phase filter execution: runs the pipeline on upstream response headers and syncs modifications.

use pingora_core::Result;
use praxis_filter::{FilterAction, FilterPipeline};
use tracing::{debug, warn};

use super::super::{context::PingoraRequestCtx, convert::response_header_from_pingora};

// -----------------------------------------------------------------------------
// Response Filters
// -----------------------------------------------------------------------------

/// Run the response-phase pipeline and sync header changes to Pingora.
///
/// Strips [RFC 9110] hop-by-hop headers from the upstream response
/// before the filter pipeline sees them, ensuring they are never
/// forwarded to the client.
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    upstream_response: &mut pingora_http::ResponseHeader,
    ctx: &mut PingoraRequestCtx,
) -> Result<()> {
    let is_upgrade_response = upstream_response.status == 101 && is_websocket_101(&upstream_response.headers);
    if upstream_response.status == 101 && !is_upgrade_response {
        debug!("101 response missing valid WebSocket Upgrade header; not marking as upgraded");
    }
    super::upstream_response::strip_hop_by_hop_response(upstream_response, is_upgrade_response);
    let mut resp = response_header_from_pingora(upstream_response);
    ctx.connection_upgraded = is_upgrade_response;
    ctx.response_phase_done = true;

    let (result, _headers_modified) = run_response_pipeline(pipeline, ctx, &mut resp).await?;
    handle_response_result(result, upstream_response, &resp)
}

/// Run the response pipeline and capture the result plus header-modified flag.
async fn run_response_pipeline(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
    resp: &mut praxis_filter::Response,
) -> Result<(std::result::Result<FilterAction, praxis_filter::FilterError>, bool)> {
    let mut fctx = ctx.filter_context_for(pipeline, Some(resp)).ok_or_else(|| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "request snapshot not set during response phase",
        )
    })?;
    let r = pipeline.execute_http_response(&mut fctx).await;
    Ok((r, fctx.response_headers_modified))
}

/// Map the filter pipeline result to a Pingora Result, restoring headers on success.
///
/// Headers were taken from the Pingora response via [`std::mem::take`] earlier,
/// so they must always be restored. We re-insert through Pingora's API to keep
/// the internal `header_name_map` consistent with the `HeaderMap`.
fn handle_response_result(
    result: std::result::Result<FilterAction, praxis_filter::FilterError>,
    upstream_response: &mut pingora_http::ResponseHeader,
    resp: &praxis_filter::Response,
) -> Result<()> {
    match result {
        Ok(FilterAction::Continue | FilterAction::Release) => {
            write_headers_to_pingora(&resp.headers, resp.status, upstream_response);
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

/// Restore headers into a Pingora response via its insert API.
///
/// Pingora's [`ResponseHeader`] maintains an internal name map alongside
/// the [`HeaderMap`]. Direct field assignment desynchronises the two,
/// causing iteration panics. Re-inserting through [`insert_header`]
/// keeps both structures consistent.
///
/// [`ResponseHeader`]: pingora_http::ResponseHeader
/// [`HeaderMap`]: http::HeaderMap
/// [`insert_header`]: pingora_http::ResponseHeader::insert_header
fn write_headers_to_pingora(src: &http::HeaderMap, status: http::StatusCode, dst: &mut pingora_http::ResponseHeader) {
    #[allow(clippy::expect_used, reason = "valid upstream status")]
    let mut rebuilt = pingora_http::ResponseHeader::build(status, Some(src.len())).expect("valid status");
    for (name, value) in src {
        let _insert = rebuilt.append_header(name.clone(), value.clone());
    }
    *dst = rebuilt;
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Whether a 101 response carries a valid `WebSocket` `Upgrade` header.
///
/// Returns `true` only when the response includes an `Upgrade` header
/// whose value is exactly `websocket` (case-insensitive). A bare 101
/// without proper `WebSocket` headers (e.g. from a buggy upstream)
/// should not be treated as a successful upgrade.
fn is_websocket_101(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"))
        && headers.get("sec-websocket-accept").is_some()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_filter::{FilterPipeline, FilterRegistry, Request};

    use super::*;
    use crate::http::pingora::context::PingoraRequestCtx;

    #[tokio::test]
    async fn empty_pipeline_passes_through() {
        let pipeline = make_pipeline();
        let mut upstream_response = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut upstream_response, &mut ctx).await;

        assert!(result.is_ok(), "empty pipeline should pass through without error");
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
    async fn unmodified_headers_restored_after_pipeline() {
        let pipeline = make_pipeline();
        let mut upstream_response = pingora_http::ResponseHeader::build(200, Some(2)).unwrap();
        drop(upstream_response.insert_header("x-original", "keep-me"));
        drop(upstream_response.insert_header("content-type", "text/plain"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut upstream_response, &mut ctx).await.unwrap();

        assert_eq!(upstream_response.headers.get("x-original").unwrap(), "keep-me");
        assert_eq!(upstream_response.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(upstream_response.headers.len(), 2);
    }

    #[tokio::test]
    async fn websocket_101_sets_connection_upgraded() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(101, None).unwrap();
        drop(resp.insert_header("upgrade", "websocket"));
        drop(resp.insert_header("connection", "Upgrade"));
        drop(resp.insert_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut resp, &mut ctx).await.unwrap();

        assert!(
            ctx.connection_upgraded,
            "valid WebSocket 101 should set connection_upgraded"
        );
    }

    #[tokio::test]
    async fn bare_101_without_upgrade_header_does_not_set_flag() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(101, None).unwrap();
        let mut ctx = make_ctx();

        execute(&pipeline, &mut resp, &mut ctx).await.unwrap();

        assert!(
            !ctx.connection_upgraded,
            "bare 101 without Upgrade header should not set connection_upgraded"
        );
    }

    #[tokio::test]
    async fn non_websocket_101_does_not_set_flag() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(101, None).unwrap();
        drop(resp.insert_header("upgrade", "h2c"));
        drop(resp.insert_header("connection", "Upgrade"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut resp, &mut ctx).await.unwrap();

        assert!(
            !ctx.connection_upgraded,
            "non-WebSocket 101 (h2c) should not set connection_upgraded"
        );
    }

    #[tokio::test]
    async fn non_101_status_never_sets_flag() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        drop(resp.insert_header("upgrade", "websocket"));
        let mut ctx = make_ctx();

        execute(&pipeline, &mut resp, &mut ctx).await.unwrap();

        assert!(
            !ctx.connection_upgraded,
            "200 with Upgrade header should not set connection_upgraded"
        );
    }

    #[test]
    fn is_websocket_101_with_valid_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(
            "sec-websocket-accept".parse::<http::header::HeaderName>().unwrap(),
            "x".parse().unwrap(),
        );
        assert!(is_websocket_101(&headers), "should recognize lowercase websocket");
    }

    #[test]
    fn is_websocket_101_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "WebSocket".parse().unwrap());
        headers.insert(
            "sec-websocket-accept".parse::<http::header::HeaderName>().unwrap(),
            "x".parse().unwrap(),
        );
        assert!(is_websocket_101(&headers), "should recognize mixed-case WebSocket");
    }

    #[test]
    fn is_websocket_101_missing_upgrade_header() {
        let headers = http::HeaderMap::new();
        assert!(
            !is_websocket_101(&headers),
            "missing Upgrade header should return false"
        );
    }

    #[test]
    fn is_websocket_101_missing_accept_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        assert!(
            !is_websocket_101(&headers),
            "missing Sec-WebSocket-Accept header should return false"
        );
    }

    #[test]
    fn is_websocket_101_with_whitespace() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "  websocket  ".parse().unwrap());
        headers.insert(
            "sec-websocket-accept".parse::<http::header::HeaderName>().unwrap(),
            "x".parse().unwrap(),
        );
        assert!(
            is_websocket_101(&headers),
            "padded websocket value should be recognized after trimming"
        );
    }

    #[test]
    fn is_websocket_101_wrong_protocol() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "h2c".parse().unwrap());
        headers.insert(
            "sec-websocket-accept".parse::<http::header::HeaderName>().unwrap(),
            "x".parse().unwrap(),
        );
        assert!(!is_websocket_101(&headers), "h2c should not be treated as websocket");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an empty filter pipeline for tests.
    fn make_pipeline() -> FilterPipeline {
        let registry = FilterRegistry::with_builtins();
        FilterPipeline::build(&mut [], &registry).unwrap()
    }

    /// Create a request context with a GET snapshot for tests.
    fn make_ctx() -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
        });
        ctx
    }
}
