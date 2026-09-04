// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Response-phase filter execution: runs the pipeline on upstream
//! response headers and syncs modifications.
//!
//! Implements Pingora's `upstream_response_filter` hook. Strips
//! hop-by-hop and reserved internal headers before the pipeline
//! runs, then diffs the header map to sync additions, removals,
//! and modifications back into Pingora's response object.

use std::{collections::hash_map::DefaultHasher, hash::Hasher as _};

use pingora_core::Result;
use praxis_filter::{FilterAction, FilterPipeline};
use tracing::{debug, error, warn};

use super::{
    super::{context::PingoraRequestCtx, convert::response_header_from_pingora},
    hop_by_hop::{self, RemoveHeader as _},
};

// -----------------------------------------------------------------------------
// Response Filters
// -----------------------------------------------------------------------------

/// Run the response-phase pipeline and sync header changes to Pingora.
///
/// Strips [RFC 9110] hop-by-hop headers and reserved internal
/// routing headers (`x-praxis-*` and AI extension prefixes) from
/// the upstream response before the filter pipeline sees them,
/// ensuring proxy-internal metadata is never forwarded to the
/// client.
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
#[expect(clippy::too_many_lines, reason = "linear response orchestration")]
pub(super) async fn execute(
    pipeline: &FilterPipeline,
    upstream_response: &mut pingora_http::ResponseHeader,
    ctx: &mut PingoraRequestCtx,
) -> Result<()> {
    if upstream_response.status == 101 && !request_has_upgrade(ctx) {
        error!("upstream sent unsolicited 101 without matching request Upgrade header");
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::HTTPStatus(502),
            "unsolicited 101 response from upstream",
        ));
    }
    let is_upgrade_response = upstream_response.status == 101 && is_websocket_101(&upstream_response.headers);
    if upstream_response.status == 101 && !is_upgrade_response {
        debug!("101 response missing valid WebSocket Upgrade header; not marking as upgraded");
    }
    super::upstream_response::strip_hop_by_hop_response(upstream_response, is_upgrade_response);
    upstream_response.strip_reserved_internal();
    let mut resp = response_header_from_pingora(upstream_response);
    // An empty pipeline cannot reorder headers, so the before/after
    // fingerprint comparison is unnecessary — skip hashing the whole header
    // map on every response for listeners with no filters.
    let name_fingerprint_before = (!pipeline.is_empty()).then(|| header_name_fingerprint(&resp.headers));
    ctx.connection_upgraded = is_upgrade_response;
    ctx.upstream_response_status = Some(upstream_response.status.as_u16());
    let is_bodyless = ctx
        .request_snapshot
        .as_ref()
        .is_some_and(|request| praxis_filter::bodyless_response(resp.status, &request.method));

    // Evaluate HTTP-status retry before running response filters / committing
    // the response phase, so a retriable 5xx does not leak to the client.
    if let Some(err) = super::maybe_retry_response(ctx, upstream_response.status.as_u16()) {
        return Err(err);
    }

    ctx.response_phase_done = true;

    let (result, filter_flagged_modification) = run_response_pipeline(pipeline, ctx, &mut resp).await?;
    // A filter may rearrange the header name sequence without changing the
    // header count, so the count alone cannot decide whether the direct
    // write-back is safe. Re-fingerprint and treat any change to the name
    // sequence as a modification, independent of what filters self-reported.
    let headers_modified = filter_flagged_modification
        || name_fingerprint_before.is_some_and(|before| header_name_fingerprint(&resp.headers) != before);
    // Upstream-supplied reserved internal headers were stripped before the
    // pipeline ran, but a response filter can add one afterwards; re-strip so
    // the "reserved headers never reach the client" invariant holds after the
    // pipeline too. An empty pipeline cannot add headers, so skip the pass.
    if !pipeline.is_empty() {
        hop_by_hop::strip_reserved_internal_header_map(&mut resp.headers);
    }
    let should_snapshot_response_header = pipeline.body_capabilities().any_response_body_condition
        && matches!(
            &result,
            Ok(FilterAction::Continue
                | FilterAction::Release
                | FilterAction::BodyDone
                | FilterAction::TerminalResponse(_)
                | FilterAction::StreamingTerminalResponse(_))
        );
    if should_snapshot_response_header {
        ctx.response_header_snapshot = Some(praxis_filter::Response {
            headers: resp.headers.clone(),
            status: resp.status,
        });
    }
    handle_response_result(result, upstream_response, resp, headers_modified, is_bodyless, ctx)
}

/// Run the response pipeline and capture the result plus header-modified flag.
#[expect(clippy::too_many_lines, reason = "writeback destructuring")]
async fn run_response_pipeline(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
    resp: &mut praxis_filter::Response,
) -> Result<(std::result::Result<FilterAction, praxis_filter::FilterError>, bool)> {
    let baseline_response_body_mode = ctx.response_body_mode;
    let (
        r,
        headers_modified,
        response_body_mode,
        cluster,
        cluster_retry_state_released,
        extensions,
        filter_metadata,
        filter_state,
        executed_indices,
        body_done,
        attempted_endpoints,
    ) = {
        let mut fctx = ctx.filter_context_for(pipeline, Some(resp)).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "request snapshot not set during response phase",
            )
        })?;
        let r = pipeline.execute_http_response(&mut fctx).await;
        (
            r,
            fctx.response_headers_modified,
            fctx.response_body_mode,
            fctx.cluster,
            fctx.cluster_retry_state_released,
            fctx.extensions,
            fctx.filter_metadata,
            fctx.filter_state,
            fctx.executed_filter_indices,
            fctx.body_done_indices,
            fctx.attempted_endpoints,
        )
    };
    ctx.cluster = cluster;
    ctx.cluster_retry_state_released = cluster_retry_state_released;
    ctx.response_body_mode = super::clamp_body_mode_to_ceiling(response_body_mode, baseline_response_body_mode);
    ctx.extensions = extensions;
    ctx.filter_metadata = filter_metadata;
    ctx.filter_state = filter_state;
    ctx.cached_executed_filter_indices = executed_indices;
    ctx.cached_body_done_indices = body_done;
    ctx.attempted_endpoints = attempted_endpoints;
    Ok((r, headers_modified))
}

/// Map the filter pipeline result to a Pingora Result, restoring headers on success.
///
/// Headers were taken from the Pingora response via [`std::mem::take`] earlier,
/// so they must always be restored. When the header name sequence is unchanged,
/// a direct swap is safe because the internal `header_name_map` still lines up
/// positionally with the restored [`HeaderMap`]. When the name sequence changed,
/// we rebuild through Pingora's API to keep the two structures consistent.
///
/// The status is written back unconditionally: it lives in the plain
/// [`RespParts`] and has no coupling to the name map, so a filter that adjusts
/// only the status must not depend on a header change to have its edit applied.
///
/// [`HeaderMap`]: http::HeaderMap
/// [`RespParts`]: http::response::Parts
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "linear result dispatch"
)]
fn handle_response_result(
    result: std::result::Result<FilterAction, praxis_filter::FilterError>,
    upstream_response: &mut pingora_http::ResponseHeader,
    mut resp: praxis_filter::Response,
    headers_modified: bool,
    is_bodyless: bool,
    ctx: &mut PingoraRequestCtx,
) -> Result<()> {
    match result {
        Ok(
            FilterAction::Continue
            | FilterAction::Release
            | FilterAction::BodyDone
            | FilterAction::TerminalResponse(_)
            | FilterAction::StreamingTerminalResponse(_),
        ) => {
            // Bodyless responses skip the body phase, so a successful
            // header phase is their delivery completion. Marking earlier
            // would hide responses the pipeline itself rejects.
            if is_bodyless {
                ctx.response_delivery_complete = true;
            }
            write_back_response(upstream_response, &mut resp, headers_modified);
            Ok(())
        },
        Ok(FilterAction::Reject(rejection)) => {
            warn!(status = rejection.status, "filter rejected response");
            let status = rejection.status;
            // Carry the full rejection across the error boundary so
            // fail_to_proxy can deliver its configured headers and body.
            ctx.pending_rejection = Some(rejection);
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(status),
                "response rejected by filter pipeline",
            ))
        },
        Err(e) => {
            error!(error = %e, "filter pipeline error during response");
            Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("response filter error: {e}"),
            ))
        },
    }
}

/// Restore the filtered headers and status onto the Pingora response.
///
/// The header map was moved out with [`std::mem::take`] before the
/// pipeline ran, so it must always be put back. `headers_modified`
/// selects how: an unchanged name sequence can be swapped straight in,
/// while a changed one has to be rebuilt through Pingora's API so the
/// `header_name_map` stays in step (see [`write_headers_to_pingora`]).
///
/// The status is assigned on both paths — it lives in the plain
/// [`RespParts`] with no coupling to the name map, so it must not
/// depend on whether headers happened to change.
///
/// [`RespParts`]: http::response::Parts
fn write_back_response(
    upstream_response: &mut pingora_http::ResponseHeader,
    resp: &mut praxis_filter::Response,
    headers_modified: bool,
) {
    if headers_modified {
        write_headers_to_pingora(&resp.headers, resp.status, upstream_response);
    } else {
        upstream_response.headers = std::mem::take(&mut resp.headers);
        upstream_response.status = resp.status;
    }
}

/// Restore headers into a Pingora response via its append API.
///
/// Pingora's [`ResponseHeader`] maintains an internal `header_name_map`
/// (original header casing) alongside the [`HeaderMap`], and serialises
/// HTTP/1.1 responses by zipping the two together. That zip asserts the
/// two sequences agree, so a [`HeaderMap`] whose name sequence no longer
/// matches the name map aborts the worker. Re-appending through
/// [`append_header`] rebuilds both structures in lockstep.
///
/// The upstream reason phrase is carried across the rebuild; it is not
/// derived from the status line and would otherwise be reset to the
/// canonical phrase for the status code.
///
/// [`ResponseHeader`]: pingora_http::ResponseHeader
/// [`HeaderMap`]: http::HeaderMap
/// [`append_header`]: pingora_http::ResponseHeader::append_header
fn write_headers_to_pingora(src: &http::HeaderMap, status: http::StatusCode, dst: &mut pingora_http::ResponseHeader) {
    #[expect(clippy::expect_used, reason = "valid upstream status")]
    let mut rebuilt = pingora_http::ResponseHeader::build(status, Some(src.len())).expect("valid status");
    for (name, value) in src {
        let _append = rebuilt.append_header(name.clone(), value.clone());
    }
    let reason = dst.get_reason_phrase().map(str::to_owned);
    if let Some(reason) = reason {
        let _set = rebuilt.set_reason_phrase(Some(&reason));
    }
    *dst = rebuilt;
}

/// Order-sensitive fingerprint of a header map's name sequence.
///
/// Hashes the names in iteration order, including repeats for
/// multi-valued headers, because that is exactly the sequence Pingora
/// zips against its `header_name_map` when serialising. A change in this
/// fingerprint means the direct write-back would desynchronise the two.
///
/// Header *values* are deliberately excluded: they are not part of the
/// name map, so a value-only edit stays safe on the direct path and does
/// not need to pay for a rebuild.
fn header_name_fingerprint(headers: &http::HeaderMap) -> u64 {
    let mut hasher = DefaultHasher::new();
    for (name, _value) in headers {
        hasher.write(name.as_str().as_bytes());
        hasher.write_u8(0xFF);
    }
    hasher.finish()
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Whether the original client request included an `Upgrade` header.
///
/// Returns `false` when the request snapshot is missing (should not
/// happen in normal flow since `request_filter` always sets it).
fn request_has_upgrade(ctx: &PingoraRequestCtx) -> bool {
    ctx.request_snapshot
        .as_ref()
        .is_some_and(|req| req.headers.contains_key(http::header::UPGRADE))
}

/// Whether a 101 response carries a valid `WebSocket` `Upgrade` header.
///
/// Returns `true` only when the response includes an `Upgrade` header
/// whose value is exactly `websocket` (case-insensitive). A bare 101
/// without proper `WebSocket` headers (e.g. from a buggy upstream)
/// should not be treated as a successful upgrade.
fn is_websocket_101(headers: &http::HeaderMap) -> bool {
    hop_by_hop::has_websocket_upgrade(headers) && headers.get("sec-websocket-accept").is_some()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use praxis_filter::{FilterRegistry, Request};

    use super::*;

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
        let mut ctx = make_upgrade_ctx();

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
        let mut ctx = make_upgrade_ctx();

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
        let mut ctx = make_upgrade_ctx();

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

    #[tokio::test]
    async fn unsolicited_101_websocket_rejected() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(101, None).unwrap();
        drop(resp.insert_header("upgrade", "websocket"));
        drop(resp.insert_header("connection", "Upgrade"));
        drop(resp.insert_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut resp, &mut ctx).await;

        assert!(result.is_err(), "unsolicited WebSocket 101 should be rejected");
        assert!(
            !ctx.connection_upgraded,
            "unsolicited 101 must not set connection_upgraded"
        );
    }

    #[tokio::test]
    async fn unsolicited_101_bare_rejected() {
        let pipeline = make_pipeline();
        let mut resp = pingora_http::ResponseHeader::build(101, None).unwrap();
        let mut ctx = make_ctx();

        let result = execute(&pipeline, &mut resp, &mut ctx).await;

        assert!(result.is_err(), "unsolicited bare 101 should be rejected");
        assert!(
            !ctx.connection_upgraded,
            "unsolicited 101 must not set connection_upgraded"
        );
    }

    #[test]
    fn request_has_upgrade_true_when_present() {
        let ctx = make_upgrade_ctx();
        assert!(request_has_upgrade(&ctx), "should detect Upgrade header in request");
    }

    #[test]
    fn request_has_upgrade_false_when_absent() {
        let ctx = make_ctx();
        assert!(!request_has_upgrade(&ctx), "should return false when no Upgrade header");
    }

    #[test]
    fn request_has_upgrade_false_when_no_snapshot() {
        let ctx = PingoraRequestCtx::default();
        assert!(
            !request_has_upgrade(&ctx),
            "should return false when request_snapshot is None"
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
    // Header Write-Back
    // -------------------------------------------------------------------------

    #[test]
    fn fingerprint_changes_when_a_header_name_is_swapped() {
        let mut before = http::HeaderMap::new();
        before.insert("x-old", "v".parse().unwrap());
        let mut after = http::HeaderMap::new();
        after.insert("x-new", "v".parse().unwrap());

        assert_eq!(before.len(), after.len(), "precondition: the counts match");
        assert_ne!(
            header_name_fingerprint(&before),
            header_name_fingerprint(&after),
            "a same-count name swap must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_is_stable_when_only_a_value_changes() {
        let mut before = http::HeaderMap::new();
        before.insert("x-same", "old".parse().unwrap());
        let mut after = http::HeaderMap::new();
        after.insert("x-same", "new".parse().unwrap());

        assert_eq!(
            header_name_fingerprint(&before),
            header_name_fingerprint(&after),
            "value-only edits leave the name sequence intact and stay on the direct path"
        );
    }

    #[test]
    fn fingerprint_accounts_for_repeated_names() {
        let mut single = http::HeaderMap::new();
        single.append("x-multi", "a".parse().unwrap());
        let mut double = http::HeaderMap::new();
        double.append("x-multi", "a".parse().unwrap());
        double.append("x-multi", "b".parse().unwrap());

        assert_ne!(
            header_name_fingerprint(&single),
            header_name_fingerprint(&double),
            "multi-valued headers occupy multiple slots in the zipped sequence"
        );
    }

    #[test]
    fn status_change_is_written_back_without_header_changes() {
        let mut upstream = pingora_http::ResponseHeader::build(200, None).unwrap();
        let resp = praxis_filter::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::IM_A_TEAPOT,
        };

        handle_response_result(
            Ok(FilterAction::Continue),
            &mut upstream,
            resp,
            false,
            false,
            &mut PingoraRequestCtx::default(),
        )
        .unwrap();

        assert_eq!(
            upstream.status, 418,
            "a status-only edit must reach the response even on the direct write-back path"
        );
    }

    #[test]
    fn rebuilt_response_serialises_after_a_name_swap() {
        let mut upstream = pingora_http::ResponseHeader::build(200, Some(1)).unwrap();
        drop(upstream.insert_header("x-old", "v"));

        // Mirror what the response phase does: take the map, let a filter
        // swap one name for another, then write back through the rebuild.
        let mut taken = std::mem::take(&mut upstream.headers);
        taken.remove("x-old");
        taken.insert("x-new", "v".parse().unwrap());
        let resp = praxis_filter::Response {
            headers: taken,
            status: http::StatusCode::OK,
        };

        handle_response_result(
            Ok(FilterAction::Continue),
            &mut upstream,
            resp,
            true,
            false,
            &mut PingoraRequestCtx::default(),
        )
        .unwrap();

        // Serialising exercises the name-map zip that aborts on desync.
        let mut buf = bytes::BytesMut::new();
        upstream.header_to_h1_wire(&mut buf);
        let wire = String::from_utf8_lossy(&buf);
        assert!(wire.contains("x-new"), "swapped-in header should serialise: {wire}");
        assert!(!wire.contains("x-old"), "swapped-out header should be gone: {wire}");
    }

    #[test]
    fn rebuild_preserves_the_upstream_reason_phrase() {
        let mut upstream = pingora_http::ResponseHeader::build(200, None).unwrap();
        upstream.set_reason_phrase(Some("Totally Fine")).unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-added", "1".parse().unwrap());
        let resp = praxis_filter::Response {
            headers,
            status: http::StatusCode::OK,
        };

        handle_response_result(
            Ok(FilterAction::Continue),
            &mut upstream,
            resp,
            true,
            false,
            &mut PingoraRequestCtx::default(),
        )
        .unwrap();

        assert_eq!(
            upstream.get_reason_phrase(),
            Some("Totally Fine"),
            "the rebuild must not reset a custom reason phrase"
        );
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

    /// Create a request context with `Upgrade: websocket` for tests.
    fn make_upgrade_ctx() -> PingoraRequestCtx {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(Request {
            method: http::Method::GET,
            uri: http::Uri::from_static("/"),
            headers,
        });
        ctx
    }
}
