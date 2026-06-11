// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! StreamBuffer pre-read logic and TRACE response construction.

use std::{borrow::Cow, collections::VecDeque, fmt::Write};

use pingora_proxy::Session;
use praxis_filter::{BodyBuffer, BodyMode, FilterAction, FilterError, FilterPipeline, Rejection, Request};
use tracing::debug;

use crate::http::pingora::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Defense-in-depth fallback when `StreamBuffer { max_bytes: None }`
/// reaches the body filter layer (64 MiB, matching the filter crate's
/// `MAX_JSON_BODY_BYTES` ceiling).
const BODY_FALLBACK_LIMIT: usize = 67_108_864; // 64 MiB

/// Headers allowed in TRACE echo responses.
///
/// Only headers known to be non-sensitive are echoed. All others
/// are redacted to prevent credential leakage (e.g. `Authorization`,
/// `Cookie`, `X-Auth-Token`, `X-Api-Key`).
const TRACE_ALLOWED_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "host",
    "max-forwards",
    "user-agent",
    "via",
];

// -----------------------------------------------------------------------------
// TRACE Response
// -----------------------------------------------------------------------------

/// Build a TRACE echo response containing the request headers as the body.
///
/// Per [RFC 9110 Section 9.3.8], a TRACE response echoes the request
/// message with content-type `message/http`. Only headers in
/// [`TRACE_ALLOWED_HEADERS`] are echoed; all others are redacted.
///
/// TRACE is enabled by default per RFC. Deployments concerned about
/// TRACE-based reconnaissance should block it via filter conditions.
///
/// [RFC 9110 Section 9.3.8]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.8
pub(super) fn build_trace_response(session: &Session) -> Rejection {
    let req = session.req_header();
    let mut body = format!("{} {} {:?}\r\n", req.method, req.uri, req.version);
    for (name, value) in &req.headers {
        if !TRACE_ALLOWED_HEADERS.contains(&name.as_str()) {
            tracing::debug!(header = %name, "redacting header from TRACE response");
            continue;
        }
        let val = value.to_str().unwrap_or("[binary]");
        let _infallible = write!(body, "{name}: {val}\r\n");
    }

    let mut rejection = Rejection::status(200);
    rejection
        .headers
        .push(("Content-Type".to_owned(), "message/http".to_owned()));
    rejection.body = Some(bytes::Bytes::from(body));
    rejection
}

// -----------------------------------------------------------------------------
// StreamBuffer Pre-Read
// -----------------------------------------------------------------------------

/// Errors that can occur during body pre-reading in `StreamBuffer` mode.
pub(super) enum PreReadError {
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
#[allow(
    clippy::too_many_lines,
    unused_assignments,
    reason = "buffer management orchestration"
)]
pub(super) async fn pre_read_body(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    request: &Request,
) -> Result<Vec<(Cow<'static, str>, String)>, PreReadError> {
    let caps = pipeline.body_capabilities();
    let max_bytes = match caps.request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(BODY_FALLBACK_LIMIT),
        _ => return Ok(Vec::new()),
    };

    // Pingora only calls `request_body_filter` after pre-read when its
    // body-forwarding path remains active. Initial forwarding uses
    // Praxis-owned `pre_read_body`; actual retries still replay from
    // Pingora's fixed retry buffer and are guarded in `handle_connect_failure`.
    session.downstream_session.enable_retry_buffering();

    let mut buffer = BodyBuffer::new(max_bytes);
    let mut all_extra_headers = Vec::new();
    let mut released = false;
    let mut eos_body = None;
    let mut original_body_bytes: u64 = 0;

    loop {
        let chunk = session
            .downstream_session
            .read_request_body()
            .await
            .map_err(PreReadError::Io)?;

        let end_of_stream = chunk.is_none();
        let mut body = chunk;
        let downstream_chunk_len = body.as_ref().map_or(0, bytes::Bytes::len) as u64;

        // Track original downstream bytes before the synthetic EOS
        // body is created. This stays separate from the pipeline's
        // accumulate_body_bytes so the retry guard sees the original
        // size even when a ReadWrite filter shrinks or grows the body.
        original_body_bytes += downstream_chunk_len;

        if let Some(ref b) = body
            && buffer.push(b.clone()).is_err()
        {
            return Err(PreReadError::Rejected(Rejection::status(413)));
        }

        // At EOS, deliver the accumulated body to filters so
        // body writers receive the complete payload — even when
        // a read-only filter returned Release before EOS.
        if end_of_stream {
            body = Some(buffer.freeze());
            buffer = BodyBuffer::new(max_bytes);
        }

        ctx.request_body_bytes = if end_of_stream {
            0
        } else {
            original_body_bytes.saturating_sub(downstream_chunk_len)
        };

        let mut filter_ctx = ctx.build_filter_context(pipeline, request, None);
        let action = pipeline
            .execute_http_request_body(&mut filter_ctx, &mut body, end_of_stream)
            .await;

        ctx.request_body_bytes = original_body_bytes;
        ctx.cluster = filter_ctx.cluster;
        ctx.rewritten_path = filter_ctx.rewritten_path;
        ctx.upstream = filter_ctx.upstream;
        ctx.filter_metadata = filter_ctx.filter_metadata;
        ctx.filter_results = filter_ctx.filter_results;
        all_extra_headers.extend(filter_ctx.extra_request_headers);

        match action {
            Ok(FilterAction::Continue | FilterAction::BodyDone) => {},
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

        if end_of_stream {
            eos_body = body;
            break;
        }
    }

    tracing::debug!("storing pre-read body for forwarding by request_body_filter");
    let forwarded = eos_body.unwrap_or_else(|| buffer.freeze());

    // The retry guard compares max(request_body_bytes, mutated_request_body_len)
    // against Pingora's fixed retry buffer. Keeping the original downstream
    // size here ensures a large original body still prevents retries even
    // when a ReadWrite filter shrinks the forwarded payload.
    ctx.request_body_bytes = original_body_bytes;
    if caps.any_request_body_writer {
        ctx.mutated_request_body_len = Some(forwarded.len());
    }
    if forwarded.is_empty() {
        ctx.pre_read_body = Some(VecDeque::new());
    } else {
        ctx.pre_read_body = Some(VecDeque::from([forwarded]));
    }

    ctx.request_body_released = true;

    Ok(all_extra_headers)
}
