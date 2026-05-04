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

/// Headers redacted from TRACE echo responses to prevent credential leakage.
const TRACE_REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
];

// -----------------------------------------------------------------------------
// TRACE Response
// -----------------------------------------------------------------------------

/// Build a TRACE echo response containing the request headers as the body.
///
/// Per [RFC 9110 Section 9.3.8], a TRACE response echoes the request
/// message with content-type `message/http`.
///
/// [RFC 9110 Section 9.3.8]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.8
pub(super) fn build_trace_response(session: &Session) -> Rejection {
    let req = session.req_header();
    let mut body = format!("{} {} {:?}\r\n", req.method, req.uri, req.version);
    for (name, value) in &req.headers {
        if TRACE_REDACTED_HEADERS.contains(&name.as_str()) {
            tracing::debug!(header = %name, "redacting sensitive header from TRACE response");
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
    // Config validation enforces reasonable limits on `max_bytes`.
    // `usize::MAX` here means "no limit at this layer"; the
    // configured cap (or its absence) was already validated.
    let max_bytes = match caps.request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(usize::MAX),
        _ => return Ok(Vec::new()),
    };

    // Enable retry buffering so Pingora's body forwarding loop can
    // replay the consumed body via `get_retry_buffer()`. Without this,
    // `is_body_done()` returns true after pre-read and Pingora never
    // calls `request_body_filter`, leaving the pre-read body stranded.
    //
    // Limitation: Pingora's retry buffer is capped at 64 KiB
    // (`BODY_BUF_LIMIT` in pingora-core). Bodies exceeding that limit
    // are silently truncated and will not be forwarded to upstream.
    // Tracked for an upstream fix: https://github.com/praxis-proxy/praxis/issues/75
    session.downstream_session.enable_retry_buffering();

    let mut buffer = BodyBuffer::new(max_bytes);
    let mut all_extra_headers = Vec::new();
    let mut released = false;
    let mut eos_body = None;

    loop {
        let chunk = session
            .downstream_session
            .read_request_body()
            .await
            .map_err(PreReadError::Io)?;

        let end_of_stream = chunk.is_none();
        let mut body = chunk;

        if !released
            && let Some(ref b) = body
            && buffer.push(b.clone()).is_err()
        {
            return Err(PreReadError::Rejected(Rejection::status(413)));
        }

        // At EOS, deliver the accumulated body to filters so they
        // can inspect or transform the complete payload.
        if end_of_stream && !released {
            body = Some(buffer.freeze());
            buffer = BodyBuffer::new(max_bytes);
        }

        let mut filter_ctx = ctx.build_filter_context(pipeline, request, None);
        let action = pipeline
            .execute_http_request_body(&mut filter_ctx, &mut body, end_of_stream)
            .await;

        ctx.request_body_bytes = filter_ctx.request_body_bytes;
        ctx.cluster = filter_ctx.cluster;
        ctx.upstream = filter_ctx.upstream;
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
    if forwarded.is_empty() {
        ctx.pre_read_body = Some(VecDeque::new());
    } else {
        ctx.pre_read_body = Some(VecDeque::from([forwarded]));
    }

    ctx.request_body_released = true;

    Ok(all_extra_headers)
}
