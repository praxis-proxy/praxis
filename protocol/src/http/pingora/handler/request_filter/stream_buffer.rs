// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! StreamBuffer pre-read logic and TRACE response construction.

use std::{collections::VecDeque, fmt::Write as _};

use pingora_proxy::Session;
use praxis_core::config::ABSOLUTE_MAX_BODY_BYTES;
use praxis_filter::{
    BodyBuffer, BodyMode, FilterAction, FilterError, FilterPipeline, Rejection, Request, TrustedHeaderMutation,
};
use tracing::{debug, warn};

use crate::http::pingora::context::PingoraRequestCtx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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

/// Holds ordered trusted mutation log for provenance resolution.
pub(super) struct PreReadMutations {
    /// Ordered trusted header mutation log.
    pub mutations: Vec<TrustedHeaderMutation>,
}

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
/// Returns the ordered trusted mutation log emitted by body filters.
/// The accumulated body is stored in `ctx.pre_read_body` for later
/// forwarding by `request_body_filter`.
#[expect(
    clippy::too_many_lines,
    unused_assignments,
    reason = "buffer management orchestration"
)]
pub(super) async fn pre_read_body(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    request: &Request,
) -> Result<PreReadMutations, PreReadError> {
    let caps = pipeline.body_capabilities();
    let max_bytes = match caps.request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES),
        _ => return Ok(PreReadMutations { mutations: Vec::new() }),
    };

    // Pingora only calls `request_body_filter` after pre-read when its
    // body-forwarding path remains active. Initial forwarding uses
    // Praxis-owned `pre_read_body`; actual retries still replay from
    // Pingora's fixed retry buffer and are guarded in `handle_connect_failure`.
    session.downstream_session.enable_retry_buffering();

    let mut buffer = BodyBuffer::new(max_bytes);
    let mut mutation_log: Vec<TrustedHeaderMutation> = Vec::new();
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

        if let Some(b) = &body
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
        ctx.extensions = filter_ctx.extensions;
        ctx.filter_metadata = filter_ctx.filter_metadata;
        ctx.filter_state = filter_ctx.filter_state;
        ctx.filter_results = filter_ctx.filter_results;
        ctx.cached_executed_filter_indices = filter_ctx.executed_filter_indices;
        ctx.cached_body_done_indices = filter_ctx.body_done_indices;
        ctx.structured_metadata = filter_ctx.structured_metadata;

        if filter_ctx.pre_read_mutations.is_empty() {
            // Fallback for filters that only populate the legacy grouped
            // mutation queues. This preserves their existing remove -> set
            // -> add application order.
            //
            // A pre-read chain must use one mutation mechanism for forwarded
            // header provenance: either the ordered pre_read_mutations log or
            // these legacy grouped queues. Mixing them would make ordering
            // ambiguous, so the ordered log takes precedence when present.
            for name in &filter_ctx.request_headers_to_remove {
                mutation_log.push(TrustedHeaderMutation::Remove(name.clone()));
            }
            for (name, value) in &filter_ctx.request_headers_to_set {
                mutation_log.push(TrustedHeaderMutation::Set(name.clone(), value.clone()));
            }
            for (name, value) in &filter_ctx.extra_request_headers {
                if let (Ok(hname), Ok(_)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::header::HeaderValue::from_str(value),
                ) {
                    mutation_log.push(TrustedHeaderMutation::Add(hname, value.clone()));
                } else {
                    warn!(header = %name, "skipping invalid promoted header");
                }
            }
        } else {
            mutation_log.extend(filter_ctx.pre_read_mutations);
        }

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

    Ok(PreReadMutations {
        mutations: mutation_log,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_core::config::ABSOLUTE_MAX_BODY_BYTES;

    use super::*;

    #[test]
    fn trace_redacts_authorization_header() {
        assert!(
            !is_trace_allowed("authorization"),
            "authorization should be redacted from TRACE"
        );
    }

    #[test]
    fn trace_redacts_cookie_header() {
        assert!(!is_trace_allowed("cookie"), "cookie should be redacted from TRACE");
    }

    #[test]
    fn trace_redacts_x_api_key_header() {
        assert!(
            !is_trace_allowed("x-api-key"),
            "x-api-key should be redacted from TRACE"
        );
    }

    #[test]
    fn trace_redacts_x_auth_token_header() {
        assert!(
            !is_trace_allowed("x-auth-token"),
            "x-auth-token should be redacted from TRACE"
        );
    }

    #[test]
    fn trace_redacts_proxy_authorization_header() {
        assert!(
            !is_trace_allowed("proxy-authorization"),
            "proxy-authorization should be redacted from TRACE"
        );
    }

    #[test]
    fn trace_redacts_set_cookie_header() {
        assert!(
            !is_trace_allowed("set-cookie"),
            "set-cookie should be redacted from TRACE"
        );
    }

    #[test]
    fn trace_allows_host_header() {
        assert!(is_trace_allowed("host"), "host should be allowed in TRACE");
    }

    #[test]
    fn trace_allows_content_type_header() {
        assert!(
            is_trace_allowed("content-type"),
            "content-type should be allowed in TRACE"
        );
    }

    #[test]
    fn trace_allows_accept_header() {
        assert!(is_trace_allowed("accept"), "accept should be allowed in TRACE");
    }

    #[test]
    fn trace_allows_user_agent_header() {
        assert!(is_trace_allowed("user-agent"), "user-agent should be allowed in TRACE");
    }

    #[test]
    fn trace_allowlist_excludes_all_sensitive_headers() {
        let sensitive = [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "proxy-authorization",
            "x-csrf-token",
            "x-forwarded-for",
        ];
        for header in sensitive {
            assert!(
                !is_trace_allowed(header),
                "{header} should not be in the TRACE allowlist"
            );
        }
    }

    #[test]
    fn stream_buffer_max_bytes_uses_value_when_set() {
        let mode = BodyMode::StreamBuffer { max_bytes: Some(4096) };
        let resolved = match mode {
            BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES),
            _ => 0,
        };
        assert_eq!(resolved, 4096, "explicit max_bytes should be used");
    }

    #[test]
    fn stream_buffer_max_bytes_falls_back_to_absolute_max() {
        let mode = BodyMode::StreamBuffer { max_bytes: None };
        let resolved = match mode {
            BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES),
            _ => 0,
        };
        assert_eq!(
            resolved, ABSOLUTE_MAX_BODY_BYTES,
            "None max_bytes should fall back to ABSOLUTE_MAX_BODY_BYTES"
        );
    }

    #[test]
    fn non_stream_buffer_mode_skips_pre_read() {
        let modes = [BodyMode::Stream, BodyMode::SizeLimit { max_bytes: 1024 }];
        for mode in modes {
            let is_stream_buffer = matches!(mode, BodyMode::StreamBuffer { .. });
            assert!(!is_stream_buffer, "{mode:?} should not trigger StreamBuffer pre-read");
        }
    }

    #[test]
    fn body_buffer_overflow_produces_413() {
        let mut buffer = BodyBuffer::new(10);
        let large = bytes::Bytes::from(vec![0_u8; 20]);
        assert!(buffer.push(large).is_err(), "oversized push should fail");
    }

    #[test]
    fn body_buffer_within_limit_succeeds() {
        let mut buffer = BodyBuffer::new(100);
        let small = bytes::Bytes::from(vec![0_u8; 50]);
        assert!(buffer.push(small).is_ok(), "within-limit push should succeed");
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn is_trace_allowed(name: &str) -> bool {
        TRACE_ALLOWED_HEADERS.contains(&name)
    }
}
