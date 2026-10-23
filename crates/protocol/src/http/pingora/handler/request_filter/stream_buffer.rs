// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! StreamBuffer pre-read logic and TRACE response construction.

use std::{collections::VecDeque, fmt::Write as _};

#[cfg(feature = "pingora")]
use pingora_proxy::Session;
use praxis_core::config::ABSOLUTE_MAX_BODY_BYTES;
use praxis_filter::{
    BodyBuffer, BodyMode, FilterAction, FilterError, FilterPipeline, HttpFilterContext, Rejection, Request,
    TrustedHeaderMutation,
};
use tracing::{debug, warn};

use crate::http::pingora::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

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
#[cfg(feature = "pingora")]
pub(super) fn build_trace_response(session: &Session) -> Rejection {
    let req = session.req_header();
    trace_response_for(&req.method, &req.uri, req.version, &req.headers)
}

/// Build a TRACE echo response from the request line and headers; the
/// backend-neutral core of `build_trace_response`.
pub(in crate::http) fn trace_response_for(
    method: &http::Method,
    uri: &http::Uri,
    version: http::Version,
    headers: &http::HeaderMap,
) -> Rejection {
    let mut body = format!("{method} {uri} {version:?}\r\n");
    for (name, value) in headers {
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
pub(in crate::http) struct PreReadMutations {
    /// Ordered trusted header mutation log.
    pub mutations: Vec<TrustedHeaderMutation>,
}

/// Errors that can occur during body pre-reading in `StreamBuffer` mode.
#[cfg(feature = "pingora")]
pub(super) enum PreReadError {
    /// A filter rejected the request during body processing.
    Rejected(Rejection),

    /// A filter returned an error during body processing.
    Filter(FilterError),

    /// An I/O error from Pingora while reading the body.
    Io(Box<pingora_core::Error>),
}

#[cfg(feature = "pingora")]
impl From<PreReadStop> for PreReadError {
    fn from(stop: PreReadStop) -> Self {
        match stop {
            PreReadStop::Rejected(rejection) => Self::Rejected(rejection),
            PreReadStop::Filter(error) => Self::Filter(error),
        }
    }
}

/// Why a pre-read pass stopped before the body ended.
pub(in crate::http) enum PreReadStop {
    /// A filter rejected the request during body processing.
    Rejected(Rejection),

    /// A filter returned an error during body processing.
    Filter(FilterError),
}

/// Pre-read the request body from the session and run body filters.
///
/// Returns the ordered trusted mutation log emitted by body filters.
/// The accumulated body is stored in `ctx.pre_read_body` for later
/// forwarding by `request_body_filter`.
#[cfg(feature = "pingora")]
pub(super) async fn pre_read_body(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    request: &Request,
) -> Result<PreReadMutations, PreReadError> {
    let Some(mut pass) = PreReadPass::new(pipeline) else {
        return Ok(PreReadMutations { mutations: Vec::new() });
    };

    // Pingora only calls `request_body_filter` after pre-read when its
    // body-forwarding path remains active. Initial forwarding uses
    // Praxis-owned `pre_read_body`; actual retries still replay from
    // Pingora's fixed retry buffer and are guarded in `handle_connect_failure`.
    session.downstream_session.enable_retry_buffering();

    loop {
        let chunk = session
            .downstream_session
            .read_request_body()
            .await
            .map_err(PreReadError::Io)?;
        if pass.feed(pipeline, ctx, request, chunk).await? {
            break;
        }
    }

    Ok(pass.finish(pipeline, ctx))
}

/// One `StreamBuffer` pre-read of a request body: the chunks seen so far
/// and the filters' state across them, fed one downstream chunk at a time.
///
/// The backend-neutral core of `pre_read_body`: a backend reads the body
/// its own way, feeds each chunk (and `None` at the end) to [`feed`], and
/// stores the result with [`finish`].
///
/// [`feed`]: Self::feed
/// [`finish`]: Self::finish
pub(in crate::http) struct PreReadPass {
    /// Accumulated body, frozen and handed to the filters at end of stream.
    buffer: BodyBuffer,

    /// The body the filters left at end of stream.
    eos_body: Option<bytes::Bytes>,

    /// Buffering cap from the pipeline's `StreamBuffer` mode.
    max_bytes: usize,

    /// Ordered trusted header mutations the passes emitted.
    mutation_log: Vec<TrustedHeaderMutation>,

    /// Downstream bytes read so far, before any filter rewrote them.
    original_body_bytes: u64,

    /// Whether a filter released the buffer during pre-read.
    released: bool,
}

impl PreReadPass {
    /// Start a pre-read when the pipeline buffers request bodies in
    /// `StreamBuffer` mode; `None` otherwise.
    pub(in crate::http) fn new(pipeline: &FilterPipeline) -> Option<Self> {
        let BodyMode::StreamBuffer { max_bytes } = pipeline.body_capabilities().request_body_mode else {
            return None;
        };
        let max_bytes = max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES);
        Some(Self {
            buffer: BodyBuffer::new(max_bytes),
            eos_body: None,
            max_bytes,
            mutation_log: Vec::new(),
            original_body_bytes: 0,
            released: false,
        })
    }

    /// Feed the next downstream chunk, `None` at end of stream, through the
    /// request body filters. Returns `true` once the body has ended.
    ///
    /// # Errors
    ///
    /// Returns [`PreReadStop`] when the body outgrows the buffer (a 413) or
    /// a filter rejects or fails.
    #[expect(clippy::too_many_lines, reason = "buffer management orchestration")]
    pub(in crate::http) async fn feed(
        &mut self,
        pipeline: &FilterPipeline,
        ctx: &mut PingoraRequestCtx,
        request: &Request,
        chunk: Option<bytes::Bytes>,
    ) -> Result<bool, PreReadStop> {
        let end_of_stream = chunk.is_none();
        let mut body = chunk;
        let downstream_chunk_len = body.as_ref().map_or(0, bytes::Bytes::len) as u64;

        // Track original downstream bytes before the synthetic EOS
        // body is created. This stays separate from the pipeline's
        // accumulate_body_bytes so the retry guard sees the original
        // size even when a ReadWrite filter shrinks or grows the body.
        self.original_body_bytes += downstream_chunk_len;

        if let Some(chunk) = &body
            && let Err(overflow) = self.buffer.push(chunk.clone())
        {
            ctx.request_body_bytes = self.original_body_bytes;
            warn!(
                status = 413,
                limit = overflow.limit,
                attempted = overflow.attempted,
                "request body exceeds StreamBuffer limit"
            );
            return Err(PreReadStop::Rejected(
                Rejection::status(413)
                    .with_header("content-type", "application/json")
                    .with_body(r#"{"error":"request body too large"}"#),
            ));
        }

        // At EOS, deliver the accumulated body to filters so
        // body writers receive the complete payload — even when
        // a read-only filter returned Release before EOS.
        if end_of_stream {
            let accumulated = std::mem::replace(&mut self.buffer, BodyBuffer::new(self.max_bytes));
            body = Some(accumulated.freeze());
        }

        ctx.request_body_bytes = if end_of_stream {
            0
        } else {
            self.original_body_bytes.saturating_sub(downstream_chunk_len)
        };

        let mut filter_ctx = ctx.build_filter_context(pipeline, request, None);
        // Seed the read-only prior log so this pass's condition evaluation
        // sees headers earlier passes promoted from the body.
        filter_ctx.prior_pre_read_mutations = std::mem::take(&mut self.mutation_log);

        let action = pipeline
            .execute_http_request_body(&mut filter_ctx, &mut body, end_of_stream)
            .await;

        // Restore the prior log (filters never write it) and append this
        // pass's mutations, before the copy-backs partially move filter_ctx.
        self.mutation_log = std::mem::take(&mut filter_ctx.prior_pre_read_mutations);
        if filter_ctx.pre_read_mutations.is_empty() {
            // Fallback for filters that only populate the legacy grouped
            // mutation queues. This preserves their existing remove -> set
            // -> add application order.
            //
            // A pre-read chain must use one mutation mechanism for forwarded
            // header provenance: either the ordered pre_read_mutations log or
            // these legacy grouped queues. Mixing them would make ordering
            // ambiguous, so the ordered log takes precedence when present.
            push_grouped_queues(&filter_ctx, &mut self.mutation_log);
        } else {
            self.mutation_log.extend(filter_ctx.pre_read_mutations);
        }

        ctx.request_body_bytes = self.original_body_bytes;
        ctx.cluster = filter_ctx.cluster;
        ctx.rewritten_path = filter_ctx.rewritten_path;
        ctx.upstream = filter_ctx.upstream;
        ctx.attempted_endpoints = filter_ctx.attempted_endpoints;
        ctx.retry_policy = filter_ctx.retry_policy;
        ctx.route_retry_policy = filter_ctx.route_retry_policy;
        ctx.hedge_policy = filter_ctx.hedge_policy;
        ctx.cluster_retry_state = filter_ctx.cluster_retry_state;
        ctx.cluster_retry_state_released = filter_ctx.cluster_retry_state_released;
        ctx.endpoint_reselector = filter_ctx.endpoint_reselector;
        ctx.extensions = filter_ctx.extensions;
        ctx.filter_metadata = filter_ctx.filter_metadata;
        ctx.filter_state = filter_ctx.filter_state;
        ctx.filter_results = filter_ctx.filter_results;
        ctx.cached_executed_branch_filters = filter_ctx.executed_branch_filters;
        ctx.cached_executed_filter_indices = filter_ctx.executed_filter_indices;
        ctx.cached_body_done_indices = filter_ctx.body_done_indices;
        ctx.structured_metadata = filter_ctx.structured_metadata;

        match action {
            Ok(
                FilterAction::Continue
                | FilterAction::BodyDone
                | FilterAction::TerminalResponse(_)
                | FilterAction::StreamingTerminalResponse(_),
            ) => {},
            Ok(FilterAction::Release) => {
                if !self.released {
                    debug!("StreamBuffer released during pre-read");
                    self.released = true;
                }
            },
            Ok(FilterAction::Reject(rejection)) => {
                return Err(PreReadStop::Rejected(rejection));
            },
            Err(e) => return Err(PreReadStop::Filter(e)),
        }

        if end_of_stream {
            self.eos_body = body;
        }
        Ok(end_of_stream)
    }

    /// Store the pre-read body on `ctx` for forwarding and retry replay,
    /// and return the trusted header mutations the passes emitted.
    pub(in crate::http) fn finish(self, pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) -> PreReadMutations {
        tracing::debug!("storing pre-read body for forwarding by request_body_filter");
        let forwarded = self.eos_body.unwrap_or_else(|| self.buffer.freeze());

        // The retry guard compares max(request_body_bytes, mutated_request_body_len)
        // against Pingora's fixed retry buffer. Keeping the original downstream
        // size here ensures a large original body still prevents retries even
        // when a ReadWrite filter shrinks the forwarded payload.
        ctx.request_body_bytes = self.original_body_bytes;
        let writer_ran = pipeline.body_capabilities().any_request_body_writer;
        let forwarded_len = forwarded.len();
        if writer_ran {
            ctx.mutated_request_body_len = Some(forwarded_len);
        }
        let chunks = if forwarded.is_empty() {
            VecDeque::new()
        } else {
            VecDeque::from([forwarded])
        };
        // A body writer may have changed the forwarded bytes (or their length). The
        // first attempt forwards them from pre_read_body; retries replay from
        // Pingora's fixed buffer (the ORIGINAL bytes). Retain the mutated body so
        // upstream_request_filter can re-seed it per retry, keeping the replayed
        // body matched to the re-stamped Content-Length.
        if writer_ran {
            ctx.retained_pre_read_body = super::body_handling::retry_copy(&chunks, forwarded_len);
        }
        ctx.pre_read_body = Some(chunks);

        ctx.request_body_released = true;

        PreReadMutations {
            mutations: self.mutation_log,
        }
    }
}

/// Append a pre-read context's legacy grouped header queues to `log` as
/// ordered trusted mutations (remove -> set -> add).
///
/// Used only when a pass wrote no ordered `pre_read_mutations`, so the two
/// mechanisms never mix within one pass. Shared with the request-head phase,
/// which captures head-filter mutations with the same precedence.
pub(super) fn push_grouped_queues(filter_ctx: &HttpFilterContext<'_>, log: &mut Vec<TrustedHeaderMutation>) {
    for name in &filter_ctx.request_headers_to_remove {
        log.push(TrustedHeaderMutation::Remove(name.clone()));
    }
    for (name, value) in &filter_ctx.request_headers_to_set {
        log.push(TrustedHeaderMutation::Set(name.clone(), value.clone()));
    }
    for (name, value) in &filter_ctx.extra_request_headers {
        if let (Ok(hname), Ok(_)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            log.push(TrustedHeaderMutation::Add(hname, value.clone()));
        } else {
            warn!(header = %name, "skipping invalid promoted header");
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tracing::instrument::WithSubscriber as _;

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
        #[expect(clippy::wildcard_enum_match_arm, reason = "BodyMode is non_exhaustive")]
        let resolved = match mode {
            BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES),
            _ => 0,
        };
        assert_eq!(resolved, 4096, "explicit max_bytes should be used");
    }

    #[test]
    fn stream_buffer_max_bytes_falls_back_to_absolute_max() {
        let mode = BodyMode::StreamBuffer { max_bytes: None };
        #[expect(clippy::wildcard_enum_match_arm, reason = "BodyMode is non_exhaustive")]
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

    #[tokio::test]
    async fn pre_read_overflow_returns_json_413_and_accounts_for_rejected_chunk()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = limited_pipeline()?;
        let mut pass = PreReadPass::new(&pipeline).ok_or("expected StreamBuffer pre-read")?;
        let mut ctx = PingoraRequestCtx::default();
        let request = post_request();

        let result = pass
            .feed(
                &pipeline,
                &mut ctx,
                &request,
                Some(bytes::Bytes::from_static(b"01234567890")),
            )
            .await;

        let Err(PreReadStop::Rejected(rejection)) = result else {
            return Err("buffer overflow must return a rejection".into());
        };
        assert_eq!(rejection.status, 413, "overflow must retain its client-error status");
        let error: serde_json::Value = serde_json::from_slice(rejection.body.as_deref().ok_or("missing error body")?)?;
        assert_eq!(
            error.get("error").and_then(serde_json::Value::as_str),
            Some("request body too large")
        );
        assert_eq!(
            ctx.request_body_bytes, 11,
            "rejection accounting includes the overflowing chunk"
        );
        drop(ctx);
        assert_eq!(pass.buffer.total_bytes(), 0, "overflowing bytes must not be retained");
        Ok(())
    }

    #[tokio::test]
    async fn pre_read_overflow_logs_warning_with_limit_and_attempted_size()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = limited_pipeline()?;
        let mut pass = PreReadPass::new(&pipeline).ok_or("expected StreamBuffer pre-read")?;
        let mut ctx = PingoraRequestCtx::default();
        let request = post_request();
        let output = tempfile::NamedTempFile::new()?;
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(output.reopen()?)
            .finish();
        let chunk = Some(bytes::Bytes::from_static(b"01234567890"));

        let result = pass
            .feed(&pipeline, &mut ctx, &request, chunk)
            .with_subscriber(subscriber)
            .await;
        drop(ctx);

        assert!(
            matches!(result, Err(PreReadStop::Rejected(_))),
            "overflow must reject the request"
        );
        let log = std::fs::read_to_string(output.path())?;
        assert!(log.contains("WARN") && log.contains("request body exceeds StreamBuffer limit"));
        assert!(log.contains("status=413") && log.contains("limit=10") && log.contains("attempted=11"));
        Ok(())
    }

    #[test]
    fn body_buffer_within_limit_succeeds() {
        let mut buffer = BodyBuffer::new(100);
        let small = bytes::Bytes::from(vec![0_u8; 50]);
        assert!(buffer.push(small).is_ok(), "within-limit push should succeed");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a pipeline with a ten-byte request-body inspection limit.
    fn limited_pipeline() -> Result<FilterPipeline, Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = vec![praxis_filter::FilterEntry {
            name: None,
            branch_chains: None,
            conditions: vec![],
            config: serde_yaml::from_str("field: model\nheader: X-Model\nmax_body_bytes: 10\n")?,
            failure_mode: praxis_core::config::FailureMode::default(),
            filter_type: "json_body_field".into(),
            response_conditions: vec![],
        }];
        FilterPipeline::build(&mut entries, &praxis_filter::FilterRegistry::with_builtins())
    }

    /// Build a POST request for body pre-read tests.
    fn post_request() -> Request {
        Request {
            headers: http::HeaderMap::new(),
            method: http::Method::POST,
            uri: http::Uri::from_static("/"),
        }
    }

    fn is_trace_allowed(name: &str) -> bool {
        TRACE_ALLOWED_HEADERS.contains(&name)
    }
}
