// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! StreamBuffer pre-read logic and TRACE response construction.

use std::{collections::VecDeque, fmt::Write as _};

#[cfg(feature = "pingora")]
use pingora_proxy::Session;
#[cfg(test)]
use praxis_core::config::DEFAULT_MAX_BUFFER_BYTES;
use praxis_filter::{
    BodyBuffer, BodyMode, FilterAction, FilterError, FilterPipeline, HttpFilterContext, Rejection, Request,
    TrustedHeaderMutation,
};
use tracing::{debug, warn};

use crate::http::{
    body_limit::{BodyLimitPhase, body_limit_rejection},
    pingora::context::PingoraRequestCtx,
};

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
        let max_bytes = max_bytes
            .unwrap_or_else(|| pipeline.buffer_cap())
            .min(pipeline.buffer_cap());
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
        let downstream_chunk_len = u64::try_from(body.as_ref().map_or(0, bytes::Bytes::len)).unwrap_or(u64::MAX);

        // Track original downstream bytes before the synthetic EOS
        // body is created. This stays separate from the pipeline's
        // accumulate_body_bytes so the retry guard sees the original
        // size even when a ReadWrite filter shrinks or grows the body.
        self.original_body_bytes = self.original_body_bytes.saturating_add(downstream_chunk_len);

        if let Some(chunk) = &body
            && let Err(overflow) = self.buffer.push(chunk.clone())
        {
            ctx.request_body_bytes = self.original_body_bytes;
            return Err(PreReadStop::Rejected(body_limit_rejection(
                overflow.limit,
                u64::try_from(overflow.attempted).unwrap_or(u64::MAX),
                BodyLimitPhase::PreRead,
            )));
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
                praxis_filter::cancel_bandwidth(&mut ctx.extensions);
                return Err(PreReadStop::Rejected(rejection));
            },
            Err(e) => {
                praxis_filter::cancel_bandwidth(&mut ctx.extensions);
                return Err(PreReadStop::Filter(e));
            },
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::type_complexity,
    clippy::significant_drop_tightening,
    reason = "generated state-machine fixtures"
)]
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
            BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(DEFAULT_MAX_BUFFER_BYTES),
            _ => 0,
        };
        assert_eq!(resolved, 4096, "explicit max_bytes should be used");
    }

    #[test]
    fn stream_buffer_max_bytes_falls_back_to_absolute_max() {
        let mode = BodyMode::StreamBuffer { max_bytes: None };
        #[expect(clippy::wildcard_enum_match_arm, reason = "BodyMode is non_exhaustive")]
        let resolved = match mode {
            BodyMode::StreamBuffer { max_bytes } => max_bytes.unwrap_or(DEFAULT_MAX_BUFFER_BYTES),
            _ => 0,
        };
        assert_eq!(
            resolved, DEFAULT_MAX_BUFFER_BYTES,
            "None max_bytes should fall back to DEFAULT_MAX_BUFFER_BYTES"
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
    async fn generated_pre_read_partitions_preserve_release_and_single_drain() {
        use std::sync::{Arc, Mutex};

        use praxis_filter::{BodyAccess, FilterFactory, FilterRegistry, HttpFilter};

        for size in 0..=9 {
            for width in [1, 2, 3, 9] {
                let seen = Arc::new(Mutex::new(Vec::new()));
                let mut registry = FilterRegistry::with_builtins();
                registry
                    .register(
                        "release_test",
                        FilterFactory::Http(Arc::new(|_| Ok(Box::new(ReleaseTest)))),
                    )
                    .unwrap();
                let captured = Arc::clone(&seen);
                registry
                    .register(
                        "rewrite_test",
                        FilterFactory::Http(Arc::new(move |_| Ok(Box::new(RewriteTest(Arc::clone(&captured)))))),
                    )
                    .unwrap();
                let mut entries: Vec<praxis_filter::FilterEntry> =
                    serde_yaml::from_str("- filter: release_test\n- filter: rewrite_test\n").unwrap();
                let mut pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
                pipeline.apply_body_limits(Some(8), None, false).unwrap();
                let mut pass = PreReadPass::new(&pipeline).unwrap();
                let mut ctx = PingoraRequestCtx::default();
                let request = post_request();
                let bytes: Vec<_> = (0..size).map(|index| b'a' + u8::try_from(index).unwrap()).collect();
                assert!(matches!(
                    pass.feed(&pipeline, &mut ctx, &request, Some(bytes::Bytes::new()))
                        .await,
                    Ok(false)
                ));
                let mut rejected = false;
                for chunk in bytes.chunks(width) {
                    match pass
                        .feed(
                            &pipeline,
                            &mut ctx,
                            &request,
                            Some(bytes::Bytes::copy_from_slice(chunk)),
                        )
                        .await
                    {
                        Ok(false) => {},
                        Err(PreReadStop::Rejected(rejection)) => {
                            assert_eq!(rejection.status, 413);
                            rejected = true;
                            break;
                        },
                        _ => panic!("unexpected pre-read outcome"),
                    }
                }
                assert_eq!(rejected, size > 8, "size={size}, width={width}");
                if rejected {
                    continue;
                }
                assert!(matches!(pass.feed(&pipeline, &mut ctx, &request, None).await, Ok(true)));
                assert_eq!(ctx.request_body_bytes, u64::try_from(size).unwrap());
                let calls = seen.lock().unwrap().clone();
                assert_eq!(
                    calls.last(),
                    Some(&(true, bytes.clone())),
                    "writer sees the complete original body at EOS"
                );
                let mutations = pass.finish(&pipeline, &mut ctx);
                assert_eq!(mutations.mutations.len(), 1);
                assert_eq!(ctx.mutated_request_body_len, Some(size));
                let mut forwarded = Some(bytes::Bytes::from_static(b"stale"));
                assert!(
                    super::super::super::request_body_filter::run_request_body(
                        &pipeline,
                        &mut forwarded,
                        false,
                        &mut ctx
                    )
                    .await
                    .is_ok()
                );
                assert_eq!(
                    forwarded.unwrap_or_default(),
                    bytes::Bytes::from(bytes.to_ascii_uppercase())
                );
                assert_eq!(*seen.lock().unwrap(), calls, "draining does not rerun hooks");
            }
        }

        struct ReleaseTest;
        #[async_trait::async_trait]
        impl HttpFilter for ReleaseTest {
            fn name(&self) -> &'static str {
                "release_test"
            }

            async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::StreamBuffer { max_bytes: Some(8) }
            }

            async fn on_request_body(
                &self,
                _: &mut HttpFilterContext<'_>,
                _: &mut Option<bytes::Bytes>,
                _: bool,
            ) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Release)
            }
        }
        struct RewriteTest(Arc<Mutex<Vec<(bool, Vec<u8>)>>>);
        #[async_trait::async_trait]
        impl HttpFilter for RewriteTest {
            fn name(&self) -> &'static str {
                "rewrite_test"
            }

            async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
            }

            async fn on_request_body(
                &self,
                ctx: &mut HttpFilterContext<'_>,
                body: &mut Option<bytes::Bytes>,
                end_of_stream: bool,
            ) -> Result<FilterAction, FilterError> {
                let input = body.as_deref().unwrap_or_default();
                self.0.lock().unwrap().push((end_of_stream, input.to_vec()));
                if end_of_stream {
                    *body = Some(bytes::Bytes::from(input.to_ascii_uppercase()));
                    ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
                        http::header::HeaderName::from_static("x-praxis-probe"),
                        http::HeaderValue::from_static("done"),
                    ));
                }
                Ok(FilterAction::Continue)
            }
        }
    }

    #[tokio::test]
    async fn cancelling_suspended_pre_read_drops_body_and_filter_state() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use praxis_filter::{BodyAccess, FilterFactory, FilterRegistry, HttpFilter};
        use tokio::sync::Notify;

        let entered = Arc::new(Notify::new());
        let drops = Arc::new(AtomicUsize::new(0));
        let mut registry = FilterRegistry::with_builtins();
        let probe_entered = Arc::clone(&entered);
        let probe_drops = Arc::clone(&drops);
        registry
            .register(
                "pending_test",
                FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(PendingTest {
                        entered: Arc::clone(&probe_entered),
                        drops: Arc::clone(&probe_drops),
                    }))
                })),
            )
            .unwrap();
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str("- filter: pending_test").unwrap();
        let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
        let mut pass = PreReadPass::new(&pipeline).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        let request = post_request();
        let owner: Arc<[u8]> = vec![b'x'; 4].into();
        let chunk = bytes::Bytes::from_owner(Arc::clone(&owner));
        let mut call = Box::pin(pass.feed(&pipeline, &mut ctx, &request, Some(chunk)));
        tokio::select! {
            _ = &mut call => panic!("hook must stay suspended"),
            () = entered.notified() => {},
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(call);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "future owns the suspended filter state"
        );
        assert_eq!(Arc::strong_count(&owner), 1, "cancelled input owner is released");
        drop(pass);
        drop(ctx);
        let fresh = PingoraRequestCtx::default();
        assert!(fresh.filter_state.is_empty());
        assert_eq!(fresh.request_body_bytes, 0);

        struct DropProbe(Arc<AtomicUsize>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct PendingTest {
            entered: Arc<Notify>,
            drops: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl HttpFilter for PendingTest {
            fn name(&self) -> &'static str {
                "pending_test"
            }

            async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::StreamBuffer { max_bytes: Some(8) }
            }

            async fn on_request_body(
                &self,
                ctx: &mut HttpFilterContext<'_>,
                _: &mut Option<bytes::Bytes>,
                _: bool,
            ) -> Result<FilterAction, FilterError> {
                ctx.filter_state.insert(0, Box::new(DropProbe(Arc::clone(&self.drops))));
                self.entered.notify_one();
                std::future::pending::<()>().await;
                Ok(FilterAction::Continue)
            }
        }
    }

    #[tokio::test]
    async fn dropping_frozen_pre_read_releases_writer_owned_body() {
        use std::sync::Arc;

        use praxis_filter::{BodyAccess, FilterFactory, FilterRegistry, HttpFilter};

        let owner: Arc<[u8]> = Vec::from(b"REWRITE".as_slice()).into();
        let mut registry = FilterRegistry::with_builtins();
        let factory_owner = Arc::clone(&owner);
        registry
            .register(
                "owner_writer",
                FilterFactory::Http(Arc::new(move |_| Ok(Box::new(OwnerWriter(Arc::clone(&factory_owner)))))),
            )
            .unwrap();
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str("- filter: owner_writer").unwrap();
        let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
        drop(registry);
        assert_eq!(
            Arc::strong_count(&owner),
            2,
            "test and installed filter own the backing"
        );
        let mut pass = PreReadPass::new(&pipeline).unwrap();
        let mut ctx = PingoraRequestCtx::default();
        let request = post_request();
        assert!(matches!(
            pass.feed(&pipeline, &mut ctx, &request, Some(bytes::Bytes::from_static(b"ab")))
                .await,
            Ok(false)
        ));
        assert!(matches!(pass.feed(&pipeline, &mut ctx, &request, None).await, Ok(true)));
        assert_eq!(Arc::strong_count(&owner), 3, "frozen output owns the backing");
        let _mutations = pass.finish(&pipeline, &mut ctx);
        assert_eq!(ctx.mutated_request_body_len, Some(owner.len()));
        assert_eq!(
            Arc::strong_count(&owner),
            3,
            "direct and replay views share one output owner"
        );
        drop(ctx);
        assert_eq!(
            Arc::strong_count(&owner),
            2,
            "request cancellation drops its retained output"
        );
        drop(pipeline);
        assert_eq!(Arc::strong_count(&owner), 1);

        struct OwnerWriter(Arc<[u8]>);
        #[async_trait::async_trait]
        impl HttpFilter for OwnerWriter {
            fn name(&self) -> &'static str {
                "owner_writer"
            }

            async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
                Ok(FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
            }

            fn request_body_mode(&self) -> BodyMode {
                BodyMode::StreamBuffer { max_bytes: Some(8) }
            }

            async fn on_request_body(
                &self,
                _: &mut HttpFilterContext<'_>,
                body: &mut Option<bytes::Bytes>,
                end_of_stream: bool,
            ) -> Result<FilterAction, FilterError> {
                if end_of_stream {
                    *body = Some(bytes::Bytes::from_owner(Arc::clone(&self.0)));
                }
                Ok(FilterAction::Continue)
            }
        }
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
        assert!(log.contains("WARN") && log.contains("request body exceeds configured limit"));
        assert!(log.contains("status=413") && log.contains("limit=10") && log.contains("attempted=11"));
        assert!(log.contains("bytes_seen=11") && log.contains("phase=PreRead"));
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
