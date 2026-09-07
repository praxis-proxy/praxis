// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reusable execution of a filtered HTTP sub-request.
//!
//! [`FilteredSubrequestExecutor`] runs a single named filter pipeline against a
//! sub-request and returns owned continuation state: it reconstructs a nested
//! [`HttpFilterContext`](crate::HttpFilterContext), runs the request, request-body,
//! response, and (for buffered responses) response-body phases, applies the same
//! forwarding boundary as the normal upstream path, dispatches the transport in
//! either buffered or streaming mode, and captures a
//! [`FilteredSubrequestContinuation`] the caller drives to completion.
//!
//! The executor owns three transient extension mechanisms end-to-end —
//! [`RetainedFilterResults`], [`PendingStreamChunks`], and
//! [`StreamTermination`] — and recognizes one framework-defined caller-staged
//! channel, [`PendingCredentials`]: it drains that channel and materializes each
//! authority-bound secret only after resolving the destination (see
//! [`DeferredCredential`](crate::DeferredCredential)). It otherwise never
//! inspects caller-injected extension types. Callers that stash their own state
//! in the request extensions recover it from
//! [`FilteredSubrequestError::into_parts`],
//! [`FilteredSubrequestContinuation::into_parent_extensions`], or
//! [`FilteredSubrequestContinuation::into_completion`], and strip it themselves.
//!
//! Retained-state accounting is delegated to the caller through the
//! [`RetainedStateAccounting`] hook so the executor stays independent of any
//! particular caller's state layout while still enforcing a ceiling at every
//! phase boundary.

mod context;
mod continuation;
mod sanitize;
mod streaming;
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;
mod transport;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::HeaderMap;
use praxis_core::subrequest::{FrameworkHeaders, StreamLimits, SubResponseBody};
use tracing::{Instrument as _, warn};

use self::{
    context::{SubrequestRuntimeResources, build_sub_filter_context},
    sanitize::{
        apply_pre_read_header_mutations, apply_request_header_mutations, body_exceeds_limit, ensure_destination_host,
        response_body_exceeds_limits, sanitize_subrequest_headers, sanitize_subresponse_headers, set_authority_host,
        streaming_transport_limit, strip_reserved_headers, subresponse_from_rejection,
    },
    transport::{build_peer, classify_transport_failure, stream_termination_cause},
};
pub(crate) use self::{
    continuation::{FilteredSubrequestContinuation, SubrequestCompletion},
    sanitize::normalize_response_status,
    streaming::{CalloutStreamingBody, FilteredStreamingBody},
};
use crate::{
    FilterAction, FilterError, FilterPipeline, StreamTermination, StreamTerminationCause, SubRequest,
    SubRequestResponseMode, SubResponse,
    actions::Rejection,
    context::PendingStreamChunks,
    credentials::{PendingCredentials, ResolvedDestination},
    extensions::RequestExtensions,
    results::RetainedFilterResults,
};

/// Idle timeout applied to a streaming sub-request transport.
///
/// The absolute per-step deadline still bounds total duration; this only
/// caps the gap between upstream chunks so a stalled source is abandoned.
pub(crate) const STREAMING_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Caller-supplied accounting for retained sub-request state.
///
/// The executor enforces a ceiling on caller-owned retained state at every
/// phase boundary without knowing how that state is represented. Callers
/// implement this to report, from the live request extensions, whether their
/// retained footprint currently exceeds the limit.
pub(crate) trait RetainedStateAccounting {
    /// Whether the caller-owned retained state currently exceeds its ceiling.
    fn exceeds_limit(&self, extensions: &RequestExtensions) -> bool;
}

/// Where a captured sub-response originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseOrigin {
    /// A real upstream produced the response.
    Upstream,
    /// A nested filter produced the response locally.
    Local,
    /// A transport failure was synthesized into a response.
    Transport,
}

/// Transport failure classification used to synthesize a gateway response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportFailure {
    /// Admission control timed out before dispatch.
    AdmissionTimeout,
    /// The circuit breaker was open.
    CircuitOpen,
    /// The connection could not be established.
    Connect,
    /// A generic I/O failure occurred.
    Io,
    /// The transport deadline was exceeded.
    DeadlineExceeded,
    /// The response exceeded the configured size limit.
    ResponseTooLarge,
}

/// Owned downstream request attributes carried into a filtered sub-request.
///
/// A chain-binding callout builds this from its request context so the nested
/// pipeline sees the real client identity, transport security, and request
/// clock — the inputs security and observability filters in an outbound chain
/// depend on.
#[derive(Clone)]
pub struct SubrequestRuntime {
    /// Original downstream client address.
    pub(crate) client_addr: Option<std::net::IpAddr>,
    /// Whether the original downstream uses TLS.
    pub(crate) downstream_tls: bool,
    /// Verified downstream peer identity.
    pub(crate) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
    /// Start time of the logical client request.
    pub(crate) request_start: Instant,
}

impl SubrequestRuntime {
    /// Capture the downstream attributes to forward into a filtered sub-request.
    ///
    /// `client_addr`, `downstream_tls`, and `peer_identity` come from the
    /// originating client connection; `request_start` is the instant the logical
    /// client request began, used for consistent duration accounting across the
    /// sub-request.
    #[must_use]
    pub fn new(
        client_addr: Option<std::net::IpAddr>,
        downstream_tls: bool,
        peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
        request_start: Instant,
    ) -> Self {
        Self {
            client_addr,
            downstream_tls,
            peer_identity,
            request_start,
        }
    }
}

/// A captured sub-response together with its origin classification.
pub(crate) struct SubrequestOutcome {
    /// The buffered or header-only response.
    pub(crate) response: SubResponse,
    /// Where the response came from.
    pub(crate) origin: ResponseOrigin,
    /// Transport failure detail, when the response was synthesized.
    pub(crate) transport_error: Option<TransportFailure>,
}

/// Transport/body shape selected by the sub-request's filters.
pub(crate) enum OpenedResponse {
    /// The complete response was collected and filtered.
    Complete(SubrequestOutcome),
    /// Response headers are filtered; body remains pull-based.
    Streaming {
        /// Live upstream response body.
        body: Box<SubResponseBody>,
        /// Header-time transition metadata.
        outcome: SubrequestOutcome,
    },
}

/// One opened sub-request, including state needed for body/completion processing.
pub(crate) struct OpenedSubrequest {
    /// Owned filter lifecycle state.
    pub(crate) continuation: FilteredSubrequestContinuation,
    /// Buffered or pull-based response source.
    pub(crate) kind: OpenedResponse,
}

/// A sub-request error together with the caller extensions it borrowed.
pub(crate) struct FilteredSubrequestError {
    /// Underlying filter or lifecycle error.
    error: FilterError,
    /// Caller-owned extensions recovered from the nested filter context.
    extensions: RequestExtensions,
}

impl FilteredSubrequestError {
    /// Build an error before a nested filter context exists.
    fn new(error: FilterError, extensions: RequestExtensions) -> Self {
        Self { error, extensions }
    }

    /// Recover caller-owned extensions from a failed nested context.
    ///
    /// Only the executor-owned mechanisms are stripped; caller-injected
    /// extension types remain for the caller to remove before returning them
    /// to the parent request context.
    fn capture(error: FilterError, ctx: &mut crate::HttpFilterContext<'_>) -> Self {
        ctx.extensions.remove::<PendingStreamChunks>();
        ctx.extensions.remove::<RetainedFilterResults>();
        ctx.extensions.remove::<StreamTermination>();
        Self::new(error, std::mem::take(&mut ctx.extensions))
    }

    /// Split the error from the extensions its caller must restore.
    pub(crate) fn into_parts(self) -> (FilterError, RequestExtensions) {
        (self.error, self.extensions)
    }
}

/// Internal result before owned continuation state is captured.
enum RawResponse {
    /// Complete buffered or synthetic response.
    Complete(SubrequestOutcome),
    /// Local filter rejection.
    Rejected(Rejection),
    /// Open pull-based upstream response.
    Streaming {
        /// Live upstream response body.
        body: Box<SubResponseBody>,
        /// Header-time transition metadata.
        outcome: SubrequestOutcome,
    },
}

/// One sub-request to execute against a named step pipeline.
pub(crate) struct FilteredSubrequestInput<'a> {
    /// Pre-built pipeline for this step.
    pub(crate) pipeline: &'a Arc<FilterPipeline>,
    /// The sub-request to dispatch.
    pub(crate) request: &'a SubRequest,
    /// Human-readable step label for tracing and error messages.
    pub(crate) label: &'a str,
    /// Zero-based iteration index for tracing.
    pub(crate) iteration: u32,
    /// Absolute overall deadline shared across the logical request.
    pub(crate) deadline: Instant,
    /// Caller-provided request extensions, moved into the nested context.
    pub(crate) extensions: RequestExtensions,
}

/// The response an outbound chain produced for a callout.
///
/// The outbound chain — not the calling method — decides whether the response
/// is delivered whole or streamed, by whether a filter selects a streaming
/// sub-request response. [`run`](FilteredSubrequestExecutor::run) surfaces that
/// choice so the caller handles each shape explicitly, mirroring the epic's
/// "one buffered or streaming subrequest" contract.
pub enum CalloutResponse {
    /// The complete response, fully filtered through the response-body phase.
    Buffered(SubResponse),
    /// Transition-time headers now, with the body pulled through the outbound
    /// chain's response-body filters as it flows.
    Streaming {
        /// Status and headers after the response-header phase; the body field
        /// is empty because the payload is delivered through `body`.
        response: SubResponse,
        /// Pull-based response body. Each [`next_chunk`] applies the outbound
        /// chain's response-body filters and, after upstream EOF, flushes any
        /// completion output the chain emits before yielding `None`. An
        /// upstream failure the chain did not convert into a valid terminal
        /// sequence surfaces as an error after buffered chunks drain.
        ///
        /// [`next_chunk`]: crate::StreamingResponseBody::next_chunk
        body: Box<dyn crate::StreamingResponseBody>,
    },
}

/// No-op retained-state accounting for callers that keep no cross-sub-request
/// state, so the callout entry point never has to expose the
/// [`RetainedStateAccounting`] hook.
struct NoRetainedState;

impl RetainedStateAccounting for NoRetainedState {
    fn exceeds_limit(&self, _extensions: &RequestExtensions) -> bool {
        false
    }
}

/// Executes exactly one filtered sub-request and returns owned continuation state.
pub struct FilteredSubrequestExecutor {
    /// Caller-supplied retained-state ceiling accounting.
    accounting: Box<dyn RetainedStateAccounting + Send + Sync>,
    /// Shared transport client.
    client: praxis_core::subrequest::SubRequestClient,
    /// Nested depth forwarded to sub-requests.
    depth: u8,
    /// Owned downstream request attributes.
    downstream: SubrequestRuntime,
    /// Per-step buffered response ceiling.
    max_response_bytes: usize,
    /// Retained-state raw byte ceiling for stream chunk emission.
    max_state_bytes: usize,
    /// Per-step duration ceiling.
    step_timeout: Duration,
}

impl FilteredSubrequestExecutor {
    /// Build an executor for one logical filtered-sub-request sequence.
    #[expect(
        clippy::too_many_arguments,
        reason = "executor owns explicit subrequest limits and resources"
    )]
    pub(crate) fn new(
        accounting: Box<dyn RetainedStateAccounting + Send + Sync>,
        client: praxis_core::subrequest::SubRequestClient,
        depth: u8,
        downstream: SubrequestRuntime,
        max_response_bytes: usize,
        max_state_bytes: usize,
        step_timeout: Duration,
    ) -> Self {
        Self {
            accounting,
            client,
            depth,
            downstream,
            max_response_bytes,
            max_state_bytes,
            step_timeout,
        }
    }

    /// Build an executor for an application callout that runs a single bound
    /// outbound chain and keeps no cross-sub-request retained state.
    ///
    /// This is the small constructor a chain-binding filter (for example an AI
    /// provider callout) uses together with [`run`]. `client` is the
    /// shared sub-request transport (available from
    /// `HttpFilterContext::subrequest_client`); `downstream` carries the
    /// originating client attributes; `depth` is the current sub-request nesting
    /// depth; `max_response_bytes` caps the response (the buffered body, or the
    /// cumulative bytes emitted by a streaming body); `step_timeout` bounds the
    /// sub-request's own duration within the caller's deadline.
    ///
    /// [`run`]: Self::run
    #[must_use]
    pub fn for_callout(
        client: praxis_core::subrequest::SubRequestClient,
        downstream: SubrequestRuntime,
        depth: u8,
        max_response_bytes: usize,
        step_timeout: Duration,
    ) -> Self {
        // A callout retains no state across sub-requests, so the response ceiling
        // doubles as the stream-chunk emission ceiling.
        Self::new(
            Box::new(NoRetainedState),
            client,
            depth,
            downstream,
            max_response_bytes,
            max_response_bytes,
            step_timeout,
        )
    }

    /// Run `request` through `pipeline` as a filtered sub-request and return the
    /// response the outbound chain produced — buffered or streaming.
    ///
    /// This is the deliberately small entry point for application callout
    /// filters that bound an outbound chain via
    /// [`ChainBindingContext::bind_chain`]. It runs the request, request-body,
    /// response, and (for buffered responses) response-body phases; enforces the
    /// resolved destination authority, DNS/SSRF, TLS/SNI, Host, deadline, and
    /// transport limits; and materializes any staged [`PendingCredentials`] only
    /// after the destination is resolved. `extensions` is the caller-staged
    /// projection moved into the isolated child context.
    ///
    /// The outbound chain decides the response shape: a filter that selects a
    /// streaming sub-request response yields [`CalloutResponse::Streaming`] with
    /// the transition-time headers and a pull-based body that keeps applying the
    /// chain's response-body filters as chunks flow; otherwise the fully
    /// filtered response is returned as [`CalloutResponse::Buffered`].
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if a filter phase errors or the deadline is
    /// exceeded before the response transition. For a streaming response, errors
    /// that occur while pulling the body surface from
    /// [`StreamingResponseBody::next_chunk`](crate::StreamingResponseBody::next_chunk)
    /// instead.
    ///
    /// # Examples
    ///
    /// A callout drives its prebuilt outbound chain to a response. In production
    /// the pipeline comes from [`ChainBindingContext::bind_chain`] at
    /// construction and the shared client from the filter's
    /// [`HttpFilterContext`]; here both are built directly so the example runs,
    /// and a `static_response` filter answers locally so no upstream is needed.
    ///
    /// ```
    /// use std::{
    ///     sync::Arc,
    ///     time::{Duration, Instant},
    /// };
    ///
    /// use praxis_core::subrequest::{SubRequestClient, SubRequestConnector};
    /// use praxis_filter::{
    ///     CalloutResponse, FilterEntry, FilterPipeline, FilterRegistry, FilteredSubrequestExecutor,
    ///     RequestExtensions, SubRequest, SubrequestRuntime,
    /// };
    ///
    /// let rt = tokio::runtime::Builder::new_current_thread()
    ///     .enable_all()
    ///     .build()
    ///     .unwrap();
    /// rt.block_on(async {
    ///     // The outbound chain a callout binds once at construction.
    ///     let registry = FilterRegistry::with_builtins();
    ///     let mut chain: Vec<FilterEntry> = serde_yaml::from_str(
    ///         "- filter: static_response\n  status: 200\n  body: hello from the outbound chain\n",
    ///     )
    ///     .unwrap();
    ///     let outbound = Arc::new(FilterPipeline::build(&mut chain, &registry).unwrap());
    ///
    ///     // At request time the callout builds an executor from the shared client
    ///     // and the downstream attributes it reads off its `HttpFilterContext`.
    ///     let client = SubRequestClient::new(SubRequestConnector::new(1, None));
    ///     let downstream = SubrequestRuntime::new(None, false, None, Instant::now());
    ///     let executor = FilteredSubrequestExecutor::for_callout(
    ///         client,
    ///         downstream,
    ///         0,                      // sub-request nesting depth
    ///         1 << 20,                // 1 MiB response ceiling
    ///         Duration::from_secs(5), // per-sub-request step timeout
    ///     );
    ///
    ///     let request = SubRequest {
    ///         method: http::Method::GET,
    ///         uri: http::Uri::from_static("/"),
    ///         headers: http::HeaderMap::new(),
    ///         body: bytes::Bytes::new(),
    ///     };
    ///     let deadline = Instant::now() + Duration::from_secs(5);
    ///     let response = match executor
    ///         .run(&outbound, &request, RequestExtensions::default(), deadline)
    ///         .await
    ///         .expect("the outbound chain produces a response")
    ///     {
    ///         CalloutResponse::Buffered(response) => response,
    ///         CalloutResponse::Streaming { .. } => unreachable!("static_response is buffered"),
    ///     };
    ///
    ///     assert_eq!(response.status, 200);
    ///     assert_eq!(&response.body[..], b"hello from the outbound chain");
    /// });
    /// ```
    ///
    /// [`ChainBindingContext::bind_chain`]: crate::ChainBindingContext::bind_chain
    /// [`HttpFilterContext`]: crate::HttpFilterContext
    #[expect(clippy::large_futures, reason = "delegates to the full step future")]
    #[expect(
        clippy::large_stack_frames,
        reason = "delegates to execute, which reconstructs a full filter context"
    )]
    pub async fn run(
        &self,
        pipeline: &Arc<FilterPipeline>,
        request: &SubRequest,
        extensions: RequestExtensions,
        deadline: Instant,
    ) -> Result<CalloutResponse, FilterError> {
        let input = FilteredSubrequestInput {
            pipeline,
            request,
            label: "callout",
            iteration: 0,
            deadline,
            extensions,
        };
        let OpenedSubrequest { continuation, kind } =
            self.execute(input).await.map_err(|error| error.into_parts().0)?;
        match kind {
            OpenedResponse::Complete(outcome) => Ok(CalloutResponse::Buffered(outcome.response)),
            OpenedResponse::Streaming { body, outcome } => Ok(CalloutResponse::Streaming {
                response: outcome.response,
                body: Box::new(CalloutStreamingBody::new(
                    FilteredStreamingBody::new(body, continuation),
                    self.max_response_bytes,
                )),
            }),
        }
    }

    /// Execute one sub-request under the remaining overall deadline.
    #[expect(
        clippy::too_many_lines,
        reason = "one sub-request owns the complete filter and transport lifecycle"
    )]
    #[expect(clippy::large_futures, reason = "step execution spans filter and transport futures")]
    #[expect(
        clippy::large_stack_frames,
        reason = "step execution reconstructs a full filter context"
    )]
    pub(crate) async fn execute(
        &self,
        input: FilteredSubrequestInput<'_>,
    ) -> Result<OpenedSubrequest, FilteredSubrequestError> {
        let FilteredSubrequestInput {
            pipeline,
            request: current_request,
            label,
            iteration,
            deadline,
            mut extensions,
        } = input;

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(FilteredSubrequestError::new(
                "filtered_subrequest: overall deadline exceeded".to_owned().into(),
                extensions,
            ));
        }

        let mut sub_headers = current_request.headers.clone();
        strip_reserved_headers(&mut sub_headers);
        let sub_req = crate::Request {
            method: current_request.method.clone(),
            uri: current_request.uri.clone(),
            headers: sub_headers.clone(),
        };
        let mut routed_req = sub_req.clone();
        let mut response_header = crate::Response {
            headers: HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        let resources = SubrequestRuntimeResources {
            client_addr: self.downstream.client_addr,
            downstream_tls: self.downstream.downstream_tls,
            health_registry: pipeline.health_registry(),
            id_generator: pipeline.id_generator(),
            kv_stores: pipeline.kv_stores(),
            session_stores: pipeline.session_stores(),
            peer_identity: self.downstream.peer_identity.as_ref(),
            request_start: self.downstream.request_start,
            subrequest_client: Some(&self.client),
            time_source: pipeline.time_source(),
        };
        let mut filter_ctx = build_sub_filter_context(pipeline, &sub_req, resources);
        filter_ctx.extensions = std::mem::take(&mut extensions);
        filter_ctx.extensions.insert(RetainedFilterResults::default());
        filter_ctx.enable_stream_chunk_emission(self.max_state_bytes);

        let step_budget = remaining.min(self.step_timeout);
        let step_started = Instant::now();
        let step_deadline = step_started.checked_add(step_budget).unwrap_or(deadline);
        let in_transport = Arc::new(AtomicBool::new(false));
        let in_transport_inner = Arc::clone(&in_transport);

        let step_span = tracing::info_span!("filtered_subrequest", step = label, iteration = iteration);

        let timed: Result<Result<RawResponse, FilterError>, tokio::time::error::Elapsed> =
            tokio::time::timeout(step_budget, async {
            let mut request_body = Some(current_request.body.clone());
            if body_exceeds_limit(
                pipeline.body_capabilities().request_body_mode,
                request_body.as_ref().map_or(0, Bytes::len),
            ) {
                return Ok(RawResponse::Rejected(Rejection::status(413)));
            }

            let pre_read_body = matches!(
                pipeline.body_capabilities().request_body_mode,
                crate::BodyMode::StreamBuffer { .. }
            );
            if pre_read_body {
                let action = pipeline
                    .execute_http_request_body(&mut filter_ctx, &mut request_body, true)
                    .await?;
                if let FilterAction::Reject(rejection) = action {
                    return Ok(RawResponse::Rejected(rejection));
                }
                if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                    return Ok(RawResponse::Rejected(Rejection::status(413)));
                }
                apply_pre_read_header_mutations(&mut routed_req.headers, &filter_ctx);
                filter_ctx.extra_request_headers.clear();
                filter_ctx.request_headers_to_remove.clear();
                filter_ctx.request_headers_to_set.clear();
                filter_ctx.pre_read_mutations.clear();
                sub_headers.clone_from(&routed_req.headers);
                filter_ctx.request = &routed_req;
            }

            let action = pipeline.execute_http_request(&mut filter_ctx).await?;
            if let FilterAction::Reject(rejection) = action {
                return Ok(RawResponse::Rejected(rejection));
            }
            if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                return Ok(RawResponse::Rejected(Rejection::status(413)));
            }
            if !pre_read_body {
                let action = pipeline
                    .execute_http_request_body(&mut filter_ctx, &mut request_body, true)
                    .await?;
                if let FilterAction::Reject(rejection) = action {
                    return Ok(RawResponse::Rejected(rejection));
                }
                if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                    return Ok(RawResponse::Rejected(Rejection::status(413)));
                }
            }

            let upstream = filter_ctx.upstream.as_ref().ok_or_else(|| -> FilterError {
                format!("filtered_subrequest: step '{label}' did not resolve an upstream").into()
            })?;
            let destination_authority = Arc::clone(&upstream.address);
            // The credential-matching key and upstream Host are the *logical*
            // authority the operator configured for this upstream (`authority`
            // override), not the transport endpoint bytes travel to. Derived
            // from trusted config, never the client-influenced Host header.
            let authority_override: Option<Arc<str>> = upstream
                .authority
                .as_ref()
                .and_then(|value| value.to_str().ok())
                .map(Arc::from);
            // Fall back to the transport only when no override is set.
            let logical_authority: Arc<str> = authority_override
                .clone()
                .unwrap_or_else(|| Arc::clone(&destination_authority));
            in_transport_inner.store(true, Ordering::Release);
            let peer = build_peer(upstream, pipeline.allow_private_upstreams()).await;
            apply_request_header_mutations(&mut sub_headers, &filter_ctx);
            // Mirror the normal proxy path (`apply_authority_override`): a
            // configured authority override becomes the upstream Host,
            // replacing any prior step's or caller's Host. Without an override,
            // default the Host to the transport endpoint only when absent.
            match authority_override.as_deref() {
                Some(authority) => set_authority_host(&mut sub_headers, authority)?,
                None => ensure_destination_host(&mut sub_headers, &destination_authority)?,
            }
            sanitize_subrequest_headers(&mut sub_headers);
            // Destination-bound credential injection: only now that the upstream
            // authority is resolved do we materialize staged secrets, and only
            // into a request bound for the authority each credential was issued
            // for. Injecting after sanitization keeps the credential header from
            // being stripped as hop-by-hop/framing.
            if let Some(pending) = filter_ctx.extensions.remove::<PendingCredentials>() {
                let destination = ResolvedDestination {
                    authority: &logical_authority,
                    transport: &destination_authority,
                };
                let injected = pending.inject_authorized(&destination, &mut sub_headers);
                if injected > 0 {
                    // A credential was authorized against `logical_authority`, so
                    // the upstream must see exactly that authority as its Host. Pin
                    // it here — replacing any step- or caller-set Host the
                    // no-override path preserved — so a secret can never be
                    // delivered under a divergent Host to a shared-vhost endpoint.
                    // (With an override the Host already equals `logical_authority`;
                    // this keeps that true.) A staged credential that matched
                    // nothing injects no secret, so it must not retarget the Host —
                    // doing so would silently change virtual-host routing.
                    set_authority_host(&mut sub_headers, &logical_authority)?;
                    tracing::debug!(
                        authority = %logical_authority,
                        transport = %destination_authority,
                        injected,
                        "materialized destination-bound credentials"
                    );
                }
            }
            let request = SubRequest {
                method: current_request.method.clone(),
                uri: filter_ctx.rewritten_path.as_ref().map_or_else(
                    || current_request.uri.clone(),
                    |path| http::Uri::try_from(path.as_str()).unwrap_or_else(|_| current_request.uri.clone()),
                ),
                headers: sub_headers,
                body: request_body.unwrap_or_default(),
            };
            let mut framework_headers = FrameworkHeaders::new();
            framework_headers.set_depth(self.depth + 1);
            let transport_budget = step_budget
                .checked_sub(step_started.elapsed())
                .unwrap_or(Duration::ZERO);
            if transport_budget.is_zero() {
                return Ok(RawResponse::Rejected(Rejection::status(504)));
            }

            match filter_ctx.subrequest_response_mode {
                SubRequestResponseMode::Streaming => {
                    if matches!(
                        pipeline.body_capabilities().response_body_mode,
                        crate::BodyMode::StreamBuffer { .. }
                    ) {
                        return Err(format!(
                            "filtered_subrequest: step '{label}' selected streaming despite a StreamBuffer response mode"
                        )
                        .into());
                    }
                    let limits = StreamLimits {
                        idle_timeout: STREAMING_IDLE_TIMEOUT,
                        // FilteredStreamingBody enforces the original absolute step
                        // deadline so header time cannot be granted twice.
                        max_stream_duration: None,
                        max_total_bytes: streaming_transport_limit(
                            pipeline.body_capabilities().response_body_mode,
                        ),
                    };
                    let response = match peer {
                        Ok(peer) => self
                            .client
                            .send_streaming(&peer, &request, transport_budget, limits, Some(&framework_headers))
                            .await,
                        Err(error) => Err(praxis_core::subrequest::SubRequestError::Connect(error.to_string())),
                    };
                    in_transport_inner.store(false, Ordering::Release);
                    match response {
                        Ok(response) => {
                            let status = response.status;
                            let mut headers = response.headers;
                            sanitize_subresponse_headers(&mut headers);
                            response_header.status = http::StatusCode::from_u16(status)
                                .map_err(|error| -> FilterError { format!("invalid upstream status: {error}").into() })?;
                            response_header.headers.clone_from(&headers);
                            filter_ctx.response_header = Some(&mut response_header);
                            let response_action = pipeline.execute_http_response(&mut filter_ctx).await?;
                            if let FilterAction::Reject(rejection) = response_action {
                                response.body.cancel().await;
                                return Ok(RawResponse::Rejected(rejection));
                            }
                            if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                                response.body.cancel().await;
                                return Ok(RawResponse::Rejected(Rejection::status(413)));
                            }
                            let metadata = filter_ctx.response_header.as_deref().ok_or_else(|| -> FilterError {
                                "filtered_subrequest: response metadata missing after header filters"
                                    .to_owned()
                                    .into()
                            })?;
                            let status = metadata.status;
                            let mut headers = metadata.headers.clone();
                            sanitize_subresponse_headers(&mut headers);
                            Ok(RawResponse::Streaming {
                                body: Box::new(response.body),
                                outcome: SubrequestOutcome {
                                    response: SubResponse { status: status.as_u16(), headers, body: Bytes::new() },
                                    origin: ResponseOrigin::Upstream,
                                    transport_error: None,
                                },
                            })
                        },
                        Err(error) => {
                            let (status, kind) = classify_transport_failure(&error);
                            warn!(step = label, %error, status, "filtered sub-request streaming transport failure");
                            let response = SubResponse { status, headers: HeaderMap::new(), body: Bytes::new() };
                            response_header.status = http::StatusCode::from_u16(status)
                                .map_err(|source| -> FilterError { source.into() })?;
                            filter_ctx.response_header = Some(&mut response_header);
                            let response_action = pipeline.execute_http_response(&mut filter_ctx).await?;
                            if let FilterAction::Reject(rejection) = response_action {
                                return Ok(RawResponse::Rejected(rejection));
                            }
                            if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                                return Ok(RawResponse::Rejected(Rejection::status(413)));
                            }
                            let metadata = filter_ctx.response_header.as_deref().ok_or_else(|| -> FilterError {
                                "filtered_subrequest: response metadata missing after header filters"
                                    .to_owned()
                                    .into()
                            })?;
                            let mut headers = metadata.headers.clone();
                            sanitize_subresponse_headers(&mut headers);
                            Ok(RawResponse::Complete(SubrequestOutcome {
                                response: SubResponse {
                                    status: metadata.status.as_u16(),
                                    headers,
                                    body: response.body,
                                },
                                origin: ResponseOrigin::Transport,
                                transport_error: Some(kind),
                            }))
                        },
                    }
                },
                SubRequestResponseMode::Buffered => {
                    let (mut response, origin, transport_error) = match peer {
                        Ok(peer) => match self
                            .client
                            .execute(&peer, &request, self.max_response_bytes, transport_budget, Some(&framework_headers))
                            .await
                        {
                            Ok(response) => (response, ResponseOrigin::Upstream, None),
                            Err(error) => {
                                let (status, kind) = classify_transport_failure(&error);
                                warn!(step = label, %error, status, "filtered sub-request buffered transport failure");
                                (
                                    SubResponse { status, headers: HeaderMap::new(), body: Bytes::new() },
                                    ResponseOrigin::Transport,
                                    Some(kind),
                                )
                            },
                        },
                        Err(error) => {
                            warn!(step = label, %error, status = 502_u16, "filtered sub-request buffered transport failure");
                            (
                                SubResponse { status: 502, headers: HeaderMap::new(), body: Bytes::new() },
                                ResponseOrigin::Transport,
                                Some(TransportFailure::Connect),
                            )
                        },
                    };
                    in_transport_inner.store(false, Ordering::Release);
                    sanitize_subresponse_headers(&mut response.headers);
                    response_header.status = http::StatusCode::from_u16(response.status)
                        .map_err(|error| -> FilterError { error.into() })?;
                    response_header.headers.clone_from(&response.headers);
                    filter_ctx.response_header = Some(&mut response_header);
                    let response_action = pipeline.execute_http_response(&mut filter_ctx).await?;
                    if let FilterAction::Reject(rejection) = response_action {
                        return Ok(RawResponse::Rejected(rejection));
                    }
                    if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                        return Ok(RawResponse::Rejected(Rejection::status(413)));
                    }
                    let mut body = Some(std::mem::take(&mut response.body));
                    if response_body_exceeds_limits(
                        pipeline.body_capabilities().response_body_mode,
                        self.max_response_bytes,
                        body.as_ref().map_or(0, Bytes::len),
                    ) {
                        return Err("filtered_subrequest: step response exceeds configured body limit".into());
                    }
                    let body_action = pipeline.execute_http_response_body(&mut filter_ctx, &mut body, true)?;
                    if let FilterAction::Reject(rejection) = body_action {
                        return Ok(RawResponse::Rejected(rejection));
                    }
                    if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                        return Ok(RawResponse::Rejected(Rejection::status(413)));
                    }
                    if response_body_exceeds_limits(
                        pipeline.body_capabilities().response_body_mode,
                        self.max_response_bytes,
                        body.as_ref().map_or(0, Bytes::len),
                    ) {
                        return Err(
                            "filtered_subrequest: transformed step response exceeds configured body limit"
                                .into(),
                        );
                    }
                    response.body = body.unwrap_or_default();
                    if let Some(metadata) = filter_ctx.response_header.as_deref() {
                        response.status = metadata.status.as_u16();
                        response.headers.clone_from(&metadata.headers);
                    }
                    sanitize_subresponse_headers(&mut response.headers);
                    Ok(RawResponse::Complete(SubrequestOutcome { response, origin, transport_error }))
                },
            }
            }
            .instrument(step_span))
            .await;

        let mut raw = match timed {
            Ok(Ok(raw)) => raw,
            Ok(Err(error)) => return Err(FilteredSubrequestError::capture(error, &mut filter_ctx)),
            Err(_) if in_transport.load(Ordering::Acquire) => RawResponse::Complete(SubrequestOutcome {
                response: SubResponse {
                    status: 504,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                },
                origin: ResponseOrigin::Transport,
                transport_error: Some(TransportFailure::DeadlineExceeded),
            }),
            Err(_) => RawResponse::Rejected(Rejection::status(504)),
        };

        filter_ctx.response_header = None;
        if filter_ctx.subrequest_response_mode == SubRequestResponseMode::Streaming
            && let RawResponse::Complete(outcome) = &mut raw
            && outcome.origin == ResponseOrigin::Transport
        {
            let cause = outcome
                .transport_error
                .map_or(StreamTerminationCause::Io, stream_termination_cause);
            filter_ctx.extensions.insert(StreamTermination::new(cause));
            let response_snapshot = crate::Response {
                status: http::StatusCode::from_u16(outcome.response.status).unwrap_or(http::StatusCode::BAD_GATEWAY),
                headers: outcome.response.headers.clone(),
            };
            let mut completion_body = None;
            let completion_action = pipeline
                .execute_http_response_body_with_response_header(
                    &mut filter_ctx,
                    &mut completion_body,
                    true,
                    Some(&response_snapshot),
                )
                .map_err(|error| FilteredSubrequestError::capture(error, &mut filter_ctx))?;
            if let FilterAction::Reject(_) = completion_action {
                let error = "filtered_subrequest: step completion filter rejected an abnormal stream"
                    .to_owned()
                    .into();
                return Err(FilteredSubrequestError::capture(error, &mut filter_ctx));
            }
            if self.accounting.exceeds_limit(&filter_ctx.extensions) {
                let error = "filtered_subrequest: retained state limit exceeded during stream completion"
                    .to_owned()
                    .into();
                return Err(FilteredSubrequestError::capture(error, &mut filter_ctx));
            }
            if completion_body
                .as_ref()
                .is_some_and(|body| body.len() > self.max_response_bytes)
            {
                let error = "filtered_subrequest: abnormal completion exceeds response body limit"
                    .to_owned()
                    .into();
                return Err(FilteredSubrequestError::capture(error, &mut filter_ctx));
            }
            outcome.response.body = completion_body.unwrap_or_default();
        }
        let (kind, response_snapshot, completed) = match raw {
            RawResponse::Complete(outcome) => {
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(outcome.response.status)
                        .unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: outcome.response.headers.clone(),
                };
                (OpenedResponse::Complete(outcome), snapshot, true)
            },
            RawResponse::Rejected(rejection) => {
                let response = subresponse_from_rejection(rejection);
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(response.status).unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: response.headers.clone(),
                };
                (
                    OpenedResponse::Complete(SubrequestOutcome {
                        response,
                        origin: ResponseOrigin::Local,
                        transport_error: None,
                    }),
                    snapshot,
                    true,
                )
            },
            RawResponse::Streaming { body, outcome } => {
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(outcome.response.status)
                        .unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: outcome.response.headers.clone(),
                };
                (OpenedResponse::Streaming { body, outcome }, snapshot, false)
            },
        };
        let request_snapshot = crate::Request {
            method: filter_ctx.request.method.clone(),
            uri: filter_ctx.request.uri.clone(),
            headers: filter_ctx.request.headers.clone(),
        };
        let continuation = FilteredSubrequestContinuation::capture(
            Arc::clone(pipeline),
            request_snapshot,
            response_snapshot,
            &mut filter_ctx,
            completed,
            step_deadline,
        );
        Ok(OpenedSubrequest { continuation, kind })
    }
}
