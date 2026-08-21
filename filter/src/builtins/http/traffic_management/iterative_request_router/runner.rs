// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! One-step execution for the iterative request router.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::HeaderMap;
use praxis_core::subrequest::{FrameworkHeaders, StreamLimits};
use tracing::{Instrument as _, warn};

use super::{
    StepOutcome, SubPipelineRuntimeResources, apply_pre_read_header_mutations, apply_request_header_mutations,
    body_exceeds_limit, build_peer, build_sub_filter_context, classify_transport_failure, config,
    ensure_destination_host, iteration_state_exceeds_limit, response_body_exceeds_limits, sanitize_subrequest_headers,
    sanitize_subresponse_headers, streaming::StepResponseContinuation, streaming_transport_limit,
    strip_reserved_headers, subresponse_from_rejection,
};
use crate::{
    FilterAction, FilterError, FilterPipeline, IterationState, NextIterationBody, RequestExtensions, StreamTermination,
    StreamTerminationCause, SubRequest, SubRequestResponseMode, SubResponse, actions::Rejection,
    context::PendingStreamChunks, results::RetainedFilterResults,
};

/// Owned request attributes needed after the outer request hook returns.
#[derive(Clone)]
pub(super) struct StepRuntime {
    /// Original downstream client address.
    pub(super) client_addr: Option<std::net::IpAddr>,
    /// Whether the original downstream uses TLS.
    pub(super) downstream_tls: bool,
    /// Verified downstream peer identity.
    pub(super) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
    /// Start time of the logical client request.
    pub(super) request_start: Instant,
}

/// Executes exactly one IRR step and returns owned continuation state.
pub(super) struct IrrStepRunner {
    /// Shared transport client.
    client: praxis_core::subrequest::SubRequestClient,
    /// Nested IRR depth forwarded to subrequests.
    depth: u8,
    /// Per-step buffered response ceiling.
    max_response_bytes: usize,
    /// Retained iteration-state and pending-output ceiling.
    max_state_bytes: usize,
    /// Owned downstream request attributes.
    runtime: StepRuntime,
    /// Named, pre-built step pipelines.
    step_pipelines: HashMap<Arc<str>, Arc<FilterPipeline>>,
    /// Per-step duration ceiling.
    step_timeout: Duration,
}

/// One opened step, including state needed for body/completion processing.
pub(super) struct OpenedStep {
    /// Owned filter lifecycle state.
    pub(super) continuation: StepResponseContinuation,
    /// Buffered or pull-based response source.
    pub(super) kind: OpenedStepKind,
}

/// A step error together with the parent request extensions it borrowed.
pub(super) struct OpenStepError {
    /// Underlying filter or lifecycle error.
    error: FilterError,
    /// Parent-owned extensions recovered from the nested filter context.
    extensions: RequestExtensions,
}

impl OpenStepError {
    /// Build an error before a nested filter context exists.
    fn new(error: FilterError, extensions: RequestExtensions) -> Self {
        Self { error, extensions }
    }

    /// Recover only the parent-owned extensions from a failed nested context.
    fn capture(error: FilterError, ctx: &mut crate::HttpFilterContext<'_>) -> Self {
        ctx.extensions.remove::<IterationState>();
        ctx.extensions.remove::<NextIterationBody>();
        ctx.extensions.remove::<PendingStreamChunks>();
        ctx.extensions.remove::<RetainedFilterResults>();
        ctx.extensions.remove::<StreamTermination>();
        Self::new(error, std::mem::take(&mut ctx.extensions))
    }

    /// Split the error from the extensions its caller must restore.
    pub(super) fn into_parts(self) -> (FilterError, RequestExtensions) {
        (self.error, self.extensions)
    }
}

/// Transport/body shape selected by the step filters.
pub(super) enum OpenedStepKind {
    /// The complete response was collected and filtered.
    Complete(StepOutcome),
    /// Response headers are filtered; body remains pull-based.
    Streaming {
        /// Live upstream response body.
        body: Box<praxis_core::subrequest::SubResponseBody>,
        /// Header-time transition metadata.
        outcome: StepOutcome,
    },
}

/// Internal result before owned continuation state is captured.
enum RawStepKind {
    /// Complete buffered or synthetic response.
    Complete(StepOutcome),
    /// Local filter rejection.
    Rejected(Rejection),
    /// Open pull-based upstream response.
    Streaming {
        /// Live upstream response body.
        body: Box<praxis_core::subrequest::SubResponseBody>,
        /// Header-time transition metadata.
        outcome: StepOutcome,
    },
}

impl IrrStepRunner {
    /// Build an owned runner for one logical IRR request.
    #[expect(clippy::too_many_arguments, reason = "runner owns explicit IRR limits and resources")]
    pub(super) fn new(
        client: praxis_core::subrequest::SubRequestClient,
        depth: u8,
        max_response_bytes: usize,
        max_state_bytes: usize,
        runtime: StepRuntime,
        step_pipelines: HashMap<Arc<str>, Arc<FilterPipeline>>,
        step_timeout: Duration,
    ) -> Self {
        Self {
            client,
            depth,
            max_response_bytes,
            max_state_bytes,
            runtime,
            step_pipelines,
            step_timeout,
        }
    }

    /// Open one named step under the remaining overall deadline.
    #[expect(
        clippy::too_many_lines,
        reason = "one step owns the complete filter and transport lifecycle"
    )]
    #[expect(clippy::large_futures, reason = "step execution spans filter and transport futures")]
    #[expect(
        clippy::large_stack_frames,
        reason = "step execution reconstructs a full filter context"
    )]
    pub(super) async fn open_step(
        &self,
        current_step: &Arc<str>,
        current_request: &SubRequest,
        state: &IterationState,
        mut extensions: RequestExtensions,
    ) -> Result<OpenedStep, OpenStepError> {
        let remaining = state
            .deadline()
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(OpenStepError::new(
                "iterative_request_router: overall deadline exceeded".to_owned().into(),
                extensions,
            ));
        }
        let Some(pipeline) = self.step_pipelines.get(current_step) else {
            return Err(OpenStepError::new(
                format!("iterative_request_router: step '{current_step}' not found").into(),
                extensions,
            ));
        };

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
        let resources = SubPipelineRuntimeResources {
            client_addr: self.runtime.client_addr,
            downstream_tls: self.runtime.downstream_tls,
            health_registry: pipeline.health_registry(),
            id_generator: pipeline.id_generator(),
            kv_stores: pipeline.kv_stores(),
            peer_identity: self.runtime.peer_identity.as_ref(),
            request_start: self.runtime.request_start,
            subrequest_client: Some(&self.client),
            time_source: pipeline.time_source(),
        };
        let mut filter_ctx = build_sub_filter_context(pipeline, &sub_req, resources);
        filter_ctx.extensions = std::mem::take(&mut extensions);
        filter_ctx.extensions.insert(state.clone());
        filter_ctx.extensions.insert(RetainedFilterResults::default());
        filter_ctx.enable_stream_chunk_emission(self.max_state_bytes);

        let step_budget = remaining.min(self.step_timeout);
        let step_started = Instant::now();
        let step_deadline = step_started
            .checked_add(step_budget)
            .unwrap_or_else(|| state.deadline());
        let in_transport = Arc::new(AtomicBool::new(false));
        let in_transport_inner = Arc::clone(&in_transport);

        let step_span = tracing::info_span!(
            "iterative_subrequest",
            step = current_step.as_ref(),
            iteration = state.iteration,
        );

        let timed: Result<Result<RawStepKind, FilterError>, tokio::time::error::Elapsed> =
            tokio::time::timeout(step_budget, async {
            let mut request_body = Some(current_request.body.clone());
            if body_exceeds_limit(
                pipeline.body_capabilities().request_body_mode,
                request_body.as_ref().map_or(0, Bytes::len),
            ) {
                return Ok(RawStepKind::Rejected(Rejection::status(413)));
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
                    return Ok(RawStepKind::Rejected(rejection));
                }
                if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                    return Ok(RawStepKind::Rejected(Rejection::status(413)));
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
                return Ok(RawStepKind::Rejected(rejection));
            }
            if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                return Ok(RawStepKind::Rejected(Rejection::status(413)));
            }
            if !pre_read_body {
                let action = pipeline
                    .execute_http_request_body(&mut filter_ctx, &mut request_body, true)
                    .await?;
                if let FilterAction::Reject(rejection) = action {
                    return Ok(RawStepKind::Rejected(rejection));
                }
                if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                    return Ok(RawStepKind::Rejected(Rejection::status(413)));
                }
            }

            let upstream = filter_ctx.upstream.as_ref().ok_or_else(|| -> FilterError {
                format!("iterative_request_router: step '{current_step}' did not resolve an upstream").into()
            })?;
            in_transport_inner.store(true, Ordering::Release);
            let peer = build_peer(upstream).await;
            apply_request_header_mutations(&mut sub_headers, &filter_ctx);
            ensure_destination_host(&mut sub_headers, &upstream.address)?;
            sanitize_subrequest_headers(&mut sub_headers);
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
                return Ok(RawStepKind::Rejected(Rejection::status(504)));
            }

            match filter_ctx.subrequest_response_mode {
                SubRequestResponseMode::Streaming => {
                    if matches!(
                        pipeline.body_capabilities().response_body_mode,
                        crate::BodyMode::StreamBuffer { .. }
                    ) {
                        return Err(format!(
                            "iterative_request_router: step '{current_step}' selected streaming with StreamBuffer response mode"
                        )
                        .into());
                    }
                    let limits = StreamLimits {
                        idle_timeout: super::STREAMING_IDLE_TIMEOUT,
                        // IrrStreamingBody enforces the original absolute step
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
                                return Ok(RawStepKind::Rejected(rejection));
                            }
                            if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                                response.body.cancel().await;
                                return Ok(RawStepKind::Rejected(Rejection::status(413)));
                            }
                            let metadata = filter_ctx.response_header.as_deref().ok_or_else(|| -> FilterError {
                                "iterative_request_router: response metadata missing after header filters"
                                    .to_owned()
                                    .into()
                            })?;
                            let status = metadata.status;
                            let mut headers = metadata.headers.clone();
                            sanitize_subresponse_headers(&mut headers);
                            Ok(RawStepKind::Streaming {
                                body: Box::new(response.body),
                                outcome: StepOutcome {
                                    response: SubResponse { status: status.as_u16(), headers, body: Bytes::new() },
                                    origin: config::ResponseOrigin::Upstream,
                                    transport_error: None,
                                },
                            })
                        },
                        Err(error) => {
                            let (status, kind) = classify_transport_failure(&error);
                            warn!(step = current_step.as_ref(), %error, status, "IRR streaming transport failure");
                            let response = SubResponse { status, headers: HeaderMap::new(), body: Bytes::new() };
                            response_header.status = http::StatusCode::from_u16(status)
                                .map_err(|source| -> FilterError { source.into() })?;
                            filter_ctx.response_header = Some(&mut response_header);
                            let response_action = pipeline.execute_http_response(&mut filter_ctx).await?;
                            if let FilterAction::Reject(rejection) = response_action {
                                return Ok(RawStepKind::Rejected(rejection));
                            }
                            if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                                return Ok(RawStepKind::Rejected(Rejection::status(413)));
                            }
                            let metadata = filter_ctx.response_header.as_deref().ok_or_else(|| -> FilterError {
                                "iterative_request_router: response metadata missing after header filters"
                                    .to_owned()
                                    .into()
                            })?;
                            let mut headers = metadata.headers.clone();
                            sanitize_subresponse_headers(&mut headers);
                            Ok(RawStepKind::Complete(StepOutcome {
                                response: SubResponse {
                                    status: metadata.status.as_u16(),
                                    headers,
                                    body: response.body,
                                },
                                origin: config::ResponseOrigin::Transport,
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
                            Ok(response) => (response, config::ResponseOrigin::Upstream, None),
                            Err(error) => {
                                let (status, kind) = classify_transport_failure(&error);
                                warn!(step = current_step.as_ref(), %error, status, "IRR buffered transport failure");
                                (
                                    SubResponse { status, headers: HeaderMap::new(), body: Bytes::new() },
                                    config::ResponseOrigin::Transport,
                                    Some(kind),
                                )
                            },
                        },
                        Err(error) => {
                            warn!(step = current_step.as_ref(), %error, status = 502_u16, "IRR buffered transport failure");
                            (
                                SubResponse { status: 502, headers: HeaderMap::new(), body: Bytes::new() },
                                config::ResponseOrigin::Transport,
                                Some(config::TransportErrorKind::Connect),
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
                        return Ok(RawStepKind::Rejected(rejection));
                    }
                    if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                        return Ok(RawStepKind::Rejected(Rejection::status(413)));
                    }
                    let mut body = Some(std::mem::take(&mut response.body));
                    if response_body_exceeds_limits(
                        pipeline.body_capabilities().response_body_mode,
                        self.max_response_bytes,
                        body.as_ref().map_or(0, Bytes::len),
                    ) {
                        return Err("iterative_request_router: step response exceeds configured body limit".into());
                    }
                    let body_action = pipeline.execute_http_response_body(&mut filter_ctx, &mut body, true)?;
                    if let FilterAction::Reject(rejection) = body_action {
                        return Ok(RawStepKind::Rejected(rejection));
                    }
                    if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                        return Ok(RawStepKind::Rejected(Rejection::status(413)));
                    }
                    if response_body_exceeds_limits(
                        pipeline.body_capabilities().response_body_mode,
                        self.max_response_bytes,
                        body.as_ref().map_or(0, Bytes::len),
                    ) {
                        return Err(
                            "iterative_request_router: transformed step response exceeds configured body limit"
                                .into(),
                        );
                    }
                    response.body = body.unwrap_or_default();
                    if let Some(metadata) = filter_ctx.response_header.as_deref() {
                        response.status = metadata.status.as_u16();
                        response.headers.clone_from(&metadata.headers);
                    }
                    sanitize_subresponse_headers(&mut response.headers);
                    Ok(RawStepKind::Complete(StepOutcome { response, origin, transport_error }))
                },
            }
            }
            .instrument(step_span))
            .await;

        let mut raw = match timed {
            Ok(Ok(raw)) => raw,
            Ok(Err(error)) => return Err(OpenStepError::capture(error, &mut filter_ctx)),
            Err(_) if in_transport.load(Ordering::Acquire) => RawStepKind::Complete(StepOutcome {
                response: SubResponse {
                    status: 504,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                },
                origin: config::ResponseOrigin::Transport,
                transport_error: Some(config::TransportErrorKind::DeadlineExceeded),
            }),
            Err(_) => RawStepKind::Rejected(Rejection::status(504)),
        };

        filter_ctx.response_header = None;
        if filter_ctx.subrequest_response_mode == SubRequestResponseMode::Streaming
            && let RawStepKind::Complete(outcome) = &mut raw
            && outcome.origin == config::ResponseOrigin::Transport
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
                .map_err(|error| OpenStepError::capture(error, &mut filter_ctx))?;
            if let FilterAction::Reject(_) = completion_action {
                let error = "iterative_request_router: step completion filter rejected an abnormal stream"
                    .to_owned()
                    .into();
                return Err(OpenStepError::capture(error, &mut filter_ctx));
            }
            if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                let error = "iterative_request_router: retained state limit exceeded during stream completion"
                    .to_owned()
                    .into();
                return Err(OpenStepError::capture(error, &mut filter_ctx));
            }
            if completion_body
                .as_ref()
                .is_some_and(|body| body.len() > self.max_response_bytes)
            {
                let error = "iterative_request_router: abnormal completion exceeds response body limit"
                    .to_owned()
                    .into();
                return Err(OpenStepError::capture(error, &mut filter_ctx));
            }
            outcome.response.body = completion_body.unwrap_or_default();
        }
        let (kind, response_snapshot, completed) = match raw {
            RawStepKind::Complete(outcome) => {
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(outcome.response.status)
                        .unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: outcome.response.headers.clone(),
                };
                (OpenedStepKind::Complete(outcome), snapshot, true)
            },
            RawStepKind::Rejected(rejection) => {
                let response = subresponse_from_rejection(rejection);
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(response.status).unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: response.headers.clone(),
                };
                (
                    OpenedStepKind::Complete(StepOutcome {
                        response,
                        origin: config::ResponseOrigin::Local,
                        transport_error: None,
                    }),
                    snapshot,
                    true,
                )
            },
            RawStepKind::Streaming { body, outcome } => {
                let snapshot = crate::Response {
                    status: http::StatusCode::from_u16(outcome.response.status)
                        .unwrap_or(http::StatusCode::BAD_GATEWAY),
                    headers: outcome.response.headers.clone(),
                };
                (OpenedStepKind::Streaming { body, outcome }, snapshot, false)
            },
        };
        let request_snapshot = crate::Request {
            method: filter_ctx.request.method.clone(),
            uri: filter_ctx.request.uri.clone(),
            headers: filter_ctx.request.headers.clone(),
        };
        let continuation = StepResponseContinuation::capture(
            Arc::clone(pipeline),
            request_snapshot,
            response_snapshot,
            &mut filter_ctx,
            completed,
            step_deadline,
        );
        Ok(OpenedStep { continuation, kind })
    }
}

/// Convert transition-level transport metadata into completion-hook metadata.
fn stream_termination_cause(kind: config::TransportErrorKind) -> StreamTerminationCause {
    match kind {
        config::TransportErrorKind::AdmissionTimeout => StreamTerminationCause::AdmissionTimeout,
        config::TransportErrorKind::CircuitOpen => StreamTerminationCause::CircuitOpen,
        config::TransportErrorKind::Connect => StreamTerminationCause::Connect,
        config::TransportErrorKind::Io => StreamTerminationCause::Io,
        config::TransportErrorKind::DeadlineExceeded => StreamTerminationCause::DeadlineExceeded,
        config::TransportErrorKind::ResponseTooLarge => StreamTerminationCause::ResponseTooLarge,
    }
}
