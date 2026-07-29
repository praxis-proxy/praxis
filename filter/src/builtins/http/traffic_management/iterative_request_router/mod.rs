// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Iterative request router: a framework-level filter that executes
//! multiple sequential HTTP sub-requests through composable filter
//! chains before returning a final response to the client.
//!
//! # Header isolation
//!
//! Every transitioned step begins with empty headers. `Host` is
//! reconstructed from the selected destination. `Content-Type`,
//! `Accept`, authorization tokens, and custom headers are **not**
//! inherited from the previous step. Each step must explicitly
//! inject its own credentials and required representation headers
//! (e.g. via a `headers` or `credential_injection` filter).
//!
//! # Streaming limitations
//!
//! Intermediate and terminal responses are fully buffered in memory
//! (bounded by `max_response_bytes`). SSE and long-lived streaming
//! responses are not supported. The iterative request router is
//! designed for bounded, buffered workflows.
//!
//! # Position requirement
//!
//! This filter must be the last filter in its parent chain because
//! it produces terminal responses that bypass remaining request-phase
//! filters. Place accounting and observability filters before it so
//! they participate in the response lifecycle.
//!
//! See proposal 00786 for the full design rationale.

mod config;
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use pingora_core::upstreams::peer::HttpPeer;
use praxis_core::subrequest::FrameworkHeaders;
use tracing::{debug, info, warn};

use self::config::IterativeRequestRouterConfig;
use crate::{
    FilterEntry, FilterError, FilterPipeline, FilterRegistry, IterationState, NextIterationBody, SubRequest,
    SubResponse,
    actions::{FilterAction, Rejection, TerminalResponse},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    pipeline::subrequest::DEPTH_HEADER,
    results::RetainedFilterResults,
};

// ---------------------------------------------------------------------------
// IterativeRequestRouterFilter
// ---------------------------------------------------------------------------

/// Framework-level filter for iterative sub-request execution.
///
/// Holds named steps, each backed by a pre-built sub-pipeline.
/// During request processing, runs an iteration loop: execute each
/// step's request filters, make the HTTP call via Pingora's
/// `Connector`, execute its response filters, evaluate transition
/// rules, and continue or return the final response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: iterative_request_router
/// initial_step: model-call
/// steps:
///   - name: model-call
///     filters:
///       - filter: router
///         routes:
///           - cluster: llm-backend
///       - filter: load_balancer
///         clusters:
///           - name: llm-backend
///             endpoints: ["10.0.0.1:8000"]
///     on_result:
///       - default: true
///         done: true
/// ```
pub struct IterativeRequestRouterFilter {
    /// Name of the first step to execute.
    initial_step: Arc<str>,

    /// Maximum iterations.
    max_iterations: u32,

    /// Maximum response body bytes per sub-request.
    max_response_bytes: usize,

    /// Maximum accumulated state bytes.
    max_state_bytes: usize,

    /// Per-step timeout cap.
    step_timeout: Duration,

    /// Pre-built sub-pipelines keyed by step name.
    step_pipelines: HashMap<Arc<str>, FilterPipeline>,

    /// Transition rules keyed by step name.
    step_transitions: HashMap<Arc<str>, Vec<config::StepTransition>>,

    /// Overall timeout.
    timeout: Duration,
}

impl IterativeRequestRouterFilter {
    /// Create from YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the config is invalid or step
    /// pipelines fail to build.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", value)?;
        Self::from_parsed_config(cfg, &FilterRegistry::with_builtins())
    }

    /// Create from YAML config, resolving step filters through the
    /// registry that owns the containing pipeline.
    pub(crate) fn from_config_with_registry(
        value: &serde_yaml::Value,
        registry: &FilterRegistry,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: IterativeRequestRouterConfig = parse_filter_config("iterative_request_router", value)?;
        Self::from_parsed_config(cfg, registry)
    }

    /// Validate parsed configuration and build each step pipeline.
    #[expect(clippy::too_many_lines, reason = "validation and named step construction")]
    fn from_parsed_config(
        cfg: IterativeRequestRouterConfig,
        registry: &FilterRegistry,
    ) -> Result<Box<dyn HttpFilter>, FilterError> {
        config::validate(&cfg)?;
        let timeout = Duration::from_millis(cfg.timeout_ms);
        if Instant::now().checked_add(timeout).is_none() {
            return Err(
                "iterative_request_router: timeout_ms exceeds the platform Instant range"
                    .to_owned()
                    .into(),
            );
        }

        let mut step_pipelines = HashMap::new();
        let mut step_transitions = HashMap::new();

        for step in cfg.steps {
            let name: Arc<str> = Arc::from(step.name.as_str());

            let mut entries: Vec<FilterEntry> = step.filters.into_iter().collect();
            let pipeline = FilterPipeline::build(&mut entries, registry)?;
            let ordering_errors =
                pipeline.ordering_errors(&entries, false, &praxis_core::config::SkipPipelineChecks::default());
            if !ordering_errors.is_empty() {
                return Err(format!(
                    "iterative_request_router: invalid step '{}': {}",
                    step.name,
                    ordering_errors.join("; ")
                )
                .into());
            }

            step_pipelines.insert(Arc::clone(&name), pipeline);
            step_transitions.insert(Arc::clone(&name), step.on_result);
        }

        let step_timeout = cfg.step_timeout_ms.map_or(timeout, Duration::from_millis);

        Ok(Box::new(Self {
            initial_step: Arc::from(cfg.initial_step.as_str()),
            max_iterations: cfg.max_iterations,
            max_response_bytes: cfg.max_response_bytes,
            max_state_bytes: cfg.max_state_bytes,
            step_pipelines,
            step_timeout,
            step_transitions,
            timeout,
        }))
    }
}

#[async_trait]
impl HttpFilter for IterativeRequestRouterFilter {
    fn name(&self) -> &'static str {
        "iterative_request_router"
    }

    fn request_body_access(&self) -> crate::body::BodyAccess {
        crate::body::BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> crate::body::BodyMode {
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(self.max_state_bytes),
        }
    }

    /// Validate the request, then run the iteration at the router's normal
    /// request-header position after preceding filters have completed.
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let depth = parse_depth(ctx.request);
        if depth >= config::max_depth() {
            warn!(
                depth,
                max = config::max_depth(),
                "iterative_request_router: max depth exceeded"
            );
            return Ok(FilterAction::Reject(Rejection::status(508)));
        }

        if ctx.subrequest_client().is_none() {
            return Err("iterative_request_router: no sub-request \
                 client available"
                .to_owned()
                .into());
        }

        let request_body = ctx.buffered_request_body.take().ok_or_else(|| -> FilterError {
            "iterative_request_router: buffered request body unavailable"
                .to_owned()
                .into()
        })?;

        Box::pin(self.run_iterations(ctx, request_body)).await
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "lifecycle implementation is kept separate from construction"
)]
impl IterativeRequestRouterFilter {
    /// Run the complete iterative subrequest lifecycle.
    #[expect(clippy::too_many_lines, reason = "iteration loop is inherently sequential")]
    #[expect(clippy::large_stack_frames, reason = "sub-pipeline execution needs stack space")]
    async fn run_iterations(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        request_body: Bytes,
    ) -> Result<FilterAction, FilterError> {
        let depth = parse_depth(ctx.request);
        let client = ctx
            .subrequest_client()
            .ok_or_else(|| -> FilterError { "iterative_request_router: no sub-request client".to_owned().into() })?
            .clone();
        let max_response_bytes = effective_response_limit(self.max_response_bytes, ctx.response_body_mode);

        let original_request = SubRequest {
            method: ctx.request.method.clone(),
            uri: ctx.request.uri.clone(),
            headers: ctx.request.headers.clone(),
            body: request_body,
        };

        let mut state = IterationState {
            original_request: original_request.clone(),
            previous_response: None,
            accumulator: HashMap::new(),
            iteration: 0,
            max_iterations: self.max_iterations,
            deadline: Instant::now().checked_add(self.timeout).ok_or_else(|| -> FilterError {
                "iterative_request_router: deadline exceeds the platform Instant range"
                    .to_owned()
                    .into()
            })?,
            max_response_bytes,
            depth,
        };
        if state.retained_bytes() > self.max_state_bytes {
            return Ok(FilterAction::Reject(Rejection::status(413)));
        }

        let mut current_step = Arc::clone(&self.initial_step);
        let mut current_request = original_request;

        loop {
            if state.iteration >= self.max_iterations {
                warn!(
                    iterations = state.iteration,
                    max = self.max_iterations,
                    "iterative_request_router: max iterations \
                     exhausted"
                );
                return Ok(FilterAction::Reject(Rejection::status(508)));
            }

            let remaining = state
                .deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                warn!(
                    iterations = state.iteration,
                    "iterative_request_router: deadline exceeded"
                );
                return Ok(FilterAction::Reject(Rejection::status(504)));
            }

            let pipeline = self.step_pipelines.get(&current_step).ok_or_else(|| -> FilterError {
                format!(
                    "iterative_request_router: step \
                         '{current_step}' not found"
                )
                .into()
            })?;

            let step_span = tracing::info_span!(
                "iterative_subrequest",
                step = current_step.as_ref(),
                iteration = state.iteration,
            );
            let _enter = step_span.enter();

            debug!(
                step = current_step.as_ref(),
                iteration = state.iteration,
                "executing step"
            );

            let mut sub_headers = current_request.headers.clone();
            strip_reserved_headers(&mut sub_headers);

            let sub_req = crate::Request {
                method: current_request.method.clone(),
                uri: current_request.uri.clone(),
                headers: sub_headers.clone(),
            };
            let mut routed_req = sub_req.clone();

            // Keep the response metadata alive for the full step
            // context so response-header and response-body hooks share
            // the same lifecycle state.
            let mut response_header = crate::Response {
                headers: HeaderMap::new(),
                status: http::StatusCode::OK,
            };
            let runtime_resources = SubPipelineRuntimeResources {
                client_addr: ctx.client_addr,
                downstream_tls: ctx.downstream_tls,
                health_registry: ctx.health_registry,
                id_generator: ctx.id_generator,
                kv_stores: ctx.kv_stores,
                peer_identity: ctx.peer_identity.as_ref(),
                request_start: ctx.request_start,
                subrequest_client: Some(&client),
                time_source: ctx.time_source,
            };
            let mut filter_ctx = build_sub_filter_context(pipeline, &sub_req, runtime_resources);
            std::mem::swap(&mut filter_ctx.extensions, &mut ctx.extensions);
            filter_ctx.extensions.insert(state.clone());
            filter_ctx.extensions.insert(RetainedFilterResults::default());
            let step_timeout = remaining.min(self.step_timeout);
            let step_start = Instant::now();
            let in_transport = Arc::new(AtomicBool::new(false));
            let in_transport_inner = Arc::clone(&in_transport);
            let step_result: Result<StepExecution, FilterError> = match tokio::time::timeout(step_timeout, async {
                let mut request_body = Some(current_request.body.clone());
                if body_exceeds_limit(
                    pipeline.body_capabilities().request_body_mode,
                    request_body.as_ref().map_or(0, Bytes::len),
                ) {
                    return Ok(StepExecution::Rejected(Rejection::status(413)));
                }

                let pre_read_body = matches!(
                    pipeline.body_capabilities().request_body_mode,
                    crate::body::BodyMode::StreamBuffer { .. }
                );
                if pre_read_body {
                    let action = pipeline
                        .execute_http_request_body(&mut filter_ctx, &mut request_body, true)
                        .await?;
                    if let FilterAction::Reject(rejection) = action {
                        return Ok(StepExecution::Rejected(rejection));
                    }
                    if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                        return Ok(StepExecution::Rejected(Rejection::status(413)));
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
                    return Ok(StepExecution::Rejected(rejection));
                }
                if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                    return Ok(StepExecution::Rejected(Rejection::status(413)));
                }

                if !pre_read_body {
                    let action = pipeline
                        .execute_http_request_body(&mut filter_ctx, &mut request_body, true)
                        .await?;
                    if let FilterAction::Reject(rejection) = action {
                        return Ok(StepExecution::Rejected(rejection));
                    }
                    if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                        return Ok(StepExecution::Rejected(Rejection::status(413)));
                    }
                }

                let upstream = filter_ctx.upstream.as_ref().ok_or_else(|| -> FilterError {
                    format!(
                        "iterative_request_router: step \
                         '{current_step}' did not resolve an upstream"
                    )
                    .into()
                })?;
                in_transport_inner.store(true, Ordering::Release);
                let peer = build_peer(upstream).await;

                apply_request_header_mutations(&mut sub_headers, &filter_ctx);
                ensure_destination_host(&mut sub_headers, &upstream.address)?;
                sanitize_subrequest_headers(&mut sub_headers);
                let sub_request_for_exec = SubRequest {
                    method: current_request.method.clone(),
                    uri: filter_ctx.rewritten_path.as_ref().map_or_else(
                        || current_request.uri.clone(),
                        |p| http::Uri::try_from(p.as_str()).unwrap_or_else(|_| current_request.uri.clone()),
                    ),
                    headers: sub_headers,
                    body: request_body.unwrap_or_default(),
                };

                let mut fw_headers = FrameworkHeaders::new();
                let depth_value = (depth + 1).to_string();
                if let Ok(val) = http::HeaderValue::from_str(&depth_value) {
                    let _ok = fw_headers.insert(http::header::HeaderName::from_static(DEPTH_HEADER), val);
                }

                let per_request_timeout = step_timeout.checked_sub(step_start.elapsed()).unwrap_or(Duration::ZERO);
                if per_request_timeout.is_zero() {
                    return Ok(StepExecution::Rejected(Rejection::status(504)));
                }
                let mut step_origin = config::ResponseOrigin::Upstream;
                let mut step_transport_error = None;
                let mut response = match peer {
                    Ok(peer) => match client
                        .execute(
                            &peer,
                            &sub_request_for_exec,
                            max_response_bytes,
                            per_request_timeout,
                            Some(&fw_headers),
                        )
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            let (status, kind) = classify_transport_failure(&error);
                            step_origin = config::ResponseOrigin::Transport;
                            step_transport_error = Some(kind);
                            warn!(
                                step = current_step.as_ref(),
                                %error,
                                status,
                                "iterative_request_router: sub-request transport failure"
                            );
                            SubResponse {
                                status,
                                headers: HeaderMap::new(),
                                body: Bytes::new(),
                            }
                        },
                    },
                    Err(error) => {
                        step_origin = config::ResponseOrigin::Transport;
                        step_transport_error = Some(config::TransportErrorKind::Connect);
                        let status = 502;
                        warn!(
                            step = current_step.as_ref(),
                            %error,
                            status,
                            "iterative_request_router: sub-request transport failure"
                        );
                        SubResponse {
                            status,
                            headers: HeaderMap::new(),
                            body: Bytes::new(),
                        }
                    },
                };
                in_transport_inner.store(false, Ordering::Release);
                sanitize_subresponse_headers(&mut response.headers);

                response_header.status = http::StatusCode::from_u16(response.status).map_err(|e| -> FilterError {
                    format!("iterative_request_router: invalid upstream status: {e}").into()
                })?;
                response_header.headers.clone_from(&response.headers);
                filter_ctx.response_header = Some(&mut response_header);

                let action = pipeline.execute_http_response(&mut filter_ctx).await?;
                if let FilterAction::Reject(rejection) = action {
                    return Ok(StepExecution::Rejected(rejection));
                }
                if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                    return Ok(StepExecution::Rejected(Rejection::status(413)));
                }

                let mut response_body = Some(std::mem::take(&mut response.body));
                if response_body_exceeds_limits(
                    pipeline.body_capabilities().response_body_mode,
                    max_response_bytes,
                    response_body.as_ref().map_or(0, Bytes::len),
                ) {
                    return Err("iterative_request_router: step response exceeds configured body limit"
                        .to_owned()
                        .into());
                }
                let action = pipeline.execute_http_response_body(&mut filter_ctx, &mut response_body, true)?;
                if let FilterAction::Reject(rejection) = action {
                    return Ok(StepExecution::Rejected(rejection));
                }
                if iteration_state_exceeds_limit(&filter_ctx, self.max_state_bytes) {
                    return Ok(StepExecution::Rejected(Rejection::status(413)));
                }
                if response_body_exceeds_limits(
                    pipeline.body_capabilities().response_body_mode,
                    max_response_bytes,
                    response_body.as_ref().map_or(0, Bytes::len),
                ) {
                    return Err(
                        "iterative_request_router: transformed step response exceeds configured body limit"
                            .to_owned()
                            .into(),
                    );
                }

                if let Some(meta) = filter_ctx.response_header.as_deref() {
                    response.status = meta.status.as_u16();
                    response.headers.clone_from(&meta.headers);
                }
                response.body = response_body.unwrap_or_default();
                sanitize_subresponse_headers(&mut response.headers);

                Ok(StepExecution::Complete {
                    response,
                    origin: step_origin,
                    transport_error: step_transport_error,
                })
            })
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => {
                    if in_transport.load(Ordering::Acquire) {
                        Ok(StepExecution::Complete {
                            response: SubResponse {
                                status: 504,
                                headers: HeaderMap::new(),
                                body: Bytes::new(),
                            },
                            origin: config::ResponseOrigin::Transport,
                            transport_error: Some(config::TransportErrorKind::DeadlineExceeded),
                        })
                    } else {
                        Ok(StepExecution::Rejected(Rejection::status(504)))
                    }
                },
            };

            if let Some(updated_state) = filter_ctx.extensions.remove::<IterationState>() {
                state = updated_state;
            }
            if state.retained_bytes() > self.max_state_bytes {
                return Ok(FilterAction::Reject(Rejection::status(413)));
            }
            let next_iteration_body = filter_ctx.extensions.remove::<NextIterationBody>();
            let mut step_filter_results = filter_ctx
                .extensions
                .remove::<RetainedFilterResults>()
                .unwrap_or_default()
                .0;
            step_filter_results.extend(
                filter_ctx
                    .filter_results
                    .iter()
                    .map(|(name, results)| (*name, results.clone())),
            );
            std::mem::swap(&mut filter_ctx.extensions, &mut ctx.extensions);

            let (mut response, origin, transport_error) = match step_result? {
                StepExecution::Complete {
                    response,
                    origin,
                    transport_error,
                } => (response, origin, transport_error),
                StepExecution::Rejected(rejection) => {
                    debug!(
                        step = current_step.as_ref(),
                        status = rejection.status,
                        "step pipeline produced a local response"
                    );
                    (
                        subresponse_from_rejection(rejection),
                        config::ResponseOrigin::Local,
                        None,
                    )
                },
            };
            sanitize_subresponse_headers(&mut response.headers);

            info!(
                step = current_step.as_ref(),
                iteration = state.iteration,
                status = response.status,
                body_bytes = response.body.len(),
                "sub-request complete"
            );

            state.previous_response = Some(response.clone());
            state.iteration += 1;
            if state.retained_bytes() > self.max_state_bytes {
                return Ok(FilterAction::Reject(Rejection::status(413)));
            }

            let outcome = StepOutcome {
                response,
                origin,
                transport_error,
            };

            let transitions = self
                .step_transitions
                .get(&current_step)
                .map_or(&[][..], |v| v.as_slice());

            match evaluate_transitions(transitions, &outcome, &step_filter_results) {
                TransitionResult::Done => {
                    debug!(step = current_step.as_ref(), "iteration complete, returning response");
                    return Ok(FilterAction::TerminalResponse(Box::new(build_terminal_response(
                        &outcome.response,
                        current_request.method == http::Method::HEAD,
                    ))));
                },
                TransitionResult::Next(next_step) => {
                    debug!(
                        from = current_step.as_ref(),
                        to = next_step.as_ref(),
                        "transitioning to next step"
                    );
                    let next_body = next_iteration_body.map_or_else(|| current_request.body.clone(), |b| b.0);
                    current_request = SubRequest {
                        method: current_request.method.clone(),
                        uri: current_request.uri.clone(),
                        headers: HeaderMap::new(),
                        body: next_body,
                    };
                    current_step = next_step;
                },
                TransitionResult::NoMatch => {
                    debug!(
                        step = current_step.as_ref(),
                        "no transition matched, returning response"
                    );
                    return Ok(FilterAction::TerminalResponse(Box::new(build_terminal_response(
                        &outcome.response,
                        current_request.method == http::Method::HEAD,
                    ))));
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transition Evaluation
// ---------------------------------------------------------------------------

/// Result of executing one step's complete filter and HTTP lifecycle.
enum StepExecution {
    /// A step filter rejected the request or response.
    Rejected(Rejection),

    /// The upstream exchange completed after all response hooks.
    Complete {
        /// The sub-request response.
        response: SubResponse,
        /// Where the response originated.
        origin: config::ResponseOrigin,
        /// Transport error classification, if any.
        transport_error: Option<config::TransportErrorKind>,
    },
}

/// A step's response together with metadata about where it came from.
struct StepOutcome {
    /// The sub-request response.
    response: SubResponse,
    /// Where the response originated.
    origin: config::ResponseOrigin,
    /// Transport error classification, if any.
    transport_error: Option<config::TransportErrorKind>,
}

/// Result of evaluating step transition rules.
enum TransitionResult {
    /// Return the current response to the client.
    Done,

    /// Transition to the named step.
    Next(Arc<str>),

    /// No transition matched.
    NoMatch,
}

/// Convert transport failures into a gateway status and error classification.
fn classify_transport_failure(error: &praxis_core::subrequest::SubRequestError) -> (u16, config::TransportErrorKind) {
    use praxis_core::subrequest::SubRequestError;
    match error {
        SubRequestError::AdmissionTimeout { .. } => (503, config::TransportErrorKind::AdmissionTimeout),
        SubRequestError::Connect(_) => (502, config::TransportErrorKind::Connect),
        SubRequestError::DeadlineExceeded => (504, config::TransportErrorKind::DeadlineExceeded),
        SubRequestError::ResponseTooLarge { .. } => (502, config::TransportErrorKind::ResponseTooLarge),
        _ => (502, config::TransportErrorKind::Io),
    }
}

/// Convert a nested filter's local response into transition input.
fn subresponse_from_rejection(rejection: Rejection) -> SubResponse {
    let status = normalize_response_status(rejection.status);
    let mut headers = HeaderMap::new();
    for (name, value) in rejection.headers {
        let Ok(name) = http::HeaderName::try_from(name) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::try_from(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(header_map) = rejection.header_map {
        for (name, value) in header_map.iter() {
            headers.append(name.clone(), value.clone());
        }
    }
    let mut response = SubResponse {
        status,
        headers,
        body: rejection.body.unwrap_or_default(),
    };
    sanitize_subresponse_headers(&mut response.headers);
    response
}

/// Keep final locally generated statuses inside the terminal response range.
/// Informational, invalid upstream, or invalid custom-filter values become 502.
fn normalize_response_status(status: u16) -> u16 {
    if (200..=599).contains(&status) { status } else { 502 }
}

/// Evaluate transition rules against a step outcome.
fn evaluate_transitions(
    transitions: &[config::StepTransition],
    outcome: &StepOutcome,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> TransitionResult {
    for t in transitions {
        if t.default || matches_transition(t, outcome, filter_results) {
            if t.done {
                return TransitionResult::Done;
            }
            if let Some(next) = &t.next {
                return TransitionResult::Next(Arc::from(next.as_str()));
            }
            return TransitionResult::Done;
        }
    }

    TransitionResult::NoMatch
}

/// Check if a transition matches the outcome and/or filter results.
fn matches_transition(
    transition: &config::StepTransition,
    outcome: &StepOutcome,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> bool {
    let status_ok = transition
        .status
        .as_ref()
        .is_none_or(|codes| codes.contains(&outcome.response.status));

    let origin_ok = transition.origin.is_none_or(|expected| expected == outcome.origin);

    let transport_ok = transition
        .transport_error
        .is_none_or(|expected| outcome.transport_error == Some(expected));

    let result_ok = match (
        transition.filter.as_deref(),
        transition.key.as_deref(),
        transition.value.as_deref(),
    ) {
        (Some(filter_name), Some(key), Some(value)) => {
            crate::matches_filter_result(filter_results, filter_name, key, value)
        },
        (None, None, None) => true,
        _ => false,
    };

    status_ok && origin_ok && transport_ok && result_ok
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Parse the iterative depth from request headers.
fn parse_depth(request: &crate::Request) -> u8 {
    request
        .headers
        .get(DEPTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Strip all reserved internal headers and the depth header from
/// sub-request headers so the core executor re-injects depth via
/// [`FrameworkHeaders`].
fn strip_reserved_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()) || name.as_str() == DEPTH_HEADER)
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// Apply request mutations emitted across the step's header and body
/// filter phases before dispatching its upstream request.
fn apply_request_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    for name in &ctx.request_headers_to_remove {
        headers.remove(name);
    }
    for (name, value) in &ctx.request_headers_to_set {
        headers.insert(name.clone(), value.clone());
    }
    for (name, value) in &ctx.extra_request_headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
}

/// Apply body pre-read mutations to the request snapshot that header
/// filters use for classification and routing.
fn apply_pre_read_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    if ctx.pre_read_mutations.is_empty() {
        apply_request_header_mutations(headers, ctx);
        return;
    }

    for mutation in &ctx.pre_read_mutations {
        match mutation {
            crate::TrustedHeaderMutation::Remove(name) => {
                headers.remove(name);
            },
            crate::TrustedHeaderMutation::Set(name, value) => {
                headers.insert(name.clone(), value.clone());
            },
            crate::TrustedHeaderMutation::Add(name, value) => {
                if let Ok(value) = http::HeaderValue::from_str(value) {
                    headers.append(name.clone(), value);
                }
            },
        }
    }
}

/// Remove inbound message-framing headers after request-body filters
/// have potentially changed the payload. The subrequest executor adds
/// the correct `Content-Length` for non-empty bodies.
fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Headers that apply only to one HTTP connection and must not cross it.
const REQUEST_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Response-side hop-by-hop headers.
const RESPONSE_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Apply the same forwarding boundary as the normal upstream path.
fn sanitize_subrequest_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, REQUEST_HOP_BY_HOP);
    strip_reserved_headers(headers);
    strip_request_framing_headers(headers);
}

/// Supply the selected upstream authority without carrying a prior step's Host.
fn ensure_destination_host(headers: &mut HeaderMap, address: &str) -> Result<(), FilterError> {
    if !headers.contains_key(http::header::HOST) {
        let value = http::HeaderValue::from_str(address).map_err(|error| -> FilterError {
            format!("iterative_request_router: invalid upstream Host: {error}").into()
        })?;
        headers.insert(http::header::HOST, value);
    }
    Ok(())
}

/// Remove connection-scoped and proxy-internal response metadata.
fn sanitize_subresponse_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_headers(headers);
}

/// Remove the static hop-by-hop set and headers named by `Connection`.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap, static_headers: &[&str]) {
    let connection_values: Vec<_> = headers.get_all(http::header::CONNECTION).iter().cloned().collect();
    for name in static_headers {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            headers.remove(token);
        }
    }
}

/// Whether a fully buffered nested body exceeds its pipeline mode's
/// configured ceiling.
fn body_exceeds_limit(mode: crate::body::BodyMode, body_len: usize) -> bool {
    match mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => body_len > max_bytes,
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => false,
    }
}

/// Whether a response exceeds either the iterative router's global
/// per-step ceiling or the nested pipeline's body-mode ceiling.
fn response_body_exceeds_limits(mode: crate::body::BodyMode, max_response_bytes: usize, body_len: usize) -> bool {
    body_len > max_response_bytes || body_exceeds_limit(mode, body_len)
}

/// Clamp the router-specific response cap to the listener's global body mode.
fn effective_response_limit(configured: usize, parent_mode: crate::body::BodyMode) -> usize {
    match parent_mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => configured.min(max_bytes),
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => configured,
    }
}

/// Whether a step filter grew the shared iteration state past its ceiling.
fn iteration_state_exceeds_limit(ctx: &HttpFilterContext<'_>, max_state_bytes: usize) -> bool {
    ctx.extensions
        .get::<IterationState>()
        .is_some_and(|state| state.retained_bytes() > max_state_bytes)
}

/// Runtime resources inherited from the pipeline that contains the
/// iterative router.
#[derive(Clone, Copy)]
struct SubPipelineRuntimeResources<'a> {
    /// Original downstream client address.
    client_addr: Option<std::net::IpAddr>,

    /// Whether the original downstream connection uses TLS.
    downstream_tls: bool,

    /// Shared endpoint-health state.
    health_registry: Option<&'a praxis_core::health::HealthRegistry>,

    /// Shared request ID generator.
    id_generator: &'a praxis_core::id::IdGenerator,

    /// Named runtime key-value stores.
    kv_stores: Option<&'a praxis_core::kv::KvStoreRegistry>,

    /// Verified downstream mTLS identity.
    peer_identity: Option<&'a praxis_tls::TlsPeerIdentity>,

    /// Start time of the containing client request.
    request_start: Instant,

    /// Shared client used for recursive subrequests.
    subrequest_client: Option<&'a praxis_core::subrequest::SubRequestClient>,

    /// Server-provided wall-clock source.
    time_source: &'a dyn praxis_core::time::TimeSource,
}

/// Build a [`HttpFilterContext`] for running a step's sub-pipeline,
/// inheriting server-injected resources from the containing request.
#[expect(clippy::too_many_lines, reason = "all fields must be initialized")]
fn build_sub_filter_context<'a>(
    pipeline: &'a FilterPipeline,
    request: &'a crate::Request,
    runtime: SubPipelineRuntimeResources<'a>,
) -> HttpFilterContext<'a> {
    HttpFilterContext {
        buffered_request_body: None,
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: runtime.client_addr,
        cluster: None,
        current_filter_id: None,
        downstream_tls: runtime.downstream_tls,
        extensions: crate::extensions::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
        filter_state: HashMap::new(),
        health_registry: runtime.health_registry,
        id_generator: runtime.id_generator,
        kv_stores: runtime.kv_stores,
        peer_identity: runtime.peer_identity.cloned(),
        pre_read_mutations: Vec::new(),
        request,
        request_body_bytes: 0,
        request_body_mode: pipeline.body_capabilities().request_body_mode,
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        request_start: runtime.request_start,
        response_body_bytes: 0,
        response_body_mode: pipeline.body_capabilities().response_body_mode,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        structured_metadata: HashMap::new(),
        subrequest_client: runtime.subrequest_client,
        time_source: runtime.time_source,
        upstream: None,
    }
}

/// Convert a Praxis [`Upstream`] to a Pingora [`HttpPeer`].
///
/// Applies TLS settings (CA, client cert, verify toggle) and
/// connection options (timeouts) from the upstream config. Derives
/// SNI from the address hostname when not explicitly configured.
///
/// [`Upstream`]: praxis_core::connectivity::Upstream
async fn build_peer(
    upstream: &praxis_core::connectivity::Upstream,
) -> Result<HttpPeer, praxis_core::connectivity::peer::AddressResolutionError> {
    use praxis_core::connectivity::peer as peer_utils;

    let addr: &str = &upstream.address;
    let socket_addr = peer_utils::resolve_address(addr).await?;
    let tls_enabled = upstream.tls.is_some();
    let sni = upstream
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned))
        .unwrap_or_else(|| {
            if tls_enabled {
                peer_utils::derive_sni(addr)
            } else {
                String::new()
            }
        });

    let mut peer = HttpPeer::new(socket_addr, tls_enabled, sni);
    peer_utils::apply_connection_options(&mut peer, &upstream.connection);

    if let Some(tls) = &upstream.tls {
        peer_utils::apply_cached_tls(&mut peer, tls, addr);
    }

    Ok(peer)
}

/// Build a [`TerminalResponse`] carrying the sub-request response.
fn build_terminal_response(response: &SubResponse, preserve_content_length: bool) -> TerminalResponse {
    let status = normalize_response_status(response.status);
    let mut headers = HeaderMap::new();
    for (name, value) in &response.headers {
        if (name == http::header::CONTENT_LENGTH && !preserve_content_length) || name == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    if !preserve_content_length && status != 204 && status != 304 {
        let content_length = response.body.len().to_string();
        if let Ok(value) = http::HeaderValue::from_str(&content_length) {
            headers.insert(http::header::CONTENT_LENGTH, value);
        }
    }
    let mut terminal = TerminalResponse::new(status).with_headers(headers);
    if !response.body.is_empty() {
        terminal = terminal.with_body(response.body.clone());
    }
    terminal
}
