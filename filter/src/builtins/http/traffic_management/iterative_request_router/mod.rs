// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Iterative request router: a framework-level filter that executes
//! multiple sequential HTTP sub-requests through composable filter
//! chains before returning a final response to the client.
//!
//! See proposal 00786 for the full design rationale.

mod config;
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests;

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use pingora_core::upstreams::peer::HttpPeer;
use praxis_core::{id::IdGenerator, time::SystemTimeSource};
use tracing::{debug, info, warn};

use self::config::IterativeRequestRouterConfig;
use crate::{
    FilterEntry, FilterError, FilterPipeline, FilterRegistry,
    actions::{FilterAction, Rejection},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    pipeline::subrequest::{self, DEPTH_HEADER, IterationState, SubRequest, SubResponse},
};

// ---------------------------------------------------------------------------
// IterativeRequestRouterFilter
// ---------------------------------------------------------------------------

/// Framework-level filter for iterative sub-request execution.
///
/// Holds named steps, each backed by a pre-built sub-pipeline.
/// During `on_request`, runs an iteration loop: execute a step's
/// pipeline to resolve routing, make the HTTP call via Pingora's
/// `Connector`, evaluate transition rules, and continue or
/// return the final response.
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
    _max_state_bytes: usize,

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
        config::validate(&cfg)?;

        let registry = FilterRegistry::with_builtins();
        let mut step_pipelines = HashMap::new();
        let mut step_transitions = HashMap::new();

        for step in cfg.steps {
            let name: Arc<str> = Arc::from(step.name.as_str());

            let mut entries: Vec<FilterEntry> = step.filters.into_iter().collect();
            let pipeline = FilterPipeline::build(&mut entries, &registry)?;

            step_pipelines.insert(Arc::clone(&name), pipeline);
            step_transitions.insert(Arc::clone(&name), step.on_result);
        }

        Ok(Box::new(Self {
            initial_step: Arc::from(cfg.initial_step.as_str()),
            max_iterations: cfg.max_iterations,
            max_response_bytes: cfg.max_response_bytes,
            _max_state_bytes: cfg.max_state_bytes,
            step_pipelines,
            step_transitions,
            timeout: Duration::from_millis(cfg.timeout_ms),
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
            max_bytes: Some(self.max_response_bytes),
        }
    }

    /// Early validation: depth check and connector availability.
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

        if ctx.subrequest_connector().is_none() {
            return Err("iterative_request_router: no sub-request \
                 connector available"
                .to_owned()
                .into());
        }

        Ok(FilterAction::Continue)
    }

    /// Runs the iteration loop once the full request body is
    /// buffered.
    #[expect(clippy::too_many_lines, reason = "iteration loop is inherently sequential")]
    #[expect(clippy::large_stack_frames, reason = "sub-pipeline execution needs stack space")]
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let depth = parse_depth(ctx.request);
        let connector = ctx
            .subrequest_connector()
            .ok_or_else(|| -> FilterError { "iterative_request_router: no sub-request connector".to_owned().into() })?
            .clone();

        let request_body = body.take().unwrap_or_default();

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
            deadline: Instant::now() + self.timeout,
            max_response_bytes: self.max_response_bytes,
            depth,
        };

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
            if let Ok(depth_val) = http::HeaderValue::from_str(&(depth + 1).to_string()) {
                sub_headers.insert(DEPTH_HEADER, depth_val);
            }
            strip_reserved_headers(&mut sub_headers);

            let sub_req = crate::Request {
                method: current_request.method.clone(),
                uri: current_request.uri.clone(),
                headers: sub_headers.clone(),
            };

            let mut filter_ctx = build_sub_filter_context(pipeline, &sub_req, Some(&connector));
            filter_ctx.extensions.insert(state.clone());
            let action = pipeline.execute_http_request(&mut filter_ctx).await?;

            if let FilterAction::Reject(r) = &action {
                debug!(
                    step = current_step.as_ref(),
                    status = r.status,
                    "step pipeline rejected request"
                );
                return Ok(action);
            }

            let upstream = filter_ctx.upstream.ok_or_else(|| -> FilterError {
                format!(
                    "iterative_request_router: step \
                     '{current_step}' did not resolve an upstream"
                )
                .into()
            })?;

            let peer = build_peer(&upstream);

            for (name, value) in &filter_ctx.extra_request_headers {
                if let (Ok(hn), Ok(hv)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    sub_headers.insert(hn, hv);
                }
            }

            let sub_request_for_exec = SubRequest {
                method: current_request.method.clone(),
                uri: filter_ctx.rewritten_path.as_ref().map_or_else(
                    || current_request.uri.clone(),
                    |p| http::Uri::try_from(p.as_str()).unwrap_or_else(|_| current_request.uri.clone()),
                ),
                headers: sub_headers,
                body: current_request.body.clone(),
            };

            let per_request_timeout = remaining.min(Duration::from_secs(30));

            #[expect(clippy::large_futures, reason = "Pingora session types are large")]
            let response = subrequest::execute(
                &connector,
                &peer,
                &sub_request_for_exec,
                self.max_response_bytes,
                per_request_timeout,
            )
            .await
            .map_err(|e| -> FilterError {
                format!(
                    "iterative_request_router: step \
                     '{current_step}' sub-request failed: {e}"
                )
                .into()
            })?;

            info!(
                step = current_step.as_ref(),
                iteration = state.iteration,
                status = response.status,
                body_bytes = response.body.len(),
                "sub-request complete"
            );

            state.previous_response = Some(response.clone());
            state.iteration += 1;

            let transitions = self
                .step_transitions
                .get(&current_step)
                .map_or(&[][..], |v| v.as_slice());

            match evaluate_transitions(transitions, &response, &filter_ctx.filter_results) {
                TransitionResult::Done => {
                    debug!(step = current_step.as_ref(), "iteration complete, returning response");
                    return Ok(FilterAction::Reject(build_response_rejection(&response)));
                },
                TransitionResult::Next(next_step) => {
                    debug!(
                        from = current_step.as_ref(),
                        to = next_step.as_ref(),
                        "transitioning to next step"
                    );
                    let mut next_headers = HeaderMap::new();
                    for (name, value) in &filter_ctx.request_headers_to_set {
                        next_headers.insert(name.clone(), value.clone());
                    }
                    let next_body = filter_ctx
                        .extensions
                        .remove::<NextIterationBody>()
                        .map_or_else(|| current_request.body.clone(), |b| b.0);
                    current_request = SubRequest {
                        method: current_request.method.clone(),
                        uri: current_request.uri.clone(),
                        headers: next_headers,
                        body: next_body,
                    };
                    current_step = next_step;
                },
                TransitionResult::NoMatch => {
                    debug!(
                        step = current_step.as_ref(),
                        "no transition matched, returning response"
                    );
                    return Ok(FilterAction::Reject(build_response_rejection(&response)));
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NextIterationBody
// ---------------------------------------------------------------------------

/// Newtype for step chain filters to provide a custom body for the
/// next iteration. Set via `ctx.extensions.insert(NextIterationBody(body))`.
pub(crate) struct NextIterationBody(pub(crate) Bytes);

// ---------------------------------------------------------------------------
// Transition Evaluation
// ---------------------------------------------------------------------------

/// Result of evaluating step transition rules.
enum TransitionResult {
    /// Return the current response to the client.
    Done,

    /// Transition to the named step.
    Next(Arc<str>),

    /// No transition matched.
    NoMatch,
}

/// Evaluate transition rules against a sub-request response.
fn evaluate_transitions(
    transitions: &[config::StepTransition],
    response: &SubResponse,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> TransitionResult {
    for t in transitions {
        if t.default || matches_transition(t, response, filter_results) {
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

/// Check if a transition matches the response and/or filter results.
fn matches_transition(
    transition: &config::StepTransition,
    response: &SubResponse,
    filter_results: &HashMap<&str, crate::results::FilterResultSet>,
) -> bool {
    let status_ok = transition
        .status
        .as_ref()
        .is_none_or(|codes| codes.contains(&response.status));

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

    status_ok && result_ok
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

/// Strip all reserved internal headers from sub-request headers.
fn strip_reserved_headers(headers: &mut HeaderMap) {
    let reserved: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()))
        .cloned()
        .collect();
    for name in reserved {
        headers.remove(&name);
    }
}

/// Shared ID generator for sub-request filter contexts.
static SUB_ID_GENERATOR: std::sync::LazyLock<IdGenerator> = std::sync::LazyLock::new(IdGenerator::new);

/// Build a minimal [`HttpFilterContext`] for running a step's
/// sub-pipeline.
#[expect(clippy::too_many_lines, reason = "all fields must be initialized")]
fn build_sub_filter_context<'a>(
    pipeline: &'a FilterPipeline,
    request: &'a crate::Request,
    connector: Option<&'a praxis_core::subrequest::SubRequestConnector>,
) -> HttpFilterContext<'a> {
    HttpFilterContext {
        body_done_indices: Vec::new(),
        branch_iterations: HashMap::new(),
        client_addr: None,
        cluster: None,
        current_filter_id: None,
        downstream_tls: false,
        extensions: crate::extensions::RequestExtensions::default(),
        executed_filter_indices: Vec::new(),
        extra_request_headers: Vec::new(),
        filter_metadata: HashMap::new(),
        filter_results: HashMap::new(),
        filter_state: HashMap::new(),
        health_registry: pipeline.health_registry(),
        id_generator: &SUB_ID_GENERATOR,
        kv_stores: pipeline.kv_stores(),
        peer_identity: None,
        pre_read_mutations: Vec::new(),
        request,
        request_body_bytes: 0,
        request_body_mode: crate::body::BodyMode::Stream,
        request_headers_to_remove: Vec::new(),
        request_headers_to_set: Vec::new(),
        request_start: Instant::now(),
        response_body_bytes: 0,
        response_body_mode: crate::body::BodyMode::Stream,
        response_header: None,
        response_headers_modified: false,
        rewritten_path: None,
        selected_endpoint_index: None,
        structured_metadata: HashMap::new(),
        subrequest_connector: connector.or_else(|| pipeline.subrequest_connector()),
        time_source: &SystemTimeSource,
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
fn build_peer(upstream: &praxis_core::connectivity::Upstream) -> HttpPeer {
    use praxis_core::connectivity::peer as peer_utils;

    let addr: &str = &upstream.address;
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

    let mut peer = HttpPeer::new(addr, tls_enabled, sni);
    peer_utils::apply_connection_options(&mut peer, &upstream.connection);

    if let Some(tls) = &upstream.tls {
        peer_utils::apply_cached_tls(&mut peer, tls, addr);
    }

    peer
}

/// Build a [`Rejection`] that carries the sub-request response.
fn build_response_rejection(response: &SubResponse) -> Rejection {
    let mut rejection = Rejection::status(response.status);
    if !response.body.is_empty() {
        rejection = rejection.with_body(response.body.clone());
    }
    for (name, value) in &response.headers {
        if let Ok(val_str) = value.to_str() {
            rejection = rejection.with_header(name.to_string(), val_str);
        }
    }
    rejection
}
