// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Thin adapter running one IRR step through the generic subrequest executor.
//!
//! [`IrrStepRunner`] owns a [`FilteredSubrequestExecutor`] and the router's
//! named step pipelines. [`open_step`](IrrStepRunner::open_step) looks up the
//! selected step pipeline, injects the router's [`IterationState`] into the
//! request extensions, and delegates the filter and transport lifecycle to the
//! executor. The executor's continuation types are mapped back onto the
//! router's [`OpenedStep`] and [`StepOutcome`] vocabulary so the rest of the
//! router is unchanged.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use praxis_core::subrequest::{SubRequestClient, SubResponseBody};

use super::{StepOutcome, config, strip_iteration_extensions};
use crate::{
    FilterError, FilterPipeline, IterationState, RequestExtensions, SubRequest,
    filtered_subrequest::{
        FilteredSubrequestContinuation, FilteredSubrequestExecutor, FilteredSubrequestInput, OpenedResponse,
        OpenedSubrequest, ResponseOrigin, RetainedStateAccounting, SubrequestOutcome, SubrequestRuntime,
        TransportFailure,
    },
};

/// One opened step, including state needed for body/completion processing.
pub(super) struct OpenedStep {
    /// Owned filter lifecycle state.
    pub(super) continuation: FilteredSubrequestContinuation,
    /// Buffered or pull-based response source.
    pub(super) kind: OpenedStepKind,
}

/// Transport/body shape selected by the step filters.
pub(super) enum OpenedStepKind {
    /// The complete response was collected and filtered.
    Complete(StepOutcome),
    /// Response headers are filtered; body remains pull-based.
    Streaming {
        /// Live upstream response body.
        body: Box<SubResponseBody>,
        /// Header-time transition metadata.
        outcome: StepOutcome,
    },
}

/// A step error together with the parent request extensions it borrowed.
pub(super) struct OpenStepError {
    /// Underlying filter or lifecycle error.
    error: FilterError,
    /// Parent-owned extensions recovered from the nested filter context.
    extensions: RequestExtensions,
}

impl OpenStepError {
    /// Build an error carrying the parent extensions to restore.
    fn new(error: FilterError, extensions: RequestExtensions) -> Self {
        Self { error, extensions }
    }

    /// Split the error from the extensions its caller must restore.
    pub(super) fn into_parts(self) -> (FilterError, RequestExtensions) {
        (self.error, self.extensions)
    }
}

/// Reports whether the router's retained iteration state exceeds its ceiling.
///
/// The generic executor enforces the ceiling at every phase boundary through
/// this hook without knowing the router's [`IterationState`] layout.
struct IterationAccounting {
    /// Retained-state raw byte ceiling.
    max_state_bytes: usize,
}

impl RetainedStateAccounting for IterationAccounting {
    fn exceeds_limit(&self, extensions: &RequestExtensions) -> bool {
        extensions
            .get::<IterationState>()
            .is_some_and(|state| state.retained_bytes() > self.max_state_bytes)
    }
}

impl From<ResponseOrigin> for config::ResponseOrigin {
    fn from(origin: ResponseOrigin) -> Self {
        match origin {
            ResponseOrigin::Upstream => config::ResponseOrigin::Upstream,
            ResponseOrigin::Local => config::ResponseOrigin::Local,
            ResponseOrigin::Transport => config::ResponseOrigin::Transport,
        }
    }
}

impl From<TransportFailure> for config::TransportErrorKind {
    fn from(failure: TransportFailure) -> Self {
        match failure {
            TransportFailure::AdmissionTimeout => config::TransportErrorKind::AdmissionTimeout,
            TransportFailure::CircuitOpen => config::TransportErrorKind::CircuitOpen,
            TransportFailure::Connect => config::TransportErrorKind::Connect,
            TransportFailure::Io => config::TransportErrorKind::Io,
            TransportFailure::DeadlineExceeded => config::TransportErrorKind::DeadlineExceeded,
            TransportFailure::ResponseTooLarge { .. } => config::TransportErrorKind::ResponseTooLarge,
        }
    }
}

/// Map a generic executor outcome onto the router's transition vocabulary.
fn step_outcome_from(outcome: SubrequestOutcome) -> StepOutcome {
    StepOutcome {
        response: outcome.response,
        origin: outcome.origin.into(),
        transport_error: outcome.transport_error.map(Into::into),
    }
}

impl OpenedStep {
    /// Adapt the generic opened sub-request into the router's step vocabulary.
    fn from_executor(opened: OpenedSubrequest) -> Self {
        let OpenedSubrequest { continuation, kind } = opened;
        let kind = match kind {
            OpenedResponse::Complete(outcome) => OpenedStepKind::Complete(step_outcome_from(outcome)),
            OpenedResponse::Streaming { body, outcome } => OpenedStepKind::Streaming {
                body,
                outcome: step_outcome_from(outcome),
            },
        };
        Self { continuation, kind }
    }
}

/// Executes exactly one IRR step by delegating to the generic executor.
pub(super) struct IrrStepRunner {
    /// Generic filtered sub-request executor.
    executor: FilteredSubrequestExecutor,
    /// Named, pre-built step pipelines.
    step_pipelines: HashMap<Arc<str>, Arc<FilterPipeline>>,
}

impl IrrStepRunner {
    /// Build an owned runner for one logical IRR request.
    #[expect(clippy::too_many_arguments, reason = "runner owns explicit IRR limits and resources")]
    pub(super) fn new(
        client: SubRequestClient,
        depth: u8,
        max_response_bytes: usize,
        max_state_bytes: usize,
        downstream: SubrequestRuntime,
        step_pipelines: HashMap<Arc<str>, Arc<FilterPipeline>>,
        step_timeout: Duration,
    ) -> Self {
        let executor = FilteredSubrequestExecutor::new(
            Box::new(IterationAccounting { max_state_bytes }),
            client,
            depth,
            downstream,
            max_response_bytes,
            max_state_bytes,
            step_timeout,
        );
        Self {
            executor,
            step_pipelines,
        }
    }

    /// Open one named step under the remaining overall deadline.
    ///
    /// The deadline and step-existence checks run before the router's iteration
    /// state is injected, preserving the router's error precedence; the filter
    /// and transport lifecycle is then delegated to the executor.
    #[expect(
        clippy::too_many_lines,
        reason = "adapter keeps the router's step-open error precedence in one place"
    )]
    #[expect(
        clippy::large_stack_frames,
        reason = "constructs the executor's full step future before boxing it"
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
        extensions.insert(state.clone());
        let input = FilteredSubrequestInput {
            pipeline,
            request: current_request,
            label: current_step.as_ref(),
            iteration: state.iteration,
            deadline: state.deadline(),
            extensions,
            inherits_binding: true,
        };
        match Box::pin(self.executor.execute(input)).await {
            Ok(opened) => Ok(OpenedStep::from_executor(opened)),
            Err(error) => {
                let (error, extensions) = error.into_parts();
                Err(OpenStepError::new(error, strip_iteration_extensions(extensions)))
            },
        }
    }
}
