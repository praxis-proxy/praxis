// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration types for the iterative request router filter.

use serde::Deserialize;

use crate::FilterError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum iterations.
const DEFAULT_MAX_ITERATIONS: u32 = 10;

/// Hard ceiling on `max_iterations`.
const MAX_ITERATIONS_CEILING: u32 = 100;

/// Default overall timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000; // 30s

/// Hard ceiling on the overall iterative deadline (24 hours).
const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Maximum number of named steps.
const MAX_STEPS: usize = 20;

/// Default maximum iteration state accumulator bytes.
const DEFAULT_MAX_STATE_BYTES: usize = 52_428_800; // 50 MiB

/// Maximum iterative depth for loop prevention.
const MAX_DEPTH: u8 = 3;

// ---------------------------------------------------------------------------
// Config Types
// ---------------------------------------------------------------------------

/// Top-level config for the iterative request router.
///
/// ```yaml
/// filter: iterative_request_router
/// max_iterations: 10
/// timeout_ms: 30000
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
///       - filter: response_classifier
///         key: has_tool_calls
///         value: "true"
///         next: tool-dispatch
///       - default: true
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IterativeRequestRouterConfig {
    /// Name of the first step to execute.
    pub(crate) initial_step: String,

    /// Maximum iterations before aborting (default 10, max 100).
    #[serde(default = "default_max_iterations")]
    pub(crate) max_iterations: u32,

    /// Maximum response body bytes per sub-request.
    #[serde(default = "default_max_response_bytes")]
    pub(crate) max_response_bytes: usize,

    /// Optional cumulative byte ceiling for one logical streamed response.
    /// This is intentionally distinct from buffered per-step response limits.
    #[serde(default)]
    pub(crate) max_stream_response_bytes: Option<usize>,

    /// Maximum accumulated iteration state bytes.
    #[serde(default = "default_max_state_bytes")]
    pub(crate) max_state_bytes: usize,

    /// Per-step timeout in milliseconds. Defaults to `timeout_ms`.
    #[serde(default)]
    pub(crate) step_timeout_ms: Option<u64>,

    /// Named steps, each with filters and transition rules.
    pub(crate) steps: Vec<StepConfig>,

    /// Overall timeout in milliseconds (default 30000).
    #[serde(default = "default_timeout_ms")]
    pub(crate) timeout_ms: u64,
}

/// A named step within the iterative router.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StepConfig {
    /// Step name (must be unique within the router).
    pub(crate) name: String,

    /// Filters to execute for this step's sub-request.
    pub(crate) filters: Vec<crate::FilterEntry>,

    /// Transition rules evaluated in order. Streaming header-safe failovers
    /// run before body exposure; remaining rules run after step completion.
    #[serde(default)]
    pub(crate) on_result: Vec<StepTransition>,
}

/// A transition rule evaluated after a step completes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StepTransition {
    /// If true, this is the default (always-match) rule.
    #[serde(default)]
    pub(crate) default: bool,

    /// Filter name whose results to check.
    #[serde(default)]
    pub(crate) filter: Option<String>,

    /// Result key to match.
    #[serde(default)]
    pub(crate) key: Option<String>,

    /// Name of the step to transition to (mutually
    /// exclusive with `done`).
    #[serde(default)]
    pub(crate) next: Option<String>,

    /// Where the response originated: `upstream`, `local`,
    /// or `transport`. When unset, any origin matches.
    #[serde(default)]
    pub(crate) origin: Option<ResponseOrigin>,

    /// Response status codes to match (e.g., [502, 503, 504]).
    /// Transport failures are exposed as 502 and deadline expiry
    /// as 504.
    #[serde(default)]
    pub(crate) status: Option<Vec<u16>>,

    /// Transport error kind to match: `admission_timeout`,
    /// `circuit_open`, `connect`, `io`, `deadline_exceeded`,
    /// or `response_too_large`. `circuit_open` requires
    /// `runtime.subrequest_circuit_breaker` to be configured.
    /// Only meaningful when `origin: transport`.
    #[serde(default)]
    pub(crate) transport_error: Option<TransportErrorKind>,

    /// Result value to match.
    #[serde(default)]
    pub(crate) value: Option<String>,

    /// If true, return the current response to the client.
    #[serde(default)]
    pub(crate) done: bool,
}

/// Where the step's response originated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResponseOrigin {
    /// A real HTTP response from the upstream.
    Upstream,
    /// A locally generated response (filter rejection, validation).
    Local,
    /// A synthetic response from a transport-level failure.
    Transport,
}

/// Classification of transport-level failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransportErrorKind {
    /// All concurrency slots were busy and the admission wait timed out.
    AdmissionTimeout,
    /// The circuit breaker for the target peer is open. Requires
    /// `runtime.subrequest_circuit_breaker` to be configured.
    CircuitOpen,
    /// TCP or TLS connection establishment failed.
    Connect,
    /// Post-connect I/O error during request/response exchange.
    Io,
    /// The per-step or overall deadline expired.
    DeadlineExceeded,
    /// Response body exceeded the configured size limit.
    ResponseTooLarge,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the iterative request router config.
///
/// # Errors
///
/// Returns [`FilterError`] on invalid configuration.
#[expect(clippy::too_many_lines, reason = "validation checks are sequential")]
pub(crate) fn validate(cfg: &IterativeRequestRouterConfig) -> Result<(), FilterError> {
    if cfg.max_iterations == 0 || cfg.max_iterations > MAX_ITERATIONS_CEILING {
        return Err(format!(
            "iterative_request_router: max_iterations must be \
             1..={MAX_ITERATIONS_CEILING}, got {}",
            cfg.max_iterations
        )
        .into());
    }

    if cfg.timeout_ms == 0 {
        return Err("iterative_request_router: timeout_ms must be > 0".to_owned().into());
    }
    if cfg.timeout_ms > MAX_TIMEOUT_MS {
        return Err(format!(
            "iterative_request_router: timeout_ms must be <= {MAX_TIMEOUT_MS}, got {}",
            cfg.timeout_ms
        )
        .into());
    }

    if cfg.max_state_bytes == 0 {
        return Err("iterative_request_router: max_state_bytes must be > 0"
            .to_owned()
            .into());
    }

    if cfg.max_stream_response_bytes == Some(0) {
        return Err(
            "iterative_request_router: max_stream_response_bytes must be > 0 when configured"
                .to_owned()
                .into(),
        );
    }

    if cfg.steps.is_empty() {
        return Err("iterative_request_router: at least one step required".to_owned().into());
    }

    if cfg.steps.len() > MAX_STEPS {
        return Err(format!(
            "iterative_request_router: too many steps \
             ({} > {MAX_STEPS})",
            cfg.steps.len()
        )
        .into());
    }

    let step_names: Vec<&str> = cfg.steps.iter().map(|s| s.name.as_str()).collect();

    let mut seen = std::collections::HashSet::new();
    for name in &step_names {
        if !seen.insert(*name) {
            return Err(format!(
                "iterative_request_router: duplicate step \
                 name '{name}'"
            )
            .into());
        }
    }

    if !step_names.contains(&cfg.initial_step.as_str()) {
        return Err(format!(
            "iterative_request_router: initial_step \
             '{}' not found in steps",
            cfg.initial_step
        )
        .into());
    }

    for step in &cfg.steps {
        if step.filters.is_empty() {
            return Err(format!(
                "iterative_request_router: step '{}' \
                 has no filters",
                step.name
            )
            .into());
        }

        for entry in &step.filters {
            if entry.filter_type == "iterative_request_router" {
                return Err(format!(
                    "iterative_request_router: nested \
                     iterative_request_router not allowed in \
                     step '{}' (recursive iterative execution is \
                     not supported)",
                    step.name
                )
                .into());
            }

            if entry.filter_type == "compression" {
                return Err(format!(
                    "iterative_request_router: protocol-only filter \
                     'compression' is not supported in step '{}'",
                    step.name
                )
                .into());
            }

            if entry.branch_chains.is_some() {
                return Err(format!(
                    "iterative_request_router: branch_chains \
                     not allowed in step '{}' (use step-level \
                     on_result instead)",
                    step.name
                )
                .into());
            }
        }

        validate_transitions(&step.name, &step.on_result, &step_names)?;
    }

    validate_reachability(cfg, &step_names);

    Ok(())
}

/// Validate step transitions.
#[expect(clippy::too_many_lines, reason = "validation checks are sequential")]
fn validate_transitions(
    step_name: &str,
    transitions: &[StepTransition],
    step_names: &[&str],
) -> Result<(), FilterError> {
    let mut has_default = false;

    for (i, t) in transitions.iter().enumerate() {
        if t.default {
            if has_default {
                return Err(format!(
                    "iterative_request_router: step '{step_name}' \
                     has multiple default transitions"
                )
                .into());
            }
            has_default = true;
        }

        if t.done && t.next.is_some() {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: 'done' and 'next' are mutually \
                 exclusive"
            )
            .into());
        }

        if !t.done && t.next.is_none() && !t.default {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: must specify 'next' or 'done'"
            )
            .into());
        }

        if let Some(next) = &t.next
            && !step_names.contains(&next.as_str())
        {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                     transition references unknown step '{next}'"
            )
            .into());
        }

        if !t.default && t.filter.is_none() && t.status.is_none() && t.origin.is_none() {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: non-default transition must \
                 specify 'filter', 'status', or 'origin'"
            )
            .into());
        }

        if t.transport_error.is_some() && t.origin != Some(ResponseOrigin::Transport) {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: 'transport_error' requires \
                 'origin: transport'"
            )
            .into());
        }

        let filter_fields = [t.filter.as_deref(), t.key.as_deref(), t.value.as_deref()];
        let filter_field_count = filter_fields.iter().filter(|field| field.is_some()).count();
        if filter_field_count != 0 && filter_field_count != filter_fields.len() {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: 'filter', 'key', and 'value' must be \
                 specified together"
            )
            .into());
        }
        if filter_fields.iter().flatten().any(|field| field.is_empty()) {
            return Err(format!(
                "iterative_request_router: step '{step_name}' \
                 transition {i}: filter predicate fields must not be empty"
            )
            .into());
        }

        if let Some(statuses) = &t.status {
            if statuses.is_empty() {
                return Err(format!(
                    "iterative_request_router: step '{step_name}' \
                     transition {i}: status predicate must not be empty"
                )
                .into());
            }
            if let Some(status) = statuses.iter().find(|&&status| !(100..=599).contains(&status)) {
                return Err(format!(
                    "iterative_request_router: step '{step_name}' \
                     transition {i}: status must be 100..=599, got {status}"
                )
                .into());
            }
        }
    }

    Ok(())
}

/// Warn about unreachable steps.
fn validate_reachability(cfg: &IterativeRequestRouterConfig, step_names: &[&str]) {
    let mut reachable = std::collections::HashSet::new();
    reachable.insert(cfg.initial_step.as_str());

    let mut changed = true;
    while changed {
        changed = false;
        for step in &cfg.steps {
            if !reachable.contains(step.name.as_str()) {
                continue;
            }
            for t in &step.on_result {
                if let Some(next) = &t.next
                    && reachable.insert(next.as_str())
                {
                    changed = true;
                }
            }
        }
    }

    for name in step_names {
        if !reachable.contains(name) {
            tracing::warn!(step = name, "iterative_request_router: step is unreachable");
        }
    }
}

/// Returns the maximum iterative depth for loop prevention.
pub(crate) fn max_depth() -> u8 {
    MAX_DEPTH
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Serde default for `max_iterations`.
fn default_max_iterations() -> u32 {
    DEFAULT_MAX_ITERATIONS
}

/// Serde default for `max_response_bytes`.
fn default_max_response_bytes() -> usize {
    crate::pipeline::subrequest::default_max_response_bytes()
}

/// Serde default for `max_state_bytes`.
fn default_max_state_bytes() -> usize {
    DEFAULT_MAX_STATE_BYTES
}

/// Serde default for `timeout_ms`.
fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}
