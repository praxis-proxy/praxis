// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Public snapshot of a resolved [`FilterPipeline`] for admin inspection.

use praxis_core::config::{Condition, FailureMode, ResponseCondition};
use serde::Serialize;

use super::{
    branch::{RejoinTarget, ResolvedBranch, ResolvedBranchCondition},
    filter::PipelineFilter,
};
use crate::{
    FilterPipeline,
    any_filter::AnyFilter,
    body::{BodyAccess, BodyMode},
    filter::HttpFilter,
};

// -----------------------------------------------------------------------------
// Public DTOs
// -----------------------------------------------------------------------------

/// One resolved filter (and nested branches) for admin JSON.
#[derive(Clone, Debug, Serialize)]
pub struct FilterIntrospection {
    /// Zero-based index in the enclosing filter list.
    pub index: usize,
    /// Filter type name from [`AnyFilter::name`].
    pub filter: String,
    /// Optional user-assigned name for rejoin targeting.
    pub name: Option<String>,
    /// Request-phase conditions.
    pub conditions: Vec<Condition>,
    /// Response-phase conditions.
    pub response_conditions: Vec<ResponseCondition>,
    /// Per-filter failure mode.
    pub failure_mode: FailureMode,
    /// Derived phase participation.
    pub phases: Vec<&'static str>,
    /// HTTP request-body access/mode; omitted for TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<BodyAccessInfo>,
    /// HTTP response-body access/mode; omitted for TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<BodyAccessInfo>,
    /// Branch points after this filter.
    pub branches: Vec<BranchIntrospection>,
}

/// Body access and delivery mode for an HTTP filter phase.
#[derive(Clone, Debug, Serialize)]
pub struct BodyAccessInfo {
    /// Access level (`none` / `read_only` / `read_write`).
    pub access: &'static str,
    /// Delivery mode (`stream` / `stream_buffer` / `size_limit`).
    pub mode: &'static str,
    /// Optional byte limit for buffered / size-limited modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}

/// One resolved branch chain.
#[derive(Clone, Debug, Serialize)]
pub struct BranchIntrospection {
    /// Globally unique branch name.
    pub name: String,
    /// Result-based condition; `null` when unconditional.
    pub condition: Option<BranchConditionInfo>,
    /// Nested filters when the branch matches.
    pub filters: Vec<FilterIntrospection>,
    /// Max re-enter iterations when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_iterations: Option<u32>,
    /// Rejoin target (`next` / `terminal` / named filter).
    pub rejoin: String,
}

/// Branch `on_result` condition with config-aligned field names.
#[derive(Clone, Debug, Serialize)]
pub struct BranchConditionInfo {
    /// Filter type name whose results are inspected.
    pub filter: String,
    /// Result key.
    pub key: String,
    /// Expected result value (YAML `result`).
    pub result: String,
}

// -----------------------------------------------------------------------------
// FilterPipeline API
// -----------------------------------------------------------------------------

#[expect(
    clippy::multiple_inherent_impl,
    reason = "pipeline concerns are split across modules"
)]
impl FilterPipeline {
    /// Public introspection snapshot of the resolved filter chain.
    pub fn introspection(&self) -> Vec<FilterIntrospection> {
        snapshot_filters(&self.filters)
    }
}

// -----------------------------------------------------------------------------
// Walkers
// -----------------------------------------------------------------------------

/// Snapshot an ordered filter list.
fn snapshot_filters(filters: &[PipelineFilter]) -> Vec<FilterIntrospection> {
    filters
        .iter()
        .enumerate()
        .map(|(index, pf)| snapshot_filter(index, pf, filters))
        .collect()
}

/// Snapshot one filter with branch rejoin labels against `siblings`.
fn snapshot_filter(index: usize, pf: &PipelineFilter, siblings: &[PipelineFilter]) -> FilterIntrospection {
    let (phases, request_body, response_body) = phase_and_body_info(pf);
    FilterIntrospection {
        index,
        filter: pf.filter.name().to_owned(),
        name: pf.name.as_ref().map(ToString::to_string),
        conditions: pf.conditions.clone(),
        response_conditions: pf.response_conditions.clone(),
        failure_mode: pf.failure_mode,
        phases,
        request_body,
        response_body,
        branches: pf
            .branches
            .iter()
            .map(|branch| snapshot_branch(branch, siblings))
            .collect(),
    }
}

/// HTTP phases + body info, or TCP `connect`/`disconnect` with no body fields.
fn phase_and_body_info(pf: &PipelineFilter) -> (Vec<&'static str>, Option<BodyAccessInfo>, Option<BodyAccessInfo>) {
    match &pf.filter {
        AnyFilter::Http(f) => {
            let req_access = HttpFilter::request_body_access(f.as_ref());
            let resp_access = HttpFilter::response_body_access(f.as_ref());
            let req_mode = HttpFilter::request_body_mode(f.as_ref());
            let resp_mode = HttpFilter::response_body_mode(f.as_ref());
            (
                http_phases(req_access, resp_access, &pf.response_conditions),
                Some(body_info(req_access, req_mode)),
                Some(body_info(resp_access, resp_mode)),
            )
        },
        AnyFilter::Tcp(_) => (vec!["connect", "disconnect"], None, None),
    }
}

/// Snapshot a branch including nested filters.
fn snapshot_branch(branch: &ResolvedBranch, parent_siblings: &[PipelineFilter]) -> BranchIntrospection {
    BranchIntrospection {
        name: branch.name.to_string(),
        condition: branch.condition.as_ref().map(branch_condition_info),
        filters: snapshot_filters(&branch.filters),
        max_iterations: branch.max_iterations,
        rejoin: rejoin_label(&branch.rejoin, parent_siblings),
    }
}

/// Map a resolved branch condition to the admin JSON shape.
fn branch_condition_info(cond: &ResolvedBranchCondition) -> BranchConditionInfo {
    BranchConditionInfo {
        filter: cond.filter_name.to_string(),
        key: cond.key.to_string(),
        result: cond.value.to_string(),
    }
}

/// HTTP phase participation heuristic for v1.
fn http_phases(
    request_body: BodyAccess,
    response_body: BodyAccess,
    response_conditions: &[ResponseCondition],
) -> Vec<&'static str> {
    let mut phases = vec!["request"];
    if request_body != BodyAccess::None {
        phases.push("request_body");
    }
    if !response_conditions.is_empty() || response_body != BodyAccess::None {
        phases.push("response");
    }
    if response_body != BodyAccess::None {
        phases.push("response_body");
    }
    phases
}

/// Convert body trait values into a serde-friendly record.
fn body_info(access: BodyAccess, mode: BodyMode) -> BodyAccessInfo {
    let (mode_name, max_bytes) = match mode {
        BodyMode::Stream => ("stream", None),
        BodyMode::StreamBuffer { max_bytes } => ("stream_buffer", max_bytes),
        BodyMode::SizeLimit { max_bytes } => ("size_limit", Some(max_bytes)),
    };
    BodyAccessInfo {
        access: match access {
            BodyAccess::None => "none",
            BodyAccess::ReadOnly => "read_only",
            BodyAccess::ReadWrite => "read_write",
        },
        mode: mode_name,
        max_bytes,
    }
}

/// Operator-readable rejoin target.
fn rejoin_label(rejoin: &RejoinTarget, siblings: &[PipelineFilter]) -> String {
    match rejoin {
        RejoinTarget::Next => "next".to_owned(),
        RejoinTarget::Terminal => "terminal".to_owned(),
        RejoinTarget::SkipTo(idx) | RejoinTarget::ReEnter(idx) => siblings
            .get(*idx)
            .and_then(|pf| pf.name.as_ref())
            .map_or_else(|| format!("index:{idx}"), ToString::to_string),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::{FilterRegistry, body::BodyAccess};

    #[test]
    fn empty_pipeline_introspection() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&mut [], &registry).expect("empty pipeline builds");
        let snap = pipeline.introspection();
        assert!(snap.is_empty(), "empty pipeline should introspect to []");
    }

    #[test]
    fn body_info_maps_access_and_mode() {
        let info = body_info(BodyAccess::ReadOnly, BodyMode::StreamBuffer { max_bytes: Some(64) });
        assert_eq!(info.access, "read_only");
        assert_eq!(info.mode, "stream_buffer");
        assert_eq!(info.max_bytes, Some(64));
    }

    #[test]
    fn http_phases_include_response_when_conditions_present() {
        use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

        let conditions = vec![ResponseCondition::When(ResponseConditionMatch {
            status: Some(vec![500]),
            headers: None,
        })];
        let phases = http_phases(BodyAccess::None, BodyAccess::None, &conditions);
        assert_eq!(phases, ["request", "response"]);
    }

    #[test]
    fn http_phases_always_include_request() {
        let phases = http_phases(BodyAccess::None, BodyAccess::None, &[]);
        assert_eq!(phases, ["request"]);
    }
}
