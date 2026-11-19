// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pipeline filter: a filter with its conditions and branch chains.
//!
//! [`PipelineFilter`] wraps an [`AnyFilter`] together with its
//! request/response conditions, failure mode, optional user name,
//! and resolved branch chains. It is the unit of execution in the
//! pipeline.
//!
//! [`AnyFilter`]: crate::any_filter::AnyFilter

use std::{fmt, sync::Arc};

use praxis_core::config::{Condition, FailureMode, ResponseCondition};

use super::branch::ResolvedBranch;
use crate::any_filter::AnyFilter;

// -----------------------------------------------------------------------------
// PipelineFilter
// -----------------------------------------------------------------------------

/// A filter with its conditions and branches.
pub(crate) struct PipelineFilter {
    /// Optional user-assigned name for rejoin targeting.
    ///
    /// From [`FilterEntry::name`] in YAML config (e.g.,
    /// `name: routing`). Distinct from `self.filter.name()`, which
    /// returns the filter TYPE name (e.g., `"router"`).
    ///
    /// - `on_result.filter` in branch conditions matches the TYPE name
    /// - `rejoin` targets match this USER name
    ///
    /// [`FilterEntry::name`]: praxis_core::config::FilterEntry::name
    pub(crate) name: Option<Arc<str>>,

    /// Branches evaluated after this filter.
    pub(crate) branches: Vec<ResolvedBranch>,

    /// Request-phase conditions.
    pub(crate) conditions: Vec<Condition>,

    /// Per-filter failure mode (open or closed).
    pub(crate) failure_mode: FailureMode,

    /// The filter implementation.
    pub(crate) filter: AnyFilter,

    /// Unique invocation identity for per-request state storage.
    ///
    /// Assigned monotonically during pipeline build across all
    /// filters including branch sub-chains. Used as the key in
    /// [`HttpFilterContext::filter_state`] so that multiple
    /// instances of the same filter type (and filters in
    /// different branch levels) get independent state.
    ///
    /// [`HttpFilterContext::filter_state`]: crate::HttpFilterContext::filter_state
    pub(crate) filter_id: usize,

    /// Whether this filter type is [`SecurityClass::Security`].
    ///
    /// Stamped at pipeline build from the registry after `create`
    /// succeeds. Config-time checks (fail-open, conditions, `SkipTo`,
    /// `Terminal` rejoin) use this bit instead of a hardcoded name list.
    ///
    /// [`SecurityClass::Security`]: crate::SecurityClass::Security
    pub(crate) is_security: bool,

    /// Response-phase conditions.
    pub(crate) response_conditions: Vec<ResponseCondition>,
}

impl fmt::Debug for PipelineFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipelineFilter")
            .field("filter", &self.filter.name())
            .field("name", &self.name)
            .field("branches", &self.branches.len())
            .field("conditions", &self.conditions.len())
            .finish()
    }
}

/// Built-in filters that always answer the request themselves.
pub(super) const ANSWERING_FILTERS: &[&str] = &["iterative_request_router", "redirect", "static_response"];

impl PipelineFilter {
    /// Whether this filter can end a request in its request phase, before a
    /// later filter runs: it declares it [may end the request], answers
    /// requests, declares terminal responses, or a filter in one of its
    /// branches can.
    ///
    /// [may end the request]: crate::HttpFilter::may_end_request
    pub(crate) fn can_end_request(&self) -> bool {
        matches!(&self.filter, AnyFilter::Http(filter) if filter.may_end_request() || filter.produces_terminal_response())
            || ANSWERING_FILTERS.contains(&self.filter.name())
            || self
                .branches
                .iter()
                .any(|branch| branch.filters.iter().any(Self::can_end_request))
    }

    /// Create a `PipelineFilter` with no branches or name.
    pub(crate) fn new(
        filter_id: usize,
        filter: AnyFilter,
        conditions: Vec<Condition>,
        response_conditions: Vec<ResponseCondition>,
    ) -> Self {
        Self {
            name: None,
            branches: Vec::new(),
            conditions,
            failure_mode: FailureMode::default(),
            filter,
            filter_id,
            is_security: false,
            response_conditions,
        }
    }

    /// Whether any request condition on this filter gates on `bound_upstream`.
    ///
    /// Only request-phase conditions are consulted: a response-phase
    /// condition always runs after routing, so the binding it reads is
    /// guaranteed to exist. Used both by binding validation and by
    /// [`effective_request_body_phase`] to infer whether a dual-phase body
    /// hook defers to the bound-upstream barrier.
    ///
    /// [`effective_request_body_phase`]: super::body::effective_request_body_phase
    pub(crate) fn has_bound_upstream_condition(&self) -> bool {
        self.conditions.iter().any(|condition| {
            let (Condition::When(m) | Condition::Unless(m)) = condition;
            m.bound_upstream.is_some()
        })
    }
}
