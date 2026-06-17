// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pipeline filter: a filter with its conditions and branch chains.

use std::{fmt, sync::Arc};

use praxis_core::config::{Condition, FailureMode, ResponseCondition};

use super::branch::ResolvedBranch;
use crate::any_filter::AnyFilter;

// ---------------------------------------------------------------------------
// PipelineFilter
// ---------------------------------------------------------------------------

/// A filter with its conditions and branches.
///
/// Replaces the `ConditionalFilter` tuple alias with a
/// named struct that also carries branch chains and an
/// optional user-assigned name.
pub(crate) struct PipelineFilter {
    /// Optional user-assigned name for rejoin targeting.
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
    /// instances of the same filter type — and filters in
    /// different branch levels — get independent state.
    ///
    /// [`HttpFilterContext::filter_state`]: crate::HttpFilterContext::filter_state
    pub(crate) filter_id: usize,

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

impl PipelineFilter {
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
            response_conditions,
        }
    }
}
