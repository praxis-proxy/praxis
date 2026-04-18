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
    /// Branches evaluated after this filter.
    pub branches: Vec<ResolvedBranch>,

    /// Request-phase conditions.
    pub conditions: Vec<Condition>,

    /// Per-filter failure mode (open or closed).
    pub failure_mode: FailureMode,

    /// The filter implementation.
    pub filter: AnyFilter,

    /// Optional user-assigned name for rejoin targeting.
    pub name: Option<Arc<str>>,

    /// Response-phase conditions.
    pub response_conditions: Vec<ResponseCondition>,
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
        filter: AnyFilter,
        conditions: Vec<Condition>,
        response_conditions: Vec<ResponseCondition>,
    ) -> Self {
        Self {
            branches: Vec::new(),
            conditions,
            failure_mode: FailureMode::default(),
            filter,
            name: None,
            response_conditions,
        }
    }
}
