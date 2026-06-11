// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Branch chain runtime types for pipeline execution.

use std::sync::Arc;

use super::filter::PipelineFilter;
use crate::actions::Rejection;

// ---------------------------------------------------------------------------
// RejoinTarget
// ---------------------------------------------------------------------------

/// Where to resume after a branch completes.
#[derive(Debug, Clone)]
pub(crate) enum RejoinTarget {
    /// Continue with the next filter (default).
    Next,

    /// Stop the parent chain entirely.
    Terminal,

    /// Skip forward to a filter at this index in the
    /// parent pipeline.
    SkipTo(usize),

    /// Re-enter at a filter at this index. Requires
    /// iteration tracking.
    ReEnter(usize),
}

// ---------------------------------------------------------------------------
// ResolvedBranchCondition
// ---------------------------------------------------------------------------

/// A resolved branch condition for runtime evaluation.
pub(crate) struct ResolvedBranchCondition {
    /// Filter name whose results to check.
    pub filter_name: Arc<str>,

    /// Result key to match.
    pub key: Arc<str>,

    /// Expected value.
    pub value: Arc<str>,
}

// ---------------------------------------------------------------------------
// ResolvedBranch
// ---------------------------------------------------------------------------

/// A resolved branch chain ready for execution.
pub(crate) struct ResolvedBranch {
    /// Globally unique branch name.
    pub name: Arc<str>,

    /// Result-based condition (None = unconditional).
    pub condition: Option<ResolvedBranchCondition>,

    /// Resolved filters from all referenced chains.
    pub filters: Vec<PipelineFilter>,

    /// Max loop iterations (only for [`ReEnter`]).
    ///
    /// [`ReEnter`]: RejoinTarget::ReEnter
    pub max_iterations: Option<u32>,

    /// Where to resume after the branch.
    pub rejoin: RejoinTarget,
}

// ---------------------------------------------------------------------------
// BranchOutcome
// ---------------------------------------------------------------------------

/// Outcome of branch evaluation.
pub(crate) enum BranchOutcome {
    /// No matching branch; advance to next filter.
    Continue,

    /// A branch filter rejected the request.
    Reject(Rejection),

    /// Re-enter at this filter index.
    ReEnter(usize),

    /// Skip forward to this filter index.
    SkipTo(usize),

    /// A terminal branch completed; stop parent.
    Terminal,
}
