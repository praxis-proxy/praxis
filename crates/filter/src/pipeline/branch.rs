// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Runtime branch types produced by [`build_branch`] resolution.
//!
//! These types are the runtime counterparts of the config types in
//! [`praxis_core::config`]:
//!
//! | Config type | Runtime type |
//! |---|---|
//! | [`BranchChainConfig`] | [`ResolvedBranch`] |
//! | [`BranchCondition`] | [`ResolvedBranchCondition`] |
//! | `rejoin` string | [`RejoinTarget`] enum |
//!
//! [`BranchOutcome`] is produced by [`evaluate_branches`] and drives
//! the while-loop index in [`execute_http_request`]: `Continue`
//! advances, `SkipTo` jumps forward, `ReEnter` loops back,
//! `Terminal` stops, and `Reject` aborts with an error response.
//!
//! [`build_branch`]: super::build_branch
//! [`BranchChainConfig`]: praxis_core::config::BranchChainConfig
//! [`BranchCondition`]: praxis_core::config::BranchCondition
//! [`evaluate_branches`]: super::evaluate::evaluate_branches
//! [`execute_http_request`]: super::FilterPipeline::execute_http_request

use std::sync::Arc;

use super::filter::PipelineFilter;
use crate::actions::{Rejection, StreamingTerminalResponse, TerminalResponse};

// -----------------------------------------------------------------------------
// RejoinTarget
// -----------------------------------------------------------------------------

/// Where to resume after a branch completes.
#[derive(Clone, Debug)]
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

// -----------------------------------------------------------------------------
// ResolvedBranchCondition
// -----------------------------------------------------------------------------

/// A resolved branch condition for runtime evaluation.
pub(crate) struct ResolvedBranchCondition {
    /// Filter TYPE name (from [`HttpFilter::name()`]) whose results
    /// to check. Not the user-assigned [`FilterEntry::name`].
    ///
    /// [`HttpFilter::name()`]: crate::HttpFilter::name
    /// [`FilterEntry::name`]: praxis_core::config::FilterEntry::name
    pub filter_name: Arc<str>,

    /// Result key to match.
    pub key: Arc<str>,

    /// Expected value.
    pub value: Arc<str>,
}

// -----------------------------------------------------------------------------
// ResolvedBranch
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// BranchOutcome
// -----------------------------------------------------------------------------

/// Outcome of branch evaluation.
pub(crate) enum BranchOutcome {
    /// No matching branch; advance to next filter.
    Continue,

    /// A branch filter rejected the request.
    Reject(Rejection),

    /// A branch filter produced a terminal response.
    TerminalResponse(Box<TerminalResponse>),

    /// A branch filter produced a streaming terminal response.
    StreamingTerminalResponse(Box<StreamingTerminalResponse>),

    /// Re-enter at this filter index.
    ReEnter(usize),

    /// Skip forward to this filter index.
    SkipTo(usize),

    /// A terminal branch completed; stop parent.
    Terminal,
}
