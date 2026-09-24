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
//! [`record_executed_branch_filter`] marks the branch filters that ran
//! `on_request` in the request context, so the response phase can pair
//! their `on_response`.
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

// -----------------------------------------------------------------------------
// Executed Branch Filters
// -----------------------------------------------------------------------------

/// Whether the branch filter `filter_id` is marked in `executed`, the
/// request context's [`executed_branch_filters`] record.
///
/// [`executed_branch_filters`]: crate::HttpFilterContext::executed_branch_filters
pub(crate) fn branch_filter_executed(executed: &[bool], filter_id: usize) -> bool {
    executed.get(filter_id) == Some(&true)
}

/// Mark the branch filter `filter_id` in `executed`, the request context's
/// [`executed_branch_filters`] record, as having run `on_request`.
///
/// The record is indexed by the pipeline's dense `filter_id`s and grows only
/// as far as the highest id marked, so a request that runs no branch filter
/// leaves it empty and marking the same filter again (re-entrance) is a no-op.
///
/// [`executed_branch_filters`]: crate::HttpFilterContext::executed_branch_filters
pub(crate) fn record_executed_branch_filter(executed: &mut Vec<bool>, filter_id: usize) {
    if executed.len() <= filter_id {
        executed.resize(filter_id.saturating_add(1), false);
    }
    if let Some(ran) = executed.get_mut(filter_id) {
        *ran = true;
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_record_contains_nothing() {
        assert!(
            !branch_filter_executed(&[], 0),
            "an empty record means no branch filter ran"
        );
    }

    #[test]
    fn record_marks_only_recorded_filters() {
        let mut executed = Vec::new();

        record_executed_branch_filter(&mut executed, 7);
        record_executed_branch_filter(&mut executed, 3);
        record_executed_branch_filter(&mut executed, 7);

        assert_eq!(
            [3, 5, 7, 8].map(|id| branch_filter_executed(&executed, id)),
            [true, false, true, false],
            "only recorded filters match, including past the highest recorded id"
        );
        assert_eq!(executed.len(), 8, "recording again must not grow the record");
    }
}
