// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Branch evaluation and execution for HTTP pipeline.

use std::{future::Future, pin::Pin, sync::Arc};

use tracing::{debug, trace};

use super::{
    branch::{BranchOutcome, RejoinTarget, ResolvedBranch},
    filter::PipelineFilter,
};
use crate::{
    FilterError, actions::FilterAction, any_filter::AnyFilter, condition::should_execute, context::HttpFilterContext,
};

// -----------------------------------------------------------------------------
// Branch Evaluation
// -----------------------------------------------------------------------------

/// Evaluate all branches on a filter, executing matching ones.
pub(crate) fn evaluate_branches<'a>(
    branches: &'a [ResolvedBranch],
    ctx: &'a mut HttpFilterContext<'_>,
) -> Pin<Box<dyn Future<Output = Result<BranchOutcome, FilterError>> + Send + 'a>> {
    Box::pin(evaluate_branches_inner(branches, ctx))
}

/// Inner implementation of branch evaluation.
async fn evaluate_branches_inner(
    branches: &[ResolvedBranch],
    ctx: &mut HttpFilterContext<'_>,
) -> Result<BranchOutcome, FilterError> {
    for branch in branches {
        if !should_branch_fire(branch, ctx) {
            trace!(branch = %branch.name, "branch condition not met");
            continue;
        }

        if !check_reentrance_limit(branch, ctx) {
            continue;
        }

        debug!(
            branch = %branch.name,
            "executing branch chain"
        );

        let action = execute_branch_filters(&branch.filters, ctx).await?;

        if let FilterAction::Reject(r) = action {
            return Ok(BranchOutcome::Reject(r));
        }

        match &branch.rejoin {
            RejoinTarget::Next => {},
            RejoinTarget::Terminal => return Ok(BranchOutcome::Terminal),
            RejoinTarget::SkipTo(target) => return Ok(BranchOutcome::SkipTo(*target)),
            RejoinTarget::ReEnter(target) => {
                ctx.filter_results.clear();
                return Ok(BranchOutcome::ReEnter(*target));
            },
        }
    }

    ctx.filter_results.clear();

    Ok(BranchOutcome::Continue)
}

/// Check whether a branch's condition is met.
fn should_branch_fire(branch: &ResolvedBranch, ctx: &HttpFilterContext<'_>) -> bool {
    match &branch.condition {
        None => true,
        Some(cond) => ctx
            .filter_results
            .get(cond.filter_name.as_ref())
            .is_some_and(|rs| rs.matches(cond.key.as_ref(), cond.value.as_ref())),
    }
}

/// Check re-entrance limits, returning false if exceeded.
fn check_reentrance_limit(branch: &ResolvedBranch, ctx: &mut HttpFilterContext<'_>) -> bool {
    if let RejoinTarget::ReEnter(_) = branch.rejoin {
        let count = ctx.branch_iterations.entry(Arc::clone(&branch.name)).or_insert(0);
        *count += 1;
        if let Some(max) = branch.max_iterations
            && *count > max
        {
            debug!(
                branch = %branch.name,
                iterations = *count,
                "max iterations exceeded, falling through"
            );
            return false;
        }
    }
    true
}

/// Execute a branch's filter list.
async fn execute_branch_filters(
    filters: &[PipelineFilter],
    ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    for pf in filters {
        let http_filter = match &pf.filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };
        if !should_execute(&pf.conditions, ctx.request) {
            continue;
        }
        match http_filter.on_request(ctx).await {
            Ok(FilterAction::Continue | FilterAction::Release) => {},
            Ok(FilterAction::Reject(r)) => return Ok(FilterAction::Reject(r)),
            Err(e) => return Err(e),
        }
        if let Some(action) = dispatch_nested_outcome(&pf.branches, ctx).await? {
            return Ok(action);
        }
    }
    Ok(FilterAction::Continue)
}

/// Evaluate nested branches and convert their outcome for the parent.
///
/// Returns `Some(action)` when the parent should stop iteration
/// (terminal or reject), `None` to continue.
async fn dispatch_nested_outcome(
    branches: &[ResolvedBranch],
    ctx: &mut HttpFilterContext<'_>,
) -> Result<Option<FilterAction>, FilterError> {
    let outcome = evaluate_branches(branches, ctx).await?;
    match outcome {
        BranchOutcome::Continue => Ok(None),
        BranchOutcome::SkipTo(target) => {
            debug!(
                target,
                "discarding SkipTo from nested branch; nested control flow does not propagate"
            );
            Ok(None)
        },
        BranchOutcome::ReEnter(target) => {
            debug!(
                target,
                "discarding ReEnter from nested branch; nested control flow does not propagate"
            );
            Ok(None)
        },
        BranchOutcome::Terminal => Ok(Some(FilterAction::Continue)),
        BranchOutcome::Reject(r) => Ok(Some(FilterAction::Reject(r))),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    reason = "tests"
)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use http::Method;
    use praxis_core::config::FailureMode;

    use super::*;
    use crate::{
        FilterError, Rejection, filter::HttpFilter, pipeline::branch::ResolvedBranchCondition, results::FilterResultSet,
    };

    #[tokio::test]
    async fn unconditional_branch_fires() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "uncond",
            None,
            RejoinTarget::Next,
            None,
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "unconditional branch with Next rejoin should continue"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "unconditional branch filter should have executed"
        );
    }

    #[tokio::test]
    async fn conditional_branch_fires_on_match() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "cond_match",
            Some(("cache", "status", "hit")),
            RejoinTarget::Next,
            None,
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        ctx.filter_results.insert("cache", rs);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "matching conditional branch should continue"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "matching branch filter should have executed"
        );
    }

    #[tokio::test]
    async fn conditional_branch_skips_on_mismatch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "cond_miss",
            Some(("cache", "status", "hit")),
            RejoinTarget::Next,
            None,
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut rs = FilterResultSet::new();
        rs.set("status", "miss").unwrap();
        ctx.filter_results.insert("cache", rs);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "mismatched branch should continue"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "mismatched branch filter should not have executed"
        );
    }

    #[tokio::test]
    async fn terminal_rejoin_stops_parent() {
        let branches = vec![make_branch("term", None, RejoinTarget::Terminal, None, vec![])];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Terminal),
            "terminal branch should stop parent"
        );
    }

    #[tokio::test]
    async fn skip_to_advances_to_target() {
        let branches = vec![make_branch("skip", None, RejoinTarget::SkipTo(5), None, vec![])];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::SkipTo(5)),
            "SkipTo branch should advance to target index 5"
        );
    }

    #[tokio::test]
    async fn reenter_loops_back() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "reenter",
            None,
            RejoinTarget::ReEnter(1),
            Some(3),
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::ReEnter(1)),
            "ReEnter branch should loop back to target index"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "branch filter should execute once per evaluation"
        );
    }

    #[tokio::test]
    async fn reenter_max_iterations_exceeded_falls_through() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "limited",
            None,
            RejoinTarget::ReEnter(0),
            Some(2),
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        evaluate_branches(&branches, &mut ctx).await.unwrap();
        evaluate_branches(&branches, &mut ctx).await.unwrap();

        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "exceeded max_iterations should fall through to Continue"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "branch should execute max_iterations times then stop"
        );
    }

    #[tokio::test]
    async fn branch_filter_reject_propagates() {
        let branches = vec![make_branch(
            "reject",
            None,
            RejoinTarget::Next,
            None,
            vec![reject_pf(403)],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Reject(r) if r.status == 403),
            "branch filter rejection should propagate"
        );
    }

    #[tokio::test]
    async fn results_cleared_after_evaluation() {
        let branches: Vec<ResolvedBranch> = vec![];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut rs = FilterResultSet::new();
        rs.set("status", "hit").unwrap();
        ctx.filter_results.insert("cache", rs);
        assert!(
            !ctx.filter_results.is_empty(),
            "results should be present before evaluation"
        );
        evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            ctx.filter_results.is_empty(),
            "results should be cleared after evaluation"
        );
    }

    #[tokio::test]
    async fn multiple_branches_first_match_wins() {
        let counter_a = Arc::new(AtomicUsize::new(0));
        let counter_b = Arc::new(AtomicUsize::new(0));
        let branches = vec![
            make_branch(
                "first",
                None,
                RejoinTarget::Terminal,
                None,
                vec![counting_pf(Arc::clone(&counter_a))],
            ),
            make_branch(
                "second",
                None,
                RejoinTarget::Terminal,
                None,
                vec![counting_pf(Arc::clone(&counter_b))],
            ),
        ];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Terminal),
            "first matching branch should win"
        );
        assert_eq!(counter_a.load(Ordering::SeqCst), 1, "first branch should execute");
        assert_eq!(counter_b.load(Ordering::SeqCst), 0, "second branch should not execute");
    }

    #[tokio::test]
    async fn empty_branches_is_noop() {
        let branches: Vec<ResolvedBranch> = vec![];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "empty branches should continue"
        );
    }

    #[tokio::test]
    async fn nested_branch_terminal_propagates() {
        let inner_branch = make_branch("inner", None, RejoinTarget::Terminal, None, vec![]);
        let outer_filter = PipelineFilter {
            branches: vec![inner_branch],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(NoopFilter)),
            name: None,
            response_conditions: vec![],
        };
        let outer_branches = vec![make_branch("outer", None, RejoinTarget::Next, None, vec![outer_filter])];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&outer_branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "nested terminal should stop the branch but outer continues with Next rejoin"
        );
    }

    #[tokio::test]
    async fn conditional_branch_skips_when_filter_absent_from_results() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "absent_filter",
            Some(("cache", "status", "hit")),
            RejoinTarget::Next,
            None,
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "branch should not fire when referenced filter has no results"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "branch filter should not execute when referenced filter is absent from results"
        );
    }

    #[tokio::test]
    async fn reenter_does_not_carry_stale_results_into_conditional_branch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "cond_reenter",
            Some(("tracker", "status", "stale")),
            RejoinTarget::ReEnter(0),
            Some(3),
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut rs = FilterResultSet::new();
        rs.set("status", "stale").unwrap();
        ctx.filter_results.insert("tracker", rs);

        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::ReEnter(0)),
            "first call should fire and produce ReEnter"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "branch should execute once on first evaluation"
        );

        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "second call should not fire because stale results were cleared"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "branch should not execute again when stale result is gone"
        );
    }

    #[tokio::test]
    async fn reenter_max_iterations_at_ceiling_fires_exactly_100_times() {
        let counter = Arc::new(AtomicUsize::new(0));
        let branches = vec![make_branch(
            "ceiling",
            None,
            RejoinTarget::ReEnter(0),
            Some(100),
            vec![counting_pf(Arc::clone(&counter))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        for i in 1..=100 {
            let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
            assert!(
                matches!(outcome, BranchOutcome::ReEnter(0)),
                "iteration {i} should re-enter"
            );
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            100,
            "branch should fire exactly 100 times"
        );

        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "iteration 101 should fall through"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            100,
            "branch should not fire after max_iterations exceeded"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Noop HTTP filter for branch testing.
    struct NoopFilter;

    #[async_trait]
    impl HttpFilter for NoopFilter {
        fn name(&self) -> &'static str {
            "noop"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    /// HTTP filter that counts on_request invocations.
    struct CountFilter {
        counter: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HttpFilter for CountFilter {
        fn name(&self) -> &'static str {
            "count"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }
    }

    /// HTTP filter that rejects with a given status.
    struct RejectFilter {
        status: u16,
    }

    #[async_trait]
    impl HttpFilter for RejectFilter {
        fn name(&self) -> &'static str {
            "reject"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(Rejection::status(self.status)))
        }
    }

    /// Build a counting [`PipelineFilter`].
    fn counting_pf(counter: Arc<AtomicUsize>) -> PipelineFilter {
        PipelineFilter {
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(CountFilter { counter })),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build a rejecting [`PipelineFilter`].
    fn reject_pf(status: u16) -> PipelineFilter {
        PipelineFilter {
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(RejectFilter { status })),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build a [`ResolvedBranch`] for testing.
    fn make_branch(
        name: &str,
        condition: Option<(&str, &str, &str)>,
        rejoin: RejoinTarget,
        max_iterations: Option<u32>,
        filters: Vec<PipelineFilter>,
    ) -> ResolvedBranch {
        ResolvedBranch {
            condition: condition.map(|(filter, key, value)| ResolvedBranchCondition {
                filter_name: Arc::from(filter),
                key: Arc::from(key),
                value: Arc::from(value),
            }),
            filters,
            max_iterations,
            name: Arc::from(name),
            rejoin,
        }
    }
}
