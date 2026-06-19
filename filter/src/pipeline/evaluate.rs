// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Branch evaluation and execution for HTTP pipeline.

use std::{future::Future, pin::Pin, sync::Arc};

use tracing::{debug, trace, warn};

use super::{
    branch::{BranchOutcome, RejoinTarget, ResolvedBranch},
    check_failure_mode,
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
        ctx.current_filter_id = Some(pf.filter_id);
        let result = http_filter.on_request(ctx).await;
        ctx.current_filter_id = None;
        match result {
            Ok(FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone) => {},
            Ok(FilterAction::Reject(r)) => return Ok(FilterAction::Reject(r)),
            Err(e) => {
                check_failure_mode(http_filter.name(), e, "branch request", pf.failure_mode)?;
            },
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
            warn!(
                target,
                "discarding SkipTo from nested branch; nested control flow does not propagate"
            );
            Ok(None)
        },
        BranchOutcome::ReEnter(target) => {
            warn!(
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    async fn branch_filter_error_respects_failure_mode_open() {
        let branches = vec![make_branch(
            "open_error",
            None,
            RejoinTarget::Next,
            None,
            vec![error_pf(FailureMode::Open)],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            matches!(outcome, BranchOutcome::Continue),
            "failure_mode=open should swallow branch filter errors"
        );
        assert_eq!(ctx.current_filter_id, None, "filter id should be cleared after error");
    }

    #[tokio::test]
    async fn branch_filter_error_respects_failure_mode_closed() {
        let branches = vec![make_branch(
            "closed_error",
            None,
            RejoinTarget::Next,
            None,
            vec![error_pf(FailureMode::Closed)],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let Err(err) = evaluate_branches(&branches, &mut ctx).await else {
            panic!("failure_mode=closed should propagate branch filter errors");
        };
        assert!(
            err.to_string().contains("branch error"),
            "unexpected branch filter error: {err}"
        );
        assert_eq!(ctx.current_filter_id, None, "filter id should be cleared after error");
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
            filter_id: 100,
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
    // Filter State in Branches
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn branch_filter_can_insert_and_read_own_state() {
        let log: ObsLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let branch_pf_id = NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let branch_pf = PipelineFilter {
            filter_id: branch_pf_id,
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(BranchStatefulFilter {
                id: 42,
                log: Arc::clone(&log),
            })),
            name: None,
            response_conditions: vec![],
        };
        let branches = vec![make_branch(
            "state_branch",
            None,
            RejoinTarget::Next,
            None,
            vec![branch_pf],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        evaluate_branches(&branches, &mut ctx).await.unwrap();
        let recorded = log.lock().unwrap().clone();
        assert_eq!(recorded, vec![(42, "insert")], "branch filter should insert state");
        assert!(
            ctx.filter_state.contains_key(&branch_pf_id),
            "state should exist at the branch filter's unique id"
        );
    }

    #[tokio::test]
    async fn branch_filter_state_does_not_collide_with_parent() {
        let log: ObsLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let parent_id = NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let branch_id = NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst);
        let branch_pf = PipelineFilter {
            filter_id: branch_id,
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(BranchStatefulFilter {
                id: 99,
                log: Arc::clone(&log),
            })),
            name: None,
            response_conditions: vec![],
        };
        let branches = vec![make_branch(
            "state_branch",
            None,
            RejoinTarget::Next,
            None,
            vec![branch_pf],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.filter_state.insert(parent_id, Box::new(77_u64));
        evaluate_branches(&branches, &mut ctx).await.unwrap();
        let parent_state = ctx.filter_state.get(&parent_id).unwrap().downcast_ref::<u64>().unwrap();
        let branch_state = ctx.filter_state.get(&branch_id).unwrap().downcast_ref::<u64>().unwrap();
        assert_eq!(*parent_state, 77, "parent state should be unchanged");
        assert_eq!(*branch_state, 99, "branch filter should have its own state");
    }

    #[tokio::test]
    async fn two_branch_filters_of_same_type_get_independent_state() {
        let log: ObsLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pf_a = stateful_pf(100, &log);
        let pf_b = stateful_pf(200, &log);
        let id_a = pf_a.filter_id;
        let id_b = pf_b.filter_id;
        let branches = vec![make_branch("dual", None, RejoinTarget::Next, None, vec![pf_a, pf_b])];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        evaluate_branches(&branches, &mut ctx).await.unwrap();
        let recorded = log.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![(100, "insert"), (200, "insert")],
            "both branch filters should insert"
        );
        let state_a = ctx.filter_state.get(&id_a).unwrap().downcast_ref::<u64>().unwrap();
        let state_b = ctx.filter_state.get(&id_b).unwrap().downcast_ref::<u64>().unwrap();
        assert_eq!(*state_a, 100, "first branch filter state");
        assert_eq!(*state_b, 200, "second branch filter state");
    }

    #[tokio::test]
    async fn identity_is_none_after_branch_evaluation() {
        let branches = vec![make_branch(
            "check",
            None,
            RejoinTarget::Next,
            None,
            vec![counting_pf(Arc::new(AtomicUsize::new(0)))],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(
            ctx.current_filter_id.is_none(),
            "current_filter_id should be None after branch evaluation"
        );
    }

    #[tokio::test]
    async fn identity_is_none_after_branch_rejection() {
        let branches = vec![make_branch(
            "reject_branch",
            None,
            RejoinTarget::Next,
            None,
            vec![reject_pf(403)],
        )];
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let outcome = evaluate_branches(&branches, &mut ctx).await.unwrap();
        assert!(matches!(outcome, BranchOutcome::Reject(_)), "should reject");
        assert!(
            ctx.current_filter_id.is_none(),
            "current_filter_id should be None after branch rejection"
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

    /// HTTP filter that returns an injected error.
    struct ErrorFilter;

    #[async_trait]
    impl HttpFilter for ErrorFilter {
        fn name(&self) -> &'static str {
            "error"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Err("branch error".into())
        }
    }

    type ObsLog = Arc<std::sync::Mutex<Vec<(u64, &'static str)>>>;

    /// Filter that stores its id as typed state and records observations.
    struct BranchStatefulFilter {
        id: u64,
        log: ObsLog,
    }

    #[async_trait]
    impl HttpFilter for BranchStatefulFilter {
        fn name(&self) -> &'static str {
            "branch_stateful"
        }

        async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            ctx.insert_filter_state(self.id);
            self.log.lock().unwrap().push((self.id, "insert"));
            Ok(FilterAction::Continue)
        }
    }

    /// Monotonic counter for test filter IDs.
    static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(1000);

    /// Build a counting [`PipelineFilter`].
    fn counting_pf(counter: Arc<AtomicUsize>) -> PipelineFilter {
        PipelineFilter {
            filter_id: NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst),
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
            filter_id: NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst),
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(RejectFilter { status })),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build an erroring [`PipelineFilter`].
    fn error_pf(failure_mode: FailureMode) -> PipelineFilter {
        PipelineFilter {
            filter_id: NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst),
            branches: vec![],
            conditions: vec![],
            failure_mode,
            filter: AnyFilter::Http(Box::new(ErrorFilter)),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build a stateful [`PipelineFilter`].
    fn stateful_pf(id: u64, log: &ObsLog) -> PipelineFilter {
        PipelineFilter {
            filter_id: NEXT_TEST_ID.fetch_add(1, Ordering::SeqCst),
            branches: vec![],
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter: AnyFilter::Http(Box::new(BranchStatefulFilter {
                id,
                log: Arc::clone(log),
            })),
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
