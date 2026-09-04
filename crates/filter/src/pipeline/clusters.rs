// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Cluster name extraction from filter pipeline capabilities.
//!
//! Collects the set of cluster names declared by cluster-selecting
//! filters (routers, endpoint selectors) and load-balancer filters.
//! The ordering checks in [`checks`] compare these two sets to detect
//! misaligned or orphaned cluster references at build time.
//!
//! [`checks`]: super::checks

use std::collections::HashSet;

use super::filter::PipelineFilter;

// -----------------------------------------------------------------------------
// Cluster Extraction
// -----------------------------------------------------------------------------

/// Cluster selectors declare every cluster name they may assign.
///
/// Recurses into branch sub-chains: a cluster selected inside a branch is
/// assigned to `ctx.cluster` when the branch runs, so it must be checked
/// against the load balancers just like a top-level selection — otherwise a
/// branch selecting an undefined cluster passes the build and 502s at request
/// time.
pub(super) fn extract_selected_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    let mut out = HashSet::new();
    for pf in filters {
        out.extend(pf.filter.selected_clusters());
        for branch in &pf.branches {
            out.extend(extract_selected_clusters(&branch.filters));
        }
    }
    out
}

/// Load-balancers declare the cluster names they can consume.
///
/// Recurses into branch sub-chains for the same reason as
/// [`extract_selected_clusters`].
pub(super) fn extract_lb_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    let mut out = HashSet::new();
    for pf in filters {
        out.extend(pf.filter.load_balancer_clusters());
        for branch in &pf.branches {
            out.extend(extract_lb_clusters(&branch.filters));
        }
    }
    out
}

/// Cluster names selected by this level's filters only (no branch recursion).
///
/// Branch-level demands are checked per branch with that branch's own
/// availability; see `check_misaligned_clusters`.
pub(super) fn level_selected_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    filters.iter().flat_map(|pf| pf.filter.selected_clusters()).collect()
}

/// Cluster names provided by load balancers guaranteed to run for every
/// request that reaches this level.
///
/// This is this level's own load balancers plus those inside *unconditional*
/// branches (`condition: None`) hung off *unconditional* host filters (no
/// filter conditions), recursively. Such a branch always fires and its filters
/// run against the same `ctx`, so a load balancer inside it sets `ctx.upstream`
/// for the enclosing selection exactly like a top-level one — an inlined chain
/// in all but syntax. A *conditional* branch (or one on a conditional host) is
/// excluded: it may not run, so its load balancer cannot be relied on to serve
/// an enclosing selection.
///
/// The branch's rejoin target is irrelevant here: whether it rejoins `Next` or
/// `Terminal`, the branch's own filters still run and set `ctx.upstream` before
/// control leaves the branch; rejoin only governs which *later* top-level
/// filters run.
pub(super) fn reachable_lb_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    let mut out = HashSet::new();
    for pf in filters {
        out.extend(pf.filter.load_balancer_clusters());
        if pf.conditions.is_empty() {
            for branch in &pf.branches {
                if branch.condition.is_none() {
                    out.extend(reachable_lb_clusters(&branch.filters));
                }
            }
        }
    }
    out
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
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::pipeline::test_filters::{lb_filter, noop_filter, selector_filter};

    #[test]
    fn extracts_selected_clusters() {
        let filters = vec![selector_filter("router", &["web", "api"])];
        let clusters = extract_selected_clusters(&filters);
        assert_eq!(clusters.len(), 2, "should extract two clusters");
        assert!(clusters.contains("web"), "should contain 'web'");
        assert!(clusters.contains("api"), "should contain 'api'");
    }

    #[test]
    fn extracts_lb_clusters() {
        let filters = vec![lb_filter(&["web", "api"])];
        let clusters = extract_lb_clusters(&filters);
        assert_eq!(clusters.len(), 2, "should extract two clusters");
        assert!(clusters.contains("web"), "should contain 'web'");
        assert!(clusters.contains("api"), "should contain 'api'");
    }

    #[test]
    fn skips_non_cluster_selecting_entries() {
        let filters = vec![noop_filter("ip_acl")];
        let clusters = extract_selected_clusters(&filters);
        assert!(
            clusters.is_empty(),
            "non-cluster-selecting entries should yield no clusters"
        );
    }

    #[test]
    fn merges_selected_clusters_from_multiple_filters() {
        let filters = vec![
            selector_filter("router", &["web"]),
            selector_filter("custom_selector", &["weather-backend"]),
        ];
        let clusters = extract_selected_clusters(&filters);
        assert_eq!(clusters.len(), 2, "should merge selected clusters");
        assert!(clusters.contains("web"), "should contain router cluster");
        assert!(
            clusters.contains("weather-backend"),
            "should contain custom selector cluster"
        );
    }

    #[test]
    fn skips_non_load_balancer_entries() {
        let filters = vec![selector_filter("router", &["web"])];
        let clusters = extract_lb_clusters(&filters);
        assert!(clusters.is_empty(), "non-LB entries should yield no clusters");
    }

    #[test]
    fn deduplicates_selected_clusters() {
        let filters = vec![
            selector_filter("router", &["web"]),
            selector_filter("custom_selector", &["web"]),
        ];
        let clusters = extract_selected_clusters(&filters);
        assert_eq!(clusters.len(), 1, "duplicate cluster names should be deduplicated");
        assert!(clusters.contains("web"), "should contain 'web'");
    }

    #[test]
    fn recurses_into_branch_subchains() {
        use std::sync::Arc;

        use crate::pipeline::branch::{RejoinTarget, ResolvedBranch};

        let mut host = noop_filter("headers");
        host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![selector_filter("router", &["branch-cluster"])],
            max_iterations: None,
            name: Arc::from("br"),
            rejoin: RejoinTarget::Terminal,
        }];
        let selected = extract_selected_clusters(&[host]);
        assert!(
            selected.contains("branch-cluster"),
            "a cluster selected inside a branch sub-chain must be collected"
        );
    }

    #[test]
    fn empty_entries_yields_empty() {
        let filters = vec![];
        assert!(
            extract_selected_clusters(&filters).is_empty(),
            "empty input should yield empty set"
        );
        assert!(
            extract_lb_clusters(&filters).is_empty(),
            "empty input should yield empty set"
        );
    }

    use std::sync::Arc;

    use praxis_core::config::{Condition, ConditionMatch};

    use crate::pipeline::branch::{RejoinTarget, ResolvedBranch, ResolvedBranchCondition};

    /// Build a host filter carrying one branch (condition controls reachability).
    fn host_with(condition: Option<ResolvedBranchCondition>, branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        let mut host = noop_filter("headers");
        host.branches = vec![ResolvedBranch {
            condition,
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from("br"),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    fn cond() -> ResolvedBranchCondition {
        ResolvedBranchCondition {
            filter_name: Arc::from("classifier"),
            key: Arc::from("kind"),
            value: Arc::from("premium"),
        }
    }

    #[test]
    fn reachable_includes_this_levels_load_balancers() {
        let filters = vec![lb_filter(&["web", "api"])];
        let clusters = reachable_lb_clusters(&filters);
        assert!(clusters.contains("web") && clusters.contains("api"));
    }

    #[test]
    fn reachable_folds_unconditional_branch_lb() {
        // An unconditional branch on an unconditional host always runs, so its
        // LB is reachable for the enclosing scope.
        let filters = vec![host_with(None, vec![lb_filter(&["x"])])];
        assert!(
            reachable_lb_clusters(&filters).contains("x"),
            "unconditional branch LB must be reachable"
        );
    }

    #[test]
    fn reachable_excludes_conditional_branch_lb() {
        // A conditional branch may not fire, so its LB is not reachable.
        let filters = vec![host_with(Some(cond()), vec![lb_filter(&["x"])])];
        assert!(
            !reachable_lb_clusters(&filters).contains("x"),
            "conditional branch LB must not be reachable"
        );
    }

    #[test]
    fn reachable_excludes_branch_lb_on_conditional_host() {
        // Even an unconditional branch is unreachable when its host filter is
        // conditional (the host, and thus the branch, may be skipped).
        let mut host = noop_filter("headers");
        host.conditions = vec![Condition::When(ConditionMatch {
            path: None,
            path_prefix: Some("/x".to_owned()),
            methods: None,
            headers: None,
        })];
        host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![lb_filter(&["x"])],
            max_iterations: None,
            name: Arc::from("br"),
            rejoin: RejoinTarget::Next,
        }];
        assert!(
            !reachable_lb_clusters(&[host]).contains("x"),
            "a branch on a conditional host must not be reachable"
        );
    }

    #[test]
    fn reachable_folds_nested_unconditional_branches() {
        let inner = host_with(None, vec![lb_filter(&["deep"])]);
        let outer = host_with(None, vec![inner]);
        assert!(
            reachable_lb_clusters(&[outer]).contains("deep"),
            "nested unconditional branch LBs must fold up"
        );
    }

    #[test]
    fn reachable_stops_folding_at_conditional_nesting() {
        // Outer unconditional, inner conditional: the inner LB is unreachable.
        let inner = host_with(Some(cond()), vec![lb_filter(&["deep"])]);
        let outer = host_with(None, vec![inner]);
        assert!(
            !reachable_lb_clusters(&[outer]).contains("deep"),
            "a conditional nested branch stops the reachability fold"
        );
    }
}
