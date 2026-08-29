// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Ordering validation checks for filter pipelines.
//!
//! Detects structural misconfigurations that would cause runtime
//! failures: load balancers without a preceding cluster selector,
//! unreachable filters behind unconditional static responses,
//! conditional security filters (bypass risk), duplicate routers or
//! load balancers, and cluster name mismatches. Each check is
//! individually skippable via [`SkipPipelineChecks`].
//!
//! Called by [`FilterPipeline::ordering_errors`] at startup and on
//! dynamic config reload.
//!
//! [`SkipPipelineChecks`]: praxis_core::config::SkipPipelineChecks
//! [`FilterPipeline::ordering_errors`]: super::FilterPipeline::ordering_errors

use praxis_core::config::{FailureMode, FilterEntry};
use tracing::warn;

use super::{branch::RejoinTarget, filter::PipelineFilter};
use crate::{any_filter::AnyFilter, body::BodyAccess};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Filters classified as security-critical (bypass risk when conditional).
const SECURITY_FILTERS: &[&str] = &[
    #[cfg(feature = "basic-auth-filter")]
    "basic_auth",
    "cors",
    "credential_injection",
    "csrf",
    "forwarded_headers",
    "guardrails",
    "ip_acl",
    "peer_identity_trust",
    #[cfg(feature = "policy-engine")]
    "policy",
    "rate_limit",
];

/// Filters that rewrite the request path.
const REWRITE_FILTERS: &[&str] = &["path_rewrite", "url_rewrite"];

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// `load_balancer` without a filter that sets `ctx.cluster` will fail
/// every request with "no cluster selected".
pub(super) fn check_lb_without_cluster_selector(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, filter) in filters.iter().enumerate() {
        if filter.filter.name() == "load_balancer"
            && !filters
                .get(..i)
                .unwrap_or_default()
                .iter()
                .any(|f| f.filter.selects_cluster())
        {
            errors.push(
                "load_balancer without a preceding router \
                 or cluster-selecting filter; requests will \
                 fail with 'no cluster selected'"
                    .to_owned(),
            );
            return;
        }
    }
}

/// Unconditional `static_response` blocking subsequent filters.
pub(super) fn check_unconditional_static_response(
    names: &[&str],
    filters: &[PipelineFilter],
    errors: &mut Vec<String>,
) {
    for (i, name) in names.iter().enumerate() {
        if *name == "static_response" && i + 1 < names.len() {
            let unconditional = filters.get(i).is_some_and(|pf| pf.conditions.is_empty());
            if unconditional {
                errors.push(format!(
                    "unconditional static_response at \
                     position {i} makes subsequent filters \
                     unreachable: {}",
                    names.get(i + 1..).unwrap_or_default().join(", ")
                ));
            }
        }
    }
}

/// Security filters with request conditions (bypass risk).
pub(super) fn check_conditional_security(names: &[&str], filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, (name, pf)) in names.iter().zip(filters).enumerate() {
        if SECURITY_FILTERS.contains(name) && !pf.conditions.is_empty() {
            errors.push(format!(
                "security filter '{name}' at position {i} has \
                 request conditions; it will be bypassed for \
                 non-matching requests"
            ));
        }
    }
}

/// Security filters with `failure_mode: open` (bypass risk on error).
///
/// When `allow` is `true`, the error is demoted to a warning.
pub(super) fn check_open_security_filters(
    names: &[&str],
    filters: &[PipelineFilter],
    allow: bool,
    errors: &mut Vec<String>,
) {
    for (i, (name, pf)) in names.iter().zip(filters).enumerate() {
        if SECURITY_FILTERS.contains(name) && pf.failure_mode == FailureMode::Open {
            let msg = format!(
                "security filter '{name}' at position {i} has \
                 failure_mode: open; runtime errors will bypass \
                 security enforcement"
            );
            if allow {
                warn!(
                    filter = %name,
                    "{msg}; allowed by insecure_options.allow_open_security_filters"
                );
            } else {
                errors.push(msg);
            }
        }
    }
}

/// Duplicate router filters.
pub(super) fn check_duplicate_routers(names: &[&str], errors: &mut Vec<String>) {
    let router_count = names.iter().filter(|n| **n == "router").count();
    if router_count > 1 {
        errors.push(format!(
            "multiple router filters in chain ({router_count}); \
             only the last one's cluster selection will take effect"
        ));
    }
}

/// Duplicate `load_balancer` filters.
pub(super) fn check_duplicate_load_balancers(names: &[&str], errors: &mut Vec<String>) {
    let lb_count = names.iter().filter(|n| **n == "load_balancer").count();
    if lb_count > 1 {
        errors.push(format!(
            "multiple load_balancer filters in chain ({lb_count}); \
             only the last one's upstream selection will take effect"
        ));
    }
}

/// Multiple cluster-selecting filters before the same load balancer
/// compete for `ctx.cluster`; the later one silently overwrites the
/// earlier selection.
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_conflicting_cluster_selectors(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, filter) in filters.iter().enumerate() {
        if filter.filter.name() != "load_balancer" {
            continue;
        }

        let mut saw_router = false;
        let selectors: Vec<&str> = filters[..i]
            .iter()
            .filter(|f| f.filter.selects_cluster())
            .filter_map(|f| {
                let name = f.filter.name();
                if name == "router" {
                    if saw_router {
                        return None;
                    }
                    saw_router = true;
                }
                Some(name)
            })
            .collect();

        if selectors.len() > 1 {
            errors.push(format!(
                "pipeline contains multiple cluster-selecting filters \
                 before load_balancer ({}); only the last one's cluster \
                 selection will take effect",
                selectors.join(", ")
            ));
            return;
        }
    }
}

/// Every cluster selected by a pipeline filter must be defined by the
/// load balancer that will consume `ctx.cluster`.
pub(super) fn check_misaligned_clusters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    // Reachability-aware alignment: a top-level selection must be served by a
    // load balancer that is *guaranteed to run* for it. That is this level's
    // own load balancers plus those inside unconditional branches on
    // unconditional hosts (which always run and share `ctx`, so they serve an
    // enclosing selection just like a top-level load balancer — see
    // `reachable_lb_clusters`). A *conditional* branch's load balancer is
    // excluded: it may not fire, so relying on it would hide a guaranteed 502
    // for requests that skip the branch.
    let top_selected = super::clusters::level_selected_clusters(filters);
    let top_lb = super::clusters::reachable_lb_clusters(filters);

    // The empty-LB escape is judged on the WHOLE pipeline: a pipeline with no
    // load balancer anywhere may route by other means (static upstream), but
    // one whose only LBs live inside branches cannot serve a top-level
    // selection, so the top-level check must still run against top_lb.
    let any_lb = !super::clusters::extract_lb_clusters(filters).is_empty();
    if !top_selected.is_empty() && any_lb {
        for cluster in &top_selected {
            if !top_lb.contains(cluster.as_str()) {
                errors.push(format!(
                    "cluster-selecting filter references cluster \
                     '{cluster}' which is not defined in the \
                     load_balancer configuration"
                ));
            }
        }
    }

    check_branch_cluster_demands(filters, &top_lb, any_lb, errors);

    // The unused-cluster warning stays whole-pipeline: a cluster selected
    // only inside a branch still counts as used.
    let selected_clusters = super::clusters::extract_selected_clusters(filters);
    let lb_clusters = super::clusters::extract_lb_clusters(filters);
    for cluster in &lb_clusters {
        if !selected_clusters.contains(cluster.as_str()) {
            warn!(
                cluster = %cluster,
                "load_balancer defines cluster not referenced by any cluster-selecting filter"
            );
        }
    }
}

/// Check each branch sub-chain's cluster demands against its availability.
///
/// A branch's available load balancers are those inherited from enclosing
/// scopes plus the load balancers *guaranteed to run* within the branch —
/// its own level plus any unconditional sub-branches on unconditional hosts
/// (see [`reachable_lb_clusters`]). A *conditional* nested branch's load
/// balancer is excluded: it only runs when that nested branch fires, so
/// counting it here would hide the same guaranteed-502 shape one level down.
/// The empty-LB escape is pipeline-global (`any_lb`), matching the top-level
/// check: only a pipeline with no load balancer anywhere (static upstream)
/// skips demand validation — a branch whose local availability happens to be
/// empty is still checked.
///
/// [`reachable_lb_clusters`]: super::clusters::reachable_lb_clusters
fn check_branch_cluster_demands(
    filters: &[PipelineFilter],
    inherited_lb: &std::collections::HashSet<String>,
    any_lb: bool,
    errors: &mut Vec<String>,
) {
    for pf in filters {
        for branch in &pf.branches {
            let mut available = inherited_lb.clone();
            available.extend(super::clusters::reachable_lb_clusters(&branch.filters));

            let demands = super::clusters::level_selected_clusters(&branch.filters);
            if any_lb {
                for cluster in &demands {
                    if !available.contains(cluster.as_str()) {
                        errors.push(format!(
                            "cluster-selecting filter in branch '{name}' references cluster \
                             '{cluster}' which is not defined in any load_balancer \
                             visible to that branch",
                            name = branch.name,
                        ));
                    }
                }
            }

            check_branch_cluster_demands(&branch.filters, &available, any_lb, errors);
        }
    }
}

/// Multiple path rewriting filters (`path_rewrite` / `url_rewrite`).
pub(super) fn check_duplicate_rewrite_filters(names: &[&str], entries: &[FilterEntry], errors: &mut Vec<String>) {
    let rewrite_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| REWRITE_FILTERS.contains(n))
        .map(|(i, _)| i)
        .collect();

    let Some((&first_idx, rest)) = rewrite_indices.split_first() else {
        return;
    };
    let first_name = names.get(first_idx).copied().unwrap_or_default();

    for &idx in rest {
        let later_name = names.get(idx).copied().unwrap_or_default();
        let allows_override = has_allow_rewrite_override(entries, idx);

        if allows_override {
            warn!(
                first = first_name,
                later = later_name,
                "multiple rewrite filters: '{later_name}' will override '{first_name}' (allow_rewrite_override=true)"
            );
        } else {
            errors.push(format!(
                "multiple path rewriting filters in pipeline: both \
                 '{first_name}' and '{later_name}' write to \
                 rewritten_path. Set `allow_rewrite_override: true` \
                 on the later filter to allow this (last writer wins)"
            ));
        }
    }
}

/// `SkipTo` branches that bypass security-critical filters.
///
/// When a branch's rejoin target jumps forward past a security filter,
/// that filter will not execute for requests taking the branch path.
pub(super) fn check_skip_to_bypasses_security(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, pf) in filters.iter().enumerate() {
        for branch in &pf.branches {
            let RejoinTarget::SkipTo(target) = branch.rejoin else {
                continue;
            };
            for (skip_idx, skipped) in filters
                .iter()
                .enumerate()
                .skip(i + 1)
                .take(target.saturating_sub(i + 1))
            {
                let name = skipped.filter.name();
                if SECURITY_FILTERS.contains(&name) {
                    errors.push(format!(
                        "branch '{branch}' on filter at position {i} \
                         uses SkipTo rejoin that bypasses security \
                         filter '{name}' at position {skip_idx}",
                        branch = branch.name,
                    ));
                }
            }
        }
    }
}

/// `Terminal` branches that select a cluster and bypass later security filters.
///
/// When a branch rejoins at `Terminal` and its sub-chain selects a cluster,
/// the pipeline forwards the request upstream immediately, skipping every
/// top-level filter after the branch's host filter. A security filter placed
/// after such a branch is silently bypassed for requests that take the branch
/// — the same hazard [`check_skip_to_bypasses_security`] guards for `SkipTo`.
pub(super) fn check_terminal_rejoin_bypasses_security(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    // Tracks whether any filter up to and including the branch host can
    // select a cluster. The runtime forwards a Terminal branch upstream
    // whenever ctx.cluster is set — by the branch sub-chain OR by a router
    // earlier in the pipeline — so a terminal branch after a selector
    // bypasses later security filters even when the sub-chain itself
    // selects nothing. Reachability-blind over-approximation, consistent
    // with the module's other ordering checks.
    let mut cluster_selected_before = false;
    for (i, pf) in filters.iter().enumerate() {
        // The host filter runs before its branches are evaluated, so its own
        // selection counts for its branches too — as does a selection made
        // inside any branch sub-chain reached so far (a router in an earlier
        // Next-rejoin branch sets ctx.cluster just like a top-level one).
        cluster_selected_before = cluster_selected_before
            || pf.filter.selects_cluster()
            || pf.branches.iter().any(|b| branch_selects_cluster(&b.filters));
        let terminal_selects_cluster = pf.branches.iter().any(|branch| {
            matches!(branch.rejoin, RejoinTarget::Terminal)
                && (cluster_selected_before || branch_selects_cluster(&branch.filters))
        });
        if !terminal_selects_cluster {
            continue;
        }
        for (later_idx, later) in filters.iter().enumerate().skip(i + 1) {
            let name = later.filter.name();
            if SECURITY_FILTERS.contains(&name) {
                errors.push(format!(
                    "filter at position {i} has a Terminal branch that forwards upstream (a \
                     cluster is selected in the sub-chain or earlier in the pipeline), \
                     bypassing security filter '{name}' at position {later_idx}; \
                     place the security filter before the routing branch"
                ));
            }
        }
    }
}

/// Whether any filter in a branch sub-chain (recursively) selects a cluster.
fn branch_selects_cluster(filters: &[PipelineFilter]) -> bool {
    filters
        .iter()
        .any(|pf| pf.filter.selects_cluster() || pf.branches.iter().any(|b| branch_selects_cluster(&b.filters)))
}

/// Body-access filters inside branch chains.
///
/// Branch sub-chains only run `on_request`: `on_request_body` and
/// `on_response_body` never execute for filters inside branches, yet
/// their declared body access would silently enable pipeline-wide
/// buffering for hooks that never run. Body-processing filters must be
/// in the main pipeline path or gated with normal filter conditions.
pub(super) fn check_branch_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Recursively collect body-access violations inside one branch sub-chain.
fn collect_branch_body_errors(branch_name: &str, filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && (filter.request_body_access() != BodyAccess::None || filter.response_body_access() != BodyAccess::None)
        {
            errors.push(format!(
                "filter '{name}' in branch '{branch_name}' declares body \
                 access, but branch filters only run on_request and body \
                 hooks never execute; move it to the main pipeline or gate \
                 it with filter conditions",
                name = filter.name(),
            ));
        }
        for branch in &pf.branches {
            collect_branch_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// `iterative_request_router` coexisting with `router` or `load_balancer`.
///
/// The IRR owns the full sub-request lifecycle including routing.
/// A `router` or `load_balancer` in the same chain would conflict.
pub(super) fn check_irr_with_router_or_lb(names: &[&str], errors: &mut Vec<String>) {
    if !names.contains(&"iterative_request_router") {
        return;
    }
    if names.contains(&"router") {
        errors.push(
            "iterative_request_router and router in the same \
             chain: the IRR owns routing within its step chains; \
             a top-level router will conflict"
                .to_owned(),
        );
    }
    if names.contains(&"load_balancer") {
        errors.push(
            "iterative_request_router and load_balancer in the \
             same chain: the IRR owns endpoint selection within \
             its step chains; a top-level load_balancer will \
             conflict"
                .to_owned(),
        );
    }
}

// -----------------------------------------------------------------------------
// Warning Checks
// -----------------------------------------------------------------------------

/// Router without any following LB (requests will 502).
pub(super) fn check_router_without_lb(names: &[&str], warnings: &mut Vec<String>) {
    let has_router = names.contains(&"router");
    let has_lb = names.contains(&"load_balancer");
    if has_router && !has_lb {
        warnings.push(
            "router filter without a load_balancer; \
             routed requests will fail with 502"
                .to_owned(),
        );
    }
}

/// All routers conditional with no unconditional fallback.
pub(super) fn check_all_routers_conditional(names: &[&str], filters: &[PipelineFilter], warnings: &mut Vec<String>) {
    let router_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| **n == "router")
        .map(|(i, _)| i)
        .collect();

    if router_indices.is_empty() {
        return;
    }

    let all_conditional = router_indices
        .iter()
        .all(|&i| filters.get(i).is_some_and(|pf| !pf.conditions.is_empty()));

    if all_conditional {
        warnings.push(
            "all router filters are conditional; requests \
             not matching any condition will have no route"
                .to_owned(),
        );
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Check whether the filter entry at `idx` has
/// `allow_rewrite_override: true` in its YAML config.
///
/// Pipeline indices correspond 1:1 with `entries` indices.
fn has_allow_rewrite_override(entries: &[FilterEntry], idx: usize) -> bool {
    entries
        .get(idx)
        .and_then(|e| e.config.get("allow_rewrite_override"))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
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
    use std::sync::Arc;

    use praxis_core::config::{Condition, ConditionMatch};

    use super::*;
    use crate::pipeline::{
        branch::ResolvedBranch,
        test_filters::{lb_filter, noop_filter_with_conditions, selector_filter},
    };

    #[test]
    fn security_filter_list_matches_registry_metadata() {
        let registry = crate::FilterRegistry::with_builtins();
        let mut expected = registry.security_filters();
        let mut actual = SECURITY_FILTERS.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();

        assert_eq!(
            actual, expected,
            "pipeline checks and registry security metadata diverged"
        );
    }

    #[test]
    fn lb_without_router_errors() {
        let filters = vec![lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("load_balancer without a preceding router"),
            "error should mention missing router: {}",
            errors[0]
        );
    }

    #[test]
    fn lb_with_router_no_error() {
        let filters = vec![selector_filter("router", &[]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "router before LB should produce no errors");
    }

    #[test]
    fn lb_with_only_non_cluster_filter_errors() {
        let filters = vec![named_noop_filter("custom_filter", vec![]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("load_balancer without a preceding router"),
            "non-cluster-selecting filter should not satisfy requirement: {}",
            errors[0]
        );
    }

    #[test]
    fn custom_cluster_selector_before_lb_no_error() {
        let filters = vec![selector_filter("custom_selector", &["c"]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "custom cluster selector before LB should produce no errors"
        );
    }

    #[test]
    fn named_non_cluster_filter_before_lb_errors() {
        let filters = vec![named_noop_filter("classifier", vec![]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "named non-cluster filter before LB should error");
    }

    #[test]
    fn non_cluster_filter_then_router_then_lb_no_error() {
        let filters = vec![
            named_noop_filter("classifier", vec![]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "non-cluster filter -> router -> LB should be valid");
    }

    #[test]
    fn router_and_custom_selector_conflict_rejected() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "two selectors should produce a conflict error");
        assert!(
            errors[0].contains("multiple cluster-selecting filters"),
            "error should mention conflicting selectors: {}",
            errors[0]
        );
    }

    #[test]
    fn custom_selector_and_router_conflict_rejected() {
        let filters = vec![
            selector_filter("custom_selector", &["c"]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "two selectors should produce a conflict error");
    }

    #[test]
    fn duplicate_routers_before_lb_do_not_add_selector_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "duplicate router validation should own this diagnostic"
        );
    }

    #[test]
    fn duplicate_routers_plus_custom_selector_still_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "router plus another selector should still produce a conflict"
        );
        assert!(
            errors[0].contains("router, custom_selector"),
            "error should collapse duplicate router names but keep the real conflict: {}",
            errors[0]
        );
    }

    #[test]
    fn non_cluster_filter_and_router_no_conflict() {
        let filters = vec![
            named_noop_filter("classifier", vec![]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "non-cluster filter + router should not conflict");
    }

    #[test]
    fn custom_selector_without_router_no_conflict() {
        let filters = vec![selector_filter("custom_selector", &["c"]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "single custom selector should not conflict");
    }

    #[test]
    fn multiple_selectors_without_lb_no_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "multiple selectors without LB should not conflict");
    }

    #[test]
    fn router_after_lb_does_not_conflict_with_selector_before_lb() {
        let filters = vec![
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
            selector_filter("router", &[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "conflict check should only consider selectors before the load balancer"
        );
    }

    #[test]
    fn no_lb_no_error() {
        let filters = vec![selector_filter("router", &[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "no LB present should produce no errors");
    }

    #[test]
    fn unconditional_static_response_middle_errors() {
        let names = vec!["static_response", "router"];
        let filters = vec![make_pf(vec![]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("unreachable"),
            "error should mention unreachable filters: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_static_response_no_error() {
        let names = vec!["static_response", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "conditional static_response should not error");
    }

    #[test]
    fn static_response_last_no_error() {
        let names = vec!["router", "static_response"];
        let filters = vec![make_pf(vec![]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "static_response at end should not error");
    }

    #[test]
    fn conditional_security_filter_errors() {
        let names = vec!["ip_acl"];
        let filters = vec![make_pf(vec![make_condition()])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("security filter"),
            "error should mention security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn unconditional_security_filter_no_error() {
        let names = vec!["ip_acl"];
        let filters = vec![make_pf(vec![])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "unconditional security filter should not error");
    }

    #[test]
    fn open_security_filter_errors() {
        let names = vec!["ip_acl"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("failure_mode: open"),
            "error should mention failure_mode: {}",
            errors[0]
        );
    }

    #[test]
    fn open_security_filter_allowed_demotes_to_warning() {
        let names = vec!["ip_acl"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, true, &mut errors);
        assert!(errors.is_empty(), "allow flag should demote error to warning");
    }

    #[test]
    fn closed_security_filter_no_error() {
        let names = vec!["ip_acl"];
        let filters = vec![make_pf(vec![])];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(errors.is_empty(), "closed security filter should not error");
    }

    #[test]
    fn open_forwarded_headers_filter_errors() {
        let names = vec!["forwarded_headers"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("failure_mode: open") && errors[0].contains("forwarded_headers"),
            "error should mention forwarded_headers with failure_mode: open: {}",
            errors[0]
        );
    }

    #[test]
    fn open_forwarded_headers_allowed_demotes_to_warning() {
        let names = vec!["forwarded_headers"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, true, &mut errors);
        assert!(
            errors.is_empty(),
            "allow flag should demote forwarded_headers error to warning"
        );
    }

    #[test]
    fn open_non_security_filter_no_error() {
        let names = vec!["headers"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(errors.is_empty(), "open non-security filter should not error");
    }

    #[test]
    fn duplicate_routers_errors() {
        let names = vec!["router", "router"];
        let mut errors = Vec::new();
        check_duplicate_routers(&names, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple router"),
            "error should mention multiple routers: {}",
            errors[0]
        );
    }

    #[test]
    fn single_router_no_error() {
        let names = vec!["router"];
        let mut errors = Vec::new();
        check_duplicate_routers(&names, &mut errors);
        assert!(errors.is_empty(), "single router should produce no errors");
    }

    #[test]
    fn duplicate_load_balancers_errors() {
        let names = vec!["load_balancer", "load_balancer"];
        let mut errors = Vec::new();
        check_duplicate_load_balancers(&names, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple load_balancer"),
            "error should mention multiple LBs: {}",
            errors[0]
        );
    }

    #[test]
    fn router_without_lb_warns() {
        let names = vec!["router"];
        let mut warnings = Vec::new();
        check_router_without_lb(&names, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning");
        assert!(
            warnings[0].contains("router filter without a load_balancer"),
            "warning should mention missing LB: {}",
            warnings[0]
        );
    }

    #[test]
    fn router_with_lb_no_warning() {
        let names = vec!["router", "load_balancer"];
        let mut warnings = Vec::new();
        check_router_without_lb(&names, &mut warnings);
        assert!(warnings.is_empty(), "router with LB should produce no warnings");
    }

    #[test]
    fn all_routers_conditional_warns() {
        let names = vec!["router", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![make_condition()])];
        let mut warnings = Vec::new();
        check_all_routers_conditional(&names, &filters, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning");
        assert!(
            warnings[0].contains("all router filters are conditional"),
            "warning should mention conditional routers: {}",
            warnings[0]
        );
    }

    #[test]
    fn one_unconditional_router_no_warning() {
        let names = vec!["router", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![])];
        let mut warnings = Vec::new();
        check_all_routers_conditional(&names, &filters, &mut warnings);
        assert!(warnings.is_empty(), "one unconditional router should suppress warning");
    }

    #[test]
    fn misaligned_clusters_errors() {
        let filters = vec![selector_filter("router", &["missing"]), lb_filter(&["other"])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("missing") && errors[0].contains("not defined"),
            "error should mention the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn aligned_clusters_no_error() {
        let filters = vec![selector_filter("router", &["web"]), lb_filter(&["web"])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(errors.is_empty(), "aligned clusters should produce no errors");
    }

    /// Build an unconditional host filter carrying one unconditional
    /// Next-rejoin branch with `filters`. Such a branch always runs and shares
    /// `ctx`, so its load balancers are reachable for the enclosing scope.
    fn host_with_branch(branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        let mut host = noop_filter_with_conditions("headers", vec![]);
        host.branches = vec![ResolvedBranch {
            condition: None,
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from("br"),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    /// Build an unconditional host filter carrying one *conditional*
    /// Next-rejoin branch with `filters`. A conditional branch may not fire, so
    /// its load balancers cannot be relied on to serve an enclosing selection.
    fn host_with_conditional_branch(branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        let mut host = noop_filter_with_conditions("headers", vec![]);
        host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from("cond_br"),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    #[test]
    fn unconditional_branch_lb_satisfies_top_level_selection() {
        // An unconditional branch on an unconditional host always runs and its
        // filters share `ctx`, so the branch LB sets `ctx.upstream` for the
        // top-level selection exactly like a top-level LB (verified against the
        // runtime: evaluate.rs runs branch filters on the shared ctx, and the
        // trailing lb(other) early-returns once ctx.upstream is set). This
        // config succeeds at runtime, so it must NOT be rejected at build time.
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_branch(vec![lb_filter(&["x"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional branch LB is always reachable and satisfies a top-level selection: {errors:?}"
        );
    }

    #[test]
    fn conditional_branch_lb_does_not_satisfy_top_level_selection() {
        // A CONDITIONAL branch may not fire; when it does not, the top-level
        // selection of "x" reaches the trailing lb(other), which does not
        // define "x", and the request 502s. The branch LB therefore cannot be
        // relied on to satisfy the selection, so this must error.
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_conditional_branch(vec![lb_filter(&["x"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional branch LB must not satisfy a top-level selection: {errors:?}"
        );
        assert!(
            errors[0].contains('x'),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_selection_without_any_visible_lb_errors() {
        // A router inside a branch demanding a cluster no visible LB defines
        // is the guaranteed request-time 502 this check exists to catch.
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["y"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch selecting an undefined cluster must error: {errors:?}"
        );
        assert!(
            errors[0].contains('y'),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_selection_satisfied_by_top_level_lb_no_error() {
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["web"])]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a top-level LB is visible inside branches and satisfies the demand: {errors:?}"
        );
    }

    #[test]
    fn top_level_selection_with_only_unconditional_branch_lb_no_error() {
        // No top-level LB exists, but the only LB lives in an UNCONDITIONAL
        // branch, which always runs and serves the top-level selection at
        // runtime. It must NOT error.
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_branch(vec![lb_filter(&["x"])]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional branch LB serves a top-level selection even with no top-level LB: {errors:?}"
        );
    }

    #[test]
    fn top_level_selection_with_only_conditional_branch_lb_errors() {
        // The pipeline's only LB lives in a CONDITIONAL branch that may not
        // fire; a non-matching request then forwards with no upstream selected
        // and 502s. The whole-pipeline escape must not skip this.
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_conditional_branch(vec![lb_filter(&["x"])]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a top-level selection served only by a conditional branch LB must error: {errors:?}"
        );
    }

    #[test]
    fn branch_demand_served_by_unconditional_nested_branch_lb_no_error() {
        // The demand sits at branch level and the LB defining its cluster is
        // inside an UNCONDITIONAL nested branch on an unconditional host. That
        // nested branch always runs when the outer branch runs, so lb(deep) is
        // reachable and the request succeeds. It must NOT error.
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["deep"]), nested_host]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional nested branch LB is reachable and serves the branch demand: {errors:?}"
        );
    }

    #[test]
    fn branch_demand_served_only_by_conditional_nested_branch_lb_errors() {
        // The LB defining "deep" is inside a CONDITIONAL nested branch that may
        // not fire, so the branch-level selection of "deep" can reach
        // forwarding with no upstream selected. This is the guaranteed-502
        // shape one level down and must error.
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested_cond"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["deep"]), nested_host]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch demand served only by a conditional nested branch LB must error: {errors:?}"
        );
        assert!(
            errors[0].contains("deep"),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn nested_unconditional_branch_lb_without_outer_lb_no_error() {
        // The pipeline's only LB sits in an UNCONDITIONAL nested branch and
        // there is no top-level LB. The nested branch always runs, so lb(deep)
        // is reachable and the branch selection of "deep" succeeds at runtime.
        // It must NOT error.
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![host_with_branch(vec![
            selector_filter("router", &["deep"]),
            nested_host,
        ])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional nested branch LB is reachable even with no top-level LB: {errors:?}"
        );
    }

    #[test]
    fn nested_conditional_branch_lb_without_outer_lb_still_errors() {
        // The pipeline's only LB sits in a CONDITIONAL nested branch and there
        // is no top-level LB. The empty-LB escape is pipeline-global, so the
        // branch demand is still validated and rejected: the nested LB only
        // runs when the nested branch fires.
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested_cond"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![host_with_branch(vec![
            selector_filter("router", &["deep"]),
            nested_host,
        ])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "the pipeline-global escape must not skip a conditional branch demand: {errors:?}"
        );
        assert!(
            errors[0].contains("deep"),
            "error should name the cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn self_contained_branch_selection_no_error() {
        // A branch that both selects and defines its own cluster is complete
        // on its own; the top level must not be required to re-define it.
        let filters = vec![
            selector_filter("router", &["web"]),
            host_with_branch(vec![selector_filter("router", &["z"]), lb_filter(&["z"])]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a self-contained branch selection must not error: {errors:?}"
        );
    }

    #[test]
    fn custom_selector_missing_cluster_reference_rejected() {
        let filters = vec![
            selector_filter("custom_selector", &["missing-custom-cluster"]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("missing-custom-cluster") && errors[0].contains("not defined"),
            "error should mention the missing custom selector cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn duplicate_rewrite_errors() {
        let names = vec!["path_rewrite", "url_rewrite"];
        let entries = vec![
            make_entry("path_rewrite", "strip_prefix: \"/api\""),
            make_entry("url_rewrite", "operations: []"),
        ];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple path rewriting filters"),
            "error should mention multiple rewrite filters: {}",
            errors[0]
        );
    }

    #[test]
    fn duplicate_rewrite_with_override_no_error() {
        let names = vec!["path_rewrite", "url_rewrite"];
        let entries = vec![
            make_entry("path_rewrite", "strip_prefix: \"/api\""),
            make_entry("url_rewrite", "operations: []\nallow_rewrite_override: true"),
        ];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert!(errors.is_empty(), "allow_rewrite_override should suppress error");
    }

    #[test]
    fn single_rewrite_no_error() {
        let names = vec!["path_rewrite"];
        let entries = vec![make_entry("path_rewrite", "strip_prefix: \"/api\"")];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert!(errors.is_empty(), "single rewrite filter should produce no errors");
    }

    #[test]
    fn skip_to_bypassing_security_filter_errors() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = named_noop_filter("ip_acl", vec![]);
        let f2 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should detect skipped security filter");
        assert!(
            errors[0].contains("ip_acl"),
            "error should mention the bypassed security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn skip_to_bypassing_multiple_security_filters_reports_each() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("big_skip", 3)];
        let f1 = named_noop_filter("ip_acl", vec![]);
        let f2 = named_noop_filter("cors", vec![]);
        let f3 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2, f3];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert_eq!(errors.len(), 2, "should report each skipped security filter");
    }

    #[test]
    fn skip_to_over_non_security_no_error() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = named_noop_filter("request_id", vec![]);
        let f2 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "skipping non-security filters should produce no error"
        );
    }

    #[test]
    fn skip_to_landing_on_security_filter_no_error() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = named_noop_filter("request_id", vec![]);
        let f2 = named_noop_filter("ip_acl", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "SkipTo landing ON a security filter should not error"
        );
    }

    #[test]
    fn no_branches_no_skip_to_error() {
        let filters = vec![
            named_noop_filter("headers", vec![]),
            named_noop_filter("ip_acl", vec![]),
        ];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(errors.is_empty(), "filters without branches should produce no error");
    }

    #[test]
    fn branch_body_filter_errors() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters("body_branch", vec![body_filter()])];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "body filter in branch should error");
        assert!(
            errors[0].contains("body_branch") && errors[0].contains("branch_body"),
            "error should name the branch and the filter: {}",
            errors[0]
        );
    }

    #[test]
    fn nested_branch_body_filter_errors() {
        let mut inner_parent = named_noop_filter("classifier", vec![]);
        inner_parent.branches = vec![make_branch_with_filters("inner", vec![body_filter()])];
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters("outer", vec![inner_parent])];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "nested branch body filter should error");
        assert!(
            errors[0].contains("inner"),
            "error should name the innermost branch: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_without_body_filters_no_error() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters(
            "noop_branch",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert!(errors.is_empty(), "branch without body filters should not error");
    }

    #[test]
    fn top_level_body_filter_no_branch_error() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert!(errors.is_empty(), "top-level body filters are legitimate");
    }

    #[test]
    fn irr_with_router_errors() {
        let names = vec!["iterative_request_router", "router"];
        let mut errors = Vec::new();
        check_irr_with_router_or_lb(&names, &mut errors);
        assert_eq!(errors.len(), 1, "IRR + router should produce one error");
        assert!(
            errors[0].contains("router"),
            "error should mention router: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_load_balancer_errors() {
        let names = vec!["iterative_request_router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_with_router_or_lb(&names, &mut errors);
        assert_eq!(errors.len(), 1, "IRR + LB should produce one error");
        assert!(
            errors[0].contains("load_balancer"),
            "error should mention load_balancer: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_both_router_and_lb_errors_twice() {
        let names = vec!["iterative_request_router", "router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_with_router_or_lb(&names, &mut errors);
        assert_eq!(errors.len(), 2, "IRR + router + LB should produce two errors");
    }

    #[test]
    fn irr_alone_no_error() {
        let names = vec!["iterative_request_router"];
        let mut errors = Vec::new();
        check_irr_with_router_or_lb(&names, &mut errors);
        assert!(errors.is_empty(), "IRR alone should not error");
    }

    #[test]
    fn no_irr_router_and_lb_no_error() {
        let names = vec!["router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_with_router_or_lb(&names, &mut errors);
        assert!(errors.is_empty(), "no IRR means no conflict");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`PipelineFilter`] with the given conditions.
    fn make_pf(conditions: Vec<Condition>) -> PipelineFilter {
        named_noop_filter("noop", conditions)
    }

    fn named_noop_filter(name: &'static str, conditions: Vec<Condition>) -> PipelineFilter {
        noop_filter_with_conditions(name, conditions)
    }

    /// Build a `When` condition for testing.
    fn make_condition() -> Condition {
        Condition::When(ConditionMatch {
            path: None,
            path_prefix: Some("/test".to_owned()),
            methods: None,
            headers: None,
        })
    }

    /// Build a [`FilterEntry`] for testing.
    fn make_entry(filter_type: &str, yaml: &str) -> FilterEntry {
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter_type: filter_type.to_owned(),
            config: serde_yaml::from_str(yaml).expect("valid test YAML"),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build a [`ResolvedBranch`] with a [`SkipTo`] rejoin target.
    ///
    /// [`SkipTo`]: RejoinTarget::SkipTo
    fn make_skip_branch(name: &str, target: usize) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::SkipTo(target),
        }
    }

    /// Build a [`ResolvedBranch`] containing the given filters.
    fn make_branch_with_filters(name: &str, filters: Vec<PipelineFilter>) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters,
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::Next,
        }
    }

    /// Build a [`PipelineFilter`] whose filter declares request body access.
    fn body_filter() -> PipelineFilter {
        /// Minimal filter declaring request body access.
        struct BranchBodyFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for BranchBodyFilter {
            fn name(&self) -> &'static str {
                "branch_body"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadOnly
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(BranchBodyFilter)), vec![], vec![])
    }

    /// Build a [`PipelineFilter`] whose filter selects a cluster.
    fn cluster_selecting_filter() -> PipelineFilter {
        /// Minimal filter that reports it selects a cluster.
        struct ClusterSelectingFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for ClusterSelectingFilter {
            fn name(&self) -> &'static str {
                "router"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn selects_cluster(&self) -> bool {
                true
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(ClusterSelectingFilter)), vec![], vec![])
    }

    /// Build a [`ResolvedBranch`] with a [`Terminal`] rejoin target.
    ///
    /// [`Terminal`]: RejoinTarget::Terminal
    fn make_terminal_branch(name: &str, filters: Vec<PipelineFilter>) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters,
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::Terminal,
        }
    }

    #[test]
    fn terminal_routing_branch_before_security_filter_errors() {
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch("route", vec![cluster_selecting_filter()])];
        let ip_acl = named_noop_filter("ip_acl", vec![]);
        let filters = vec![host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a terminal routing branch before ip_acl must be flagged"
        );
        assert!(
            errors[0].contains("ip_acl") && errors[0].contains("bypassing"),
            "error should name the bypassed filter: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_branch_without_cluster_selection_no_error() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_terminal_branch(
            "br",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let ip_acl = named_noop_filter("ip_acl", vec![]);
        let filters = vec![host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a terminal branch that selects no cluster does not forward, so no bypass: {errors:?}"
        );
    }

    #[test]
    fn terminal_branch_after_upstream_selector_errors() {
        // The branch sub-chain selects nothing, but a router earlier in the
        // pipeline already set the cluster, so at runtime the Terminal branch
        // forwards upstream and bypasses the later security filter all the
        // same.
        let selector = cluster_selecting_filter();
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch(
            "br",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let ip_acl = named_noop_filter("ip_acl", vec![]);
        let filters = vec![selector, host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a terminal branch after an upstream selector forwards and must error: {errors:?}"
        );
        assert!(
            errors[0].contains("ip_acl"),
            "the bypassed security filter should be named: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_branch_after_earlier_branch_selector_errors() {
        // The selector lives inside an EARLIER host's Next-rejoin branch: a
        // request taking that branch has ctx.cluster set when it reaches the
        // later host's empty Terminal branch, which then forwards upstream
        // past ip_acl.
        let mut selector_host = named_noop_filter("classifier", vec![]);
        selector_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![cluster_selecting_filter()],
            max_iterations: None,
            name: Arc::from("route"),
            rejoin: RejoinTarget::Next,
        }];
        let mut terminal_host = named_noop_filter("headers", vec![]);
        terminal_host.branches = vec![make_terminal_branch("stop", vec![])];
        let ip_acl = named_noop_filter("ip_acl", vec![]);
        let filters = vec![selector_host, terminal_host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a selection inside an earlier branch also forwards a later terminal branch: {errors:?}"
        );
        assert!(
            errors[0].contains("ip_acl"),
            "the bypassed security filter should be named: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_routing_branch_after_security_filter_no_error() {
        let ip_acl = named_noop_filter("ip_acl", vec![]);
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch("route", vec![cluster_selecting_filter()])];
        // ip_acl runs before the routing branch, so it is not bypassed.
        let filters = vec![ip_acl, host];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "security filter before the branch is not bypassed: {errors:?}"
        );
    }
}
