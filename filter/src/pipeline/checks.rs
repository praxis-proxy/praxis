// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Ordering validation checks for filter pipelines.

use praxis_core::config::{FailureMode, FilterEntry};
use tracing::warn;

use super::{branch::RejoinTarget, filter::PipelineFilter};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Filters classified as security-critical (bypass risk when conditional).
const SECURITY_FILTERS: &[&str] = &[
    "cors",
    "credential_injection",
    "csrf",
    "forwarded_headers",
    "guardrails",
    "ip_acl",
    "rate_limit",
];

/// Filters that rewrite the request path.
const REWRITE_FILTERS: &[&str] = &["path_rewrite", "url_rewrite"];

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// `load_balancer` without a filter that sets `ctx.cluster` will fail
/// every request with "no cluster selected".
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_lb_without_cluster_selector(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, filter) in filters.iter().enumerate() {
        if filter.filter.name() == "load_balancer" && !filters[..i].iter().any(|f| f.filter.selects_cluster()) {
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
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_unconditional_static_response(
    names: &[&str],
    filters: &[PipelineFilter],
    errors: &mut Vec<String>,
) {
    for (i, name) in names.iter().enumerate() {
        if *name == "static_response" && i + 1 < names.len() {
            let conditions = &filters[i].conditions;
            if conditions.is_empty() {
                errors.push(format!(
                    "unconditional static_response at \
                     position {i} makes subsequent filters \
                     unreachable: {}",
                    names[i + 1..].join(", ")
                ));
            }
        }
    }
}

/// Security filters with request conditions (bypass risk).
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_conditional_security(names: &[&str], filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, name) in names.iter().enumerate() {
        if SECURITY_FILTERS.contains(name) {
            let conditions = &filters[i].conditions;
            if !conditions.is_empty() {
                errors.push(format!(
                    "security filter '{name}' at position {i} has \
                     request conditions; it will be bypassed for \
                     non-matching requests"
                ));
            }
        }
    }
}

/// Security filters with `failure_mode: open` (bypass risk on error).
///
/// When `allow` is `true`, the error is demoted to a warning.
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_open_security_filters(
    names: &[&str],
    filters: &[PipelineFilter],
    allow: bool,
    errors: &mut Vec<String>,
) {
    for (i, name) in names.iter().enumerate() {
        if SECURITY_FILTERS.contains(name) && filters[i].failure_mode == FailureMode::Open {
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
    let selected_clusters = super::clusters::extract_selected_clusters(filters);
    let lb_clusters = super::clusters::extract_lb_clusters(filters);

    if selected_clusters.is_empty() || lb_clusters.is_empty() {
        return;
    }

    for cluster in &selected_clusters {
        if !lb_clusters.contains(cluster.as_str()) {
            errors.push(format!(
                "cluster-selecting filter references cluster \
                 '{cluster}' which is not defined in the \
                 load_balancer configuration"
            ));
        }
    }

    for cluster in &lb_clusters {
        if !selected_clusters.contains(cluster.as_str()) {
            warn!(
                cluster = %cluster,
                "load_balancer defines cluster not referenced by any cluster-selecting filter"
            );
        }
    }
}

/// Multiple path rewriting filters (`path_rewrite` / `url_rewrite`).
#[expect(clippy::indexing_slicing, reason = "checked before usage")]
pub(super) fn check_duplicate_rewrite_filters(names: &[&str], entries: &[FilterEntry], errors: &mut Vec<String>) {
    let rewrite_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| REWRITE_FILTERS.contains(n))
        .map(|(i, _)| i)
        .collect();

    if rewrite_indices.len() < 2 {
        return;
    }

    let first_idx = rewrite_indices[0];
    let first_name = names[first_idx];

    for &idx in &rewrite_indices[1..] {
        let later_name = names[idx];
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
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
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

    let all_conditional = router_indices.iter().all(|&i| !filters[i].conditions.is_empty());

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

    use praxis_core::config::{Condition, ConditionMatch, FailureMode, FilterEntry};

    use super::*;
    use crate::pipeline::{
        branch::{RejoinTarget, ResolvedBranch},
        test_filters::{lb_filter, noop_filter_with_conditions, selector_filter},
    };

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
}
