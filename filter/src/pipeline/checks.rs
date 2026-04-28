// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Ordering validation checks for filter pipelines.

use praxis_core::config::FilterEntry;
use tracing::warn;

use super::filter::PipelineFilter;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Filters classified as security-critical (bypass risk when conditional).
const SECURITY_FILTERS: &[&str] = &["ip_acl", "forwarded_headers"];

/// Filters that rewrite the request path.
const REWRITE_FILTERS: &[&str] = &["path_rewrite", "url_rewrite"];

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// LB without a preceding router.
#[allow(clippy::indexing_slicing, reason = "position() is within bounds")]
pub(super) fn check_lb_without_router(names: &[&str], errors: &mut Vec<String>) {
    if let Some(lb_pos) = names.iter().position(|n| *n == "load_balancer") {
        let has_router_before = names[..lb_pos].contains(&"router");
        if !has_router_before {
            errors.push(
                "load_balancer without a preceding router \
                 filter; requests will fail with \
                 'no cluster selected'"
                    .to_owned(),
            );
        }
    }
}

/// Unconditional `static_response` blocking subsequent filters.
#[allow(clippy::indexing_slicing, reason = "enumeration bounds")]
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
#[allow(clippy::indexing_slicing, reason = "enumeration bounds")]
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

/// Cross-reference router cluster names against LB cluster names.
pub(super) fn check_misaligned_clusters(entries: &[FilterEntry], errors: &mut Vec<String>) {
    let router_clusters = super::clusters::extract_router_clusters(entries);
    let lb_clusters = super::clusters::extract_lb_clusters(entries);

    if router_clusters.is_empty() || lb_clusters.is_empty() {
        return;
    }

    for cluster in &router_clusters {
        if !lb_clusters.contains(cluster.as_str()) {
            errors.push(format!(
                "router routes to cluster '{cluster}' which is not \
                 defined in the load_balancer configuration"
            ));
        }
    }

    for cluster in &lb_clusters {
        if !router_clusters.contains(cluster.as_str()) {
            warn!(
                cluster = %cluster,
                "load_balancer defines cluster not referenced by any router"
            );
        }
    }
}

/// Multiple path rewriting filters (`path_rewrite` / `url_rewrite`).
#[allow(clippy::indexing_slicing, reason = "checked before usage")]
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
#[allow(clippy::indexing_slicing, reason = "enumeration bounds")]
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use praxis_core::config::{Condition, ConditionMatch, FilterEntry};

    use super::*;
    use crate::any_filter::AnyFilter;

    #[test]
    fn lb_without_router_errors() {
        let names = vec!["load_balancer"];
        let mut errors = Vec::new();
        check_lb_without_router(&names, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("load_balancer without a preceding router"),
            "error should mention missing router: {}",
            errors[0]
        );
    }

    #[test]
    fn lb_with_router_no_error() {
        let names = vec!["router", "load_balancer"];
        let mut errors = Vec::new();
        check_lb_without_router(&names, &mut errors);
        assert!(errors.is_empty(), "router before LB should produce no errors");
    }

    #[test]
    fn no_lb_no_error() {
        let names = vec!["router", "ip_acl"];
        let mut errors = Vec::new();
        check_lb_without_router(&names, &mut errors);
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
        let entries = vec![
            make_entry("router", "routes:\n  - path_prefix: \"/\"\n    cluster: missing"),
            make_entry(
                "load_balancer",
                "clusters:\n  - name: other\n    endpoints: [\"1.2.3.4:80\"]",
            ),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&entries, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("missing") && errors[0].contains("not defined"),
            "error should mention the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn aligned_clusters_no_error() {
        let entries = vec![
            make_entry("router", "routes:\n  - path_prefix: \"/\"\n    cluster: web"),
            make_entry(
                "load_balancer",
                "clusters:\n  - name: web\n    endpoints: [\"1.2.3.4:80\"]",
            ),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&entries, &mut errors);
        assert!(errors.is_empty(), "aligned clusters should produce no errors");
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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`PipelineFilter`] with the given conditions.
    fn make_pf(conditions: Vec<Condition>) -> PipelineFilter {
        PipelineFilter {
            branches: vec![],
            conditions,
            filter: AnyFilter::Http(Box::new(NoopFilter)),
            name: None,
            response_conditions: vec![],
        }
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
            filter_type: filter_type.to_owned(),
            config: serde_yaml::from_str(yaml).expect("valid test YAML"),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Noop HTTP filter for pipeline filter construction.
    struct NoopFilter;

    #[async_trait::async_trait]
    impl crate::filter::HttpFilter for NoopFilter {
        fn name(&self) -> &'static str {
            "noop"
        }

        async fn on_request(
            &self,
            _ctx: &mut crate::filter::HttpFilterContext<'_>,
        ) -> Result<crate::FilterAction, crate::FilterError> {
            Ok(crate::FilterAction::Continue)
        }
    }
}
