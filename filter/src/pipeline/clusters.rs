// SPDX-License-Identifier: MIT
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
pub(super) fn extract_selected_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    filters.iter().flat_map(|pf| pf.filter.selected_clusters()).collect()
}

/// Load-balancers declare the cluster names they can consume.
pub(super) fn extract_lb_clusters(filters: &[PipelineFilter]) -> HashSet<String> {
    filters
        .iter()
        .flat_map(|pf| pf.filter.load_balancer_clusters())
        .collect()
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
}
