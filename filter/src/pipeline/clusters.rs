// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! YAML cluster name extraction from filter entries.

use std::collections::HashSet;

use praxis_core::config::FilterEntry;

// -----------------------------------------------------------------------------
// YAML Cluster Extraction
// -----------------------------------------------------------------------------

/// Cluster cross-reference validation must understand each filter's
/// config shape before comparing selected clusters to load-balancer clusters.
pub(super) fn extract_selected_clusters(entries: &[FilterEntry]) -> HashSet<String> {
    let mut clusters = HashSet::new();
    for entry in entries {
        if entry.filter_type == "router" {
            extract_from_router(&entry.config, &mut clusters);
        }
    }
    clusters
}

/// Router validation needs every configured route target.
fn extract_from_router(config: &serde_yaml::Value, clusters: &mut HashSet<String>) {
    let Some(routes) = config.get("routes").and_then(|v| v.as_sequence()) else {
        return;
    };
    for route in routes {
        if let Some(cluster) = route.get("cluster").and_then(|v| v.as_str()) {
            clusters.insert(cluster.to_owned());
        }
    }
}

/// Load-balancer cluster names are the authoritative set for selected
/// cluster validation.
pub(super) fn extract_lb_clusters(entries: &[FilterEntry]) -> HashSet<String> {
    let mut clusters = HashSet::new();
    for entry in entries {
        if entry.filter_type != "load_balancer" {
            continue;
        }
        let Some(cluster_list) = entry.config.get("clusters") else {
            continue;
        };
        let Some(cluster_list) = cluster_list.as_sequence() else {
            continue;
        };
        for cluster in cluster_list {
            if let Some(name) = cluster.get("name").and_then(|v| v.as_str()) {
                clusters.insert(name.to_owned());
            }
        }
    }
    clusters
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
    use praxis_core::config::{FailureMode, FilterEntry};

    use super::*;

    #[test]
    fn extracts_router_clusters() {
        let entries = vec![make_entry(
            "router",
            "routes:\n  - path_prefix: \"/\"\n    cluster: web\n  - path_prefix: \"/api\"\n    cluster: api",
        )];
        let clusters = extract_selected_clusters(&entries);
        assert_eq!(clusters.len(), 2, "should extract two clusters");
        assert!(clusters.contains("web"), "should contain 'web'");
        assert!(clusters.contains("api"), "should contain 'api'");
    }

    #[test]
    fn extracts_lb_clusters() {
        let entries = vec![make_entry(
            "load_balancer",
            "clusters:\n  - name: web\n    endpoints: [\"1.2.3.4:80\"]\n  - name: api\n    endpoints: [\"5.6.7.8:80\"]",
        )];
        let clusters = extract_lb_clusters(&entries);
        assert_eq!(clusters.len(), 2, "should extract two clusters");
        assert!(clusters.contains("web"), "should contain 'web'");
        assert!(clusters.contains("api"), "should contain 'api'");
    }

    #[test]
    fn skips_non_cluster_selecting_entries() {
        let entries = vec![
            make_entry("ip_acl", "allow: [\"10.0.0.0/8\"]"),
            make_entry(
                "mcp",
                "servers:\n  - name: weather\n    cluster: weather-mcp\n    tools: []",
            ),
        ];
        let clusters = extract_selected_clusters(&entries);
        assert!(
            clusters.is_empty(),
            "non-cluster-selecting entries should yield no clusters"
        );
    }

    #[test]
    fn skips_non_lb_entries() {
        let entries = vec![make_entry(
            "router",
            "routes:\n  - path_prefix: \"/\"\n    cluster: web",
        )];
        let clusters = extract_lb_clusters(&entries);
        assert!(clusters.is_empty(), "non-LB entries should yield no clusters");
    }

    #[test]
    fn handles_missing_routes_key() {
        let entries = vec![make_entry("router", "default_upstream: \"1.2.3.4:80\"")];
        let clusters = extract_selected_clusters(&entries);
        assert!(clusters.is_empty(), "missing routes key should yield no clusters");
    }

    #[test]
    fn handles_missing_clusters_key() {
        let entries = vec![make_entry("load_balancer", "mode: round_robin")];
        let clusters = extract_lb_clusters(&entries);
        assert!(clusters.is_empty(), "missing clusters key should yield no clusters");
    }

    #[test]
    fn deduplicates_router_clusters() {
        let entries = vec![
            make_entry("router", "routes:\n  - path_prefix: \"/a\"\n    cluster: web"),
            make_entry("router", "routes:\n  - path_prefix: \"/b\"\n    cluster: web"),
        ];
        let clusters = extract_selected_clusters(&entries);
        assert_eq!(clusters.len(), 1, "duplicate cluster names should be deduplicated");
        assert!(clusters.contains("web"), "should contain 'web'");
    }

    #[test]
    fn empty_entries_yields_empty() {
        let entries: Vec<FilterEntry> = vec![];
        assert!(
            extract_selected_clusters(&entries).is_empty(),
            "empty input should yield empty set"
        );
        assert!(
            extract_lb_clusters(&entries).is_empty(),
            "empty input should yield empty set"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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
}
