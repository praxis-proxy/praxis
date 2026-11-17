// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Cluster endpoint metadata for admin stats snapshots.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use praxis_core::config::{ChainRef, Cluster, Config, FilterEntry};
use serde::Serialize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Filter types whose config may declare inline `clusters:` lists.
const CLUSTER_BEARING_FILTERS: &[&str] = &["load_balancer", "tcp_load_balancer"];

/// Filter type that nests entries under `steps[].filters`.
const STEP_BEARING_FILTER: &str = "iterative_request_router";

// -----------------------------------------------------------------------------
// ClusterMeta
// -----------------------------------------------------------------------------

/// Upstream endpoint addresses for one cluster (from resolved config).
#[derive(Clone, Debug, Serialize)]
pub struct ClusterMeta {
    /// Cluster name.
    pub name: String,
    /// Upstream socket addresses (`host:port`).
    pub endpoints: Vec<String>,
    /// Declaration supplying the endpoint health rows.
    pub endpoint_source: String,
    /// Inline routing declarations for this cluster name.
    pub routed_definitions: Vec<RoutedClusterDefinition>,
}

/// An inline routing declaration with its configuration path.
#[derive(Clone, Debug, Serialize)]
pub struct RoutedClusterDefinition {
    /// Chain, branch and filter path declaring the endpoints.
    pub source: String,
    /// Addresses routed by this declaration.
    pub endpoints: Vec<String>,
}

/// Hot-swappable cluster metadata for `/api/stats`.
pub type ClusterMetaStore = Arc<ArcSwap<HashMap<String, ClusterMeta>>>;

/// Wrap a metadata map in an [`ArcSwap`] store.
pub fn new_cluster_meta_store(meta: HashMap<String, ClusterMeta>) -> ClusterMetaStore {
    Arc::new(ArcSwap::from_pointee(meta))
}

/// Build cluster metadata from configuration.
pub fn cluster_meta_from_config(config: &Config) -> HashMap<String, ClusterMeta> {
    let mut meta: HashMap<String, ClusterMeta> = config
        .clusters
        .iter()
        .map(|cluster| (cluster.name.to_string(), cluster_meta_from_cluster(cluster)))
        .collect();

    for chain in &config.filter_chains {
        for entry in &chain.filters {
            collect_clusters_from_entry(entry, &format!("chain:{}", chain.name), &mut meta);
        }
    }

    meta
}

/// Build metadata for one configured cluster.
fn cluster_meta_from_cluster(cluster: &Cluster) -> ClusterMeta {
    ClusterMeta {
        name: cluster.name.to_string(),
        endpoints: cluster.endpoints.iter().map(|ep| ep.address().to_owned()).collect(),
        endpoint_source: "top_level".to_owned(),
        routed_definitions: Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// Metadata Extraction
// -----------------------------------------------------------------------------

/// Merge inline and nested load-balancer clusters into `meta`.
fn collect_clusters_from_entry(entry: &FilterEntry, scope: &str, meta: &mut HashMap<String, ClusterMeta>) {
    let source = format!("{scope}/filter:{}", entry.name.as_deref().unwrap_or(&entry.filter_type));
    if CLUSTER_BEARING_FILTERS.contains(&entry.filter_type.as_str())
        && let Some(clusters) = inline_clusters_from_entry(entry)
    {
        for cluster in clusters {
            record_routed_cluster(&cluster, &source, meta);
        }
    }

    for branch in entry.branch_chains.as_deref().unwrap_or_default() {
        for chain_ref in &branch.chains {
            if let ChainRef::Inline { name, filters } = chain_ref {
                for nested in filters {
                    collect_clusters_from_entry(nested, &format!("{source}/branch:{}/chain:{name}", branch.name), meta);
                }
            }
        }
    }

    if entry.filter_type == STEP_BEARING_FILTER {
        for (step, nested) in step_filters_from_entry(entry) {
            collect_clusters_from_entry(&nested, &format!("{source}/step:{step}"), meta);
        }
    }
}

/// Preserve the health view while recording every routed declaration.
fn record_routed_cluster(cluster: &Cluster, source: &str, meta: &mut HashMap<String, ClusterMeta>) {
    let mut candidate = cluster_meta_from_cluster(cluster);
    let definition = RoutedClusterDefinition {
        source: source.to_owned(),
        endpoints: candidate.endpoints.clone(),
    };
    match meta.entry(candidate.name.clone()) {
        std::collections::hash_map::Entry::Occupied(mut entry) => entry.get_mut().routed_definitions.push(definition),
        std::collections::hash_map::Entry::Vacant(entry) => {
            source.clone_into(&mut candidate.endpoint_source);
            candidate.routed_definitions.push(definition);
            entry.insert(candidate);
        },
    }
}

/// Deserialize inline `clusters:` from a load-balancer filter entry.
fn inline_clusters_from_entry(entry: &FilterEntry) -> Option<Vec<Cluster>> {
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        return None;
    };
    let clusters_value = mapping.get("clusters")?;
    serde_yaml::from_value(clusters_value.clone()).ok()
}

/// Deserialize nested filters from an `iterative_request_router` entry.
fn step_filters_from_entry(entry: &FilterEntry) -> Vec<(usize, FilterEntry)> {
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        return Vec::new();
    };
    let Some(serde_yaml::Value::Sequence(steps)) = mapping.get("steps") else {
        return Vec::new();
    };
    let mut filters = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let serde_yaml::Value::Mapping(step_map) = step else {
            continue;
        };
        let Some(step_filters) = step_map.get("filters") else {
            continue;
        };
        if let Ok(parsed) = serde_yaml::from_value::<Vec<FilterEntry>>(step_filters.clone()) {
            filters.extend(parsed.into_iter().map(|filter| (index, filter)));
        }
    }
    filters
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_raw_strings,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn cluster_meta_from_config_maps_endpoints() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints:
      - address: "127.0.0.1:9000"
      - address: "127.0.0.1:9001"
filter_chains:
  - name: main
    filters: [{ filter: static_response, status: 200 }]
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let backend = meta.get("backend").expect("backend cluster");
        assert_eq!(
            backend.endpoints,
            vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
            "endpoint addresses should match config"
        );
    }

    #[test]
    fn cluster_meta_from_config_includes_inline_load_balancer_clusters() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
          - name: inline-backend
            endpoints:
              - address: "127.0.0.1:9100"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let backend = meta.get("inline-backend").expect("inline cluster");
        assert_eq!(
            backend.endpoints,
            vec!["127.0.0.1:9100".to_owned()],
            "inline load_balancer cluster should appear in stats metadata"
        );
    }

    #[test]
    fn cluster_meta_from_config_includes_tcp_load_balancer_clusters() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: tcp
    address: "127.0.0.1:8080"
    protocol: tcp
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: tcp-backend
            endpoints:
              - address: "127.0.0.1:9200"
              - address: "127.0.0.1:9201"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let backend = meta.get("tcp-backend").expect("tcp inline cluster");
        assert_eq!(
            backend.endpoints,
            vec!["127.0.0.1:9200".to_owned(), "127.0.0.1:9201".to_owned()],
            "tcp_load_balancer cluster should appear in stats metadata"
        );
    }

    #[test]
    #[ignore]
    fn cluster_meta_from_config_handles_branch_chains() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        action: flag
        rules: []
        branch_chains:
          - on_result:
              filter: guardrails
              result: passed
            rejoin: next
            chains:
              - name: inline_branch
                filters:
                  - filter: load_balancer
                    clusters:
                      - name: branch-backend
                        endpoints:
                          - address: "127.0.0.1:9300"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let backend = meta.get("branch-backend").expect("branch cluster");
        assert_eq!(
            backend.endpoints,
            vec!["127.0.0.1:9300".to_owned()],
            "clusters in branch chains should be collected"
        );
    }

    #[ignore]
    #[test]
    fn cluster_meta_from_config_handles_nested_branches() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: guardrails
        action: flag
        rules: []
        branch_chains:
          - on_result:
              filter: guardrails
              result: passed
            rejoin: next
            chains:
              - name: outer_branch
                filters:
                  - filter: guardrails
                    action: flag
                    rules: []
                    branch_chains:
                      - on_result:
                          filter: guardrails
                          result: passed
                        rejoin: next
                        chains:
                          - name: inner_branch
                            filters:
                              - filter: load_balancer
                                clusters:
                                  - name: nested-backend
                                    endpoints:
                                      - address: "127.0.0.1:9400"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let backend = meta.get("nested-backend").expect("nested branch cluster");
        assert_eq!(
            backend.endpoints,
            vec!["127.0.0.1:9400".to_owned()],
            "clusters in nested branch chains should be collected recursively"
        );
    }

    #[test]
    fn cluster_meta_from_config_handles_iterative_request_router() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        steps:
          - filters:
              - filter: load_balancer
                clusters:
                  - name: step1-backend
                    endpoints:
                      - address: "127.0.0.1:9500"
          - filters:
              - filter: load_balancer
                clusters:
                  - name: step2-backend
                    endpoints:
                      - address: "127.0.0.1:9501"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let step1 = meta.get("step1-backend").expect("step 1 cluster");
        assert_eq!(
            step1.endpoints,
            vec!["127.0.0.1:9500".to_owned()],
            "clusters in iterative_request_router steps should be collected"
        );
        let step2 = meta.get("step2-backend").expect("step 2 cluster");
        assert_eq!(
            step2.endpoints,
            vec!["127.0.0.1:9501".to_owned()],
            "all steps should be processed"
        );
    }

    #[test]
    fn cluster_meta_from_config_skips_non_inline_clusters() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: top-level
    endpoints:
      - address: "127.0.0.1:9000"
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        cluster: top-level
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        let cluster = meta.get("top-level").expect("top-level cluster");
        assert_eq!(
            cluster.endpoints,
            vec!["127.0.0.1:9000".to_owned()],
            "top-level clusters should be collected"
        );
        assert_eq!(meta.len(), 1, "should only collect top-level cluster, not reference");
    }

    #[test]
    fn cluster_meta_from_config_handles_mixed_sources() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: top-level
    endpoints:
      - address: "127.0.0.1:9000"
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
          - name: inline-lb
            endpoints:
              - address: "127.0.0.1:9100"
      - filter: tcp_load_balancer
        clusters:
          - name: inline-tcp
            endpoints:
              - address: "127.0.0.1:9200"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        assert_eq!(
            meta.len(),
            3,
            "should collect from all sources: top-level, inline HTTP, inline TCP"
        );
        assert!(meta.contains_key("top-level"));
        assert!(meta.contains_key("inline-lb"));
        assert!(meta.contains_key("inline-tcp"));
    }

    #[test]
    fn cluster_meta_from_config_deduplicates_cluster_names() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: shared
    endpoints:
      - address: "127.0.0.1:9000"
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
          - name: shared
            endpoints:
              - address: "127.0.0.1:9100"
"#,
        )
        .expect("config should parse");
        let meta = cluster_meta_from_config(&config);
        assert_eq!(
            meta.len(),
            1,
            "duplicate cluster names should not create multiple entries"
        );
        let shared = meta.get("shared").expect("shared cluster");
        assert_eq!(
            shared.endpoints,
            vec!["127.0.0.1:9000".to_owned()],
            "top-level cluster should win (not be overwritten by inline)"
        );
    }

    #[test]
    fn cluster_meta_from_cluster_preserves_all_endpoints() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: multi
    endpoints:
      - address: "127.0.0.1:9000"
      - address: "127.0.0.1:9001"
      - address: "127.0.0.1:9002"
filter_chains:
  - name: main
    filters: [{ filter: static_response, status: 200 }]
"#,
        )
        .expect("config should parse");
        let cluster = config.clusters.first().expect("should have cluster");
        let meta = cluster_meta_from_cluster(cluster);
        assert_eq!(meta.name, "multi");
        assert_eq!(
            meta.endpoints,
            vec![
                "127.0.0.1:9000".to_owned(),
                "127.0.0.1:9001".to_owned(),
                "127.0.0.1:9002".to_owned(),
            ],
            "all endpoints should be preserved in metadata"
        );
    }

    #[test]
    fn new_cluster_meta_store_wraps_in_arcswap() {
        let mut map = HashMap::new();
        map.insert(
            "test".to_owned(),
            ClusterMeta {
                name: "test".to_owned(),
                endpoints: vec!["127.0.0.1:9000".to_owned()],
                endpoint_source: "top_level".to_owned(),
                routed_definitions: Vec::new(),
            },
        );
        let store = new_cluster_meta_store(map);
        let loaded = store.load();
        assert_eq!(loaded.len(), 1);
        let cluster = loaded.get("test").expect("should have test cluster");
        assert_eq!(cluster.name, "test");
        assert_eq!(cluster.endpoints, vec!["127.0.0.1:9000".to_owned()]);
    }

    #[test]
    fn cluster_meta_store_supports_updates() {
        let initial = HashMap::new();
        let store = new_cluster_meta_store(initial);
        assert_eq!(store.load().len(), 0, "should start empty");

        let mut updated = HashMap::new();
        updated.insert(
            "new".to_owned(),
            ClusterMeta {
                name: "new".to_owned(),
                endpoints: vec!["127.0.0.1:9999".to_owned()],
                endpoint_source: "top_level".to_owned(),
                routed_definitions: Vec::new(),
            },
        );
        store.store(Arc::new(updated));

        let loaded = store.load();
        assert_eq!(loaded.len(), 1, "should have updated cluster");
        let cluster = loaded.get("new").expect("should have new cluster");
        assert_eq!(cluster.name, "new");
    }

    #[test]
    fn inline_clusters_from_entry_handles_non_mapping_config() {
        let entry = FilterEntry {
            filter_type: "load_balancer".to_owned(),
            config: serde_yaml::Value::String("not-a-mapping".to_owned()),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = inline_clusters_from_entry(&entry);
        assert!(result.is_none(), "should return None for non-mapping config");
    }

    #[test]
    fn inline_clusters_from_entry_handles_missing_clusters_key() {
        let entry = FilterEntry {
            filter_type: "load_balancer".to_owned(),
            config: serde_yaml::from_str("other_field: value").expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = inline_clusters_from_entry(&entry);
        assert!(result.is_none(), "should return None when clusters key is missing");
    }

    #[test]
    fn inline_clusters_from_entry_handles_malformed_clusters() {
        let entry = FilterEntry {
            filter_type: "load_balancer".to_owned(),
            config: serde_yaml::from_str("clusters: not-a-list").expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = inline_clusters_from_entry(&entry);
        assert!(result.is_none(), "should return None for malformed clusters value");
    }

    #[test]
    fn step_filters_from_entry_handles_non_mapping_config() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::Value::Null,
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert!(result.is_empty(), "should return empty vec for non-mapping config");
    }

    #[test]
    fn step_filters_from_entry_handles_missing_steps() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::from_str("other_field: value").expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert!(result.is_empty(), "should return empty vec when steps key is missing");
    }

    #[test]
    fn step_filters_from_entry_handles_non_sequence_steps() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::from_str("steps: not-a-sequence").expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert!(
            result.is_empty(),
            "should return empty vec when steps is not a sequence"
        );
    }

    #[test]
    fn step_filters_from_entry_skips_non_mapping_steps() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::from_str(
                r#"
steps:
  - "not-a-mapping"
  - filters: []
"#,
            )
            .expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert_eq!(result.len(), 0, "should skip non-mapping steps and process valid ones");
    }

    #[test]
    fn step_filters_from_entry_skips_steps_without_filters() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::from_str(
                r#"
steps:
  - other_field: value
  - filters:
      - filter: static_response
        status: 200
"#,
            )
            .expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert_eq!(
            result.len(),
            1,
            "should skip steps without filters key and process valid ones"
        );
    }

    #[test]
    fn step_filters_from_entry_handles_malformed_filters() {
        let entry = FilterEntry {
            filter_type: "iterative_request_router".to_owned(),
            config: serde_yaml::from_str(
                r#"
steps:
  - filters: "not-valid-filter-list"
"#,
            )
            .expect("should parse"),
            branch_chains: None,
            conditions: Vec::new(),
            name: None,
            response_conditions: Vec::new(),
            failure_mode: praxis_core::config::FailureMode::Closed,
        };
        let result = step_filters_from_entry(&entry);
        assert_eq!(result.len(), 0, "should skip steps with malformed filters");
    }

    #[test]
    fn cluster_meta_clone() {
        let original = ClusterMeta {
            name: "test".to_owned(),
            endpoints: vec!["127.0.0.1:9000".to_owned()],
            endpoint_source: "top_level".to_owned(),
            routed_definitions: Vec::new(),
        };
        let cloned = original.clone();
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.endpoints, cloned.endpoints);
    }

    #[test]
    fn cluster_meta_debug() {
        let meta = ClusterMeta {
            name: "debug-test".to_owned(),
            endpoints: vec!["127.0.0.1:9000".to_owned()],
            endpoint_source: "top_level".to_owned(),
            routed_definitions: Vec::new(),
        };
        let debug_str = format!("{:?}", meta);
        assert!(debug_str.contains("ClusterMeta"));
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("127.0.0.1:9000"));
    }
}
