// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Cluster endpoint metadata for admin stats snapshots.

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use praxis_core::config::{ChainRef, Cluster, Config, FilterEntry};
use serde::Serialize;

/// Upstream endpoint addresses for one cluster (from resolved config).
#[derive(Clone, Debug, Serialize)]
pub struct ClusterMeta {
    /// Cluster name.
    pub name: String,
    /// Upstream socket addresses (`host:port`).
    pub endpoints: Vec<String>,
}

/// Hot-swappable cluster metadata for `/api/stats`.
pub type ClusterMetaStore = Arc<ArcSwap<HashMap<String, ClusterMeta>>>;

/// Filter types whose config may declare inline `clusters:` lists.
const CLUSTER_BEARING_FILTERS: &[&str] = &["load_balancer", "tcp_load_balancer"];
/// Filter type that nests entries under `steps[].filters`.
const STEP_BEARING_FILTER: &str = "iterative_request_router";

/// Build cluster metadata from configuration.
pub fn cluster_meta_from_config(config: &Config) -> HashMap<String, ClusterMeta> {
    let mut meta: HashMap<String, ClusterMeta> = config
        .clusters
        .iter()
        .map(|cluster| (cluster.name.to_string(), cluster_meta_from_cluster(cluster)))
        .collect();

    for chain in &config.filter_chains {
        for entry in &chain.filters {
            collect_clusters_from_entry(entry, &mut meta);
        }
    }

    meta
}

/// Build metadata for one configured cluster.
fn cluster_meta_from_cluster(cluster: &Cluster) -> ClusterMeta {
    ClusterMeta {
        name: cluster.name.to_string(),
        endpoints: cluster.endpoints.iter().map(|ep| ep.address().to_owned()).collect(),
    }
}

/// Merge inline and nested load-balancer clusters into `meta`.
fn collect_clusters_from_entry(entry: &FilterEntry, meta: &mut HashMap<String, ClusterMeta>) {
    if CLUSTER_BEARING_FILTERS.contains(&entry.filter_type.as_str())
        && let Some(clusters) = inline_clusters_from_entry(entry)
    {
        for cluster in clusters {
            meta.entry(cluster.name.to_string())
                .or_insert_with(|| cluster_meta_from_cluster(&cluster));
        }
    }

    for branch in entry.branch_chains.as_deref().unwrap_or_default() {
        for chain_ref in &branch.chains {
            if let ChainRef::Inline { filters, .. } = chain_ref {
                for nested in filters {
                    collect_clusters_from_entry(nested, meta);
                }
            }
        }
    }

    if entry.filter_type == STEP_BEARING_FILTER {
        for nested in step_filters_from_entry(entry) {
            collect_clusters_from_entry(&nested, meta);
        }
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
fn step_filters_from_entry(entry: &FilterEntry) -> Vec<FilterEntry> {
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        return Vec::new();
    };
    let Some(serde_yaml::Value::Sequence(steps)) = mapping.get("steps") else {
        return Vec::new();
    };
    let mut filters = Vec::new();
    for step in steps {
        let serde_yaml::Value::Mapping(step_map) = step else {
            continue;
        };
        let Some(step_filters) = step_map.get("filters") else {
            continue;
        };
        if let Ok(parsed) = serde_yaml::from_value::<Vec<FilterEntry>>(step_filters.clone()) {
            filters.extend(parsed);
        }
    }
    filters
}

/// Wrap a metadata map in an [`ArcSwap`] store.
pub fn new_cluster_meta_store(meta: HashMap<String, ClusterMeta>) -> ClusterMetaStore {
    Arc::new(ArcSwap::from_pointee(meta))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
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
}
