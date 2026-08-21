// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Validation for clusters defined inline in load-balancer filter configs.
//!
//! The `load_balancer` and `tcp_load_balancer` filters accept a `clusters:`
//! list inside their opaque filter config. Those clusters must pass the same
//! validation as top-level `clusters:` — endpoint weight ceiling, SSRF
//! endpoint gating, insecure-TLS gating, timeouts — otherwise the inline
//! form silently bypasses every safety check (`validate_clusters` runs only
//! over `Config::clusters`).

use std::collections::HashSet;

use super::cluster::validate_clusters;
use crate::{
    config::{ChainRef, Cluster, FilterChainConfig, FilterEntry, InsecureOptions},
    errors::ProxyError,
};

/// Filter type names whose config may define inline clusters.
const CLUSTER_BEARING_FILTERS: &[&str] = &["load_balancer", "tcp_load_balancer"];

/// Filter type whose config nests filter entries under `steps[].filters`.
const STEP_BEARING_FILTER: &str = "iterative_request_router";

// -----------------------------------------------------------------------------
// Inline Cluster Validation
// -----------------------------------------------------------------------------

/// Validate inline `clusters:` lists in every load-balancer filter entry,
/// including entries nested in inline branch chains.
pub(super) fn validate_inline_clusters(
    chains: &[FilterChainConfig],
    insecure_options: &InsecureOptions,
) -> Result<(), ProxyError> {
    for chain in chains {
        for entry in &chain.filters {
            validate_entry(&chain.name, entry, insecure_options)?;
        }
    }
    Ok(())
}

/// Validate one filter entry and recurse into its inline branch chains.
fn validate_entry(chain_name: &str, entry: &FilterEntry, insecure_options: &InsecureOptions) -> Result<(), ProxyError> {
    if CLUSTER_BEARING_FILTERS.contains(&entry.filter_type.as_str()) {
        let clusters = extract_clusters(chain_name, entry)?;
        validate_inline_names(chain_name, &entry.filter_type, &clusters)?;
        validate_clusters(&clusters, insecure_options).map_err(|e| {
            ProxyError::Config(format!(
                "chain '{chain_name}': filter '{}': inline {e}",
                entry.filter_type
            ))
        })?;
    }

    for branch in entry.branch_chains.as_deref().unwrap_or_default() {
        for chain_ref in &branch.chains {
            if let ChainRef::Inline { name, filters } = chain_ref {
                for nested in filters {
                    validate_entry(name, nested, insecure_options)?;
                }
            }
        }
    }

    if entry.filter_type == STEP_BEARING_FILTER {
        for nested in extract_step_filters(chain_name, entry)? {
            validate_entry(chain_name, &nested, insecure_options)?;
        }
    }
    Ok(())
}

/// Deserialize filter entries nested under an `iterative_request_router`
/// filter's `steps[].filters`.
///
/// These live in the opaque filter config exactly like inline branch
/// filters, and can themselves declare inline load-balancer clusters that
/// would otherwise bypass validation.
fn extract_step_filters(chain_name: &str, entry: &FilterEntry) -> Result<Vec<FilterEntry>, ProxyError> {
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        return Ok(Vec::new());
    };
    let Some(serde_yaml::Value::Sequence(steps)) = mapping.get("steps") else {
        return Ok(Vec::new());
    };
    let mut filters = Vec::new();
    for step in steps {
        let serde_yaml::Value::Mapping(step_map) = step else {
            continue;
        };
        let Some(step_filters) = step_map.get("filters") else {
            continue;
        };
        let parsed: Vec<FilterEntry> = serde_yaml::from_value(step_filters.clone()).map_err(|e| {
            ProxyError::Config(format!(
                "chain '{chain_name}': filter '{}': invalid step filters: {e}",
                entry.filter_type
            ))
        })?;
        filters.extend(parsed);
    }
    Ok(filters)
}

/// Deserialize the `clusters` key from an opaque filter config, if present.
///
/// A malformed list is an error here (with chain/filter context) rather
/// than a startup failure deep inside the filter factory.
fn extract_clusters(chain_name: &str, entry: &FilterEntry) -> Result<Vec<Cluster>, ProxyError> {
    let serde_yaml::Value::Mapping(mapping) = &entry.config else {
        return Ok(Vec::new());
    };
    let Some(clusters_value) = mapping.get("clusters") else {
        return Ok(Vec::new());
    };
    serde_yaml::from_value(clusters_value.clone()).map_err(|e| {
        ProxyError::Config(format!(
            "chain '{chain_name}': filter '{}': invalid inline clusters: {e}",
            entry.filter_type
        ))
    })
}

/// Reject duplicate cluster names within one filter's inline list.
fn validate_inline_names(chain_name: &str, filter_type: &str, clusters: &[Cluster]) -> Result<(), ProxyError> {
    let mut seen = HashSet::new();
    for cluster in clusters {
        if !seen.insert(&cluster.name) {
            return Err(ProxyError::Config(format!(
                "chain '{chain_name}': filter '{filter_type}': duplicate inline cluster name '{}'",
                cluster.name
            )));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests use unwrap/expect for brevity"
)]
mod tests {
    use crate::config::Config;

    /// Base YAML with an inline `load_balancer` cluster spliced in.
    fn config_with_inline_cluster(cluster_yaml: &str) -> String {
        format!(
            "listeners:\n  - name: main\n    address: \"127.0.0.1:18080\"\n    protocol: http\n    filter_chains: [chain]\nfilter_chains:\n  - name: chain\n    filters:\n      - filter: load_balancer\n        clusters:\n{cluster_yaml}"
        )
    }

    #[test]
    fn inline_cluster_weight_over_ceiling_rejected() {
        let yaml = config_with_inline_cluster(
            "          - name: web\n            endpoints:\n              - address: \"192.0.2.1:80\"\n                weight: 2000000000\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("weight") && err.to_string().contains("chain"),
            "inline endpoint weight must hit the same ceiling as top-level clusters: {err}"
        );
    }

    #[test]
    fn inline_cluster_insecure_tls_rejected_without_flag() {
        let yaml = config_with_inline_cluster(
            "          - name: web\n            tls:\n              verify: false\n            endpoints:\n              - address: \"192.0.2.1:443\"\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("verify"),
            "inline tls.verify: false must be gated like top-level clusters: {err}"
        );
    }

    #[test]
    fn inline_cluster_empty_endpoints_rejected() {
        let yaml = config_with_inline_cluster("          - name: web\n            endpoints: []\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("endpoint"),
            "inline cluster without endpoints must be rejected: {err}"
        );
    }

    #[test]
    fn inline_cluster_duplicate_names_rejected() {
        let yaml = config_with_inline_cluster(
            "          - name: web\n            endpoints:\n              - address: \"192.0.2.1:80\"\n          - name: web\n            endpoints:\n              - address: \"192.0.2.2:80\"\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate inline cluster name"),
            "duplicate inline cluster names must be rejected: {err}"
        );
    }

    #[test]
    fn inline_cluster_malformed_list_rejected() {
        let yaml = config_with_inline_cluster("          - just-a-string\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("invalid inline clusters"),
            "malformed inline clusters must fail validation with context: {err}"
        );
    }

    #[test]
    fn valid_inline_cluster_accepted() {
        let yaml = config_with_inline_cluster(
            "          - name: web\n            endpoints:\n              - address: \"192.0.2.1:80\"\n                weight: 5\n",
        );
        Config::from_yaml(&yaml).expect("valid inline cluster should pass validation");
    }

    #[test]
    fn inline_cluster_in_iterative_router_step_validated() {
        let yaml = "listeners:\n  - name: main\n    address: \"127.0.0.1:18080\"\n    protocol: http\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: iterative_request_router\n        steps:\n          - name: call\n            filters:\n              - filter: load_balancer\n                clusters:\n                  - name: web\n                    endpoints:\n                      - address: \"192.0.2.1:80\"\n                        weight: 2000000000\n";
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("weight"),
            "clusters inside iterative_request_router steps must be validated: {err}"
        );
    }

    #[test]
    fn inline_cluster_in_branch_chain_validated() {
        let yaml = "listeners:\n  - name: main\n    address: \"127.0.0.1:18080\"\n    protocol: http\n    filter_chains: [chain]\nfilter_chains:\n  - name: chain\n    filters:\n      - filter: header_static\n        headers:\n          x-a: b\n        branch_chains:\n          - name: br\n            chains:\n              - name: inline-sub\n                filters:\n                  - filter: load_balancer\n                    clusters:\n                      - name: web\n                        endpoints:\n                          - address: \"192.0.2.1:80\"\n                            weight: 2000000000\n            rejoin: next\n";
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("weight"),
            "branch-chain inline clusters must be validated too: {err}"
        );
    }
}
