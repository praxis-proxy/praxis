// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Filter chain validation: cardinality, name uniqueness, and listener references.

use std::collections::{HashMap, HashSet};

use crate::{
    config::{ChainRef, Condition, ConditionMatch, FilterChainConfig, FilterEntry, Listener, ResponseCondition},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of filter chains allowed in the configuration.
const MAX_CHAINS: usize = 1_000;

/// Maximum number of filters allowed per filter chain.
pub(super) const MAX_FILTERS_PER_CHAIN: usize = 100;

// -----------------------------------------------------------------------------
// Filter Chain Validation
// -----------------------------------------------------------------------------

/// Validate chain count, name uniqueness, and listener references.
pub(super) fn validate_filter_chains(chains: &[FilterChainConfig], listeners: &[Listener]) -> Result<(), ProxyError> {
    validate_chain_cardinality(chains)?;
    validate_chain_names(chains)?;
    validate_terminal_filters(chains)?;
    validate_conditions(chains)?;
    validate_listener_references(chains, listeners)
}

/// Reject conditions whose match predicate is empty.
///
/// An empty predicate (`when: {}` / `unless: {}`) matches every request,
/// so `unless: {}` silently disables its filter — almost certainly a
/// config-generation or editing accident rather than intent.
fn validate_conditions(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    for chain in chains {
        for entry in &chain.filters {
            validate_entry_conditions(&chain.name, entry)?;
        }
    }
    Ok(())
}

/// Reject empty condition predicates on one filter entry, recursing
/// into inline branch chains.
fn validate_entry_conditions(chain_name: &str, entry: &FilterEntry) -> Result<(), ProxyError> {
    validate_request_conditions(chain_name, entry)?;
    validate_response_conditions(chain_name, entry)?;
    if let Some(branches) = &entry.branch_chains {
        for branch in branches {
            for chain_ref in &branch.chains {
                if let ChainRef::Inline { filters, .. } = chain_ref {
                    for inline_entry in filters {
                        validate_entry_conditions(chain_name, inline_entry)?;
                    }
                }
            }
        }
    }
    // Filters nested in an iterative_request_router's steps are built into
    // real pipelines, so their conditions need the same empty-predicate
    // check (matching the inline-cluster validation walk).
    if entry.filter_type == super::inline_clusters::STEP_BEARING_FILTER {
        for nested in super::inline_clusters::extract_step_filters(chain_name, entry)? {
            validate_entry_conditions(chain_name, &nested)?;
        }
    }
    Ok(())
}

/// Reject empty request-condition predicates on one filter entry.
fn validate_request_conditions(chain_name: &str, entry: &FilterEntry) -> Result<(), ProxyError> {
    for (idx, condition) in entry.conditions.iter().enumerate() {
        let matcher = match condition {
            Condition::When(m) | Condition::Unless(m) => m,
        };
        if matcher.path.is_none()
            && matcher.path_prefix.is_none()
            && matcher.methods.is_none()
            && matcher.headers.is_none()
        {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': condition {idx} is \
                 empty; set at least one of path, path_prefix, methods, or \
                 headers (an empty condition matches every request, so \
                 'unless' would disable the filter entirely)",
                filter = entry.filter_type,
            )));
        }
        // An empty container is as pathological as an all-absent predicate:
        // `methods: []` can never match and `headers: {}` always matches.
        if matcher.methods.as_ref().is_some_and(Vec::is_empty) {
            return Err(empty_predicate_error(chain_name, &entry.filter_type, idx, "methods"));
        }
        if matcher.headers.as_ref().is_some_and(HashMap::is_empty) {
            return Err(empty_predicate_error(chain_name, &entry.filter_type, idx, "headers"));
        }
        validate_condition_paths(chain_name, &entry.filter_type, idx, matcher)?;
    }
    Ok(())
}

/// Reject condition `path`/`path_prefix` values that make the predicate a no-op.
///
/// Request paths always begin with '/', so a condition path without the
/// leading slash can never match — a `when` then silently disables the gated
/// filter (an `unless` silently un-gates it). Same accident class the
/// router's route validation rejects. An empty `path` can never match and an
/// empty `path_prefix` matches every request; both are equally pathological.
fn validate_condition_paths(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &ConditionMatch,
) -> Result<(), ProxyError> {
    for (field, value) in [("path", &matcher.path), ("path_prefix", &matcher.path_prefix)] {
        if let Some(value) = value
            && !value.starts_with('/')
        {
            let consequence = if value.is_empty() {
                "an empty value makes this predicate a no-op"
            } else {
                "request paths always begin with '/', so this condition could never match"
            };
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': condition {idx} \
                 {field} must start with '/' (got '{value}'); {consequence}",
            )));
        }
    }
    Ok(())
}

/// Reject empty response-condition predicates on one filter entry.
fn validate_response_conditions(chain_name: &str, entry: &FilterEntry) -> Result<(), ProxyError> {
    for (idx, condition) in entry.response_conditions.iter().enumerate() {
        let matcher = match condition {
            ResponseCondition::When(m) | ResponseCondition::Unless(m) => m,
        };
        if matcher.status.is_none() && matcher.headers.is_none() {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': response condition \
                 {idx} is empty; set at least one of status or headers",
                filter = entry.filter_type,
            )));
        }
        if matcher.status.as_ref().is_some_and(Vec::is_empty) {
            return Err(empty_predicate_error(
                chain_name,
                &entry.filter_type,
                idx,
                "response status",
            ));
        }
        if matcher.headers.as_ref().is_some_and(HashMap::is_empty) {
            return Err(empty_predicate_error(
                chain_name,
                &entry.filter_type,
                idx,
                "response headers",
            ));
        }
    }
    Ok(())
}

/// Error for a condition predicate given as an empty container.
fn empty_predicate_error(chain_name: &str, filter: &str, idx: usize, field: &str) -> ProxyError {
    ProxyError::Config(format!(
        "filter '{filter}' in chain '{chain_name}': condition {idx} has an \
         empty {field} list; remove the field or list at least one value"
    ))
}

/// Filter types that must be the last filter in their chain and in
/// the flattened listener pipeline.
pub const TERMINAL_FILTERS: &[&str] = &["iterative_request_router"];

/// Reject terminal filters that are not last in their chain.
fn validate_terminal_filters(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    for chain in chains {
        for (i, entry) in chain.filters.iter().enumerate() {
            if TERMINAL_FILTERS.contains(&entry.filter_type.as_str()) && i + 1 < chain.filters.len() {
                return Err(ProxyError::Config(format!(
                    "filter '{}' must be the last filter in chain '{}' \
                     because it produces terminal responses",
                    entry.filter_type, chain.name
                )));
            }
        }
    }
    Ok(())
}

/// Reject configs that exceed chain or per-chain filter limits.
fn validate_chain_cardinality(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    if chains.len() > MAX_CHAINS {
        return Err(ProxyError::Config(format!(
            "too many filter chains ({}, max {MAX_CHAINS})",
            chains.len()
        )));
    }
    for chain in chains {
        if chain.filters.len() > MAX_FILTERS_PER_CHAIN {
            return Err(ProxyError::Config(format!(
                "filter chain '{}' has too many filters ({}, max \
                 {MAX_FILTERS_PER_CHAIN})",
                chain.name,
                chain.filters.len()
            )));
        }
    }
    Ok(())
}

/// Reject empty, invalid-character, or duplicate chain names.
fn validate_chain_names(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    let mut seen = HashSet::new();
    for chain in chains {
        if chain.name.is_empty() {
            return Err(ProxyError::Config("filter chain name must not be empty".into()));
        }
        super::validate_name_chars(&chain.name, "filter chain")?;
        if !seen.insert(&chain.name) {
            return Err(ProxyError::Config(format!(
                "duplicate filter chain name '{}'",
                chain.name
            )));
        }
    }
    Ok(())
}

/// Reject listener references to non-existent chains.
fn validate_listener_references(chains: &[FilterChainConfig], listeners: &[Listener]) -> Result<(), ProxyError> {
    let chain_names: HashSet<&str> = chains.iter().map(|c| c.name.as_str()).collect();
    for listener in listeners {
        for chain_ref in &listener.filter_chains {
            if !chain_names.contains(chain_ref.as_str()) {
                return Err(ProxyError::Config(format!(
                    "listener '{}' references unknown filter chain \
                     '{chain_ref}'",
                    listener.name
                )));
            }
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
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use std::fmt::Write as _;

    use crate::config::Config;

    #[test]
    fn reject_empty_chain_name() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - ""
filter_chains:
  - name: ""
    filters:
      - filter: request_id
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn reject_empty_unless_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        deny: ["10.0.0.0/8"]
        conditions:
          - unless: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("condition 0 is empty"),
            "an empty unless predicate silently disables the filter: {err}"
        );
    }

    #[test]
    fn reject_empty_condition_in_iterative_router_step() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        steps:
          - name: call
            url: "http://backend"
            filters:
              - filter: ip_acl
                deny: ["10.0.0.0/8"]
                conditions:
                  - unless: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("condition 0 is empty"),
            "an empty predicate inside an IRR step must be rejected too: {err}"
        );
    }

    #[test]
    fn reject_empty_when_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("is empty"),
            "an empty when predicate should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_methods_list_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when:
              methods: []
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty methods list"),
            "an empty methods list can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_headers_map_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - unless:
              headers: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty headers list"),
            "an empty headers map matches vacuously and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_condition_path_without_leading_slash() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when:
              path: "health"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("path must start with '/'"),
            "a condition path without a leading '/' can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_condition_path_prefix_without_leading_slash() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - unless:
              path_prefix: "api"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("path_prefix must start with '/'"),
            "a condition path_prefix without a leading '/' can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_condition_empty_path_prefix() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when:
              path_prefix: ""
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("no-op"),
            "an empty condition path_prefix matches everything and must be rejected: {err}"
        );
    }

    #[test]
    fn accept_condition_path_with_leading_slash() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when:
              path_prefix: "/api"
"#;
        assert!(
            Config::from_yaml(yaml).is_ok(),
            "a '/'-prefixed condition path_prefix should be accepted"
        );
    }

    #[test]
    fn reject_empty_status_list_response_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        response_add:
          - name: X-A
            value: b
        response_conditions:
          - when:
              status: []
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty response status list"),
            "an empty status list can never match and must be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_response_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        response_conditions:
          - when: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("response condition 0 is empty"),
            "an empty response predicate should be rejected: {err}"
        );
    }

    #[test]
    fn accept_populated_conditions() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        conditions:
          - when:
              path_prefix: "/health"
"#;
        Config::from_yaml(yaml).expect("populated conditions are valid");
    }

    #[test]
    fn reject_empty_condition_in_inline_branch_chain() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: branch
            chains:
              - name: inline
                filters:
                  - filter: headers
                    conditions:
                      - unless: {}
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("condition 0 is empty"),
            "empty predicates inside inline branch chains should be rejected: {err}"
        );
    }

    #[test]
    fn reject_duplicate_chain_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: request_id
  - name: main
    filters:
      - filter: access_log
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("duplicate filter chain name"));
    }

    #[test]
    fn reject_chain_name_with_special_chars() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - "bad.chain"
filter_chains:
  - name: "bad.chain"
    filters:
      - filter: request_id
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "filter chain names with special chars should be rejected: {err}"
        );
    }

    #[test]
    fn reject_unknown_chain_reference() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - nonexistent
filter_chains:
  - name: main
    filters:
      - filter: request_id
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown filter chain"), "got: {err}");
    }

    #[test]
    fn reject_too_many_chains() {
        let mut yaml = String::from(
            "listeners:\n  - name: web\n    address: \"0.0.0.0:8080\"\n    filter_chains: [c0]\nfilter_chains:\n",
        );
        for i in 0..1_001 {
            write!(yaml, "  - name: c{i}\n    filters:\n      - filter: headers\n").unwrap();
        }
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("too many filter chains"),
            "should reject exceeding MAX_CHAINS: {err}"
        );
    }

    #[test]
    fn reject_too_many_filters_per_chain() {
        let mut yaml = String::from(
            "listeners:\n  - name: web\n    address: \"0.0.0.0:8080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n",
        );
        for _ in 0..101 {
            yaml.push_str("      - filter: headers\n");
        }
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("too many filters"),
            "should reject exceeding MAX_FILTERS_PER_CHAIN: {err}"
        );
    }

    #[test]
    fn accept_exactly_max_chains() {
        let mut yaml = String::from(
            "listeners:\n  - name: web\n    address: \"0.0.0.0:8080\"\n    filter_chains: [c0]\nfilter_chains:\n",
        );
        for i in 0..1_000 {
            write!(yaml, "  - name: c{i}\n    filters:\n      - filter: headers\n").unwrap();
        }
        Config::from_yaml(&yaml).expect("exactly MAX_CHAINS should be accepted");
    }

    #[test]
    fn accept_exactly_max_filters_per_chain() {
        let mut yaml = String::from(
            "listeners:\n  - name: web\n    address: \"0.0.0.0:8080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n",
        );
        for _ in 0..100 {
            yaml.push_str("      - filter: headers\n");
        }
        Config::from_yaml(&yaml).expect("exactly MAX_FILTERS_PER_CHAIN should be accepted");
    }

    #[test]
    fn reject_terminal_filter_not_last() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
      - filter: headers
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("must be the last filter"), "got: {err}");
    }

    #[test]
    fn accept_terminal_filter_when_last() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: headers
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
"#;
        Config::from_yaml(yaml).expect("terminal filter as last should be accepted");
    }

    #[test]
    fn valid_chain_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints: ["10.0.0.1:8080"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.filter_chains.len(), 1, "should have 1 filter chain");
        assert_eq!(
            config.listeners[0].filter_chains,
            vec!["main"],
            "listener should reference 'main' chain"
        );
    }
}
