//! Filter chain validation tests.
//!
//! Covers: empty chain names, duplicates, unknown references,
//! cardinality limits, and valid multi-chain configurations.

use praxis_core::config::Config;

use super::test_utils;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn reject_empty_chain_name() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [""]
filter_chains:
  - name: ""
    filters:
      - filter: request_id
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("must not be empty"), "got: {err}");
}

#[test]
fn reject_duplicate_chain_names() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
  - name: main
    filters:
      - filter: access_log
"#;
    let err = Config::from_yaml(yaml).unwrap_err();
    assert!(err.to_string().contains("duplicate filter chain name"), "got: {err}");
}

#[test]
fn accept_chain_with_zero_filters() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [empty]
filter_chains:
  - name: empty
    filters: []
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert!(
        config.filter_chains[0].filters.is_empty(),
        "empty filters list should be accepted"
    );
}

#[test]
fn accept_chain_with_unknown_filter_name() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: totally_made_up_filter
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.filter_chains[0].filters[0].filter_type, "totally_made_up_filter",
        "unknown filter names should be accepted at config parse time"
    );
}

#[test]
fn reject_unknown_chain_reference() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [nonexistent]
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
    let mut chains = String::from("filter_chains:\n");
    let mut refs = Vec::new();
    for i in 0..1001 {
        chains.push_str(&format!(
            "  - name: chain{i}\n    filters:\n      - filter: request_id\n"
        ));
        refs.push(format!("chain{i}"));
    }
    let chain_list = refs.join(", ");
    let yaml = format!(
        "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n    filter_chains: [{chain_list}]\n{chains}"
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many filter chains"), "got: {err}");
}

#[test]
fn reject_too_many_filters_per_chain() {
    let mut filters = String::new();
    for _ in 0..101 {
        filters.push_str("      - filter: request_id\n");
    }
    let yaml = format!(
        r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [big]
filter_chains:
  - name: big
    filters:
{filters}"#
    );
    let err = Config::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains("too many filters"), "got: {err}");
}

#[test]
fn accept_valid_chains() {
    let config = Config::from_yaml(&test_utils::valid_filter_chain_yaml()).unwrap();
    assert_eq!(config.filter_chains.len(), 1, "should have exactly 1 filter chain");
    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["main"],
        "listener should reference 'main' chain"
    );
}

#[test]
fn accept_multiple_listeners_same_chain() {
    let yaml = r#"
listeners:
  - name: web1
    address: "127.0.0.1:8080"
    filter_chains: [shared]
  - name: web2
    address: "127.0.0.1:9090"
    filter_chains: [shared]
filter_chains:
  - name: shared
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(config.listeners.len(), 2, "should have 2 listeners");
    assert_eq!(
        config.listeners[0].filter_chains,
        vec!["shared"],
        "first listener should reference 'shared'"
    );
    assert_eq!(
        config.listeners[1].filter_chains,
        vec!["shared"],
        "second listener should reference 'shared'"
    );
}

#[test]
fn accept_listener_with_multiple_chains() {
    let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [observability, routing]
filter_chains:
  - name: observability
    filters:
      - filter: request_id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["127.0.0.1:3000"]
"#;
    let config = Config::from_yaml(yaml).unwrap();
    assert_eq!(
        config.listeners[0].filter_chains.len(),
        2,
        "listener should reference 2 chains"
    );
}
