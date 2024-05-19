//! Filter chain validation: cardinality, name uniqueness, and listener
//! references.

use std::collections::HashSet;

use crate::{
    config::{FilterChainConfig, Listener},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

/// Validate chain count, name uniqueness, and listener references.
pub(super) fn validate_filter_chains(chains: &[FilterChainConfig], listeners: &[Listener]) -> Result<(), ProxyError> {
    const MAX_CHAINS: usize = 1_000;
    const MAX_FILTERS_PER_CHAIN: usize = 100;

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

    let mut seen = HashSet::new();
    for chain in chains {
        if chain.name.is_empty() {
            return Err(ProxyError::Config("filter chain name must not be empty".into()));
        }
        if !seen.insert(&chain.name) {
            return Err(ProxyError::Config(format!(
                "duplicate filter chain name '{}'",
                chain.name
            )));
        }
    }

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
mod tests {
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
        assert!(err.to_string().contains("unknown filter chain"), "got: {}", err);
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
        assert_eq!(config.filter_chains.len(), 1);
        assert_eq!(config.listeners[0].filter_chains, vec!["main"]);
    }
}
