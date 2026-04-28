// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Branch chain validation: name uniqueness, chain references, cycle detection, and nesting depth.

use std::collections::HashSet;

use crate::{
    config::{BranchChainConfig, ChainRef, FilterChainConfig, FilterEntry},
    errors::ProxyError,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum allowed branch nesting depth (inline chains within
/// inline chains). Limits config complexity and prevents
/// combinatorial explosion during build-time resolution.
/// Each level allocates its own name index and filter vec,
/// so deep nesting multiplies startup cost.
pub const MAX_BRANCH_DEPTH: usize = 10;

/// Maximum allowed `max_iterations` value for re-entrant
/// branches. Prevents accidental infinite loops when a
/// branch rejoins at or before its own filter. Every
/// re-entrant branch must specify `max_iterations`; this
/// ceiling caps what users can configure.
pub const MAX_ITERATIONS_CEILING: u32 = 100;

// -----------------------------------------------------------------------------
// Branch Chain Validation
// -----------------------------------------------------------------------------

/// Validate all branch chains across all filter chains.
pub(crate) fn validate_branch_chains(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    let chain_names: HashSet<&str> = chains.iter().map(|c| c.name.as_str()).collect();
    let mut all_names: HashSet<String> = chain_names.iter().map(|s| (*s).to_owned()).collect();

    for chain in chains {
        validate_filter_names_unique(&chain.filters, &chain.name)?;
        collect_branch_names(&chain.filters, &mut all_names, &chain_names, 0)?;
    }

    Ok(())
}

/// Validate that filter names within a chain are unique.
fn validate_filter_names_unique(filters: &[FilterEntry], chain_name: &str) -> Result<(), ProxyError> {
    let mut seen = HashSet::new();
    for entry in filters {
        if let Some(name) = &entry.name {
            validate_filter_name_chars(name)?;
            if !seen.insert(name.as_str()) {
                return Err(ProxyError::Config(format!(
                    "duplicate filter name '{name}' in chain '{chain_name}'"
                )));
            }
        }
    }
    Ok(())
}

/// Validate that a filter name contains only valid characters.
fn validate_filter_name_chars(name: &str) -> Result<(), ProxyError> {
    if name.is_empty() {
        return Err(ProxyError::Config("filter name must not be empty".into()));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ProxyError::Config(format!(
            "filter name '{name}' must be ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}

/// Recursively collect and validate branch names, chain refs, and nesting depth.
fn collect_branch_names(
    filters: &[FilterEntry],
    all_names: &mut HashSet<String>,
    chain_names: &HashSet<&str>,
    depth: usize,
) -> Result<(), ProxyError> {
    // `validate_chain_ref` checks depth before recursing here,
    // so this should never fire. Keep as a safety net.
    debug_assert!(
        depth <= MAX_BRANCH_DEPTH,
        "collect_branch_names entered at depth {depth} > {MAX_BRANCH_DEPTH}"
    );

    for entry in filters {
        let Some(branches) = &entry.branch_chains else {
            continue;
        };
        for branch in branches {
            validate_branch(branch, all_names, chain_names, depth)?;
        }
    }
    Ok(())
}

/// Validate a single branch chain config.
fn validate_branch(
    branch: &BranchChainConfig,
    all_names: &mut HashSet<String>,
    chain_names: &HashSet<&str>,
    depth: usize,
) -> Result<(), ProxyError> {
    if !all_names.insert(branch.name.clone()) {
        return Err(ProxyError::Config(format!("duplicate branch name '{}'", branch.name)));
    }

    if branch.rejoin.contains(':') {
        return Err(ProxyError::Config(format!(
            "branch '{}': cross-chain rejoin '{}' is not supported; \
             listeners flatten all referenced chains into one pipeline, \
             so use the filter's name directly (e.g. 'routing' not 'main:routing')",
            branch.name, branch.rejoin
        )));
    }

    if branch.chains.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{}' must have at least one chain",
            branch.name
        )));
    }

    validate_max_iterations(branch)?;
    validate_on_result_filter_name(branch)?;

    for chain_ref in &branch.chains {
        validate_chain_ref(chain_ref, all_names, chain_names, depth)?;
    }

    Ok(())
}

/// Validate that `on_result.filter` is non-empty and uses valid name characters.
fn validate_on_result_filter_name(branch: &BranchChainConfig) -> Result<(), ProxyError> {
    let Some(cond) = &branch.on_result else {
        return Ok(());
    };

    if cond.filter.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{}': on_result.filter must not be empty",
            branch.name
        )));
    }
    if !cond
        .filter
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ProxyError::Config(format!(
            "branch '{}': on_result.filter '{}' must be ASCII alphanumeric, '_', or '-'",
            branch.name, cond.filter
        )));
    }
    Ok(())
}

/// Validate `max_iterations` constraints.
fn validate_max_iterations(branch: &BranchChainConfig) -> Result<(), ProxyError> {
    if let Some(max) = branch.max_iterations
        && !(1..=MAX_ITERATIONS_CEILING).contains(&max)
    {
        return Err(ProxyError::Config(format!(
            "branch '{}': max_iterations must be 1-{MAX_ITERATIONS_CEILING}, got {max}",
            branch.name
        )));
    }
    Ok(())
}

/// Validate a single chain reference.
fn validate_chain_ref(
    chain_ref: &ChainRef,
    all_names: &mut HashSet<String>,
    chain_names: &HashSet<&str>,
    depth: usize,
) -> Result<(), ProxyError> {
    match chain_ref {
        ChainRef::Named(name) => {
            if !chain_names.contains(name.as_str()) {
                return Err(ProxyError::Config(format!("branch references unknown chain '{name}'")));
            }
        },
        ChainRef::Inline { name, filters } => {
            if depth + 1 > MAX_BRANCH_DEPTH {
                return Err(ProxyError::Config(format!(
                    "branch nesting depth exceeds maximum ({MAX_BRANCH_DEPTH})"
                )));
            }
            if !all_names.insert(name.clone()) {
                return Err(ProxyError::Config(format!("duplicate inline chain name '{name}'")));
            }
            collect_branch_names(filters, all_names, chain_names, depth + 1)?;
        },
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::panic,
    reason = "tests use unwrap/expect/indexing/raw strings/panic for brevity"
)]
mod tests {
    use crate::config::Config;

    #[test]
    fn valid_branch_config() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: utility
    filters:
      - filter: headers
  - name: main
    filters:
      - filter: headers
        name: pre_route
        branch_chains:
          - name: my_branch
            chains:
              - utility
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.filter_chains.len(), 2, "should have 2 chains");
    }

    #[test]
    fn reject_duplicate_branch_name() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: dup
            chains:
              - name: inline1
                filters:
                  - filter: headers
          - name: dup
            chains:
              - name: inline2
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate branch name"),
            "should reject duplicate branch name: {err}"
        );
    }

    #[test]
    fn reject_duplicate_filter_name_in_chain() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: same
      - filter: cors
        name: same
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate filter name"),
            "should reject duplicate filter name: {err}"
        );
    }

    #[test]
    fn reject_unknown_chain_ref() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: my_branch
            chains:
              - nonexistent_chain
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unknown chain"),
            "should reject unknown chain ref: {err}"
        );
    }

    #[test]
    fn reject_empty_branch_chains() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: empty_branch
            chains: []
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("at least one chain"),
            "should reject empty branch chains: {err}"
        );
    }

    #[test]
    fn reject_max_iterations_zero() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: retry
            max_iterations: 0
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_iterations must be 1-100"),
            "should reject max_iterations=0: {err}"
        );
    }

    #[test]
    fn reject_max_iterations_too_high() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: retry
            max_iterations: 101
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("max_iterations must be 1-100"),
            "should reject max_iterations=101: {err}"
        );
    }

    #[test]
    fn accept_max_iterations_valid_range() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: retry
            max_iterations: 3
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_invalid_filter_name_chars() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: "bad.name"
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "should reject filter name with dots: {err}"
        );
    }

    #[test]
    fn accept_valid_filter_names() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: pre-route_1
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_duplicate_inline_chain_name() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: branch_a
            chains:
              - name: inline
                filters:
                  - filter: headers
          - name: branch_b
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate inline chain name"),
            "should reject duplicate inline chain name: {err}"
        );
    }

    #[test]
    fn reject_nesting_depth_exceeded() {
        fn nested_yaml(depth: usize) -> String {
            let mut yaml = String::from(
                r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
"#,
            );

            fn write_level(yaml: &mut String, depth: usize, current: usize, indent: usize) {
                let pad = " ".repeat(indent);
                let filter_name = format!("branch_{current}");
                let chain_name = format!("inline_{current}");
                yaml.push_str(&format!("{pad}- filter: headers\n"));
                if current < depth {
                    yaml.push_str(&format!("{pad}  branch_chains:\n"));
                    yaml.push_str(&format!("{pad}    - name: {filter_name}\n"));
                    yaml.push_str(&format!("{pad}      chains:\n"));
                    yaml.push_str(&format!("{pad}        - name: {chain_name}\n"));
                    yaml.push_str(&format!("{pad}          filters:\n"));
                    write_level(yaml, depth, current + 1, indent + 12);
                }
            }

            write_level(&mut yaml, depth, 0, 6);

            yaml.push_str(
                r#"      - filter: static_response
        status: 200
"#,
            );
            yaml
        }

        let yaml = nested_yaml(11);
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("nesting depth"),
            "should reject excessive nesting depth: {err}"
        );
    }

    #[test]
    fn accept_nesting_within_limit() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: level_0
            chains:
              - name: inline_0
                filters:
                  - filter: headers
                    branch_chains:
                      - name: level_1
                        chains:
                          - name: inline_1
                            filters:
                              - filter: headers
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }

    #[test]
    fn reject_cross_chain_rejoin() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: cross
            rejoin: "other:routing"
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("cross-chain rejoin"),
            "should reject cross-chain rejoin syntax: {err}"
        );
    }

    #[test]
    fn reject_empty_filter_name() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        name: ""
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "should reject empty filter name: {err}"
        );
    }

    #[test]
    fn accept_max_iterations_at_boundaries() {
        let yaml_1 = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: retry
            max_iterations: 1
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml_1).unwrap();

        let yaml_100 = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: retry
            max_iterations: 100
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml_100).unwrap();
    }

    #[test]
    fn reject_empty_on_result_filter() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: bad_branch
            on_result:
              filter: ""
              result: hit
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("on_result.filter must not be empty"),
            "should reject empty on_result.filter: {err}"
        );
    }

    #[test]
    fn reject_on_result_filter_invalid_chars() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: bad_branch
            on_result:
              filter: "my.filter"
              result: hit
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "should reject on_result.filter with invalid chars: {err}"
        );
    }

    #[test]
    fn accept_valid_on_result_filter() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: good_branch
            on_result:
              filter: cache-check_1
              result: hit
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        Config::from_yaml(yaml).unwrap();
    }
}
