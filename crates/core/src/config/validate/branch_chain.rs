// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Branch chain validation: name uniqueness, chain references, and nesting depth.
//!
//! Branch chains are resolved into concrete pipelines at startup, so
//! structural problems must be caught here rather than at request time.
//! This module rejects duplicate branch names, dangling chain
//! references, and inline-nesting past the depth ceiling, and enforces
//! ceilings on branch counts and re-entrant iteration limits so that a
//! configuration cannot cause an unbounded loop when a branch rejoins at
//! or before its own filter.
//!
//! Cycles through *named* chain references are not detected here (this
//! module only follows inline chains); they are caught during pipeline
//! resolution, where the recursion trips the depth limit and the build
//! fails. The total expansion size is likewise bounded at build time by
//! the pipeline builder's per-pipeline filter-instance ceiling.

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

/// Maximum branch chains a single filter may define.
const MAX_BRANCHES_PER_FILTER: usize = 16;

/// Maximum total branch chain count across all filter chains.
const MAX_TOTAL_BRANCHES: usize = 256;

// -----------------------------------------------------------------------------
// Branch Chain Validation
// -----------------------------------------------------------------------------

/// Validate all branch chains across all filter chains.
pub(crate) fn validate_branch_chains(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    let chain_names: HashSet<&str> = chains.iter().map(|c| c.name.as_str()).collect();
    let initial_count = chain_names.len();
    let mut all_names: HashSet<String> = chain_names.iter().map(|s| (*s).to_owned()).collect();

    for chain in chains {
        validate_filter_names_unique(&chain.filters, &chain.name)?;
        collect_branch_names(&chain.filters, &mut all_names, &chain_names, 0)?;
    }

    let branch_count = all_names.len() - initial_count;
    if branch_count > MAX_TOTAL_BRANCHES {
        return Err(ProxyError::Config(format!(
            "total branch count ({branch_count}) exceeds maximum ({MAX_TOTAL_BRANCHES})"
        )));
    }

    Ok(())
}

/// Validate branch-chain constraints for a single chain's filter entries.
///
/// This is the entry-level slice of the whole-config `validate_branch_chains`
/// pass: it enforces filter-name uniqueness, the per-filter branch cap, the
/// re-entrant [`MAX_ITERATIONS_CEILING`], the inline nesting [`MAX_BRANCH_DEPTH`],
/// the total-branch ceiling (`MAX_TOTAL_BRANCHES`), and chain-reference
/// resolution over one list of [`FilterEntry`]. It exists so outbound chains
/// bound at pipeline-build time — which never appear in `Config::filter_chains`
/// — are held to the same branch-chain limits (notably the `max_iterations`
/// ceiling that bounds re-entrant request loops) as top-level chains instead of
/// bypassing them.
///
/// `known_chains` names the top-level filter chains a [`ChainRef::Named`] branch
/// reference may resolve against; a bound chain with no reachable named chains
/// passes an empty set.
///
/// `prior_branch_count` is the number of branch definitions already counted
/// toward the total-branch ceiling elsewhere in the same build — the branches
/// present configuration-wide and in any previously bound inline outbound chains.
/// The ceiling bounds config complexity across the whole build, not each chain in
/// isolation, so this chain's own branch count is added to `prior_branch_count`
/// and the cumulative total is checked. The cumulative total is returned so a
/// caller can thread it into the next bound chain's check; seed the first call
/// with [`count_build_branches`] over the listener entries and every named chain
/// so branches already present anywhere in the configuration are counted.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if a filter or branch name duplicates, a
/// re-entrant branch exceeds `max_iterations`, inline nesting exceeds
/// [`MAX_BRANCH_DEPTH`], a chain reference is malformed or dangling, or the
/// cumulative branch total exceeds the maximum (`MAX_TOTAL_BRANCHES`).
pub fn validate_chain_entries_branch_chains(
    chain_name: &str,
    entries: &[FilterEntry],
    known_chains: &HashSet<&str>,
    prior_branch_count: usize,
) -> Result<usize, ProxyError> {
    validate_filter_names_unique(entries, chain_name)?;
    let initial_count = known_chains.len();
    let mut all_names: HashSet<String> = known_chains.iter().map(|s| (*s).to_owned()).collect();
    collect_branch_names(entries, &mut all_names, known_chains, 0)?;

    let branch_count = all_names.len() - initial_count;
    let total = prior_branch_count + branch_count;
    if total > MAX_TOTAL_BRANCHES {
        return Err(ProxyError::Config(format!(
            "total branch count ({total}) exceeds maximum ({MAX_TOTAL_BRANCHES})"
        )));
    }

    Ok(total)
}

/// Count the branch definitions across a whole pipeline build: the listener's
/// own `entries` plus every named chain in `chains`, deduplicated by name
/// exactly as the whole-config `validate_branch_chains` pass counts them.
///
/// `validate_branch_chains` enforces the total-branch ceiling only over
/// `Config::filter_chains`; outbound chains bound at pipeline-build time never
/// appear there. Seeding a build's shared branch budget with this
/// configuration-wide count — rather than the listener's entries alone — makes
/// the ceiling span the whole configuration: a named outbound chain the listener
/// never references still counts toward the budget that later-bound *inline*
/// chains accumulate on top of, so the config-wide pool and the inline pool
/// cannot each sit under the ceiling while exceeding it together. In production
/// the listener `entries` are a concatenation of chains already in `chains`, so
/// counting both merely deduplicates; a caller that passes entries not present in
/// `chains` (a direct build) still has those branches counted.
///
/// Named refs resolve to chains counted here, so they are ignored inside branch
/// chains; `known_chains` seeds the name set so a branch or inline name colliding
/// with a chain name is not double counted. This is a pure counter: unlike the
/// validating pass it emits no config-typo warnings and enforces no limits, so
/// seeding a build's budget does not re-warn about entries the whole-config pass
/// already validated.
pub fn count_build_branches(entries: &[FilterEntry], chains: &[&[FilterEntry]], known_chains: &HashSet<&str>) -> usize {
    let initial_count = known_chains.len();
    let mut all_names: HashSet<String> = known_chains.iter().map(|s| (*s).to_owned()).collect();
    count_branch_names(entries, &mut all_names);
    for &chain in chains {
        count_branch_names(chain, &mut all_names);
    }
    all_names.len().saturating_sub(initial_count)
}

/// Recursively insert branch and inline-chain names into `all_names`, ignoring
/// named references. The pure counting counterpart to [`collect_branch_names`],
/// with no validation, typo warnings, or limit checks.
fn count_branch_names(entries: &[FilterEntry], all_names: &mut HashSet<String>) {
    for entry in entries {
        let Some(branches) = &entry.branch_chains else {
            continue;
        };
        for branch in branches {
            all_names.insert(branch.name.clone());
            for chain_ref in &branch.chains {
                if let ChainRef::Inline { name, filters } = chain_ref {
                    all_names.insert(name.clone());
                    count_branch_names(filters, all_names);
                }
            }
        }
    }
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
        entry.warn_config_typos();
        let Some(branches) = &entry.branch_chains else {
            continue;
        };
        if branches.len() > MAX_BRANCHES_PER_FILTER {
            return Err(ProxyError::Config(format!(
                "filter has {} branch chains (max {MAX_BRANCHES_PER_FILTER})",
                branches.len()
            )));
        }
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
    let bname = &branch.name;
    super::validate_name_chars(bname, "branch")?;
    if !all_names.insert(branch.name.clone()) {
        return Err(ProxyError::Config(format!("duplicate branch name '{bname}'")));
    }

    let rejoin = &branch.rejoin;
    if branch.rejoin.contains(':') {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': cross-chain rejoin '{rejoin}' is not supported; \
             listeners flatten all referenced chains into one pipeline, \
             so use the filter's name directly (e.g. 'routing' not 'main:routing')"
        )));
    }

    if branch.chains.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{bname}' must have at least one chain"
        )));
    }

    validate_max_iterations(branch)?;
    validate_on_result_filter_name(branch)?;
    validate_on_result_key_value(branch)?;

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

    let bname = &branch.name;
    let filter = &cond.filter;
    if cond.filter.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': on_result.filter must not be empty"
        )));
    }
    if !cond
        .filter
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': on_result.filter '{filter}' must be ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}

/// Validate `on_result.key` and `on_result.value` are non-empty
/// and contain only safe characters.
fn validate_on_result_key_value(branch: &BranchChainConfig) -> Result<(), ProxyError> {
    let Some(cond) = &branch.on_result else {
        return Ok(());
    };
    let bname = &branch.name;
    if cond.key.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': on_result.key must not be empty"
        )));
    }
    validate_on_result_field(&cond.key, "key", bname)?;
    if cond.value.is_empty() {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': on_result.result must not be empty"
        )));
    }
    validate_on_result_field(&cond.value, "result", bname)
}

/// Validate a single `on_result` field uses safe characters.
fn validate_on_result_field(val: &str, field: &str, branch_name: &str) -> Result<(), ProxyError> {
    if !val.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(ProxyError::Config(format!(
            "branch '{branch_name}': on_result.{field} '{val}' must be ASCII alphanumeric, '_', or '-'"
        )));
    }
    Ok(())
}

/// Validate `max_iterations` constraints.
fn validate_max_iterations(branch: &BranchChainConfig) -> Result<(), ProxyError> {
    let bname = &branch.name;
    if let Some(max) = branch.max_iterations
        && !(1..=MAX_ITERATIONS_CEILING).contains(&max)
    {
        return Err(ProxyError::Config(format!(
            "branch '{bname}': max_iterations must be 1-{MAX_ITERATIONS_CEILING}, got {max}"
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
            super::validate_name_chars(name, "inline chain")?;
            if depth + 1 > MAX_BRANCH_DEPTH {
                return Err(ProxyError::Config(format!(
                    "branch nesting depth exceeds maximum ({MAX_BRANCH_DEPTH})"
                )));
            }
            if filters.len() > super::filter_chain::MAX_FILTERS_PER_CHAIN {
                return Err(ProxyError::Config(format!(
                    "inline chain '{name}' has too many filters ({}, max {})",
                    filters.len(),
                    super::filter_chain::MAX_FILTERS_PER_CHAIN
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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    use std::fmt::Write as _;

    use crate::config::Config;

    #[test]
    fn reject_branch_name_with_special_chars() {
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
          - name: "bad.branch"
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
            "branch name with dots should be rejected: {err}"
        );
    }

    #[test]
    fn reject_inline_chain_name_with_special_chars() {
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
          - name: branch
            chains:
              - name: "bad.inline"
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("alphanumeric"),
            "inline chain name with dots should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_on_result_key() {
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
          - name: branch
            on_result:
              filter: cache
              key: ""
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
            err.to_string().contains("on_result.key must not be empty"),
            "empty on_result key should be rejected: {err}"
        );
    }

    #[test]
    fn reject_empty_on_result_value() {
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
          - name: branch
            on_result:
              filter: cache
              result: ""
            chains:
              - name: inline
                filters:
                  - filter: headers
      - filter: static_response
        status: 200
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("on_result.result must not be empty"),
            "empty on_result value should be rejected: {err}"
        );
    }

    #[test]
    fn reject_on_result_key_with_special_chars() {
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
          - name: branch
            on_result:
              filter: cache
              key: "bad.key"
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
            err.to_string().contains("on_result.key"),
            "on_result key with dots should be rejected: {err}"
        );
    }

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
                writeln!(yaml, "{pad}- filter: headers").unwrap();
                if current < depth {
                    writeln!(yaml, "{pad}  branch_chains:").unwrap();
                    writeln!(yaml, "{pad}    - name: {filter_name}").unwrap();
                    writeln!(yaml, "{pad}      chains:").unwrap();
                    writeln!(yaml, "{pad}        - name: {chain_name}").unwrap();
                    writeln!(yaml, "{pad}          filters:").unwrap();
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
    fn accept_nesting_at_exact_max_depth() {
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
                writeln!(yaml, "{pad}- filter: headers").unwrap();
                if current < depth {
                    writeln!(yaml, "{pad}  branch_chains:").unwrap();
                    writeln!(yaml, "{pad}    - name: {filter_name}").unwrap();
                    writeln!(yaml, "{pad}      chains:").unwrap();
                    writeln!(yaml, "{pad}        - name: {chain_name}").unwrap();
                    writeln!(yaml, "{pad}          filters:").unwrap();
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

        let yaml = nested_yaml(super::super::branch_chain::MAX_BRANCH_DEPTH);
        Config::from_yaml(&yaml).expect("nesting at exactly MAX_BRANCH_DEPTH should pass");
    }

    #[test]
    fn reject_too_many_branches_per_filter() {
        let mut branches = String::new();
        for i in 0..17 {
            write!(
                branches,
                "          - name: branch_{i}\n            chains:\n              \
                 - name: inline_{i}\n                filters:\n                  \
                 - filter: headers\n"
            )
            .unwrap();
        }
        let yaml = format!(
            r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
{branches}      - filter: static_response
        status: 200
"#
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("branch chains"),
            "should reject >16 branches per filter: {err}"
        );
    }

    #[test]
    fn accept_max_branches_per_filter() {
        let mut branches = String::new();
        for i in 0..16 {
            write!(
                branches,
                "          - name: branch_{i}\n            chains:\n              \
                 - name: inline_{i}\n                filters:\n                  \
                 - filter: headers\n"
            )
            .unwrap();
        }
        let yaml = format!(
            r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
{branches}      - filter: static_response
        status: 200
"#
        );
        Config::from_yaml(&yaml).expect("exactly 16 branches per filter should pass");
    }

    #[test]
    fn reject_inline_chain_too_many_filters() {
        let mut filters = String::new();
        for _ in 0..101 {
            filters.push_str("                  - filter: headers\n");
        }
        let yaml = format!(
            r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: big_branch
            chains:
              - name: big_inline
                filters:
{filters}      - filter: static_response
        status: 200
"#
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("too many filters"),
            "inline chain with >100 filters should be rejected: {err}"
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

    // -------------------------------------------------------------------------
    // Entry-level validation (validate_chain_entries_branch_chains)
    //
    // The whole-config pass (validate_branch_chains) is reached through
    // Config::from_yaml above. Outbound chains bound at pipeline-build time never
    // appear in Config::filter_chains, so they are held to the same branch limits
    // through validate_chain_entries_branch_chains instead. These exercise that
    // function directly.
    // -------------------------------------------------------------------------

    #[test]
    fn chain_entries_reject_total_branch_count_over_ceiling() {
        use std::collections::HashSet;

        use crate::config::FilterEntry;

        // 17 filters x 16 branches = 272 uniquely-named branches, each pointing
        // at a known named chain so only branch names count toward the total.
        // This exceeds MAX_TOTAL_BRANCHES; the entry-level validator must reject
        // it exactly as the whole-config pass does, so an outbound chain cannot
        // bypass the ceiling by never appearing in Config::filter_chains.
        let mut yaml = String::new();
        let mut n = 0;
        for _ in 0..17 {
            yaml.push_str("- filter: headers\n  branch_chains:\n");
            for _ in 0..16 {
                writeln!(yaml, "    - name: br_{n}\n      chains: [utility]").unwrap();
                n += 1;
            }
        }
        let entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let known: HashSet<&str> = HashSet::from(["utility"]);

        let err = super::validate_chain_entries_branch_chains("outbound", &entries, &known, 0).unwrap_err();
        assert!(
            err.to_string().contains("total branch count")
                && err.to_string().contains(&super::MAX_TOTAL_BRANCHES.to_string()),
            "an outbound chain whose branch total exceeds the ceiling must be rejected: {err}"
        );
    }

    #[test]
    fn chain_entries_reject_branches_over_per_filter_cap() {
        use std::collections::HashSet;

        use crate::config::FilterEntry;

        // A single filter with 17 branch chains exceeds MAX_BRANCHES_PER_FILTER.
        // Already enforced via collect_branch_names; this documents that the
        // per-filter cardinality cap is not bypassed on the entry-level path.
        let mut yaml = String::from("- filter: headers\n  branch_chains:\n");
        for n in 0..17 {
            writeln!(yaml, "    - name: br_{n}\n      chains: [utility]").unwrap();
        }
        let entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let known: HashSet<&str> = HashSet::from(["utility"]);

        let err = super::validate_chain_entries_branch_chains("outbound", &entries, &known, 0).unwrap_err();
        assert!(
            err.to_string().contains("branch chains") && err.to_string().contains("16"),
            "a filter exceeding the per-filter branch cap must be rejected: {err}"
        );
    }

    #[test]
    fn chain_entries_reject_invalid_on_result_condition() {
        use std::collections::HashSet;

        use crate::config::FilterEntry;

        // A branch whose on_result declares an empty filter is rejected via
        // validate_branch. This documents that the on_result condition checks are
        // not bypassed on the entry-level path.
        let entries: Vec<FilterEntry> = serde_yaml::from_str(
            "
- filter: headers
  branch_chains:
    - name: br
      on_result:
        filter: \"\"
        result: hit
      chains: [utility]
",
        )
        .unwrap();
        let known: HashSet<&str> = HashSet::from(["utility"]);

        let err = super::validate_chain_entries_branch_chains("outbound", &entries, &known, 0).unwrap_err();
        assert!(
            err.to_string().contains("on_result.filter must not be empty"),
            "a branch with an empty on_result filter must be rejected: {err}"
        );
    }

    #[test]
    fn count_build_branches_counts_entries_and_named_chains_ignoring_named_refs() {
        use std::collections::HashSet;

        use crate::config::FilterEntry;

        // The listener entries define two branches: one resolving against a known
        // named chain (contributes only its branch name) and one with an inline
        // sub-chain (contributes both the branch name and the inline name). Named
        // refs resolve to already-counted top-level chains, so they are not counted.
        let entries: Vec<FilterEntry> = serde_yaml::from_str(
            "
- filter: headers
  branch_chains:
    - name: br_named
      chains: [utility]
    - name: br_inline
      chains:
        - name: sub
          filters:
            - filter: headers
",
        )
        .unwrap();
        // A named chain that itself defines a branch: config-wide counting must
        // count it too, on top of the listener's own branches.
        let utility: Vec<FilterEntry> = serde_yaml::from_str(
            "
- filter: headers
  branch_chains:
    - name: u_br
      chains: [utility]
",
        )
        .unwrap();
        let chains: [&[FilterEntry]; 1] = [utility.as_slice()];
        let known: HashSet<&str> = HashSet::from(["utility"]);

        // br_named + br_inline + sub (entries) + u_br (named chain) = 4; the chain
        // name `utility` is not counted, and named refs are ignored.
        assert_eq!(
            super::count_build_branches(&entries, &chains, &known),
            4,
            "config-wide counting must count entries and named chains, but not named refs"
        );
    }

    #[test]
    fn chain_entries_branch_count_accumulates_prior_and_returns_total() {
        use std::collections::HashSet;

        use crate::config::FilterEntry;

        // A chain defining 10 branches. On its own (prior 0) it passes and the
        // cumulative total is returned. With enough prior branches from elsewhere
        // in the same build, the same chain pushes the cumulative total past the
        // ceiling and is rejected — proving the ceiling bounds the whole build, not
        // each chain in isolation.
        let mut yaml = String::from("- filter: headers\n  branch_chains:\n");
        for n in 0..10 {
            writeln!(yaml, "    - name: br_{n}\n      chains: [utility]").unwrap();
        }
        let entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let known: HashSet<&str> = HashSet::from(["utility"]);

        let total = super::validate_chain_entries_branch_chains("outbound", &entries, &known, 0).unwrap();
        assert_eq!(total, 10, "the cumulative total must include this chain's 10 branches");

        let err =
            super::validate_chain_entries_branch_chains("outbound", &entries, &known, super::MAX_TOTAL_BRANCHES - 5)
                .unwrap_err();
        assert!(
            err.to_string().contains("total branch count")
                && err.to_string().contains(&(super::MAX_TOTAL_BRANCHES + 5).to_string()),
            "prior branch count must accumulate into the cumulative total: {err}"
        );
    }
}
