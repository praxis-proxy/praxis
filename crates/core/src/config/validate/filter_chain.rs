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
    validate_terminal_filters(chains, listeners)?;
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
            validate_entry_conditions(&chain.name, entry, 0)?;
        }
    }
    Ok(())
}

/// Reject empty condition predicates on one filter entry, recursing
/// into inline branch chains.
///
/// `depth` is the entry's nesting level (0 for a top-level chain filter);
/// nested entries are bounded by [`nested_filter_depth`] so a config
/// cannot drive this recursion without limit.
///
/// [`nested_filter_depth`]: super::nested_filter_depth
fn validate_entry_conditions(chain_name: &str, entry: &FilterEntry, depth: usize) -> Result<(), ProxyError> {
    validate_request_conditions(chain_name, entry)?;
    validate_response_conditions(chain_name, entry)?;
    if let Some(branches) = &entry.branch_chains {
        for branch in branches {
            for chain_ref in &branch.chains {
                if let ChainRef::Inline { filters, .. } = chain_ref {
                    let nested_depth = super::nested_filter_depth(depth, chain_name)?;
                    for inline_entry in filters {
                        validate_entry_conditions(chain_name, inline_entry, nested_depth)?;
                    }
                }
            }
        }
    }
    // Filters nested in an iterative_request_router's steps are built into
    // real pipelines, so their conditions need the same empty-predicate
    // check (matching the inline-cluster validation walk).
    if entry.filter_type == super::inline_clusters::STEP_BEARING_FILTER {
        let nested_depth = super::nested_filter_depth(depth, chain_name)?;
        for nested in super::inline_clusters::extract_step_filters(chain_name, entry)? {
            validate_entry_conditions(chain_name, &nested, nested_depth)?;
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
        validate_request_header_names(chain_name, &entry.filter_type, idx, matcher)?;
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

/// Reject request-condition header names that are not valid HTTP header names.
///
/// The request header a name like `x apikey` would have to match cannot
/// exist, so the predicate is another silent no-op, the same accident class
/// as an unmatchable condition path.
fn validate_request_header_names(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &ConditionMatch,
) -> Result<(), ProxyError> {
    let Some(headers) = &matcher.headers else {
        return Ok(());
    };
    for name in headers.keys() {
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': condition \
                 {idx} header name '{name}' is not a valid HTTP header name, so \
                 the predicate can never match"
            )));
        }
    }
    Ok(())
}

/// Reject response-condition predicates that are empty or impossible.
fn validate_response_conditions(chain_name: &str, entry: &FilterEntry) -> Result<(), ProxyError> {
    for (idx, condition) in entry.response_conditions.iter().enumerate() {
        let matcher = match condition {
            ResponseCondition::When(m) | ResponseCondition::Unless(m) => m,
        };
        let filter = entry.filter_type.as_str();
        validate_response_predicate_present(chain_name, filter, idx, matcher)?;
        validate_response_status_codes(chain_name, filter, idx, matcher)?;
        validate_response_header_names(chain_name, filter, idx, matcher)?;
    }
    Ok(())
}

/// Reject a response-condition predicate given as nothing at all or as
/// an empty container.
fn validate_response_predicate_present(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &crate::config::ResponseConditionMatch,
) -> Result<(), ProxyError> {
    if matcher.status.is_none() && matcher.headers.is_none() {
        return Err(ProxyError::Config(format!(
            "filter '{filter}' in chain '{chain_name}': response condition \
             {idx} is empty; set at least one of status or headers"
        )));
    }
    if matcher.status.as_ref().is_some_and(Vec::is_empty) {
        return Err(empty_predicate_error(chain_name, filter, idx, "response status"));
    }
    if matcher.headers.as_ref().is_some_and(HashMap::is_empty) {
        return Err(empty_predicate_error(chain_name, filter, idx, "response headers"));
    }
    Ok(())
}

/// Reject response-condition status codes outside the HTTP range.
///
/// A response status is always 100..=599, so `status: [9999]` is a
/// predicate nothing can satisfy: the `when` form silently disables its
/// filter and the `unless` form silently un-gates it. Same accident
/// class as the empty predicates above, and the same range health
/// checks already enforce for `expected_status`.
fn validate_response_status_codes(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &crate::config::ResponseConditionMatch,
) -> Result<(), ProxyError> {
    let Some(codes) = &matcher.status else {
        return Ok(());
    };
    for code in codes {
        if !(100..=599).contains(code) {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': response condition \
                 {idx} status {code} is outside the HTTP range 100..=599, so \
                 the predicate can never match"
            )));
        }
    }
    Ok(())
}

/// Reject response-condition header names that are not valid HTTP header names.
///
/// The response header a name like `x apikey` would have to match cannot
/// exist, so the predicate is another silent no-op.
fn validate_response_header_names(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &crate::config::ResponseConditionMatch,
) -> Result<(), ProxyError> {
    let Some(headers) = &matcher.headers else {
        return Ok(());
    };
    for name in headers.keys() {
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': response condition \
                 {idx} header name '{name}' is not a valid HTTP header name, so \
                 the predicate can never match"
            )));
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
///
/// This name list drives the config-time "terminal filter must be last"
/// ordering check, which runs on `FilterEntry` values before any filter is
/// instantiated and so has no trait object to query. The runtime outbound-chain
/// rejection instead uses the `HttpFilter::produces_terminal_response`
/// capability (filter crate). The two live at different layers and must stay in
/// sync: any new builtin that produces a terminal response must be added here
/// *and* override `produces_terminal_response`, or it will be enforced by only
/// one of the two checks.
pub const TERMINAL_FILTERS: &[&str] = &["iterative_request_router"];

/// Reject terminal filters that are not last in their chain, or not
/// last in a listener's flattened pipeline.
fn validate_terminal_filters(chains: &[FilterChainConfig], listeners: &[Listener]) -> Result<(), ProxyError> {
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
    validate_terminal_position_per_listener(chains, listeners)
}

/// Reject a terminal filter that chain concatenation leaves in the
/// middle of a listener's pipeline.
///
/// A listener flattens its chains into a single pipeline, so a terminal
/// filter can be last in its own chain and still be followed by the
/// filters of the next chain the listener names. Pipeline construction
/// rejects that, but only at startup, long after `Config::from_yaml`
/// has handed back a "validated" config, which is what `--validate` and
/// the reload gate act on.
fn validate_terminal_position_per_listener(
    chains: &[FilterChainConfig],
    listeners: &[Listener],
) -> Result<(), ProxyError> {
    let by_name: HashMap<&str, &FilterChainConfig> = chains.iter().map(|c| (c.name.as_str(), c)).collect();
    for listener in listeners {
        // Unknown chain names are reported by `validate_listener_references`.
        let flattened: Vec<(&str, &FilterEntry)> = listener
            .filter_chains
            .iter()
            .filter_map(|name| by_name.get(name.as_str()))
            .flat_map(|chain| chain.filters.iter().map(|entry| (chain.name.as_str(), entry)))
            .collect();
        for (i, (chain_name, entry)) in flattened.iter().enumerate() {
            if TERMINAL_FILTERS.contains(&entry.filter_type.as_str()) && i + 1 < flattened.len() {
                return Err(ProxyError::Config(format!(
                    "filter '{}' in chain '{chain_name}' must be the last filter in \
                     the flattened pipeline for listener '{}' because it produces \
                     terminal responses (at position {i} of {}, after the listener's \
                     chains are concatenated)",
                    entry.filter_type,
                    listener.name,
                    flattened.len()
                )));
            }
        }
    }
    Ok(())
}

/// Reject a bound chain whose own entries exceed the per-chain filter cap.
///
/// A bound outbound chain never appears in `Config::filter_chains`, so the
/// whole-config `validate_chain_cardinality` walk never sees it. This applies
/// the same `MAX_FILTERS_PER_CHAIN` limit to a bound chain's top-level entries,
/// so a runaway outbound chain cannot build unbounded.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if `entries` exceeds `MAX_FILTERS_PER_CHAIN`.
pub fn validate_chain_entries_cardinality(chain_name: &str, entries: &[FilterEntry]) -> Result<(), ProxyError> {
    if entries.len() > MAX_FILTERS_PER_CHAIN {
        return Err(ProxyError::Config(format!(
            "filter chain '{chain_name}' has too many filters ({}, max \
             {MAX_FILTERS_PER_CHAIN})",
            entries.len()
        )));
    }
    Ok(())
}

/// Reject empty condition predicates on a bound chain's entries, recursing into
/// inline branch chains and iterative-router steps.
///
/// A bound outbound chain never appears in `Config::filter_chains`, so the
/// whole-config `validate_conditions` walk never sees it. This applies the same
/// empty-`when`/`unless` rejection (see `validate_entry_conditions`) to a bound
/// chain's entries, so an accidental match-everything predicate cannot silently
/// disable a filter inside an outbound chain.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any entry — including one nested in an
/// inline branch chain or an iterative-router step — carries an empty or
/// unmatchable condition predicate.
pub fn validate_chain_entries_conditions(chain_name: &str, entries: &[FilterEntry]) -> Result<(), ProxyError> {
    for entry in entries {
        validate_entry_conditions(chain_name, entry, 0)?;
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

    use super::super::MAX_NESTED_FILTER_DEPTH;
    use crate::config::Config;

    /// YAML for `depth` nested `iterative_request_router` step filters,
    /// innermost holding one ordinary filter, indented for a chain's
    /// `filters:` list.
    fn nested_step_filters(depth: usize) -> String {
        let mut yaml = "- filter: request_id\n".to_owned();
        for _ in 0..depth {
            let inner: String = yaml.lines().map(|line| format!("            {line}\n")).collect();
            yaml = format!("- filter: iterative_request_router\n  steps:\n    - name: s\n      filters:\n{inner}");
        }
        yaml.lines().map(|line| format!("      {line}\n")).collect()
    }

    /// A one-listener config whose only chain holds `filters`.
    fn config_with_filters(filters: &str) -> String {
        format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n{filters}"
        )
    }

    #[test]
    fn reject_step_filter_nesting_past_the_depth_limit() {
        // Without a ceiling this recursion is driven by config text alone
        // and runs until the validation thread's stack is exhausted.
        let yaml = config_with_filters(&nested_step_filters(MAX_NESTED_FILTER_DEPTH + 1));
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("nesting depth"),
            "step filters nested past the ceiling must be rejected: {err}"
        );
    }

    #[test]
    fn accept_step_filter_nesting_at_the_depth_limit() {
        let yaml = config_with_filters(&nested_step_filters(MAX_NESTED_FILTER_DEPTH));
        Config::from_yaml(&yaml).expect("step nesting at exactly the ceiling must still pass");
    }

    /// A one-listener config whose only filter carries `response_conditions`.
    fn config_with_response_condition(condition: &str) -> String {
        format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n    filter_chains: [main]\nfilter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n        response_conditions:\n{condition}"
        )
    }

    #[test]
    fn reject_response_condition_status_outside_the_http_range() {
        let yaml = config_with_response_condition("          - when:\n              status: [9999]\n");
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("outside the HTTP range"),
            "a status no response can carry makes the predicate a no-op: {err}"
        );
    }

    #[test]
    fn accept_response_condition_status_at_the_range_boundaries() {
        let yaml = config_with_response_condition("          - when:\n              status: [100, 599]\n");
        Config::from_yaml(&yaml).expect("the ends of the HTTP status range must be accepted");
    }

    #[test]
    fn reject_response_condition_invalid_header_name() {
        let yaml = config_with_response_condition(
            "          - unless:\n              headers:\n                \"bad header\": \"x\"\n",
        );
        let err = Config::from_yaml(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP header name"),
            "a header name no response can carry makes the predicate a no-op: {err}"
        );
    }

    #[test]
    fn accept_response_condition_header_name_in_any_case() {
        // Header names are case-insensitive; only invalid characters are
        // the defect being rejected.
        let yaml = config_with_response_condition(
            "          - when:\n              headers:\n                Content-Type: \"application/json\"\n",
        );
        Config::from_yaml(&yaml).expect("a valid header name must be accepted whatever its case");
    }

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
    fn reject_condition_invalid_header_name() {
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
              headers:
                "bad header": "x"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("not a valid HTTP header name"),
            "a request-condition header name no request can carry makes the predicate a no-op: {err}"
        );
    }

    #[test]
    fn accept_condition_header_name_in_any_case() {
        // Header names are case-insensitive; only invalid characters are
        // the defect being rejected.
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
              headers:
                Content-Type: "application/json"
"#;
        Config::from_yaml(yaml).expect("a valid request-condition header name must be accepted whatever its case");
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
    fn reject_terminal_filter_followed_by_another_chain() {
        // Each chain is fine on its own; the listener concatenates them, so
        // the router ends up mid-pipeline. Pipeline construction caught this
        // at startup, but `Config::from_yaml` reported the config valid.
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [routing, trailing]
filter_chains:
  - name: routing
    filters:
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
  - name: trailing
    filters:
      - filter: headers
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("flattened pipeline") && err.to_string().contains("web"),
            "a terminal filter must be last across the listener's chains: {err}"
        );
    }

    #[test]
    fn accept_terminal_filter_in_the_last_chain_of_a_listener() {
        // The same two chains in the order that puts the router last.
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [trailing, routing]
filter_chains:
  - name: routing
    filters:
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
  - name: trailing
    filters:
      - filter: headers
"#;
        Config::from_yaml(yaml).expect("a terminal filter ending the flattened pipeline must pass");
    }

    #[test]
    fn accept_terminal_chain_a_listener_puts_last_and_another_never_uses() {
        // The chain following `routing` belongs to a different listener, so
        // no flattened pipeline actually places a filter after the router.
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains: [routing]
  - name: other
    address: "0.0.0.0:8081"
    filter_chains: [trailing]
filter_chains:
  - name: routing
    filters:
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
  - name: trailing
    filters:
      - filter: headers
"#;
        Config::from_yaml(yaml).expect("chains used by different listeners must not be conflated");
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
