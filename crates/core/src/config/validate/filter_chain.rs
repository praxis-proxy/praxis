// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Filter chain validation: cardinality, name uniqueness, and listener references.

use std::collections::{HashMap, HashSet};

use crate::{
    config::{
        ChainRef, Cluster, Condition, ConditionMatch, FilterChainConfig, FilterEntry, Listener, ResponseCondition,
        SelectedUpstreamMatch,
    },
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
            Condition::When(inner) | Condition::Unless(inner) => inner,
        };
        if matcher.grpc.is_none()
            && matcher.path.is_none()
            && matcher.path_prefix.is_none()
            && matcher.methods.is_none()
            && matcher.headers.is_none()
            && matcher.selected_upstream.is_none()
        {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': condition {idx} is \
                 empty; set at least one of grpc, path, path_prefix, methods, \
                 headers, or selected_upstream (an empty condition matches \
                 every request, so 'unless' would disable the filter entirely)",
                filter = entry.filter_type,
            )));
        }
        validate_condition_containers(chain_name, &entry.filter_type, idx, matcher)?;
        validate_condition_paths(chain_name, &entry.filter_type, idx, matcher)?;
    }
    Ok(())
}

/// Reject request-condition predicates given as empty containers.
///
/// An empty container is as pathological as an all-absent predicate:
/// `methods: []` can never match, while `headers: {}` and
/// `selected_upstream: {}` match every request and so silently disable an
/// `unless`.
fn validate_condition_containers(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &ConditionMatch,
) -> Result<(), ProxyError> {
    if matcher.methods.as_ref().is_some_and(Vec::is_empty) {
        return Err(empty_predicate_error(chain_name, filter, idx, "methods"));
    }
    if matcher.headers.as_ref().is_some_and(HashMap::is_empty) {
        return Err(empty_predicate_error(chain_name, filter, idx, "headers"));
    }
    if matcher
        .selected_upstream
        .as_ref()
        .is_some_and(SelectedUpstreamMatch::is_empty)
    {
        return Err(ProxyError::Config(format!(
            "filter '{filter}' in chain '{chain_name}': condition {idx} has \
             an empty selected_upstream predicate; set application_protocol, \
             application_provider, or both",
        )));
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
            ResponseCondition::When(inner) | ResponseCondition::Unless(inner) => inner,
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

// -----------------------------------------------------------------------------
// Selected-Upstream Matcher Validation
// -----------------------------------------------------------------------------

/// Reject `selected_upstream` matcher values that name no declared cluster.
///
/// A `selected_upstream` condition matches the `application_protocol` /
/// `application_provider` the load balancer publishes for the cluster it
/// selected. Those values come only from a declared cluster's `http:` block, so
/// a matcher value that equals no declared cluster's identifier can never be
/// satisfied: every request evaluates it to a fail-closed miss (a `when` never
/// fires; an `unless` never suppresses). That is almost always a typo, and it
/// silently degrades exactly like an empty predicate — so reject it at startup
/// with the offending value named.
///
/// The declared set is the union of every top-level cluster and every inline
/// cluster (`load_balancer` / `tcp_load_balancer`, including those nested in
/// inline branch chains and `iterative_request_router` steps), because any of
/// them can be the one a router points the load balancer at.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any `selected_upstream` matcher names an
/// `application_protocol` or `application_provider` that no declared cluster
/// carries.
pub(super) fn validate_selected_upstream_matchers(
    chains: &[FilterChainConfig],
    clusters: &[Cluster],
) -> Result<(), ProxyError> {
    let inline = super::inline_clusters::collect_inline_clusters(chains)?;
    let mut declared = DeclaredUpstreams::default();
    for cluster in clusters.iter().chain(inline.iter()) {
        let protocol = cluster.http.application_protocol.as_deref();
        let provider = cluster.http.application_provider.as_deref();
        if let Some(protocol) = protocol {
            declared.protocols.insert(protocol);
        }
        if let Some(provider) = provider {
            declared.providers.insert(provider);
        }
        // A matcher naming both fields matches only a single selected cluster
        // that carries both, so record the pairs a cluster declares together.
        if let (Some(protocol), Some(provider)) = (protocol, provider) {
            declared.pairs.insert((protocol, provider));
        }
    }

    for chain in chains {
        for entry in &chain.filters {
            validate_entry_selected_upstream(&chain.name, entry, &declared)?;
        }
    }
    Ok(())
}

/// The declared cluster application identifiers a `selected_upstream` matcher
/// may name (across top-level and inline clusters).
#[derive(Default)]
struct DeclaredUpstreams<'cfg> {
    /// Every declared cluster's `application_protocol`.
    protocols: HashSet<&'cfg str>,
    /// Every declared cluster's `application_provider`.
    providers: HashSet<&'cfg str>,
    /// Every `(application_protocol, application_provider)` pair declared
    /// together on a single cluster. A matcher naming both fields matches only a
    /// cluster that carries both, so it must name a pair from this set, not one
    /// value drawn from each of two different clusters.
    pairs: HashSet<(&'cfg str, &'cfg str)>,
}

/// Check one filter entry's `selected_upstream` matchers, recursing into inline
/// branch chains and `iterative_request_router` steps (mirrors
/// [`validate_entry_conditions`]).
fn validate_entry_selected_upstream(
    chain_name: &str,
    entry: &FilterEntry,
    declared: &DeclaredUpstreams<'_>,
) -> Result<(), ProxyError> {
    for (idx, condition) in entry.conditions.iter().enumerate() {
        let matcher = match condition {
            Condition::When(inner) | Condition::Unless(inner) => inner,
        };
        if let Some(selected) = &matcher.selected_upstream {
            check_selected_upstream_values(chain_name, &entry.filter_type, idx, selected, declared)?;
        }
    }

    if let Some(branches) = &entry.branch_chains {
        for branch in branches {
            for chain_ref in &branch.chains {
                if let ChainRef::Inline { filters, .. } = chain_ref {
                    for inline_entry in filters {
                        validate_entry_selected_upstream(chain_name, inline_entry, declared)?;
                    }
                }
            }
        }
    }

    if entry.filter_type == super::inline_clusters::STEP_BEARING_FILTER {
        for nested in super::inline_clusters::extract_step_filters(chain_name, entry)? {
            validate_entry_selected_upstream(chain_name, &nested, declared)?;
        }
    }
    Ok(())
}

/// Reject a single `selected_upstream` matcher that no upstream can satisfy:
/// a protocol or provider naming no declared cluster, or a both-fields pair no
/// single cluster declares together.
fn check_selected_upstream_values(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &SelectedUpstreamMatch,
    declared: &DeclaredUpstreams<'_>,
) -> Result<(), ProxyError> {
    for (field, value, set) in [
        (
            "application_protocol",
            &matcher.application_protocol,
            &declared.protocols,
        ),
        (
            "application_provider",
            &matcher.application_provider,
            &declared.providers,
        ),
    ] {
        if let Some(value) = value
            && !set.contains(value.as_str())
        {
            return Err(ProxyError::Config(format!(
                "filter '{filter}' in chain '{chain_name}': condition {idx} \
                 selected_upstream.{field} '{value}' matches no cluster's \
                 {field}; no load balancer can select an upstream that satisfies \
                 it, so the condition fails closed on every request. Declare a \
                 cluster with this {field} or correct the value"
            )));
        }
    }
    check_selected_upstream_pair(chain_name, filter, idx, matcher, declared)
}

/// Reject a `selected_upstream` matcher naming both fields as a pair no single
/// cluster declares together.
///
/// The per-field checks pass when each value exists on *some* cluster, but a
/// load balancer selects one upstream and publishes its protocol and provider
/// together (from the same cluster). A matcher whose two values come from
/// different clusters can therefore never match, so require the pair to exist on
/// *one* cluster.
fn check_selected_upstream_pair(
    chain_name: &str,
    filter: &str,
    idx: usize,
    matcher: &SelectedUpstreamMatch,
    declared: &DeclaredUpstreams<'_>,
) -> Result<(), ProxyError> {
    if let (Some(protocol), Some(provider)) = (&matcher.application_protocol, &matcher.application_provider)
        && !declared.pairs.contains(&(protocol.as_str(), provider.as_str()))
    {
        return Err(ProxyError::Config(format!(
            "filter '{filter}' in chain '{chain_name}': condition {idx} \
             selected_upstream requires application_protocol '{protocol}' and \
             application_provider '{provider}' together, but no single cluster \
             declares both; a load balancer selects one upstream, so a matcher \
             whose values come from different clusters can never match and the \
             condition fails closed on every request. Declare a cluster with \
             both, or split the matcher"
        )));
    }
    Ok(())
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

/// Reject terminal filters that are not last in their chain.
fn validate_terminal_filters(chains: &[FilterChainConfig]) -> Result<(), ProxyError> {
    for chain in chains {
        for (i, entry) in chain.filters.iter().enumerate() {
            if TERMINAL_FILTERS.contains(&entry.filter_type.as_str()) && i.saturating_add(1) < chain.filters.len() {
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
        validate_entry_conditions(chain_name, entry)?;
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
    let chain_names: HashSet<&str> = chains.iter().map(|chain| chain.name.as_str()).collect();
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
    fn accept_grpc_only_condition() {
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
          - when:
              grpc: true
"#;
        let config = Config::from_yaml(yaml);
        assert!(
            config.is_ok(),
            "grpc alone is a complete predicate and must not be rejected as empty: {:?}",
            config.err()
        );
    }

    #[test]
    fn empty_condition_error_lists_the_grpc_predicate() {
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
          - when: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("at least one of grpc, path"),
            "the remedy should name every settable predicate: {err}"
        );
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
    fn reject_empty_selected_upstream_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream: {}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("empty selected_upstream predicate"),
            "an empty selected_upstream predicate matches everything and must be rejected: {err}"
        );
    }

    #[test]
    fn accept_selected_upstream_condition() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream:
                application_provider: vllm
clusters:
  - name: vllm_backend
    http:
      application_provider: vllm
    endpoints: ["10.0.0.1:80"]
"#;
        Config::from_yaml(yaml).expect("a populated selected_upstream condition is valid config");
    }

    #[test]
    fn reject_selected_upstream_provider_matching_no_cluster() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream:
                application_provider: vlim
clusters:
  - name: vllm_backend
    http:
      application_provider: vllm
    endpoints: ["10.0.0.1:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("application_provider 'vlim' matches no cluster"),
            "a selected_upstream provider that names no declared cluster must be rejected: {err}"
        );
    }

    #[test]
    fn reject_selected_upstream_protocol_matching_no_cluster() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream:
                application_protocol: openai_responses
clusters:
  - name: backend
    http:
      application_protocol: openai_chat_completions
    endpoints: ["10.0.0.1:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("application_protocol 'openai_responses' matches no cluster"),
            "a selected_upstream protocol that names no declared cluster must be rejected: {err}"
        );
    }

    #[test]
    fn reject_selected_upstream_matching_only_the_other_field() {
        // The protocol names no cluster at all, so the per-field check rejects
        // the matcher (before the pair check even applies) even though the
        // provider half is declared.
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream:
                application_protocol: unknown_protocol
                application_provider: vllm
clusters:
  - name: vllm_backend
    http:
      application_protocol: openai_chat_completions
      application_provider: vllm
    endpoints: ["10.0.0.1:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("application_protocol 'unknown_protocol' matches no cluster"),
            "a matcher whose protocol names no cluster must be rejected even when its provider matches: {err}"
        );
    }

    #[test]
    fn reject_selected_upstream_pair_split_across_clusters() {
        // Both values are declared, but on *different* clusters: the protocol on
        // one, the provider on another, with no single cluster carrying both. A
        // load balancer selects one upstream, so the AND-matcher can never match
        // and must be rejected even though each value passes the per-field check.
        // (Flow-style YAML keeps the fixture under the line cap.)
        let yaml = r#"
listeners: [{name: web, address: "127.0.0.1:8080", filter_chains: [main]}]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when: {selected_upstream: {application_protocol: openai_chat_completions, application_provider: vllm}}
clusters:
  - {name: chat, http: {application_protocol: openai_chat_completions, application_provider: ollama}, endpoints: ["10.0.0.1:80"]}
  - {name: vllm, http: {application_protocol: openai_responses, application_provider: vllm}, endpoints: ["10.0.0.2:80"]}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains(
                "requires application_protocol 'openai_chat_completions' and \
                 application_provider 'vllm' together"
            ),
            "a matcher whose protocol and provider are declared only on different clusters must be rejected: {err}"
        );
    }

    #[test]
    fn accept_selected_upstream_pair_on_single_cluster() {
        // The requested pair is carried together by one cluster (even though a
        // second cluster shares only the protocol), so a load balancer can
        // select an upstream that satisfies the matcher.
        let yaml = r#"
listeners: [{name: web, address: "127.0.0.1:8080", filter_chains: [main]}]
filter_chains:
  - name: main
    filters:
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when: {selected_upstream: {application_protocol: openai_chat_completions, application_provider: vllm}}
clusters:
  - {name: chat, http: {application_protocol: openai_chat_completions, application_provider: ollama}, endpoints: ["10.0.0.1:80"]}
  - {name: vllm, http: {application_protocol: openai_chat_completions, application_provider: vllm}, endpoints: ["10.0.0.2:80"]}
"#;
        Config::from_yaml(yaml).expect("a matcher whose protocol and provider coexist on one cluster is valid config");
    }

    #[test]
    fn accept_selected_upstream_matching_inline_cluster() {
        // The matched identifier is declared only by an inline load_balancer
        // cluster, not a top-level one — the canonical set must union both.
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: load_balancer
        clusters:
          - name: vllm_backend
            http:
              application_provider: vllm
            endpoints: ["10.0.0.1:80"]
      - filter: path_rewrite
        prefix: "/v1"
        replacement: "/openai/v1"
        conditions:
          - when:
              selected_upstream:
                application_provider: vllm
"#;
        Config::from_yaml(yaml).expect("a selected_upstream value declared by an inline cluster must be accepted");
    }

    #[test]
    fn reject_selected_upstream_in_inline_branch_chain() {
        // The recursion into inline branch chains must reach selected_upstream
        // matchers there too (flow-style YAML keeps the fixture compact).
        let yaml = r#"
listeners: [{name: web, address: "127.0.0.1:8080", filter_chains: [main]}]
filter_chains:
  - name: main
    filters:
      - filter: headers
        branch_chains:
          - name: branch
            rejoin: next
            chains:
              - name: inline
                filters:
                  - filter: request_id
                    conditions: [{when: {selected_upstream: {application_provider: ollama}}}]
      - filter: request_id
clusters:
  - {name: c, http: {application_provider: vllm}, endpoints: ["10.0.0.1:80"]}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("application_provider 'ollama' matches no cluster"),
            "a selected_upstream typo inside an inline branch chain must be rejected: {err}"
        );
    }

    #[test]
    fn reject_selected_upstream_in_iterative_router_step() {
        // IRR step filters are built into real pipelines, so selected_upstream
        // matcher validation must recurse into them just like branch chains.
        let yaml = r#"
listeners: [{name: web, address: "127.0.0.1:8080", filter_chains: [main]}]
filter_chains:
  - name: main
    filters:
      - filter: iterative_request_router
        steps:
          - name: call
            url: "http://backend"
            filters:
              - filter: request_id
                conditions: [{when: {selected_upstream: {application_provider: ollama}}}]
clusters:
  - {name: c, http: {application_provider: vllm}, endpoints: ["10.0.0.1:80"]}
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("application_provider 'ollama' matches no cluster"),
            "a selected_upstream typo inside an IRR step must be rejected: {err}"
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
